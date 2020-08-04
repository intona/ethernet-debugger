// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "device.h"
#include "fifo.h"
#include "global.h"
#include "grabber.h"
#include "usb_io.h"
#include "utils.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

// Maximum size of what can come through the endpoints. (Upper bound, see
// PACKED_CNT_MAX in FPGA.)
#define MAX_HW_PACKET_SIZE (16 * 1024)
// Maximum USB frame size that we assume is somehow possible.
#define MAX_USB_FRAME_SIZE MAX_HW_PACKET_SIZE
// Maximum ethernet frame size we assume is somehow possible. (This could be
// larger or smaller than the USB frame size, because we can merge or split
// ethernet frames to USB frames.)
#define MAX_ETH_FRAME_SIZE MAX_HW_PACKET_SIZE

// Maximum number of ethernet frames the HW could possibly put into a USB packet.
// (Some may be partial packets.)
#define MAX_FRAMES_PER_PACKET (MAX_HW_PACKET_SIZE / sizeof(struct sc_info) + 1)

// Worst case size of a pcapng formatted packet, including pcapng overhead.
#define MAX_PCAPNG_PACKET_SIZE (MAX_ETH_FRAME_SIZE + 2048)

// State for a single packet FIFO. They are only separate because the hw wants
// them separate.
struct packet_fifo {
    // --- immutable
    unsigned interface;         // port ID (0 or 1)

    // --- No locking, but 1 producer/1 consumer max.
    struct byte_fifo data;      // footers turned headers + raw packet data

    // --- accessed under fifo_mutex
    uint64_t frames_written;    // number of frames queued to FIFO
    uint32_t hw_last_seq;       // previous packet sequence number
    uint64_t last_hw_ts;        // last known hardware timestamp (frame/idle)
    uint64_t ts_problems;       // number of packets with backward timestamps
    struct grabber_port_stats stats;

    // --- access by consumer only
    uint64_t dropped_total;     // sums any dropped frames since last frame
    uint64_t dropped_total_prev;// dropped_total before newest frame
    uint64_t broken_packets;    // indirection for synchronization
    uint8_t packet_buffer[MAX_ETH_FRAME_SIZE]; // temp. buffer for packet
    struct grabber_packet packet; // temp. packet memory
    struct grabber_interface gr_iface;

    // --- access by producer only
    uint16_t seq_counter;
    bool synced;
    int initial_sync;
    // Temporary buffer. In theory, you only need to keep sizeof(sc_info) bytes,
    // and can stream the payload directly to the data ring buffer (this is also
    // why these ring buffers are separate), but this was abandoned due to
    // complexity.
    uint8_t split_buf[MAX_ETH_FRAME_SIZE];
    size_t split_buf_size;
};

struct grabber {
    char *filename;
    struct device *device;
    struct logfn log;

    struct usb_ep eps[2];

    struct packet_fifo fifos[2];

    // access by writer thread only
    struct grabber_filter **filters;
    size_t num_filters;

    pthread_mutex_t fifo_mutex;
    pthread_cond_t fifo_wakeup;

    // protected by fifo_mutex
    bool shutdown;
    bool error_open, error_write, error_discon;
    uint64_t bytes_written;
    uint64_t system_start_time;

    pthread_t writer_thread;
    bool writer_thread_valid;
};

static const int EPs[2] = {0x81, 0x82};

struct sc_info {
    uint16_t payload_bytecount;
    uint16_t magic;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t packet_counter;
    uint32_t calculated_fcs;
    uint16_t interpacket_frame_gap;
    // bits 13-0: byte error count
    // bit 14: overflow
    // bit 15: fcs error
    uint16_t errors;
};

static_assert(sizeof(struct sc_info) == 4 * 5 + 2 * 2, "alignment?");

#define SC_INFO_TIMESTAMP(inf) ((((uint64_t)(inf).timestamp_high) << 32) | \
                                (inf).timestamp_low)

struct packet_footer {
    uint16_t magic;
    uint16_t seq_counter;
    uint16_t flags;
    uint16_t last_frame_ptr;
};

static_assert(sizeof(struct packet_footer) == 8, "???");

static void write_pcapng_block_size(struct wbuf *w, size_t start)
{
    size_t pos = w->pos;
    assert(start < pos);
    uint32_t len = pos + 4 - start;
    memcpy(w->ptr + start + 4, &len, 4);
    wbuf_write32(w, len);
}

static bool write_pipe(int fd, const void *data, size_t size)
{
    while (size) {
        ssize_t s = write(fd, data, size);
        if (s < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            return false;
        }
        data = (char *)data + s;
        size -= s;
    }
    return true;
}

static void flush_wbuf_to_pipe(struct grabber *gr, int fd, struct wbuf *w)
{
    bool ok = write_pipe(fd, w->ptr, w->pos);

    pthread_mutex_lock(&gr->fifo_mutex);
    if (ok) {
        gr->bytes_written += w->pos;
    } else {
        gr->error_write = true;
        gr->shutdown = true;
    }
    pthread_mutex_unlock(&gr->fifo_mutex);

    w->pos = 0;
}

// Read the next frame from any of the FIFOs. Blocks.
// Returns pointer to temporary data.
static struct grabber_packet *packet_fifo_read_next(struct grabber *gr,
                                                    bool allow_wait,
                                                    bool *doexit)
{
    pthread_mutex_lock(&gr->fifo_mutex);

    struct packet_fifo *read_fifo = NULL;

    while (1) {
        uint64_t read_fifo_ts = UINT64_MAX;

        *doexit = gr->shutdown;
        if (*doexit) {
            pthread_mutex_unlock(&gr->fifo_mutex);
            return NULL;
        }

        // Look for the FIFO with the next packet to read. We need to select the
        // FIFO which has the packet with the lowest timestamp (so they are
        // interleaved by time; they use the same time source).
        for (size_t n = 0; n < 2; n++) {
            struct packet_fifo *fifo = &gr->fifos[n];

            // If there's no new packet, use the last idle TS. Due to buffering,
            // an endpoint with no packets may still receive frames that are
            // _older_ than the already received packets on the other endpoint.
            // The idle TS indicates whether there were no new packets for sure.
            uint64_t next_ts = fifo->last_hw_ts;

            bool have_packets = fifo->stats.sw_frames < fifo->frames_written;
            if (have_packets) {
                // Look at the next frame's timestamp.
                struct sc_info tmp;
                size_t r = byte_fifo_peek(&fifo->data, &tmp, sizeof(tmp));
                assert(r == sizeof(tmp)); // ring buffer logic guarantees this
                assert(tmp.magic == 0xABCD);
                next_ts = SC_INFO_TIMESTAMP(tmp);
            }

            if (next_ts <= read_fifo_ts) {
                read_fifo = have_packets ? fifo : NULL;
                read_fifo_ts = next_ts;
            }

            // Always update stats.
            fifo->stats.sw_buffer_num =
                fifo->frames_written - fifo->stats.sw_frames;
            fifo->stats.sw_buffer_sz =
                have_packets ? byte_fifo_get_available(&fifo->data) : 0;
            fifo->stats.broken_packets += fifo->broken_packets;
            fifo->broken_packets = 0;
        }

        if (read_fifo)
            break;

        if (!allow_wait) {
            pthread_mutex_unlock(&gr->fifo_mutex);
            return NULL;
        }

        pthread_cond_wait(&gr->fifo_wakeup, &gr->fifo_mutex);
    }

    assert(read_fifo);

    read_fifo->stats.sw_frames++;

    read_fifo->dropped_total_prev = read_fifo->dropped_total;
    read_fifo->dropped_total =
        read_fifo->stats.hw_dropped + read_fifo->stats.sw_dropped;

    uint64_t system_start_time = gr->system_start_time;

    pthread_mutex_unlock(&gr->fifo_mutex);

    struct sc_info info;
    size_t r = byte_fifo_read(&read_fifo->data, &info, sizeof(info));
    assert(r == sizeof(info)); // ring buffer logic guarantees this

    size_t aligned_size = (info.payload_bytecount + 3) & (~(size_t)3);

    assert(aligned_size <= MAX_ETH_FRAME_SIZE);

    r = byte_fifo_read(&read_fifo->data, read_fifo->packet_buffer, aligned_size);
    assert(r == aligned_size); // ring buffer logic guarantees this

    read_fifo->packet = (struct grabber_packet){
        .iface = &read_fifo->gr_iface,
        .data = read_fifo->packet_buffer,
        .size = info.payload_bytecount,
        .time_ns = SC_INFO_TIMESTAMP(info) + system_start_time,
        .dropped_inc = read_fifo->dropped_total - read_fifo->dropped_total_prev,
        .interpacket_frame_gap = info.interpacket_frame_gap,
        .fcs_error = info.errors & (1 << 15),
        .symbol_error = info.errors & ((1 << 14) - 1),
    };

    return &read_fifo->packet;
}

static void *writer_thread(void *ptr)
{
    struct grabber *gr = ptr;
    // Temporary buffer used for headers and packets.
    size_t wbuf_size = MAX_PCAPNG_PACKET_SIZE * 1000;
    uint8_t *wbuf_data = NULL;
    int output_fd = -1;
    int link_type = gr->fifos[0].gr_iface.pcap_linktype;

    struct grabber_interface *ifaces[2] = {
        &gr->fifos[0].gr_iface,
        &gr->fifos[1].gr_iface,
    };

    for (size_t n = 0; n < gr->num_filters; n++) {
        struct grabber_filter *filt = gr->filters[n];
        if (filt->fns->init && !filt->fns->init(filt, ifaces, 2)) {
            pthread_mutex_lock(&gr->fifo_mutex);
            gr->error_open = true;
            gr->shutdown = true;
            pthread_mutex_unlock(&gr->fifo_mutex);
            goto done;
        }
    }

    if (strncmp(gr->filename, "fd:", 3) == 0) {
        char *end;
        output_fd = strtoul(gr->filename + 3, &end, 0);
        if (end[0])
            output_fd = -1;
    } else {
        output_fd = open(gr->filename, O_CREAT | O_WRONLY | O_TRUNC | O_BINARY, 0666);
    }

    wbuf_data = malloc(wbuf_size);

    if (output_fd < 0 || !wbuf_data) {
        pthread_mutex_lock(&gr->fifo_mutex);
        gr->error_open = true;
        gr->shutdown = true;
        pthread_mutex_unlock(&gr->fifo_mutex);
        goto done;
    }

    struct wbuf hdrbuf = {
        .ptr = wbuf_data,
        .size = wbuf_size,
    };

    // section header block
    size_t pos = 0;
    wbuf_write32(&hdrbuf, 0x0A0D0D0A); // block type
    wbuf_write32(&hdrbuf, 0); // block total length
    wbuf_write32(&hdrbuf, 0x1A2B3C4D); // byte order magic
    wbuf_write32(&hdrbuf, 1); // version
    wbuf_write64(&hdrbuf, -1); // section length
    // options end
    wbuf_write32(&hdrbuf, 0);
    // block end
    write_pcapng_block_size(&hdrbuf, pos);

    // Note: we write 2 interface blocks for both directions. But we could also
    //       just use 1 interface and set the inbound/outbound flags.
    //       Using separate interfaces lets us set different names, though.
    for (int n = 0; n < 2; n++) {
        // interface description block
        pos = hdrbuf.pos;
        wbuf_write32(&hdrbuf, 1);
        wbuf_write32(&hdrbuf, 0);
        wbuf_write32(&hdrbuf, link_type); // LinkType
        wbuf_write32(&hdrbuf, 0); // SnapLen
        // option: if_fcslen
        wbuf_write16(&hdrbuf, 13); // if_fcslen
        wbuf_write16(&hdrbuf, 1); // 1 byte length
        wbuf_write8(&hdrbuf, 4); // value: 4 bytes
        wbuf_write_pad32(&hdrbuf);
        // option: if_name
        const char *if_name = n == 0 ? "Port A" : "Port B";
        wbuf_write16(&hdrbuf, 2); // if_name
        wbuf_write16(&hdrbuf, strlen(if_name)); // length
        wbuf_write(&hdrbuf, if_name, strlen(if_name));
        wbuf_write_pad32(&hdrbuf);
        // option: if_tsresol (timestamp resolution)
        wbuf_write16(&hdrbuf, 9); // if_tsresol
        wbuf_write16(&hdrbuf, 1); // 1 byte length
        wbuf_write8(&hdrbuf, 9); // value: 10^-9 => nanoseconds
        wbuf_write_pad32(&hdrbuf);
        // options end
        wbuf_write32(&hdrbuf, 0);
        // block end
        write_pcapng_block_size(&hdrbuf, pos);
    }

    flush_wbuf_to_pipe(gr, output_fd, &hdrbuf);

    struct wbuf buf = {
        .ptr = wbuf_data,
        .size = wbuf_size,
    };

    while (1) {
        if (buf.size - buf.pos < MAX_PCAPNG_PACKET_SIZE)
            flush_wbuf_to_pipe(gr, output_fd, &buf);

        bool doexit;
        struct grabber_packet *pkt =
            packet_fifo_read_next(gr, buf.pos == 0, &doexit);

        if (!pkt) {
            // No new packet, so just flush and then wait.
            flush_wbuf_to_pipe(gr, output_fd, &buf);
            if (doexit)
                break;
            continue;
        }

        for (size_t n = 0; n < gr->num_filters; n++) {
            if (!gr->filters[n]->fns->filter(gr->filters[n], pkt)) {
                pthread_mutex_lock(&gr->fifo_mutex);
                gr->error_write = true;
                gr->shutdown = true;
                pthread_mutex_unlock(&gr->fifo_mutex);
                goto done;
            }

            if (!pkt->iface)
                break; // dropped
        }

        if (!pkt->iface)
            break; // dropped

        uint8_t *packet_data = pkt->data;
        uint8_t *pcap_data = packet_data;
        size_t pcap_len = pkt->size;
        // The ethernet link type doesn't want the preamble/SFD.
        if (link_type == LINKTYPE_ETHERNET) {
            if (pcap_len >= 8) {
                pcap_data += 8;
                pcap_len -= 8;
            }
        }

        // a pcapng packet
        pos = buf.pos;
        wbuf_write32(&buf, 6);
        wbuf_write32(&buf, 0);
        wbuf_write32(&buf, pkt->iface->port); // interface ID
        wbuf_write32(&buf, pkt->time_ns >> 32); // timestamp high
        wbuf_write32(&buf, pkt->time_ns & UINT32_MAX); // timestamp low
        wbuf_write32(&buf, pcap_len); // packet length (captured)
        wbuf_write32(&buf, pcap_len); // packet length (original)
        wbuf_write(&buf, pcap_data, pcap_len);
        wbuf_write_pad32(&buf);
        // option: packet flags
        wbuf_write16(&buf, 2); // epb_flags
        wbuf_write16(&buf, 4); // length
        uint32_t flags = 0;
        // Note: there are many other errors you could flag (it's unclear
        // whether this really helps with anything).
        if (pkt->size < 7 || memcmp(pkt->data, "UUUUUUU", 7) != 0)
            flags |= 1u << 30; // "preamble error"
        if (pkt->size < 8 || pkt->data[7] != 0xD5)
            flags |= 1u << 29; // "start frame delimiter error"
        if (pkt->fcs_error)
            flags |= 1u << 24; // "crc error"
        if (pkt->symbol_error)
            flags |= 1u << 31; // "symbol error"
        // (depends on ethernet speed; use lowest tolerated gap for gigabit)
        if (pkt->interpacket_frame_gap < 8)
            flags |= 1u << 27; // "wrong Inter Frame Gap error"
        if (flags)
            gr->fifos[pkt->iface->port].broken_packets++;
        wbuf_write32(&buf, flags);
        // option: dropped packet count
        wbuf_write16(&buf, 4); // epb_dropcount
        wbuf_write16(&buf, 8); // length
        wbuf_write64(&buf, pkt->dropped_inc);
        // option: text comment (we can use this to add any information
        // without having to write a dissector; although new option types
        // using "native" values instead of text could be added officially)
        size_t comm_len = strlen(pkt->comments);
        // Drop trailing \n, because it looks bad in Wireshark.
        if (comm_len > 0 && pkt->comments[comm_len - 1] == '\n') {
            pkt->comments[comm_len - 1] = '\0';
            comm_len--;
        }
        if (comm_len) {
            wbuf_write16(&buf, 1); // opt_comment
            wbuf_write16(&buf, comm_len); // length
            wbuf_write(&buf, pkt->comments, comm_len);
            wbuf_write_pad32(&buf);
        }
        // options end
        wbuf_write32(&buf, 0);
        // block end
        write_pcapng_block_size(&buf, pos);
    }

done:

    if (output_fd >= 0)
        close(output_fd);
    free(wbuf_data);

    return NULL;
}

static void transmit_packet(struct grabber *gr, struct packet_fifo *fifo,
                            uint8_t *data, size_t size)
{
    struct sc_info info;

    // Yes, decode_packed_frames() could still pass such frames.
    if (size < sizeof(info)) {
        LOG(gr, "port %u: error: discarding broken frame (%zd bytes)\n",
            fifo->interface, size);
        return;
    }

    memcpy(&info, data + size - sizeof(info), sizeof(info));

    if (info.magic != 0xABCD) {
        LOG(gr, "port %u: error: discarding broken frame (no footer)\n",
            fifo->interface);
        return;
    }

    size_t packet_space = size - sizeof(info);
    size_t packet_len = info.payload_bytecount;
    if (packet_space != ((packet_len  + 3) & (~(size_t)3))) {
        LOG(gr, "port: %u: error: mismatching packet payload size: %zd vs. %zd\n",
            fifo->interface, packet_space, packet_len);
        // FIFO consumer must know packet allocation size, so this is mandatory.
        info.payload_bytecount = packet_space;
    }

    assert(!(info.errors & (1 << 14))); // caller should have filtered this
    assert(packet_space <= MAX_ETH_FRAME_SIZE);

    // In particular, write the footer as header.
    bool ok = byte_fifo_write_atomic_2(&fifo->data, &info, sizeof(info),
                                       data, size - sizeof(info));

    pthread_mutex_lock(&gr->fifo_mutex);

    // with mod32 wraparound
    fifo->stats.hw_dropped += info.packet_counter - fifo->hw_last_seq - 1;
    fifo->hw_last_seq = info.packet_counter;
    // Don't report bogus missing frames at the start.
    if (!fifo->frames_written)
        fifo->stats.hw_dropped = 0;

    uint64_t ts = SC_INFO_TIMESTAMP(info);

    // Sample the first timestamp. Do this here, where it's roughly at the time
    // when we receive the first packet and know its device timestamp. Since the
    // system clock will deviate anyway, determining the exact time (including
    // latency from USB) is probably not worth the trouble.
    if (!gr->system_start_time)
        gr->system_start_time = get_time_us() * 1000 - ts;

    if (ts <= fifo->last_hw_ts) {
        LOG(gr, "port %u: warning: hardware packet time is going backwards: "
            "0x%"PRIx64" -> 0x%"PRIx64"\n",
            fifo->interface, fifo->last_hw_ts, ts);
        fifo->stats.ts_problems++;
    }
    fifo->last_hw_ts = ts;

    if (ok) {
        fifo->frames_written++;
        pthread_cond_signal(&gr->fifo_wakeup);
    } else {
        fifo->stats.sw_dropped++;
    }

    fifo->stats.hw_packet_counter = fifo->hw_last_seq;

    pthread_mutex_unlock(&gr->fifo_mutex);
}

static void decode_packed_frames(struct grabber *gr, int interface,
                                 uint8_t *buf, size_t size)
{
    struct packet_fifo *fifo = &gr->fifos[interface];

    if (fifo->initial_sync < 10) {
        fifo->initial_sync++;
        return;
    }

    if (size < sizeof(struct packet_footer)) {
        LOG(gr, "port %u: error: short USB packet\n", fifo->interface);
        return;
    }

    struct packet_footer footer;
    size_t payload_size = size - sizeof(footer);
    memcpy(&footer, buf + payload_size, sizeof(footer));

    if (footer.magic != 0x63E7) {
        LOG(gr, "port %u: error: incorrect USB footer magic: 0x%x\n",
            fifo->interface, footer.magic);
        return;
    }

    if (fifo->synced && footer.seq_counter != (uint16_t)(fifo->seq_counter + 1)) {
        LOG(gr, "port %u: warning: packet counter going backwards: %u -> %u\n",
            fifo->interface, fifo->seq_counter, footer.seq_counter);
    }
    fifo->seq_counter = footer.seq_counter;

    // Idle frames.
    if (footer.last_frame_ptr == 0xFFFFu) {
        if (size != 16) {
            LOG(gr, "port %u: error: broken frame of size %zu\n",
                fifo->interface, size);
            return;
        }
        uint32_t i[2];
        memcpy(i, buf, 8);
        // ah yes, we have some sort of mixed-endian
        uint64_t ts = (((uint64_t)i[0]) << 32) | i[1];

        pthread_mutex_lock(&gr->fifo_mutex);
        if (ts <= fifo->last_hw_ts) {
            LOG(gr, "port %u: warning: hardware idle time is going backwards: "
                "ts=%"PRIx64" fifo->last_hw_ts=%"PRIx64"\n",
                fifo->interface, ts, fifo->last_hw_ts);
            fifo->stats.ts_problems++;
        }
        fifo->last_hw_ts = ts;
        pthread_cond_signal(&gr->fifo_wakeup);
        pthread_mutex_unlock(&gr->fifo_mutex);
        fifo->synced = true;
        return;
    }

    // May happen if FX3 sends us a partial packet when connecting.
    // Probably should not happen, but it is unknown how the start gets lost.
    if (!fifo->synced && footer.last_frame_ptr > payload_size)
        return;

    if (footer.last_frame_ptr > payload_size || (footer.last_frame_ptr & 3)) {
        LOG(gr, "port: %u: error: invalid footer: %04zx/%04x\n", fifo->interface,
            size, footer.last_frame_ptr);
        return;
    }

    // pos_list[first_packet..MAX_FRAMES_PER_PACKET-1]
    // Each entry points to the start of a frame (last one is partial or the end).
    int32_t pos_list[MAX_FRAMES_PER_PACKET];
    size_t first_packet = MAX_FRAMES_PER_PACKET;

    // Invariant: points to the start of the last partial frame in the USB packet.
    int32_t pos;

    if (footer.last_frame_ptr) {
        // Search for all frames.
        pos = footer.last_frame_ptr;
        while (1) {
            assert(first_packet > 0);
            pos_list[--first_packet] = pos;

            struct sc_info info;
            if (pos < sizeof(info))
                break;

            memcpy(&info, buf + pos - sizeof(info), sizeof(info));
            if (info.magic != 0xABCD) {
                LOG(gr, "port %u: error: discarding packet with broken magic\n",
                    fifo->interface);
                return;
            }
            if (info.errors & (1 << 14)) {
                LOG(gr, "port: %u: warning: hardware FIFO overflow encountered\n",
                    fifo->interface);
                // Discard this, and all before.
                fifo->synced = false;
                fifo->split_buf_size = 0;
                pthread_mutex_lock(&gr->fifo_mutex);
                fifo->stats.overflows++;
                pthread_mutex_unlock(&gr->fifo_mutex);
                return;
            }
            if (info.payload_bytecount >= sizeof(fifo->split_buf)) {
                LOG(gr, "port %u: error: discarding packet with broken frame size\n",
                    fifo->interface);
                return;
            }
            int32_t psize = (info.payload_bytecount + 3) & (~(size_t)3);
            if (psize > pos - sizeof(info))
                break;
            pos = pos - sizeof(info) - psize;
        }
    } else {
        // Special case: there is no frame footer in the entire packet.
        pos = payload_size;
    }

    if (pos > 0) {
        if (sizeof(fifo->split_buf) - fifo->split_buf_size < pos) {
            LOG(gr, "port %u: error: discarding packet with overlong split frame (head)\n",
                fifo->interface);
            return;
        }
        memcpy(fifo->split_buf + fifo->split_buf_size, buf, pos);
        fifo->split_buf_size += pos;
    }

    // Discard previous split packet if this is the first packet.
    if (!fifo->synced)
        fifo->split_buf_size = 0;

    // Terminate previous split packet (complete if another frame is started).
    if (fifo->split_buf_size > 0 && MAX_FRAMES_PER_PACKET - first_packet > 0) {
        transmit_packet(gr, fifo, fifo->split_buf, fifo->split_buf_size);
        fifo->split_buf_size = 0;
    }

    // Transmit complete frames.
    for (size_t n = first_packet + 1; n < MAX_FRAMES_PER_PACKET; n++) {
        transmit_packet(gr, fifo, buf + pos_list[n - 1],
                        pos_list[n] - pos_list[n - 1]);
    }

    // Trailing partial last frame (if any).
    if (MAX_FRAMES_PER_PACKET - first_packet > 0) {
        size_t offset = pos_list[MAX_FRAMES_PER_PACKET - 1];
        size_t len = payload_size - offset;
        if (sizeof(fifo->split_buf) - fifo->split_buf_size < len) {
            LOG(gr, "port %u: error: discarding packet with overlong split frame (tail)\n",
                fifo->interface);
            return;
        }
        memcpy(fifo->split_buf + fifo->split_buf_size, buf + offset, len);
        fifo->split_buf_size += len;
    }

    fifo->synced = true;
}

static void on_receive(struct usb_ep *ep, void *data, size_t size)
{
    struct grabber *gr = ep->user_data;
    int interface = ep->ep == EPs[0] ? 0 : 1;

    decode_packed_frames(gr, interface, data, size);
}

static void on_error(struct usb_ep *ep, enum libusb_error error)
{
    struct grabber *gr = ep->user_data;

    if (error == LIBUSB_ERROR_NO_DEVICE) {
        pthread_mutex_lock(&gr->fifo_mutex);
        gr->error_discon = true;
        gr->shutdown = true;
        pthread_cond_signal(&gr->fifo_wakeup);
        pthread_mutex_unlock(&gr->fifo_mutex);
    }
}

void grabber_read_status(struct grabber *gr, struct grabber_status *out_stats)
{
    pthread_mutex_lock(&gr->fifo_mutex);
    *out_stats = (struct grabber_status) {
        .fatal_error = gr->error_discon ? "USB disconnected" :
                       gr->error_open ? "failed to open file" :
                       gr->error_write ? "failed to write to file" :
                       NULL,
        .bytes_written = gr->bytes_written,
        .port_stats = {gr->fifos[0].stats, gr->fifos[1].stats},
    };
    pthread_mutex_unlock(&gr->fifo_mutex);
}

void grabber_destroy(struct grabber *gr)
{
    if (!gr)
        return;

    for (size_t n = 0; n < 2; n++)
        usb_ep_remove(&gr->eps[n]);

    pthread_mutex_lock(&gr->fifo_mutex);
    gr->shutdown = true;
    pthread_cond_signal(&gr->fifo_wakeup);
    pthread_mutex_unlock(&gr->fifo_mutex);

    if (gr->writer_thread_valid)
        pthread_join(gr->writer_thread, NULL);

    for (size_t n = 0; n < gr->num_filters; n++)
        grabber_filter_destroy(gr->filters[n]);
    free(gr->filters);

    for (size_t n = 0; n < 2; n++)
        byte_fifo_dealloc(&gr->fifos[n].data);

    assert(gr->device->grabber == gr);
    gr->device->grabber = NULL;

    pthread_mutex_destroy(&gr->fifo_mutex);
    pthread_cond_destroy(&gr->fifo_wakeup);
    free(gr->filename);
    free(gr);
}

int grabber_start(struct global *global, struct grabber_options *opts)
{
    assert(!opts->device->grabber);

    size_t usb_buf_num = opts->usb_buffer / 2 / MAX_USB_FRAME_SIZE;
    size_t fifo_buf_size = round_down_power_of_2(opts->soft_buffer);
    if (!usb_buf_num || !fifo_buf_size)
        return -1; // buffer not large enough

    int error = -1;
    struct grabber *gr = XALLOC_PTRTYPE(gr);
    pthread_mutex_init(&gr->fifo_mutex, NULL);
    pthread_cond_init(&gr->fifo_wakeup, NULL);

    gr->log = global->log;
    gr->device = opts->device;
    gr->device->grabber = gr;

    gr->filename = xstrdup(opts->filename);

    XEXTEND_ARRAY(gr->filters, 0, opts->num_filters);
    for (size_t n = 0; n < opts->num_filters; n++)
        gr->filters[gr->num_filters++] = opts->filters[n];

    int linktype = opts->linktype;
    if (!linktype)
        linktype = LINKTYPE_ETHERNET_MPACKET;
    if (linktype != LINKTYPE_ETHERNET_MPACKET &&
        linktype != LINKTYPE_ETHERNET)
        goto done; // not supported

    for (size_t n = 0; n < 2; n++) {
        struct usb_ep *ep = &gr->eps[n];

        ep->ep = EPs[n];
        ep->dev = opts->device->dev;
        ep->on_receive = on_receive;
        ep->on_error = on_error;
        ep->user_data = gr;

        struct packet_fifo *fifo = &gr->fifos[n];
        *fifo = (struct packet_fifo){
            .interface = n,
            .gr_iface = {
                .port = n,
                .pcap_linktype = linktype,
            },
        };

        if (!byte_fifo_alloc(&fifo->data, fifo_buf_size))
            goto done;

        if (!usb_ep_in_add(global->usb_thr, ep, usb_buf_num, MAX_USB_FRAME_SIZE))
            goto done;

        fifo->stats.sw_buffer_sz_max = fifo->data.size;
    }

    gr->writer_thread_valid = true;
    if (pthread_create(&gr->writer_thread, NULL, writer_thread, gr)) {
        gr->writer_thread_valid = false;
        goto done;
    }

    error = 0;

done:
    if (error)
        grabber_destroy(gr);
    return error;
}

void grabber_filter_destroy(struct grabber_filter *filt)
{
    if (!filt)
        return;
    filt->fns->destroy(filt);
}

// Attempt to append the given string to the current packet comments.
void grabber_packet_add_comment(struct grabber_packet *pkt, const char *str)
{
    size_t len = strlen(pkt->comments);
    snprintf_append(pkt->comments, sizeof(pkt->comments), len, "%s\n", str);
}
