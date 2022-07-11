// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GRABBER_H_
#define GRABBER_H_

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct global;

struct grabber_interface {
    unsigned port;                          // 0=port A, 1=port B
    unsigned pcap_linktype;                 // one of LINKTYPE_ETHERNET_*
};

struct grabber_packet {
    struct grabber_interface *iface;        // which port
    uint8_t *data;                          // raw packet data
    size_t size;                            // size of data
    uint64_t time_ns;                       // capture time (UTC, nanoseconds)
    uint64_t dropped_inc;                   // dropped frames since previous
                                            // packet on this iface
    uint16_t interpacket_frame_gap;
    bool fcs_error, symbol_error;
    // pcapng comments. Since Wireshark discards multiple comments (even though
    // the format allows multiple comments), it discards all but the first, so
    // the comments are to be '\n'-separated.
    char comments[1024];
};

// If grabber_packet.interpacket_frame_gap has this value, the frame gap is
// larger than what the hardware can report.
#define INTERPACKET_FRAME_GAP_UNKNOWN UINT16_MAX

// "Normal", can show FCS, but no preamble/sfd. (We include FCS.)
#define LINKTYPE_ETHERNET 1
// This makes wireshark show the preamble/fcs as "frame preemption" frame, but
// it's exactly what we want, and better than LINKTYPE_NETANALYZER_TRANSPARENT.
// It's relatively new (2017/2018).
#define LINKTYPE_ETHERNET_MPACKET 274

// Filters can inspect, change, drop, or just pass through captured packets.
// Main use is analyzing and annotating packet contents.
struct grabber_filter {
    const struct grabber_filter_fns *fns;

    // Free use by filter implementation.
    void *priv;
};

struct grabber_filter_fns {
    // If non-NULL, this is called once on capture start.
    // It is likely that num_ifaces==2 always. If we're ever capturing from
    // multiple devices, each device will have its own grabber thread.
    // The pcap_linktype fields are the same for all interfaces.
    //  ifaces, num_ifaces: all interfaces participating in this
    //  returns: success
    bool (*init)(struct grabber_filter *filt,
                 struct grabber_interface **ifaces, size_t num_ifaces);

    // Process a newly captured packet.
    // Rules:
    //  - can do only 1->[0,1] filtering (no packet splitting or generation, but
    //    dropping is allowed)
    //  - pkt can be mutated (changing any fields)
    //  - memory referenced by pkt can be written to, but not reallocated (if
    //    you need to add comments are enlarge the packet, allocate some private
    //    memory)
    //  - pkt and memory referenced by it are only valid until filter() returns
    //    (later filters will modify it)
    //  - memory set by filter() in the returned pkt must stay valid until the
    //    next filter() call, or capturing stops
    //  - the filter is invoked for packets in the same direction, in their
    //    absolute time order, and on the same thread
    // To drop a packet, set *pkt=(struct grabber_packet){0}.
    // Returns false on fatal errors.
    bool (*filter)(struct grabber_filter *filt, struct grabber_packet *pkt);

    // Deallocate private data and filt itself.
    void (*destroy)(struct grabber_filter *filt);
};

struct grabber_options {
    const char *filename;                   // pcapng output file (NULL to discard)
    size_t soft_buffer;                     // buffer between USB and file writer
                                            // (rounded down)
    size_t usb_buffer;                      // libusb buffers (rounded down)
    int linktype;                           // LINKTYPE_*, 0 to pick a default
    bool strip_fcs;                         // Remove the FCS (CRC) at the end
    struct device *device;
    // Filters to apply in order. The filters are destroyed when capturing stops
    // (always before grabber_destroy() has returned). The array itself is
    // copied. If grabber_start() fails, the filters are also destroyed.
    struct grabber_filter **filters;
    size_t num_filters;
};

struct grabber;

// Returns !=0 on error. The created grabber is set on opts->device->grabber.
int grabber_start(struct global *global, struct grabber_options *opts);

// Stop grabbing, deallocate gr. Unsets it from device->grabber.
void grabber_destroy(struct grabber *gr);

// Per-port stats (one for each physical ethernet connector).
struct grabber_port_stats {
    uint64_t num_packets;   // number of total packets according to hardware
    uint64_t num_bytes;     // number of total packet bytes received via USB
    uint64_t sw_frames;     // number of total packets captured (and not dropped)
    uint64_t sw_buffer_num; // number of frames currently in SW buffer
    size_t sw_buffer_sz;    // like sw_buffer_num, but in bytes
    size_t sw_buffer_sz_max;// total size of the sw_buffer
    uint64_t sw_dropped;    // number of packets dropped due to full SW buffer
    uint64_t hw_dropped;    // number of packets dropped in HW or host USB stack
    uint64_t num_crcerr;    // number of packets with incorrect FCS
    uint64_t ts_problems;   // number of broken timestamps (internal problem)
    uint64_t overflows;     // number of known FIFO overflow events
};

struct grabber_status {
    // Set in case the writer failed. Typically failure to open, or full disk.
    // String memory is valid until next grabber_read_status()/grabber_destroy().
    const char *fatal_error;

    uint64_t bytes_written; // number of bytes written to output file
    struct grabber_port_stats port_stats[2];
};

// Read status (errors and stats). Poll this frequently (there is no other error
// notification mechanism, as you want to report stats periodically anyway).
void grabber_read_status(struct grabber *gr, struct grabber_status *out_stats);

// Destroy and deallocate filt.
void grabber_filter_destroy(struct grabber_filter *filt);

// Attempt to append the given string to the current packet comments.
void grabber_packet_add_comment(struct grabber_packet *pkt, const char *str);

#endif
