// SPDX-License-Identifier: GPL-3.0-or-later
#include "filters.h"
#include "grabber.h"
#include "utils.h"

struct priv {
    struct logfn log;
    char *out_filename;
    bool wait_0;
    bool seq_locked;
    uint64_t prev_t;
    int prev_port;
    uint32_t prev_seq;
    int prev_num;
    bool problems;
    FILE *out;
};

static bool filter(struct grabber_filter *filt, struct grabber_packet *pkt)
{
    struct priv *p = filt->priv;

    if (pkt->size < (26 + 8) || pkt->fcs_error)
        return true;

    uint8_t *data = pkt->data + 8;

    if (data[12] != 0xBE || data[13] != 0xEF)
        return true;

    if (memcmp(&data[14], &(uint32_t){LATENCY_TESTER_MAGIC}, 4))
        return true;

    uint32_t seq;
    memcpy(&seq, &data[18], 4);

    uint32_t end;
    memcpy(&end, &data[22], 4);

    bool last = end == ~(uint32_t)0;
    if (!last && end) {
        // Corrupted packet? Something else using the ethertype?
        LOG(p, "invalid magic\n");
        return true;
    }

    // Shouldn't happen ever (buggy firmware or packet sorting?)
    if (pkt->time_ns < p->prev_t) {
        LOG(p, "broken time?\n");
        p->problems = true;
    }

    if (!p->seq_locked) {
        if (p->wait_0 && seq != 0)
            return true; // ignore
        if (p->out_filename && p->out_filename[0]) {
            // only start once out file does not exist anymore
            FILE *f = fopen(p->out_filename, "r");
            bool exists = !!f;
            if (f)
                fclose(f);
            if (exists) {
                LOG(p, "File '%s' exists, skipping sequence.\n", p->out_filename);
                return true;
            }
            p->out = fopen(p->out_filename, "w");
            if (p->out) {
                LOG(p, "Opened file '%s' for writing.\n", p->out_filename);
            } else {
                LOG(p, "Failed to open '%s' for writing.\n", p->out_filename);
            }
        }
        LOG(p, "Starting recording sequence...\n");
        p->seq_locked = true;
        p->prev_num = 0;
        p->prev_seq = 0;
        p->problems = false;
    }

    if (p->prev_num == 1) {
        p->prev_num = 0;
        if (p->prev_port == pkt->iface->port) {
            LOG(p, "out of order or dropped packets\n");
            p->problems = true;
        }
        if (seq != p->prev_seq) {
            LOG(p, "unexpected seq. nr.: %"PRIu32" != %"PRIu32"\n",
                seq, p->prev_seq);
            p->prev_num = 1;
            p->problems = true;
        }
        int64_t diff = pkt->time_ns - p->prev_t;
        if (p->prev_port == 1)
            diff = -diff;
        if ((seq % 100) == 99)
            LOG(p, "seq=%"PRIu32" diff=%"PRId64"\n", seq, diff);
        if (last) {
            LOG(p, "Recording sequence finished.\n");
            LOG(p, "Problems detected: %s\n", p->problems ? "yes" : "no");
            p->seq_locked = false;
        }
        if (p->out) {
            fprintf(p->out, "%"PRId64"\n", diff);
            if (last) {
                if (fclose(p->out)) {
                    LOG(p, "Error flushing or closing file '%s'.\n",
                        p->out_filename);
                } else {
                    LOG(p, "File '%s' closed.\n", p->out_filename);
                }
                p->out = NULL;
            }
        }
    } else {
        p->prev_num = 1;
        if (seq < p->prev_seq) {
            LOG(p, "unexpected seq. nr.: %"PRIu32" < %"PRIu32"\n",
                seq, p->prev_seq);
            p->prev_num = 0;
            p->problems = true;
        }
    }

    p->prev_seq = seq;
    p->prev_t = pkt->time_ns;
    p->prev_port = pkt->iface->port;

    return true;
}

static void destroy(struct grabber_filter *filt)
{
    struct priv *p = filt->priv;
    free(p->out_filename);
    free(p);
    free(filt);
}

static const struct grabber_filter_fns filter_commenter = {
    .filter = filter,
    .destroy = destroy,
};

struct grabber_filter *filter_latency_tester_create(struct logfn log,
                                                    const char *out_filename,
                                                    bool wait_0)
{
    struct grabber_filter *filt = XALLOC_PTRTYPE(filt);
    filt->fns = &filter_commenter;
    filt->priv = XALLOC(struct priv);
    struct priv *p = filt->priv;
    p->log = log;
    p->out_filename = xstrdup(out_filename);
    p->wait_0 = wait_0;
    return filt;
}
