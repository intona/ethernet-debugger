// SPDX-License-Identifier: GPL-3.0-or-later
#include "filters.h"
#include "grabber.h"
#include "utils.h"

static bool filter(struct grabber_filter *filt, struct grabber_packet *pkt)
{
    if (pkt->interpacket_frame_gap != INTERPACKET_FRAME_GAP_UNKNOWN) {
        grabber_packet_add_comment(pkt,
            stack_sprintf(80, "interpacket_frame_gap=%d",
                          pkt->interpacket_frame_gap));
    }

    if (pkt->dropped_inc) {
        grabber_packet_add_comment(pkt,
            stack_sprintf(80, "dropped=%"PRIu64, pkt->dropped_inc));
    }

    return true;
}

static void destroy(struct grabber_filter *filt)
{
    free(filt);
}

static const struct grabber_filter_fns filter_commenter = {
    .filter = filter,
    .destroy = destroy,
};

struct grabber_filter *filter_commenter_create(void)
{
    struct grabber_filter *filt = XALLOC_PTRTYPE(filt);
    filt->fns = &filter_commenter;
    return filt;
}
