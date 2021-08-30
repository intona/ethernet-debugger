// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef FILTERS_H_
#define FILTERS_H_

#include "grabber.h"
#include "utils.h"

// Shared header file for filter constructors.

struct grabber_filter *filter_commenter_create(void);
struct grabber_filter *filter_latency_tester_create(struct logfn log,
                                                    const char *out_filename,
                                                    bool wait_0);

#define LATENCY_TESTER_MAGIC 0xC001C0FE

#endif
