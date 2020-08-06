// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GLOBAL_H_
#define GLOBAL_H_

#include <stdio.h>

#include "utils.h"

// Stuff in here whatever needs to be global. Be mindful of issues like
// synchronization from multiple threads, and reducing interdependence of
// components.
// Since we want any code that wants to depend on this to be library-safe, there
// will never be a global variable of this type.
struct global {
    // All of these fields are fixed at init time. All must be inherently
    // thread-safe.

    // All terminal output should go through this.
    struct logfn log;

    // Same as log, but for lower verbosity messages.
    struct logfn loghint;

    // We always need USB anyway, so it may as well be global.
    struct usb_thread *usb_thr;
};

#endif
