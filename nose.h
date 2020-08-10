// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef NOSE_H_
#define NOSE_H_

#include "global.h"

extern const char version[];

void run_init_and_test(struct global *global, char *device, char *serial);

#endif
