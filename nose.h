// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef NOSE_H_
#define NOSE_H_

#include "cmd_parser.h"
#include "global.h"

extern const char version[];
extern const struct command_def command_list[];

void run_init_and_test(struct global *global, char *device, char *serial);

#endif
