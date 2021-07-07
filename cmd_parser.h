// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef CMD_PARSER_H_
#define CMD_PARSER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils.h"

struct command_ctx {
    struct logfn log;               // the one that was passed to the parser
    int64_t seq_id;                 // command reply ID, or -1
    struct json_out *jout;          // if non-NULL, write json command output
    bool success;                   // whether command was successful (already
                                    // set to true when command handler starts)
    void *priv;                     // opaque; set by caller of command_dispatch()
};

enum command_param_type {
    COMMAND_PARAM_TYPE_NONE,        // end of parameter list
    COMMAND_PARAM_TYPE_STR,         // command_param.p_str or char*
    COMMAND_PARAM_TYPE_INT64,       // command_param.p_int or int64_t
    COMMAND_PARAM_TYPE_INT64_S,     // command_param.p_int or int64_t
                                    // a size: parsing allows "mb" etc. suffixes
                                    // cannot be negative, range [0, INT64_MAX]
    COMMAND_PARAM_TYPE_BOOL,        // command_param.p_bool or bool
    COMMAND_PARAM_TYPE_JSON,        // command_param.p_json or struct json_tok*
};

enum command_flags {
    COMMAND_FLAG_RUNTIME    = (1u << 0), // can be changed by options_set()
    COMMAND_FLAG_ALIAS_ONLY = (1u << 1), // only allow values in the aliases[]
                                         // list, reject all others
};

#define COMMAND_MAX_PARAMS 10

struct command_alias_val {
    const char *user_val;
    const char *param_val;
    // desc must be set for options, but is ignored for commands.
    const char *desc;
};

// If {0, 0}, the range is treated the same as {INT64_MIN, INT64_MAX}.
struct command_i64_range {
    int64_t min, max;
};

struct command_param_def {
    const char *name;
    enum command_param_type type;
    const char *def;                // if NULL => non-optional
    const char *desc;
    unsigned flags;                 // bitset of COMMAND_FLAG_*
    // Aliases: replace user input matching .user_val with .param_val.
    // Use PARAM_ALIASES to set this (it also terminates the array correctly).
    const struct command_alias_val *aliases;
    struct command_i64_range irange; // for COMMAND_PARAM_TYPE_INT64[_S]
};

#define PARAM_ALIASES(...) \
    .aliases = (const struct command_alias_val[]){__VA_ARGS__, {0}}

struct command_param {
    const struct command_param_def *def;
    // Could be an union, but let's not.
    int64_t p_int;
    const char *p_str;
    bool p_bool;
    struct json_tok *p_json;
};

struct command_def {
    const char *name;
    const char *desc;
    // params[0]..params[num_params-1] are accessible. num_params depends on
    // command_def.params[] and always has the same value for given command_def
    // (default parameters are filled in; missing non-optional params cause
    // errors). num_params is just for robustness or whatever.
    // ctx is the command_dispatch() parameter.
    void (*cb)(struct command_ctx *ctx, struct command_param *params,
               size_t num_params);
    struct command_param_def params[COMMAND_MAX_PARAMS + 1];
};

// Parses cmd using the command list given by cmds[] (terminated with an all-0
// command_def item). If parsing succeeds, the matching command_def's .cb is
// called, and true is returned.
// ctx must be initialized by the caller. The seq_id and success fields are
// overwritten by the function. jout is also set to NULL if cmd did not use
// json form, otherwise it will write stuff if jout is set to non-NULL by the
// caller. Command callbacks can append new object fields to jout.
void command_dispatch(const struct command_def *cmds, struct command_ctx *ctx,
                      const char *cmd);

// Print human readable help via lfn.
// cmds is like in command_dispatch.
void command_list_help(const struct command_def *cmds, struct logfn lfn,
                       const char *filter, bool filter_exact);

struct option_def {
    const char *name;
    int offset;                     // field offset within option struct
    enum command_param_type type;   // type pointed to by offset
    const char *desc;               // description for help output
    unsigned flags;                 // bitset of COMMAND_FLAG_*
    // Aliases: replace user input matching .user_val with .param_val.
    // Use PARAM_ALIASES to set this (it also terminates the array correctly).
    const struct command_alias_val *aliases;
    struct command_i64_range irange; // for COMMAND_PARAM_TYPE_INT64[_S]
};

// Parse argv and write the result to a struct pointed to by target, using the
// option/field list in opts.
// Options not passed by the user are not touched, so the struct can be pre-
// filled with default values.
// If a string option is set, the old value is free'd with free(). Use
// options_init_allocs() to ensure static strings are malloc'ed.
//  log: for error messages
//  opts: the option definition array
//  target: the user struct, as described by opts
//  argv: as passed to main() (argv[0] is the program name, the array is
//        terminated with a NULL entry)
//  returns: success
bool options_parse(struct logfn log, const struct option_def *opts,
                   void *target, char **argv);

// Set a single option's value. This is quite similar to options_parse(), except
// that it's for 1 option, name and value are separate, and implicit values
// (such as for BOOL options without arguments) are not handled.
//  log, opts, target: as in options_parse()
//  flags:
//      COMMAND_FLAG_RUNTIME: if set, reject setting options that do not have
//                            this flag set
bool options_set_str(struct logfn log, const struct option_def *opts,
                     void *target, const char *name, const char *value,
                     unsigned flags);

// Like options_set_str(), but takes an arbitrary json value.
bool options_set_json(struct logfn log, const struct option_def *opts,
                      void *target, const char *name, struct json_tok *value,
                      unsigned flags);

// Free all fields that use dynamic memory allocation.
void options_free(const struct option_def *opts, void *target);

// This calls xstrdup() on every string option in the target struct. This is
// convenient if you want to provide defaults as static strings, instead of
// having to strdup() them manually at program start. Also properly initializes
// NULL string fields to "".
void options_init_allocs(const struct option_def *opts, void *target);

#endif
