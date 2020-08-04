// SPDX-License-Identifier: GPL-3.0-or-later
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "cmd_parser.h"
#include "json.h"
#include "json_helpers.h"
#include "utils.h"

static void json_log(void *opaque, size_t loc, const char *msg)
{
    struct logfn lfn = *(struct logfn *)opaque;
    logline(lfn, "json: %s\n", msg);
}

static char **split_spaces(const char *s)
{
    static const char spaces[] = " \t\n\r";

    char **res = NULL;
    size_t res_n = 0;

    do {
        // Leading space
        s += strspn(s, spaces);
        const char *start = s;
        s += strcspn(s, spaces);
        if (s == start && !s[0] && res_n)
            break; // trailing space
        char *word = strndup(start, s - start);
        if (!word)
            goto fail;
        if (!EXTEND_ARRAY(res, res_n, 1)) {
            free(word);
            goto fail;
        }
        res[res_n++] = word;
    } while (s[0]);

    // terminating NULL
    if (!EXTEND_ARRAY(res, res_n, 1))
        goto fail;
    res[res_n++] = NULL;

    return res;

fail:
    for (size_t n = 0; n < res_n; n++)
        free(res[n]);
    free(res);
    return NULL;
}

// Parse a user-provided value.
//  log: for error messages
//  name: name of the value for user log messages (parameter or option name)
//  def: metadata for the parameter/option
//  el: user-provided value
//  data: overwritten with returned parsed data (may have pointers to el)
//  return: true on success
static bool parse_value(struct logfn log, const char *name,
                        const struct command_param_def *def, struct json_tok *el,
                        struct command_param *data)
{
    struct json_tok tmp;

    if (!el && def->def) {
        tmp.type = JSON_TYPE_STRING;
        tmp.u.str = (char *)def->def;
        el = &tmp;
    }

    if (!el) {
        logline(log, "error: %s is required.\n", name);
        return false;
    }

    *data = (struct command_param){ .def = def };

    switch (def->type) {
    case COMMAND_PARAM_TYPE_STR:
        if (el->type == JSON_TYPE_STRING) {
            data->p_str = el->u.str;
        } else {
            logline(log, "error: %s must be a string.\n", name);
            return false;
        }
        break;
    case COMMAND_PARAM_TYPE_INT64:
    case COMMAND_PARAM_TYPE_INT64_S: {
        if (el->type == JSON_TYPE_STRING) {
            char *val = el->u.str;
            int64_t mult = 1;
            char *end = val + strlen(val);
            if (def->type == COMMAND_PARAM_TYPE_INT64_S) {
                if (str_ends_with(val, "kib", &end)) {
                    mult = 1024;
                } else if (str_ends_with(val, "mib", &end)) {
                    mult = 1024 * 1024;
                } else if (str_ends_with(val, "gib", &end)) {
                    mult = 1024 * 1024 * 1024;
                }
            }
            errno = 0;
            char *end_num = NULL;
            int64_t ival = strtoll(val, &end_num, 0);
            if (end_num != end || end == val || errno) {
                logline(log, "error: %s requires an integer, not '%s'.\n",
                        name, val);
                return false;
            }
            if ((ival < 0 && mult > 1) || (ival > 0 && ival > INT64_MAX / mult)) {
                logline(log, "error: %s with value %s overflows.\n", name, val);
                return false;
            }
            data->p_int = ival * mult;
        } else if (el->type == JSON_TYPE_DOUBLE) {
            data->p_int = el->u.d;
        } else {
            logline(log, "error: %s requires an integer.\n", name);
            return false;
        }
        break;
    }
    case COMMAND_PARAM_TYPE_BOOL:
        if (el->type == JSON_TYPE_BOOL) {
            data->p_bool = el->u.b;
        } else if (el->type == JSON_TYPE_STRING) {
            char *val = el->u.str;
            if (strcmp(val, "true") == 0) {
                data->p_bool = true;
            } else if (strcmp(val, "false") == 0) {
                data->p_bool = false;
            } else {
                logline(log, "error: %s requires true or false, not '%s'.\n",
                        name, val);
                return false;
            }
        } else {
            logline(log, "error: %s requires bool.\n", name);
            return false;
        }
        break;
    case COMMAND_PARAM_TYPE_JSON:
        if (el == &tmp) {
            // (because tmp is a stack allocated value)
            logline(log, "error: %s cannot have default value.\n", name);
            return false;
        }
        data->p_json = el;
        break;
    default: assert(0);
    }

    return true;
}

void command_dispatch(const struct command_def *cmds, struct command_ctx *ctx,
                      const char *cmd)
{
    char mem[8192];
    struct json_tok *jcmd = NULL;
    char **args = NULL;
    size_t num_args = 0;
    const char *cmdname = NULL;

    ctx->seq_id = -1;
    ctx->success = false;

    // Assume JSON if it starts with '{'.
    if (cmd && cmd[0] == '{') {
        struct json_parse_opts jopts = {
            .msg_cb = json_log,
            .msg_cb_opaque = &ctx->log,
        };
        struct json_tok *obj = json_parse(cmd, mem, sizeof(mem), &jopts);
        if (!obj || obj->type != JSON_TYPE_OBJECT)
            return;

        cmdname = json_get_string(obj, "command", "");
        ctx->seq_id = json_get_double(obj, "id", -1);

        jcmd = obj;
    } else {
        args = split_spaces(cmd);

        for (size_t n = 0; args && args[n]; n++)
            num_args++;
        if (num_args > 0)
            cmdname = args[0];
    }

    if (!cmdname) {
        LOG(ctx, "missing command name\n");
        goto done;
    }

    const struct command_def *cmd_def = NULL;
    for (size_t n = 0; cmds[n].name; n++) {
        if (strcmp(cmdname, cmds[n].name) == 0) {
            cmd_def = &cmds[n];
            break;
        }
    }

    if (!cmd_def) {
        if (cmdname[0])
            LOG(ctx, "error: command %s not found\n", cmdname);
        goto done;
    }

    struct command_param params[COMMAND_MAX_PARAMS];
    size_t num_params = 0;
    size_t consumed_args = 1; // first is command name

    for (size_t p = 0; cmd_def->params[p].type; p++) {
        assert(p < COMMAND_MAX_PARAMS);
        const struct command_param_def *def = &cmd_def->params[p];

        char *param_name =
            stack_sprintf(80, "parameter %zu/%s (%s)", p, def->name, def->desc);

        struct json_tok tmp;
        struct json_tok *el = NULL;

        if (jcmd) {
            el = json_get(jcmd, def->name);
        } else {
            if (consumed_args < num_args) {
                tmp.type = JSON_TYPE_STRING;
                tmp.u.str = args[consumed_args++];
                el = &tmp;
            }
        }

        if (!parse_value(ctx->log, param_name, def, el, &params[num_params++]))
            goto done;
    }

    if (!jcmd && consumed_args < num_args) {
        LOG(ctx, "error: %zu unused arguments (starting with '%s').\n",
            num_args - consumed_args, args[consumed_args]);
        goto done;
    }

    ctx->success = true;
    cmd_def->cb(ctx, params, num_params);

done:
    for (size_t n = 0; args && args[n]; n++)
        free(args[n]);
    free(args);
}

static const char *get_type_help(enum command_param_type t)
{
    switch (t) {
    case COMMAND_PARAM_TYPE_STR: return "string";
    case COMMAND_PARAM_TYPE_INT64: return "integer";
    case COMMAND_PARAM_TYPE_INT64_S: return "integer, with kib/mib/gib suffix";
    case COMMAND_PARAM_TYPE_BOOL: return "bool: true/false";
    case COMMAND_PARAM_TYPE_JSON: return "anything";
    }
    return "?";
}

void command_list_help(const struct command_def *cmds, struct logfn lfn)
{
    logline(lfn, "List of commands:\n");

    for (size_t c = 0; cmds[c].name; c++) {
        const struct command_def *cmd_def = &cmds[c];

        logline(lfn, "  %s: %s\n", cmd_def->name, cmd_def->desc);

        for (size_t p = 0; cmd_def->params[p].type; p++) {
            assert(p < COMMAND_MAX_PARAMS);
            const struct command_param_def *def = &cmd_def->params[p];

            logline(lfn, "    %-10s %s (%s, %s%s)\n", def->name, def->desc,
                    get_type_help(def->type),
                    def->def ? "default: " : "",
                    def->def ? def->def : "required parameter");
        }
    }

    logline(lfn, "Syntax: command param1-value param2-value...\n");
    logline(lfn, "Or: {\"command\":\"cmd-name\",\"param1-name\":\"param1-value\", ...}\n");
}

static const struct option_def *find_opt(const struct option_def *opts,
                                         const char *name)
{
    for (size_t n = 0; opts[n].name; n++) {
        if (strcmp(opts[n].name, name) == 0)
            return &opts[n];
    }
    return NULL;
}

bool options_set_json(struct logfn log, const struct option_def *opts,
                      void *target, const char *name, struct json_tok *value,
                      unsigned flags)
{
    const struct option_def *opt = find_opt(opts, name);
    if (!opt) {
        logline(log, "error: option %s not found\n", name);
        return false;
    }

    char *logname = stack_sprintf(80, "option %s", opt->name);

    if ((flags & COMMAND_FLAG_RUNTIME) && !(opt->flags & COMMAND_FLAG_RUNTIME)) {
        logline(log, "error: %s cannot be changed at runtime\n", logname);
        return false;
    }

    if (opt->type == COMMAND_PARAM_TYPE_JSON) {
        // meh, too messy (would need to recursively copy and allocate)
        logline(log, "error: %s JSON not supported\n", logname);
        return false;
    }

    struct command_param_def def = {
        .type = opt->type,
    };

    void *field_ptr = (char *)target + opt->offset;

    struct command_param pval;
    if (!parse_value(log, logname, &def, value, &pval))
        return false;

    switch (opt->type) {
    case COMMAND_PARAM_TYPE_STR:
        free(*(char **)field_ptr);
        *(char **)field_ptr = xstrdup(pval.p_str);
        break;
    case COMMAND_PARAM_TYPE_INT64:
    case COMMAND_PARAM_TYPE_INT64_S:
        *(int64_t *)field_ptr = pval.p_int;
        break;
    case COMMAND_PARAM_TYPE_BOOL:
        *(bool *)field_ptr = pval.p_bool;
        break;
    default: assert(0);
    }

    return true;
}

bool options_set_str(struct logfn log, const struct option_def *opts,
                     void *target, const char *name, const char *value,
                     unsigned flags)
{
    struct json_tok jstr = {
        .type = JSON_TYPE_STRING,
        .u.str = (char *)value,
    };

    return options_set_json(log, opts, target, name, &jstr, flags);
}

bool options_parse(struct logfn log, const struct option_def *opts,
                   void *target, char **argv)
{
    if (argv[0])
        argv++; // skip program name

    while (argv[0]) {
        int skip = 1;
        char *arg = argv[0];

        if (strncmp(arg, "--", 2) != 0)
            goto error; // we don't support any non-option arguments yet

        char optname[80];
        char *val = strchr(arg, '=');
        if (val) {
            snprintf(optname, sizeof(optname), "%.*s", (int)(val - arg), arg);
            val += 1;
        } else {
            snprintf(optname, sizeof(optname), "%s", arg);
        }

        const struct option_def *opt = find_opt(opts, optname + 2);
        if (!opt) {
            logline(log, "error: option %s not found\n", optname);
            goto error;
        }

        // "Flag" options do not need an argument, but can have one.
        if (!val && opt->type == COMMAND_PARAM_TYPE_BOOL) {
            if (!argv[1] || strncmp(argv[1], "--", 2) == 0)
                val = "true";
        }

        if (!val) {
            val = argv[1];
            skip += 1;
        }

        if (!val) {
            logline(log, "error: argument expected\n");
            goto error;
        }

        if (!options_set_str(log, opts, target, opt->name, val, 0))
            goto error;

        argv += skip;
    }

    return true;

error:
    logline(log, "error: error at argument '%s'\n", argv[0]);
    logline(log, "Usage:\n");
    for (const struct option_def *opt = opts; opt->name; opt++) {
        logline(log, "  --%-*s%s (%s)\n", 20, opt->name, opt->desc,
                get_type_help(opt->type));
    }
    logline(log, "Usually: --optname optvalue\n");
    logline(log, "Bool options implicitly use 'true' if no value is provided.\n");
    logline(log, "Alternative syntax: --optname=optvalue\n");
    return false;
}

void options_free(const struct option_def *opts, void *target)
{
    for (const struct option_def *opt = opts; opt->name; opt++) {
        void *field_ptr = (char *)target + opt->offset;

        if (opt->type == COMMAND_PARAM_TYPE_STR) {
            free(*(char **)field_ptr);
            *(char **)field_ptr = NULL;
        }
    }
}

void options_init_allocs(const struct option_def *opts, void *target)
{
    for (const struct option_def *opt = opts; opt->name; opt++) {
        void *field_ptr = (char *)target + opt->offset;

        if (opt->type == COMMAND_PARAM_TYPE_STR) {
            char *val = *(char **)field_ptr;
            *(char **)field_ptr = xstrdup(val ? val : "");
        }
    }
}
