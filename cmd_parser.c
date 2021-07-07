// SPDX-License-Identifier: GPL-3.0-or-later
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "cmd_parser.h"
#include "json.h"
#include "json_helpers.h"
#include "json_out.h"
#include "utils.h"

static void json_log(void *opaque, size_t loc, const char *msg)
{
    struct logfn lfn = *(struct logfn *)opaque;
    logline(lfn, "json: %s\n", msg);
}

static char map_escape(char r)
{
    switch (r) {
    case '\\': return '\\';
    case '\"': return '\"';
    case '\'': return '\'';
    case ' ':  return ' ';
    case '/':  return '/';
    case 'b':  return '\b';
    case 'f':  return '\f';
    case 'n':  return '\n';
    case 'r':  return '\r';
    case 't':  return '\t';
    }
    return 0;
}

// Split on spaces, but also interpret quotes (") and escapes (\...).
// Somewhat reminiscent of shell.
static char **split_spaces_with_quotes(const char *s)
{
    static const char spaces[] = " \t\n\r";

    char **res = NULL;
    size_t res_n = 0;
    char *tmp = malloc(strlen(s) + 1); // worst case work buffer
    if (!tmp)
        goto fail;

    do {
        // Leading space
        s += strspn(s, spaces);
        const char *end = s + strcspn(s, spaces);
        if (end == s && !end[0] && res_n)
            break; // trailing space

        size_t len = 0;
        char quote = 0;

        while (s[0]) {
            if (s[0] == quote) {
                quote = 0;
                s++;
                continue;
            } else if (!quote && (s[0] == '\"' || s[0] == '\'')) {
                quote = s[0];
                s++;
                continue;
            } else if (s[0] == '\\') {
                char esc = map_escape(s[1]);
                if (esc) {
                    tmp[len++] = esc;
                    s += 2;
                    continue;
                }
            } else if (strchr(spaces, s[0]) && !quote) {
                break;
            }
            tmp[len++] = *s++;
        }

        // Note: unterminated quotes are left as is.

        char *word = strndup(tmp, len);
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

    free(tmp);
    return res;

fail:
    for (size_t n = 0; n < res_n; n++)
        free(res[n]);
    free(res);
    free(tmp);
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

    if (el && el->type == JSON_TYPE_STRING && def->aliases) {
        for (size_t n = 0; def->aliases[n].user_val; n++) {
            if (strcasecmp(el->u.str, def->aliases[n].user_val) == 0) {
                tmp = (struct json_tok){
                    .type = JSON_TYPE_STRING,
                    .u.str = (char *)def->aliases[n].param_val,
                };
                el = &tmp;
                break;
            }
        }
    }

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
        if (def->irange.min || def->irange.max) {
            if (data->p_int < def->irange.min) {
                logline(log, "error: %s out of range: %"PRId64" < %"PRId64".\n",
                        name, data->p_int, def->irange.min);
                return false;
            }
            if (data->p_int > def->irange.max) {
                logline(log, "error: %s out of range: %"PRId64" > %"PRId64".\n",
                        name, data->p_int, def->irange.max);
                return false;
            }
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

static int find_cmd_param(const struct command_def *cmd, const char *name)
{
    for (size_t p = 0; cmd->params[p].type; p++) {
        assert(p < COMMAND_MAX_PARAMS);
        if (strcmp(cmd->params[p].name, name) == 0)
            return p;
    }
    return -1;
}

void command_dispatch(const struct command_def *cmds, struct command_ctx *ctx,
                      const char *cmd)
{
    char mem[8192];
    struct json_tok *jcmd = NULL;
    char **args = NULL;
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
            goto done;

        cmdname = json_get_string(obj, "command", "");
        ctx->seq_id = json_get_double(obj, "id", -1);

        jcmd = obj;
    } else {
        args = split_spaces_with_quotes(cmd);
        cmdname = args ? args[0] : NULL;
        ctx->jout = NULL;
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
        // Ignore whitespace or comment-only lines.
        if (cmdname[0] && cmdname[0] != '#')
            LOG(ctx, "error: command %s not found\n", cmdname);
        goto done;
    }

    struct command_param params[COMMAND_MAX_PARAMS] = {{0}};
    struct json_tok jtok_tmp[COMMAND_MAX_PARAMS];

    if (jcmd) {
        for (size_t p = 0; cmd_def->params[p].type; p++) {
            assert(p < COMMAND_MAX_PARAMS);
            const struct command_param_def *def = &cmd_def->params[p];
            struct json_tok *el = json_get(jcmd, def->name);
            char *param_name =
                stack_sprintf(80, "parameter %zu/%s (%s)", p, def->name, def->desc);

            if (!parse_value(ctx->log, param_name, def, el, &params[p]))
                goto done;
        }
    } else {
        size_t cur_arg = 1; // first is command name
        size_t cur_pos = 0; // current positional parameter, index into params[]
        bool positional_only = false;

        while (args[cur_arg]) {
            char *arg = args[cur_arg];
            char *val = NULL;
            int p = -1;
            const struct command_param_def *def = NULL;

            if (!positional_only && strncmp(arg, "--", 2) == 0) {
                arg += 2;
                cur_arg++;

                if (!arg[0]) {
                    positional_only = true;
                    continue;
                }

                char optname[80];
                val = strchr(arg, '=');
                if (val) {
                    snprintf(optname, sizeof(optname), "%.*s", (int)(val - arg), arg);
                    val += 1;
                } else {
                    snprintf(optname, sizeof(optname), "%s", arg);
                }

                p = find_cmd_param(cmd_def, optname);
                if (p < 0) {
                    if (strcmp(optname, "help") == 0) {
                        command_list_help(cmds, ctx->log, cmd_def->name, true);
                    } else {
                        LOG(ctx, "error: parameter --%s not found\n", optname);
                    }
                    goto done;
                }
                def = &cmd_def->params[p];

                // "Flag" parameters do not need an argument, but can have one.
                if (!val && def->type == COMMAND_PARAM_TYPE_BOOL) {
                    if (!args[cur_arg] || strncmp(args[cur_arg], "--", 2) == 0)
                        val = "true";
                }

                if (!val && args[cur_arg]) {
                    val = args[cur_arg];
                    cur_arg++;
                }
            } else {
                p = cur_pos;
                def = p < COMMAND_MAX_PARAMS ? &cmd_def->params[p] : NULL;
                if (!def || !def->type) {
                    LOG(ctx, "error: unused arguments starting with '%s'.\n", arg);
                    goto done;
                }
                val = arg;
                cur_pos++;
                cur_arg++;
            }

            jtok_tmp[p] = (struct json_tok){
                .type = JSON_TYPE_STRING,
                .u.str = val,
            };

            char *param_name =
                stack_sprintf(80, "parameter %u/%s (%s)", p, def->name, def->desc);

            if (!val) {
                LOG(ctx, "error: %s expects an argument\n", param_name);
                goto done;
            }

            if (params[p].def) {
                LOG(ctx, "error: %s provided more than once\n", param_name);
                goto done;
            }

            if (!parse_value(ctx->log, param_name, def, &jtok_tmp[p], &params[p]))
                goto done;
        }
    }

    size_t num_params = 0;
    for (size_t p = 0; cmd_def->params[p].type; p++) {
        assert(p < COMMAND_MAX_PARAMS);
        const struct command_param_def *def = &cmd_def->params[p];

        if (!def)
            break;

        if (!params[p].def) {
            char *param_name =
                stack_sprintf(80, "parameter %zu/%s (%s)", p, def->name, def->desc);

            if (!parse_value(ctx->log, param_name, def, NULL, &params[p]))
                goto done;
        }

        assert(params[p].def == def);
        num_params++;
    }

    if (ctx->jout) {
        json_out_object_start(ctx->jout);
        json_out_field_int(ctx->jout, "id", ctx->seq_id);
    }

    ctx->success = true;
    cmd_def->cb(ctx, params, num_params);

done:
    if (ctx->jout) {
        json_out_field_bool(ctx->jout, "success", ctx->success);
        json_out_object_end(ctx->jout);
    }

    for (size_t n = 0; args && args[n]; n++)
        free(args[n]);
    free(args);
}

static const char *get_type_help(const struct command_param_def *def)
{


    if (def->type == COMMAND_PARAM_TYPE_INT64) {
        if (def->flags & COMMAND_FLAG_ALIAS_ONLY)
            return "string choice";
        if (def->aliases)
            return "integer or string choice";
    }

    switch (def->type) {
    case COMMAND_PARAM_TYPE_STR: return "string";
    case COMMAND_PARAM_TYPE_INT64: return "integer";
    case COMMAND_PARAM_TYPE_INT64_S: return "integer, with kib/mib/gib suffix";
    case COMMAND_PARAM_TYPE_BOOL: return "bool: true/false";
    case COMMAND_PARAM_TYPE_JSON: return "anything";
    }
    return "?";
}

void command_list_help(const struct command_def *cmds, struct logfn lfn,
                       const char *filter, bool filter_exact)
{
    bool use_filter = false, any_matches = false;

    for (size_t c = 0; cmds[c].name; c++) {
        const struct command_def *cmd_def = &cmds[c];

        if (filter && filter[0] && strcasecmp(filter, "all") != 0) {
            if (!use_filter && !filter_exact)
                logline(lfn, "Commands matching '%s':\n\n", filter);
            use_filter = true;
            if (strcasecmp(cmd_def->name, filter) != 0 &&
                !(!filter_exact && strstr(cmd_def->desc, filter)))
                continue;
            any_matches = true;
        }

        if (!use_filter && c == 0)
            logline(lfn, "List of commands:\n\n");

        logline(lfn, "  %s\n", cmd_def->name);
        logline(lfn, "    %s\n", cmd_def->desc);

        if (cmd_def->params[0].type)
            logline(lfn, "\n    Parameters:\n");

        for (size_t p = 0; cmd_def->params[p].type; p++) {
            assert(p < COMMAND_MAX_PARAMS);
            const struct command_param_def *def = &cmd_def->params[p];

            logline(lfn, "      %-15s %s\n", def->name, def->desc);
            logline(lfn, "    %-17s Type: %s\n", "", get_type_help(def));
            if (def->def) {
                logline(lfn, "    %-17s Default: '%s'\n", "", def->def);
            } else {
                logline(lfn, "    %-17s Required parameter.\n", "");
            }

            char aliases[80] = {0};
            int o = 0;
            for (size_t n = 0; def->aliases && def->aliases[n].user_val; n++) {
                o = snprintf_append(aliases, sizeof(aliases), o, "%s%s (%s)",
                                    n ? ", " : "",
                                    def->aliases[n].user_val,
                                    def->aliases[n].param_val);
            }
            if (o > 0)
                logline(lfn, "    %-17s Special values: %s\n", "", aliases);
        }

        logline(lfn, "\n");
    }

    if (use_filter && !any_matches) {
        logline(lfn, "No matches. Use 'help' to list all commands.\n");
    } else {
        logline(lfn, "Syntax: command param1 param2...\n");
        logline(lfn, "Named parameters: command --paramname1=paramvalue1...\n");
        logline(lfn, "Values can be quoted with \"...\" (or \'), some \\ escapes work.\n");
        logline(lfn, "You can add a ' -- ' after the command name to avoid\n");
        logline(lfn, "interpreting '--something...' as option name.\n");
        logline(lfn, "Or: {\"command\":\"cmd-name\",\"paramname1\":\"paramvalue1\", ...}\n");
    }
}

static void set_cmd_def_from_opt_def(struct command_param_def *dst,
                                     const struct option_def *src)
{
    *dst = (struct command_param_def){
        .type = src->type,
        .flags = src->flags,
        .aliases = src->aliases,
        .irange = src->irange,
    };
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

    struct command_param_def def;
    set_cmd_def_from_opt_def(&def, opt);

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
            logline(log, "error: option %s requires an argument\n", optname);
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
        struct command_param_def def;
        set_cmd_def_from_opt_def(&def, opt);
        logline(log, "  --%-22s%s (%s)\n", opt->name, opt->desc,
                get_type_help(&def));
        if (def.aliases) {
            logline(log, "    %22s  Choices:\n", "");
            for (size_t n = 0; def.aliases[n].user_val; n++) {
                logline(log, "    %22s     %s (%s)\n", "",
                        def.aliases[n].user_val,
                        def.aliases[n].desc);
            }
        }
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
