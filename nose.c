// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cmd_parser.h"
#include "device.h"
#include "event_loop.h"
#include "fifo.h"
#include "filters.h"
#include "fw_header.h"
#include "global.h"
#include "grabber.h"
#include "json_out.h"
#include "nose.h"
#include "usb_control.h"
#include "usb_io.h"
#include "utils.h"

#if HAVE_POSIX
#include <signal.h>
#include <spawn.h>
#else
#define INITGUID
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <knownfolders.h>
#endif

#if HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)-1)
#endif

extern char **environ;

struct options {
    int64_t verbosity;
    bool run_selftest;
    char *init_serial;
    bool run_wireshark;
    char *device;
    char *fw_update_file;
    bool fw_update_all;
    bool fw_update_force;
    char *capture_to;
    char *ipc_connect;
    char *ipc_server;
    int64_t softbuf;
    int64_t usbbuf;
    bool strip_frames;
    bool strip_fcs;
    bool capture_stats;
    bool capture_speed_test;
    char *init_cmds;
    char *post_init_cmds;
    int64_t exit_on;
    int64_t exit_timeout;
    bool print_version;
    char *extcap_version;
    bool extcap_interfaces;
    char *extcap_interface;
    bool extcap_config;
    bool extcap_dlts;
    bool extcap_capture;
    char *extcap_ctrl_in;
    char *extcap_ctrl_out;
};

const struct option_def option_list[] = {
    {"verbosity", offsetof(struct options, verbosity),
        COMMAND_PARAM_TYPE_INT64,
        "Log verbosity level: 0 silent, 1 normal, 2 verbose messages.",
        .flags = COMMAND_FLAG_RUNTIME},
    {"selftest", offsetof(struct options, run_selftest),
        COMMAND_PARAM_TYPE_BOOL,
        "Run internal device initialization and self-test."},
    {"selftest-serial", offsetof(struct options, init_serial),
        COMMAND_PARAM_TYPE_STR,
        "Serial number/ID to write when running --selftest"},
    {"wireshark", offsetof(struct options, run_wireshark),
        COMMAND_PARAM_TYPE_BOOL,
        "Start wireshark and dump packets to it. Terminate once done."},
    {"device", offsetof(struct options, device),
        COMMAND_PARAM_TYPE_STR,
        "Device to open (default: first device, pass 'none' to open none, "
        "'help' lists devices and exits)."},
    {"firmware-update", offsetof(struct options, fw_update_file),
        COMMAND_PARAM_TYPE_STR,
        "Perform a firmware update using this file."},
    {"firmware-update-all", offsetof(struct options, fw_update_all),
        COMMAND_PARAM_TYPE_BOOL,
        "Update all found devices, instead of asking interactively."},
    {"firmware-update-force", offsetof(struct options, fw_update_force),
        COMMAND_PARAM_TYPE_BOOL,
        "Update a device even if it has a recent or newer firmware version."},
    {"cmd", offsetof(struct options, init_cmds),
        COMMAND_PARAM_TYPE_STR,
        "Run a list of commands on start. Multiple commands can be separated "
        "with ; (needs spaces around it). If a command fails, exit with exit "
        "code 2."},
    {"run", offsetof(struct options, post_init_cmds),
        COMMAND_PARAM_TYPE_STR,
        "Run a list of commands on start. See --cmd for syntax. Unlike --cmd, "
        "these commands are run after performing initialization."},
    {"exit-on", offsetof(struct options, exit_on),
        COMMAND_PARAM_TYPE_INT64,
        "Control when to exit the program.",
        PARAM_ALIASES({"default", "0", "Like 'no-input', but 'no-capture' if --wireshark/--fifo is used."},
                      {"no-input", "4", "Exit if no command input (terminal, IPC) is active."},
                      {"no-capture", "1", "Exit if capturing stops or wasn't started."},
                      {"never", "2", "Do not auto-exit (except on signals or exit command)."},
                      {"always", "3", "Exit after initialization."}),
        .flags = COMMAND_FLAG_ALIAS_ONLY | COMMAND_FLAG_RUNTIME},
    {"exit-timeout", offsetof(struct options, exit_timeout),
        COMMAND_PARAM_TYPE_INT64,
        "Exit after the given number of seconds has passed.",
        PARAM_ALIASES({"never", "-1", "Disable timeout"}),
        .irange = {-1, INT_MAX / 1000}},
    // Also used by Wireshark extcap.
    {"fifo", offsetof(struct options, capture_to),
        COMMAND_PARAM_TYPE_STR,
        "Start capture and write to the given file or fifo."},
    {"ipc-connect", offsetof(struct options, ipc_connect),
        COMMAND_PARAM_TYPE_STR,
        "Connect IPC to this socket/named pipe. Terminate on disconnect."},
    {"ipc-server", offsetof(struct options, ipc_server),
        COMMAND_PARAM_TYPE_STR,
        "Host IPC on this socket/named pipe."},
    {"capture-soft-buffer", offsetof(struct options, softbuf),
        COMMAND_PARAM_TYPE_INT64_S,
        "Capture soft buffer (in bytes)",
        .flags = COMMAND_FLAG_RUNTIME,
        .irange = {1, SIZE_MAX / 2}},
    {"capture-usb-buffer", offsetof(struct options, usbbuf),
        COMMAND_PARAM_TYPE_INT64_S,
        "Capture libusb buffer (in bytes)",
        .flags = COMMAND_FLAG_RUNTIME,
        .irange = {1, SIZE_MAX / 2}},
    {"capture-stats", offsetof(struct options, capture_stats),
        COMMAND_PARAM_TYPE_BOOL,
        "Show capture statistics every 1 seconds.",
        .flags = COMMAND_FLAG_RUNTIME},
    {"capture-speed-test", offsetof(struct options, capture_speed_test),
        COMMAND_PARAM_TYPE_BOOL,
        "Capture speed test. Discard capture USB data on reception. See manual "
        "on how to use.",
        .flags = COMMAND_FLAG_RUNTIME},
    {"strip-frames", offsetof(struct options, strip_frames),
        COMMAND_PARAM_TYPE_BOOL,
        "Strip preamble & SFD from ethernet frames. (And FCS if --strip-fcs is provided.)",
        .flags = COMMAND_FLAG_RUNTIME},
    {"strip-fcs", offsetof(struct options, strip_fcs),
        COMMAND_PARAM_TYPE_BOOL,
        "Strip FCS from ethernet frames. (Ignored without --strip-frames.)",
        .flags = COMMAND_FLAG_RUNTIME},
    {"version", offsetof(struct options, print_version),
        COMMAND_PARAM_TYPE_BOOL,
        "Print host tool version and exit."},
    // For Wireshark's extcap interface.
    {"extcap-version", offsetof(struct options, extcap_version),
        COMMAND_PARAM_TYPE_STR,
        "Wireshark extcap"},
    {"extcap-interfaces", offsetof(struct options, extcap_interfaces),
        COMMAND_PARAM_TYPE_BOOL,
        "Wireshark extcap"},
    {"extcap-interface", offsetof(struct options, extcap_interface),
        COMMAND_PARAM_TYPE_STR,
        "Wireshark extcap"},
    {"extcap-config", offsetof(struct options, extcap_config),
        COMMAND_PARAM_TYPE_BOOL,
        "Wireshark extcap"},
    {"extcap-dlts", offsetof(struct options, extcap_dlts),
        COMMAND_PARAM_TYPE_BOOL,
        "Wireshark extcap"},
    {"capture", offsetof(struct options, extcap_capture),
        COMMAND_PARAM_TYPE_BOOL,
        "Wireshark extcap (ignored)"},
    {"extcap-control-in", offsetof(struct options, extcap_ctrl_in),
        COMMAND_PARAM_TYPE_STR,
        "Wireshark extcap"},
    {"extcap-control-out", offsetof(struct options, extcap_ctrl_out),
        COMMAND_PARAM_TYPE_STR,
        "Wireshark extcap"},
    {0}
};

static const struct options option_defs = {
    .verbosity = 1,
    .softbuf = 512 * 1024 * 1024,
    .usbbuf = 2 * 1024 * 1024,
    .exit_timeout = -1,
};

struct nose_ctx {
    struct event_loop *ev;
    struct global *global;
    struct options opts;
    struct event *phy_update_event;
    struct event *usb_discon_event;
    struct device *usb_dev;
    struct timer *check_links_timer;
    struct timer *grabber_status_timer;
    struct timer *exit_timer;
    struct timer *hw_info_timer;
    struct grabber_status grabber_status_prev;
    bool grabber_speed_test;
    struct pipe *ipc_server;
    struct pipe *signalfd;
    struct logfn log;
    atomic_bool log_indirect;
    atomic_int log_r_len;
    bool mute_terminal;
    bool extcap_active;
    struct pipe *extcap_ctrl_in, *extcap_ctrl_out, *extcap_fake_fifo;
    char *extcap_prelog;
    size_t extcap_prelog_sz;
    bool extcap_prelog_done;
    char *fifo_path; // for delete-on-exit
    char *wireshark_path;
    // Put all log output through a FIFO. Makes dealing with text from random
    // threads easier to deal with.
    struct byte_fifo log_fifo;
    pthread_mutex_t log_fifo_writer_lock;
    struct event *log_event;
    struct client **clients;
    size_t num_clients;
    struct phy_status prev_phy_st[2];
    uint64_t last_link_up_time[2]; // in get_time_us()
    uint64_t last_link_down_time[2]; // in get_time_us()
    uint64_t num_link_changes[2];
    bool latency_tester_sender, latency_tester_receiver;
    size_t latency_tester_cnt;
    uint32_t latency_tester_seq, latency_tester_seq_max;
    bool latency_tester_once;
    int latency_tester_pkt_size;
    struct timer *latency_tester_timer;
#if HAVE_READLINE
    char readline_buf[10];
    size_t readline_buf_size;
    char **readline_completion;
    char histfile[80];
#endif
    struct pipe *rl_pipe;
};

struct client {
    struct pipe *conn;
    bool is_terminal;
    bool is_control;
};

#define MAX_LOG_RECORD 512

static void process_command(struct nose_ctx *ctx, char *cmd, struct pipe *p);

// Speed mode names/descriptions, indexed by raw DEVICE_SETTING_SPEED_MODE.
// Beware that future firmware versions might add new values.
// The cmd_set_speed declaration duplicates some of these.
static const char* const speed_mode_settings_desc[] = {
    "same (try to force a speed mode that works on both links)",
    "10 (10MBit full duplex)",
    "100 (100MBit full duplex)",
    "1000 (1000MBit full duplex)",
    "manual (reset PHYs to independent auto-negotiation and don't touch them)",
    "10half (10MBit half duplex)",
    "100half (100MBit half duplex)",
    "1000half (1000MBit half duplex)",
};

#if HAVE_READLINE

static struct nose_ctx *cb_rl_nose_ctx;
static bool rl_in_handler;

static int cb_rl_input_available_hook(void)
{
    struct nose_ctx *ctx = cb_rl_nose_ctx;
    return ctx && ctx->readline_buf_size > 0;
}

static int cb_rl_getc_function(FILE *f)
{
    struct nose_ctx *ctx = cb_rl_nose_ctx;
    if (!ctx || !ctx->readline_buf_size)
        return EOF;
    unsigned char r = ctx->readline_buf[0];
    memmove(ctx->readline_buf, ctx->readline_buf + 1, ctx->readline_buf_size - 1);
    ctx->readline_buf_size -= 1;
    return r;
}

static void cb_rl_handler(char *line)
{
    struct nose_ctx *ctx = cb_rl_nose_ctx;
    if (ctx && line) {
        // Do not add empty or duplicate lines to history.
        if (line[strspn(line, " \t\n\r")]) {
            HIST_ENTRY *prev = history_get(history_base + history_length - 1);
            if (!prev || strcmp(prev->line, line))
                add_history(line);
        }

        rl_in_handler = true; // prevent redrawing the current input line
        process_command(ctx, line, ctx->rl_pipe);
        rl_in_handler = false;
    }
    free(line);
}

static void clear_last_completion(struct nose_ctx *ctx)
{
    if (ctx->readline_completion) {
        for (size_t n = 0; ctx->readline_completion[n]; n++)
            free(ctx->readline_completion[n]);
        free(ctx->readline_completion);
        ctx->readline_completion = NULL;
    }
}

static char *cb_completion(const char *text, int state)
{
    struct nose_ctx *ctx = cb_rl_nose_ctx;
    if (!ctx)
        return NULL;

    if (state == 0) {
        clear_last_completion(ctx);
        int a, b; // unused, hoping readline word boundaries are as ours
        ctx->readline_completion =
            command_completer(command_list, ctx, rl_line_buffer, rl_point, &a, &b);
    }

    if (!ctx->readline_completion)
        return NULL;
    // This relies on readline stopping iterating once we return NULL.
    return xstrdup(ctx->readline_completion[state]);
}

static int dummy_hook(int a, int b)
{
    return 0;
}

static void init_readline(struct nose_ctx *ctx, struct pipe *p)
{
    if (cb_rl_nose_ctx)
        return;

    cb_rl_nose_ctx = ctx;

    ctx->rl_pipe = p;

    rl_catch_signals = 0;
    // do not allow readline to freely corrupt memory
    rl_change_environment = 0;

    rl_completion_entry_function = cb_completion;

    rl_input_available_hook = cb_rl_input_available_hook;
    rl_getc_function = cb_rl_getc_function;
    rl_callback_handler_install("> ", cb_rl_handler);

    // libreadline 8.1: bracketed pasting, although a good idea, is implemented
    // in a way that expects the getc callback to block. We can't block, and
    // return EOF if the buffer is empty. This in turn makes rl_read_key() an
    // error, which in turn makes _rl_bracketed_text() return a string that is
    // not 0-terminated string due to buggy partial error handling. It will
    // either insert some uninitialized data, or crash. This is both a
    // libreadline design- and implementation bug.
    rl_variable_bind("enable-bracketed-paste", "off");
    // And for some reason, the above is not enough. Possibly, the terminal or
    // shell always enable this mode, and above doesn't disable the parsing of
    // the escapes.
    rl_bind_keyseq("\033[200~", dummy_hook);
    rl_bind_keyseq("\033[201~", dummy_hook);

    rl_initialize();
    using_history();
    stifle_history(200);

#if HAVE_POSIX
    char *home = getenv("HOME");
    if (home)
        snprintf(ctx->histfile, sizeof(ctx->histfile), "%s/.nose_hist", home);
#endif

    if (ctx->histfile[0])
        read_history(ctx->histfile);

    // Make history navigation work as expected after initialization. No idea
    // why the API forces us to do this.
    history_set_pos(history_length);

    // This fixes readline showing strange behavior after init (if no other
    // lines are printed through nose's logging).
    rl_clear_visible_line();
    rl_forced_update_display();
}

static void uninit_readline(struct nose_ctx *ctx, struct pipe *p)
{
    if (ctx->rl_pipe == p) {
        rl_clear_visible_line();
        rl_callback_handler_remove();
        ctx->rl_pipe = NULL;
        clear_last_completion(cb_rl_nose_ctx);
        cb_rl_nose_ctx = NULL;

        if (ctx->histfile[0])
            write_history(ctx->histfile);
    }
}

static void work_readline(struct nose_ctx *ctx)
{
    if (!ctx->rl_pipe)
        return;

    while (1) {
        // Drain readline buffer.
        while (ctx->readline_buf_size)
            rl_callback_read_char();
        // Drain pipe buffer.
        ctx->readline_buf_size =
            pipe_read(ctx->rl_pipe, ctx->readline_buf, sizeof(ctx->readline_buf));
        if (!ctx->readline_buf_size)
            break;
    }
}

static void hide_readline(struct nose_ctx *ctx, bool hide)
{
    if (!cb_rl_nose_ctx)
        return;

    if (hide) {
        rl_clear_visible_line();
    } else if (!rl_in_handler) {
        rl_forced_update_display();
    }
}

#else /* HAVE_READLINE */

static void init_readline(struct nose_ctx *ctx, struct pipe *p)
{
}

static void uninit_readline(struct nose_ctx *ctx, struct pipe *p)
{
}

static void work_readline(struct nose_ctx *ctx)
{
}

static void hide_readline(struct nose_ctx *ctx, bool hide)
{
}

#endif

static void log_write_lev(void *pctx, const char *fmt, va_list va, int lev)
{
    struct nose_ctx *ctx = pctx;
    char buf[MAX_LOG_RECORD + 1];
    vsnprintf(buf, sizeof(buf), fmt, va);

    if (lev > ctx->opts.verbosity)
        return;

    if (!ctx->log_indirect) {
        hide_readline(ctx, true);
        // Prettify output that is using \r somewhat: if the previous log line
        // ended in \r, but the new one does not, then insert an additional \n
        // before the new line. (Except if the entire line is "\n".)
        size_t len = strlen(buf);
        int old_len = ctx->log_r_len;
        bool has_r = len && buf[len - 1] == '\r';
        ctx->log_r_len = has_r ? len - 1 : -1;
        if (old_len >= 0 && !has_r && strcmp(buf, "\n") != 0)
            printf("\n");
        // Also, if the previous log line was \r, and the current one also is,
        // then append space characters to clear the previous line (using the
        // ANSI EL escape sequence would be nicer, but what about win32?).
        if (old_len > 0 && has_r && old_len > len && old_len < MAX_LOG_RECORD) {
            memset(&buf[len - 1], ' ', old_len + 1 - len);
            buf[old_len + 1] = '\r';
            buf[old_len + 2] = '\0';
        }
        printf("%s", buf);
        fflush(stdout);
        hide_readline(ctx, false);
    }

    // Split by lines, because it's convenient.
    char *cur = buf;
    while (cur[0]) {
        size_t len = strcspn(cur, "\n\r");
        uint16_t tlen = MIN(len, MAX_LOG_RECORD);
        pthread_mutex_lock(&ctx->log_fifo_writer_lock);
        // Silently discard if it doesn't fit in completely.
        byte_fifo_write_atomic_2(&ctx->log_fifo, &tlen, 2, cur, tlen);
        pthread_mutex_unlock(&ctx->log_fifo_writer_lock);
        cur += len + (cur[len] == '\n' || cur[len] == '\r');
    }
    event_signal(ctx->log_event);
}

static void log_write(void *pctx, const char *fmt, va_list va)
{
    log_write_lev(pctx, fmt, va, 1);
}

static void log_write_hint(void *pctx, const char *fmt, va_list va)
{
    log_write_lev(pctx, fmt, va, 2);
}

static void extcap_send_msg(struct nose_ctx *ctx, uint8_t control,
                            uint8_t command, void *data, size_t data_sz)
{
    if (!ctx->extcap_ctrl_out)
        return;

    if (data_sz >= (1u << 16) - 2)
        return;

    uint16_t size = 2 + data_sz;
    uint8_t header[6] = {
        'T',
        size >> 16, (size >> 8) & 0xFF, size & 0xFF,
        control,
        command,
    };

    pipe_write(ctx->extcap_ctrl_out, &header, sizeof(header));
    pipe_write(ctx->extcap_ctrl_out, data, data_sz);
}

static void log_extcap(struct nose_ctx *ctx, char *line)
{
    if (!ctx->extcap_ctrl_out)
        return;

    size_t line_len = strlen(line);

    if (!ctx->extcap_prelog_done) {
        XEXTEND_ARRAY(ctx->extcap_prelog, ctx->extcap_prelog_sz, line_len);
        memcpy(ctx->extcap_prelog + ctx->extcap_prelog_sz, line, line_len);
        ctx->extcap_prelog_sz += line_len;
    }

    extcap_send_msg(ctx, 1, 2, line, line_len);
}

// For use with json_out_init_cb() + writing to a struct pipe in *ctx.
static void jout_to_pipe_cb(void *ctx, const char *buf, size_t len)
{
    struct pipe *p = ctx;
    pipe_write(p, (char *)buf, len);
}

// For use with json_out_init_cb() + writing to a struct logfn in *ctx.
static void jout_to_log_cb(void *ctx, const char *buf, size_t len)
{
    struct logfn *log = ctx;
    logline(*log, "%.*s", (int)len, buf);
}

static void flush_log(struct nose_ctx *ctx)
{
    uint16_t tlen = 0;
    while (byte_fifo_read(&ctx->log_fifo, &tlen, 2) == 2) {
        char buf[MAX_LOG_RECORD + 2];
        assert(tlen <= MAX_LOG_RECORD);
        byte_fifo_read(&ctx->log_fifo, buf, tlen);
        buf[tlen] = '\n';
        buf[tlen + 1] = '\0';

        if (ctx->log_indirect && !ctx->mute_terminal) {
            hide_readline(ctx, true);
            FILE *f = ctx->extcap_active ? stderr : stdout;
            fprintf(f, "%s", buf);
            fflush(f);
            hide_readline(ctx, false);
        }

        for (size_t n = 0; n < ctx->num_clients; n++) {
            struct client *cl = ctx->clients[n];
            if (cl->is_terminal)
                continue;
            // A proper protocol will need the log line be escaped or such, for
            // now achieve that by adding a seemingly redundant prefix.
            struct json_out jout;
            json_out_init_cb(&jout, jout_to_pipe_cb, cl->conn);
            json_out_object_start(&jout);
            json_out_field_string(&jout, "type", "log");
            json_out_field_string(&jout, "msg", buf);
            json_out_object_end(&jout);
            json_out_finish(&jout);
            pipe_write(cl->conn, "\n", 1);
        }

        log_extcap(ctx, buf);
    }
}

static void on_log_data(void *ud, struct event *ev)
{
    struct nose_ctx *ctx = ud;

    flush_log(ctx);
}

// Run the given command.
//  cmd: command string
//  p: if not NULL, all command output is supposed to go here and as json
static void process_command(struct nose_ctx *ctx, char *cmd, struct pipe *p)
{
    struct json_out jout;
    if (p) {
        json_out_init_cb(&jout, jout_to_pipe_cb, p);
    } else {
        json_out_init_cb(&jout, jout_to_log_cb, &ctx->log);
    }

    struct command_ctx cctx = {
        // Log output could be reformatted ad-hoc for IPC output. But for now,
        // output them as global messages to everywhere. Command for which it
        // matters can explicitly switch between output styles.
        .log = ctx->log,
        .jout = &jout,
        .priv = ctx,
    };

    command_dispatch(command_list, &cctx, cmd);

    if (cctx.jout) {
        json_out_newline(cctx.jout);
        json_out_finish(cctx.jout);
    }
}

static void cmd_help(struct command_ctx *cctx, struct command_param *params,
                     size_t num_params)
{
    command_list_help(command_list, cctx->log, params[0].p_str, false);
}

static void on_check_links(void *ud, struct timer *t)
{
    struct nose_ctx *ctx = ud;

    timer_stop(t);

    struct device *dev = ctx->usb_dev;
    if (!dev)
        return;

    int speed[2];
    for (int port = 1; port <= 2; port++) {
        struct phy_status st;
        device_get_phy_status(dev, port, &st);
        speed[port - 1] = st.link ? st.speed : 0;
    }

    if (speed[0] && speed[1] && speed[0] != speed[1]) {
        LOG(ctx, "Warning: links have different speed. Communication is blocked.\n");
    } else if (!speed[0] != !speed[1]) {
        LOG(ctx, "Warning: only one port has a link.\n");
    } else if (!speed[0] && !speed[1]) {
        LOG(ctx, "Warning: no link.\n");
    } else if (speed[0] == 10 || speed[0] == 100) {
        if (dev->fw_version <= 0x106) {
            LOG(ctx, "This version of the firmware has known problems with %d "
                "MBit mode. Updating to the latest firmware release is "
                "recommended.\n", speed[0]);
            print_fw_update_instructions(ctx->log, dev);
        }
    }
}

static void on_phy_change(void *ud, struct event *ev)
{
    struct nose_ctx *ctx = ud;

    struct device *dev = ctx->usb_dev;
    if (!dev)
        return;

    bool any_link_changes = false;
    for (int port = 1; port <= 2; port++) {
        struct phy_status pst = ctx->prev_phy_st[port - 1];
        struct phy_status st;
        device_get_phy_status(dev, port, &st);

        if (pst.link != st.link ||
            pst.speed != st.speed ||
            pst.duplex != st.duplex)
        {
            ctx->num_link_changes[port - 1]++;

            if (st.link) {
                ctx->last_link_up_time[port - 1] = get_time_us();
            } else {
                ctx->last_link_down_time[port - 1] = get_time_us();
            }

            any_link_changes = true;
        }

        ctx->prev_phy_st[port - 1] = st;
    }

    if (any_link_changes) {
        bool both_1000_fd = true;

        for (int port = 1; port <= 2; port++) {
            struct phy_status st = ctx->prev_phy_st[port - 1];

            struct device_port_state pst;
            if (device_get_port_state(ctx->log, dev, port, &pst))
                pst = (struct device_port_state){0};

            char *master = "";
            if (st.master >= 0)
                master = st.master ? " (master)" : " (slave)";

            char *disrupt = "";
            if (pst.disrupt_active)
                disrupt = " (disruptor active)";

            char *inject = "";
            if (pst.inject_active)
                inject = " (injector active)";

            char *duplex = "";
            if (st.speed && !st.duplex)
                duplex = " half-duplex";

            both_1000_fd &= st.speed == 1000 && st.duplex;

            LOG(ctx, "PHY %s: link %s %dMBit%s%s%s%s\n", port_names[port],
                st.link ? "up" : "down", st.speed, duplex, master, disrupt, inject);
        }

        uint32_t fw_mode;
        int r = device_setting_read(ctx->log, dev, DEVICE_SETTING_SPEED_MODE,
                                    &fw_mode);

        if (r >= 0 && fw_mode < ARRAY_LENGTH(speed_mode_settings_desc) &&
            fw_mode != 0 && !both_1000_fd)
        {
            LOG(ctx, "Forced speed: %s\n", speed_mode_settings_desc[fw_mode]);
        }

        timer_start(ctx->check_links_timer, 2000);
    }
}

static void grab_stop(struct nose_ctx *ctx)
{
    if (ctx->usb_dev && ctx->usb_dev->grabber) {
        LOG(ctx, "Stopping capture thread...\n");
        grabber_destroy(ctx->usb_dev->grabber);
        assert(!ctx->usb_dev->grabber);
        timer_destroy(ctx->grabber_status_timer);
        ctx->grabber_status_timer = NULL;
        LOG(ctx, "Capture thread stopped.\n");
        if (ctx->latency_tester_receiver) {
            LOG(ctx, "Receiver stopped. Ports will remain blocked.\n"
                      "(Use 'block_ports none' to unblock.)\n");
            ctx->latency_tester_receiver = false;
        }
    }
}

static void usbdev_close(struct nose_ctx *ctx)
{
    if (ctx->usb_dev) {
        grab_stop(ctx);
        device_close(ctx->usb_dev);
        ctx->usb_dev = NULL;
        LOG(ctx, "USB device closed.\n");
    }
}

static void on_usb_discon(void *ud, struct event *ev)
{
    struct nose_ctx *ctx = ud;

    struct device *dev = ctx->usb_dev;
    if (!dev)
        return;

    usbdev_close(ctx);
}

static void handle_device_opened(struct nose_ctx *ctx, struct device *dev)
{
    assert(dev);
    assert(!ctx->usb_dev);

    // Reset change detection.
    for (int port = 1; port <= 2; port++)
        ctx->prev_phy_st[port - 1].speed = -1;

    ctx->usb_dev = dev;
    event_set_notifier(ctx->phy_update_event, dev->phy_update);
    event_set_notifier(ctx->usb_discon_event, dev->on_disconnect);
}

static void cmd_dev_open(struct command_ctx *cctx, struct command_param *params,
                         size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    usbdev_close(ctx);

    const char *devname = strcmp(params[0].p_str, "default") == 0
                          ? ctx->opts.device : params[0].p_str;

    struct device *dev = device_open(ctx->global, devname);

    if (dev) {
        handle_device_opened(ctx, dev);
        LOG(ctx, "Opening succeeded.\n");
    } else {
        LOG(ctx, "Opening failed.\n");
    }
}

static void cmd_dev_close(struct command_ctx *cctx, struct command_param *params,
                          size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    usbdev_close(ctx);
}

static void cmd_dev_list(struct command_ctx *cctx, struct command_param *params,
                         size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    libusb_device **list = NULL;
    libusb_get_device_list(usb_thread_libusb_context(ctx->global->usb_thr), &list);

    if (cctx->jout) {
        json_out_field_start(cctx->jout, "list");
        json_out_array_start(cctx->jout);
    } else {
        LOG(cctx, "Devices:\n");
    }

    size_t num_devs = 0;

    for (size_t n = 0; list && list[n]; n++) {
        char devname[USB_DEVICE_NAME_LEN];

        if (!usb_get_device_name(list[n], devname, sizeof(devname)))
            continue;

        if (cctx->jout) {
            json_out_array_entry_start(cctx->jout);
            json_out_string(cctx->jout, devname);
        } else {
            char *state = "";
            if (ctx->usb_dev && libusb_get_device(ctx->usb_dev->dev) == list[n])
                state = " [opened]";
            // Note: no serial number return per API yet. Maybe if someone
            // actually requests it as a feature.
            char serial[USB_DEVICE_SERIAL_LEN];
            if (usb_get_device_serial(list[n], serial, sizeof(serial))) {
                LOG(cctx, " - '%s' (%s)%s\n", serial, devname, state);
            } else {
                LOG(cctx, " - '%s'%s\n", devname, state);
            }
        }

        num_devs++;
    }

    libusb_free_device_list(list, 1);

    if (cctx->jout) {
        json_out_array_end(cctx->jout);
    } else {
        LOG(cctx, "Found %zu devices.\n", num_devs);
    }
}

static char **complete_dev_name(void *ud)
{
    struct nose_ctx *ctx = ud;
    char **res = NULL;
    size_t num_res = 0;

    libusb_device **list = NULL;
    libusb_get_device_list(usb_thread_libusb_context(ctx->global->usb_thr), &list);

    for (size_t n = 0; list && list[n]; n++) {
        char devname[USB_DEVICE_NAME_LEN];

        if (!usb_get_device_name(list[n], devname, sizeof(devname)))
            continue;

        XEXTEND_ARRAY(res, num_res, 1);
        res[num_res++] = xstrdup(devname);

        char serial[USB_DEVICE_SERIAL_LEN];
        if (usb_get_device_serial(list[n], serial, sizeof(serial))) {
            XEXTEND_ARRAY(res, num_res, 1);
            res[num_res++] = xstrdup(serial);
        }
    }

    libusb_free_device_list(list, 1);

    XEXTEND_ARRAY(res, num_res, 1);
    res[num_res] = NULL;
    return res;
}

static void on_grabber_status_timer(void *ud, struct timer *t)
{
    struct nose_ctx *ctx = ud;

    assert(ctx->usb_dev->grabber);

    // If extcap is active, "ping" Wireshark regularly to check whether it's
    // still alive. There is no dedicated ping command, but appending an empty
    // string to the log will have the same effect.
    log_extcap(ctx, "");

    struct grabber_status st;
    grabber_read_status(ctx->usb_dev->grabber, &st);

    if (st.fatal_error) {
        LOG(ctx, "Capturing failed: %s\n", st.fatal_error);
        grab_stop(ctx);
        return;
    }

    if (!ctx->opts.capture_stats)
        return;

    LOG(ctx, "Capturing, %"PRIu64" MiB written (%"PRIu64" packets).\n",
        st.bytes_written / (1024 * 1024),
        st.port_stats[0].sw_frames + st.port_stats[1].sw_frames);

    for (size_t p = 0; p < 2; p++) {
        struct grabber_port_stats pst = st.port_stats[p];
        struct grabber_port_stats pst_prev = ctx->grabber_status_prev.port_stats[p];

        double last_link_up = ctx->last_link_up_time[p]
            ? (get_time_us() - ctx->last_link_up_time[p]) / 1e6 : 0;
        double last_link_down = ctx->last_link_down_time[p]
            ? (get_time_us() - ctx->last_link_down_time[p]) / 1e6 : 0;

        LOG(ctx,
            " Port %s: Packets transmitted (delta): %"PRIu64" (%"PRIu64")\n"
            "         Bytes captured (delta): %s (%s)\n",
            port_names[DEV_PORT_FROM_INDEX(p)],
            pst.num_packets,
            pst.num_packets - pst_prev.num_packets,
            format_byte_count(pst.num_bytes),
            format_byte_count(pst.num_bytes - pst_prev.num_bytes));

        if (ctx->grabber_speed_test)
            continue; // the stats below are not set in this mode

        LOG(ctx,
            "         CRC errors (delta): %"PRId64" (%"PRIu64")\n"
            "         Packets dropped HW (delta): %"PRIu64" (%"PRIu64")\n"
            "         Packets dropped SW (delta): %"PRIu64" (%"PRIu64")\n"
            "         Times since last link up / down: %.1fs / %.1fs\n"
            "         Link up / down changes: %"PRIu64"\n"
            "         Buffer fill: %.0f%% (%"PRId64" overflows)\n",
            pst.num_crcerr,
            pst.num_crcerr - pst_prev.num_crcerr,
            pst.hw_dropped,
            pst.hw_dropped - pst_prev.hw_dropped,
            pst.sw_dropped,
            pst.sw_dropped - pst_prev.sw_dropped,
            last_link_up, last_link_down,
            ctx->num_link_changes[p],
            100 * pst.sw_buffer_sz / (double)pst.sw_buffer_sz_max,
            pst.overflows + (pst.sw_dropped != pst_prev.sw_dropped));
    }

    ctx->grabber_status_prev = st;
}

static void init_grabber_opts(struct nose_ctx *ctx, struct grabber_options *opts)
{
    *opts = (struct grabber_options) {
        .soft_buffer = ctx->opts.softbuf, // TODO: can overflow on 32 bit
        .usb_buffer = ctx->opts.usbbuf,
        .linktype = ctx->opts.strip_frames ? LINKTYPE_ETHERNET
                                           : LINKTYPE_ETHERNET_MPACKET,
        .strip_fcs = ctx->opts.strip_frames && ctx->opts.strip_fcs,
        .speed_test = ctx->opts.capture_speed_test,
        .device = ctx->usb_dev,
    };
};

static bool start_grabber(struct nose_ctx *ctx, struct grabber_options *opts)
{
    if (!ctx->usb_dev || ctx->usb_dev->grabber)
        return false; // leaks opts->filters

    grabber_start(ctx->global, opts);
    bool success = !!ctx->usb_dev->grabber;

    if (success) {
        ctx->grabber_status_timer = event_loop_create_timer(ctx->ev);
        timer_set_on_timer(ctx->grabber_status_timer, ctx, on_grabber_status_timer);
        timer_start(ctx->grabber_status_timer, 1000);

        ctx->grabber_speed_test = opts->speed_test;

        grabber_read_status(ctx->usb_dev->grabber, &ctx->grabber_status_prev);
    }

    LOG(ctx, "Starting capture thread %s.\n", success ? "succeeded" : "failed");
    return success;
}

static bool grab_start(struct nose_ctx *ctx, struct logfn log, const char *file)
{
    if (!ctx->usb_dev) {
        logline(log, "Error: no device opened.\n");
        return false;
    }

    grab_stop(ctx);

    struct grabber_filter *filters[10];
    size_t num_filters = 0;

    filters[num_filters++] = filter_commenter_create();

    struct grabber_options opts;
    init_grabber_opts(ctx, &opts);
    opts.filename = file;
    opts.filters = filters;
    opts.num_filters = num_filters;
    return start_grabber(ctx, &opts);
}

static struct device *require_dev(struct command_ctx *cctx)
{
    struct nose_ctx *ctx = cctx->priv;
    if (!ctx->usb_dev) {
        LOG(cctx, "Error: this command requires an opened device.\n");
        cctx->success = false;
    }
    return ctx->usb_dev;
}

static void cmd_grab_start(struct command_ctx *cctx, struct command_param *params,
                           size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;
    if (!require_dev(cctx))
        return;

    cctx->success = grab_start(ctx, cctx->log, params[0].p_str);
}

static void cmd_grab_stop(struct command_ctx *cctx, struct command_param *params,
                          size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    grab_stop(ctx);
}

// Extra validation for PHY_SELECT parameters (in val), for which selecting no
// port makes no sense.
static bool check_ports(struct command_ctx *cctx, int val)
{
    if (!val) {
        // Is this error message too smug?
        LOG(cctx, "Error: you passed 0 or none as PHY argument. This would do "
                  "nothing (as it would affect no PHY) and is thus rejected "
                  "as potential user error.\n");
        cctx->success = false;
        return false;
    }
    return true;
}

static void cmd_mdio_read(struct command_ctx *cctx, struct command_param *params,
                          size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    int phy = params[0].p_int;
    bool both = phy == 3;
    int reg = params[1].p_int;
    int p = params[2].p_int;
    if (p >= 0)
        reg = MDIO_PAGE_REG(p, reg);

    if (!check_ports(cctx, phy))
        return;

    int r;
    int regs[2] = {-1, -1};
    if (both) {
        r = device_mdio_read_both(dev, reg, regs);
    } else {
        r = device_mdio_read(dev, phy, reg);
    }

    cctx->success = r >= 0;

    if (cctx->jout) {
        if (cctx->success && both) {
            json_out_field_int(cctx->jout, "result_phy0", regs[0]);
            json_out_field_int(cctx->jout, "result_phy1", regs[1]);
        } else {
            json_out_field_int(cctx->jout, "result", r);
        }
    } else {
        if (cctx->success) {
            if (both) {
                LOG(cctx, "result: value=0x%04x/0x%04x\n", regs[0], regs[1]);
            } else {
                LOG(cctx, "result: value=0x%04x\n", r);
            }
        } else {
            LOG(cctx, "error %d\n", r);
        }
    }
}

static void cmd_mdio_write(struct command_ctx *cctx, struct command_param *params,
                           size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    int ports = params[0].p_int;
    int reg = params[1].p_int;
    int p = params[3].p_int;
    if (p >= 0)
        reg = MDIO_PAGE_REG(p, reg);

    if (!check_ports(cctx, ports))
        return;

    int r = device_mdio_write(dev, ports, reg, params[2].p_int);
    if (r >= 0) {
        LOG(cctx, "success\n");
    } else {
        LOG(cctx, "error %d\n", r);
        cctx->success = false;
    }
}

static void cmd_set_speed(struct command_ctx *cctx, struct command_param *params,
                          size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    int fw_speed_mode = params[0].p_int;

    if ((dev->fw_version < 0x108 && fw_speed_mode > 4) ||
        (dev->fw_version < 0x106 && fw_speed_mode == 0))
    {
        LOG(cctx, "this mode is not supported with this firmware version\n");
        print_fw_update_instructions(cctx->log, dev);
        cctx->success = false;
        return;
    }

    int r;
    if (dev->fw_version < 0x106) {
        int speed = 0;
        int autoneg = 0;
        if (fw_speed_mode == 4) {
            autoneg = 1;
        } else {
            speed = fw_speed_mode - 1;
        }
        uint16_t v = (1 << 15) |                // reset
                     ((!!(speed & 1)) << 13) |  // speed select
                     (!!((speed & 2)) << 6) |
                     (1 << 8) |                 // full duplex
                     (autoneg << 12);           // auto negotiation enable

        r = device_mdio_write(dev, 3, 0, v);
    } else {
        r = device_setting_write(cctx->log, dev, DEVICE_SETTING_SPEED_MODE,
                                 fw_speed_mode);
    }

    if (r >= 0) {
        LOG(cctx, "setting speed to %s\n",
            speed_mode_settings_desc[fw_speed_mode]);
    } else {
        LOG(cctx, "error %d\n", r);
        cctx->success = false;
    }
}

static void cmd_set_phy_time(struct command_ctx *cctx, struct command_param *params,
                             size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    if (dev->fw_version < 0x106) {
        LOG(cctx, "Firmware too old.\n");
        cctx->success = false;
        return;
    }

    uint32_t s = params[0].p_int;
    int r = device_setting_write(cctx->log, dev, DEVICE_SETTING_SPEED_PHY_WAIT, s);

    if (r >= 0) {
        LOG(cctx, "setting PHY link up wait time to %"PRIu32" ms.\n", s);
    } else {
        LOG(cctx, "error %d\n", r);
        cctx->success = false;
    }
}

static void cmd_cfg_packet(struct command_ctx *cctx, struct command_param *params,
                           size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    uint8_t *bytes = NULL;
    size_t size = 0;

    if (!parse_hex(cctx->log, params[0].p_str, &bytes, &size))
        goto fail;

    if (size & 3) {
        LOG(cctx, "error: data size must a be multiple of 4\n");
        goto fail;
    }

    LOG(cctx, "Sending:\n");
    log_hexdump(cctx->log, bytes, size);

    // NB: that cast is unkosher, but not UB. Probably.
    uint32_t *res_data;
    size_t res_num;
    int r = device_config_raw(dev, (uint32_t *)bytes, size / 4,
                              &res_data, &res_num);
    if (r < 0) {
        LOG(cctx, "error: failed to send command\n");
        goto fail;
    }

    LOG(cctx, "Reply:\n");
    log_hexdump(cctx->log, res_data, res_num * 4);

    free(res_data);
    free(bytes);
    return;
fail:
    cctx->success = false;
    free(bytes);
}

static void cmd_disrupt(struct command_ctx *cctx, struct command_param *params,
                        size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    int ports = params[0].p_int;
    int64_t mode = params[1].p_int;

    struct device_disrupt_params p = {
        .num_packets    = params[2].p_int,
        .skip           = params[3].p_int,
        .offset         = params[4].p_int,
    };

    if (!check_ports(cctx, ports))
        return;

    switch (mode) {
    case 0: p.mode = DEVICE_DISRUPT_DROP; break;
    case 1: p.mode = DEVICE_DISRUPT_BIT_FLIP; break;
    case 2: p.mode = DEVICE_DISRUPT_BIT_ERR; break;
    default:
        LOG(cctx, "error: invalid mode parameter\n");
        cctx->success = false;
    }

    cctx->success = device_disrupt_pkt(cctx->log, dev, ports, &p) >= 0;
}

static void cmd_disrupt_stop(struct command_ctx *cctx, struct command_param *params,
                             size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    int ports = params[0].p_int;
    if (!check_ports(cctx, ports))
        return;

    struct device_disrupt_params p = {0};
    cctx->success = device_disrupt_pkt(cctx->log, dev, ports, &p) >= 0;
}


static void cmd_block_ports(struct command_ctx *cctx, struct command_param *params,
                            size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    struct device_disrupt_params p = {
        .mode           = DEVICE_DISRUPT_DROP,
        .num_packets    = UINT32_MAX,
    };

    int block = params[0].p_int;
    int unblock = 3u & ~(block & 3u);

    int r1 = device_disrupt_pkt(cctx->log, dev, block, &p);

    p.num_packets = 0;
    int r2 = device_disrupt_pkt(cctx->log, dev, unblock, &p);

    if (r1 < 0 || r2 < 0) {
        LOG(cctx, "error: failed to send command\n");
        cctx->success = false;
    }
}

static void cmd_inject(struct command_ctx *cctx, struct command_param *params,
                       size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    cctx->success = false;

    int ports = params[0].p_int;
    const char *s = params[1].p_str;
    const char *file = params[8].p_str;

    if (s[0] && file[0]) {
        LOG(cctx, "error: cannot provide both data and file arguments\n");
        return;
    }

    struct device_inject_params p = {
        .raw            = params[2].p_bool,
        .num_packets    = params[3].p_int,
        .gap            = params[4].p_int,
        .append_random  = params[5].p_int,
        .append_zero    = params[6].p_int,
        .loop_count     = params[9].p_int,
        .loop_offset    = params[10].p_int,
        .nopad          = params[11].p_bool,
    };
    int64_t corrupt = params[7].p_int;
    if (corrupt >= 0) {
        p.enable_corrupt = true;
        p.corrupt_at = corrupt;
    };

    if (!check_ports(cctx, ports))
        return;

    uint8_t *bytes = NULL;
    size_t size = 0;

    if (s[0]) {
        if (!parse_hex(cctx->log, s, &bytes, &size))
            goto done;
    } else if (file[0]) {
        void *vdata = NULL;
        if (!read_file(cctx->log, file, &vdata, &size))
            goto done;
        bytes = vdata;
    }

    p.data = bytes;
    p.data_size = size;

    int64_t bw_bytes = params[12].p_int;
    int64_t bw_pkts = params[13].p_int;

    if (bw_bytes || bw_pkts) {
        if ((p.num_packets == 1 || p.num_packets == UINT32_MAX) && p.loop_count == 0) {
            int64_t rawlen = device_inject_get_raw_length(&p);

            if (rawlen < 1) {
                LOG(cctx, "error: packet with length 0\n");
                goto done;
            }

            struct phy_status st[2];
            device_get_phy_status(dev, DEV_PORT_A, &st[0]);
            device_get_phy_status(dev, DEV_PORT_B, &st[1]);
            if (!st[0].link || !st[1].link || !st[0].speed ||
                st[0].speed != st[1].speed)
            {
                LOG(cctx, "error: not both links up and at the same speed\n");
                goto done;
            }

            int64_t clocks_per_sec = 125000000;
            switch (st[0].speed) {
            case 10: clocks_per_sec = 1250000; break;
            case 100: clocks_per_sec = 12500000; break;
            }

            if (bw_bytes) {
                int64_t unused = clocks_per_sec - bw_bytes;
                p.gap = unused < 0 ? 0 : unused * rawlen / bw_bytes;
            } else if (bw_pkts) {
                int64_t bytes_per_pkt = clocks_per_sec / bw_pkts;
                p.gap = bytes_per_pkt <= rawlen ? 0 : bytes_per_pkt - rawlen;
            }

            if (p.gap < ETHERNET_MIN_GAP) {
                LOG(cctx, "error: cannot reach bandwidth\n");
                goto done;
            }

            p.num_packets = UINT32_MAX;
        } else {
            LOG(cctx, "warning: --bw-bytes/--bw-packets ignored\n");
        }
    }

    cctx->success = device_inject_pkt(cctx->log, dev, ports, &p) >= 0;

done:
    free(bytes);
}

static void cmd_inject_stop(struct command_ctx *cctx, struct command_param *params,
                            size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    int ports = params[0].p_int;
    if (!check_ports(cctx, ports))
        return;

    struct device_inject_params p = {0};
    cctx->success = device_inject_pkt(cctx->log, dev, ports, &p) >= 0;
}

// Going by the convention used with certain hardware registers.
#define NUM32_OR_INF(i) \
    ((i) == UINT32_MAX ? "inf" : stack_sprintf(40, "%"PRIu32, i))

static void show_hw_info(struct command_ctx *cctx)
{
    struct nose_ctx *ctx = cctx->priv;

    LOG(cctx, "Host tool version: %s\n", version);

    struct device *dev = require_dev(cctx);
    if (!dev) {
        timer_destroy(ctx->hw_info_timer);
        ctx->hw_info_timer = NULL;
        return;
    }

    struct libusb_device_descriptor desc;
    if (!libusb_get_device_descriptor(libusb_get_device(dev->dev), &desc)) {
        LOG(cctx, "Firmware version: %d.%02x\n", desc.bcdDevice >> 8,
            desc.bcdDevice & 0xFF);

        char name[USB_DEVICE_NAME_LEN];
        if (usb_get_device_name(libusb_get_device(dev->dev), name, sizeof(name)))
            LOG(cctx, "Device address: %s\n", name);

        char serial[USB_DEVICE_SERIAL_LEN];
        if (usb_get_device_serial(libusb_get_device(dev->dev), serial, sizeof(serial)))
            LOG(cctx, "Serial number: %s\n", serial);
    }

    uint32_t *res = NULL;
    size_t res_num = 0;

    uint32_t cmd = 0;
    int r = device_config_raw(dev, &cmd, 1, &res, &res_num);
    if (r < 0 || cmd == (uint32_t)-1 || res_num < 2) {
        LOG(cctx, "error: failed to retrieve FPGA bitstream version\n");
        cctx->success = false;
    } else {
        LOG(cctx, "FPGA bitstream version: %"PRIx32"\n", res[1]);
    }

    free(res);

    cmd = 5 << 24;
    res = NULL;
    res_num = 0;
    r = device_config_raw(dev, &cmd, 1, &res, &res_num);
    if (r < 0 || cmd == (uint32_t)-1 || res_num < 2) {
        LOG(cctx, "error: failed to retrieve hwrev\n");
        cctx->success = false;
    } else {
        LOG(cctx, "HWREV: %"PRIu32"\n", res[1] & 7);
    }
    free(res);

    if (dev->fw_version >= 0x111) {
        uint32_t cmd = 10 << 24;
        uint32_t *recv;
        size_t recv_sz;
        int r = device_config_raw(dev, &cmd, 1, &recv, &recv_sz);
        if (r >= 0 && recv_sz >= 2) {
            uint64_t ts = (((uint64_t)recv[0]) << 32) | recv[1];
            LOG(cctx, "HW-Timestamp: 0x%"PRIx64"\n", ts);
        } else {
            LOG(cctx, "HW-Timestamp: error %d\n", r);
        }
        free(recv);
    }

    LOG(cctx, "Persistent settings stored on the device:\n");
    if (dev->fw_version < 0x106) {
        LOG(cctx, " (none)\n");
    } else {
        uint32_t fw_mode;
        r = device_setting_read(cctx->log, dev, DEVICE_SETTING_SPEED_MODE,
                                &fw_mode);

        const char *name = NULL;
        if (r < 0) {
            name = "(failed to read setting)";
        } else if (fw_mode < ARRAY_LENGTH(speed_mode_settings_desc)) {
            name = speed_mode_settings_desc[fw_mode];
        }
        char buf[30];
        if (!name)
            snprintf(buf, sizeof(buf), "unknown (%"PRIu32")", fw_mode);
        LOG(cctx, "    Forced speed: %s\n", name);

        uint32_t phy_wait;
        r = device_setting_read(cctx->log, dev, DEVICE_SETTING_SPEED_PHY_WAIT,
                                &phy_wait);
        char delay[80];
        if (r < 0) {
            snprintf(delay, sizeof(delay), "(failed to read setting)");
        } else {
            snprintf(delay, sizeof(delay), "%"PRIu32" ms", phy_wait);
        }
        LOG(cctx, "    PHY auto-negotiation wait delay: %s\n", delay);
    }

    if (dev->fw_version >= 0x106) {
        LOG(cctx, "Runtime state:\n");

        for (int port = DEV_PORT_A; port <= DEV_PORT_B; port++) {
            struct device_port_state state;

            LOG(cctx, "  Port %s:\n", port_names[port]);

            if (device_get_port_state(cctx->log, dev, port, &state) < 0) {
                LOG(cctx, "    error: could not retrieve state\n");
                continue;
            }

            if (state.packets_valid) {
                LOG(cctx, "    Packets (mod 2^32): %"PRIu32"\n",
                    state.packets);
            }

            if (state.sym_error_bytes_valid) {
                LOG(cctx, "    Symbol error bytes (mod 2^32): %"PRIu32"\n",
                    state.sym_error_bytes);
            }

            if (state.crc_error_count_valid) {
                LOG(cctx, "    Packets with CRC error (mod 2^32): %"PRIu32"\n",
                    state.crc_error_count);
            }

            if (state.reset_count_valid) {
                LOG(cctx, "    Port FIFO overflows (mod 2^32): %"PRIu32"\n",
                    state.reset_count);
            }

            if (state.inject_active) {
                LOG(cctx, "    Injector packets to inject: %s\n",
                    NUM32_OR_INF(state.inject_active));
            } else {
                LOG(cctx, "    Injector inactive.\n");
            }

            LOG(cctx, "    Injector inserted packets (mod 2^31): %"PRIu32"\n",
                state.inject_count);

            LOG(cctx, "    Injector-dropped packets (mod 2^32): %"PRIu32"\n",
                state.inject_dropped);

            if (state.disrupt_active) {
                LOG(cctx, "    Disruptor packets to fry: %s\n",
                    NUM32_OR_INF(state.disrupt_active));
            } else {
                LOG(cctx, "    Disruptor inactive.\n");
            }

            LOG(cctx, "    Disruptor packets fried (mod 2^32): %"PRIu32"\n",
                state.disrupt_affected);
        }
    }
}

static void hw_info_on_timer(void *ud, struct timer *t)
{
    struct nose_ctx *ctx = ud;

    // a bit of it a hack
    struct command_ctx cctx = {
        .log = ctx->log,
        .priv = ctx,
    };
    show_hw_info(&cctx);
}

static void cmd_hw_info(struct command_ctx *cctx, struct command_param *params,
                        size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    int time = params[0].p_int;
    if (time > 0) {
        if (!ctx->hw_info_timer)
            ctx->hw_info_timer = event_loop_create_timer(ctx->ev);
        timer_set_on_timer(ctx->hw_info_timer, ctx, hw_info_on_timer);
        timer_start(ctx->hw_info_timer, time);
    } else if (time == 0) {
        timer_destroy(ctx->hw_info_timer);
        ctx->hw_info_timer = NULL;
    }

    show_hw_info(cctx);
}

static void cmd_hw_time_sync(struct command_ctx *cctx,
                             struct command_param *params, size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    struct device_clock_info info1, info2;

    device_get_clock_info(dev, &info1);

    device_time_sync(dev);

    device_get_clock_info(dev, &info2);

    if (!(info1.valid && info2.valid)) {
        // This assumes opening the device called device_time_sync(), so info1
        // is valid.
        LOG(cctx, "error: time sync failed or unavailable (update firmware?)\n");
        cctx->success = false;
        return;
    }

    int64_t host_diff = info2.host_time - info1.host_time;
    int64_t dev_diff = info2.device_time - info1.device_time;
    int64_t deviation = host_diff - dev_diff;
    double ns_per_sec = 1000.0 * 1000.0 * 1000.0;
    LOG(cctx, "Query delay: %"PRIu64" us (previous: %"PRIu64" us)\n",
        info2.delay / 1000, info1.delay / 1000);
    LOG(cctx, "Time passed since previous sync:\n");
    LOG(cctx, "...real time: %.3f s\n", host_diff / ns_per_sec);
    LOG(cctx, "...device time: %.3f s\n", dev_diff / ns_per_sec);
    LOG(cctx, "Deviation (real - device): %"PRId64" ns\n", deviation);
    if (imaxabs(host_diff) > ns_per_sec / 10) {
        LOG(cctx, "Computed deviation every 1 hour (based on the above): %"PRId64" ms\n",
            60 * 60 * deviation * 1000 / host_diff);
    }
}

static void cmd_dev_reset_settings(struct command_ctx *cctx,
                                   struct command_param *params,
                                   size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    if (dev->fw_version < 0x106) {
        LOG(cctx, "Device with old firmware; no persistent settings.\n");
        return;
    }

    uint32_t cmd = (7 << 24);
    uint32_t *res = NULL;
    size_t res_num = 0;
    int r = device_config_raw(dev, &cmd, 1, &res, &res_num);
    if (r >= 0 && (res_num < 2 || (res[1] & 0xFF)))
        r = -2;
    free(res);

    if (r < 0) {
        LOG(cctx, "error: failed with code %d\n", r);
        cctx->success = false;
    } else {
        LOG(cctx, "Settings reset; use hw_info to confirm.\n");
    }
}

static void cmd_identify(struct command_ctx *cctx, struct command_param *params,
                         size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    libusb_control_transfer(dev->dev,
        LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_OUT,
        0xC0,
        0x00,
        0x00,
        NULL,
        0,
        USB_TIMEOUT);
}

static void cmd_set(struct command_ctx *cctx, struct command_param *params,
                    size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    cctx->success = options_set_json(cctx->log, option_list, &ctx->opts,
                                     params[0].p_str, params[1].p_json,
                                     COMMAND_FLAG_RUNTIME);
}

static void cmd_exit(struct command_ctx *cctx, struct command_param *params,
                     size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    LOG(ctx, "Exit command received.\n");
    event_loop_request_terminate(ctx->ev);
}

static void cmd_reboot(struct command_ctx *cctx, struct command_param *params,
                       size_t num_params)
{
    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    usb_reboot(dev->dev, cctx->log);
}

static void on_send_test(void *ud, struct timer *t)
{
    struct nose_ctx *ctx = ud;
    if (!ctx->usb_dev || !ctx->latency_tester_sender)
        goto disable;

    bool last = ctx->latency_tester_seq == ctx->latency_tester_seq_max;

    if (!ctx->latency_tester_seq)
        LOG(ctx, "Latency tester: new test run (%zu)\n", ctx->latency_tester_cnt++);

    uint8_t pkt[DEV_INJECT_MAX_PKT_SIZE] = {0};
    // Set 00:00:00:00:00:02 as destination MAC
    pkt[5] = 2;
    // Set 00:00:00:00:00:01 as source MAC
    pkt[11] = 1;
    // Set 0xBEEF as ethertype (big endian), a random unassigned protocol type.
    // (https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
    pkt[12] = 0xBE;
    pkt[13] = 0xEF;
    // Specific magic
    memcpy(&pkt[14], &(uint32_t){LATENCY_TESTER_MAGIC}, 4);
    // Sequence number (little endian)
    memcpy(&pkt[18], &(uint32_t){ctx->latency_tester_seq}, 4);
    // Another magic, 0..0 or 1..1 depending on whether this is the end.
    uint32_t last_magic = 0;
    if (last)
        last_magic = ~last_magic;
    memcpy(&pkt[22], &last_magic, 4);

    struct device_inject_params p = {
        .num_packets    = 1,
        .data           = pkt,
        .data_size      = ctx->latency_tester_pkt_size,
    };

    device_inject_pkt(ctx->log, ctx->usb_dev, 3, &p);

    ctx->latency_tester_seq++;
    if (last) {
        ctx->latency_tester_seq = 0;
        if (ctx->latency_tester_once)
            goto disable;
    }

    return;
disable:
    if (ctx->latency_tester_timer) {
        LOG(ctx, "Sender stopped. Ports will remain blocked.\n"
                 "(Use 'block_ports none' to unblock.)\n");
    }
    ctx->latency_tester_sender = false;
    timer_destroy(ctx->latency_tester_timer);
    ctx->latency_tester_timer = NULL;
}

static void cmd_latency_tester_sender(struct command_ctx *cctx,
                                      struct command_param *params,
                                      size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    bool stop = params[0].p_bool;
    int64_t samples = params[1].p_int;
    int psize = params[2].p_int;
    int delay = params[3].p_int;
    bool once = params[4].p_bool;

    ctx->latency_tester_sender = false;
    // Mess to share disable/message.
    on_send_test(ctx, ctx->latency_tester_timer);

    if (stop)
        return;

    if (ctx->latency_tester_receiver) {
        LOG(cctx, "Latency tester sender/receiver cannot be on the same device.\n");
        cctx->success = false;
        return;
    }

    ctx->latency_tester_timer = event_loop_create_timer(ctx->ev);
    timer_set_on_timer(ctx->latency_tester_timer, ctx, on_send_test);
    timer_start(ctx->latency_tester_timer, delay);

    struct device_disrupt_params p = {
        .mode           = DEVICE_DISRUPT_DROP,
        .num_packets    = UINT32_MAX,
    };
    device_disrupt_pkt(cctx->log, dev, 3, &p);

    ctx->latency_tester_seq = 0;
    ctx->latency_tester_cnt = 0;
    ctx->latency_tester_seq_max = samples - 1;
    ctx->latency_tester_once = once;
    ctx->latency_tester_pkt_size = psize;
    ctx->latency_tester_sender = true;
}

static void cmd_latency_tester_receiver(struct command_ctx *cctx,
                                        struct command_param *params,
                                        size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    bool stop = params[0].p_bool;
    bool wait_for_0 = params[1].p_bool;
    const char *outfile = params[2].p_str;

    if (stop) {
        if (ctx->latency_tester_receiver)
            grab_stop(ctx);
        return;
    }

    if (ctx->latency_tester_sender) {
        LOG(cctx, "Latency tester sender/receiver cannot be on the same device.\n");
        cctx->success = false;
        return;
    }

    grab_stop(ctx);

    struct grabber_options opts;
    init_grabber_opts(ctx, &opts);

    struct grabber_filter *filters[1] = {
        filter_latency_tester_create(ctx->log, outfile, wait_for_0)
    };
    opts.filters = filters;
    opts.num_filters = 1;

    if (!start_grabber(ctx, &opts)) {
        cctx->success = false;
        return;
    }

    struct device_disrupt_params p = {
        .mode           = DEVICE_DISRUPT_DROP,
        .num_packets    = UINT32_MAX,
    };
    device_disrupt_pkt(cctx->log, dev, 3, &p);

    ctx->latency_tester_receiver = true;
    LOG(cctx, "Receiver setup. Listening to incoming packets.\n");
};

static void write_to_pipe(void *ctx, const char *fmt, va_list va)
{
    struct pipe *p = ctx;
    char buf[4096];
    if (vsnprintf(buf, sizeof(buf), fmt, va) >= sizeof(buf))
        snprintf(buf, sizeof(buf), "(error)\n");
    pipe_write(p, buf, strlen(buf));
}

static void on_ipc_client_event(void *ud, struct pipe *p, unsigned events)
{
    struct nose_ctx *ctx = ud;

    struct client *cl = NULL;
    for (size_t n = 0; n < ctx->num_clients; n++) {
        if (ctx->clients[n]->conn == p) {
            cl = ctx->clients[n];
            break;
        }
    }

    assert(cl);

    if (events & PIPE_EVENT_NEW_DATA) {
        if (p == ctx->rl_pipe) {
            work_readline(ctx);
        } else {
            while (1) {
                char line[4096];
                void *buf;
                size_t size;
                pipe_peek(p, &buf, &size);
                char *nl = memchr(buf, '\n', size);
                if (!nl) {
                    if (size >= sizeof(line))
                        pipe_read(p, NULL, size);
                    pipe_read_more(p);
                    break;
                }
                int len = nl - (char *)buf;
                snprintf(line, sizeof(line), "%.*s", len, (char *)buf);
                pipe_read(p, NULL, len + 1);
                process_command(ctx, line, cl->is_terminal ? NULL : p);
            }
        }
    }

    if (events & PIPE_EVENT_CLOSED_READ) {
        for (size_t n = 0; n < ctx->num_clients; n++) {
            if (ctx->clients[n]->conn == p) {
                ctx->clients[n] = ctx->clients[ctx->num_clients - 1];
                ctx->num_clients--;
                break;
            }
        }
        uninit_readline(ctx, p);
        pipe_drain_destroy(p);
        free(cl);
    }
}

static struct client *add_client(struct nose_ctx *ctx, struct pipe *p,
                                 bool is_terminal)
{
    if (!p)
        return NULL;

    XEXTEND_ARRAY(ctx->clients, ctx->num_clients, 1);
    struct client *cl = XALLOC_PTRTYPE(cl);
    *cl = (struct client){
        .conn = p,
        .is_terminal = is_terminal,
        .is_control = is_terminal,
    };
    ctx->clients[ctx->num_clients++] = cl;

    pipe_set_on_event(cl->conn, ctx, on_ipc_client_event);

    if (pipe_isatty(cl->conn) && cl->is_terminal)
        init_readline(ctx, cl->conn);

    return cl;
}

static void on_ipc_server_event(void *ud, struct pipe *p, unsigned events)
{
    struct nose_ctx *ctx = ud;

    if (events & PIPE_EVENT_NEW_CLIENT) {
        struct pipe *conn = pipe_accept(p);
        if (conn)
            add_client(ctx, conn, false);
    }
}

static void on_extcap_ctrl_in(void *ud, struct pipe *p, unsigned events)
{
    struct nose_ctx *ctx = ud;

    void *buf;
    size_t buf_size;
    pipe_peek(p, &buf, &buf_size);
    uint8_t *pkt = buf;

    if (buf_size > 0 && pkt[0] != 'T') {
        // Shouldn't happen.
        pipe_read(p, NULL, buf_size);
        LOG(ctx, "error parsing extcap input\n");
        goto done;
    }

    if (buf_size < 6) {
        pipe_read_more(p);
        goto done;
    }

    int size = (pkt[1] << 16) | (pkt[2] << 8) | pkt[3];
    if (size < 2) {
        pipe_read(p, NULL, buf_size);
        LOG(ctx, "invalid extcap input\n");
        goto done;
    }
    if (buf_size < 4 + size) {
        pipe_read_more(p);
        goto done;
    }

    // ctrl_number is associated with the "number=" argument in the controls
    // output by handle_extcap().
    int ctrl_number = pkt[4];
    int cmd = pkt[5];

    bool handled = false;
    switch (cmd) {
    case 0: // Initialized
        handled = true;
        break;
    case 1: // Set
        switch (ctrl_number) {
        case 0: // blink
            process_command(ctx, "blink_led", NULL);
            handled = true;
            break;
        case 3: { // command
            char cmd[1 << 16];
            snprintf(cmd, sizeof(cmd), "%.*s", size - 2, pkt + 6);
            process_command(ctx, cmd, NULL);
            // Reset the textbox
            if (ctx->extcap_ctrl_out) {
                uint8_t header[6] = {'T', 0, 0, 2, 3, 1};
                pipe_write(ctx->extcap_ctrl_out, &header, sizeof(header));
            }
            handled = true;
            break;
        }
        }
        break;
    }

    if (!handled)
        LOG(ctx, "got unknown extcap command %d from wireshark.\n", cmd);

    pipe_read(p, NULL, 4 + size);

done:
    if (events & PIPE_EVENT_CLOSED_READ) {
        pipe_destroy(p);
        ctx->extcap_ctrl_in = NULL;
    }
}

static void on_extcap_ctrl_out(void *ud, struct pipe *p, unsigned events)
{
    struct nose_ctx *ctx = ud;

    if (events & PIPE_EVENT_CLOSED_WRITE) {
        pipe_destroy(p);
        ctx->extcap_ctrl_out = NULL;

        grab_stop(ctx);
    }
}

#define PHY_SELECT_DEF(def) \
    {"phy", COMMAND_PARAM_TYPE_INT64, def, "Port/PHY", \
     PARAM_ALIASES({"A", "1"}, {"B", "2"}, {"AB", "3"}, {"none", "0"}, {"-", "0"}), \
     .irange = {0, 3}}

#define PHY_SELECT PHY_SELECT_DEF(NULL)

const struct command_def command_list[] = {
    {"help", "List commands", cmd_help, {
        {"search", COMMAND_PARAM_TYPE_STR, "all", "show help for specific command"}, }},
    {"device_open", "Open USB device", cmd_dev_open, {
        {"name", COMMAND_PARAM_TYPE_STR, "default", "device name",
            .completer = complete_dev_name,
        },
    }},
    {"device_close", "Close USB device", cmd_dev_close},
    {"device_list", "List relevant USB devices", cmd_dev_list},
    {"capture_start", "Start capture", cmd_grab_start, {
        {"file", COMMAND_PARAM_TYPE_STR, "/tmp/test.pcapng", "target filename"}, }},
    {"capture_stop", "Stop capture", cmd_grab_stop, },
    {"mdio_read", "Read MDIO register", cmd_mdio_read, {
        PHY_SELECT,
        {"address", COMMAND_PARAM_TYPE_INT64, NULL, "MDIO register address",
            .irange = {0, 31}},
        {"page", COMMAND_PARAM_TYPE_INT64, "nop", "Register page",
            PARAM_ALIASES({"nop", "-1"}),
            .irange = {-1, 255}},
    }},
    {"mdio_write", "Write MDIO register", cmd_mdio_write, {
        PHY_SELECT,
        {"address", COMMAND_PARAM_TYPE_INT64, NULL, "MDIO register address",
            .irange = {0, 31}},
        {"value", COMMAND_PARAM_TYPE_INT64, NULL, "new register value",
            .irange = {0, 65535}},
        {"page", COMMAND_PARAM_TYPE_INT64, "nop", "Register page",
            PARAM_ALIASES({"nop", "-1"}),
            .irange = {-1, 255}},
    }},
    {"speed", "Set Ethernet speed on both ports", cmd_set_speed, {
        {"speed", COMMAND_PARAM_TYPE_INT64, NULL, "speed mode",
            // also see speed_mode_settings_desc[]
            PARAM_ALIASES({"same", "0"},
                          {"10", "1"},
                          {"100", "2"},
                          {"1000", "3"},
                          {"10half", "5"},
                          {"100half", "6"},
                          {"1000half", "7"},
                          {"manual", "4"}),
            .flags = COMMAND_FLAG_ALIAS_ONLY},
    }},
    {"block_ports", "Port blocker", cmd_block_ports, {
        PHY_SELECT }},
    {"disrupt", "Packet disruptor", cmd_disrupt, {
        PHY_SELECT,
        {"mode", COMMAND_PARAM_TYPE_INT64, "drop", "what to do with packets",
            PARAM_ALIASES({"drop", "0"},
                          {"corrupt", "1"},
                          {"err", "2"}),
            .flags = COMMAND_FLAG_ALIAS_ONLY},
        {"num", COMMAND_PARAM_TYPE_INT64, "1", "number of packets",
            PARAM_ALIASES({"stop", "0"}, {"inf", "4294967295"}),
            .irange = {0, UINT32_MAX}},
        {"skip", COMMAND_PARAM_TYPE_INT64, "0",
            "let N packets pass every time",
            .irange = {0, UINT32_MAX}},
        {"offset", COMMAND_PARAM_TYPE_INT64, "20",
            "corrupt byte offset (0=preamble)",
            .irange = {0, UINT32_MAX}},
    }},
    {"disrupt_stop", "Disable packet disruptor", cmd_disrupt_stop, {
        PHY_SELECT_DEF("AB"),
    }},
    {"inject", "Packet injector", cmd_inject, {
        PHY_SELECT,
        {"data", COMMAND_PARAM_TYPE_STR, "",
            "hex: 0x... 0x.. words, ABCD bytes"},
        {"raw", COMMAND_PARAM_TYPE_BOOL, "false",
            "if true, do not add preamble/SFD/CRC"},
        {"num", COMMAND_PARAM_TYPE_INT64, "1",
            "number of packets (inf=continuous mode)",
            PARAM_ALIASES({"stop", "0"}, {"inf", "4294967295"}),
            .irange = {0, UINT32_MAX}},
        {"gap", COMMAND_PARAM_TYPE_INT64, "12",
            "minimum IPG before/after",
            .irange = {0, UINT32_MAX}},
        {"append-random", COMMAND_PARAM_TYPE_INT64, "0",
            "append this many random bytes",
            .irange = {0, DEV_INJECT_ETH_BUF_SIZE}},
        {"append-zero", COMMAND_PARAM_TYPE_INT64, "0",
            "append this many zero bytes",
            .irange = {0, DEV_INJECT_ETH_BUF_SIZE}},
        {"gen-error", COMMAND_PARAM_TYPE_INT64, "-1",
            "generate error at byte offset",
            PARAM_ALIASES({"disable", "-1"}),
            .irange = {-1, UINT32_MAX}},
        {"file", COMMAND_PARAM_TYPE_STR, "",
            "send packet loaded from file"},
        {"loop-count", COMMAND_PARAM_TYPE_INT64, "0",
            "repeat packet data at end of packet",
            PARAM_ALIASES({"inf", "4294967295"}),
            .irange = {0, UINT32_MAX}},
        {"loop-offset", COMMAND_PARAM_TYPE_INT64, "0",
            "repeat packet data at this offset",
            .irange = {0, DEV_INJECT_ETH_BUF_SIZE}},
        {"nopad", COMMAND_PARAM_TYPE_BOOL, "false",
            "do not pad short packets to mandatory packet length"},
        {"bw-bytes",  COMMAND_PARAM_TYPE_INT64_S, "0",
            "set gap to repeat packets to reach this bytes/second rate",
            .irange = {0, 125000000}},
        {"bw-packets", COMMAND_PARAM_TYPE_INT64, "0",
            "set gap to repeat this many packets per second",
            .irange = {0, 125000000 / 2}},
    }},
    {"inject_stop", "Disable packet injector", cmd_inject_stop, {
        PHY_SELECT_DEF("AB"),
    }},
    {"hw_info", "Show hardware information", cmd_hw_info, {
        {"update", COMMAND_PARAM_TYPE_INT64, "0",
            "Update period in MS (0 disables)",
            .irange = {0, 100000}},
    }},
    {"hw_time_sync", "Sync with hardware clock", cmd_hw_time_sync},
    {"reset_device_settings", "Reset settings stored on the device to defaults.",
        cmd_dev_reset_settings },
    {"cfg_packet", "Write raw config command packet", cmd_cfg_packet, {
        {"data", COMMAND_PARAM_TYPE_STR, NULL,
            "hex: 0x... 0x.. words, ABCD bytes"}, }},
    {"blink_led", "Cause the main LED to blink for a moment.", cmd_identify },
    {"set", "Set a command line option.", cmd_set, {
        {"name", COMMAND_PARAM_TYPE_STR, NULL, "option name, without '--'"},
        {"value", COMMAND_PARAM_TYPE_JSON, NULL, "new option value"}, }},
    {"set_device_phy_wait", "Set PHY link up wait time in ms", cmd_set_phy_time, {
        {"time", COMMAND_PARAM_TYPE_INT64, NULL,
            "wait time in MS",
            .irange = {0, 10737}},
    }},
    {"latency_tester_sender", "setup latency testing (sender role)", cmd_latency_tester_sender, {
        {"stop", COMMAND_PARAM_TYPE_BOOL, "false", "disable testing"},
        {"samples", COMMAND_PARAM_TYPE_INT64, "10000", "number of packets per test run",
            .irange = {1, INT_MAX}},
        {"packet-size", COMMAND_PARAM_TYPE_INT64, "64", "test payload length",
            .irange = {26, DEV_INJECT_MAX_PKT_SIZE}},
        {"delay", COMMAND_PARAM_TYPE_INT64, "1", "delay in milliseconds (approx)",
            .irange = {1, 10000}},
        {"once", COMMAND_PARAM_TYPE_BOOL, "false", "perform only one test run"},
    }},
    {"latency_tester_receiver", "setup latency testing (receiver role)", cmd_latency_tester_receiver, {
        {"stop", COMMAND_PARAM_TYPE_BOOL, "false", "disable testing"},
        {"wait-start", COMMAND_PARAM_TYPE_BOOL, "true", "wait for first sample"},
        {"out-file", COMMAND_PARAM_TYPE_STR, "", "write results to this file"},
    }},
    {"exit", "Exit program", cmd_exit },
    {"reboot", "Restart device", cmd_reboot},
    {0}
};

static int run_commands(struct nose_ctx *ctx, char *cmds)
{
    // In case someone tries to be funny and uses "set cmd ..." in --cmd.
    cmds = xstrdup(cmds);
    struct wordbound *bounds;
    char **words = split_spaces_with_quotes(cmds,  &bounds);
    size_t cmd_start = 0; // offset into cmds string
    int rc = 0;
    for (size_t n = 0; ; n++) {
        bool valid = words && words[n];
        bool flush = !valid;
        if (valid) {
            // Accept only an unquoted ; as command separator. Quoted ";" can be
            // a normal argument to a command (if ever needed).
            if (strcmp(words[n], ";") == 0 && bounds[n].b - bounds[n].a == 1)
                flush = true;
        }

        if (flush) {
            // Split the original string, because we don't want to have any kind
            // of double-escaping hell; basically split_spaces_with_quotes() is
            // done only to find unquoted ; separators in a clean and simple way.
            size_t cmd_end = valid ? bounds[n].a : strlen(cmds);
            char *cmd = xasprintf("%.*s", (int)(cmd_end - cmd_start),
                                  cmds + cmd_start);

            struct command_ctx cctx = {
                .log = ctx->log,
                .priv = ctx,
            };

            command_dispatch(command_list, &cctx, cmd);

            free(cmd);

            if (!cctx.success) {
                rc = 2;
                goto done;
            }

            if (!valid)
                break;

            cmd_start = bounds[n].b + 1;
        }
    }

done:
    for (size_t n = 0; words && words[n]; n++)
        free(words[n]);
    free(words);
    free(bounds);
    free(cmds);
    return rc;
}

static int handle_firmware_update(struct nose_ctx *ctx)
{
    // (duplicates some of the --device logic)
    bool specific_device = strcmp(ctx->opts.device, "none") != 0 &&
                           ctx->opts.device[0];
    bool all = ctx->opts.fw_update_all;
    bool interactive = !all && !specific_device;
    bool force = ctx->opts.fw_update_force;

    if (specific_device && all) {
        LOG(ctx, "Firmware update requested, but both --device and conflicting"
                 " --firmware-update-all provided; exiting.\n");
        return 1;
    }

    void *data;
    size_t size;
    if (!read_file(ctx->log, ctx->opts.fw_update_file, &data, &size))
        return 2;
    int fw_version = fw_verify(ctx->log, data, size);
    if (!fw_version) {
        free(data);
        return 2;
    }

    LOG(ctx, "Firmware file: version %d.%02x\n", fw_version >> 8, fw_version & 0xFF);

    libusb_device **list = NULL;
    libusb_get_device_list(usb_thread_libusb_context(ctx->global->usb_thr), &list);

    long dev_choice = -1;

    if (interactive) {
        LOG(ctx, "Select firmware update action:\n\n");
        LOG(ctx, "  Choice   Address   Serial           Firmware version\n");
        LOG(ctx, " -------------------------------------------------------\n");
        size_t last_valid = 0;
        for (size_t n = 0; list && list[n]; n++) {
            char devname[USB_DEVICE_NAME_LEN];
            char devserial[USB_DEVICE_SERIAL_LEN];
            char ver[20] = "?";

            if (!usb_get_device_name(list[n], devname, sizeof(devname)))
                continue;

            last_valid = n + 1;

            if (!usb_get_device_serial(list[n], devserial, sizeof(devserial)))
                snprintf(devserial, sizeof(devserial), "?");

            struct libusb_device_descriptor desc;
            if (!libusb_get_device_descriptor(list[n], &desc)) {
                char *comment = "";
                if (desc.bcdDevice < fw_version)
                    comment = " (outdated)";
                snprintf(ver, sizeof(ver), "%d.%02x%s", desc.bcdDevice >> 8,
                         desc.bcdDevice & 0xFF, comment);
            }

            LOG(ctx, "  %-8zd %-9s %-16s %-30s\n", n, devname, devserial, ver);
        }
        LOG(ctx, " -------------------------------------------------------\n");
        if (last_valid) {
            LOG(ctx, "  a        Update all devices with outdated firmware\n");
            LOG(ctx, "  b        Force update all devices (dangerous)\n");
            LOG(ctx, "  c        Do nothing and exit\n");
            LOG(ctx, " -------------------------------------------------------\n");
            LOG(ctx, "\nEnter your choice (a number, or one of a, b, c): ");
        } else {
            LOG(ctx, "\nNo devices found! Press enter to continue...\n");
        }
        char input[80];
        if (!fgets(input, sizeof(input), stdin))
            input[0] = '\0';
        if (!last_valid)
            return 1;
        char *end;
        long num = strtol(input, &end, 10);
        if (end != input && end[0] == '\n' && num >= 0 && num < last_valid) {
            dev_choice = num;
            LOG(ctx, "Updating device %ld...\n", dev_choice);
        } else if (strcasecmp(input, "a\n") == 0) {
            all = true;
            force = false;
        } else if (strcasecmp(input, "b\n") == 0) {
            all = true;
            force = true;
        } else {
            bool err = strcasecmp(input, "c\n") != 0;
            if (err)
                LOG(ctx, "Invalid choice, exiting.\n");
            libusb_free_device_list(list, 1);
            free(data);
            return err ? 1 : 0;
        }
    }

    size_t num_devs = 0;
    size_t num_failed = 0;
    size_t num_updated = 0;

    bool last = false;
    for (size_t n = 0; !last; n++) {
        struct device *dev = NULL;

        // Don't blame me, blame C. Just trying to unify it into one code block,
        // while not having painless closures available.
        last = !(list && list[n]);
        if (last) {
            if (!specific_device)
                break;
            dev = device_open(ctx->global, ctx->opts.device);
        } else {
            char devname[USB_DEVICE_NAME_LEN];

            if (specific_device)
                continue;

            if (!all && n != dev_choice)
                continue;

            if (!usb_get_device_name(list[n], devname, sizeof(devname)))
                continue;

            dev = device_open(ctx->global, devname);
        }

        if (dev) {
            if (!force && dev->fw_version >= fw_version) {
                LOG(ctx, "Device has recent or newer firmware version, skipping.\n");
            } else {
                uint32_t addr = FW_BASE_ADDRESS_1 + FW_HEADER_OFFSET;
                if (usb_write_flash(dev->dev, ctx->log, addr, data, size)) {
                    LOG(ctx, "Firmware apparently successfully written.\n");
                    usb_reboot(dev->dev, ctx->log);
                    num_updated++;
                } else {
                    LOG(ctx, "Firmware could not be written!\n");
                    num_failed++;
                }
            }
            device_close(dev);
        } else {
            num_failed++;
        }

        num_devs++;
    }

    libusb_free_device_list(list, 1);
    free(data);

    if (!num_devs) {
        LOG(ctx, "No devices found or invalid selection.\n");
        return 1;
    }

    LOG(ctx, "%zu device(s) found.\n", num_devs);
    size_t skipped = num_devs - (num_failed + num_updated);
    if (skipped)
        LOG(ctx, "%zu device(s) skipped.\n", skipped);
    if (num_updated)
        LOG(ctx, "%zu device(s) successfully updated.\n", num_updated);


    if (num_failed) {
        LOG(ctx, "Warning: %zu device(s) failed to update!\n", num_failed);
        LOG(ctx, "Please try again. If the update already started, but was "
                 "interrupted or failed, then the device will hopefully boot "
                 "from the factory image after a power-cycle, and you can retry "
                 "the firmware update.\n");
    }

    return num_failed ? 3 : 0;
}

#if HAVE_POSIX

// Returns a malloc'ed string with the full wireshark path; NULL if not found.
static char *find_wireshark(void)
{
    char *p = getenv("PATH");
    const char *const names[] = {"wireshark", "Wireshark"};
    while (p && p[0]) {
        void *tmp = NULL;
        char *end = strchr(p, ':');
        char *path = p;
        if (end) {
            path = tmp = strndup(p, end - p);
            end += 1;
        }
        if (!path || !path[0])
            continue;
        for (size_t n = 0; n < ARRAY_LENGTH(names); n++) {
            char *fpath = xasprintf("%s/%s", path, names[n]);
            if (access(fpath, X_OK) == 0) {
                free(tmp);
                return fpath;
            }
            free(fpath);
        }
        free(tmp);
        p = end;
    }
    return NULL;
}

static bool start_wireshark_etc(struct nose_ctx *ctx)
{
    ctx->wireshark_path = find_wireshark();
    if (!ctx->wireshark_path) {
        LOG(ctx, "error: wireshark not found\n");
        return false;
    }

    ctx->fifo_path = xasprintf("/tmp/nose-%d-%d.fifo", getuid(), getpid());
    if (mkfifo(ctx->fifo_path, 0600)) {
        LOG(ctx, "error: could not create FIFO\n");
        return false;
    }

    if (!grab_start(ctx, ctx->log, ctx->fifo_path))
        return false;

    char *argv[] = {ctx->wireshark_path, "-k", "-i", ctx->fifo_path, NULL};
    pid_t pid;
    posix_spawnattr_t attr;
    if (posix_spawnattr_init(&attr))
        report_oom((size_t)-1, __FILE__, __LINE__);
#ifdef POSIX_SPAWN_SETSID
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);
#endif
    int r = posix_spawn(&pid, ctx->wireshark_path, NULL, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);
    if (r) {
        LOG(ctx, "error: failed to spawn '%s'\n", ctx->wireshark_path);
        return false;
    }

    // Note: since process management on UNIX is such a god damn pain, we let
    //       the child process in pid (wireshark) become a zombie when it ends.
    //       But since we terminate anyway when capture ends, this is OK.

    return true;
}

static int term_signal_fd = -1;

static void term_signal(int s)
{
    write(term_signal_fd, &(char){s}, 1);
}

static void on_term_signal(void *ud, struct pipe *p, unsigned events)
{
    struct nose_ctx *ctx = ud;

    if (events & PIPE_EVENT_NEW_DATA) {
        char sig = 0;
        pipe_read(p, &sig, 1);
        if (!event_loop_is_terminate_pending(ctx->ev)) {
            LOG(ctx, "Signal %d received, exiting.\n", sig);
            event_loop_request_terminate(ctx->ev);
        }
    }
}

static void setup_signal_handler(struct nose_ctx *ctx)
{
    int fds[2];
    if (pipe(fds))
        return; // ?

    ctx->signalfd = event_loop_open_pipe(ctx->ev, stack_sprintf(10, "%d", fds[0]),
                                         PIPE_FLAG_READ | PIPE_FLAG_FILENAME_IS_FD);
    if (!ctx->signalfd) {
        close(fds[0]);
        close(fds[1]);
        return;
    }
    pipe_set_on_event(ctx->signalfd, ctx, on_term_signal);

    term_signal_fd = fds[1];
    struct sigaction sa = {
        .sa_handler = term_signal,
        .sa_flags = SA_RESTART | SA_RESETHAND,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    // Do not stop the process if it's trying to read or write from the terminal
    // while being backgrounded.
    struct sigaction saign = { .sa_handler = SIG_IGN };
    sigemptyset(&saign.sa_mask);
    sigaction(SIGTTIN, &saign, NULL);
    sigaction(SIGTTOU, &saign, NULL);
}

#else

static bool file_exists_w(wchar_t *path)
{
    FILE *f = _wfopen(path, L"rb");
    bool exists = !!f;
    if (f)
        fclose(f);
    return exists;
}

static bool start_wireshark_etc(struct nose_ctx *ctx)
{
    REFKNOWNFOLDERID folders[] =
        {&FOLDERID_ProgramFilesX64, &FOLDERID_ProgramFiles};

    wchar_t path[4096] = {0};
    wchar_t *ws_inst_path = L"\\Wireshark\\Wireshark.exe";

    for (size_t idx = 0; idx < ARRAY_LENGTH(folders); idx++) {
        PWSTR res = NULL;
        HRESULT status = SHGetKnownFolderPath(folders[idx], 0, NULL, &res);
        if (!FAILED(status)) {
            snwprintf(path, ARRAY_LENGTH(path), L"%ls%ls", res, ws_inst_path);
            CoTaskMemFree(res);
            if (file_exists_w(path))
                break;
        }
        path[0] = 0;
    }

    // Fallback using env var - useful only for 32 bit exe running on 64 bit OS.
    if (!path[0]) {
        wchar_t *p = _wgetenv(L"ProgramW6432");
        if (p) {
            snwprintf(path, ARRAY_LENGTH(path), L"%ls%ls", p, ws_inst_path);
            if (!file_exists_w(path))
                path[0] = 0;
        }
    }

    if (!path[0]) {
        LOG(ctx, "error: wireshark not found\n");
        return false;
    }

    char fifo[80];
    snprintf(fifo, sizeof(fifo), "\\\\.\\pipe\\wireshark-pipe-%u",
             (unsigned)GetCurrentProcessId());

    HANDLE h = CreateNamedPipeA(fifo, PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_BYTE, 1, 32 * 1024, 32 * 1024, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        LOG(ctx, "error: could not create FIFO\n");
        return false;
    }

    wchar_t cmdline[8192];
    snwprintf(cmdline, ARRAY_LENGTH(cmdline), L"%ls -k -i %s", path, fifo);

    STARTUPINFOW sa = {.cb = sizeof(sa)};
    PROCESS_INFORMATION pi;

    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &sa, &pi))
    {
        LOG(ctx, "error: failed to spawn '%ls'\n", path);
        return false;
    }

    // Wait until the read-end is opened. Trying to write to the pipe before
    // that happen will result in an error.
    // This blocks forever if wireshark does not open the pipe (but errors or
    // fails to fully load).
    ConnectNamedPipe(h, NULL);

    // Apparently we need to use the handle directly. "fd:" is a workaround.
    int fd = _open_osfhandle((intptr_t)h, 0);
    if (!grab_start(ctx, ctx->log, stack_sprintf(10, "fd:%d", fd)))
        return false;

    // Note: since file management on win32 is such a god damn pain, we let
    //       the fifo handle etc. leak. But since we terminate anyway when
    //       capture ends, this is OK. (Probably.)

    return true;
}

#endif

static void enable_extcap_mode(struct nose_ctx *ctx)
{
    if (!ctx->extcap_active) {
        ctx->extcap_active = true;
        flush_log(ctx);
        ctx->mute_terminal = true;
        ctx->log_indirect = true;
    }
}

static bool handle_extcap(struct nose_ctx *ctx)
{
    if (ctx->opts.extcap_interfaces) {
        printf("extcap {version=1.0}{help=https://intona.eu/doc/ethernet-debugger}\n");

        libusb_device **list = NULL;
        libusb_get_device_list(usb_thread_libusb_context(ctx->global->usb_thr),
                               &list);
        for (size_t n = 0; list && list[n]; n++) {
            char name[USB_DEVICE_NAME_LEN];
            char serial[USB_DEVICE_SERIAL_LEN];
            char *usertxt = NULL;

            if (!usb_get_device_name(list[n], name, sizeof(name)))
                continue;

            if (usb_get_device_serial(list[n], serial, sizeof(serial))) {
                usertxt = serial;
            } else {
                usertxt = name;
            }

            printf("interface {value=%s}{display=Ethernet Debugger USB (%s)}\n",
                   name, usertxt);
        }

        libusb_free_device_list(list, 1);

        // Extcap toolbar controls.
        printf("control {number=3}{type=string}{display=Command}{tooltip=Send a command to driver (see help).}\n");
        printf("control {number=1}{type=button}{role=logger}{display=Log}{tooltip=Show log window}\n");
        printf("control {number=0}{type=button}{role=control}{display=Blink LED}{tooltip=Blink the main LED for a moment}\n");
        printf("control {number=2}{type=button}{role=help}{display=Help}{tooltip=Open help URL}\n");
        goto exit_immediately;
    }

    if (ctx->opts.extcap_version[0])
        enable_extcap_mode(ctx);

    if (ctx->opts.extcap_dlts)
        goto exit_immediately;

    if (ctx->opts.extcap_config) {
        printf("arg {number=0}{call=--capture-stats}{display=Log stats}{tooltip=Output stats to log view}{type=boolflag}{default=false}\n");
        printf("arg {number=1}{call=--strip-frames}{display=Strip physical layer fields}{tooltip=Strip preamble, SFD, and (if the option below is enabled) FCS from ethernet frames (changes pcap linktype)}{type=boolflag}{default=false}\n");
        printf("arg {number=1}{call=--strip-fcs}{display=Strip FCS (CRC) when stripping physical layer}{tooltip=If the above option is enabled, the FCS/CRC field is also stripped. Wireshark won't be able to check frame integrity anymore.}{type=boolflag}{default=false}\n");
        goto exit_immediately;
    }

    if (ctx->opts.extcap_interface[0]) {
        // "Redirect" it to --device in a slightly bogus way.
        free(ctx->opts.device);
        ctx->opts.device = xstrdup(ctx->opts.extcap_interface);
        enable_extcap_mode(ctx);
    }

    if (ctx->opts.extcap_ctrl_in[0]) {
        enable_extcap_mode(ctx);
        ctx->extcap_ctrl_in = event_loop_open_pipe(ctx->ev, ctx->opts.extcap_ctrl_in,
                                                   PIPE_FLAG_READ |
                                                   PIPE_FLAG_OPEN_BLOCK);
        if (!ctx->extcap_ctrl_in) {
            LOG(ctx, "could not open '%s'\n", ctx->opts.extcap_ctrl_in);
            return false;
        }
        pipe_set_on_event(ctx->extcap_ctrl_in, ctx, on_extcap_ctrl_in);
    }

    if (ctx->opts.extcap_ctrl_out[0]) {
        enable_extcap_mode(ctx);
        ctx->extcap_ctrl_out = event_loop_open_pipe(ctx->ev, ctx->opts.extcap_ctrl_out,
                                                    PIPE_FLAG_WRITE |
                                                    PIPE_FLAG_OPEN_BLOCK);
        if (!ctx->extcap_ctrl_out) {
            LOG(ctx, "could not open '%s'\n", ctx->opts.extcap_ctrl_out);
            return false;
        }
        pipe_set_on_event(ctx->extcap_ctrl_out, ctx, on_extcap_ctrl_out);
    }

    return true;

exit_immediately:
    fflush(stdout);
    _Exit(0);
}

static void on_terminate(void *ud, struct event_loop *ev)
{
    struct nose_ctx *ctx = ud;

    usbdev_close(ctx);

    for (size_t n = 0; n < ctx->num_clients; n++) {
        struct client *cl = ctx->clients[n];
        uninit_readline(ctx, cl->conn);
        pipe_destroy(cl->conn);
        free(cl);
    }
    ctx->num_clients = 0;

    pipe_destroy(ctx->ipc_server);
    ctx->ipc_server = NULL;

    timer_destroy(ctx->latency_tester_timer);
    ctx->latency_tester_timer = NULL;

    timer_destroy(ctx->hw_info_timer);
    ctx->hw_info_timer = NULL;

    pipe_destroy(ctx->extcap_ctrl_in);
    ctx->extcap_ctrl_in = NULL;

    pipe_destroy(ctx->extcap_ctrl_out);
    ctx->extcap_ctrl_out = NULL;

    event_loop_exit(ctx->ev);
}

static bool has_control_input(struct nose_ctx *ctx)
{
    if (ctx->ipc_server)
        return true;

    for (size_t n = 0; n < ctx->num_clients; n++) {
        if (ctx->clients[n]->is_control)
            return true;
    }

    return false;
}

static void check_auto_exit(struct nose_ctx *ctx)
{
    bool capturing = ctx->usb_dev && ctx->usb_dev->grabber;
    bool has_control = has_control_input(ctx);
    const char *reason = NULL;

    if (event_loop_is_terminate_pending(ctx->ev))
        return;

    int effective_exit_on = ctx->opts.exit_on;
    if (!effective_exit_on)
        effective_exit_on = 4; // default to "no-input"

    switch (effective_exit_on) {
    case 1: // "no-capture"
        if (!capturing)
            reason = "Exiting because capture ended.\n";
        break;
    case 2: // "never"
        break;
    case 3: // "always"
        reason = "Exiting immediately as requested by --exit-on.\n";
        break;
    case 4: // "no-input"
        if (!has_control)
            reason = "Exiting because no controlling input (terminal/IPC) present.\n";
        break;
    default:
        assert(0);
    }

    if (reason) {
        LOG(ctx, "%s", reason);
        event_loop_request_terminate(ctx->ev);
    }
}

static void on_idle(void *ud, struct event_loop *ev)
{
    struct nose_ctx *ctx = ud;

    check_auto_exit(ctx);
}

static void on_exit_timer(void *ud, struct timer *t)
{
    struct nose_ctx *ctx = ud;

    LOG(ctx, "Exiting because timeout elapsed.\n");
    event_loop_request_terminate(ctx->ev);
}

int main(int argc, char **argv)
{
    struct event_loop *ev = event_loop_create();

    struct nose_ctx *ctx = &(struct nose_ctx){
        .ev = ev,
        .global = &(struct global){{0}},
    };
    pthread_mutex_init(&ctx->log_fifo_writer_lock, NULL);

    ctx->log_event = event_loop_create_event(ev);
    event_set_on_signal(ctx->log_event, ctx, on_log_data);

    ctx->phy_update_event = event_loop_create_event(ev);
    event_set_on_signal(ctx->phy_update_event, ctx, on_phy_change);

    ctx->usb_discon_event = event_loop_create_event(ev);
    event_set_on_signal(ctx->usb_discon_event, ctx, on_usb_discon);

    ctx->check_links_timer = event_loop_create_timer(ctx->ev);
    timer_set_on_timer(ctx->check_links_timer, ctx, on_check_links);

    if (!byte_fifo_alloc(&ctx->log_fifo, 64 * 1024))
        abort();
    ctx->global->log = (struct logfn){ctx, log_write};
    ctx->global->loghint = (struct logfn){ctx, log_write_hint};
    ctx->log = ctx->global->log;

    event_loop_set_on_terminate(ev, ctx, on_terminate);
    event_loop_set_on_idle(ev, ctx, on_idle);

    ctx->opts = option_defs;
    options_init_allocs(option_list, &ctx->opts);

    if (!options_parse(ctx->log, option_list, &ctx->opts, argv))
        goto error_exit;

    ctx->global->usb_thr = usb_thread_create(ctx->global);
    if (!ctx->global->usb_thr)
        goto error_exit;

    if (ctx->opts.init_cmds[0]) {
        int err = run_commands(ctx, ctx->opts.init_cmds);
        if (err) {
            flush_log(ctx);
            exit(err);
        }
    }

    if (strcmp(ctx->opts.device, "help") == 0) {
        process_command(ctx, "device_list", NULL);
        flush_log(ctx);
        exit(0);
    }

    if (ctx->opts.print_version) {
        printf("Version: %s\n", version);
        printf("Optional features:");
#if HAVE_READLINE
        printf(" libreadline");
#endif
        printf("\n");
        exit(0);
    }

    if (ctx->opts.run_selftest)
        run_init_and_test(ctx->global, ctx->opts.device, ctx->opts.init_serial);

    if (ctx->opts.init_serial[0]) {
        LOG(ctx, "Using --selftest-serial requires --selftest.\n");
        goto error_exit;
    }

    if (ctx->opts.fw_update_file[0]) {
        int r = handle_firmware_update(ctx);
        flush_log(ctx);
        return r;
    }

    if (!handle_extcap(ctx))
        goto error_exit;

    if (strcmp(ctx->opts.device, "none") != 0) {
        struct device *dev = device_open(ctx->global, ctx->opts.device);
        if (dev) {
            handle_device_opened(ctx, dev);
        } else {
            // Only make it an error if a specific device was selected. If
            // other options are used which need a device, it will error out
            // anyway.
            if (ctx->opts.device[0]) {
                LOG(ctx, "Exiting because device could not be opened.\n");
                if (!ctx->extcap_active)
                    goto error_exit;
            }
        }

        if (!dev && ctx->extcap_active) {
            // Failure in extcap mode: this is a mess because of how Wireshark
            // acts and blocking pipe open calls etc.
            // Beware that Wireshark can remain broken if the extcap binary
            // "misbehaves" once and leaves it around as zombie. (Try restarting
            // Wireshark when debugging this and it seems to act weird.)
            if (ctx->opts.capture_to[0]) {
                ctx->extcap_fake_fifo = event_loop_open_pipe(ctx->ev,
                    ctx->opts.capture_to, PIPE_FLAG_WRITE | PIPE_FLAG_OPEN_BLOCK);
            }
            void *buf;
            size_t sz;
            grabber_get_pcap_dummy_header(&buf, &sz);
            if (sz)
                pipe_write(ctx->extcap_fake_fifo, buf, sz);
            // Just wait until the mainloop has written the data and exit after
            // a while. This is just a workaround so no effort is made to check
            // when writing has finished; the timeout is needed to avoid another
            // annoying Wireshark interaction error message.
            ctx->opts.capture_to[0] = '\0';
            ctx->opts.exit_on = 2;
            ctx->opts.exit_timeout = 1;
            // Show what happened as extcap error message.
            flush_log(ctx);
            if (ctx->extcap_prelog_sz)
                extcap_send_msg(ctx, 0, 9, ctx->extcap_prelog, ctx->extcap_prelog_sz);
        }
    }

    ctx->extcap_prelog_done = true;
    free(ctx->extcap_prelog);
    ctx->extcap_prelog = NULL;
    ctx->extcap_prelog_sz = 0;

    bool exit_on_capture_stop = false;

    if (ctx->opts.run_wireshark) {
        if (!ctx->usb_dev)
            goto error_exit;
        if (!start_wireshark_etc(ctx))
            goto error_exit;
        exit_on_capture_stop = true;
    }

    if (ctx->opts.capture_to[0]) {
        if (!grab_start(ctx, ctx->log, ctx->opts.capture_to))
            goto error_exit;
        exit_on_capture_stop = true;
    }

    if (exit_on_capture_stop && !ctx->opts.exit_on)
        ctx->opts.exit_on = 1; // "no-capture"

    if (ctx->opts.ipc_server[0]) {
        char *ipc_path = NULL;
        if (strchr(ctx->opts.ipc_server, '/') ||
            strchr(ctx->opts.ipc_server, '\\'))
        {
            ipc_path = xstrdup(ctx->opts.ipc_server);
        } else {
            ipc_path = pipe_format_pipe_path(ctx->opts.ipc_server);
        }
        ctx->ipc_server = event_loop_open_pipe(ctx->ev, ipc_path, PIPE_FLAG_SERVE);
        if (!ctx->ipc_server) {
            LOG(ctx, "error: creating IPC server failed.\n");
            goto error_exit;
        }
        pipe_set_on_event(ctx->ipc_server, ctx, on_ipc_server_event);

        LOG(ctx, "Serving IPC on: %s\n", ipc_path);
        free(ipc_path);
    }

    if (ctx->opts.ipc_connect[0]) {
        struct pipe *p = event_loop_open_pipe(ctx->ev, ctx->opts.ipc_connect,
                                              PIPE_FLAG_READ | PIPE_FLAG_WRITE);
        struct client *cl = add_client(ctx, p, false);
        if (!cl) {
            LOG(ctx, "error: creating IPC connection failed.\n");
            goto error_exit;
        }
        cl->is_control = true;
    }

#if HAVE_POSIX
    setup_signal_handler(ctx);
#endif

    if (!ctx->extcap_active) {
        struct pipe *p = event_loop_open_pipe(ctx->ev, "/dev/stdin", PIPE_FLAG_READ);
        add_client(ctx, p, true);
    }

    if (ctx->opts.post_init_cmds[0]) {
        int err = run_commands(ctx, ctx->opts.post_init_cmds);
        if (err) {
            flush_log(ctx);
            exit(err);
        }
    }

    if (ctx->opts.exit_timeout >= 0) {
        ctx->exit_timer = event_loop_create_timer(ctx->ev);
        timer_set_on_timer(ctx->exit_timer, ctx, on_exit_timer);
        timer_start(ctx->exit_timer, ctx->opts.exit_timeout * 1000);
    }

    event_loop_run(ev);
    options_free(option_list, &ctx->opts);
    if (ctx->fifo_path)
        unlink(ctx->fifo_path);
    free(ctx->fifo_path);
    free(ctx->wireshark_path);
    free(ctx->clients);
    usb_thread_destroy(ctx->global->usb_thr);

    event_destroy(ctx->phy_update_event);
    event_destroy(ctx->usb_discon_event);
    timer_destroy(ctx->check_links_timer);
    timer_destroy(ctx->grabber_status_timer);
    timer_destroy(ctx->exit_timer);
    pipe_destroy(ctx->signalfd);
    event_destroy(ctx->log_event);
    pipe_destroy(ctx->extcap_fake_fifo);
    event_loop_destroy(ev);

    flush_log(ctx);
    byte_fifo_dealloc(&ctx->log_fifo);
    pthread_mutex_destroy(&ctx->log_fifo_writer_lock);
    return 0;

error_exit:
    if (ctx->extcap_active) {
        LOG(ctx, "Capture failed.\n");
        ctx->mute_terminal = false; // let flush_log() write to stderr
    }
    flush_log(ctx);
    return 1;
}
