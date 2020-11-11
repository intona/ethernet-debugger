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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cmd_parser.h"
#include "crc32.h"
#include "device.h"
#include "event_loop.h"
#include "fifo.h"
#include "filters.h"
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

extern char **environ;

static const struct command_def command_list[];

struct options {
    int64_t verbosity;
    bool run_selftest;
    char *init_serial;
    bool run_wireshark;
    char *device;
    char *fw_update_file;
    char *capture_to;
    char *ipc_connect;
    char *ipc_server;
    int64_t softbuf;
    int64_t usbbuf;
    bool strip_frames;
    bool capture_stats;
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
        .flags = COMMAND_FLAG_RUNTIME},
    {"capture-usb-buffer", offsetof(struct options, usbbuf),
        COMMAND_PARAM_TYPE_INT64_S,
        "Capture libusb buffer (in bytes)",
        .flags = COMMAND_FLAG_RUNTIME},
    {"capture-stats", offsetof(struct options, capture_stats),
        COMMAND_PARAM_TYPE_BOOL,
        "Show capture statistics every 1 seconds.",
        .flags = COMMAND_FLAG_RUNTIME},
    {"strip-frames", offsetof(struct options, strip_frames),
        COMMAND_PARAM_TYPE_BOOL,
        "Strip preamble, SFD, and FCS from ethernet frames.",
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
    struct grabber_status grabber_status_prev;
    struct pipe *ipc_server;
    struct pipe *signalfd;
    struct logfn log;
    atomic_bool log_indirect;
    bool mute_terminal;
    bool exit_on_capture_stop;
    bool extcap_active;
    struct pipe *extcap_ctrl_in, *extcap_ctrl_out;
    char *fifo_path; // for delete-on-exit
    char *wireshark_path;
    // Put all log output through a FIFO. Makes dealing with text from random
    // threads easier to deal with.
    struct byte_fifo log_fifo;
    struct event *log_event;
    struct client **clients;
    size_t num_clients;
    struct phy_status prev_phy_st[2];
    uint64_t last_link_up_time[2]; // in get_time_us()
    uint64_t last_link_down_time[2]; // in get_time_us()
    uint64_t num_link_changes[2];
};

struct client {
    struct pipe *conn;
    bool is_terminal;
    bool exit_on_close;
};

#define MAX_LOG_RECORD 512

static void log_write_lev(void *pctx, const char *fmt, va_list va, int lev)
{
    struct nose_ctx *ctx = pctx;
    char buf[MAX_LOG_RECORD + 1];
    vsnprintf(buf, sizeof(buf), fmt, va);

    if (lev > ctx->opts.verbosity)
        return;

    if (!ctx->log_indirect)
        printf("%s", buf);

    // Split by lines, because it's convenient.
    char *cur = buf;
    while (cur[0]) {
        size_t len = strcspn(cur, "\n");
        uint16_t tlen = MIN(len, MAX_LOG_RECORD);
        // Silently discard if it doesn't fit in completely.
        byte_fifo_write_atomic_2(&ctx->log_fifo, &tlen, 2, cur, tlen);
        cur += len + (cur[len] == '\n');
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

static void log_extcap(struct nose_ctx *ctx, char *line)
{
    if (!ctx->extcap_ctrl_out)
        return;

    int line_len = strlen(line);
    int size = 2 + line_len;
    uint8_t header[6] = {
        'T',
        size >> 16, (size >> 8) & 0xFF, size & 0xFF,
        1,
        2
    };

    pipe_write(ctx->extcap_ctrl_out, &header, sizeof(header));
    pipe_write(ctx->extcap_ctrl_out, line, line_len);
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
            FILE *f = ctx->extcap_active ? stderr : stdout;
            fprintf(f, "%s", buf);
            fflush(f);
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

    event_reset(ev);

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
    command_list_help(command_list, cctx->log);
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

    if (speed[0] == 10 || speed[1] == 10) {
        LOG(ctx, "Warning: 10Mbit mode is not supported.\n");
    } else if (speed[0] && speed[1] && speed[0] != speed[1]) {
        LOG(ctx, "Warning: links have different speed. Communication is blocked.\n");
    } else if (!speed[0] != !speed[1]) {
        LOG(ctx, "Warning: only one port has a link.\n");
    } else if (!speed[0] && !speed[1]) {
        LOG(ctx, "Warning: no link.\n");
    }
}

static void on_phy_change(void *ud, struct event *ev)
{
    struct nose_ctx *ctx = ud;

    event_reset(ev);

    struct device *dev = ctx->usb_dev;
    if (!dev)
        return;

    for (int port = 1; port <= 2; port++) {
        struct phy_status st;
        device_get_phy_status(dev, port, &st);
        // We don't really know which port or what changed, so whatever.
        LOG(ctx, "PHY %d: link=%s speed=%dMBit\n", port, st.link ? "up" : "down",
            st.speed);
        timer_start(ctx->check_links_timer, 2000);

        struct phy_status pst = ctx->prev_phy_st[port - 1];
        if (pst.link != st.link || pst.speed != st.speed) {
            ctx->num_link_changes[port - 1]++;

            if (st.link) {
                ctx->last_link_up_time[port - 1] = get_time_us();
            } else {
                ctx->last_link_down_time[port - 1] = get_time_us();
            }
        }
        ctx->prev_phy_st[port - 1] = st;
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
        if (ctx->exit_on_capture_stop)
            event_loop_request_terminate(ctx->ev);
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

    event_reset(ev);

    struct device *dev = ctx->usb_dev;
    if (!dev)
        return;

    usbdev_close(ctx);
}

static void handle_device_opened(struct nose_ctx *ctx, struct device *dev)
{
    assert(dev);
    assert(!ctx->usb_dev);

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
            LOG(cctx, " - '%s'\n", devname);
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

static void on_grabber_status_timer(void *ud, struct timer *t)
{
    struct nose_ctx *ctx = ud;

    assert(ctx->usb_dev->grabber);

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

        const int mib = 1024 * 1024;

        LOG(ctx,
            " Port %zd: Packets transmitted (delta): %"PRIu64" (%"PRIu64")\n"
            "         Bytes captured (delta): %"PRId64" MiB (%"PRIu64" MiB)\n"
            "         CRC errors (delta): %"PRId64" (%"PRIu64")\n"
            "         Times silence last link up / down: %.1fs / %.1fs\n"
            "         Link up / down changes: %"PRIu64"\n"
            "         Buffer fill: %.0f%% (%"PRId64" overflows)\n",
            p,
            pst.num_packets,
            pst.num_packets - pst_prev.num_packets,
            pst.num_bytes / mib,
            (pst.num_bytes - pst_prev.num_bytes) / mib,
            pst.num_crcerr,
            pst.num_crcerr - pst_prev.num_crcerr,
            last_link_up, last_link_down,
            ctx->num_link_changes[p],
            100 * pst.sw_buffer_sz / (double)pst.sw_buffer_sz_max,
            pst.overflows + (pst.sw_dropped != pst_prev.sw_dropped));
    }

    ctx->grabber_status_prev = st;
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

    struct grabber_options opts = {
        .filename = file,
        .soft_buffer = ctx->opts.softbuf, // TODO: can overflow on 32 bit
        .usb_buffer = ctx->opts.usbbuf,
        .linktype = ctx->opts.strip_frames ? LINKTYPE_ETHERNET
                                           : LINKTYPE_ETHERNET_MPACKET,
        .device = ctx->usb_dev,
        .filters = filters,
        .num_filters = num_filters,
    };

    grabber_start(ctx->global, &opts);
    bool success = !!ctx->usb_dev->grabber;

    if (success) {
        ctx->grabber_status_timer = event_loop_create_timer(ctx->ev);
        timer_set_on_timer(ctx->grabber_status_timer, ctx, on_grabber_status_timer);
        timer_start(ctx->grabber_status_timer, 1000);

        grabber_read_status(ctx->usb_dev->grabber, &ctx->grabber_status_prev);
    }

    LOG(ctx, "Starting capture thread %s.\n", success ? "succeeded" : "failed");
    return success;
}

static void cmd_grab_start(struct command_ctx *cctx, struct command_param *params,
                           size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    cctx->success = grab_start(ctx, cctx->log, params[0].p_str);
}

static void cmd_grab_stop(struct command_ctx *cctx, struct command_param *params,
                          size_t num_params)
{
    struct nose_ctx *ctx = cctx->priv;

    grab_stop(ctx);
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

    int reg = params[1].p_int;
    int p = params[3].p_int;
    if (p >= 0)
        reg = MDIO_PAGE_REG(p, reg);

    int r = device_mdio_write(dev, params[0].p_int, reg, params[2].p_int);
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

    const char *mode = params[0].p_str;
    int speed = 0;
    int autoneg = 0;
    if (strcmp(mode, "1000") == 0) {
        speed = 2;
    } else if (strcmp(mode, "100") == 0) {
        speed = 1;
    } else if (strcmp(mode, "10") == 0) {
        speed = 0;
    } else if (strcmp(mode, "auto") == 0) {
        autoneg = 1;
    } else {
        LOG(cctx, "argument must be one of: 10 100 1000 auto\n");
        cctx->success = false;
        return;
    }
    uint16_t v = (1 << 15) |                // reset
                 ((!!(speed & 1)) << 13) |  // speed select
                 (!!((speed & 2)) << 6) |
                 (1 << 8) |                 // full duplex
                 (autoneg << 12);           // auto negotiation enable

    int r = device_mdio_write(dev, 3, 0, v);
    if (r >= 0) {
        LOG(cctx, "setting speed to %s\n", mode);
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
    bool drop = params[1].p_bool;
    int num = CLAMP(params[2].p_int, 0, 0xFF);
    int skip = CLAMP(params[3].p_int, 0, (1 << 4));
    int offset = CLAMP(params[4].p_int, 0, (1 << 12));

    uint32_t cmd = ((ports & 3u) << (24 + 6)) | (drop << (24 + 5)) | (2 << 24) |
                   (num << 16) | (skip << 12) | offset;

    int r = device_config_raw(dev, &cmd, 1, NULL, NULL);
    if (r < 0) {
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
    bool raw = params[2].p_bool;
    int repeat = CLAMP(params[3].p_int, 0, 15);
    int gap = CLAMP(params[4].p_int, 0, 0xFF);
    int random = CLAMP(params[5].p_int, 0, DEV_INJECT_ETH_BUF_SIZE);

    uint8_t *bytes = NULL;
    size_t size = 0;

    if (!parse_hex(cctx->log, s, &bytes, &size))
        goto done;

    size_t payload = size + random;
    // non-raw => pad to standard size
    while (size && !raw && payload < 46)
        payload += 1;

    size_t nsize = payload + (raw ? 0 : 8 + 4);
    uint8_t *ndata = xalloc(nsize);
    memcpy(ndata, bytes, size);

    free(bytes);
    bytes = ndata;

    for (size_t n = 0; n < random; n++)
        bytes[size + n] = rand() & 0xFF;

    if (!raw && payload) {
        uint32_t crc = crc32(~(uint32_t)0, bytes, payload);
        memmove(bytes + 8, bytes, payload);
        memcpy(bytes, "UUUUUUU\xD5", 8);
        memcpy(bytes + 8 + payload, &crc, 4);
        payload += 8 + 4;
    }

    cctx->success =
        device_inject_pkt(cctx->log, dev, ports, repeat, gap, bytes, payload);

done:
    free(bytes);
}

static void cmd_hw_info(struct command_ctx *cctx, struct command_param *params,
                        size_t num_params)
{
    LOG(cctx, "Host tool version: %s\n", version);

    struct device *dev = require_dev(cctx);
    if (!dev)
        return;

    struct libusb_device_descriptor desc;
    if (!libusb_get_device_descriptor(libusb_get_device(dev->dev), &desc)) {
        LOG(cctx, "Firmware version: %d.%02d\n", desc.bcdDevice >> 8,
            desc.bcdDevice & 0xFF);

        if (desc.iSerialNumber) {
            unsigned char text[256];
            if (libusb_get_string_descriptor_ascii(dev->dev, desc.iSerialNumber,
                                                   text, sizeof(text)) > 0)
                LOG(cctx, "Serial number: %s\n", text);
        }
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
    res = NULL;
    res_num = 0;

    cmd = 5 << 24;
    r = device_config_raw(dev, &cmd, 1, &res, &res_num);
    if (r < 0 || cmd == (uint32_t)-1 || res_num < 2) {
        LOG(cctx, "error: failed to retrieve hwrev\n");
        cctx->success = false;
    } else {
        LOG(cctx, "HWREV: %"PRIu32"\n", res[1] & 7);
    }

    free(res);
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

    event_loop_request_terminate(ctx->ev);
}

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
        while (1) {
            char line[100];
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

    if (events & PIPE_EVENT_CLOSED_READ) {
        for (size_t n = 0; n < ctx->num_clients; n++) {
            if (ctx->clients[n]->conn == p) {
                if (ctx->clients[n]->exit_on_close)
                    event_loop_request_terminate(ctx->ev);
                ctx->clients[n] = ctx->clients[ctx->num_clients - 1];
                ctx->num_clients--;
                break;
            }
        }
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
        .exit_on_close = is_terminal,
    };
    ctx->clients[ctx->num_clients++] = cl;

    pipe_set_on_event(cl->conn, ctx, on_ipc_client_event);

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
        return;
    }

    if (buf_size < 6) {
        pipe_read_more(p);
        return;
    }

    int size = (pkt[1] << 16) | (pkt[2] << 8) | pkt[3];
    if (size < 2) {
        pipe_read(p, NULL, buf_size);
        LOG(ctx, "invalid extcap input\n");
        return;
    }
    if (buf_size < 4 + size) {
        pipe_read_more(p);
        return;
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
    }
}

#define PHY_SELECT \
    {"phy", COMMAND_PARAM_TYPE_INT64, NULL, "Port/PHY (1=A, 2=B, 3=both)"}

static const struct command_def command_list[] = {
    {"help", "List commands", cmd_help},
    {"device_open", "Open USB device", cmd_dev_open, {
        {"name", COMMAND_PARAM_TYPE_STR, "default", "device name"}, }},
    {"device_close", "Close USB device", cmd_dev_close},
    {"device_list", "List relevant USB devices", cmd_dev_list},
    {"capture_start", "Start capture", cmd_grab_start, {
        {"file", COMMAND_PARAM_TYPE_STR, "/tmp/test.pcapng", "target filename"}, }},
    {"capture_stop", "Stop capture", cmd_grab_stop, },
    {"mdio_read", "Read MDIO register", cmd_mdio_read, {
        PHY_SELECT,
        {"address", COMMAND_PARAM_TYPE_INT64, NULL, "MDIO register address"},
        {"page", COMMAND_PARAM_TYPE_INT64, "-1", "Register page (-1=NOP)"}, }},
    {"mdio_write", "Write MDIO register", cmd_mdio_write, {
        PHY_SELECT,
        {"address", COMMAND_PARAM_TYPE_INT64, NULL, "MDIO register address"},
        {"value", COMMAND_PARAM_TYPE_INT64, NULL, "new register value"},
        {"page", COMMAND_PARAM_TYPE_INT64, "-1", "Register page (-1=NOP)"}, }},
    {"speed", "Set Ethernet speed on both ports", cmd_set_speed, {
        {"speed", COMMAND_PARAM_TYPE_STR, "10, 100, 1000, or auto"}, }},
    {"disrupt", "Packet disruptor", cmd_disrupt, {
        PHY_SELECT,
        {"drop", COMMAND_PARAM_TYPE_BOOL, "false", "drop only"},
        {"num", COMMAND_PARAM_TYPE_INT64, "1",
            "number of packets (0=stop, 0xFF=all)"},
        {"skip", COMMAND_PARAM_TYPE_INT64, "0",
            "let N packets pass every time"},
        {"offset", COMMAND_PARAM_TYPE_INT64, "22",
            "corrupt byte offset (0=preamble)"}, }},
    {"inject", "Packet injector", cmd_inject, {
        PHY_SELECT,
        {"data", COMMAND_PARAM_TYPE_STR, NULL,
            "hex: 0x... 0x.. words, ABCD bytes"},
        {"raw", COMMAND_PARAM_TYPE_BOOL, "false",
            "if true, do not add preamble/SFD/CRC"},
        {"repeat", COMMAND_PARAM_TYPE_INT64, "0",
            "repeat count (15==continuous mode)"},
        {"gap", COMMAND_PARAM_TYPE_INT64, "12", "minimum IPG before/after"},
        {"append_random", COMMAND_PARAM_TYPE_INT64, "0",
            "append this many bytes random data"}, }},
    {"hw_info", "Show hardware information", cmd_hw_info},
    {"cfg_packet", "Write raw config command packet", cmd_cfg_packet, {
        {"data", COMMAND_PARAM_TYPE_STR, NULL,
            "hex: 0x... 0x.. words, ABCD bytes"}, }},
    {"blink_led", "Cause the main LED to blue for a moment.", cmd_identify },
    {"set", "Set a command line option.", cmd_set, {
        {"name", COMMAND_PARAM_TYPE_STR, NULL, "option name (without '--')"},
        {"value", COMMAND_PARAM_TYPE_JSON, NULL, "new option value"}, }},
    {"exit", "Exit program", cmd_exit },
    {0}
};

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
    if (posix_spawn(&pid, ctx->wireshark_path, NULL, NULL, argv, environ)) {
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
        LOG(ctx, "Signal %d received, exiting.\n", sig);
        event_loop_request_terminate(ctx->ev);
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
            char devname[USB_DEVICE_NAME_LEN];

            if (!usb_get_device_name(list[n], devname, sizeof(devname)))
                continue;

            printf("interface {value=%s}{display=Ethernet Debugger USB (%s)}\n",
                   devname, devname);
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
        printf("arg {number=1}{call=--strip-frames}{display=Strip physical layer fields}{tooltip=Strip preamble, SFD, and FCS from ethernet frames (pcap linktype)}{type=boolflag}{default=false}\n");
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
        pipe_destroy(cl->conn);
        free(cl);
    }
    ctx->num_clients = 0;

    event_loop_exit(ctx->ev);
}

int main(int argc, char **argv)
{
    struct event_loop *ev = event_loop_create();

    struct nose_ctx *ctx = &(struct nose_ctx){
        .ev = ev,
        .global = &(struct global){{0}},
    };

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

    ctx->opts = option_defs;
    options_init_allocs(option_list, &ctx->opts);

    if (!options_parse(ctx->log, option_list, &ctx->opts, argv))
        goto error_exit;

    ctx->global->usb_thr = usb_thread_create(ctx->global);
    if (!ctx->global->usb_thr)
        goto error_exit;

    if (strcmp(ctx->opts.device, "help") == 0) {
        process_command(ctx, "device_list", NULL);
        flush_log(ctx);
        exit(0);
    }

    if (ctx->opts.print_version) {
        printf("Version: %s\n", version);
        exit(0);
    }

    if (ctx->opts.run_selftest)
        run_init_and_test(ctx->global, ctx->opts.device, ctx->opts.init_serial);

    if (ctx->opts.init_serial[0]) {
        LOG(ctx, "Using --selftest-serial requires --selftest.");
        goto error_exit;
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
                goto error_exit;
            }
        }
    }

    if (ctx->opts.fw_update_file[0]) {
        if (!ctx->usb_dev)
            goto error_exit;
        if (usb_fw_update(ctx->usb_dev->dev, ctx->log, ctx->opts.fw_update_file, 1))
        {
            LOG(ctx, "Firmware apparently successfully written.\n");
            usb_reboot(ctx->usb_dev->dev, ctx->log);
            return 0;
        } else {
            LOG(ctx, "Firmware could not be written! Please try again. If the "
                "update already started, but was interrupted or failed, and the "
                "device is power-cycled, it will hopefully boot from the "
                "factory image.\n");
            goto error_exit;
        }
    }

    if (ctx->opts.run_wireshark) {
        if (!ctx->usb_dev)
            goto error_exit;
        if (!start_wireshark_etc(ctx))
            goto error_exit;
        ctx->exit_on_capture_stop = true;
    }

    if (ctx->opts.capture_to[0]) {
        if (!grab_start(ctx, ctx->log, ctx->opts.capture_to))
            goto error_exit;
        ctx->exit_on_capture_stop = true;
    }

    if (ctx->opts.ipc_server[0]) {
        char *ipc_path = pipe_format_pipe_path(ctx->opts.ipc_server);
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
        cl->exit_on_close = true;
    }

    if (!ctx->extcap_active) {
        struct pipe *p = event_loop_open_pipe(ctx->ev, "/dev/stdin", PIPE_FLAG_READ);
        add_client(ctx, p, true);
    }

#if HAVE_POSIX
    setup_signal_handler(ctx);
#endif

    if (!ctx->num_clients && !ctx->ipc_server &&
        !(ctx->usb_dev && ctx->usb_dev->grabber))
    {
        LOG(ctx, "Nothing to do. Exiting.\n");
        event_loop_request_terminate(ev);
    }

    event_loop_run(ev);
    event_loop_destroy(ev);
    options_free(option_list, &ctx->opts);
    if (ctx->fifo_path)
        unlink(ctx->fifo_path);
    free(ctx->fifo_path);
    free(ctx->wireshark_path);
    free(ctx->clients);
    byte_fifo_dealloc(&ctx->log_fifo);
    usb_thread_destroy(ctx->global->usb_thr);
    return 0;

error_exit:
    if (ctx->extcap_active) {
        LOG(ctx, "Capture failed.\n");
        ctx->mute_terminal = false; // let flush_log() write to stderr
    }
    flush_log(ctx);
    return 1;
}
