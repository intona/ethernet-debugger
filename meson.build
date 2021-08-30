# SPDX-License-Identifier: GPL-3.0-or-later
project('nose', 'c')

compiler = meson.get_compiler('c')
deps = []

deps += dependency('libusb-1.0', version : '>=1.0.21')
deps += dependency('threads')
# gcc sometimes requires it, while it's not provided by some other C11 platforms.
deps += compiler.find_library('atomic', required: false)

incdir = include_directories('json-parser/')

wflags = ['-W', '-Wall', '-Wno-unused-parameter', '-Wno-unused-function',
          '-Werror=format', '-Werror=implicit-function-declaration',
          '-Wno-sign-compare', '-Wno-unused-result', '-Wmissing-prototypes',
          '-Wno-missing-field-initializers', '-Wno-switch']

cflags = wflags + ['-D_POSIX_C_SOURCE=200809L', '-D_GNU_SOURCE']

ldflags = []

sources = [
    'nose.c',
    'grabber.c',
    'usb_control.c',
    'fifo.c',
    'utils.c',
    'usb_io.c',
    'event_loop.c',
    'buffer.c',
    'cmd_parser.c',
    'device.c',
    'crc32.c',
    'filter_commenter.c',
    'filter_latency_tester.c',
    'init_and_test.c',
    'json-parser/json.c',
    'json-parser/json_helpers.c',
    'json-parser/json_out.c',
]

if compiler.has_header('windows.h')
    sources += 'event_loop_win32.c'
    # https://docs.microsoft.com/en-us/cpp/porting/modifying-winver-and-win32-winnt
    cflags += '-D_WIN32_WINNT=0x0601'
    ldflags += '-lole32'
else
    sources += 'event_loop_posix.c'
endif

readline = dependency('readline', required: false)

if readline.found()
    deps += readline
    cflags += ['-DHAVE_READLINE=1']
else
    cflags += ['-DHAVE_READLINE=0']
endif

sources += vcs_tag(command: ['git', 'describe', '--always', '--tags'],
                   fallback: '<unknown>',
                   input: 'version.c.in',
                   output: 'version.c')

executable('nose',
           sources,
           include_directories: incdir,
           dependencies: deps,
           c_args: cflags,
           link_args: ldflags,
           install: true)
