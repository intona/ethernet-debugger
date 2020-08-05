About
=====

This is the host program / userspace driver for the Intona Ethernet Debugger.

Copyright
=========

This software is copyrighted by Intona Technology GmbH.

This software is licensed GPL 3.0 or later. See the following link for details,
and the full license text: https://www.gnu.org/licenses/gpl-3.0.html

Documentation
=============

The complete user-guide is located here: https://intona.eu/doc/ethernet-debugger

Build instructions
==================

Requirements:

- A C11 compiler (gcc, clang)
- libusb-1 library and header files
- json-parser git submodule (https://github.com/intona/json-parser/)
- modern POSIX environment for Unix-like, or MinGW-w64 for win32
- meson 0.53.0 (older releases might work, but they're usually plagued by bugs)
  (use your package manager, or "pip3 install meson" / "pip install meson")
- little endian build target

After installing the dependencies, run the following::

    git submodule init
    git submodule update
    meson build     # create build files in directory named "build"
    ninja -C build  # pass it the build directory chosen above

If you're trying to cross-compile to Windows, the situation is more complex.
See for example:
https://mesonbuild.com/Cross-compilation.html

On macOS, you can use the provided homebrew tap::

    brew install --HEAD intona/ethernet-debugger/nose

Installation
============

You can run in the build dir::

    ninja install

By default, this installs to /usr/local/bin. Run meson with -Dprefix=/usr to
install it in another path (this is an argument to meson, not ninja).

Installation is not necessary. You can simply use the produced binary
immediately.

Hardware access permissions
---------------------------

The device is accessed via libusb. No driver installation is necessary. However,
you may need to manually install an udev rule to allow access to the device::

    sudo cp udev.rules /etc/udev/rules.d/50-intona-ethernet-debugger.rules
    sudo udevadm trigger

(Assumes you are in the "plugdev" group.)

Wireshark extcap
----------------

The host program provides Wireshark extcap support. This works only if the host
program is installed correctly to the extcap sub-directory in either Wireshark's
installation, or user config directory.

You can for example do (after "nose" is installed)::

    mkdir -p ~/.config/wireshark/extcap/
    ln -s `which nose` ~/.config/wireshark/extcap/nose

See the Wireshark documentation for details about extcap:
https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html

See the Ethernet Debugger Guide for details and information about other OSes.

Usage instructions
==================

There are multiple ways to start capture:

- starting Wireshark with nose --wireshark (automatically sets up FIFO)
- letting Wireshark start nose via extcap by selecting the "Ethernet Debugger"
  capture device in Wireshark (see extcap installation instructions if it's
  missing)
- starting nose manually (see nose --help, and the --fifo option)

