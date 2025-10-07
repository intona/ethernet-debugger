About
=====

This is the host program / userspace driver for the Intona Ethernet Debugger. It
provides a "userspace driver" to Wireshark for packet capturing, and can access
special hardware features.

Copyright
=========

This software is copyrighted by Intona Technology GmbH.

This software is licensed as GPL 3.0 or later. See the following link for details,
and the full license text: https://www.gnu.org/licenses/gpl-3.0.html

Documentation
=============

The complete Ethernet Debugger User Guide is located here:
https://intona.eu/doc/ethernet-debugger

Build instructions
==================

Requirements:

- A C11 compiler (gcc, clang)
- libusb-1 library and header files
- json-parser git submodule (https://github.com/intona/json-parser/)
  (automatically checked out if you use the git submodule commands)
- modern POSIX environment for Unix-like, or MinGW-w64 for win32
- meson 0.53.0 (older releases might work, but they're usually plagued by bugs)
  (use your package manager, or "pip3 install meson" / "pip install meson")
- little endian build target
- libreadline (optional, can be disabled by passing -Dreadline=false to meson)

The following command should be sufficient to install the dependencies on
Ubuntu::

    sudo apt install build-essential meson libusb-1.0-0-dev libreadline-dev

At least Ubuntu 18.04 and later should work. The only real restriction is the
version of the libusb API provided, and whether the meson package is recent
enough.

After installing the dependencies, run the following::

    git clone --recursive https://github.com/intona/ethernet-debugger.git
    cd ethernet-debugger
    meson setup build       # create build files in directory named "build"
    meson compile -C build  # pass it the build directory chosen above

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
you may need to manually install a udev rule to allow access to the device::

    sudo cp udev.rules /etc/udev/rules.d/50-intona-ethernet-debugger.rules
    sudo udevadm trigger

(Assumes you are in the "plugdev" group.)

Wireshark extcap
----------------

The host program provides Wireshark extcap support. This works only if the host
program is installed correctly to the extcap sub-directory in either Wireshark's
installation, or user config directory.

You can for example do (after "nose" is installed)::

    mkdir -p ~/.local/lib/wireshark/extcap/
    ln -s `which nose` ~/.local/lib/wireshark/extcap/nose

Wireshark seems to change these paths every other release. If in doubt, check
the paths and the list of loaded plugins in the Wireshark Help / About Wireshark
dialog. "nose" should be listed as an extcap plugin.

See the Wireshark documentation for details about extcap:
https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html
https://www.wireshark.org/docs/man-pages/extcap.html

See the `Ethernet Debugger User Guide <https://intona.eu/doc/ethernet-debugger>`_
for details and information about other OSes.

Usage instructions
==================

There are multiple ways to start capture:

- starting Wireshark with nose --wireshark (automatically sets up FIFO)
- letting Wireshark start nose via extcap by selecting the "Ethernet Debugger"
  capture device in Wireshark (see extcap installation instructions if it's
  missing)
- starting nose manually (see nose --help, and the --fifo option)

See the `Ethernet Debugger User Guide <https://intona.eu/doc/ethernet-debugger>`_
for details.
