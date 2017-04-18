"""
    Open Security Analysis Workbench (OpenSAW) - A concolic security test tool
    Copyright (C) 2016 Ericsson AB

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""
# Invoke from the command line as:
#
#     $ python -m opensaw
#
# It is more pythonic, promotes reuse and
# will allow execution OpenSAW as a package, meaning we don't need:
#
#     if __name__ == "__main__":
#        ...

from __future__ import absolute_import, print_function

from opensaw.application import main

import code
import signal

import sys
import traceback

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# For debugging install simple signal handler that dumps stacktraces of all threads
# when signal SIGUSR1 is received.
try:
    import faulthandler
    faulthandler.register(signal.SIGUSR1)
except Exception as e:
    eprint("Failed to start faulthandler due to: %s. Ignoring exception."%repr(e))

main(sys.argv)
