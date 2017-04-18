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
from .jumps import *


def find_fault_in_file(il_file):
    """
    Searches for `"special \"Exception number "` at the end
    of an `.il` file. Returns the number of the signal
    that terminated the process, otherwise `None`.
    """
    prefix = "special \"Exception number "

    # We don't know the number of lines, so can't take last 5 directly
    lastlines = {}
    for idx, line in enumerate(iterate_lines(il_file)):
        lastlines[idx % 5] = line

    # Look at the last five lines
    for line in lastlines.values():
        if not line.startswith(prefix):
            continue

        # Slice away prefix
        interest = line[len(prefix):]

        # Get numbers
        i = 0
        while interest[i] in "0123456789":
            i += 1

        # Return signal number
        return int(interest[:i])
    return None
