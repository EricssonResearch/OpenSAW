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
"""
The CVC module contains functions manipulating the CVC Lite format.
This is done through the external tool [`STP`](http://stp.github.io/).
"""

import subprocess

extension = ".cvc"


# TODO: Do not override subprocess module, use correct module from start
def set_subprocess(p):
    """
    Overrides the local reference to the `subprocess` module.
    This is done to allow calls through it to be measured.
    See [`opensaw.statistics.performance`](../statistics/performance.html)
    for details.
    """
    global subprocess
    subprocess = p


def new_input_from_path_condition(old_input, pc_file, timeout=0):
    return new_input_from_solution(old_input,
                                   solve_path_condition(pc_file, timeout=timeout))


def solve_path_condition(pc_file, timeout=0):
    """
    Invokes STP to solve the given Path Condition named `pc_file`.
    """
    return subprocess.check_output(["stp", pc_file], timeout=timeout, save_stdout=True,save_stderr=False)[0]


def new_input_from_solution(old_input, solution):
    """
    Given an input string and a CVC solution string,
    generate a new input string, and a bool indicating
    whether it is different from the original.

        >>> new_input_from_solution('a', 'ASSERT( symb_1_ = 0x62 )')
        ('b', True)
        >>> new_input_from_solution('a', 'ASSERT( symb_1_ = 0x61 )')
        ('a', False)
    """
    has_changed_input = False
    new_input = list(old_input)

    for line in solution.splitlines():
        if not line.startswith("ASSERT( "):
            continue

        spaced_line = line.split(" ")
        if not spaced_line[1].startswith("symb_"):
            continue

        # Parse symbol number and value
        symbol_number = int(line.split('_')[1]) - 1
        symbol_value = int(line.split()[3], 0)

        # Make it a writable character
        new_value = chr(symbol_value)

        if old_input[symbol_number] != new_value:
            has_changed_input = True

        # Assign it
        new_input[symbol_number] = new_value

    return ''.join(new_input), has_changed_input
