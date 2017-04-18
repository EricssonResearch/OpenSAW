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
from opensaw.concolic.pinbap.solver.cvc import new_input_from_solution


solution = """
ASSERT( symb_5_645 = 0x21 ); # The last char is '!'
ASSERT( not_symb_1 = 0x0 );  # Invalid symbol
ASSERT( symb_1_43 = 0x68 );  # The first char is 'h'
Valid;
"""


def test_new_input_from_solution():
    assert ("hell!", True) == new_input_from_solution("hello", solution)
    assert ("hell!", False) == new_input_from_solution("hell!", solution)
