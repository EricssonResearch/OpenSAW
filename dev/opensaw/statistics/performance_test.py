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
from opensaw.statistics.performance import Performance, get_time_from_line


def test_performance():
    perf = Performance()
    assert (perf.total, perf.measurements) == (0, 0)

    perf.report(7)
    assert (perf.total, perf.measurements) == (7, 1)

    perf.report(4)
    perf.report(6)
    assert (perf.total, perf.measurements) == (17, 3)


def test_get_time_from_line():
    assert get_time_from_line("user 3.12") == 3.12

    assert sum(map(get_time_from_line,
                   "user 0.04\nsys 42.0".splitlines())) == 42.04
