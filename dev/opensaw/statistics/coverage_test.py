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
from opensaw.statistics.coverage import (Coverage,
                                         CONDITIONAL, NON_CONDITIONAL,
                                         TRUE_BRANCH, FALSE_BRANCH, BOTH_BRANCHES)


def test_coverage():
    cov = Coverage(0)
    assert cov.blocks == {}

    cov.update({
        1: CONDITIONAL     | TRUE_BRANCH,
        2: NON_CONDITIONAL
    })
    assert cov.visited_branches[-1] == 1
    assert cov.blocks == {1: 5, 2: 0}

    cov.update({
        1: CONDITIONAL     | FALSE_BRANCH,
        3: CONDITIONAL     | FALSE_BRANCH
    })
    assert cov.visited_branches[-1] == 3
    assert cov.blocks == {
        1: CONDITIONAL     | BOTH_BRANCHES,
        2: NON_CONDITIONAL,
        3: CONDITIONAL     | FALSE_BRANCH
    }

    cov.update({
        2: NON_CONDITIONAL | BOTH_BRANCHES
    })
    assert cov.visited_branches[-1] == 3
    assert cov.blocks == {
        1: CONDITIONAL     | BOTH_BRANCHES,
        2: NON_CONDITIONAL | BOTH_BRANCHES,
        3: CONDITIONAL     | FALSE_BRANCH
    }
