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
The coverage format is encoded using 3-bits:

 bit | meaning
-----|---------
 3   | conditional
 2   | `false`-branch taken
 1   | `true`-branch taken

In the case of an unconditional branch,
both bits 1 and 2 should be set.
"""

import logging
from time import time

from opensaw.statistics.semaphore import Semaphore

NON_CONDITIONAL = NEITHER_BRANCH = 0
TRUE_BRANCH = 1
FALSE_BRANCH = 2
BOTH_BRANCHES = 3
CONDITIONAL = 4


def is_conditional(path):
    """
    Returns `True` if the conditional bit is set.
    """
    return (path & CONDITIONAL) is CONDITIONAL


def taken_branches(path):
    """
    Returns the number of branches taken given a
    conditional path enum.
    """
    # Extract only the branches.
    path = path & BOTH_BRANCHES

    if path == NEITHER_BRANCH:
        return 0
    if path == BOTH_BRANCHES:
        return 2
    return 1


class Coverage(Semaphore):
    """
    The Coverage statistics class keeps track of the visited
    blocks, and taken branches. Handles the logic to update
    and present the data as JSON.
    """
    def __init__(self, start_time):
        Semaphore.__init__(self)
        self.start = start_time

        # blocks is the datastructure which keeps track
        # of the actual coverage
        self.blocks = dict()

        # The below variables are statistics snapshots
        # which are delivered on request
        self.updated = start_time

        self.found_blocks = 0
        self.found_branches = 0

        self.timestamps = [0]
        self.visited_blocks = [0]
        self.visited_branches = [0]

    def update(self, trace):
        """
        Updates the coverage dictionary with the new entries.
        """
        for addr, path in trace.items():
            self.blocks.setdefault(addr, 0)
            self.blocks[addr] |= path

        values = self.blocks.values()

        conditionals = list(filter(is_conditional, values))

        newly_found_blocks = len(self.blocks)
        newly_found_branches = 2 * len(conditionals)

        newly_visited_blocks = len([v for v in values if v])
        newly_visited_branches = sum(map(taken_branches, conditionals))

        changed = False

        if (self.found_blocks != newly_found_blocks or
                self.found_branches != newly_found_branches):
            self.found_blocks = newly_found_blocks
            self.found_branches = newly_found_branches
            changed = True

        if (not len(self.visited_blocks) or
                self.visited_blocks[-1] != newly_visited_blocks or
                self.visited_branches[-1] != newly_visited_branches):
            self.visited_blocks.append(newly_visited_blocks)
            self.visited_branches.append(newly_visited_branches)
            self.timestamps.append(time() - self.start)
            changed = True

        if changed:
            logging.debug("Total branches seen: %d" % len(self.blocks.keys()))
            self.updated = time()

    def to_json(self):
        return {
            "updated": self.updated,
            "visited": {
                "timestamps": self.timestamps,
                "blocks": self.visited_blocks,
                "branches": self.visited_branches
            },
            "found": {
                "blocks": self.found_blocks,
                "branches": self.found_branches
            }
        }
