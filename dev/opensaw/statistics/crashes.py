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
Crashes
=======

The `Crashes` module keeps track of all reported crashes.
"""

from time import time
from opensaw.statistics.semaphore import Semaphore


class Crashes(Semaphore):
    def __init__(self, time):
        Semaphore.__init__(self)
        self.crashes = []
        self.start_time = time

    def report(self, in_file, signal, trace=[]):
        """
        Reports the crash caused by `in_file` resulting in `signal`.
        Also keeps track of the time since start.
        """
        with self:
            self.crashes.append({
                "file": in_file,
                "signal": signal,
                "time": time() - self.start_time,
		"trace": trace
            })

    def to_json(self):
        return self.crashes
