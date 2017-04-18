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
from time import time
from opensaw.statistics.performance import Performance
from opensaw.statistics.coverage import Coverage
from opensaw.statistics.crashes import Crashes


class Aggregate(object):
    """
    Aggregate is a collection of all OpenSAW statistics.
    """
    def __init__(self):
        self.start = time()
        self.end = None
        self.crashes = Crashes(self.start)
        self.coverage = Coverage(self.start)
        self.perf = DynamicPerformance()

    def complete(self):
        self.end = time()

    def to_json(self):
        complete = self.end is not None
        end = self.end if complete else time()

        return {
            "time": end - self.start,
            "done": complete,
            "performance": self.perf,
            "crashes": self.crashes,
            "coverage": self.coverage
        }


class DynamicPerformance(object):
    """
    Dynamically create performance measurements as needed.
    Request a Performance object by accessing a unique attribute
    of a DynamicPerformance instance.

        dyn = DynamicPerformance()
        pin = dyn.pin
        bap = dyn.bap
    """
    # Must add a `to_json` attribute explicitly, since the `json.dump`
    # process cannot use `hasattr` to check if such an attribute exists. See the
    # [documentation](https://docs.python.org/2/library/functions.html#hasattr).
    to_json = None

    def __getattr__(self, name):
        """
        If some Performance name is missing, create and return it.
        """
        p = Performance()
        setattr(self, name, p)
        return p

    def __getstate__(self):
        """
        Return the current state for pickling.
        """
        return self.__dict__

    def __setstate__(self, d):
        self.__dict__.update(d)
