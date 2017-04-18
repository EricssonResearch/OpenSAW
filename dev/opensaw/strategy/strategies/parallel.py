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
from opensaw.strategy.strategies.base import Base
class Parallel(Base):
    """
    Class for parallel strategy composition.
    """

    def __init__(self, strat_list):
        Base.__init__(self)
        self.__stratList = strat_list
        self.__curr = 0
        self.first = True

    # Helper for parallel strategy (used to change current strategy)
    def rotateStrat(self):
        self.__curr = (self.__curr + 1) % len(self.__stratList)

    # PIN wrapper callbacks
    def handlePINInitInput(self, input_job):
        self.__stratList[self.__curr].handlePINInitInput(input_job)

    def handlePINNewInput(self, input_job):
        self.__stratList[self.__curr].handlePINNewInput(input_job)

    def handlePINNewTrace(self, input_job, trace_job):
        self.__stratList[self.__curr].handlePINNewTrace(input_job, trace_job)

    # BAP wrapper callbacks
    def handleBAPNewTrace(self, trace_job):
        if self.first:
            self.first = False
        else:
            self.rotateStrat()
        self.__stratList[self.__curr].handleBAPNewTrace(trace_job)

    def getNodes(self, tracegraph, trace_path):
        return self.__stratList[self.__curr].getNodes(tracegraph, trace_path)

    def handleBAPNewInput(self, trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job=None):
        self.__stratList[self.__curr].handleBAPNewInput(trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job)