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
class Serial(Base):
    """
    Class for serial strategy composition.
    """

    def __init__(self, strat_list):
        Base.__init__(self)
        self.__stratList = strat_list

    # PIN wrapper callbacks
    def handlePINInitInput(self, input_job):
        for s in self.__stratList:
            s.handlePINInitInput(input_job)

    def handlePINNewInput(self, input_job):
        for s in self.__stratList:
            s.handlePINNewInput(input_job)

    def handlePINNewTrace(self, input_job, trace_job):
        for s in self.__stratList:
            s.handlePINNewTrace(input_job, trace_job)

    # BAP wrapper callbacks
    def handleBAPNewTrace(self, trace_job):
        for s in self.__stratList:
            s.handleBAPNewTrace(trace_job)

    def getNodes(self, tracegraph, trace_path):
        res = trace_path
        for s in self.__stratList:
            res = s.getNodes(tracegraph, res)
        return res

    def handleBAPNewInput(self, trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job=None):
        for s in self.__stratList:
            s.handleBAPNewInput(trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job)