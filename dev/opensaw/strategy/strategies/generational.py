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
class Generational(Base):
    """
    Generational strategy class.
    Keep track of generation levels in trace jobs and filter
    nodes up to the trace generational level.
    """
    LEVEL_ATT = "Level"

    def __init__(self):
        Base.__init__(self)
        self.__level = 0

    # PIN wrapper callbacks
    def handlePINInitInput(self, input_job):
        input_job[Generational.LEVEL_ATT] = 0

    def handlePINNewTrace(self, input_job, trace_job):
        trace_job[Generational.LEVEL_ATT] = input_job[Generational.LEVEL_ATT] + 1
        trace_job.priority = trace_job.new_blocks

    # BAP wrapper callbacks
    def handleBAPNewTrace(self, trace_job):
        self.__level = trace_job[Generational.LEVEL_ATT]

    def getNodes(self, tracegraph, trace_path):
        return trace_path[self.__level - 1:]

    def handleBAPNewInput(self, trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job):
        if input_job is not None:
            # Just copy the traces priority. SAGEs description handles
            # Tracing and input generation in same thread, our difference is that
            # another trace may come in the middle with more important work
            input_job.priority = trace_job.priority+1
            input_job[Generational.LEVEL_ATT] = tracegraph_edge.position