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
class ANR(Base):
    """
    Strategy class for Analyzed Node Removal (ANR).
    Remove explored nodes.
    """
    NODE_ATT = "Analyzed"

    def __init__(self):
        Base.__init__(self)

    def getNodes(self, tracegraph, trace_path):
        res = []
        analyzedNodes = set()
        for e, n in trace_path:
            if n not in analyzedNodes:
                if ANR.NODE_ATT in n:
                    analyzedNodes.add(n)
                else:
                    res.append((e, n))
        return res

    def handleBAPNewInput(self, trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job=None):
        if tracegraph_node.is_conditional:
            s = len(tracegraph.getSuccessors(tracegraph_node))
            if s > 0 or (input_job is None and s == 0):
                tracegraph_node[ANR.NODE_ATT] = "True"