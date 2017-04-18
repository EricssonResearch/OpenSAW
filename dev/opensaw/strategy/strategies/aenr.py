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

import os
class AENR(Base):
    """
    Strategy class for Analyzed Edge, Node pair Removal (AENR).
    Remove explored nodes.
    """

    def __init__(self):
        Base.__init__(self)

    def __getEdgeAttribute(self, edge):
        return "%s@%d" % (os.path.basename(edge.trace), edge.position)

    def getNodes(self, tracegraph, trace_path):
        res = []
        analyzedEdgeNodes = set()
        for p in trace_path:
            if p not in analyzedEdgeNodes:
                e, n = p
                if self.__getEdgeAttribute(e) in n:
                    analyzedEdgeNodes.add(p)
                else:
                    res.append(p)
        return res

    def handleBAPNewInput(self, trace_job, tracegraph, tracegraph_edge, tracegraph_node, input_job=None):
        if tracegraph_node.is_conditional:
            tracegraph_node[self.__getEdgeAttribute(tracegraph_edge)] = "True"