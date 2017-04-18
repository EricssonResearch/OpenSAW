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
class RNR(Base):
    """
    Strategy class for Redundant Node Removal (RNR).
    Remove redundant nodes.
    """

    def __init__(self):
        Base.__init__(self)

    def getNodes(self, tracegraph, trace_path):
        res = []
        visitedNodes = set()
        for e, n in trace_path:
            if n not in visitedNodes:
                res.append((e, n))
                visitedNodes.add(n)
        return res