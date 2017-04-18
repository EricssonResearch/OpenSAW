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
class NNF(Base):
    """
    New nodes first strategy class.
    Insert new nodes first in the list.
    """
    NODE_ATT = "Old"

    def __init__(self):
        Base.__init__(self)

    def getNodes(self, tracegraph, trace_path):
        res = []
        for e, n in trace_path:
            if NNF.NODE_ATT not in n:
                res.insert(0, (e, n))
                n[NNF.NODE_ATT] = "True"
            else:
                res.append((e, n))
        return res