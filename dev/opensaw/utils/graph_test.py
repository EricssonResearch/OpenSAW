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
try:
    import pytest
except ImportError as e:
    import py.test as pytest

from opensaw.utils.graph import Graph, GraphSearch


def test_Graph():
    g = Graph()

    # Initially, no nodes or edges
    assert g.size() == (0, 0)

    g.addNode(4)
    assert g.size() == (1, 0)

    # Add an edge from a non-existent node to
    # a previously added node.
    g.addEdge(0, 4, "0 -> 4")
    assert g.size() == (2, 1)

    assert g.getNodeRef(4) is 4
    assert g.getNodeRef(3) is None

    g.addEdges([
        (1, 2, "1 -> 2"),
        (2, 3, "2 -> 3")
    ])

    assert g.size() == (5, 3)


def test_search():
    search = GraphSearch(None)

    with pytest.raises(NotImplementedError):
        search.all_edges_from(None)
