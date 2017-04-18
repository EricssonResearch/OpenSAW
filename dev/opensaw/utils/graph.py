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
Module for graph helper classes and functions
"""

# Import [[picklable]] to simplify graph serialization.
from opensaw.utils import picklable
from collections import deque

class _CaptureEq:
    def __init__(self, item):
        self.me = item
        self.match = None

    def __eq__(self, other):
        if self.me == other:
            self.match = other
            return True
        return False

    def __getattr__(self, name):
        return getattr(self.me, name)


class Graph(picklable.Object):
    """
    Directed Graph
    ==============
    """

    def __init__(self):
        picklable.Object.__init__(self)
        self.nodes = set()
        self.edges = dict()
        self.bedges = dict()

    def addNode(self, node):
        """
        Add the node `node` to the graph nodes.
        """
        self.nodes.add(node)

    def addNodes(self, nodes):
        """
        Add the nodes `nodes` to the graph nodes.
        """
        self.nodes.update(nodes)

    def getNodeRef(self, node):
        """
        Get the reference to the node equivalent to `node`.
        """
        t = _CaptureEq(node)
        if t in self.nodes:
            return t.match
        return None

    def addEdge(self, node1, node2, edge):
        """
        Add the edge `edge` from node `node1` to the node `node2`.
        """
        # Ensure both nodes exist in the graph.
        self.addNodes((node1, node2))

        if node1 not in self.edges:
            self.edges[node1] = dict()
        if node2 not in self.bedges:
            self.bedges[node2] = dict()
        self.bedges[node2][node1] = edge
        self.edges[node1][node2] = edge

    def addEdges(self, edges):
        """
        Add the edges `edges` to the graph edges.
        """
        for triple in edges:
            self.addEdge(*triple)

    def getSuccessors(self, node):
        """
        Return the successors if any of the node `node`.

        @return: A dictionary of node edges.
        """
        if node not in self.edges:
            return dict()
        else:
            return self.edges[node]

    def getPredecessors(self, node):
        """
        Return the predecessors of the node `node`.

        @return: A dictionary of node edges.
        """
        if node not in self.bedges:
            return dict()
        else:
            return self.bedges[node]

    def size(self):
        """
        Return an `(int, int)` tuple;
        the number of nodes and the number of edges.
        """
        return len(self.nodes), sum(map(len, self.edges.values()))


# Traversal classes
# =================
def truefunc(_):
    return True


class GraphSearch(object):
    """
    A base class for graph search algorithms.

    @ivar graph: the graph to be searched
    @type graph: `Graph`

    @ivar should_handle_node: a Boolean function for discarding nodes during traversal
    @type should_handle_node: function

    @ivar should_handle_edge: a Boolean function for avoiding edges during traversal
    @type should_handle_edge: function
    """

    def __init__(self, graph, node_handler=None, edge_handler=None):
        if node_handler is None:
            node_handler = truefunc

        if edge_handler is None:
            edge_handler = truefunc

        self.graph = graph
        self.should_handle_node = node_handler
        self.should_handle_edge = edge_handler

    def all_edges_from(self, node):
        raise NotImplementedError


class DFS(GraphSearch):
    """
    A class for implementing depth first search graph traversal.
    """

    def all_edges_from(self, node):
        """
        Iterates through all edges starting with `node`,
        returns and iterator of `(from, edge, to)` triples.
        """
        visited = set([node])
        to_visit = deque([node])

        while len(to_visit):
            node = to_visit.pop()

            for other, edge in self.graph.getSuccessors(node).items():
                if not self.should_handle_edge(edge):
                    continue

                yield (node, edge, other)

                if other not in visited and self.should_handle_node(other):
                    visited.add(other)
                    to_visit.append(other)


class BFS(GraphSearch):
    """
    A class for implementing breadth first search graph traversal.
    """

    def all_edges_from(self, node):
        """
        Iterates through all edges starting with `node`,
        returns and iterator of `(from, edge, to)` triples.
        """
        visited = set([node])
        to_visit = deque([node])

        while len(to_visit) != 0:
            node = to_visit.popleft()

            for other, edge in self.graph.getSuccessors(node).items():
                if not self.should_handle_edge(edge):
                    continue

                yield (node, edge, other)

                if other not in visited and self.should_handle_node(other):
                    visited.add(other)
                    to_visit.append(other)
