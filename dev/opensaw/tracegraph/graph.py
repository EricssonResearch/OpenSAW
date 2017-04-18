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
Module for a data structure keeping track of the trace analysis.
"""

# Local Imports
from opensaw.utils import graph, picklable
from opensaw.utils.funs import locked
import time


class Node(picklable.Dictionary):
    """
    Tracegraph Node
    =================

    A `Node` corresponds to a BBL or basic block.
    For convenience, it can be used as a dictionary.

    #### Parameters and Attributes
        hash_val : int
            The hash value corresponding to the normalized BBL.
        is_conditional : bool
            Whether the BBL
    """

    def __init__(self, hash_val, is_conditional, ins_count=0):
        picklable.Dictionary.__init__(self)
        self.hash_val = hash_val
        self.is_conditional = is_conditional
        self.insCount = ins_count

    def __str__(self):
        return str(self.__dict__)

    def __cmp__(self, other):
        return cmp(self.hash_val, other.hash_val)

    def __hash__(self):
        """
        The `Node` already has a hash value. Use it.
        """
        return self.hash_val


class Edge(picklable.Object):
    """
    Tracegraph Edge
    =================

    A `Edge` corresponds to a jump between BBLs or basic blocks.

    #### Parameters and Attributes
        trace : str
            The name of the trace file that first generated the edge.
        input : str
            The name of the input file that first generated the edge.
        position : int [default=0]
            The relative position of the jump in the trace.
    """

    def __init__(self, trace, input, pos=0):
        picklable.Object.__init__(self)
        self.trace = trace
        self.input = input
        self.position = pos

    def __str__(self):
        return str(self.__dict__)

    def __cmp__(self, other):
        return cmp((self.trace, self.input, self.position),
                   (other.trace, other.input, other.position))

    def __hash__(self):
        return hash((self.trace, self.input, self.position))


@locked
class Graph(graph.Graph, picklable.Object):
    """
    Tracegraph
    ==================

    A Tracegraph which inherits from `graph.Graph`.


    #### Parameters
        ranking : { "N", "U", "B" } [default="N"]
            How to rank traces; None, Uniform or Bigram

    #### Attributes
        entry : Node
            The Graph's entry node.
    """

    def __init__(self):
        picklable.Object.__init__(self)
        graph.Graph.__init__(self)
        self.__entry = Node(0, False)

        self.addNode(self.__entry)

    def __str__(self):
        res = ""
        res += "Entry: %s\n" % self.__entry
        for ni in self.nodes:
            res += "   Node %s:\n" % ni
            for nj, e in self.getSuccessors(ni).items():
                res += "      %s --> %s\n" % (e, nj)
        return res

    # Override getSuccessors with a locked variant.
    getSuccessors = locked(graph.Graph.getSuccessors)

    @locked
    def __iter__(self):
        """
        Iterate through all edges of the `tracegraph.Graph` in a
        Breadth First manner.
        """
        return graph.BFS(self).all_edges_from(self.__entry)

    @property
    def entry(self):
        """
        Return the entry point of the Graph.
        """
        return self.__entry

    @locked
    def update(self, trace_job, hashes, ins_counts, context_dependant=False):
        """
        Updates the `tracegraph.Graph` with the list of trace `hashes`.
        Returns a `trace` and a `rank`.
        """
        trace = []
        prev_node = self.__entry

        # The last hash is the final basic block,
        # which never ends with a conditional jump.
        # A Node is therefore conditional if its index
        # doesn't equal the last index.
        last_i = len(hashes) - 1
        new_blocks = 0
        new_edges = 0

        for i, ith_hash in enumerate(hashes):
            # If some other thread needs to do work - let them.
            # They probably only launch a subprocess anyway.
            conditional_in_current_trace = i != last_i
            node = Node(ith_hash, conditional_in_current_trace, ins_counts[i])
            edge = Edge(trace_job.file_name, trace_job.input_name, i)

            if node in self.nodes:
                node = self.getNodeRef(node)
                if prev_node not in self.getPredecessors(node):
                    self.addEdge(prev_node, node, edge)
                    new_edges += 1

                # If the node we found is considered not conditional previously
                # but it is conditional in our current trace, relabel it.
                if not node.is_conditional and conditional_in_current_trace:
                    node.is_conditional = True

            else:
                self.addNode(node)
                self.addEdge(prev_node, node, edge)
                new_blocks += 1
                new_edges += 1

            # Must check that the node is conditional in this specific trace,
            # otherwise we can't use it anyway as it has no altered_jump.
            if node.is_conditional and conditional_in_current_trace:
                if context_dependant:
                    trace.append((edge, node))
                else:
                    trace.append(
                        (self.getPredecessors(node)[prev_node], node))
            prev_node = node



        return trace, (new_blocks, new_edges)

    def to_dot(self):
        """
        Return a string representation of the Tracegraph
        in dot format.
        """
        node_id = "{0.hash_val}_{0.is_conditional:d}".format
        edge_label = "{0.trace}@{0.position}".format

        lines = list()

        # Open the graph
        lines.append("digraph tracegraph {")

        # Iterate through all edges as: `parent` with an `edge` to `child`,
        # and add the edges.
        for parent, edge, child in self:
            lines.append("\t\"{}\" -> \"{}\" [label=\"{}\"];".format(
                node_id(parent), node_id(child), edge_label(edge)))

        # Iterate through all nodes as: `node`,
        # and add its label and meta-data.
        for node in self.nodes:
            lines.append("\t\"{0}\" [label=\"{0}\\n{1}\"];".format(
                node_id(node), "\\n".join(
                    ["{}={}".format(key, node[key]) for key in node])))

        # Close the graph
        lines.append("}")

        return "\n".join(lines)

    def to_json(self):
        """
        Return a `json.dump`-able representation of the Tracegraph.
        """
        nodes = []
        links = []

        node_id = "{0.hash_val}_{0.is_conditional:d}".format

        # The entry node is at depth 0.
        node_depth = {self.__entry: 0}

        # Iterate through all edges as: `parent` with an `edge` to `child`,
        # and add the edges. Let the node depth of a node be that
        # of its parent + 1.
        for parent, edge, child in self:
            node_depth.setdefault(child, node_depth[parent] + 1)
            links.append({"source": node_id(parent),
                          "target": node_id(child), "value": 1})

        # Add the nodes, at their respective depths.
        for node, depth in node_depth.items():
            nodes.append({"id": node_id(node), "group": depth, "ins": node.insCount})

        return {"links": links,
                "nodes": nodes,
              #  "trace": [{"id": node_id(n), "ins": n.insCount}
              #            for n in self.__lastTrace]
               }
