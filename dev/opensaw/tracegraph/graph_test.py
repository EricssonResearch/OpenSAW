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
from opensaw.tracegraph.graph import Edge, Graph, Node

EMPTY_JSON = {
    "nodes": [
        {'id': '0_0', 'ins': 0, "group": 0}
    ],
    "links": []
}

EMPTY_DOT = (
'''digraph tracegraph {
\t"0_0" [label="0_0\\n"];
}''')

FOUR_EDGE_JSON = {
    "nodes": [
        {"id": '0_0', "ins":0, "group": 0},
        {"id": '1_1', "ins":3, "group": 1},
        {"id": '2_0', "ins":3, "group": 2},
        {"id": '3_1', "ins":3, "group": 1}
    ],
    "links": [
        {"source": '0_0', "target": '1_1', "value": 1},
        {"source": '0_0', "target": '3_1', "value": 1},
        {"source": '1_1', "target": '2_0', "value": 1},
        {"source": '3_1', "target": '2_0', "value": 1}
    ]
}

FOUR_EDGE_DOT = (
'''digraph tracegraph {
\t"0_0" -> "1_1" [label="file@0"];
\t"0_0" -> "3_1" [label="file@0"];
\t"1_1" -> "2_0" [label="file@1"];
\t"3_1" -> "2_0" [label="file@1"];
\t"0_0" [label="0_0\\n"];
\t"1_1" [label="1_1\\n"];
\t"2_0" [label="2_0\\n"];
\t"3_1" [label="3_1\\n"];
}''')


def test_empty_tracegraph():
    tracegraph = Graph()

    assert tracegraph.entry == Node(0, False)

    assert tracegraph.to_dot() == EMPTY_DOT
    assert tracegraph.to_json() == EMPTY_JSON
    assert tracegraph.size() == (1, 0)


def test_four_edge_tracegraph():
    tracegraph = Graph()

    tracegraph.update(FakeJob(), [1, 2], [3,3])
    tracegraph.update(FakeJob(), [3, 2], [3,3])

    assert tracegraph.to_dot() == FOUR_EDGE_DOT
    json = tracegraph.to_json()

    assert sorted(json["links"]) == sorted(FOUR_EDGE_JSON["links"])
    assert sorted(json["nodes"]) == sorted(FOUR_EDGE_JSON["nodes"])

    assert tracegraph.size() == (4, 4)


class FakeJob(object):
    def __init__(self):
        self.file_name = "file"
        self.input_name = "in"
