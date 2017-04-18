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
import inspect
try:
    import pytest
except ImportError as e:
    import py.test as pytest

import opensaw.strategy.strategies as strats

# trace graph required.
from opensaw.tracegraph.graph import Edge, Graph, Node
from opensaw.utils.jobs import InputJob, TraceJob

input_job = InputJob.make_initial("a.in")
trace_job = TraceJob("a.il", "a.in")

tracegraph = Graph()
trace, rank = tracegraph.update(trace_job, [1, 2, 3], [5, 5, 5])


def test_base():
    base = strats.base.Base()

    # Base requires that all subclasses implement `getNodes`.
    with pytest.raises(NotImplementedError):
        base.getNodes(None, None)

    # The rest should be NOPs
    assert base.handlePINInitInput(None) is None
    assert base.handlePINNewInput(None) is None

    d = {}

    assert base.handlePINNewTrace({"a": 1}, d) is None
    assert d["a"] is 1

    assert base.handleBAPNewTrace(None) is None
    assert base.handleBAPNewInput(None, None, None, None) is None


def test_plain_strategies():
    for _, value in inspect.getmembers(strats):
        if inspect.isclass(value):

            # Ignore special cases.
            if value is strats.parallel.Parallel or value is strats.serial.Serial or value is strats.base.Base:
                continue

            _test_plain_strategy(value())


def _test_plain_strategy(strategy):
    edge_node_pairs = strategy.getNodes(tracegraph, trace)

    for e, n in edge_node_pairs:
        assert isinstance(e, Edge) and isinstance(n, Node)

    redundant_edge_node_pairs = strategy.getNodes(tracegraph, trace)

    assert len(redundant_edge_node_pairs) <= len(edge_node_pairs)
