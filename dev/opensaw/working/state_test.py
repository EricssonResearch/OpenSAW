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
## Testing `opensaw.working.state`

"""
from opensaw.working import Directory, State

class Options(object):
    initialInput = ["something"]
    queueSize = 1
    manifest = "important_file"
    ranking = "U"


def test_State(tmpdir):
    tmpdir.chdir()

    # Create initial file in current root
    file = tmpdir.join(Options.initialInput[0])
    file.write("contents")

    # Create a working directory
    directory = Directory(tmpdir.mkdir("target").strpath)

    state = State.from_options(directory, Options)

    assert not state.queues_empty()
    assert not state.is_done()

    state.in_queue.get()

    assert state.queues_empty()
    assert not state.is_done()

    state.in_queue.task_done()

    assert state.queues_empty()
    assert state.is_done()

    state.save()

    state2 = State.load(directory, Options.manifest)

    # Approximation of equivalence after save and load.
    assert state.dir == state2.dir
    assert state.manifest == state2.manifest
    assert state.queue_size == state2.queue_size
    assert state.tracegraph.size() == state2.tracegraph.size()

    assert (type(state.statistics.coverage.sem) ==
            type(state2.statistics.coverage.sem))

    # Log all work to files.
    state2.log()
