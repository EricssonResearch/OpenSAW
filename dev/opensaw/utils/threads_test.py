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
    from queue import PriorityQueue as Q
except ImportError:
    # noinspection PyUnresolvedReferences
    from Queue import PriorityQueue as Q

from opensaw.utils.threads import StoppableThread, WorkThread


def test_StoppableThread():
    st = StoppableThread()
    assert not st.is_stopped()

    st.stop()
    assert st.is_stopped()


def test_WorkThread():
    in_q, out_q = Q(1), Q(1)

    def get_none():
        assert wt.get() is None

    def get_one():
        assert wt.get() == 1
        wt.task_done()
        # Returns True on success
        assert wt.put(17)

    def out_full():
        # Returns False when full
        assert not wt.put(42)

    # Empty
    wt = WorkThread(in_q, out_q, get_none)
    wt.run()

    # One element
    in_q.put(1)
    wt = WorkThread(in_q, out_q, get_one)
    wt.run()

    # Stopped
    wt = WorkThread(in_q, out_q, get_none)
    wt.stop()
    wt.run()

    # Full
    wt = WorkThread(in_q, out_q, out_full)
    wt.run()
