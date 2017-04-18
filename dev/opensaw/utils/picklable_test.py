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
import pickle
from opensaw.utils.funs import locked
from opensaw.utils.picklable import Object, Dictionary

x = False


class Empty(Object):
    @staticmethod
    def when_unpickled(_):
        global x
        x = True


class A(Object):
    def __init__(self, a):
        self.a = a


@locked
class LockedCounter(Object):
    def __init__(self):
        self.count = 0

    @locked
    def add(self, n):
        self.count += n

    @locked
    def logging_add(self, n):
        print("adding", n)
        self.add(n)
        print("count is", self.count)


def test_Empty():
    pickle.loads(pickle.dumps(Empty()))

    assert x


def test_Object():
    a = A(1)

    a_prime = pickle.loads(pickle.dumps(a))

    assert a.a == a_prime.a


def test_Dictionary():
    d = Dictionary()

    assert len(d) == 0

    d["a"] = 1

    assert len(d) == 1
    assert "a" in d

    del d["a"]

    assert len(d) == 0
    assert "a" not in d


def test_class_with_Lock():
    l = LockedCounter()

    # Has a locked methods which can call
    l.logging_add(4)

    assert l.count is 4

    # Pickling a lock throws otherwise.
    l_str = pickle.dumps(l)

    l2 = pickle.loads(l_str)

    # Must be able to use locked add method
    l2.add(2)

    assert l2.count is 6
