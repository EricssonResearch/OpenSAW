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

import pickle

from operator import add, neg
from functools import partial

from opensaw.utils.funs import abort, compose, locked
from opensaw.utils.picklable import Object


def test_compose():
    # Works the same as `lambda x: (-x) + 1`.
    add1_neg = compose(partial(add, 1), neg)

    assert add1_neg(4) == -3

    # When composing a single function, compose :equiv: identity.
    assert compose(neg) == neg


def test_abort():
    with pytest.raises(SystemExit):
        abort("yo")


@locked
class A(Object):
    def __init__(self):
        # A locked object is born with a `__lock` property.
        assert getattr(self, "__lock", None)

    @staticmethod
    def when_unpickled(self):
        # An unpickled object should have its `__lock` property
        # restored.
        assert getattr(self, "__lock", None)


def test_locked():
    assert pickle.loads(pickle.dumps(A()))
