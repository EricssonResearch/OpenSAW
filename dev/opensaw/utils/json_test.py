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
from __future__ import absolute_import

import json
from opensaw.utils.json import from_builtin


class A(object):
    def __init__(self, a):
        self.a = a

    def to_json(self):
        return self.a


class B(object):
    def __init__(self, b):
        self.b = b


def test():
    a = A(42)
    b = B(1337)

    assert json.dumps(a, default=from_builtin) == "42"
    assert json.dumps(b, default=from_builtin) == '{"b": 1337}'
