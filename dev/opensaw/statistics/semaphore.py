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
import threading
from opensaw.utils import picklable


class Semaphore(picklable.Object):
    """
    An inheritable Semaphore that can be used in with statements.
    """
    dont_pickle = ["sem"]

    def __init__(self):
        self.sem = threading.Semaphore()

    def __enter__(self):
        self.sem.__enter__()
        return self

    def __exit__(self, *args):
        self.sem.__exit__(*args)

    def when_unpickled(self):
        Semaphore.__init__(self)
