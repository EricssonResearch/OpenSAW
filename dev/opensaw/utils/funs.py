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

# Module for practical helper functions.


from __future__ import absolute_import, print_function

# Imports
from distutils.util import strtobool
from functools import reduce
from sys import exit, stderr
from threading import RLock
import logging
import os


# Generic Functions

# Abort
# Abort with `message`, before any further damage is done.
def abort(message):
    logging.error(message)
    print("ERROR:", message, file=stderr)
    exit(1)


def chain(*fns):
    """
    Creates a function which will sequentially calls the given
    functions with its arguments, returning `None`.

        >>> fn = chain(print, compose2(print, hex))
        >>> fn(17)
        17
        0x11
    """

    def fn(*args, **kwargs):
        for sub_fn in fns:
            sub_fn(*args, **kwargs)

    return fn


def compose2(f, g):
    """
    Composes `f` and `g` together into a single function.
    """
    return lambda x: f(g(x))


def compose(*functions):
    """
    Composes any number of `functions` together into a single function.
    """
    return reduce(compose2, functions)


def constant(value):
    """
    Creates a function which returns the given value.
    """
    return lambda *args, **kwargs: value


# Returns `None`.
get_none = constant(None)


def locked(method_or_class):
    """
    @locked
    =======

    A decorator to make a locked Object or a locked method.
    Only one thread may execute any locked methods at a time.
    Works even with `picklable.Object`s.

    Warning: Attempting to call locked methods of two objects
    simultaneously may result in a _deadlock_!

        from opensaw.utils.funs import locked
        from opensaw.utils.picklable import Object

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
    """

    def add_lock(self, *args, **kwargs):
        self.__lock = RLock()

    # It is a class!
    if isinstance(method_or_class, type):
        cls = method_or_class

        cls.__init__ = chain(add_lock, cls.__init__)

        cls.dont_pickle = getattr(cls, "dont_pickle", []) + ["__lock"]

        cls.when_unpickled = staticmethod(chain(add_lock,
                                                getattr(cls, "when_unpickled", get_none)))

        return cls

    # It is a method.
    method = method_or_class

    def locked_method(self, *args, **kwargs):
        with self.__lock:
            return method(self, *args, **kwargs)

    return locked_method


# Directories and files
def findFiles(dir_name, name_substr):
    """
    Find files in C{dir_name} with names containing C{name_substr}.
    """
    res = []
    if not os.path.exists(dir_name):
        return res
    for root, _, files in os.walk(dir_name, topdown=False):
        for name in files:
            if name_substr in name:
                res.append(os.path.join(root, name))
    return res


# User interaction
def yesNoQuery(query):
    while True:
        # Hackish workaround to make it work on both python2 and python3
        try:
            input = raw_input
        except NameError:
            pass

        try:
            return strtobool(input('%s [y/n]' % query).lower())
        except ValueError:
            print('Please respond with \'y\' or \'n\'.\n')
