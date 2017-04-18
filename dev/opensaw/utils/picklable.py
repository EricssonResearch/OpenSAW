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
class Object(object):
    """
    Object
    ======

    A `picklable.Object` is an object which can be pickled and
    unpickled. To make a class picklable, simply inherit from it.

    If the class contains unpicklable attributes such as a
    `threading.Lock`, the class variable `dont_pickle` should be
    defined as a list containing the attribute names of the
    unpicklables.

    In addition, when an instance has been unpickled and the
    static method `when_unpickled()` is defined, it is called
    with the instance to add any unpicklable attributes.

        from opensaw.utils.picklable import Object
        from threading import Lock

        class LockedFile(Object):
            dont_pickle = ["lock"]

            @staticmethod
            def when_unpickled(instance):
                instance.lock = Lock()

            def __init__(self, file):
                self.file = file
                self.lock = Lock()
    """

    def __getstate__(self):
        state = self.__dict__.copy()

        unpicklables = getattr(type(self), "dont_pickle", [])

        for key in unpicklables:
            del state[key]

        # #### From the Python documentation:
        # > For new-style classes, if `__getstate__()` returns
        # > a false value, the `__setstate__()` method will not
        # > be called.
        #
        # To ensure that `__setstate__()` will be called,
        # return `True` if state is an empty dictionary.
        if not state:
            return True

        return state

    def __setstate__(self, dictionary):
        # The `dictionary` parameter is only `True` the dictionary
        # was empty. In that case, don't update `self.__dict__`.
        if dictionary is not True:
            self.__dict__.update(dictionary)

        maybe_fn = getattr(type(self), "when_unpickled", None)

        if callable(maybe_fn):
            maybe_fn(self)


class Dictionary(Object):
    """
    Dictionary
    ==========

    A `picklable.Dictionary` is like a `picklable.Object` except that
    it adds `dict` emulating methods.
    """

    def __init__(self):
        self.__data = dict()

    def __len__(self):
        return len(self.__data)

    def __getitem__(self, key):
        return self.__data[key]

    def __setitem__(self, key, value):
        self.__data[key] = value

    def __delitem__(self, key):
        del self.__data[key]

    def __iter__(self):
        return iter(self.__data)

    def __contains__(self, key):
        return key in self.__data
