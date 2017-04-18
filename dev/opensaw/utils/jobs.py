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
Module for jobs helper classes and functions.
"""

# Imports
# -------
from threading import Lock

# Import [[picklable]] to simplify serialization of Jobs.
from opensaw.utils import picklable
import os

class FileJob(picklable.Dictionary):
    """
    FileJob
    -------
    Holds information related to a task on hold or waiting
    to be executed based on a file.
    For convenience, it can be used as a dictionary.

    #### Parameters and Attributes
        file_name : str
            The name of the input file.
        priority : int
            The priority of the job.
    """
    def __init__(self, file_name, priority, path=None):
        picklable.Dictionary.__init__(self)
        if path is not None:
            self.__file_name = os.path.join(path,file_name)
        else:
            self.__file_name = file_name
        self.priority = priority

    def set_up(self):
        """
        Do any initial calculation. Obs: must be called both after
        constructor and unpickling
        """
        pass

    @property
    def file_name(self):
        return self.__file_name

    @file_name.setter
    def file_name(self, value):
        self.__file_name = value

    # Override Picklable's `__setstate__` implementation
    # to include a call to `set_up` when unpickling derived instances.
    def __setstate__(self, dictionary):
        picklable.Dictionary.__setstate__(self, dictionary)
        self.set_up()

    # Allow `FileJobs` to be sorted according to their priority.
    def __cmp__(self, other):
        """
        In order for high-priority jobs to be sorted to first,
        the comparison is reversed; `FileJob("a", 1) > FileJob("b", 2)`.
        """
        return cmp(other.priority, self.priority)


class InputJob(FileJob):
    """
    Input Job
    ---------
    Contains information about an execution job.

    #### Parameters
        name_formatter : (int) -> str
            A function taking an int and returning a file name.
            The `file_name` attribute will equal the return value.
        priority : int [default=0]
            The priority of the job.
        initial : bool [default=False]
            Whether the InputJob is the initial input.

    #### Attributes
        file_name : str
            The input file name.
        id : int
            The job id. Should also be part of the file_name.
        priority : int
            The priority of the job.
    """

    COUNT = 0
    LOCK = Lock()

    def __init__(self, name_func, priority=0, initial=False, path=None):
        self.id = 0 if initial else InputJob.next_id()
        FileJob.__init__(self, name_func(self.id), priority, path=path)

    def set_up(self):
        """
        Ensures that `InputJob.COUNT` is at least as large as `self.id`.
        """
        if self.id > InputJob.COUNT:
            InputJob.COUNT = self.id

    def is_initial(self):
        """
        Returns `True` if this `InputJob` was the initial one.
        """
        return self.id is 0

    @staticmethod
    def make_initial(name):
        return InputJob(lambda _: name, 1000000, True)

    @classmethod
    def next_id(cls):
        """
        Atomically increments `COUNT` and returns the new value.
        """
        with cls.LOCK:
            cls.COUNT += 1
            return cls.COUNT


class TraceJob(FileJob):
    """
    Trace Job
    ---------
    Contains information about a job to generate new inputs
    given a trace of a previous execution and the input yielding
    said trace.

    #### Parameters and Attributes
        file_name : str
            The name of the trace file.
        input_name : str
            The name of the input file, which yielded the trace.
        priority : int [default=0]
            The priority of the job.
    """
    COUNT = 0
    LOCK = Lock()

    def __init__(self, file_name, input_name, priority=0):
        FileJob.__init__(self, file_name, priority)
        self.__input_name = input_name

        with TraceJob.LOCK:
            TraceJob.COUNT += 1

    def set_up(self):
        TraceJob.COUNT += 1

    @property
    def input_name(self):
        return self.__input_name
