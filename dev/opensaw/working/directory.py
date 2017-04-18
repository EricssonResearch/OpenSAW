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
A module abstracting the working directory concept.

Example:

    >>> import tempfile, os
    >>> dir = Directory(tempfile.mkdtemp())
    >>> os.getcwd() == dir.path
    False
    >>> dir.enter()
    >>> os.getcwd() == dir.path
    True
    >>> chdir("..")
    >>> dir.remove()
"""

from os.path import basename, exists, join
from os import chdir, listdir, makedirs, remove, rmdir, walk
from shutil import copyfile


class Directory(object):
    """
    A working directory abstraction.

    #### Parameters and Attributes
        path : str
            The absolute path to the directory.
    """
    def __init__(self, path):
        self.path = path

        if not exists(path):
            makedirs(path)

    def is_empty(self):
        """
        Returns True if the directory is empty.
        """
        return len(listdir(self.path)) is 0

    def empty(self):
        """
        Cleans the directory by removing all files and folders.
        """
        for root, dirs, files in walk(self.path, topdown=False):
            for name in files:
                remove(join(root, name))
            for name in dirs:
                rmdir(join(root, name))

    def remove(self):
        """
        Removes the working directory. The directory must be empty.
        """
        rmdir(self.path)

    def enter(self):
        """
        Makes the process enter the directory.
        """
        chdir(self.path)

    def copy_file_here(self, path):
        """
        Copies the file at `path` to the working directory.
        """
        if exists(path):
            copyfile(path, self.local_path_for_file(basename(path)))

    def local_path_for_file(self, filename):
        """
        Returns the absolute path to a file named `filename`
        within the directory.
        """
        return join(self.path, filename)
