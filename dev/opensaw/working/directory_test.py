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
import os
import os.path

# Testing `opensaw.working.directory`
from opensaw.working import Directory


def test_create_with_nonexistent_dir(tmpdir):
    path = tmpdir.strpath
    assert os.path.exists(path)

    # Immediately remove the directory, but keep the path.
    tmpdir.remove()
    assert not os.path.exists(path)

    # Should create the directory if it doesn't exits.
    _ = Directory(path)
    assert os.path.exists(path)


def test_remove(tmpdir):
    d = Directory(tmpdir.strpath)

    assert os.path.exists(d.path)
    d.remove()
    assert not os.path.exists(d.path)


def test_copy_file(tmpdir):
    inner_dir = tmpdir.mkdir("inner")
    file = tmpdir.join("file")

    file.write("contents")

    d = Directory(inner_dir.strpath)
    assert d.is_empty()

    # Copy `file` to the `working.Directory` and
    # create another directory inside it.
    d.copy_file_here(file.strpath)
    _ = inner_dir.mkdir("inner_inner")
    assert not d.empty()

    d.empty()
    assert d.is_empty()

    d.copy_file_here("path_of_non_existent_file")
    assert d.is_empty()
