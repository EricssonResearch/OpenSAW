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
from opensaw import configure


def test_configure(tmpdir):
    # Move into temporary directory.
    tmpdir.chdir()
    crap = tmpdir.mkdir("opensaw_dir").join("crap")
    crap.write("contents")

    prog = tmpdir.join("program")
    prog.write("contents")
    assert crap.check()

    opts = configure.parse_arguments("program",
                                     "-i initial-in -c -q -- program {}".split())

    # Will enter `opensaw_dir` and delete any `crap` inside.
    configure.environment(opts)

    assert not crap.check()
    # Move into temporary directory, again.
    tmpdir.chdir()
    opts = configure.parse_arguments("program",
                                     "-d --strategy g -- program {}".split())

    configure.environment(opts)
