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

from opensaw.utils.jobs import FileJob, InputJob, TraceJob

input_formatter = "in-{}".format


def test_FileJob():
    job = FileJob("name", 0)

    # `FileJob.set_up` should be called, but do nothing.
    job_ = pickle.loads(pickle.dumps(job))

    # Highly prioritized jobs should be sorted before others.
    list_of_jobs = [FileJob("file", x) for x in range(1, 6)]

    sorted_list_of_jobs = sorted(list_of_jobs)

    assert sorted_list_of_jobs[0].priority is 5


def test_InputJob():
    # The `COUNT` should start out at 0.
    assert InputJob.COUNT == 0

    # Create two `InputJob`s, with priorities 1 and 10.
    i1 = InputJob(input_formatter, 1)
    i2 = InputJob(input_formatter, 10)

    # Verify the `file_name` attribute
    assert i1.file_name == "in-1"
    assert i2.file_name == "in-2"

    # `i2` should have higher priority than `i1`
    assert i2 < i1

    # Can add dictionary properties to job objects.
    i1["prop"] = 1337

    # Pickle `i2` and `i1`
    pickled = [pickle.dumps(i2), pickle.dumps(i1)]

    # Reset `count`
    InputJob.COUNT = 0

    # Recover the pickled objects.
    rec_i2, rec_i1 = map(pickle.loads, pickled)

    # The `id`s should be equal.
    assert rec_i1.id == i1.id
    assert rec_i2.id == i2.id

    # Dictionary properties should be preserved
    assert rec_i1["prop"] == i1["prop"]

    # As per `InputJob.set_up()` after unpickling,
    # `InputJob.COUNT` should >= the largest unpickled id.
    assert InputJob.COUNT >= rec_i2.id

    # None of the two InputJobs is the initial one.
    assert not i1.is_initial()
    assert not i2.is_initial()

    # Make the initial Job.
    i0 = InputJob.make_initial("yo")

    assert i0.is_initial()

    # Ensure that the `file_name` is unaltered.
    assert i0.file_name == "yo"


def test_TraceJob():
    # Make sure the `COUNT` is `0` before testing.
    TraceJob.COUNT = 0

    # `TraceJobs` are just like `FileJobs`, but with an
    # additional property: `input_name`.
    job = TraceJob("result-file", "caused-by-input")
    assert job.file_name == "result-file"
    assert job.input_name == "caused-by-input"

    assert TraceJob.COUNT == 1

    # `TraceJob.set_up` should be called, incrementing `TraceJob.COUNT`.
    job_ = pickle.loads(pickle.dumps(job))

    assert TraceJob.COUNT == 2
