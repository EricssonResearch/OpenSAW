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
import logging
import pickle
from os.path import basename

try:
    import queue
except ImportError:
    import Queue as queue

# Locals
from opensaw import tracegraph, statistics
from opensaw.utils.jobs import InputJob, TraceJob
from opensaw.utils.json import from_builtin
import threading

class State(object):
    """
    A class representing the work done by OpenSAW.
    Use static methods State.from_options and State.load to create instances.
    """

    def __init__(self, directory, manifest, queue_size, trace_queue, in_queue,
                 tracegraph, input_db, path_condition_db, statistics=None):
        self.dir = directory
        self.manifest = manifest
        self.queue_size = queue_size
        self.forced_done = False
        self.trace_queue = trace_queue
        self.in_queue = in_queue
        self.tracegraph = tracegraph
        self.input_db = input_db
        self.input_db_lock = threading.RLock()
        self.path_condition_db = path_condition_db
        self.statistics = statistics

    def queues_empty(self):
        """Returns True if both in_queue and trace_queue are empty"""
        return self.in_queue.empty() and self.trace_queue.empty()

    def force_done(self):
        self.forced_done = True

    def is_done(self):
        if self.forced_done:
            return True
        """
        Returns True if all tasks are done in both the trace and input queues.
        """
        with self.trace_queue.all_tasks_done, self.in_queue.all_tasks_done:
            # No queue has unfinished_tasks
            return (self.trace_queue.unfinished_tasks is 0 and
                    self.in_queue.unfinished_tasks is 0)

    def log(self):
        """
        Writes the current state to logs.
        """
        logging.info("Generated {} inputs and {} traces."
                     .format(InputJob.COUNT, TraceJob.COUNT))

        logging.info("Generated tracegraph with {} nodes and {} edges."
                     .format(*self.tracegraph.size()))

        with open("tracegraph.dot", "w") as tracegraphDot:
            tracegraphDot.write(self.tracegraph.to_dot())

        with open("statistics.json", "w") as stats:
            json.dump(self.statistics, stats,
                      indent=2, default=from_builtin)

    def get_picklable_state(self):
        return {
            "QueueSize": self.queue_size,
            "InputQueue": self.in_queue.queue,
            "TraceQueue": self.trace_queue.queue,
            "InputCount": InputJob.COUNT,
            "TraceCount": TraceJob.COUNT,
            "tracegraph": self.tracegraph,
            "InputDB": self.input_db,
            "PathCondDB": self.path_condition_db,
            "Statistics": self.statistics
        }

    def save(self):
        """
        Pickles the current working state, so that work can be
        resumed later using State.load.
        """
        file_path = self.dir.local_path_for_file(self.manifest)

        logging.info("Saving progress in %s." % file_path)

        with open(file_path, "wb") as file:
            pickle.dump(self.get_picklable_state(), file)

    @staticmethod
    def from_options(directory, options):
        """
        Create a State object using an options object rather than the constructor
        """


        trace_queue = DiscardablePriorityQueue(options.queueSize)
        in_queue = DiscardablePriorityQueue(options.queueSize)

        # Copy initial inputs to working directory.
        input_db = set()
        for initial in options.initialInput:
            directory.copy_file_here(initial)
            # Strip down to the basename. Everything should be relative
            # to the working directory.

            initial_file_name = basename(initial)

            in_queue.put(InputJob.make_initial(initial_file_name))

            with open(initial_file_name, "r") as file:
                input_db.add(hash(file.read()))

        return State(directory, options.manifest, options.queueSize, trace_queue,
                     in_queue, tracegraph.Graph(), input_db, set(),
                     statistics.Aggregate())

    @staticmethod
    def load(directory, manifest):
        """
        Static method which unpickles a previous working state,
        letting work be resumed.
        """
        file_path = directory.local_path_for_file(manifest)

        logging.info("Resuming progress from %s." % file_path)

        with open(file_path, "rb") as file:
            state = pickle.load(file)

        queue_size = state["QueueSize"]

        trace_queue = DiscardablePriorityQueue(queue_size)
        trace_queue.queue = state["TraceQueue"]

        input_queue = DiscardablePriorityQueue(queue_size)
        input_queue.queue = state["InputQueue"]

        return State(directory, manifest,
                     queue_size, trace_queue, input_queue,
                     state["tracegraph"], state["InputDB"], state["PathCondDB"],
                     state["Statistics"])

# Ugly implementation assuming implementation details of PriorityQueue
class DiscardablePriorityQueue(queue.PriorityQueue):
    def discard(self):
        with self.mutex:
            if not self._qsize():
                raise queue.Queue.Empty
            deleted = self.queue[-1]
            del self.queue[-1]
            return deleted