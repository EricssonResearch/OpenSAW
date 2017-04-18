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

# The BAP module is responsible for input generation.

from __future__ import absolute_import

import logging
import shutil
from os.path import basename
from os import remove

try:
    import queue
except ImportError:
    # noinspection PyUnresolvedReferences
    import Queue as queue

from threading import current_thread
import traceback
import sys
from time import sleep

from opensaw.concolic import ConcolicEngine
from opensaw.utils.jobs import InputJob
from opensaw.utils import threads

input_file_formatter = "generated-{}.in".format


class Worker(object):
    def __init__(self, work, strategy, options):
        """
        Takes a working.State, a strategy.Strategy, and options
        """
        self.work = work
        self.strategy = strategy
        self.options = options
        self.thread = None

        # We can analyse branches in parallel, but we want only at most bapPool nr of analyzes running
        # at the same time. As we have multiple threads adding work to the same workers we need to
        # be able to know when the work of one thread is done.
        self.bpool = threads.MultiThreadPool("BAP-pool", self.options.bapPool, self.options.profile)

    def run(self):
        """
        The main function for generating inputs called from the main thread.
        The function is intended to be running in a separate thread
        of type utils.threads.WorkThread:
           - New traces are submitted by the put method
           - New inputs are fetched by the get method
        """
        self.thread = current_thread()
        logging.debug("Running BAP in thread: {}".format(self.thread.getName()))

        # Main loop
        while not self.thread.is_stopped():
            trace_job = self.thread.get()

            if trace_job is None:
                sleep(1)
                continue
            self.handle_trace_job(trace_job)

        # All tasks in the bpool should have finished as the pool was joined.
        # Stop and join anyway
        self.bpool.stop()
        self.bpool.joinThreads()

    def handle_trace_job(self, trace_job):
        """
        Handles a single trace job.
        """
        branchPoolname = "BAP-pool-branches-%s"%trace_job.file_name;
        self.bpool.addQueue(branchPoolname,Worker.analyze_edge_node_pair,self.options.bapPool)

        logging.debug("Got trace task: {}."
                      .format(trace_job.file_name))

        self.strategy.handleBAPNewTrace(trace_job)



        #Still need to work in the path that we are working in
        #Added to be able to run in ramdisk without having to store resting traces in ramdisk
        if trace_job.file_name != basename(trace_job.file_name):
            shutil.move(trace_job.file_name,basename(trace_job.file_name))
            trace_job.file_name = basename(trace_job.file_name)


        raw_trace = ConcolicEngine(trace_job.file_name, trace_job.input_name)

        # For small traces one can store visited nodes in memory while they are in the Queue.
        # For larger we simply recalculate the visited nodes
        # Use flag --reanalyzeTrace to enable recalculation.
        if "tracegraph:trace" in trace_job:
            trace = trace_job["tracegraph:trace"]
        else:
            trace, _ = self.work.tracegraph.update(
                trace_job, raw_trace.getBblHashes(), raw_trace.getInsCounts(), not self.options.ctxIndependent)


        # Let the strategy pick the interesting nodes.
        edge_node_pairs = self.strategy.getNodes(self.work.tracegraph, trace)
        #cache = {}
        chosen_pairs = 0
        for edge, node in edge_node_pairs:
            chosen_pairs += 1
            if self.options.limitTrace != -1 and chosen_pairs > self.options.limitTrace:
                break

            if self.should_abort():
                break

            ## Previously we supported returning edges from other traces, this
            ## requires OpenSAW to store all traces ever created (could implement
            ## removal function in strategy though). As this is too much storage,
            ## we have removed this feature for now. (If reimplementing, remember
            ## to recreate the raw_trace in check_Stack_writes and remove the os.remove)

            #if edge.trace in cache:
            #    raw_trace = cache[edge.trace]
            #else:
            #    raw_trace = ConcolicEngine(edge.trace,edge.input,True)
            #    cache[edge.trace] = raw_trace
            #
            ## It's not a smart cache, but it does its job for strategies that only handle a few traces
            #if len(cache) > 3:
            #    cache = {}
            if basename(edge.trace) != basename(trace_job.file_name):
                logging.error("Strategy returned edge from different trace. This has been temporarily disabled!")

            self.bpool.addToQueue(branchPoolname,(self, edge, node, raw_trace, trace_job))

        if chosen_pairs == 0:
            logging.warning("Strategy returned 0 nodes to explore for: {}"
                            .format(trace_job.file_name))

        # TODO: Should put this in a thread too.
        if self.options.check_stack_writes:
            # File names

            # il_file = basename(trace_job.file_name)
            # in_file = basename(trace_job.input_name)
            # raw_trace = ConcolicEngine(il_file, in_file, True)

            # Check the last block, since it isn't covered
            # by the strategies, and should only ever be executed
            # once through this particular path.
            try:
                generator = raw_trace.findUnsafeStackWrite(-1, self.options)
                for new_input, different in generator:
                    if not different:
                        continue

                    input_job = self.put_new_input_job(new_input)

                    if input_job is not None:
                        # Give potentially crashing inputs a high ranking.
                        input_job.priority = 10000000

                        input_job["pin:execute_only"] = True
                        self.thread.put(input_job)
            except Exception as e:
                print("Exception in user code: %s" % repr(e))
                traceback.print_exc(file=sys.stdout)
                logging.error("Failed to look for unsafe stack write in %s due to %s" % (trace_job.input_name, repr(e)))

        while not self.should_abort() and not self.bpool.queueDone(branchPoolname):
            # TODO: Change from polling behaviour
            sleep(1)

        self.bpool.delQueue(branchPoolname)

        remove(trace_job.file_name)
        if not self.should_abort():
            self.thread.task_done()
        raw_trace.cleanup()
        # ConcolicEngine(trace_job.file_name, trace_job.input_name, True).cleanup()

    def analyze_edge_node_pair(self, edge, node, raw_trace, trace_job):
        if self.should_abort():
            return
        il_file = raw_trace.getFilename()
        logging.debug("Trace task: {}, analysis branch: {}."
                      .format(il_file, edge.position))
        try:
            input_generator = raw_trace.swapBranch(edge.position, self.options)
        except Exception as e:
            traceback.print_exc()
            logging.error("Failed to swap branch in trace %s due to %s. Ignoring exception"%(il_file,repr(e)))
            return


        for new_input,is_new in input_generator:
            if not is_new:
                self.strategy.handleBAPNewInput(trace_job, self.work.tracegraph, edge, node, None)
                continue
#            print("New input len: %d"%len(new_input))
            input_job = self.put_new_input_job(new_input)
            if input_job is not None:
                input_job.priority = trace_job.priority

            shouldHandle = self.strategy.handleBAPNewInput(trace_job, self.work.tracegraph, edge, node, input_job)

            if input_job is not None and shouldHandle is not False:
                self.thread.put(input_job)

        if self.options.check_stack_writes:
            try:
                generator = raw_trace.findUnsafeStackWrite(edge.position, self.options)
                for new_input, different in generator:
                    if not different:
                        continue

                    input_job = self.put_new_input_job(new_input)

                    if input_job is not None:
                        # Give potentially crashing inputs a high ranking.
                        input_job.priority = 10000000

                        input_job["pin:execute_only"] = True
                        self.thread.put(input_job)
            except Exception as e:
                print("Exception in user code: %s" % repr(e))
                traceback.print_exc(file=sys.stdout)
                logging.error("Failed to look for unsafe stack write in %s due to %s"%(trace_job.input_name,repr(e)))
                return

    def should_abort(self):
        """
        Returns true if the Worker thread is stopped.
        """
        if self.thread is None:
            return False
        return self.thread.is_stopped()

    def put_new_input_job(self, new_input):
        """
        Creates a new input job from the given input.
        """
        input_hash = hash(new_input)
        input_db = self.work.input_db

        # If the input_hash already exists in the input database,
        # it has already been taken care of. Ignore this duplicate
        # and return `None`.
        with self.work.input_db_lock:
            if input_hash in input_db:
                return None

            input_db.add(input_hash)

        # Create a new InputJob with a `file_name` property,
        # formatted according to `input_file_formatter`.
        input_job = InputJob(input_file_formatter,path=self.options.inputStorage)

        with open(input_job.file_name, "wb") as new_input_file:
            new_input_file.write(new_input)

        return input_job