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

# Wrapper module for the trace generation process.

# ===============================================================================
# Imports
# ===============================================================================
from __future__ import absolute_import, print_function

import sys
import traceback
import logging
import os
from threading import current_thread
from time import sleep

try:
    import queue
except ImportError:
    import Queue as queue

from opensaw.concolic import ConcolicEngine
from opensaw.utils.jobs import TraceJob
from opensaw.utils.threads import ThreadPool

# ===============================================================================
# Constants
# ===============================================================================



SIGNALS = {
    1: "SIGHUP",
    2: "SIGINT",
    4: "SIGILL",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    11: "SIGSEGV",
    15: "SIGTERM",
    24: "SIGXCPU"
}


class Worker(object):
    """
    PIN Worker
    ==========
    """

    def __init__(self, work, strategy, options):
        self.work = work
        self.statistics = work.statistics
        self.strategy = strategy
        self.options = options

    def run(self):
        """
        The main function for generating traces called from the main thread.
        The function is intended to be running in a separate thread
        of type `utils.threads.WorkThread`:

        - Current inputs used and their traces are submitted by the put method
        - New inputs from BAP component are fetched by the get method
        """
        thread = current_thread()

        logging.debug("Running PIN in thread: {}".format(thread.name))

        while not thread.is_stopped():
            bap_queue_full = self.options.maxTraceQueue != 0 and self.work.trace_queue.qsize() > self.options.maxTraceQueue
            if bap_queue_full:
                if self.options.discardOverflow:
                    # Temporary use of private stuff - self.work.trace_queue is a DiscardablePriorityQueue, discard()
                    # removes item that was last in this queue. In fact this should probably be done somewhere else,
                    # in some other way.
                    try:
                        discarded_job = self.work.trace_queue.discard()
                    except queue.Queue.empty:
                        discarded_job = None

                    if discarded_job is not None and os.path.exists(discarded_job.file_name):
                        os.unlink(discarded_job.file_name)
                else:
                    sleep(1)
                continue

            job = thread.get()

            if job is None:
                sleep(1)
                continue

            logging.debug("Got input task: {}.".format(job.file_name))

            if job.is_initial():
                self.strategy.handlePINInitInput(job)
            else:
                self.strategy.handlePINNewInput(job)
            self.handle_input_job(thread, job)


    def handle_input_job(self, parent_thread, job):
        """
        Should run in another thread.
        """
        # If the `pin:execute_only` command is received,
        # BAP has created an input which should only
        # be executed (and checked for faults).
        # If it doesn't exist, we should create a trace job
        create_trace_job_after_exec = "pin:execute_only" not in job

        in_file = job.file_name

        logging.debug("Handling input: {}".format(in_file))
        try:
            raw_trace = self.create_trace(in_file)
        except Exception as e:
            print("Exception in user code: %s"%repr(e))
            traceback.print_exc(file=sys.stdout)
            logging.error("Trace creation for input %s caused exception %s. Skipping."%(in_file,repr(e)) )
            parent_thread.task_done()
            return

        #Mark a thread finished in statistics.
        self.statistics.mark_thread_complete()        

        if raw_trace.isSuccess() == False:
            logging.error("Got no trace from input: %s" % in_file)
            parent_thread.task_done()
            return

        success = self.report_coverage(raw_trace)

        if success:
            raw_trace.removeCoverage()
        else:
            logging.error("Pin run did not create coverage file. Input %s" % in_file)

        # TODO: It's odd that we have to create a TraceJob and pass
        # it to the tracegraph in order to know what rank/priority to give it.
        if create_trace_job_after_exec:
            trace_job = TraceJob(raw_trace.getFilename(), in_file)

            # Update trace graph with the new BBL hashes.
            trace, (new_blocks, new_edges) = self.work.tracegraph.update(
                trace_job, raw_trace.getBblHashes(), raw_trace.getInsCounts(), not self.options.ctxIndependent)
            # Set additional properties.
            if self.options.ranking == 'N':
                rank = 0
            elif self.options.ranking == 'B':
                rank = new_blocks
            elif self.options.ranking == 'U':
                rank = new_edges
            else:
                raise Exception("Do not know of ranking option '%s'. Use 'N', 'B' or 'U'."%self.options.ranking)

            trace_job.new_blocks = new_blocks
            trace_job.new_edges = new_edges
            trace_job.priority = rank

            if not self.options.reanalyzeTraces:
                trace_job["tracegraph:trace"] = trace

            shouldHandle = self.strategy.handlePINNewTrace(job, trace_job)

            # Submit the trace for input generation
            if shouldHandle is not False:
                parent_thread.put(trace_job)

        parent_thread.task_done()

    def create_trace(self, in_file_path):
        thread_id = current_thread().ident

        pin_log_file = self.work.dir.local_path_for_file(
            "pintool-{}.log".format(thread_id))

        # execute to create new binary trace
        raw_trace = ConcolicEngine.executeTracer(in_file_path,pin_log_file,self.work.dir.path,self.options,self.statistics)
        if not raw_trace.isSuccess():
            logging.error(raw_trace.getError())
        else:
            # Check for faults in the IL.
            self.check_faults(raw_trace)

        # Return the BAP IL file name
        return raw_trace


    def check_faults(self, raw_trace):
        fault_string = "signal {fault} caused by input: {file}"

        if self.options.checkFaults:
            signal_number = raw_trace.getSignal()

            if signal_number is None or SIGNALS[signal_number] in self.options.ignoreSignals:
                return

            message = fault_string.format(
                fault=SIGNALS[signal_number], file=raw_trace.getInputFile())
            logging.error(message)
            print(message)
            if self.options.singleError:
                self.work.force_done()
            #Anders: Possibly naive assumption that the last node visited caused the crash
            self.statistics.crashes.report(raw_trace.getInputFile(), signal_number, self.build_crash_trace(raw_trace))

    def build_crash_trace(self, raw_trace):
        ret = []
        hashes = raw_trace.getBblHashes()
        for h in hashes:
            if not h in ret:
                ret += [h]
            else:
                i = ret.index(h)
                ret = ret[0:i+1]

        for i,h in enumerate(ret):
            ret[i] = str(h)
        return ret

    def report_coverage(self, raw_trace):
        coverage = raw_trace.getCoverage()
        if coverage == None:
            return False
        with self.statistics.coverage:
            self.statistics.coverage.update(coverage)
            return True
