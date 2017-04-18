#!/usr/bin/python
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

# Main module for OpenSAW.

# Avoid the print statement
from __future__ import absolute_import, print_function

import logging
from time import sleep

# Local
# Keep local imports relative.
from opensaw import bap, configure, pin, working
from opensaw.utils.funs import abort, yesNoQuery

from opensaw.utils.threads import WorkThread
from opensaw.webserver import WebServer
import sys

# Main
def main(arguments):
    """
    The main function for the OpenSAW framework.
    Expects arguments to be the command line arguments.
    """
    # Parse command line arguments, excluding script name
    options = configure.parse_arguments("opensaw", arguments[1:])

    # Cannot clean working directory and resume
    if options.resume and options.clean:
        abort("Unable to erase files and resume progress. " +
              "Aborting before removing files.")

    # Creating working directory (maybe cleaned)
    directory, strategy = configure.environment(options)

    # Resuming progress if required
    if options.resume:
        options.initialInput = []

        try:
            work = working.State.load(directory, options.manifest)
        except Exception as e:
            abort("Unable to resume progress: {}".format(repr(e)))
    elif options.initialInput:
        work = working.State.from_options(directory, options)
    else:
        abort("Initial input file required.")

    # Prepare to measure the performance of `STP` and `BAP`.
    configure.performance_measurements(work)

    active_threads = []

    pin_worker = pin.Worker(work, strategy, options)
    bap_worker = bap.Worker(work, strategy, options)

    # Launch and monitor working threads
    for i in range(options.pinPool):
        active_threads.append(WorkThread(
            work.in_queue, work.trace_queue,
            pin_worker.run, "PinThread-%d"%i, ()))

    for i in range(options.parallelTraces):
        active_threads.append(WorkThread(
            work.trace_queue, work.in_queue,
            bap_worker.run, "BapThread-%d"%i, ()))

    if options.web_server:
        # Expose JSON data through "/api/<key>.json"
        active_threads.append(WebServer({
            "tracegraph": work.tracegraph,
            "statistics": work.statistics
        }))

    try:
        for thread in active_threads:
            thread.start()

        while not work.is_done():
            sleep(1)

        logging.info("OpenSAW run complete")
        work.statistics.complete()

        while not options.fast_exit:
            sleep(1)

    except (KeyboardInterrupt, SystemExit):
        logging.exception("Process interrupted!")

    finally:
        for thread in active_threads:
            thread.stop()

        for thread in active_threads:
            thread.join()

    logging.debug("Saving progress")
    # Save current state (if required)
    if not work.queues_empty() and not work.forced_done and yesNoQuery("Do you want to save the progress?"):
        try:
            work.save()
        except Exception as e:
            logging.exception("Couldn't save progress: {}".format(e))

    work.log()
    logging.debug("Shutting down logging")
    logging.shutdown()
