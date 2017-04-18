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
from __future__ import absolute_import, print_function

import json
import logging
import argparse
from os.path import dirname, abspath, join, isfile
import os

from opensaw import working
from opensaw import concolic
from opensaw.strategy import from_string, Default as DefaultStrategy
from opensaw.utils.funs import abort


def parse_arguments(program, arguments):
    """
    Parse command line arguments
    """

    # TODO: Find a new placement for `opensaw_config.json`.
    # It is not easily configurable from inside OpenSAW's source code.
    # A common place is the home directory, or the current directory.
    # Perhaps we should look for `./opensaw_config.json` first,
    # and then try `~/opensaw_config.json` if we can't find it?
    config_filename = join(dirname(__file__), "opensaw_config.json")

    try:
        with open(config_filename) as file:
            config_data = json.load(file)
    except IOError as err:
        abort("Couldn't load config file, terminating:\n\t{}".format(err))
    except ValueError as err:
        abort("Couldn't parse config file, terminating:\n\t{}".format(err))

    parser = argparse.ArgumentParser(prog=program)

    #TODO: Currently configuration options used only by concolic engine are defined here, would be nice
    # if concolic engine could decide additional options for itself.

    # Common arguments and options
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        help="Debugging messages")

    parser.add_argument("-q", "--quiet",
                        action="store_true",
                        help="Disable logging")

    parser.add_argument("-l", "--logFile",
                        default="opensaw.log",
                        help="Log file")

    parser.add_argument("-w", "--workDirectory",
                        default="opensaw_dir",
                        help="Work directory")

    parser.add_argument("-r", "--resume",
                        action="store_true",
                        help="Resume progress in work directory")

    parser.add_argument("--queueSize",
                        type=int,
                        default=0,
                        help="Maximal size of the internal work queues")

    parser.add_argument("--extTimeout",
                        type=int,
                        default=0,
                        help="Maximum time to run external tools (Except tracer) such as iltrans, stp etc. 0 Means no timeout.")

    parser.add_argument("--discardOverflow",
                        default=False,
                        action="store_true",
                        help="When using --maxTraceQueue and queue is full do not block pin thread, instead drop last trace on queue.")

    parser.add_argument("--reanalyzeTraces",
                        default=False,
                        action="store_true",
                        help="The trace queue from pin to bap can become large. Instead of keeping nodes in memory, reanalyze them"
                             "when they are being handled by bap.")

    parser.add_argument("--parallelTraces",
                        type=int,
                        default=2,
                        help="Number of traces to create new inputs from simultaneously. (Default 2)")

    parser.add_argument("--traceStorage",
                        default=".",
                        help="Folder to store traces in queue. Default is same as --workDirectory")

    parser.add_argument("--inputStorage",
                        default=".",
                        help="Folder to store generated inputs in. Default is same as --workDirectory")

    parser.add_argument("--keepFailed",
                        default=False,
                        action="store_true",
                        help="Keep input files to failed pin runs.")

    parser.add_argument("--tracerTimeout",
                        type=int,
                        default=0,
                        help="Maximum time to run tracer tools such as pin etc. 0 Means no timeout. Remember to ignore signal SIGXCPU")

    parser.add_argument("--limitTrace",
                        type=int,
                        default=-1,
                        help="Only analyse the first n edges.")

    parser.add_argument("--maxTraceQueue",
                        type=int,
                        default=0,
                        help="Maximum number of traces in trace queue before pausing tracer. 0 Means no limit.")


    parser.add_argument("-c", "--clean",
                        action="store_true",
                        help="Clean the working directory before start")

    parser.add_argument("-m", "--manifest",
                        default="opensaw.manifest",
                        help="Manifest file name")

    parser.add_argument("-s", "--strategy",
                        default="",
                        help="The string defining the search strategy. See docs/Strategies.md")

    parser.add_argument("--ctxIndependent",
                        action="store_true",
                        default=False,
                        help="Context independent strategy variant")

    parser.add_argument("--inputType",
                        default="file",
                        help="[file|stdin|none]. Selects if input data from -i should be passed as filename or via stdin or not at all")

    parser.add_argument("--tracerExtra",
                        default=None,
                        help="Extra arguments to pass to tracer program (PIN). Eventual initial spaces will be stripped, use this to pass arguments starting with -")


    parser.add_argument("--ignoreSignal",
                        default=[],
                        action='append',
                        help="Signal to ignore i.e --ignoreSignal SIGTERM, can be supplied multiple times.")

    parser.add_argument("--ranking",
                        default="U",
                        help="The ranking method: (U) for unigram based and (B) for bigram based.")

    # Specific arguments and options for trace generation and PIN execution
    parser.add_argument("program",
                        help="The target program.")

    parser.add_argument("args",
                        nargs='*',
                        help="Optional arguments to use when invoking program.")

    parser.add_argument("-i", "--initialInput",
                        action='append',
                        default=[],
                        help="Initial input file unless progress is resumed. Can be supplied multiple times.")

    parser.add_argument("--initialDirectory",
                        help="Directory containing initial inputs. Can be used with -i")

    parser.add_argument("--pinPool",
                        type=int,
                        default=5,
                        help="Maximal size of the pin thread pool (default 5)")

    parser.add_argument("--bapPool",
                        type=int,
                        default=5,
                        help="Number of threads used to analyze individual branch modifications (default 5)")

    parser.add_argument("--profile",
                        action="store_true",
                        default=False,
                        help="Profile opensaw execution. Stats dumped to files in /tmp/")

    parser.add_argument("--singleError",
                        action="store_true",
                        default=False,
                        help="Finish opensaw run when first error is found")

    parser.add_argument("--pin",
                        help="Path to PIN")

    parser.add_argument("--pinTool",
                        help="Path to the PIN tool for trace generation")

    parser.add_argument("--bap",
                        help="Path to BAP")

    parser.add_argument("-f", "--checkFaults",
                        default=False,
                        action="store_true",
                        help="Check the pintool log for faults in program run")

    parser.add_argument("--web-server",
                        action="store_true",
                        help="Supply JSON statistics over HTTP at port 8080")

    parser.add_argument("--no-web-server",
                        dest="web_server",
                        action="store_false",
                        help="...")

    parser.add_argument("--fast-exit",
                        default=False,
                        action="store_true",
                        help="Exit OpenSAW as soon as execution completes")

    parser.add_argument("--no-fast-exit",
                        dest="fast_exit",
                        action="store_false",
                        help="...")

    parser.add_argument("--check-stack-writes",
                        action="store_true",
                        help="Attempt to write to return address, in order to check the validity of stack writes.")

    # Initialize arguments with config defaults.
    parser.set_defaults(**config_data)

    options = parser.parse_args(args=arguments)

    assert_required_tools_defined(options)

    # Initial input may be `None`. Only determine absolute path if str.
    if options.initialInput:
        options.initialInput = map(abspath,options.initialInput)

    if options.tracerExtra is not None:
        options.tracerExtra = options.tracerExtra.lstrip().split(" ")
    else:
        options.tracerExtra = []

    if options.initialDirectory:
        dname = abspath(options.initialDirectory)
        onlyfiles = [os.path.join(dname, f) for f in os.listdir(dname) if os.path.isfile(os.path.join(dname, f))]
        options.initialInput += onlyfiles

    is_file_input = options.inputType == "file"
    matching_args = 0
    for arg in options.args:
        if arg == '{}':
            matching_args = matching_args + 1

    if is_file_input and matching_args != 1:
        abort("User specified file input but we found %d program arguments with value '{}' to replace with filename (expected 1). See --help"%matching_args)

    options.ignoreSignals = options.ignoreSignal
    if not isfile(options.program):
        abort("Could not find program that we are supposed to test: '%s' See --help" % options.program)
    options.program = abspath(options.program)

    options.workDirectory = abspath(options.workDirectory)

    # Pretty print all options.
    if options.debug:
        print(json.dumps(options.__dict__, indent=2))

    return options


def environment(options):
    """
    Configures the current environment to be in line with
    what is expected by OpenSAW.

    This includes the current `working.Directory`,
    logging and initial setup of search strategy.
    """
    directory = working.Directory(options.workDirectory)

    if options.clean:
        directory.empty()

    directory.enter()

    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(levelname)s] [%(threadName)-10s] [%(asctime)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename=options.logFile)

    if options.quiet:
        logging.disable(logging.WARNING)

    # Set up strategy
    strategy = from_string(options.strategy)

    if options.strategy == "":
        logging.warning("No strategy was specified. The default strategy will be used.")
        strategy = DefaultStrategy()
    elif strategy is None:
        logging.error("Invalid strategy: '%s' was specified" % options.strategy)
        raise Exception("Invalid strategy: %s" % options.strategy)

    logging.info("Using strategy: {}".format(type(strategy).__name__))

    return directory, strategy


def performance_measurements(working_state):
    """
    Configures OpenSAW's ability to measure performance.
    Overrides the subprocess module of the `il` and `solver.cvc`
    packages. Thereby being able to track the resource consumption.
    """
    perf = working_state.statistics.perf
    concolic.setPerformanceMeasurer(perf)


def assert_required_tools_defined(options):
    required_path_string = "The `{tool}' tool must be specified using `--{arg} <path>'"
    required_tools = {
        "iltrans": "bap",
        "pin": "pin",
        "gentrace.so": "pinTool"
    }

    for tool, arg in required_tools.items():
        path = getattr(options, arg)
        if path is None:
            abort(required_path_string.format(tool=tool, arg=arg))
        if not isfile(path):
            abort("The file {path} could not be found. Specified by --{arg}".format(path=path, arg=arg))