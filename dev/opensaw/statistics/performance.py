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
from __future__ import division

"""
Instances of `Performance` can be used as a drop-in replacement
for the `subprocess` module. The reason is to allow easy timing
measurements to be made from invocations of external programs.

An example might look something like this:

    import subprocess

    def set_subprocess(sub):
        global subprocess
        subprocess = sub

    def some_invocation(args):
        return subprocess.check_output(['program'] + args)

If `set_subprocess` is called before `some_invocation`,
the time spent executing the program will be reported by
the `Performance` instance.
"""

from subprocess import PIPE, Popen, CalledProcessError
from operator import itemgetter

from opensaw.utils.funs import compose
from opensaw.statistics.semaphore import Semaphore
import re
import os
import logging
import resource
import tempfile
# Given a string; we split at the spaces,
# get the second item, and parse it as a float.
#
# For example:
#
#       "user 0.40" -> ["user", "0.40"] -> "0.40" -> 0.4
get_time_from_line = compose(float, itemgetter(1), str.split)


class Performance(Semaphore):
    def __init__(self):
        Semaphore.__init__(self)
        self.total = 0
        self.measurements = 0

    def report(self, time):
        """
        Reports the time spent on the last work object.
        """
        self.total += time
        self.measurements += 1

    def to_json(self):
        average = 0

        if self.measurements:
            average = self.total / self.measurements

        return {
            "average": average,
            "total": self.total,
            "measurements": self.measurements
        }

    # Do not ignore any `kwargs`, should not be confused with 'subprocess'
    def check_call(self, cmd):
        self.check_output(cmd, save_stdout=False, save_stderr=False)

    # Do not ignore any `kwargs`, should not be confused with 'subprocess'
    def check_output(self, cmd, timeout=0, save_stdout=True, save_stderr=True):
        proc, out, err = self.timed_call(cmd, timeout=timeout, save_stdout=save_stdout, save_stderr=save_stderr)

        if proc.returncode:
            raise CalledProcessError(proc.returncode, cmd, "%s \n %s"%(out,err))

        return out, err

    def timed_call(self, cmd, stdin_file=None, timeout=0, save_stdout=True, save_stderr=False):
        """
        Executes the `cmd` command, and reports the time
        spent on the command as the sum of user- and system-time.
        """
        if timeout == 0:
            limmin =resource.RLIM_INFINITY
            limmax =resource.RLIM_INFINITY
        else:
            limmin = timeout
            # Tracer needs some additional time to actually output the logfile...
            # Timeout for tracer should probably be implemented somewhere else.
            limmax = timeout+1

        # Closed automatically by Popen with close_fds=True
        stdout_arg = PIPE if save_stdout else open(os.devnull, 'w')
        stderr_arg = PIPE if save_stderr else open(os.devnull, 'w')
        stdin_arg = None if stdin_file is None else open(stdin_file,'rb')

        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        time_output = f.name

        proc = None
        try:
            proc = Popen(["/usr/bin/time","-o",time_output, "--portability"] + cmd,
                         stdout=stdout_arg, stderr=stderr_arg, stdin=stdin_arg, close_fds=True, preexec_fn=(lambda: resource.setrlimit(resource.RLIMIT_CPU, (limmin,limmax))))
            out, err = proc.communicate()
            if not save_stdout:
                out = "[Message by OpenSAW: Saving STDOUT disabled]"
            if not save_stderr:
                err = "[Message by OpenSAW: Saving STDERR disabled]"

        except Exception as e:
            # TODO Currently ugly handling of crashed runs....
            if proc is not None: # We know about the Proc, kill it
                proc.kill()
                proc.wait()
            else: # We don't know, assume it started and wait for timeout hoping it will exit
                import time
                time.sleep(timeout*2)

            if os.path.exists(time_output):
                os.unlink(time_output)
            logging.error("timed_call resulted in exception %s"%repr(e))
            raise

        # Parse the output of the time program
        # user- and system-times spent executing the `cmd` command.
        #
        # For example:
        #
        #     ...
        #     user 0.12
        #     sys 0.03
        if os.path.exists(time_output):
            time = 0
            with open(time_output,'r') as f:
                for l in f:
                    m = re.match("^(user|sys) ([0-9\\.]+).*$",l)
                    if m is None:
                        continue

                    try:
                       time = time + float(m.group(2))
                    except ValueError as e:
                        logging.error("Could not convert '%s' to time, ignoring - giving an invalid time result"%l)

            with self:
                self.report(time)

            os.unlink(time_output)

        return proc, out, err
