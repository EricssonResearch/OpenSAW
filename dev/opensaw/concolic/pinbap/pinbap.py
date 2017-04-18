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

import il
from opensaw.utils.funs import findFiles
import logging
import subprocess
import solver.cvc as solver
from re import compile
import os
import traceback
import sys
from os.path import basename

perf = None
def setPerformanceMeasurer(p):
    global perf
    perf = p
    solver.set_subprocess(p.solver)
    il.set_subprocess(p.il_tool)

# This is the class that contains the base for the functions of pinbap,
# The PinBap class below wraps the stateless functions of OldMethods
# into a stateful object.
class OldMethods(object):
    # Constants
    # Searching for a breakable stack index currently only
    # attempts to match `-0x30(%ebp, ...)`.
    #
    # InputJob requires a file_name_formatting function.
    #
    stack_index = compile("\(%e[bs]p,")



    @staticmethod
    def create_input_from_il(blocks, jump_number, prev_input, options):
        # TODO: Maybe use actual temporary files?
        il_file = "generating-{}-{}.il".format(hex(hash(prev_input)), jump_number)
        pc_file = "generating-{}-{}{}".format(hex(hash(prev_input)), jump_number, solver.extension)
        try:
            with open(il_file, "w") as file:
                # For now allow both generator and list to be able to test different
                # solutions.
                if type(blocks) == list:
                    il.write_code(blocks, jump_number, file)
                    il.write_altered_jump(blocks, jump_number, file)
                else:
                    il.write_altered_generator(blocks, jump_number, file)

            new_input = OldMethods.il_to_new_input(il_file, pc_file, prev_input, options)
        finally:
            success = os.path.isfile(pc_file)
            ignore_fail = not options.keepFailed
            PinBap._cleanup([pc_file, il_file], cleanup=(success or ignore_fail))

        return new_input

    @staticmethod
    def il_to_new_input(il_file, pc_file, prev_input, options):
        if not os.path.exists(il_file):
            logging.error("Could not find il file to read: %s"%il_file)
        try:
            il.to_path_condition(il_file, pc_file, options.bap, timeout=options.extTimeout, save_stderr=True, save_stdout=True)
        except subprocess.CalledProcessError as e:
            logging.error("Could not create constraint file %s input from: %s. Error: '%s', Cmd: '%s'. Output: '%s'" % (pc_file, il_file, repr(e), " ".join(e.cmd),e.output))
            return None, False
        try:
             new_input = solver.new_input_from_path_condition(prev_input, pc_file, timeout=options.extTimeout)
        except subprocess.CalledProcessError as e:
            logging.error("Failed to create new input from %s (%s) due to stp crash. Cmd: '%s'"%(il_file,pc_file," ".join(e.cmd)))
            return None, False
        return new_input

    @staticmethod
    def try_to_break_stack_access(blocks, jump_i, i, prev_input,options):
        """
        Tries to override the return address.
        """
        il_file_name = "break-{}-{}.il".format(hex(hash(prev_input)), jump_i)
        pc_file_name = "break-{}-{}{}".format(hex(hash(prev_input)), jump_i, solver.extension)
        try:
            with open(il_file_name, "w") as b:
                # Write all previous blocks
                il.write_code(blocks, jump_i - 1, b)
                if type(blocks) == list:
                    source = blocks[jump_i][0]
                else:
                    source = blocks.next()[0]
                # Keep the current block up to the index
                b.write(source[:i])

                # Create a jump to force an invalid stack write
                b.write(il.create_cjmp_from_source_position(source, i))
            new_input, different_from_previous = (
                OldMethods.il_to_new_input(il_file_name, pc_file_name, prev_input,options))
        finally:
            success = os.path.isfile(pc_file_name)
            ignore_fail = not options.keepFailed
            PinBap._cleanup([pc_file_name,il_file_name], cleanup=(success or ignore_fail))

        return new_input, different_from_previous

    @staticmethod
    def find_unsafe_stack_writes(blockfunc, jump_i, in_data, options):
        """
        Searches the jump with the given index for a tainted stack
        write. If one is found, it will call try_to_break_stack_access.
        """
        blocks = blockfunc()
        if type(blocks) == list:
            target_block = blocks[jump_i][0]
        else:
            for idx,jump in enumerate(blocks):
                if idx == jump_i:
                    target_block = jump[0]

        i = 0
        for line in target_block.splitlines():
            if OldMethods.stack_index.search(line):
                yield OldMethods.try_to_break_stack_access(blockfunc(), jump_i, i, in_data, options)

            # Add length of line + newline character
            i += len(line) + 1

class PinBapError(object):
    def __init__(self, trace_file, logfile, stdout, stderr, error_desc):
        self.error = error_desc

    def isSuccess(self):
        return False

    def getError(self):
        return self.error


class PinBap(object):
    IL_TRACE_SUFFIX = ".il"
    BIN_TRACE_SUFFIX = ".bpt"
    COVERAGE_SUFFIX = ".cov"

    def __init__(self, trace_file, input_file=None, success=True, coverage_file=None, stdout = None, stderr = None):
        self.file = trace_file
        self.input_file = input_file
        self.success = success
        self.coverage_file = coverage_file
        self.cache = {}
        self.stdout = stdout
        self.stderr = stderr

    def cleanup(self):
        PinBap._cleanup([self.getFilename()], cleanup=True)

    def getDebugString(self):
        return self.stderr

    def getInputFile(self):
        return self.input_file

    def isSuccess(self):
        return self.success

    def getFilename(self):
        return self.file

    def remove(self):
        PinBap._cleanup([self.getFilename(),self.coverage_file],cleanup=True)

    def removeCoverage(self):
        PinBap._cleanup([ self.coverage_file], cleanup=True)

    def getSignal(self):
         return il.find_fault_in_file(self.getFilename())

    def getCoverage(self):
        if not os.path.exists(self.coverage_file):
            logging.error('Could not find coverage file %s' % self.coverage_file)
            return None
        libs = self.__getLibs()
        with open(self.coverage_file) as block_file:
            block_dict = dict()

            entries = block_file.read().split(",")

            for entry in entries:
                if ":" not in entry:
                    continue
                address, taken_branches = map(int, entry.split(":"))
                haddress = hash(il.library_of_address(libs,address))
                block_dict[haddress] = taken_branches
            return block_dict

    def __fillCache(self):
        hashes, ins_counts, libs = il.find_bbls_and_normalized_hashes(self.getFilename())
        self.cache["hashes"] = hashes
        self.cache["ins_counts"] = ins_counts
        self.cache["libs"] = libs

    def __getJumps(self,asGenerator=True):
        if "jumps" not in self.cache:
            jumps = il.find_jumps(self.getFilename(),False)
            self.cache["jumps"] = jumps

        return self.cache["jumps"]

    def getBblHashes(self):
        if "hashes" not in self.cache:
            self.__fillCache()
        return self.cache["hashes"]

    def getInsCounts(self):
        if "ins_counts" not in self.cache:
            self.__fillCache()
        return self.cache["ins_counts"]

    def __getLibs(self):
        if "libs" not in self.cache:
            self.cache["libs"] = il.get_libs(self.getFilename())

        return self.cache["libs"]

    @staticmethod
    def __executePin(input_file, output_file, cov_file, logfile, options, timed_call):

        pin_args = ["-injection", "child",
                    "-t", options.pinTool
                    ]

        pintool_args = ["-logfile", logfile,
                        "-o", output_file,
                        "-b", cov_file,
                        ] + options.tracerExtra
        program_args = options.args[:] #Copy
        stdin_file = None

        if options.inputType == "file":
            pintool_args.extend(["-taint-files", input_file])
            for idx,arg in enumerate(program_args):
                if arg == '{}':
                    program_args[idx] = input_file
                    break
        elif options.inputType == "stdin":
            pintool_args.extend(["-taint-stdin"])
            stdin_file = input_file
        elif options.inputType == "none":
            pass
        else:
            raise NotImplementedError("Argument to --input must either be 'file' or 'stdin'")

        cmd = [options.pin] + pin_args + pintool_args + ["--"] + [options.program] + program_args
        #print("Cmd: %s"%" ".join(cmd))
        _, _, _ = timed_call(cmd, stdin_file, timeout=options.tracerTimeout, save_stdout=False, save_stderr=False)
        #TODO: Saving STDERR took too much memory for some runs, implement own Popen.communicate() that
        # only saves parts of STDERR
        return "<ERROR LOGGING DISABLED SEE pinbap.py>"

    #returns tuple (new_input, has_changed)
    # new_input is a binary string representing input required to take other path at branch[branch_number]
    # has_changed is true if the new_input is different than the original input.
    def swapBranch(self, branch_number, options):
        with open(self.getInputFile(), "rb") as in_f:
            prev_input = in_f.read()
        new_input = OldMethods.create_input_from_il(self.__getJumps(),branch_number,prev_input, options)
        return [new_input]

    #Must support negative branch numbers!
    def findUnsafeStackWrite(self, branch_number, options):
        with open(self.getInputFile(), "r") as in_f:
            prev_input = in_f.read()

        if branch_number < 0:

            jumps = self.__getJumps()
            if type(jumps) == list:
                jumplen = len(jumps)
            else:
                jumplen = sum(1 for i in jumps)
            branch_number = jumplen+branch_number

        return OldMethods.find_unsafe_stack_writes(self.__getJumps,branch_number, prev_input, options)

    @staticmethod
    def _cleanup(files, path='',bintrace=None, cleanup=True):
        if cleanup:
            if bintrace is not None:
                trace_file_matches = findFiles(path, basename(bintrace))
                files = files + trace_file_matches

            for file in files:
                if os.path.exists(file):
                    try:
                        os.unlink(file)
                    except OSError as e:
                        logging.error("Fail to cleanup file %s due to error %s, Ignoring, (see https://bugs.python.org/issue25717 )"%(file,repr(e)))

    @staticmethod
    def executeTracer(input_file, logfile, path, options, statistics):
        input_filename = os.path.basename(input_file)
        bintrace = os.path.join(path, input_filename + PinBap.BIN_TRACE_SUFFIX)
        cov_file = os.path.join(path, input_filename + PinBap.COVERAGE_SUFFIX)
        il_file = os.path.join(options.traceStorage, os.path.basename(input_file + PinBap.IL_TRACE_SUFFIX))
        try:
            ret = PinBap._executeTracer(input_file, logfile, path, options, statistics.perf.pin.timed_call, bintrace, cov_file, il_file)
            if ret.isSuccess():
                PinBap._cleanup([logfile], path, bintrace, True)
            else:
                PinBap._cleanup([cov_file, logfile, il_file], path, bintrace, not options.keepFailed)
            return ret
        except Exception as e:
            PinBap._cleanup([cov_file, logfile, il_file], path, bintrace, not options.keepFailed)
            print("Exception in user code: %s" % repr(e))
            traceback.print_exc(file=sys.stdout)
            logging.error("Exception %s during tracing, ignoring."%repr(e))
            return PinBapError(bintrace, logfile, "", "", "executeTracer crashed with %s"%repr(e))

    @staticmethod
    def _executeTracer(input_file, logfile, path, options, timed_call,bintrace,cov_file,il_file):
        try:
            err = PinBap.__executePin(input_file,bintrace,cov_file,logfile,options,timed_call)
        except subprocess.CalledProcessError as e:
            return PinBapError(bintrace, logfile, "", err, "Pin command '%s' crashed unexpectedly. Exception %s"%(" ".join(e.cmd),repr(e)))


        trace_file_matches = findFiles(path, basename(bintrace))
        if len(trace_file_matches) == 0:
            return PinBapError(bintrace, logfile, "", err,
                               "Could not find any trace file matching {tf} after pin run on input {inp}. Pin stderr: '{err}'".format(
                    tf=bintrace, err=err, inp=input_file))
        elif len(trace_file_matches) != 1:
            return PinBapError(bintrace, logfile, "", err, "Found too many matching trace files {}".format(bintrace))


        trace_file = trace_file_matches[0]

        # Lift the binary trace to the IL and remove the file, since
        # the binary trace file is no longer needed.
        if not os.path.exists(trace_file):
            return PinBapError(bintrace, logfile, None, None,
                               "Trace file %s found, but does not seem to exist." % trace_file)

        if os.path.exists(il_file):
            return PinBapError(bintrace, logfile, None, None,
                               "Cannot convert tracefile %s to %s as il file already exists." % (trace_file,il_file))

        try:
            il.from_trace(trace_file, il_file, options.bap)
        except subprocess.CalledProcessError as e:
            return PinBapError(bintrace, logfile, e.output, None, "Failed to convert trace %s to il output %s. Iltrans command '%s' crashed. Reason: %s" % (trace_file, il_file, " ".join(e.cmd),repr(e)))

        if not os.path.isfile(il_file):
            return PinBapError(bintrace, logfile, "", err, "Failed to convert trace %s to il. Iltrans did not crash." % trace_file)

        return PinBap(il_file,input_file,True,cov_file,"",err)

