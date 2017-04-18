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
import re
from zlib import adler32

from opensaw.concolic.pinbap.il.x86.cjumps import cjumps
import logging
import os

def set_subprocess(s):
    global subprocess
    subprocess = s


# Local Constants
# Compile regex once.
SPECIAL_MODULE = "special \"Loaded module "
hex_matcher = re.compile(r"0x([0-9a-f]+)")


def get_first_hex(line):
    """
    Get the value of the first hexadecimal number in `line`, or `0`.
    """
    m = hex_matcher.search(line)

    if not m:
        return 0

    return int(m.group(0), 16)


# Invoke `subprocess.check_call` with silenced outputs.
def silent_call(cmd, timeout, save_stdout=True, save_stderr=True):
    output, error = subprocess.check_output(cmd, timeout=timeout, save_stdout=save_stdout,save_stderr=save_stderr)
    return output, error


def from_trace(trace_file, il_file, iltrans="iltrans", timeout=0):
    return silent_call([
        iltrans,
        "-serializedtrace", trace_file,
        # Replace `unknown`s with zeroes. Any `unknown`s remaining
        # in the _il_ will cause an STP error when solving constraint.
        "-replace-unknowns",
        "-pp-ast", il_file], timeout=timeout, save_stdout=False, save_stderr=False)


def to_path_condition(il_file, pc_file, iltrans="iltrans", timeout=0, save_stdout=False, save_stderr=False):
    return silent_call([
        iltrans,
        "-il", il_file,
        "-trace-formula", pc_file], timeout=timeout, save_stdout=save_stdout, save_stderr=save_stderr)


def iterate_lines(filename):
    try:
        # Warning: Too many open files error is probably a result of this.
        # We use "with open(" in combination with yield - thus the file is
        # closed only when the generator is garbage collected.

        with open(filename, 'r') as f:
            for line in f:
                line = line.rstrip('\n')
                yield line
    except IOError as e:
        print("Ignoring IOError %s when parsing %s"%(repr(e),filename))
        logging.error("IOError occurred when reading %s. File exists: %s, Isfile: %s"%(filename,os.path.exists(filename),os.path.isfile(filename)))
    except MemoryError as e:
        print("Ignoring MemoryError %s while iterating lines in file %s"%(repr(e),filename))
        logging.error("MemoryError occurred when reading %s. File exists: %s, Isfile: %s" % (
        filename, os.path.exists(filename), os.path.isfile(filename)))


def find_jumps(infile,asGenerator=False):
    t = find_all_jumps(iterate_lines(infile))
    if asGenerator:
        return t
    return list(t)

def get_libs(infile):
    libs = parse_libraries(iterate_lines(infile))
    return libs

def find_bbls_and_normalized_hashes(infile):
    libs = get_libs(infile)
    jumps = find_jumps(infile,False)

    hashes, counts = normalized_bbl_hashes(libs, jumps)
    return hashes, counts, libs


# TODO: Maybe we should only use il indicies. See other comments
def find_all_jumps(line_iterator):
    before_last_jump = 0
    jump_instruction = None
    jump_state = None

    block = []
    for ln, line in enumerate(line_iterator):
        is_addr = line.startswith("addr 0x")
        block.append(line)

        # We must first check if we are currently working on some
        # jump instruction. If we encounter some other instruction,
        # we stop and clear the `jump_instruction` variable.
        # We then check if it has been cleared and parse a new one.
        if jump_instruction:
            if is_addr:
                yield (
                    ("\n".join(block[:before_last_jump]),
                     jump_state.get_altered_jump()))
                block = block[before_last_jump:]
                jump_instruction = None
            else:
                # If we have found a jump instruction, were looking
                # for the `EFLAGS` and `ECX` context data.
                # Ignore everything else...
                if '"EFLAGS"' in line:
                    jump_state.read_flags(line)
                elif '"R_ECX"' in line:
                    jump_state.read_ecx(line)

        if jump_instruction is None and is_addr:
            parts = line.split()
            if len(parts) < 4 or len(parts[3]) < 1:
                if parts[0] == 'addr':
                    continue
                logging.error("Fail to parse instruction %s"%parts)
                continue
            instruction = parts[3][1:]

            # Get the condition which satisfies the instruction.
            # Don't ask me how, but this works...
            condition = cjumps.get(instruction)
            if condition:
                jump_state = JumpState(line, condition)
                before_last_jump = len(block) - 1
                jump_instruction = instruction

    yield (("\n".join(block), None))

class JumpState(object):
    def __init__(self, initial_line, condition):
        self.line = initial_line
        self.cond = condition
        self.flags = 0
        self.ecx = 0

    def read_flags(self, line):
        self.flags = get_first_hex(line)

    def read_ecx(self, line):
        self.ecx = get_first_hex(line)

    def get_altered_jump(self):
        condition = self.cond

        # It seems that the following guideline ensures progress:
        # _Generate a condition which is satisfied_.
        #
        # If the original condition is satisfied, keep it as is.
        # Otherwise, negate it to create a satisfied condition.
        if condition.is_sat(self.flags, self.ecx):
            pass
        else:
            condition = ~condition

        return "\n".join([
            "COND:bool = %s"%str(condition),
            self.line,
            "label pc_%s"%hex(get_first_hex(self.line)),
            'cjmp COND:bool, 0x0:u32, "blank"',
            "label blank"
        ])


def libraries_parseline(libraries, line):
    line = str.strip(line)
    if not line.startswith(SPECIAL_MODULE):
        return

    # Slice off the interesting part
    library, _, low, _, high = (
        line[len(SPECIAL_MODULE):-1].split(" "))

    # Remove quotes
    library = library[1:-1]

    # Add an entry for the library,
    # mapped to it's low and high addresses.
    # Parse the hex strings to retrieve the addresses.
    libraries[library] = int(low, 16), int(high, 16)


def parse_libraries(line_iterator):
    libraries = {}

    for line in line_iterator:
        line = str.strip(line)
        libraries_parseline(libraries, line)

    return libraries


def library_of_address(libraries, addr):
    for lib, (low, high) in libraries.items():
        if low <= addr <= high:
            return lib, addr - low
    return "unknown", addr


def normalizeTraceLine(l, libs):
    """
    Normalize the instruction address by finding corresponding module
    and offset in that module.
    """
    try:
        if l.startswith("cjmp"):
            m, addr = library_of_address(libs, int(l.split(',')[1].strip().split(':')[0], base=0))
            return "cjmp %s %s_%d" % (l.split()[1], m, addr)
        if l.startswith("label"):
            m, addr = library_of_address(libs, int(l.split()[1][3:], base=0))
            return "label %s_%d" % (m, addr)
        if l.startswith("jmp"):
            m, addr = library_of_address(libs, int(l.split()[1].split(':')[0], base=0))
            return "jmp %s_%d" % (m, addr)
    except ValueError:
        pass
    return l


def keep(line):
    if line.startswith("label pc_"):
        return True
    return False


def normalized_bbl_hashes(libraries, blocks):
    normalized_jumps = []
    ins_counts = []

    for block, _ in blocks:
        lines = []
        for line in filter(keep, map(str.strip, block.splitlines())):
            lines.append(normalizeTraceLine(line, libraries))

        normalized_jumps.append("\n".join(lines))
        ins_counts.append(len(lines))

    return list(map(adler32_hash, normalized_jumps)), list(ins_counts)


def adler32_hash(string):
    return adler32(string.encode("utf-8")) & 0xffffffff


def write_code(blocks, jump_number, file):
    """
    Writes the code for all `blocks` before the given `jump_number`
    to the given `file`.
    """
    # Avoid indexing negative blocks.
    if jump_number < 0:
        return

    for i, (code, _) in enumerate(blocks):
        file.write(code)
        file.write("\n")

        if i == jump_number:
            break

def write_altered_generator(blocks, jump_number, file):
    """
    Writes the code for all `blocks` before the given `jump_number`
    to the given `file`.
    """
    # Avoid indexing negative blocks.
    if jump_number < 0:
        return

    for i, (code, altered_jump) in enumerate(blocks):
        file.write(code)
        file.write("\n")

        if i == jump_number:
            file.write(altered_jump)
            break

def write_altered_jump(blocks, jump_number, file):
    """
    Given a list of `blocks`, writes the altered jump ending the
    `jump_number`:th block to `file`.
    """
    (_, altered_jump) = blocks[jump_number]
    file.write(altered_jump)

def create_cjmp_from_source_position(il_string, index_of_addr):
    """
    TODO: Docstring
    """
    end = il_string.find("\n", index_of_addr)

    target_string = il_string[index_of_addr:end]

    return create_cjmp_from_stack_write(target_string)


def create_cjmp_from_stack_write(line):
    """
    Given a line of IL performing a tainted stack write,
    returns a `cjmp` instruction which can be used to
    generate a crashing input.
    """
    # Split at: whitespace , parenthesis % $ "
    addr = re.split("[\s,\(\)%$\"]+", line)

    # addr: []string = [
    #    "addr", address, "@asm", mnemonic,
    #    val, offset, ebp/esp, reg,
    #    word_size?, "@tid", thread_id, empty_string
    # ]

    # Parse address hex string
    address = int(addr[1], 16)

    il = "R_ZF:bool = 4:u32 == ((R_{upper}:u32 << 2:u32) {sgn}:u32)\n" \
         'addr {addr} @asm "<instruction>" @tid "0"\n' \
         '  @context "R_EIP" = {addr}, 0, u32, rw\n' \
         '  @context "EFLAGS" = 0x246, -1, u32, rd\n' \
         "label rc_{addr}\n" \
         'cjmp R_ZF:bool, {addrplus1}:u32, "no_fix_jump"\n' \
         "label no_fix_jump\n".format(addr = hex(address), addrplus1=hex(address+1), sgn=sign(addr[5]), upper=addr[-5].upper())

    return il


def sign(num):
    """
    Returns a sign and a number.

    Ex:
        "-2" -> "- 2"
        "13" -> "+ 13"
    """
    if num[0] == "-":
        return "- " + num[1:]
    else:
        return "+ " + num
