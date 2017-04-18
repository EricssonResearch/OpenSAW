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
from opensaw.concolic.pinbap.il import (
    find_bbls_and_normalized_hashes,
    get_first_hex,
    keep,
    library_of_address,
    parse_libraries,
    write_altered_jump,
    write_code,
    iterate_lines,
    find_jumps
)

# A few dummy libraries and some lines extracted from an execution.
il_string = """
special \"Loaded module 'libpy' from 0x0000 to 0xffff\"
not special

and something else
special \"Loaded module 'liberic' from 0x60000 to 0x64000\"

addr 0x80485b1 @asm "je     0x00000000080485b8" @tid "0"
  @context "R_EIP" = 0x80485b1, 0, u32, rw
  @context "EFLAGS" = 0x246, 5, u32, rd
label pc_0x80485b1
cjmp R_ZF:bool, 0x80485b8:u32, "nocjmp9"
label nocjmp9

addr 0x5a225fb6 @asm "add    $0x17303e,%ebx" @tid "0"
  @context "R_EBX" = 0x5a225fb6, 0, u32, rw
  @context "EFLAGS" = 0x246, 5, u32, wr
label pc_0x5a225fb6
T_t1_93:u32 = R_EBX:u32
T_t2_94:u32 = 0x17303e:u32
R_EBX:u32 = R_EBX:u32 + T_t2_94:u32
R_CF:bool = R_EBX:u32 < T_t1_93:u32
R_OF:bool =
  high:bool((T_t1_93:u32 ^ ~T_t2_94:u32) & (T_t1_93:u32 ^ R_EBX:u32))
R_AF:bool = 0x10:u32 == (0x10:u32 & (R_EBX:u32 ^ T_t1_93:u32 ^ T_t2_94:u32))
R_PF:bool =
  ~low:bool(R_EBX:u32 >> 7:u32 ^ R_EBX:u32 >> 6:u32 ^ R_EBX:u32 >> 5:u32 ^
            R_EBX:u32 >> 4:u32 ^ R_EBX:u32 >> 3:u32 ^ R_EBX:u32 >> 2:u32 ^
            R_EBX:u32 >> 1:u32 ^ R_EBX:u32)
R_SF:bool = high:bool(R_EBX:u32)
R_ZF:bool = 0:u32 == R_EBX:u32

addr 0x8048609 @asm "jecxz  0x000000000804860d" @tid "0"
  @context "R_ECX" = 0xfffffffe, -1, u32, rd
  @context "R_EIP" = 0x8048609, 0, u32, rw
label pc_0x8048609
cjmp R_ECX:u32 == 0:u32, 0x804860d:u32, "nocjmp7"
label nocjmp7

addr 0x804860d @asm "some instruction...
"""


def test_parse_libraries(tmpdir):
    tmpdir.chdir()
    ilfile = tmpdir.join("ilfile")
    ilfile.write(il_string)
    libs = parse_libraries(iterate_lines("ilfile"))

    assert libs == {
        "libpy":  (0x0000, 0xffff),
        "liberic": (0x60000, 0x64000)
    }

    assert ("libpy", 0x55) == library_of_address(libs, 0x55)

    assert ("unknown", 0x64126) == library_of_address(libs, 0x64126)

    assert ("liberic", 0x126) == library_of_address(libs, 0x60126)


def test_keep():
    removed_all = any(map(keep, [
        "/* a comment */",
        "special something",
        "@context of an instruction",
        "label nocjmp # shouldn't be kept"
        "anything else",
        "R_EAX:u32 = R_EAX:u32 + 0x5:u32",
        "addr to something",
    ]))
    assert not removed_all
    kept_all = all(map(keep, [
        "label pc_asdi"
    ]))
    assert kept_all


def test_find_bbls_and_normalized_hashes(tmpdir):
    tmpdir.chdir()
    ilfile = tmpdir.join("ilfile")
    ilfile.write(il_string)
    hashes, counts, libs = find_bbls_and_normalized_hashes("ilfile")
    jumps = find_jumps("ilfile")
    assert len(jumps) is 3
    assert len(hashes) is 3
    assert len(counts) is 3
    assert libs == {
        "libpy": (0x0000, 0xffff),
        "liberic": (0x60000, 0x64000)
    }


class FakeFile(object):
    def __init__(self):
        self.data = []

    def write(self, data):
        self.data.append(data)


def test_write_code_and_altered_jumps():
    file = FakeFile()

    jumps = [("code1", "jump1"), ("code2", "jump2"), ("code3", None)]

    write_code(jumps, -1, file)
    assert file.data == []

    write_code(jumps, 1, file)
    write_altered_jump(jumps, 1, file)
    assert file.data == ["code1", "\n", "code2", "\n", "jump2"]

    file = FakeFile()

    # Corner-case: Out of index write results in all code.
    # Shouldn't happen during actual run.
    write_code(jumps, 3, file)
    assert file.data == ["code1", "\n", "code2", "\n", "code3", "\n"]


def test_first_hex():
    assert get_first_hex("aef 0xg saf3 0x53 0x152") is 0x53

    # Defaults to 0.
    assert get_first_hex("") is 0x0
