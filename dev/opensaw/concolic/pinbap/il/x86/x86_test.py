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
from opensaw.concolic.pinbap.il.x86.conditionals import Bit
from opensaw.concolic.pinbap.il.x86.cjumps import cjumps, ZF, OF, SF, ECX

# Add a Right-Add function to test additions.
Bit.__radd__ = lambda self, other: self.bit + other


def test_Bits_and_ECX():
    assert ~~ZF is ZF

    assert 0 + ZF == 0x40

    assert ZF.is_sat(0x40, 0x0)
    assert not ZF.is_sat(0x0, 0x0)

    assert not (~ZF).is_sat(0x40, 0x0)
    assert (~ZF).is_sat(0x0, 0x0)

    # ECX not satified by FLAGS register value.
    # Second argument `ECX` register value, must be 0.
    assert not ECX.is_sat(0x0, 0x4)
    assert ECX.is_sat(0x0, 0x0)


def test_cjumps():
    # The Jump-if-equal instruction depends on the Zero-flag
    # exclusively.
    assert ZF is cjumps['je']

    assert 0 + SF + OF == 0x880

    # Condition: SF == OF
    assert cjumps['jge'].is_sat(0x0, 0x0)
    assert cjumps['jge'].is_sat(0x880, 0x0)
    assert not cjumps['jge'].is_sat(0x800, 0x0)
    assert not cjumps['jge'].is_sat(0x80, 0x0)


def test_strs():
    assert str(cjumps["ja"]) == "~(R_CF:bool | R_ZF:bool)"
    assert str(cjumps["jle"]) == "(R_ZF:bool | (R_SF:bool ^ R_OF:bool))"
    assert str(cjumps["jg"]) == "~(R_ZF:bool | (R_SF:bool ^ R_OF:bool))"
    assert str(cjumps["jge"]) == "(R_SF:bool == R_OF:bool)"

    assert str(ECX) == "(R_ECX:u32 == 0:u32)"
    assert str(~ECX) == "~(R_ECX:u32 == 0:u32)"

    assert str(ZF & OF) == "(R_ZF:bool & R_OF:bool)"
    assert str(~ZF & (SF | OF)) == "(~R_ZF:bool & (R_SF:bool | R_OF:bool))"
