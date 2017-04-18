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
from opensaw.concolic.pinbap.il.x86.conditionals import Bit, Condition


# Bits
# ----
# Variables corresponding to different bits of the x86 FLAGS register,
# in addition to the `%ecx` singleton.
CF = Bit("R_CF:bool", 0)
PF = Bit("R_PF:bool", 2)
ZF = Bit("R_ZF:bool", 6)
SF = Bit("R_SF:bool", 7)
OF = Bit("R_OF:bool", 11)


# Conveniently construct a singleton class.
def singleton(cls): return cls()


@singleton
class ECX(Condition):
    """
    A Singleton class representing the IL Condition when
    the x86 `R_ECX:u32` register is zero.
    """
    def __str__(self): return "(R_ECX:u32 == 0:u32)"

    def is_sat(self, flags, ecx): return ecx == 0


# Conditional Jumps
# -----------------
# Conditional jump instructions and their conditions.
cjumps = dict()

# Jump-if-overflow
cjumps["jo"]    = OF
cjumps["jno"]   = ~OF

# Jump-if-sign
cjumps["js"]    = SF
cjumps["jns"]   = ~SF

# Jump-if-zero
cjumps["je"]    = cjumps["jz"]    = ZF
cjumps["jne"]   = cjumps["jnz"]   = ~ZF

# Jump-if-below (unsigned)
cjumps["jc"]    = cjumps["jb"]    = cjumps["jnae"]  = CF
cjumps["jnc"]   = cjumps["jnb"]   = cjumps["jae"]   = ~CF

# Jump-if-above (unsigned)
cjumps["ja"]    = cjumps["jnbe"]  = ~CF & ~ZF
cjumps["jbe"]   = cjumps["jna"]   = CF | ZF

# Jump-if-less (signed)
cjumps["jl"]    = cjumps["jnge"]  = SF != OF
cjumps["jge"]   = cjumps["jnl"]   = SF == OF

# Jump-if-greater (signed)
cjumps["jg"]    = cjumps["jnle"]  = ~ZF & (SF == OF)
cjumps["jng"]   = cjumps["jle"]   = ZF | (SF != OF)

# Jump-if-parity
cjumps["jp"]    = cjumps["jpe"]   = PF
cjumps["jnp"]   = cjumps["jpo"]   = ~PF

# Jump-if-cx-zero
cjumps["jcxz"]  = cjumps["jecxz"] = ECX

# TODO: Investigate `LOOP` and `LOOPcc` instructions.
# Implementation should be something like this.
#
#    # Loop-if-cx-not-zero
#    cjumps["loop"]   = ~ECX
#
#    # Loop-if-cx-not-zero and X
#    cjumps["loope"]  = cjumps["loopz"]  = ~ECX & ZF
#    cjumps["loopne"] = cjumps["loopnz"] = ~ECX & ~ZF

# TODO: Investigate `CMOVcc` instructions.
# They are conditional operations which affect
# register assignments and hence work like branches.
