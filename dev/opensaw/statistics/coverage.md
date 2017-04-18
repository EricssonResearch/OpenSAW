<!---
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
--->
Block- and Branch Coverage
==========================

The code coverage is calculated when the PinTool
`gentrace.so` is executed. It generates a file with
the following format:

    file := entries?

    entries := entry ("," entries)?

    entry := <address of last basic block instruction> ":" <visit enum>

Where the `<visit enum>` has one of the following values. The enum is
structured so that values can be set using a bitwise or, like so: `blocks[address] |= visit_type`.

  name              | value | description
  ------------------|-------|----
  NON_CONDITIONAL   |  0    | The non-conditional instruction is not yet visited.
  THEN_BRANCH       |  1    | The conditional then-branch has been taken.
  ELSE_BRANCH       |  2    | The conditional else-branch has been taken.
  BOTH_BRANCHES     |  3    | Both conditional branches have been taken/or fallthrough taken.
  CONDITIONAL       |  4    | The instruction is a conditional jump.

So in order to encode a conditional else-branch having been taken
we bitwise-or `CONDITIONAL | ELSE_BRANCH = 1 | 4 = 5`. In practice,
this means that 1's and 2's are never encountered in a coverage file,
since in the case of a fallthrough the number 3 should be used.

    984:3,1004:5,1006:0,1011:3,1016:3,1025:7,1046:3,1072:3

In the small example above, we can note that:

  * most entries are visited fallthroughs (3)
  * one block hasn't yet been visited (0)
  * one true branch has been taken (5)
  * in one case has both branches been taken (7)
