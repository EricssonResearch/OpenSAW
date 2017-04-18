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
Testing
=======

## Getting started
Enter the directory of the program you want to test, and type `make`.
It will compile the program and run the OpenSAW framework, terminating
once all paths have been executed.

### Directories

Each directory contains files and instructions to test
a few simple test programs.

File        | Description
----------- | -----------
program.c   | The source code for the test program
initial.in  | The initial input for the program
makefile    | A testing aid, to avoid having to fiddle with the command line.

The file `test/boilerplate.h` is used by the tests
to implement the main function, which is pretty much
identical for all tests.

### The Process
Below, the process for testing programs is briefly described.

#### Record a trace
The program is executed using
[PIN](https://software.intel.com/en-us/articles/pintool),
with an initial input. This results in the generation of a binary
trace file `out.btp-<number>`, and a code coverage file
`visited_blocks.cov`.

```
$ pin \
    -injection child
    -t ../pintraces/obj-ia32/gentrace.so \
    -taint-files initial.in \
    -- ./program.out initial.in
```

#### Transform to an AST
The next step, is to transform the trace into the BAP IL. The IL
can be manipulated directly, or transformed into a trace formula
(CVC Lite or SMT2 format) and changed at that level.

```
$ iltrans -serializedtrace out.bpt-<pid> -pp-ast trace.il
```

#### Find and changing jump instructions
For example, the IL:
```bil
@context "EFLAGS" = 0x206, 1, u32, rd
```

specifies `EFLAGS = 0x206`, which means that the following set of
flags are set. To change which path is taken at a x86 `je` instruction
which depends on `ZF`, the `EFLAGS` context variable can be changed
to `0x246`. Looking at the table below, we see that the `ZF` flag
is changed.

change | EFLAGS | `...` | SF | ZF |  * | AF |  * | PF |  * | CF
------ | ------ | ----- | -- | -- | -- | -- | -- | -- | -- | --
from   | 0x206  | `...` |  0 |  0 |  0 |  0 |  0 |  1 |  1 |  0
to     | 0x246  | `...` |  0 |  1 |  0 |  0 |  0 |  1 |  1 |  0

<sup>* : Reserved</sup>

The example below will find the 1000th jump instruction in `trace.il`
truncate it and change the corresponding eflags. In this
example there are not 1000 jump instructions so the eflags will
not be changed. To truncate and change flags at first jump
call with 1 instead of 1000.

```
$ python truncate_il_trace.py 1000 trace.il new_trace.il
```

#### The Verification Condition
A verification condition for the current path can be created
in various formats. Most relevant are the CVC Lite and SMTLIB2
formats. The CVC Lite format is the default.

Unfortunately, it isn't possible to specify the format directly.
BAP selects it depending on the name of the SMT solver, for instance
Z3.
```
$ iltrans -il new_trace.il -trace-formula formula.cvc
$ iltrans -il new_trace.il -trace-solver z3 -trace-formula formula.smt2
```

Here STP is used to solve the formula in CVC Lite format.
```
$ stp formula.cvc
ASSERT( symb_3_93 = 0x00 );
ASSERT( symb_4_94 = 0x00 );
ASSERT( symb_1_91 = 0x0D );
ASSERT( symb_2_92 = 0x00 );
Invalid.
```

Z3 is used to solve it in SMTLIB2 format.
```
$ z3 formula.smt2
sat
(model
  (define-fun symb_1_91 () (_ BitVec 8)
    #x0d)
  (define-fun symb_3_93 () (_ BitVec 8)
    #x00)
  (define-fun symb_2_92 () (_ BitVec 8)
    #x00)
  (define-fun symb_4_94 () (_ BitVec 8)
    #x00)
)
```
