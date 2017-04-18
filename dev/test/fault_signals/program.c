/*
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
*/
#include "../boilerplate.h"

void faults(char input) {
  if (input == 'a') { // abort
    abort();
  }

  if (input == 'b') { // bus error
    // Enable alignment checking on x86
    __asm__("pushf\norl $0x40000,(%esp)\npopf");

    short *sptr;
    int    i;

    sptr = (short *)&i;
    // For all odd value increments, it will result in sigbus.
    sptr = (short *)(((char *)sptr) + 1);
    *sptr = 100;

  }

  if (input == 'd') { // division
    input /= 0;
  }

  if (input == 's') { // segfault
    *(int *)0 = 1;
  }

}

MAIN(char, 1, faults(input[0]))
