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
.text

.globl top
# fn top(a, b: int) -> ()
top:
  push    %ebp
  mov     %esp, %ebp
  sub     $0x18, %esp

  mov     0x8(%ebp), %eax
  mov     0xc(%ebp), %ecx
  cmp     %ecx, %eax
  jg      die             # test jump-if-greater (signed)

  ja      die             # test jump-if-above (unsigned)

  # Make the below test succeed if `b` == 2
  sub     $2, %ecx
  jecxz   die             # test jump-ecx-zero

  leave
  ret

die:
  call    abort
# end top
