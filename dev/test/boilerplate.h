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
#include <stdio.h>
#include <stdlib.h>

/*
  Defines a boilerplate main function.
  Given a type and a number, it will read that many
  types from a file, and then call invocation.
  The read input array can be accessed as `input`.
*/
#define MAIN(type, number, invocation) \
int main(int argc, char const *argv[]) { \
\
  if (argc != 2) { \
    printf("usage: program input\n"); \
    return 1; \
  } \
\
  FILE *file = fopen(argv[1], "r"); \
\
  if (file == NULL) { \
    perror("fopen"); \
    abort(); \
  } \
\
  type input[number]; \
  size_t count = fread(input, sizeof(type), number, file); \
\
  fclose(file); \
\
  if (count < number) { \
    printf("Required %d of " #type ", only read %d.\n", \
      number, count); \
    perror("fread"); \
    abort(); \
  } \
\
  invocation; \
\
  return 0; \
}
