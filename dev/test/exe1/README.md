EXE, example 1
===============

The paper detailing EXE, described a very simple example program.
This function is implemented in `program.c` with the initial input
in `initial.in`. Compile and test with `make`.

As of 2015-03-16, `OpenSAW` can detect the arithmetic error, but it
cannot generate an input to cause it.

```c
#include <assert.h>

int main(void) {
  unsigned i, t, a[4] = { 1, 3, 5, 2 };

  make_symbolic(&i);

  if (i >= 4) exit(0);

  // cast + symbolic offset + symbolic mutation
  char *p = (char *)a + i * 4;
  *p = *p - 1; // Just modifies one byte!

  // ERROR: potential overflow i = 2
  t = a[*p];
  // At this point i != 2

  // ERROR: division by 0 when i = 0
  t = t / a[i];
  // At this point i != 0 && i != 2

  // neither assert fires
  if (t == 2)
    assert(i == 1);
  else
    assert(i == 3);
}
```
