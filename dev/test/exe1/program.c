#include "../boilerplate.h"

#include <assert.h>

void top(unsigned i) {
  unsigned t, a[4] = { 1, 3, 5, 2 };

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

MAIN(char, 4, top(atoi(input)));
