/*
    Example program described in
    "Automated Whitebox Fuzz Testing" paper by
    Patrice Godefroid, Michael Y. Levin and David Molnar
*/
#include "../boilerplate.h"

// Cause segmentation fault
void fault() {
  int * ptr = NULL;
  *ptr = 1;
}

// The top function requires the input to
// have atleast length 4. Should be checked by main.
void top(const char input[4]) {
  int cnt = 0;

  if (input[0] == 'b') cnt++;
  if (input[1] == 'a') cnt++;
  if (input[2] == 'd') cnt++;
  if (input[3] == '!') cnt++;

  if (cnt >= 3) fault(); // error
}

MAIN(char, 4, top(input));
