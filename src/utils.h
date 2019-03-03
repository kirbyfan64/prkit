/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Used by prkit.c + the demos
#pragma once

#include <stdlib.h>


#define cleanup(func) __attribute__((__cleanup__(func)))


void *stealp(void *p) {
  void **pp = p;
  void *x = *pp;
  *pp = NULL;
  return x;
}


int steali(int *i) {
  int x = *i;
  *i = -1;
  return x;
}


void freep(void *p) {
  void **pp = p;
  if (*pp) {
    free(stealp(pp));
  }
}


void closep(int *fd) {
  if (*fd != -1) {
    close(steali(fd));
  }
}
