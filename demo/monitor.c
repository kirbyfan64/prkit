/* Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */

#include "../src/prkit.h"
#include "../src/utils.h"

#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define print_error(r, ...) ({ \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, ": %s\n", strerror(-(r))); \
    (r); \
  })


int run() {
  int r;

  cleanup(closep) int procfd = prkit_open();
  if (procfd < 0) {
    return print_error(procfd, "prkit_open");
  }

  cleanup(closep) int nlfd = prkit_monitor_open();
  if (nlfd < 0) {
    return print_error(nlfd, "prkit_monitor_open");
  }

  struct proc_event event;

  for (;;) {
    r = prkit_monitor_read_event(nlfd, &event);
    if (r < 0) {
      return print_error(nlfd, "prkit_monitor_read_event");
    }

    if (event.what == PROC_EVENT_EXEC) {
      int pid = event.event_data.exec.process_pid;

      int pidfd = prkit_pid_open(procfd, pid);
      if (pidfd < 0) {
        print_error(pidfd, "prkit_pid_open(%d)", pid);
        continue;
      }

      struct prkit_pid_stat pstat;
      r = prkit_pid_stat(pidfd, &pstat);
      if (r < 0) {
        print_error(r, "prkit_pid_stat(%d)", pid);
        continue;
      }

      printf("%d was started (comm = %s)\n", pid, pstat.comm);
    } else if (event.what == PROC_EVENT_EXIT) {
      int pid = event.event_data.exit.process_pid;

      printf("%d died\n", pid);
    }
  }
}


int main() {
  return run() < 0 ? 1 : 0;
}

