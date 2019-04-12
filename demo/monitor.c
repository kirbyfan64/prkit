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

  cleanup(closep) int procfd = -1;
  r = prkit_open(&procfd);
  if (r < 0) {
    return print_error(r, "prkit_open");
  }

  cleanup(closep) int nlfd = -1;
  r = prkit_monitor_open(&nlfd);
  if (r < 0) {
    return print_error(r, "prkit_monitor_open");
  }

  struct proc_event event;

  for (;;) {
    bzero(&event, sizeof(event));

    r = prkit_monitor_read_event(nlfd, &event);
    if (r < 0) {
      return print_error(r, "prkit_monitor_read_event");
    }

    if (event.what & PROC_EVENT_FORK) {
      cleanup(closep) int parent_pid = event.event_data.fork.parent_pid;
      cleanup(closep) int child_pid = event.event_data.fork.child_pid;

      int pids[] = {parent_pid, child_pid};
      char pid_comms[2][PRKIT_COMM_LENGTH];

      for (int i = 0; i < sizeof(pids) / sizeof(pids[0]); i++) {
        int pid = pids[i];
        const char *desc = i == 0 ? "parent" : "child";

        cleanup(closep) int pidfd = -1;
        r = prkit_pid_open(procfd, pid, &pidfd);
        if (r < 0) {
          print_error(r, "prkit_pid_open(%s %d)", desc, pid);
          continue;
        }

        struct prkit_pid_stat pstat;
        r = prkit_pid_stat(pidfd, &pstat);
        if (r < 0) {
          print_error(r, "prkit_pid_stat(%s %d)", desc, pid);
          continue;
        }

        memcpy(pid_comms[i], pstat.comm, PRKIT_COMM_LENGTH);
      }

      printf("%d forked to %d (parent comm = %s, child comm = %s)\n", parent_pid,
             child_pid, pid_comms[0], pid_comms[1]);
    }

    if (event.what & PROC_EVENT_EXEC) {
      int pid = event.event_data.exec.process_pid;

      int pidfd = -1;
      r = prkit_pid_open(procfd, pid, &pidfd);
      if (r < 0) {
        print_error(r, "prkit_pid_open(exec %d)", pid);
        continue;
      }

      struct prkit_pid_stat pstat;
      r = prkit_pid_stat(pidfd, &pstat);
      if (r < 0) {
        print_error(r, "prkit_pid_stat(exec %d)", pid);
        continue;
      }

      printf("%d was started (comm = %s)\n", pid, pstat.comm);
    }

    if (event.what & PROC_EVENT_EXIT) {
      int pid = event.event_data.exit.process_pid;

      printf("%d died\n", pid);
    }
  }
}


int main() {
  return run() < 0 ? 1 : 0;
}

