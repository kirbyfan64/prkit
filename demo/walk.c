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

  cleanup(freep) char *kcmdline = NULL;
  r = prkit_kernel_cmdline(procfd, &kcmdline, NULL);
  if (r < 0) {
    return print_error(r, "prkit_kernel_cmdline");
  }

  printf("Kernel cmdline: %s\n", kcmdline);

  struct prkit_kernel_stat kstat;
  r = prkit_kernel_stat(procfd, &kstat);
  if (r < 0) {
    return print_error(r, "prkit_kernel_stat");
  }

  printf("Kernel fields: %d\n", kstat.fields);
  if (kstat.fields & PRKIT_KERNEL_STAT_CTXT) {
    printf("- ctxt: %lu\n", kstat.ctxt);
  }
  if (kstat.fields & PRKIT_KERNEL_STAT_BTIME) {
    printf("- btime: %lu\n", kstat.btime);
  }
  if (kstat.fields & PRKIT_KERNEL_STAT_PROCESSES) {
    printf("- processes: %lu\n", kstat.processes);
  }
  if (kstat.fields & PRKIT_KERNEL_STAT_PROCS_RUNNING) {
    printf("- procs_running: %lu\n", kstat.procs_running);
  }
  if (kstat.fields & PRKIT_KERNEL_STAT_PROCS_BLOCKED) {
    printf("- procs_running: %lu\n", kstat.procs_blocked);
  }

  puts("Open processes:");
  r = prkit_walk_reset(procfd);
  if (r < 0) {
    return print_error(r, "prkit_walk_reset");
  }

  cleanup(freep) int *pids = NULL;
  size_t npids = 0;
  r = prkit_walk_read_all(procfd, &pids, &npids);
  if (r < 0) {
    return print_error(r, "prkit_walk_read_all");
  }

  for (int i = 0; i < npids; i++) {
    int pid = pids[i];
    printf("- %d:\n", pid);

    cleanup(closep) int pidfd = -1;
    r = prkit_pid_open(procfd, pid, &pidfd);
    if (r < 0) {
      print_error(r, "  prkit_pid_open(%d)", pid);
      continue;
    }

    cleanup(prkit_free_strvp) char **cmdline = NULL;
    r = prkit_pid_cmdline_strv(pidfd, &cmdline);
    if (r < 0) {
      print_error(r, "  prkit_pid_cmdline(%d)", pid);
      continue;
    }

    puts("  - cmdline:");
    for (char **p = cmdline; *p; p++) {
      printf("    - %s\n", *p);
    }

    cleanup(prkit_free_strvp) char **environ = NULL;
    r = prkit_pid_environ_strv(pidfd, &environ);
    if (r < 0) {
      print_error(r, "  prkit_pid_environ(%d)", pid);
      continue;
    }

    puts("  - environ:");
    for (char **p = environ; *p; p++) {
      printf("    - %s\n", *p);
    }

    cleanup(freep) char *cwd = NULL;
    r = prkit_pid_resolve_cwd(pidfd, &cwd, NULL);
    if (r < 0) {
      print_error(r, "  prkit_pid_resolve_cwd(%d)", pid);
      continue;
    }

    printf("  - cwd: %s\n", cwd);

    cleanup(freep) char *exe = NULL;
    r = prkit_pid_resolve_exe(pidfd, &exe, NULL);
    if (r < 0) {
      print_error(r, "  prkit_pid_resolve_exe(%d)", pid);
      continue;
    }

    printf("  - exe: %s\n", exe);

    struct prkit_pid_stat pstat;
    r = prkit_pid_stat(pidfd, &pstat);
    if (r < 0) {
      print_error(r, "  prkit_pid_stat(%d)", pid);
      continue;
    }

    printf("  - stat:\n");
    printf("    comm: %s\n", pstat.comm);
    printf("    state: %c\n", (char)pstat.state);
    printf("    num_threads: %u\n", pstat.num_threads);
    printf("    starttime: %llu\n", pstat.starttime);

    char buf[64];
    time_t time = prkit_pid_actual_start_time(&kstat, &pstat);
    strftime(buf, sizeof(buf), "%F %T", localtime(&time));
    printf("  - actual start time: %ld (%s)\n", time, buf);
  }

  return 0;
}


int main() {
  return run() < 0 ? 1 : 0;
}
