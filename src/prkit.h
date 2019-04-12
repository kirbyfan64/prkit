/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include <sys/types.h>

#include <unistd.h>


typedef unsigned long prkit_ulong;
typedef unsigned long long prkit_ullong;


#define PRKIT_COMM_LENGTH 16


typedef enum prkit_kernel_stat_fields {
  PRKIT_KERNEL_STAT_CTXT = 1 << 0,
  PRKIT_KERNEL_STAT_BTIME = 1 << 1,
  PRKIT_KERNEL_STAT_PROCESSES = 1 << 2,
  PRKIT_KERNEL_STAT_PROCS_RUNNING = 1 << 3,
  PRKIT_KERNEL_STAT_PROCS_BLOCKED = 1 << 4,
} prkit_kernel_stat_fields;


struct prkit_kernel_stat {
  prkit_kernel_stat_fields fields;

  prkit_ulong ctxt;
  prkit_ulong btime;
  prkit_ulong processes;
  prkit_ulong procs_running;
  prkit_ulong procs_blocked;
};


typedef enum prkit_state {
  PRKIT_STATE_RUNNING = 'R',
  PRKIT_STATE_SLEEPING = 'S',
  PRKIT_STATE_DISK = 'D',
  PRKIT_STATE_ZOMBIE = 'Z',
  PRKIT_STATE_STOPPED = 'T',
  PRKIT_STATE_TRACING = 't',
  PRKIT_STATE_DEAD = 'X',
} prkit_state;


struct prkit_pid_stat {
  int pid;
  char comm[PRKIT_COMM_LENGTH];
  prkit_state state;
  int ppid;
  int pgrp;
  int session;
  int tty_nr;
  int tpgid;
  unsigned flags;
  prkit_ulong minflt;
  prkit_ulong cminflt;
  prkit_ulong majflt;
  prkit_ulong cmajflt;
  prkit_ulong utime;
  prkit_ulong stime;
  unsigned cutime;
  unsigned cstime;
  unsigned priority;
  unsigned nice;
  unsigned num_threads;
  unsigned itrealvalue;
  prkit_ullong starttime;
  prkit_ulong vsize;
  prkit_ulong rss;
  prkit_ulong rsslim;
  prkit_ulong pt_startcode;
  prkit_ulong pt_endcode;
  prkit_ulong pt_startstack;
  prkit_ulong pt_kstkesp;
  prkit_ulong pt_kstkeip;
  prkit_ulong obsolete[4];
  prkit_ulong pt_wchan;
  prkit_ulong nswap;
  prkit_ulong cnswap;
  int exit_signal;
  int processor;
  unsigned rt_priority;
  unsigned policy;
  prkit_ullong delayacct_blkio_ticks;
  prkit_ulong guest_time;
  unsigned cguest_time;
  prkit_ulong pt_start_data;
  prkit_ulong pt_end_data;
  prkit_ulong pt_start_brk;
  prkit_ulong pt_arg_start;
  prkit_ulong pt_arg_end;
  prkit_ulong pt_env_start;
  prkit_ulong pt_env_end;
  int pt_exit_code;
};

void prkit_free_strv(char **strv);
void prkit_free_strvp(char ***strv);

int prkit_open(int *out_fd);

int prkit_kernel_cmdline(int procfd, char **out_cmdline, size_t *out_len);
int prkit_kernel_stat(int procfd, struct prkit_kernel_stat *out_kstat);

int prkit_walk_reset(int procfd);
int prkit_walk_read(int procfd, int *out_pids, size_t *out_count);
int prkit_walk_read_all(int procfd, int **out_pidsv, size_t *out_count);

int prkit_pid_open(int procfd, int pid, int *out_pidfd);

int prkit_pid_cmdline(int pidfd, char **out_cmdline, size_t *out_len);
int prkit_pid_cmdline_strv(int pidfd, char ***out_cmdline_strv);
int prkit_pid_environ(int pidfd, char **out_environ, size_t *out_len);
int prkit_pid_environ_strv(int pidfd, char ***out_environ_strv);

int prkit_pid_resolve_cwd(int pidfd, char **out_cwd, size_t *out_len);
int prkit_pid_resolve_exe(int pidfd, char **out_exe, size_t *out_len);

int prkit_pid_stat_using_buf(int pidfd, struct prkit_pid_stat *out_pstat, char **out_buf,
                             size_t *out_len);
int prkit_pid_stat(int pidfd, struct prkit_pid_stat *out_pstat);

prkit_ulong prkit_pid_actual_start_time(const struct prkit_kernel_stat *kstat,
                                        const struct prkit_pid_stat *pstat);

#define PRKIT_PID_ACTUAL_START_TIME(kstat, pstat) \
  ((kstat)->btime + (pstat)->starttime / sysconf(_SC_CLK_TCK))
#define prkit_pid_actual_start_time PRKIT_PID_ACTUAL_START_TIME

int prkit_monitor_open();
int prkit_monitor_read_event(int nlfd, struct proc_event *out_event);
