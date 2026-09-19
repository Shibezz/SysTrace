#ifndef SYSTRACE_H
#define SYSTRACE_H

#include <stdio.h>
#include <sys/types.h>

#define MAX_SYSCALL_NR 512
#define MAX_ARGS 6
#define MAX_FILTERS 32
#define MAX_LINE 2048

/* Everything the user asked for on the command line. */
struct options {
	char **child_argv;             /* program to run and its arguments */
	const char *only[MAX_FILTERS]; /* -e, trace only these names */
	int nonly;
	const char *skip[MAX_FILTERS]; /* -x, never trace these names */
	int nskip;
	int summary_only;              /* -c */
	int str_limit;                 /* -s, how many bytes of a string to show */
	FILE *out;
};

/* One syscall, filled in at the entry stop and completed at the exit stop. */
struct syscall_ev {
	long nr;
	long args[MAX_ARGS];
	long ret;
	long usec;   /* time spent between the two stops */
	int no_ret;  /* set for exit and exit_group, which never come back */
	char text[MAX_LINE];  /* the decoded "name(args)" part */
};

/* ptrace_handler.c */
int run_tracer(struct options *opt);

/* syscall_decoder.c */
const char *syscall_name(long nr);
int syscall_allowed(const struct options *opt, long nr);
int decode_at_exit(long nr);
void decode_syscall(pid_t pid, struct syscall_ev *ev, const struct options *opt);

/* reporter.c */
void report_line(const struct options *opt, const struct syscall_ev *ev);
void report_signal(const struct options *opt, int sig);
void report_exit(const struct options *opt, int status);
void stats_add(const struct syscall_ev *ev);
void report_summary(const struct options *opt);

#endif
