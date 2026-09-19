/* Prints trace lines and keeps the per syscall counters. */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "systrace.h"

#define MAX_ERRNO 134

/* strerror gives the message, but the short name has to come from here. */
static const char *const errnames[MAX_ERRNO] = {
	[EPERM] = "EPERM", [ENOENT] = "ENOENT", [ESRCH] = "ESRCH",
	[EINTR] = "EINTR", [EIO] = "EIO", [ENXIO] = "ENXIO",
	[E2BIG] = "E2BIG", [ENOEXEC] = "ENOEXEC", [EBADF] = "EBADF",
	[ECHILD] = "ECHILD", [EAGAIN] = "EAGAIN", [ENOMEM] = "ENOMEM",
	[EACCES] = "EACCES", [EFAULT] = "EFAULT", [EBUSY] = "EBUSY",
	[EEXIST] = "EEXIST", [EXDEV] = "EXDEV", [ENODEV] = "ENODEV",
	[ENOTDIR] = "ENOTDIR", [EISDIR] = "EISDIR", [EINVAL] = "EINVAL",
	[ENFILE] = "ENFILE", [EMFILE] = "EMFILE", [ENOTTY] = "ENOTTY",
	[ETXTBSY] = "ETXTBSY", [EFBIG] = "EFBIG", [ENOSPC] = "ENOSPC",
	[ESPIPE] = "ESPIPE", [EROFS] = "EROFS", [EMLINK] = "EMLINK",
	[EPIPE] = "EPIPE", [EDOM] = "EDOM", [ERANGE] = "ERANGE",
	[EDEADLK] = "EDEADLK", [ENAMETOOLONG] = "ENAMETOOLONG",
	[ENOLCK] = "ENOLCK", [ENOSYS] = "ENOSYS", [ENOTEMPTY] = "ENOTEMPTY",
	[ELOOP] = "ELOOP", [ENODATA] = "ENODATA", [EPROTO] = "EPROTO",
	[EOVERFLOW] = "EOVERFLOW", [EBADFD] = "EBADFD",
	[ENOTSOCK] = "ENOTSOCK", [EOPNOTSUPP] = "EOPNOTSUPP",
	[EADDRINUSE] = "EADDRINUSE", [ECONNRESET] = "ECONNRESET",
	[ECONNREFUSED] = "ECONNREFUSED", [EINPROGRESS] = "EINPROGRESS",
	[ETIMEDOUT] = "ETIMEDOUT",
};

struct stat_row {
	unsigned long calls;
	unsigned long errors;
	long usec;
};

static struct stat_row stats[MAX_SYSCALL_NR];
static long total_usec;

/* A negative return between -1 and -4095 is really a negated errno. */
static int error_of(long ret)
{
	if (ret < 0 && ret > -4096)
		return (int)-ret;
	return 0;
}

void stats_add(const struct syscall_ev *ev)
{
	if (ev->nr < 0 || ev->nr >= MAX_SYSCALL_NR)
		return;
	stats[ev->nr].calls++;
	stats[ev->nr].usec += ev->usec;
	total_usec += ev->usec;
	if (error_of(ev->ret))
		stats[ev->nr].errors++;
}

void report_line(const struct options *opt, const struct syscall_ev *ev)
{
	int err;

	if (opt->summary_only)
		return;

	fputs(ev->text, opt->out);

	if (ev->no_ret) {
		fprintf(opt->out, " = ?\n");
		return;
	}
	err = error_of(ev->ret);
	if (err) {
		const char *name = err < MAX_ERRNO ? errnames[err] : NULL;

		fprintf(opt->out, " = -1 %s (%s)\n", name ? name : "errno",
		        strerror(err));
	} else if (ev->nr == SYS_mmap || ev->nr == SYS_brk) {
		/* mmap and brk give back addresses, hex reads better. */
		fprintf(opt->out, " = 0x%lx\n", ev->ret);
	} else {
		fprintf(opt->out, " = %ld\n", ev->ret);
	}
}

void report_signal(const struct options *opt, int sig)
{
	if (!opt->summary_only)
		fprintf(opt->out, "--- signal %d (%s) ---\n", sig, strsignal(sig));
}

void report_exit(const struct options *opt, int status)
{
	if (opt->summary_only)
		return;
	if (WIFEXITED(status))
		fprintf(opt->out, "+++ exited with %d +++\n", WEXITSTATUS(status));
	else
		fprintf(opt->out, "+++ killed by signal %d +++\n", WTERMSIG(status));
}

static int by_time(const void *a, const void *b)
{
	long ta = stats[*(const int *)a].usec;
	long tb = stats[*(const int *)b].usec;

	if (ta != tb)
		return ta < tb ? 1 : -1;
	return *(const int *)a - *(const int *)b;
}

void report_summary(const struct options *opt)
{
	int order[MAX_SYSCALL_NR];
	unsigned long calls = 0, errors = 0;
	int i, n = 0;

	if (!opt->summary_only)
		return;

	for (i = 0; i < MAX_SYSCALL_NR; i++)
		if (stats[i].calls)
			order[n++] = i;
	qsort(order, n, sizeof order[0], by_time);

	fprintf(opt->out, "%% time     seconds  usecs/call     calls    errors syscall\n");
	fprintf(opt->out, "------ ----------- ----------- --------- --------- ---------------\n");
	for (i = 0; i < n; i++) {
		struct stat_row *r = &stats[order[i]];
		const char *name = syscall_name(order[i]);
		char fallback[24];
		double share = total_usec ? 100.0 * r->usec / total_usec : 0.0;

		if (!name) {
			snprintf(fallback, sizeof fallback, "syscall_%d", order[i]);
			name = fallback;
		}
		fprintf(opt->out, "%6.2f %11.6f %11ld %9lu %9lu %s\n",
		        share, r->usec / 1000000.0, r->usec / (long)r->calls,
		        r->calls, r->errors, name);
		calls += r->calls;
		errors += r->errors;
	}
	fprintf(opt->out, "------ ----------- ----------- --------- --------- ---------------\n");
	fprintf(opt->out, "100.00 %11.6f %11s %9lu %9lu total\n",
	        total_usec / 1000000.0, "", calls, errors);
}
