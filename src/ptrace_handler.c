/* Forks the child, keeps it under ptrace and walks the syscall stops. */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "systrace.h"

#if !defined(__x86_64__)
#error "SysTrace reads x86_64 registers and syscall numbers, build it on x86_64"
#endif

static long now_usec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000L + ts.tv_nsec / 1000;
}

/* Runs in the child after fork and never returns on success. */
static void start_child(char **argv)
{
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
		perror("ptrace traceme");
		_exit(126);
	}
	/* Stop here so the parent can set its ptrace options before execve
	   runs. Without this we would miss the execve call itself. */
	raise(SIGSTOP);
	execvp(argv[0], argv);
	fprintf(stderr, "systrace: cannot run %s: %s\n", argv[0], strerror(errno));
	_exit(127);
}

static void copy_regs(struct syscall_ev *ev, struct user_regs_struct *r)
{
	ev->nr = (long)r->orig_rax;
	ev->args[0] = (long)r->rdi;
	ev->args[1] = (long)r->rsi;
	ev->args[2] = (long)r->rdx;
	ev->args[3] = (long)r->r10;
	ev->args[4] = (long)r->r8;
	ev->args[5] = (long)r->r9;
}

int run_tracer(struct options *opt)
{
	struct syscall_ev ev;
	struct user_regs_struct regs;
	int status, sig = 0, at_entry = 1, code = 0;
	long start = 0;
	pid_t pid;

	memset(&ev, 0, sizeof ev);

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}
	if (pid == 0)
		start_child(opt->child_argv);

	/* Wait for the SIGSTOP the child raised for us. */
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}

	/* TRACESYSGOOD marks syscall stops with bit 7 in the stop signal so we
	   can tell them apart from a real SIGTRAP. EXITKILL kills the child if
	   we die, which stops runaway processes when the user hits Ctrl-C. */
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL,
	           PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) < 0) {
		perror("ptrace setoptions");
		return 1;
	}

	for (;;) {
		/* Let the child run until the next syscall boundary. */
		if (ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)sig) < 0) {
			perror("ptrace syscall");
			return 1;
		}
		sig = 0;

		if (waitpid(pid, &status, 0) < 0) {
			perror("waitpid");
			return 1;
		}

		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			report_exit(opt, status);
			code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
			break;
		}
		if (!WIFSTOPPED(status))
			continue;

		if (WSTOPSIG(status) != (SIGTRAP | 0x80)) {
			/* A successful execve delivers a plain SIGTRAP to a traced
			   child. Passing that one on would kill it, so drop it.
			   Any other signal is shown and handed to the child. */
			if (WSTOPSIG(status) == SIGTRAP)
				continue;
			sig = WSTOPSIG(status);
			report_signal(opt, sig);
			continue;
		}

		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
			perror("ptrace getregs");
			return 1;
		}

		if (at_entry) {
			copy_regs(&ev, &regs);
			start = now_usec();
			if (!decode_at_exit(ev.nr) && syscall_allowed(opt, ev.nr))
				decode_syscall(pid, &ev, opt);
			/* exit and exit_group have no exit stop, so print them now. */
			if (ev.nr == SYS_exit || ev.nr == SYS_exit_group) {
				ev.no_ret = 1;
				ev.ret = 0;
				ev.usec = 0;
				if (syscall_allowed(opt, ev.nr)) {
					stats_add(&ev);
					report_line(opt, &ev);
				}
				ev.no_ret = 0;
			}
		} else {
			ev.ret = (long)regs.rax;
			ev.usec = now_usec() - start;
			if (syscall_allowed(opt, ev.nr)) {
				if (decode_at_exit(ev.nr))
					decode_syscall(pid, &ev, opt);
				stats_add(&ev);
				report_line(opt, &ev);
			}
		}
		at_entry = !at_entry;
	}

	return code;
}
