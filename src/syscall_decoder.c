/* Turns raw syscall numbers and register values into readable text. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

#include "systrace.h"

/* x86_64 syscall numbers. The full list lives in the kernel source at
   arch/x86/entry/syscalls/syscall_64.tbl, this is the common part. */
static const char *const names[MAX_SYSCALL_NR] = {
	[0] = "read", [1] = "write", [2] = "open", [3] = "close",
	[4] = "stat", [5] = "fstat", [6] = "lstat", [7] = "poll",
	[8] = "lseek", [9] = "mmap", [10] = "mprotect", [11] = "munmap",
	[12] = "brk", [13] = "rt_sigaction", [14] = "rt_sigprocmask",
	[15] = "rt_sigreturn", [16] = "ioctl", [17] = "pread64",
	[18] = "pwrite64", [19] = "readv", [20] = "writev", [21] = "access",
	[22] = "pipe", [23] = "select", [24] = "sched_yield", [25] = "mremap",
	[26] = "msync", [27] = "mincore", [28] = "madvise", [32] = "dup",
	[33] = "dup2", [34] = "pause", [35] = "nanosleep", [39] = "getpid",
	[40] = "sendfile", [41] = "socket", [42] = "connect", [43] = "accept",
	[44] = "sendto", [45] = "recvfrom", [46] = "sendmsg", [47] = "recvmsg",
	[48] = "shutdown", [49] = "bind", [50] = "listen", [51] = "getsockname",
	[53] = "socketpair", [54] = "setsockopt", [55] = "getsockopt",
	[56] = "clone", [57] = "fork", [58] = "vfork", [59] = "execve",
	[60] = "exit", [61] = "wait4", [62] = "kill", [63] = "uname",
	[72] = "fcntl", [73] = "flock", [74] = "fsync", [75] = "fdatasync",
	[76] = "truncate", [77] = "ftruncate", [78] = "getdents",
	[79] = "getcwd", [80] = "chdir", [81] = "fchdir", [82] = "rename",
	[83] = "mkdir", [84] = "rmdir", [85] = "creat", [86] = "link",
	[87] = "unlink", [88] = "symlink", [89] = "readlink", [90] = "chmod",
	[91] = "fchmod", [92] = "chown", [93] = "fchown", [95] = "umask",
	[96] = "gettimeofday", [97] = "getrlimit", [98] = "getrusage",
	[99] = "sysinfo", [100] = "times", [101] = "ptrace", [102] = "getuid",
	[104] = "getgid", [105] = "setuid", [106] = "setgid", [107] = "geteuid",
	[108] = "getegid", [109] = "setpgid", [110] = "getppid",
	[112] = "setsid", [118] = "getresuid", [120] = "getresgid",
	[131] = "sigaltstack", [137] = "statfs", [138] = "fstatfs",
	[158] = "arch_prctl", [186] = "gettid", [200] = "tkill", [201] = "time",
	[202] = "futex", [204] = "sched_getaffinity", [217] = "getdents64",
	[218] = "set_tid_address", [228] = "clock_gettime",
	[230] = "clock_nanosleep", [231] = "exit_group", [232] = "epoll_wait",
	[233] = "epoll_ctl", [257] = "openat", [258] = "mkdirat",
	[262] = "newfstatat", [263] = "unlinkat", [265] = "linkat",
	[267] = "readlinkat", [268] = "fchmodat", [269] = "faccessat",
	[270] = "pselect6", [271] = "ppoll", [273] = "set_robust_list",
	[281] = "epoll_pwait", [284] = "eventfd", [288] = "accept4",
	[290] = "eventfd2", [291] = "epoll_create1", [292] = "dup3",
	[293] = "pipe2", [302] = "prlimit64", [309] = "getcpu",
	[318] = "getrandom", [332] = "statx", [334] = "rseq",
	[435] = "clone3", [439] = "faccessat2",
};

const char *syscall_name(long nr)
{
	if (nr >= 0 && nr < MAX_SYSCALL_NR && names[nr])
		return names[nr];
	return NULL;
}

int syscall_allowed(const struct options *opt, long nr)
{
	const char *name = syscall_name(nr);
	int i, found = 0;

	if (!name)
		name = "";
	for (i = 0; i < opt->nskip; i++)
		if (strcmp(name, opt->skip[i]) == 0)
			return 0;
	if (opt->nonly == 0)
		return 1;
	for (i = 0; i < opt->nonly; i++)
		if (strcmp(name, opt->only[i]) == 0)
			found = 1;
	return found;
}

/* How to print each argument of a syscall we know about. */
enum {
	A_NONE = 0, A_HEX, A_INT, A_FD, A_STR, A_BUF,
	A_ATFD, A_OFLAGS, A_MODE, A_ARGV, A_ENVP
};

struct spec {
	int nr;
	char arg[MAX_ARGS];
};

static const struct spec specs[] = {
	{ SYS_read,       { A_FD, A_BUF, A_INT } },
	{ SYS_write,      { A_FD, A_BUF, A_INT } },
	{ SYS_open,       { A_STR, A_OFLAGS, A_MODE } },
	{ SYS_openat,     { A_ATFD, A_STR, A_OFLAGS, A_MODE } },
	{ SYS_close,      { A_FD } },
	{ SYS_execve,     { A_STR, A_ARGV, A_ENVP } },
	{ SYS_lseek,      { A_FD, A_INT, A_INT } },
	{ SYS_stat,       { A_STR, A_HEX } },
	{ SYS_lstat,      { A_STR, A_HEX } },
	{ SYS_fstat,      { A_FD, A_HEX } },
	{ SYS_newfstatat, { A_ATFD, A_STR, A_HEX, A_HEX } },
	{ SYS_access,     { A_STR, A_INT } },
	{ SYS_unlink,     { A_STR } },
	{ SYS_chdir,      { A_STR } },
	{ SYS_readlink,   { A_STR, A_HEX, A_INT } },
	{ SYS_ioctl,      { A_FD, A_HEX, A_HEX } },
	{ SYS_fcntl,      { A_FD, A_INT, A_HEX } },
	{ SYS_dup2,       { A_FD, A_FD } },
	{ SYS_brk,        { A_HEX } },
	{ SYS_munmap,     { A_HEX, A_INT } },
	{ SYS_mprotect,   { A_HEX, A_INT, A_HEX } },
	{ SYS_kill,       { A_INT, A_INT } },
	{ SYS_exit,       { A_INT } },
	{ SYS_exit_group, { A_INT } },
};

static const struct spec *find_spec(long nr)
{
	size_t i;

	for (i = 0; i < sizeof specs / sizeof specs[0]; i++)
		if (specs[i].nr == nr)
			return &specs[i];
	return NULL;
}

/* Most calls are decoded at the entry stop, because a call like execve
   throws away the memory the pointers refer to. read and write are the
   exception: their buffer is only interesting once the call is done. */
int decode_at_exit(long nr)
{
	const struct spec *sp = find_spec(nr);
	int i;

	if (!sp)
		return 0;
	for (i = 0; i < MAX_ARGS; i++)
		if (sp->arg[i] == A_BUF)
			return 1;
	return 0;
}

/* Appends formatted text and keeps pos inside the buffer. */
static void addf(char *out, size_t size, size_t *pos, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (*pos + 1 >= size)
		return;
	va_start(ap, fmt);
	n = vsnprintf(out + *pos, size - *pos, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	*pos += ((size_t)n < size - *pos) ? (size_t)n : size - *pos - 1;
}

/* Copies len bytes out of the traced process, one word at a time.
   Returns how many bytes it actually got. */
static int read_mem(pid_t pid, unsigned long addr, char *buf, int len)
{
	int done = 0;

	while (done < len) {
		long word;
		int n = len - done;

		errno = 0;
		word = ptrace(PTRACE_PEEKDATA, pid, addr + done, NULL);
		if (word == -1 && errno != 0)
			break;
		if (n > (int)sizeof word)
			n = (int)sizeof word;
		memcpy(buf + done, &word, n);
		done += n;
	}
	return done;
}

/* Reads a C string from the child. Returns its length, or -1 on a bad
   pointer. cut is set when the string was longer than limit. */
static int read_str(pid_t pid, unsigned long addr, char *buf, int limit, int *cut)
{
	int len = 0;

	*cut = 0;
	for (;;) {
		char word[sizeof(long)];
		int n = read_mem(pid, addr + len, word, sizeof word);
		int i;

		if (n <= 0)
			return len > 0 ? len : -1;
		for (i = 0; i < n; i++) {
			if (word[i] == '\0')
				return len;
			if (len == limit) {
				*cut = 1;
				return len;
			}
			buf[len++] = word[i];
		}
	}
}

/* Escapes bytes the way strace does so binary data stays on one line. */
static void escape(const char *data, int len, char *out, size_t size)
{
	size_t pos = 0;
	int i;

	for (i = 0; i < len && pos + 5 < size; i++) {
		unsigned char c = (unsigned char)data[i];

		if (c == '\\' || c == '"') {
			out[pos++] = '\\';
			out[pos++] = (char)c;
		} else if (c == '\n' || c == '\t' || c == '\r') {
			out[pos++] = '\\';
			out[pos++] = c == '\n' ? 'n' : (c == '\t' ? 't' : 'r');
		} else if (c >= 0x20 && c < 0x7f) {
			out[pos++] = (char)c;
		} else {
			pos += (size_t)snprintf(out + pos, size - pos, "\\x%02x", c);
		}
	}
	out[pos] = '\0';
}

static void put_str(pid_t pid, unsigned long addr, int limit,
                    char *out, size_t size, size_t *pos)
{
	char raw[257], text[1040];
	int cut, len;

	if (addr == 0) {
		addf(out, size, pos, "NULL");
		return;
	}
	len = read_str(pid, addr, raw, limit, &cut);
	if (len < 0) {
		addf(out, size, pos, "0x%lx", addr);
		return;
	}
	escape(raw, len, text, sizeof text);
	addf(out, size, pos, "\"%s\"%s", text, cut ? "..." : "");
}

/* read and write buffers: the interesting length is what the call
   returned, so this only runs at the exit stop. */
static void put_buf(pid_t pid, unsigned long addr, long ret, int limit,
                    char *out, size_t size, size_t *pos)
{
	char raw[257], text[1040];
	int len, got;

	if (addr == 0 || ret <= 0) {
		if (ret == 0)
			addf(out, size, pos, "\"\"");
		else
			addf(out, size, pos, "0x%lx", addr);
		return;
	}
	len = ret < limit ? (int)ret : limit;
	got = read_mem(pid, addr, raw, len);
	if (got <= 0) {
		addf(out, size, pos, "0x%lx", addr);
		return;
	}
	escape(raw, got, text, sizeof text);
	addf(out, size, pos, "\"%s\"%s", text, ret > got ? "..." : "");
}

static const struct {
	int val;
	const char *name;
} open_flags[] = {
	{ O_CREAT, "O_CREAT" }, { O_EXCL, "O_EXCL" }, { O_NOCTTY, "O_NOCTTY" },
	{ O_TRUNC, "O_TRUNC" }, { O_APPEND, "O_APPEND" },
	{ O_NONBLOCK, "O_NONBLOCK" }, { O_SYNC, "O_SYNC" },
	{ O_DIRECTORY, "O_DIRECTORY" }, { O_NOFOLLOW, "O_NOFOLLOW" },
	{ O_CLOEXEC, "O_CLOEXEC" }, { O_DIRECT, "O_DIRECT" },
	{ O_NOATIME, "O_NOATIME" }, { O_PATH, "O_PATH" },
};

static void put_oflags(long flags, char *out, size_t size, size_t *pos)
{
	size_t i;

	if ((flags & O_ACCMODE) == O_WRONLY)
		addf(out, size, pos, "O_WRONLY");
	else if ((flags & O_ACCMODE) == O_RDWR)
		addf(out, size, pos, "O_RDWR");
	else
		addf(out, size, pos, "O_RDONLY");
	flags &= ~(long)O_ACCMODE;

	for (i = 0; i < sizeof open_flags / sizeof open_flags[0]; i++) {
		if ((flags & open_flags[i].val) == open_flags[i].val) {
			addf(out, size, pos, "|%s", open_flags[i].name);
			flags &= ~(long)open_flags[i].val;
		}
	}
	if (flags)
		addf(out, size, pos, "|0x%lx", flags);
}

/* execve gets a NULL terminated array of string pointers. */
static void put_argv(pid_t pid, unsigned long addr, int limit,
                     char *out, size_t size, size_t *pos)
{
	int i;

	if (addr == 0) {
		addf(out, size, pos, "NULL");
		return;
	}
	addf(out, size, pos, "[");
	for (i = 0; i < 8; i++) {
		unsigned long p = 0;

		if (read_mem(pid, addr + i * sizeof(long), (char *)&p, sizeof p) <= 0)
			break;
		if (p == 0)
			break;
		if (i)
			addf(out, size, pos, ", ");
		put_str(pid, p, limit, out, size, pos);
	}
	if (i == 8)
		addf(out, size, pos, ", ...");
	addf(out, size, pos, "]");
}

/* The environment is long and boring, so only the count is printed. */
static void put_envp(pid_t pid, unsigned long addr, char *out, size_t size, size_t *pos)
{
	int n = 0;

	if (addr == 0) {
		addf(out, size, pos, "NULL");
		return;
	}
	while (n < 512) {
		unsigned long p = 0;

		if (read_mem(pid, addr + n * sizeof(long), (char *)&p, sizeof p) <= 0)
			break;
		if (p == 0)
			break;
		n++;
	}
	addf(out, size, pos, "0x%lx /* %d vars */", addr, n);
}

static void put_arg(pid_t pid, const struct syscall_ev *ev, const struct options *opt,
                    int type, long val, char *out, size_t size, size_t *pos)
{
	switch (type) {
	case A_INT:
		addf(out, size, pos, "%ld", val);
		break;
	case A_FD:
		addf(out, size, pos, "%d", (int)val);
		break;
	case A_ATFD:
		if ((int)val == AT_FDCWD)
			addf(out, size, pos, "AT_FDCWD");
		else
			addf(out, size, pos, "%d", (int)val);
		break;
	case A_STR:
		put_str(pid, (unsigned long)val, opt->str_limit, out, size, pos);
		break;
	case A_BUF:
		put_buf(pid, (unsigned long)val, ev->ret, opt->str_limit, out, size, pos);
		break;
	case A_OFLAGS:
		put_oflags(val, out, size, pos);
		break;
	case A_MODE:
		addf(out, size, pos, "0%o", (unsigned)val & 07777);
		break;
	case A_ARGV:
		put_argv(pid, (unsigned long)val, opt->str_limit, out, size, pos);
		break;
	case A_ENVP:
		put_envp(pid, (unsigned long)val, out, size, pos);
		break;
	default:
		if (val == 0)
			addf(out, size, pos, "NULL");
		else
			addf(out, size, pos, "0x%lx", val);
		break;
	}
}

void decode_syscall(pid_t pid, struct syscall_ev *ev, const struct options *opt)
{
	const struct spec *sp = find_spec(ev->nr);
	const char *name = syscall_name(ev->nr);
	char *out = ev->text;
	size_t size = sizeof ev->text;
	size_t pos = 0;
	int i, n = 0;

	if (name)
		addf(out, size, &pos, "%s(", name);
	else
		addf(out, size, &pos, "syscall_%ld(", ev->nr);

	if (sp) {
		while (n < MAX_ARGS && sp->arg[n] != A_NONE)
			n++;
	} else {
		/* No spec for this call, so guess how many arguments matter by
		   printing up to the last one that is not zero. */
		for (i = 0; i < MAX_ARGS; i++)
			if (ev->args[i])
				n = i + 1;
	}

	for (i = 0; i < n; i++) {
		int type = sp ? sp->arg[i] : A_HEX;

		/* The mode of open only means something with O_CREAT. */
		if (type == A_MODE && i > 0 && !(ev->args[i - 1] & O_CREAT))
			break;
		if (i)
			addf(out, size, &pos, ", ");
		put_arg(pid, ev, opt, type, ev->args[i], out, size, &pos);
	}
	addf(out, size, &pos, ")");
}
