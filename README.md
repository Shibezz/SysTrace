# SysTrace

A small syscall tracer for Linux, written in C. It runs a program, stops it at
every system call, prints the call with decoded arguments, and can show a
summary table at the end. It is a cut down version of strace, written to
understand how ptrace actually works.

Only x86_64 is supported. The register layout and the syscall numbers are
architecture specific, and supporting more than one would have doubled the
size of the code. The build fails with a clear message on other machines.

## Build and run

```sh
make
./systrace /bin/echo hello
```

Output looks like this:

```
execve("/bin/echo", ["/bin/echo", "hello"], 0x7ffd1a2b3c40 /* 23 vars */) = 0
brk(NULL) = 0x55d6f1c0a000
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
read(3, "\x7fELF\x02\x01\x01\x03\x00\x00\x00\x00"..., 832) = 832
close(3) = 0
write(1, "hello\n", 6) = 6
exit_group(0) = ?
+++ exited with 0 +++
```

Options:

```
-e list   trace only these syscalls, comma separated
-x list   never trace these syscalls
-c        print only the summary table
-s n      how many bytes of each string to print (default 32, max 256)
-o file   write the trace to a file instead of stderr
-h        help
```

Examples:

```sh
./systrace -e openat,read,close cat /etc/hostname
./systrace -x mmap,mprotect ls
./systrace -c ls > /dev/null
```

The summary table with `-c` looks like the one strace prints:

```
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ---------------
 47.94    0.042478        1213        35        13 openat
 13.37    0.011843         394        30         0 mmap
  1.32    0.001168         116        10         0 read
------ ----------- ----------- --------- --------- ---------------
100.00    0.088607                   151        18 total
```

Run the tests with `make test`. They trace `/bin/echo` and `/bin/cat` and check
the decoded lines, both filters, the summary and the exit code.

## Files

```
include/systrace.h    shared structs and function declarations
src/main.c            command line parsing
src/ptrace_handler.c  fork, ptrace loop, wait handling
src/syscall_decoder.c syscall names, argument decoding, reading child memory
src/reporter.c        printing lines, counters, summary table
tests/run_tests.sh    short end to end checks
```

## How a syscall stop works

A syscall is not one event. The kernel stops the traced process twice for the
same call: once on the way in, when the arguments are in the registers, and
once on the way out, when the result is in the return register. So the tracer
keeps a flag and flips it at every stop. The first stop is the entry, the next
one is the exit for the same call, and so on.

Arguments are decoded at the entry stop. This matters for `execve`, because
by the time it returns the old address space is gone and every pointer in the
arguments would read as garbage. The exception is `read` and `write`, whose
buffer only becomes interesting after the call ran, so those two are decoded at
the exit stop instead.

`exit` and `exit_group` never come back, so they are printed at the entry stop
with `= ?` as the result.

## Every Linux API used here

### fork

`pid_t fork(void)` makes a copy of the current process. It returns 0 in the new
child and the child pid in the parent. SysTrace forks so that the child can put
itself under tracing before it becomes the target program.

### execvp

`int execvp(const char *file, char *const argv[])` replaces the current program
with another one, keeping the same pid. The `p` means it searches `$PATH`, so
`./systrace ls` works without typing `/bin/ls`. It only returns if it failed.

### _exit

`void _exit(int status)` ends the process without running atexit handlers or
flushing stdio buffers. The child uses it after a failed exec so that it does
not flush buffers that the parent already owns a copy of.

### ptrace

`long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)`
is the whole debugging interface of Linux in one call. The request decides what
the other arguments mean. SysTrace uses five requests.

`PTRACE_TRACEME` is called by the child itself. It says "my parent is now my
tracer". After this, every signal the child gets and every syscall stop is
reported to the parent through `waitpid`.

`PTRACE_SETOPTIONS` sets flags on an already stopped tracee. Two are used:

`PTRACE_O_TRACESYSGOOD` makes the kernel report syscall stops with signal
`SIGTRAP | 0x80` instead of a plain `SIGTRAP`. Without it, a syscall stop and a
real breakpoint trap look the same, and there is no reliable way to tell them
apart. With it, the check is one bit.

`PTRACE_O_EXITKILL` sends `SIGKILL` to the child if the tracer dies. If you kill
SysTrace with Ctrl-C, the traced program does not stay stopped forever.

`PTRACE_SYSCALL` restarts a stopped child and asks the kernel to stop it again
at the next syscall entry or exit. The `data` argument is a signal number to
deliver on the way, or 0 to deliver nothing. This is the difference between
`PTRACE_SYSCALL` and `PTRACE_CONT`: `PTRACE_CONT` just runs until the next
signal, which would show nothing about syscalls.

`PTRACE_GETREGS` copies the whole register set of the stopped child into a
`struct user_regs_struct`. This is where the syscall number, the arguments and
the return value come from.

`PTRACE_PEEKDATA` reads one word, 8 bytes on x86_64, from the address space of
the child and returns it. There is no length argument, so reading a string means
looping word by word until a zero byte turns up. A word of `-1` can be a valid
value, so `errno` is cleared before the call and checked after it to tell a real
`-1` apart from a failed read. This is how the tracer gets file names, buffer
contents and the `argv` array of `execve`. It is slow, and a real tracer would
use `process_vm_readv`, but one API is easier to follow than two.

### raise and SIGSTOP

`int raise(int sig)` sends a signal to the calling process. The child raises
`SIGSTOP` right after `PTRACE_TRACEME` and before `execvp`. That gives the
parent a chance to set the ptrace options while the child is stopped and still
has not started the target program, so the `execve` call itself gets traced.
The parent then restarts the child with a signal of 0, which throws the
`SIGSTOP` away.

### waitpid and the status macros

`pid_t waitpid(pid_t pid, int *status, int options)` blocks until the child
changes state, which for a traced child means every single stop. The integer it
fills in is decoded with macros:

`WIFEXITED(status)` is true when the child called exit, and `WEXITSTATUS` gives
the code. `WIFSIGNALED` is true when a signal killed it, and `WTERMSIG` gives
that signal. `WIFSTOPPED` is true for a stop, and `WSTOPSIG` gives the signal
that caused it. For SysTrace, `WSTOPSIG(status) == (SIGTRAP | 0x80)` means a
syscall stop, and anything else is a normal signal.

One case needs care. A successful `execve` in a traced process delivers a plain
`SIGTRAP` to the child. Passing that signal on with `PTRACE_SYSCALL` would kill
the program with signal 5, so a plain `SIGTRAP` is swallowed. Other signals are
printed as `--- signal 11 (Segmentation fault) ---` and handed to the child.

### struct user_regs_struct and the x86_64 syscall ABI

The struct comes from `<sys/user.h>` and holds the saved registers of the
stopped child. On x86_64 the calling convention for a syscall is fixed:

```
orig_rax   syscall number
rdi        argument 1
rsi        argument 2
rdx        argument 3
r10        argument 4
r8         argument 5
r9         argument 6
rax        return value at the exit stop
```

There are both `rax` and `orig_rax` because `rax` holds the syscall number on
the way in and the result on the way out. The kernel keeps the original number
in `orig_rax` so a tracer can still see which call it was.

A negative return value between -1 and -4095 is a negated errno, not a real
result. That is how the kernel reports errors, and glibc turns it into -1 plus
the `errno` variable. SysTrace does the same check and prints, for example,
`= -1 ENOENT (No such file or directory)`.

### clock_gettime

`int clock_gettime(clockid_t clk, struct timespec *ts)` reads a clock in
nanoseconds. `CLOCK_MONOTONIC` only moves forward and is not affected by the
system clock being changed, which makes it right for measuring durations. The
tracer reads it at the entry stop and again at the exit stop, and the difference
is the time the syscall spent in the kernel. That number is what fills the
seconds column of the summary.

### strerror and strsignal

`char *strerror(int errnum)` gives the message for an errno value, and
`char *strsignal(int sig)` gives the description of a signal number. Neither
gives the short name such as `ENOENT`, so the reporter keeps a small table of
the common errno names.

### Header constants that get decoded

`AT_FDCWD` from `<fcntl.h>` is the special directory descriptor meaning "start
from the current working directory". Every `*at` syscall such as `openat`
accepts it, and printing the raw value -100 would be confusing.

The `O_` flags from `<fcntl.h>` are turned back into names. The lowest two bits
are an access mode, not flags, so `O_RDONLY`, `O_WRONLY` and `O_RDWR` are
handled with a mask on `O_ACCMODE` first, and only then the real bit flags such
as `O_CREAT` and `O_CLOEXEC` are matched. The `mode` argument of `open` and
`openat` only means something when `O_CREAT` is set, so it is printed only then.

## How arguments are decoded

`syscall_decoder.c` has a table with the syscall names indexed by number, and a
second table saying what each argument of the interesting calls means:

```c
{ SYS_openat, { A_ATFD, A_STR, A_OFLAGS, A_MODE } },
```

`A_STR` reads a C string out of the child, `A_BUF` reads a buffer using the
return value as its length, `A_ARGV` walks a NULL terminated array of string
pointers, `A_ENVP` only counts the entries because the environment is long and
never interesting, `A_FD` and `A_INT` print numbers, and `A_HEX` prints a
pointer.

Strings are escaped the way strace does it. Newline becomes `\n`, quotes and
backslashes get a backslash, and anything else outside printable ASCII becomes
`\xNN`. A string longer than the `-s` limit is cut and marked with `...`.

Calls that have no entry in the table still get their name, and their arguments
are printed as hex. The number of arguments is not stored anywhere, so the
decoder prints up to the last argument that is not zero. That guess is wrong
sometimes, for example when a real argument in the middle happens to be zero, so
`mmap` may print fewer arguments than it takes.

## Limits

These were left out on purpose to keep the code small:

Child processes are not followed. There is no `-f`, so a shell script being
traced shows the syscalls of the shell and nothing from the programs it starts.
Attaching to a running process with `PTRACE_ATTACH` is not supported either, so
the program has to be started by SysTrace.

Structures such as `struct stat` and `struct timespec` are printed as pointers.
Decoding them means reading the struct out of the child and formatting every
field, which is most of the size of real strace.

Signal handling is basic. Signals are shown and passed through, but group stops
and the restart quirks around them are not handled, so tracing a program that
plays with `SIGSTOP` itself can confuse the loop.

The name table covers the common syscalls, not all of them. Anything missing
prints as `syscall_133` with hex arguments, which is enough to look the number
up in `arch/x86/entry/syscalls/syscall_64.tbl` in the kernel source.
