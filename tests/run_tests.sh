#!/bin/sh
# Short checks for systrace. Run with: make test

set -u
BIN=./systrace
TMP=$(mktemp -d)
pass=0
fail=0

check() {
	if [ "$2" = "0" ]; then
		echo "ok   $1"
		pass=$((pass + 1))
	else
		echo "FAIL $1"
		fail=$((fail + 1))
	fi
}

# 1. the execve of the child shows up with its argument list
$BIN -o "$TMP/t1" /bin/echo hello >/dev/null
grep -q 'execve("/bin/echo", \["/bin/echo", "hello"\]' "$TMP/t1"
check "execve is decoded" $?

# 2. write is decoded with the fd and the string
grep -q 'write(1, "hello\\n", 6) = 6' "$TMP/t1"
check "write is decoded" $?

# 3. exit status of the child is reported and passed back
grep -q '+++ exited with 0 +++' "$TMP/t1"
check "exit line is printed" $?

# 4. a failing open shows the errno name
$BIN -o "$TMP/t2" /bin/cat /nope/nothing >/dev/null 2>&1
grep -q 'openat(AT_FDCWD, "/nope/nothing", O_RDONLY) = -1 ENOENT' "$TMP/t2"
check "errno name is printed" $?

# 5. -e keeps only the syscalls asked for
$BIN -e close -o "$TMP/t3" /bin/echo hi >/dev/null
grep -q 'close(' "$TMP/t3" && ! grep -q 'mmap(' "$TMP/t3"
check "-e filter keeps only close" $?

# 6. -x drops a syscall
$BIN -x mmap -o "$TMP/t4" /bin/echo hi >/dev/null
! grep -q 'mmap(' "$TMP/t4"
check "-x filter drops mmap" $?

# 7. -c prints the table and no per call lines
$BIN -c -o "$TMP/t5" /bin/echo hi >/dev/null
grep -q 'usecs/call' "$TMP/t5" && grep -q 'total' "$TMP/t5" && ! grep -q '= -1' "$TMP/t5"
check "-c prints the summary only" $?

# 8. the exit code of the child comes back to the shell
$BIN -c -o /dev/null /bin/sh -c 'exit 3' >/dev/null
[ $? = 3 ]
check "child exit code is returned" $?

# 9. a child killed by a signal is reported, and the code becomes 128 + signal
$BIN -o "$TMP/t6" /bin/sh -c 'kill -TERM $$' >/dev/null 2>&1
code=$?
grep -q 'signal 15' "$TMP/t6" && grep -q 'killed by signal 15' "$TMP/t6" &&
	[ "$code" = 143 ]
check "signal death is reported" $?

rm -rf "$TMP"
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
