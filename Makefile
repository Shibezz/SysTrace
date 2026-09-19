CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
SRC = src/main.c src/ptrace_handler.c src/syscall_decoder.c src/reporter.c
OBJ = $(SRC:.c=.o)

systrace: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

src/%.o: src/%.c include/systrace.h
	$(CC) $(CFLAGS) -c $< -o $@

test: systrace
	./tests/run_tests.sh

clean:
	rm -f $(OBJ) systrace

.PHONY: test clean
