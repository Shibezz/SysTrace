/* SysTrace: a small strace clone. Command line parsing lives here. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "systrace.h"

static void usage(FILE *f, const char *prog)
{
	fprintf(f,
	        "usage: %s [options] command [args...]\n"
	        "\n"
	        "  -e list   trace only these syscalls (comma separated)\n"
	        "  -x list   never trace these syscalls\n"
	        "  -c        print only the summary table, not every call\n"
	        "  -s n      bytes of each string to print (default 32, max 256)\n"
	        "  -o file   write the trace to a file instead of stderr\n"
	        "  -h        show this help\n"
	        "\n"
	        "example: %s -e openat,read,write ls /tmp\n",
	        prog, prog);
}

/* Splits "read,write,close" in place and stores each name in list. */
static int split_names(char *arg, const char **list, int max)
{
	int n = 0;
	char *tok = strtok(arg, ",");

	while (tok) {
		if (n == max) {
			fprintf(stderr, "systrace: too many names in the filter\n");
			return -1;
		}
		list[n++] = tok;
		tok = strtok(NULL, ",");
	}
	return n;
}

int main(int argc, char **argv)
{
	struct options opt;
	int i = 1;

	memset(&opt, 0, sizeof opt);
	opt.str_limit = 32;
	opt.out = stderr;

	/* Options come first, then the command. We stop at the first thing
	   that does not start with a dash so that "systrace ls -l" works. */
	while (i < argc && argv[i][0] == '-' && argv[i][1] != '\0') {
		char *val = NULL;
		char c = argv[i][1];

		if (strcmp(argv[i], "--") == 0) {
			i++;
			break;
		}
		if (c == 'e' || c == 'x' || c == 's' || c == 'o') {
			val = argv[i][2] ? argv[i] + 2 : (i + 1 < argc ? argv[++i] : NULL);
			if (!val) {
				fprintf(stderr, "systrace: -%c needs a value\n", c);
				return 2;
			}
		}
		switch (c) {
		case 'e':
			opt.nonly = split_names(val, opt.only, MAX_FILTERS);
			if (opt.nonly < 0)
				return 2;
			break;
		case 'x':
			opt.nskip = split_names(val, opt.skip, MAX_FILTERS);
			if (opt.nskip < 0)
				return 2;
			break;
		case 'c':
			opt.summary_only = 1;
			break;
		case 's':
			opt.str_limit = atoi(val);
			if (opt.str_limit < 1)
				opt.str_limit = 1;
			if (opt.str_limit > 256)
				opt.str_limit = 256;
			break;
		case 'o':
			opt.out = fopen(val, "w");
			if (!opt.out) {
				perror(val);
				return 2;
			}
			break;
		case 'h':
			usage(stdout, argv[0]);
			return 0;
		default:
			fprintf(stderr, "systrace: unknown option -%c\n", c);
			usage(stderr, argv[0]);
			return 2;
		}
		i++;
	}

	if (i >= argc) {
		usage(stderr, argv[0]);
		return 2;
	}

	opt.child_argv = &argv[i];
	int code = run_tracer(&opt);
	report_summary(&opt);

	if (opt.out != stderr)
		fclose(opt.out);
	return code;
}
