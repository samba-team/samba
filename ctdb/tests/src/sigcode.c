/*
   Portability layer for signal codes

   Copyright (C) Amitay Isaacs  2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 * These signals are as listed in POSIX standard
 * IEEE Std 1003.1-2017 (Revision of IEEE Std 1003.1-2008)
 */

#include "replace.h"
#include "system/wait.h"

struct {
	const char *label;
	int code;
} sig_codes[] = {
	{ "SIGABRT", SIGABRT },
	{ "SIGALRM", SIGALRM },
	{ "SIBGUS", SIGBUS },
	{ "SIGCHLD", SIGCHLD },
	{ "SIGCONT", SIGCONT },
	{ "SIGFPE", SIGFPE },
	{ "SIGHUP", SIGHUP },
	{ "SIGILL", SIGILL },
	{ "SIGINT", SIGINT },
	{ "SIGKILL", SIGKILL },
	{ "SIGPIPE", SIGPIPE },
	{ "SIGQUIT", SIGQUIT },
	{ "SIGSEGV", SIGSEGV },
	{ "SIGSTOP", SIGSTOP },
	{ "SIGTERM", SIGTERM },
	{ "SIGTSTP", SIGTSTP },
	{ "SIGTTIN", SIGTTIN },
	{ "SIGTTOU", SIGTTOU },
	{ "SIGUSR1", SIGUSR1 },
	{ "SIGUSR2", SIGUSR2 },
	{ "SIGTRAP", SIGTRAP },
	{ "SIGURG", SIGURG },
	{ "SIGXCPU", SIGXCPU },
	{ "SIGXFSZ", SIGXFSZ },

};

static void dump(void)
{
	size_t i;

	for (i=0; i<ARRAY_SIZE(sig_codes); i++) {
		printf("%s %d\n", sig_codes[i].label, sig_codes[i].code);
	}
}

static void match_label(const char *str)
{
	int code = -1;
	size_t i;

	for (i=0; i<ARRAY_SIZE(sig_codes); i++) {
		if (strcasecmp(sig_codes[i].label, str) == 0) {
			code = sig_codes[i].code;
			break;
		}
	}

	printf("%d\n", code);
}

static void match_code(int code)
{
	const char *label = "UNKNOWN";
	size_t i;

	for (i=0; i<ARRAY_SIZE(sig_codes); i++) {
		if (sig_codes[i].code == code) {
			label = sig_codes[i].label;
			break;
		}
	}

	printf("%s\n", label);
}

int main(int argc, const char **argv)
{
	long int code;
	char *endptr;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s dump|<sigcode>\n", argv[0]);
		exit(1);
	}

	if (strcmp(argv[1], "dump") == 0) {
		dump();
	} else {
		code = strtol(argv[1], &endptr, 0);
		if (*endptr == '\0') {
			match_code(code);
		} else {
			match_label(argv[1]);
		}
	}

	exit(0);
}
