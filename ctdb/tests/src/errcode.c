/*
   Portability layer for error codes

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
 * These errors are as listed in POSIX standard
 * IEEE Std 1003.1-2017 (Revision of IEEE Std 1003.1-2008)
 *
 * Error codes marked obsolete are removed (ENODATA, ENOSR, ENOSTR, ETIME)
 */

#include "replace.h"

struct {
	const char *label;
	int code;
} err_codes[] = {
	{ "E2BIG", E2BIG },

	{ "EACCES", EACCES },
	{ "EADDRINUSE", EADDRINUSE },
	{ "EADDRNOTAVAIL", EADDRNOTAVAIL },
	{ "EAFNOSUPPORT", EAFNOSUPPORT },
	{ "EAGAIN", EAGAIN },
	{ "EALREADY", EALREADY },

	{ "EBADF", EBADF },
	{ "EBADMSG", EBADMSG },
	{ "EBUSY", EBUSY },

	{ "ECANCELED", ECANCELED },
	{ "ECHILD", ECHILD },
	{ "ECONNABORTED", ECONNABORTED },
	{ "ECONNREFUSED", ECONNREFUSED },
	{ "ECONNRESET", ECONNRESET },

	{ "EDEADLK", EDEADLK },
	{ "EDESTADDRREQ", EDESTADDRREQ },
	{ "EDOM", EDOM },
	{ "EDQUOT", EDQUOT },

	{ "EEXIST", EEXIST },

	{ "EFAULT", EFAULT },
	{ "EFBIG", EFBIG },

	{ "EHOSTUNREACH", EHOSTUNREACH },

	{ "EIDRM", EIDRM },
	{ "EILSEQ", EILSEQ },
	{ "EINPROGRESS", EINPROGRESS },
	{ "EINTR", EINTR },
	{ "EINVAL", EINVAL },
	{ "EIO", EIO },
	{ "EISCONN", EISCONN },
	{ "EISDIR", EISDIR },

	{ "ELOOP", ELOOP },

	{ "EMFILE", EMFILE },
	{ "EMLINK", EMLINK },
	{ "EMSGSIZE", EMSGSIZE },
	{ "EMULTIHOP", EMULTIHOP },

	{ "ENAMETOOLONG", ENAMETOOLONG },
	{ "ENETDOWN", ENETDOWN },
	{ "ENETRESET", ENETRESET },
	{ "ENETUNREACH", ENETUNREACH },
	{ "ENFILE", ENFILE },
	{ "ENOBUFS", ENOBUFS },
	{ "ENODEV", ENODEV },
	{ "ENOENT", ENOENT },
	{ "ENOEXEC", ENOEXEC },
	{ "ENOLCK", ENOLCK },
	{ "ENOLINK", ENOLINK },
	{ "ENOMEM", ENOMEM },
	{ "ENOMSG", ENOMSG },
	{ "ENOPROTOOPT", ENOPROTOOPT },
	{ "ENOSPC", ENOSPC },
	{ "ENOSYS", ENOSYS },
	{ "ENOTCONN", ENOTCONN },
	{ "ENOTDIR", ENOTDIR },
	{ "ENOTEMPTY", ENOTEMPTY },
	{ "ENOTSOCK", ENOTSOCK },
	{ "ENOTSUP", ENOTSUP },
	{ "ENOTTY", ENOTTY },
	{ "ENXIO", ENXIO },

	{ "EOPNOTSUPP", EOPNOTSUPP },
	{ "EOVERFLOW", EOVERFLOW },

	{ "EPERM", EPERM },
	{ "EPIPE", EPIPE },
	{ "EPROTO", EPROTO },
	{ "EPROTONOSUPPORT", EPROTONOSUPPORT },
	{ "EPROTOTYPE", EPROTOTYPE },

	{ "ERANGE", ERANGE },
	{ "EROFS", EROFS },

	{ "ESPIPE", ESPIPE },
	{ "ESRCH", ESRCH },
	{ "ESTALE", ESTALE },

	{ "ETIMEDOUT", ETIMEDOUT },
	{ "ETXTBSY", ETXTBSY },

	{ "EWOULDBLOCK", EWOULDBLOCK },

	{ "EXDEV", EXDEV },
};

static void dump(void)
{
	size_t i;

	for (i=0; i<ARRAY_SIZE(err_codes); i++) {
		printf("%s %d\n", err_codes[i].label, err_codes[i].code);
	}
}

static void match_label(const char *str)
{
	int code = -1;
	size_t i;

	for (i=0; i<ARRAY_SIZE(err_codes); i++) {
		if (strcasecmp(err_codes[i].label, str) == 0) {
			code = err_codes[i].code;
			break;
		}
	}

	printf("%d\n", code);
}

static void match_code(int code)
{
	const char *label = "UNKNOWN";
	size_t i;

	for (i=0; i<ARRAY_SIZE(err_codes); i++) {
		if (err_codes[i].code == code) {
			label = err_codes[i].label;
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
		fprintf(stderr, "Usage: %s dump|<errcode>\n", argv[0]);
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
