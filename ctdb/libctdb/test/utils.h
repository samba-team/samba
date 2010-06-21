/*

This file is taken from nfsim (http://ozlabs.org/~jk/projects/nfsim/)

Copyright (c) 2003,2004 Rusty Russell

This file is part of nfsim.

nfsim is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

nfsim is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with nfsim; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _UTILS_H
#define _UTILS_H
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

/* Is A == B ? */
#define streq(a,b) (strcmp((a),(b)) == 0)

/* Does A start with B ? */
#define strstarts(a,b) (strncmp((a),(b),strlen(b)) == 0)

/* Does A end in B ? */
static inline bool strends(const char *a, const char *b)
{
	if (strlen(a) < strlen(b))
		return false;

	return streq(a + strlen(a) - strlen(b), b);
}

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

/* Paste two tokens together. */
#define ___cat(a,b) a ## b
#define __cat(a,b) ___cat(a,b)

/* Try to give a unique identifier: this comes close, iff used as static. */
#define __unique_id(stem) __cat(__cat(__uniq,stem),__LINE__)

enum exitcodes {
	/* EXIT_SUCCESS, EXIT_FAILURE is in stdlib.h */
	EXIT_SCRIPTFAIL = EXIT_FAILURE + 1,
};

/* init code */
typedef void (*initcall_t)(void);
#define init_call(fn) \
	static initcall_t __initcall_##fn \
	__attribute__((__unused__)) \
	__attribute__((__section__("init_call"))) = &fn

/* distributed command line options */
struct cmdline_option
{
       struct option opt;
       void (*parse)(struct option *opt);
}  __attribute__((aligned(64)));	/* align it to 64 for 64bit arch,
 * <rusty> LaF0rge: space is cheap.  A comment might be nice. */

#define cmdline_opt(_name, _has_arg, _c, _fn)                                \
       static struct cmdline_option __cat(__cmdlnopt_,__unique_id(_fn))      \
       __attribute__((__unused__))                                           \
       __attribute__((__section__("cmdline")))                               \
       = { .opt = { .name = _name, .has_arg = _has_arg, .val = _c },         \
	   .parse = _fn }

/* In generated-usage.c */
void print_usage(void);

#endif /* _UTILS_H */
