/*
   Low level event script handling tests

   Copyright (C) Martin Schwenke  2018

   Based on run_event_test.c:

     Copyright (C) Amitay Isaacs  2017

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

#include "replace.h"

#include <popt.h>
#include <talloc.h>

#include <assert.h>

#include "common/event_script.c"

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s list <scriptdir>\n",
		prog);
	fprintf(stderr,
		"       %s chmod enable <scriptdir> <scriptname>\n",
		prog);
	fprintf(stderr,
		"       %s chmod diable <scriptdir> <scriptname>\n",
		prog);
}

static void do_list(TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	struct event_script_list *script_list = NULL;
	unsigned int i;
	int ret;

	if (argc != 3) {
		usage(argv[0]);
		exit(1);
	}

	ret = event_script_get_list(mem_ctx, argv[2], &script_list);
	if (ret != 0) {
		printf("Script list %s failed with result=%d\n", argv[2], ret);
		return;
	}

	if (script_list == NULL || script_list->num_scripts == 0) {
		printf("No scripts found\n");
		return;
	}

	for (i=0; i < script_list->num_scripts; i++) {
		struct event_script *s = script_list->script[i];
		printf("%s\n", s->name);
	}
}

static void do_chmod(TALLOC_CTX *mem_ctx,
		     int argc,
		     const char **argv,
		     bool enable)
{
	int ret;

	if (argc != 4) {
		usage(argv[0]);
		exit(1);
	}

	ret = event_script_chmod(argv[2], argv[3], enable);

	printf("Script %s %s %s completed with result=%d\n",
	       argv[1], argv[2], argv[3], ret);
}

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;

	if (argc < 3) {
		usage(argv[0]);
		exit(1);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_new() failed\n");
		exit(1);
	}

	if (strcmp(argv[1], "list") == 0) {
		do_list(mem_ctx, argc, argv);
	} else if (strcmp(argv[1], "enable") == 0) {
		do_chmod(mem_ctx, argc, argv, true);
	} else if (strcmp(argv[1], "disable") == 0) {
		do_chmod(mem_ctx, argc, argv, false);
	} else {
		fprintf(stderr, "Invalid command %s\n", argv[2]);
		usage(argv[0]);
	}

	talloc_free(mem_ctx);
	exit(0);
}
