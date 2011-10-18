/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006-2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/torture/torture.h"

static struct timeval last_suite_started;

static void simple_suite_start(struct torture_context *ctx,
			       struct torture_suite *suite)
{
	last_suite_started = timeval_current();
	printf("Running %s\n", suite->name);
}

static void simple_suite_finish(struct torture_context *ctx,
			        struct torture_suite *suite)
{

	printf("%s took %g secs\n\n", suite->name,
		   timeval_elapsed(&last_suite_started));
}

static void simple_test_result(struct torture_context *context,
			       enum torture_result res, const char *reason)
{
	switch (res) {
	case TORTURE_OK:
		if (reason)
			printf("OK: %s\n", reason);
		break;
	case TORTURE_FAIL:
		printf("TEST %s FAILED! - %s\n", context->active_test->name, reason);
		break;
	case TORTURE_ERROR:
		printf("ERROR IN TEST %s! - %s\n", context->active_test->name, reason);
		break;
	case TORTURE_SKIP:
		printf("SKIP: %s - %s\n", context->active_test->name, reason);
		break;
	}
}

static void simple_comment(struct torture_context *test,
			   const char *comment)
{
	printf("%s", comment);
}

static void simple_warning(struct torture_context *test,
			   const char *comment)
{
	fprintf(stderr, "WARNING: %s\n", comment);
}

static void simple_progress(struct torture_context *test,
	int offset, enum torture_progress_whence whence)
{
}

const struct torture_ui_ops torture_simple_ui_ops  = {
	.comment = simple_comment,
	.warning = simple_warning,
	.suite_start = simple_suite_start,
	.suite_finish = simple_suite_finish,
	.test_result = simple_test_result,
	.progress = simple_progress,
};
