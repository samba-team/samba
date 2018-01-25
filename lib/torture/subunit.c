/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   
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

static void subunit_send_event(char const * const event,
		char const * const name,
		char const * const details)
{
	if (NULL == details) {
		printf("%s: %s\n", event, name);
	} else {
		printf("%s: %s [\n", event, name);
		printf("%s", details);
		if (details[strlen(details) - 1] != '\n')
			puts("");
		puts("]");
	}
	fflush(stdout);
}

static void torture_subunit_suite_start(struct torture_context *ctx,
				struct torture_suite *suite)
{
}

static char *torture_subunit_test_name(struct torture_context *ctx,
				   struct torture_tcase *tcase,
				   struct torture_test *test)
{
	if (!strcmp(tcase->name, test->name)) {
		return talloc_strdup(ctx, test->name);
	} else {
		return talloc_asprintf(ctx, "%s.%s", tcase->name, test->name);
	}
}

static void torture_subunit_report_time(struct torture_context *tctx)
{
	struct timespec tp;
	struct tm *tmp;
	char timestr[200];
	if (clock_gettime(CLOCK_REALTIME, &tp) != 0) {
		perror("clock_gettime");
		return;
	}

	tmp = gmtime(&tp.tv_sec);
	if (!tmp) {
		perror("gmtime");
		return;
	}

	if (strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tmp) <= 0) {
		perror("strftime");
		return;
	}

	printf("time: %s.%06ld\n", timestr, tp.tv_nsec / 1000);
}

static void torture_subunit_test_start(struct torture_context *context, 
			       struct torture_tcase *tcase,
			       struct torture_test *test)
{
	char *fullname = torture_subunit_test_name(context, context->active_tcase, context->active_test);
	subunit_send_event("test", fullname, NULL);
	torture_subunit_report_time(context);
	talloc_free(fullname);
}

static void torture_subunit_test_result(struct torture_context *context, 
				enum torture_result res, const char *reason)
{
	char *fullname = torture_subunit_test_name(context, context->active_tcase, context->active_test);
	const char *result_str = "unknown";
	torture_subunit_report_time(context);
	switch (res) {
	case TORTURE_OK:
		result_str = "success";
		break;
	case TORTURE_FAIL:
		result_str = "failure";
		break;
	case TORTURE_ERROR:
		result_str = "error";
		break;
	case TORTURE_SKIP:
		result_str = "skip";
		break;
	}
	subunit_send_event(result_str, fullname, reason);
	talloc_free(fullname);
}

static void torture_subunit_comment(struct torture_context *test,
			    const char *comment)
{
	fprintf(stderr, "%s", comment);
}

static void torture_subunit_warning(struct torture_context *test,
			    const char *comment)
{
	fprintf(stderr, "WARNING!: %s\n", comment);
}

static void torture_subunit_progress(struct torture_context *tctx, int offset, enum torture_progress_whence whence)
{
	switch (whence) {
	case TORTURE_PROGRESS_SET:
		printf("progress: %d\n", offset);
		break;
	case TORTURE_PROGRESS_CUR:
		printf("progress: %+-d\n", offset);
		break;
	case TORTURE_PROGRESS_POP:
		printf("progress: pop\n");
		break;
	case TORTURE_PROGRESS_PUSH:
		printf("progress: push\n");
		break;
	default:
		fprintf(stderr, "Invalid call to progress()\n");
		break;
	}
}

const struct torture_ui_ops torture_subunit_ui_ops = {
	.comment = torture_subunit_comment,
	.warning = torture_subunit_warning,
	.test_start = torture_subunit_test_start,
	.test_result = torture_subunit_test_result,
	.suite_start = torture_subunit_suite_start,
	.progress = torture_subunit_progress,
	.report_time = torture_subunit_report_time,
};
