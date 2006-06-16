/* 
   Unix SMB/CIFS implementation.
   SMB torture UI functions

   Copyright (C) Jelmer Vernooij 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "torture/ui.h"
#include "dlinklist.h"

void torture_comment(struct torture_context *context, const char *comment, ...) _PRINTF_ATTRIBUTE(2,3)
{
	va_list ap;
	char *tmp;

	if (!context->ui_ops->comment)
		return;

	va_start(ap, comment);
	tmp = talloc_vasprintf(context, comment, ap);
		
	context->ui_ops->comment(context, tmp);
	
	talloc_free(tmp);
}

void torture_ok(struct torture_context *context)
{
	context->success++;

	if (!context->ui_ops->test_result)
		return;

	context->ui_ops->test_result(context, TORTURE_OK, NULL);
}

void torture_fail(struct torture_context *context, const char *fmt, ...) _PRINTF_ATTRIBUTE(2,3)
{
	va_list ap;
	char *reason;
	context->failed++;

	if (!context->ui_ops->test_result)
		return;

	va_start(ap, fmt);
	reason = talloc_vasprintf(context, fmt, ap);
	va_end(ap);
	context->ui_ops->test_result(context, TORTURE_FAIL, reason);
	talloc_free(reason);
}

void torture_skip(struct torture_context *context, const char *fmt, ...) _PRINTF_ATTRIBUTE(2,3)
{
	va_list ap;
	char *reason;
	context->skipped++;

	if (!context->ui_ops->test_result)
		return;

	va_start(ap, fmt);
	reason = talloc_vasprintf(context, fmt, ap);
	va_end(ap);
	context->ui_ops->test_result(context, TORTURE_SKIP, reason);
	talloc_free(reason);
}

void torture_register_suite(struct torture_suite *suite)
{
	/* FIXME */
}

struct torture_suite *torture_suite_create(TALLOC_CTX *ctx, const char *name)
{
	struct torture_suite *suite = talloc(ctx, struct torture_suite);

	suite->name = talloc_strdup(suite, name);
	suite->testcases = NULL;

	return suite;
}

void torture_tcase_set_fixture(struct torture_tcase *tcase, 
		BOOL (*setup) (struct torture_context *, void **),
		BOOL (*teardown) (struct torture_context *, void *))
{
	tcase->setup = setup;
	tcase->teardown = teardown;
}

struct torture_test *torture_tcase_add_test(struct torture_tcase *tcase, 
						const char *name, 
						BOOL (*run) (struct torture_context *, 
									 const void *tcase_data,
									 const void *test_data),
						const void *data)
{
	struct torture_test *test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = run;
	test->dangerous = False;
	test->data = data;

	DLIST_ADD(tcase->tests, test);

	return test;
}

struct torture_tcase *torture_suite_add_tcase(struct torture_suite *suite, 
							 const char *name)
{
	struct torture_tcase *tcase = talloc(suite, struct torture_tcase);

	tcase->name = talloc_strdup(tcase, name);
	tcase->description = NULL;
	tcase->setup = NULL;
	tcase->teardown = NULL;
	tcase->fixture_persistent = True;
	tcase->tests = NULL;

	DLIST_ADD(suite->testcases, tcase);

	return tcase;
}

BOOL torture_run_suite(struct torture_context *context, 
					   struct torture_suite *suite)
{
	BOOL ret = True;
	struct torture_tcase *tcase;

	if (context->ui_ops->suite_start)
		context->ui_ops->suite_start(context, suite);

	for (tcase = suite->testcases; tcase; tcase = tcase->next) {
		ret &= torture_run_tcase(context, tcase);
	}

	if (context->ui_ops->suite_finish)
		context->ui_ops->suite_finish(context, suite);
	
	return ret;
}

static BOOL internal_torture_run_test(struct torture_context *context, 
					  struct torture_tcase *tcase,
					  struct torture_test *test,
					  const void *tcase_data)
{
	BOOL ret;
	void *data = NULL;

	if (test->dangerous && !lp_parm_bool(-1, "torture", "dangerous", False)) {
		torture_skip(context, "disabled %s - enable dangerous tests to use", 
					 test->name);
		return True;
	}

	if (!tcase_data && tcase->setup && !tcase->setup(context, &data))
		return False;

	context->active_tcase = tcase;
	context->active_test = test;
	if (context->ui_ops->test_start)
		context->ui_ops->test_start(context, tcase, test);

	ret = test->run(context, tcase->setup?data:tcase->data, test->data);
	context->active_test = NULL;
	context->active_tcase = NULL;

	if (!tcase_data && tcase->teardown && !tcase->teardown(context, data))
		return False;

	return ret;
}

BOOL torture_run_tcase(struct torture_context *context, 
					   struct torture_tcase *tcase)
{
	BOOL ret = True;
	void *data = NULL;
	struct torture_test *test;

	context->active_tcase = tcase;
	if (context->ui_ops->tcase_start)
		context->ui_ops->tcase_start(context, tcase);

	if (tcase->fixture_persistent && tcase->setup 
		&& !tcase->setup(context, &data)) {
		ret = False;
		goto done;
	}

	for (test = tcase->tests; test; test = test->next) {
		ret &= internal_torture_run_test(context, tcase, test, 
									(tcase->setup?data:tcase->data));
	}

	if (tcase->fixture_persistent && tcase->teardown &&
		!tcase->teardown(context, data))
		ret = False;

done:
	context->active_tcase = NULL;

	if (context->ui_ops->tcase_finish)
		context->ui_ops->tcase_finish(context, tcase);

	return ret;
}

BOOL torture_run_test(struct torture_context *context, 
					  struct torture_tcase *tcase,
					  struct torture_test *test)
{
	return internal_torture_run_test(context, tcase, test, NULL);
}

const char *torture_setting(struct torture_context *test, const char *name, 
							const char *default_value)
{
	const char *ret = lp_parm_string(-1, "torture", name);

	if (ret == NULL)
		return default_value;

	return ret;
}

static BOOL simple_tcase_helper(struct torture_context *test, 
								const void *tcase_data,
								const void *test_data)
{
	BOOL (*run) (struct torture_context *, const void *) = test_data;

	return run(test, tcase_data);
}

struct torture_tcase *torture_suite_add_simple_tcase(
					struct torture_suite *suite, 
					const char *name,
					BOOL (*run) (struct torture_context *test, const void *),
					const void *data)
{
	struct torture_tcase *tcase;
	
	tcase = torture_suite_add_tcase(suite, name);
	tcase->data = data;
	
	torture_tcase_add_test(tcase, "Test", simple_tcase_helper, run);

	return tcase;
}

BOOL torture_teardown_free(struct torture_context *torture, void *data)
{
	return talloc_free(data);
}
