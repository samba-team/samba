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
#include "lib/util/dlinklist.h"

void torture_comment(struct torture_context *context, const char *comment, ...)
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

void torture_fail(struct torture_context *context, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	context->last_reason = talloc_vasprintf(context, fmt, ap);
	/* make sure the reason for the failure is displayed */
	context->ui_ops->comment(context, context->last_reason);
	va_end(ap);
	context->last_result = TORTURE_FAIL;
}

void torture_skip(struct torture_context *context, const char *fmt, ...)
{
	va_list ap;
	context->skipped++;

	va_start(ap, fmt);
	context->last_result = TORTURE_SKIP;
	context->last_reason = talloc_vasprintf(context, fmt, ap);
	va_end(ap);
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

	DLIST_ADD_END(tcase->tests, test, struct torture_test *);

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
					  BOOL already_setup,
					  const void *tcase_data)
{
	BOOL ret;
	void *data = NULL;

	if (test->dangerous && !lp_parm_bool(-1, "torture", "dangerous", False)) {
		torture_skip(context, "disabled %s - enable dangerous tests to use", 
					 test->name);
		return True;
	}

	if (!already_setup && tcase->setup && !tcase->setup(context, &data))
		return False;

	context->active_tcase = tcase;
	context->active_test = test;

	if (context->ui_ops->test_start)
		context->ui_ops->test_start(context, tcase, test);

	context->last_reason = NULL;
	context->last_result = TORTURE_OK;

	ret = test->run(context, !already_setup?data:tcase_data, test->data);
	if (!ret) {
		context->last_reason = talloc_strdup(context, "...");
		context->last_result = TORTURE_FAIL;
	}

	if (context->ui_ops->test_result)
		context->ui_ops->test_result(context, context->last_result, 
									 context->last_reason);


	switch (context->last_result) {
		case TORTURE_SKIP: context->success++; break;
		case TORTURE_FAIL: context->failed++; break;
		case TORTURE_TODO: context->todo++; break;
		case TORTURE_OK: context->success++; break;
	}

	talloc_free(context->last_reason);

	context->active_test = NULL;
	context->active_tcase = NULL;

	if (!already_setup && tcase->teardown && !tcase->teardown(context, data))
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
				tcase->fixture_persistent,
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
	return internal_torture_run_test(context, tcase, test, False, NULL);
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

	torture_tcase_add_test(tcase, name, simple_tcase_helper, run);

	return tcase;
}

BOOL torture_teardown_free(struct torture_context *torture, void *data)
{
	return talloc_free(data);
}
