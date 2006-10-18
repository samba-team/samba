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
#include "torture/torture.h"
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

void torture_result(struct torture_context *context, 
					enum torture_result result, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	context->last_result = result;
	context->last_reason = talloc_vasprintf(context, fmt, ap);
	va_end(ap);
}

struct torture_suite *torture_suite_create(TALLOC_CTX *ctx, const char *name)
{
	struct torture_suite *suite = talloc_zero(ctx, struct torture_suite);

	suite->name = talloc_strdup(suite, name);
	suite->testcases = NULL;
	suite->children = NULL;

	return suite;
}

void torture_tcase_set_fixture(struct torture_tcase *tcase, 
		BOOL (*setup) (struct torture_context *, void **),
		BOOL (*teardown) (struct torture_context *, void *))
{
	tcase->setup = setup;
	tcase->teardown = teardown;
}

static bool wrap_test_with_testcase(struct torture_context *torture_ctx,
									struct torture_tcase *tcase,
									struct torture_test *test)
{
	bool (*fn) (struct torture_context *, 
				 const void *tcase_data,
				 const void *test_data);

	fn = test->fn;

	return fn(torture_ctx, tcase->data, test->data);
}

struct torture_test *torture_tcase_add_test(struct torture_tcase *tcase, 
						const char *name, 
						bool (*run) (struct torture_context *, 
									 const void *tcase_data,
									 const void *test_data),
						const void *data)
{
	struct torture_test *test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_test_with_testcase;
	test->fn = run;
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

	DLIST_ADD_END(suite->testcases, tcase, struct torture_tcase *);

	return tcase;
}

BOOL torture_run_suite(struct torture_context *context, 
					   struct torture_suite *suite)
{
	BOOL ret = True;
	struct torture_tcase *tcase;
	struct torture_suite *tsuite;
	char *old_testname;

	context->level++;
	if (context->ui_ops->suite_start)
		context->ui_ops->suite_start(context, suite);

	old_testname = context->active_testname;
	if (context->active_testname)
		context->active_testname = talloc_asprintf(context, "%s-%s", 
											   old_testname, suite->name);
	else
		context->active_testname = talloc_strdup(context, suite->name);

	if (suite->path)
		ret &= torture_subunit_run_suite(context, suite);

	for (tcase = suite->testcases; tcase; tcase = tcase->next) {
		ret &= torture_run_tcase(context, tcase);
	}

	for (tsuite = suite->children; tsuite; tsuite = tsuite->next) {
		ret &= torture_run_suite(context, tsuite);
	}

	talloc_free(context->active_testname);
	context->active_testname = old_testname;

	if (context->ui_ops->suite_finish)
		context->ui_ops->suite_finish(context, suite);

	context->level--;
	
	return ret;
}

void torture_ui_test_start(struct torture_context *context,
							   struct torture_tcase *tcase,
							   struct torture_test *test)
{
	if (context->ui_ops->test_start)
		context->ui_ops->test_start(context, tcase, test);
}

int str_list_match(const char *name, char **list)
{
	int i, ret = 0;
	if (list == NULL)
		return 0;

	for (i = 0; list[i]; i++) {
		if (gen_fnmatch(list[i], name) == 0)
			ret++;
	}
	return ret;
}

void torture_ui_test_result(struct torture_context *context,
								enum torture_result result,
								const char *comment)
{
	if (context->ui_ops->test_result)
		context->ui_ops->test_result(context, result, comment);

	if (result == TORTURE_SKIP) {
		context->results.skipped++;
	} else if (result == TORTURE_OK) {
		if (str_list_match(context->active_testname, 
						   context->expected_failures)) {
			context->results.unexpected_successes = str_list_add(
					context->results.unexpected_successes, 
					talloc_reference(context, context->active_testname));
		} 
		context->results.success++;
	} else if (result == TORTURE_ERROR) {
		context->results.unexpected_errors = str_list_add(
					context->results.unexpected_errors, 
					talloc_reference(context, context->active_testname));
		context->results.errors++;
		context->results.returncode = false;
	} else if (result == TORTURE_FAIL) {
		if (0 == str_list_match(context->active_testname, 
						   context->expected_failures)) {
			context->results.unexpected_failures = str_list_add(
					context->results.unexpected_failures, 
					talloc_reference(context, context->active_testname));
			context->results.returncode = false;
		} 
		context->results.failed++;
	}
}

static BOOL internal_torture_run_test(struct torture_context *context, 
					  struct torture_tcase *tcase,
					  struct torture_test *test,
					  BOOL already_setup)
{
	BOOL ret;
	char *old_testname;

	if (test->dangerous && !torture_setting_bool(context, "dangerous", False)) {
		torture_result(context, TORTURE_SKIP,
				"disabled %s - enable dangerous tests to use", test->name);
		return True;
	}

	if (!already_setup && tcase->setup && 
		!tcase->setup(context, &(tcase->data)))
		return False;

	if (tcase == NULL || strcmp(test->name, tcase->name) != 0) { 
		old_testname = context->active_testname;
		context->active_testname = talloc_asprintf(context, "%s-%s", 
											   old_testname, test->name);
	}
	context->active_tcase = tcase;
	context->active_test = test;

	torture_ui_test_start(context, tcase, test);


	context->last_reason = NULL;
	context->last_result = TORTURE_OK;

	ret = test->run(context, tcase, test);
	if (!ret && context->last_result == TORTURE_OK) {
		if (context->last_reason == NULL)
			context->last_reason = talloc_strdup(context, "Unknown error/failure");
		context->last_result = TORTURE_ERROR;
	}

	torture_ui_test_result(context, context->last_result, context->last_reason);
	
	talloc_free(context->last_reason);

	if (tcase == NULL || strcmp(test->name, tcase->name) != 0) { 
		talloc_free(context->active_testname);
		context->active_testname = old_testname;
	}
	context->active_test = NULL;
	context->active_tcase = NULL;

	if (!already_setup && tcase->teardown && !tcase->teardown(context, tcase->data))
		return False;

	return ret;
}

BOOL torture_run_tcase(struct torture_context *context, 
					   struct torture_tcase *tcase)
{
	BOOL ret = True;
	char *old_testname;
	struct torture_test *test;

	context->level++;

	context->active_tcase = tcase;
	if (context->ui_ops->tcase_start)
		context->ui_ops->tcase_start(context, tcase);

	if (tcase->fixture_persistent && tcase->setup 
		&& !tcase->setup(context, &tcase->data)) {
		ret = False;
		goto done;
	}

	old_testname = context->active_testname;
	context->active_testname = talloc_asprintf(context, "%s-%s", 
											   old_testname, tcase->name);
	for (test = tcase->tests; test; test = test->next) {
		ret &= internal_torture_run_test(context, tcase, test, 
				tcase->fixture_persistent);
	}
	talloc_free(context->active_testname);
	context->active_testname = old_testname;

	if (tcase->fixture_persistent && tcase->teardown &&
		!tcase->teardown(context, tcase->data))
		ret = False;

done:
	context->active_tcase = NULL;

	if (context->ui_ops->tcase_finish)
		context->ui_ops->tcase_finish(context, tcase);

	context->level--;

	return ret;
}

BOOL torture_run_test(struct torture_context *context, 
					  struct torture_tcase *tcase,
					  struct torture_test *test)
{
	return internal_torture_run_test(context, tcase, test, False);
}

int torture_setting_int(struct torture_context *test, const char *name, 
							int default_value)
{
	return lp_parm_int(-1, "torture", name, default_value);
}

bool torture_setting_bool(struct torture_context *test, const char *name, 
							bool default_value)
{
	return lp_parm_bool(-1, "torture", name, default_value);
}

const char *torture_setting_string(struct torture_context *test, const char *name, 
							const char *default_value)
{
	const char *ret = lp_parm_string(-1, "torture", name);

	if (ret == NULL)
		return default_value;

	return ret;
}

static bool wrap_test_with_simple_tcase(struct torture_context *torture_ctx,
									struct torture_tcase *tcase,
									struct torture_test *test)
{
	bool (*fn) (struct torture_context *, const void *tcase_data);

	fn = test->fn;

	return fn(torture_ctx, test->data);
}

struct torture_tcase *torture_suite_add_simple_tcase(
					struct torture_suite *suite, 
					const char *name,
					bool (*run) (struct torture_context *test, const void *),
					const void *data)
{
	struct torture_tcase *tcase;
	struct torture_test *test; 
	
	tcase = torture_suite_add_tcase(suite, name);

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_test_with_simple_tcase;
	test->fn = run;
	test->data = data;
	test->dangerous = False;

	DLIST_ADD_END(tcase->tests, test, struct torture_test *);

	return tcase;
}

static bool wrap_simple_test(struct torture_context *torture_ctx,
									struct torture_tcase *tcase,
									struct torture_test *test)
{
	bool (*fn) (struct torture_context *);

	fn = test->fn;

	return fn(torture_ctx);
}

struct torture_tcase *torture_suite_add_simple_test(
					struct torture_suite *suite, 
					const char *name,
					bool (*run) (struct torture_context *test))
{
	struct torture_test *test; 
	struct torture_tcase *tcase;
	
	tcase = torture_suite_add_tcase(suite, name);

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_simple_test;
	test->fn = run;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test, struct torture_test *);

	return tcase;
}

bool torture_suite_add_suite(struct torture_suite *suite, 
							 struct torture_suite *child)
{
	if (child == NULL)
		return false;

	DLIST_ADD_END(suite->children, child, struct torture_suite *);

	/* FIXME: Check for duplicates and return false if the 
	 * added suite already exists as a child */

	return true;
}


struct torture_suite *torture_find_suite(struct torture_suite *parent, 
										 const char *name)
{
	struct torture_suite *child;

	for (child = parent->children; child; child = child->next) 
		if (!strcmp(child->name, name))
			return child;

	return NULL;
}
