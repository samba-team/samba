/*
   Unix SMB/CIFS implementation.
   SMB torture UI functions

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

#include "source4/include/includes.h"
#include <tevent.h>
#include "../lib/util/talloc_report.h"
#include "../torture/torture.h"
#include "../lib/util/dlinklist.h"
#include "param/param.h"
#include "system/filesys.h"
#include "system/dir.h"


struct torture_results *torture_results_init(TALLOC_CTX *mem_ctx, const struct torture_ui_ops *ui_ops)
{
	struct torture_results *results = talloc_zero(mem_ctx, struct torture_results);

	results->ui_ops = ui_ops;
	results->returncode = true;

	if (ui_ops->init)
		ui_ops->init(results);

	return results;
}

/**
 * Initialize a torture context
 */
struct torture_context *torture_context_init(TALLOC_CTX *mem_ctx,
					     struct tevent_context *event_ctx,
					     struct loadparm_context *lp_ctx,
					     struct torture_results *results,
					     char *outputdir_template)
{
	struct torture_context *torture = NULL;

	SMB_ASSERT(event_ctx);
	SMB_ASSERT(lp_ctx);
	SMB_ASSERT(results);
	SMB_ASSERT(outputdir_template);

	torture = talloc_zero(mem_ctx, struct torture_context);
	if (torture == NULL) {
		return NULL;
	}

	torture->ev = event_ctx;
	torture->lp_ctx = lp_ctx;
	torture->results = results;

	/*
	 * We start with an empty subunit prefix
	 */
	torture_subunit_prefix_reset(torture, NULL);

	torture->outputdir = mkdtemp(outputdir_template);
	if (torture->outputdir == NULL) {
		TALLOC_FREE(torture);
		return NULL;
	}

	return torture;
}

/**
 * Create a sub torture context
 */
struct torture_context *torture_context_child(TALLOC_CTX *mem_ctx,
					      struct torture_context *parent)
{
	struct torture_context *subtorture = NULL;

	SMB_ASSERT(parent);
	SMB_ASSERT(parent->ev);
	SMB_ASSERT(parent->lp_ctx);
	SMB_ASSERT(parent->results);
	SMB_ASSERT(parent->outputdir);

	subtorture = talloc_zero(mem_ctx, struct torture_context);
	if (subtorture == NULL) {
		return NULL;
	}

	subtorture->ev = parent->ev;
	subtorture->lp_ctx = parent->lp_ctx;
	subtorture->results = parent->results;
	subtorture->outputdir = parent->outputdir;

	if (parent->active_prefix != NULL) {
		memcpy(subtorture->_initial_prefix.subunit_prefix,
		       parent->active_prefix->subunit_prefix,
		       sizeof(subtorture->active_prefix->subunit_prefix));
	}
	subtorture->active_prefix = &subtorture->_initial_prefix;

	return subtorture;
}

/**
 create a temporary directory under the output dir
*/
_PUBLIC_ NTSTATUS torture_temp_dir(struct torture_context *tctx,
				   const char *prefix, char **tempdir)
{
	SMB_ASSERT(tctx->outputdir != NULL);

	*tempdir = talloc_asprintf(tctx, "%s/%s.XXXXXX", tctx->outputdir,
				   prefix);
	NT_STATUS_HAVE_NO_MEMORY(*tempdir);

	if (mkdtemp(*tempdir) == NULL) {
		return map_nt_error_from_unix_common(errno);
	}

	return NT_STATUS_OK;
}

static int local_deltree(const char *path)
{
	int ret = 0;
	struct dirent *dirent;
	DIR *dir = opendir(path);
	if (!dir) {
		char *error = talloc_asprintf(NULL, "Could not open directory %s", path);
		perror(error);
		talloc_free(error);
		return -1;
	}
	while ((dirent = readdir(dir))) {
		char *name;
		if ((strcmp(dirent->d_name, ".") == 0) || (strcmp(dirent->d_name, "..") == 0)) {
			continue;
		}
		name = talloc_asprintf(NULL, "%s/%s", path,
				       dirent->d_name);
		if (name == NULL) {
			closedir(dir);
			return -1;
		}
		DEBUG(0, ("About to remove %s\n", name));
		ret = remove(name);
		if (ret == 0) {
			talloc_free(name);
			continue;
		}

		if (errno == ENOTEMPTY) {
			ret = local_deltree(name);
			if (ret == 0) {
				ret = remove(name);
			}
		}
		talloc_free(name);
		if (ret != 0) {
			char *error = talloc_asprintf(NULL, "Could not remove %s", path);
			perror(error);
			talloc_free(error);
			break;
		}
	}
	closedir(dir);
	rmdir(path);
	return ret;
}

_PUBLIC_ NTSTATUS torture_deltree_outputdir(struct torture_context *tctx)
{
	if (tctx->outputdir == NULL) {
		return NT_STATUS_OK;
	}
	if ((strcmp(tctx->outputdir, "/") == 0)
	    || (strcmp(tctx->outputdir, "") == 0)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (local_deltree(tctx->outputdir) == -1) {
		if (errno != 0) {
			return map_nt_error_from_unix_common(errno);
		}
		return NT_STATUS_UNSUCCESSFUL;
	}
	return NT_STATUS_OK;
}

/**
 * Comment on the status/progress of a test
 */
void torture_comment(struct torture_context *context, const char *comment, ...)
{
	va_list ap;
	char *tmp;

	if (!context->results->ui_ops->comment)
		return;

	va_start(ap, comment);
	tmp = talloc_vasprintf(context, comment, ap);
	va_end(ap);

	context->results->ui_ops->comment(context, tmp);

	talloc_free(tmp);
}

/**
 * Print a warning about the current test
 */
void torture_warning(struct torture_context *context, const char *comment, ...)
{
	va_list ap;
	char *tmp;

	if (!context->results->ui_ops->warning)
		return;

	va_start(ap, comment);
	tmp = talloc_vasprintf(context, comment, ap);
	va_end(ap);

	context->results->ui_ops->warning(context, tmp);

	talloc_free(tmp);
}

/**
 * Store the result of a torture test.
 */
void torture_result(struct torture_context *context, 
		    enum torture_result result, const char *fmt, ...)
{
	/* Of the two outcomes, keep that with the higher priority. */
	if (result >= context->last_result) {
		va_list ap;

		va_start(ap, fmt);

		if (context->last_reason) {
			torture_warning(context, "%s", context->last_reason);
			talloc_free(context->last_reason);
		}

		context->last_result = result;
		context->last_reason = talloc_vasprintf(context, fmt, ap);

		va_end(ap);
	}
}

/**
 * Create a new torture suite
 */
struct torture_suite *torture_suite_create(TALLOC_CTX *ctx, const char *name)
{
	struct torture_suite *suite = talloc_zero(ctx, struct torture_suite);

	suite->name = talloc_strdup(suite, name);
	suite->testcases = NULL;
	suite->children = NULL;

	return suite;
}

/**
 * Set the setup() and teardown() functions for a testcase.
 */
void torture_tcase_set_fixture(struct torture_tcase *tcase, 
		bool (*setup) (struct torture_context *, void **),
		bool (*teardown) (struct torture_context *, void *))
{
	tcase->setup = setup;
	tcase->teardown = teardown;
}

static bool wrap_test_with_testcase_const(struct torture_context *torture_ctx,
				    struct torture_tcase *tcase,
				    struct torture_test *test)
{
	bool (*fn) (struct torture_context *,
		    const void *tcase_data,
		    const void *test_data);

	fn = test->fn;

	return fn(torture_ctx, tcase->data, test->data);
}

/**
 * Add a test that uses const data to a testcase
 */
struct torture_test *torture_tcase_add_test_const(struct torture_tcase *tcase,
		const char *name,
		bool (*run) (struct torture_context *, const void *tcase_data,
			const void *test_data),
		const void *data)
{
	struct torture_test *test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_test_with_testcase_const;
	test->fn = run;
	test->dangerous = false;
	test->data = data;

	DLIST_ADD_END(tcase->tests, test);

	return test;
}

/**
 * Add a new testcase
 */
bool torture_suite_init_tcase(struct torture_suite *suite, 
			      struct torture_tcase *tcase, 
			      const char *name)
{
	tcase->name = talloc_strdup(tcase, name);
	tcase->description = NULL;
	tcase->setup = NULL;
	tcase->teardown = NULL;
	tcase->fixture_persistent = true;
	tcase->tests = NULL;

	DLIST_ADD_END(suite->testcases, tcase);
	tcase->suite = suite;

	return true;
}


struct torture_tcase *torture_suite_add_tcase(struct torture_suite *suite, 
							 const char *name)
{
	struct torture_tcase *tcase = talloc(suite, struct torture_tcase);

	if (!torture_suite_init_tcase(suite, tcase, name))
		return NULL;

	return tcase;
}

char *torture_subunit_test_name(struct torture_context *ctx,
				struct torture_tcase *tcase,
				struct torture_test *test)
{
	if (!strcmp(tcase->name, test->name)) {
		return talloc_asprintf(ctx, "%s%s",
				ctx->active_prefix->subunit_prefix,
				test->name);
	} else {
		return talloc_asprintf(ctx, "%s%s.%s",
				ctx->active_prefix->subunit_prefix,
				tcase->name, test->name);
	}
}

void torture_subunit_prefix_reset(struct torture_context *ctx,
				  const char *name)
{
	struct torture_subunit_prefix *prefix = &ctx->_initial_prefix;

	ZERO_STRUCTP(prefix);

	if (name != NULL) {
		int ret;

		ret = snprintf(prefix->subunit_prefix,
			       sizeof(prefix->subunit_prefix),
			       "%s.", name);
		if (ret < 0) {
			abort();
		}
	}

	ctx->active_prefix = prefix;
}

static void torture_subunit_prefix_push(struct torture_context *ctx,
					struct torture_subunit_prefix *prefix,
					const char *name)
{
	*prefix = (struct torture_subunit_prefix) {
		.parent = ctx->active_prefix,
	};

	if (ctx->active_prefix->parent != NULL ||
	    ctx->active_prefix->subunit_prefix[0] != '\0') {
		/*
		 * We need a new component for the prefix.
		 */
		int ret;

		ret = snprintf(prefix->subunit_prefix,
			       sizeof(prefix->subunit_prefix),
			       "%s%s.",
			       ctx->active_prefix->subunit_prefix,
			       name);
		if (ret < 0) {
			abort();
		}
	}

	ctx->active_prefix = prefix;
}

static void torture_subunit_prefix_pop(struct torture_context *ctx)
{
	ctx->active_prefix = ctx->active_prefix->parent;
}

int torture_suite_children_count(const struct torture_suite *suite)
{
	int ret = 0;
	struct torture_tcase *tcase;
	struct torture_test *test;
	struct torture_suite *tsuite;
	for (tcase = suite->testcases; tcase; tcase = tcase->next) {
		for (test = tcase->tests; test; test = test->next) {
			ret++;
		}
	}
	for (tsuite = suite->children; tsuite; tsuite = tsuite->next) {
		ret ++;
	}
	return ret;
}

/**
 * Run a torture test suite.
 */
bool torture_run_suite(struct torture_context *context, 
		       struct torture_suite *suite)
{
	return torture_run_suite_restricted(context, suite, NULL);
}

bool torture_run_suite_restricted(struct torture_context *context, 
		       struct torture_suite *suite, const char **restricted)
{
	struct torture_subunit_prefix _prefix_stack;
	bool ret = true;
	struct torture_tcase *tcase;
	struct torture_suite *tsuite;

	torture_subunit_prefix_push(context, &_prefix_stack, suite->name);

	if (context->results->ui_ops->suite_start)
		context->results->ui_ops->suite_start(context, suite);

	/* FIXME: Adjust torture_suite_children_count if restricted != NULL */
	context->results->ui_ops->progress(context,
		torture_suite_children_count(suite), TORTURE_PROGRESS_SET);

	for (tcase = suite->testcases; tcase; tcase = tcase->next) {
		ret &= torture_run_tcase_restricted(context, tcase, restricted);
	}

	for (tsuite = suite->children; tsuite; tsuite = tsuite->next) {
		context->results->ui_ops->progress(context, 0, TORTURE_PROGRESS_PUSH);
		ret &= torture_run_suite_restricted(context, tsuite, restricted);
		context->results->ui_ops->progress(context, 0, TORTURE_PROGRESS_POP);
	}

	if (context->results->ui_ops->suite_finish)
		context->results->ui_ops->suite_finish(context, suite);

	torture_subunit_prefix_pop(context);

	return ret;
}

void torture_ui_test_start(struct torture_context *context, 
			   struct torture_tcase *tcase, 
			   struct torture_test *test)
{
	if (context->results->ui_ops->test_start)
		context->results->ui_ops->test_start(context, tcase, test);
}

void torture_ui_test_result(struct torture_context *context, 
			    enum torture_result result,
			    const char *comment)
{
	if (context->results->ui_ops->test_result)
		context->results->ui_ops->test_result(context, result, comment);

	if (result == TORTURE_ERROR || result == TORTURE_FAIL)
		context->results->returncode = false;
}

static bool test_needs_running(const char *name, const char **restricted)
{
	int i;
	if (restricted == NULL)
		return true;
	for (i = 0; restricted[i]; i++) {
		if (!strcmp(name, restricted[i]))
			return true;
	}
	return false;
}

static void torture_dummy_signal0_handler(struct tevent_context *ev,
					  struct tevent_signal *se,
					  int signum,
					  int count,
					  void *siginfo,
					  void *private_data)
{
}

static bool internal_torture_run_test(struct torture_context *_context,
					  struct torture_tcase *tcase,
					  struct torture_test *test,
					  bool already_setup,
					  const char **restricted)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct torture_context *context = NULL;
	char *subunit_testname = NULL;
	bool success;
	size_t evtb1 = 0;
	size_t evtb2 = 0;

	if (already_setup) {
		context = _context;
	} else {
		context = torture_context_child(frame, _context);
		if (context == NULL) {
			torture_ui_test_start(_context, tcase, test);
			torture_ui_test_result(_context, TORTURE_ERROR,
					       "torture_context_child() failed");
			TALLOC_FREE(frame);
			return false;
		}
	}

	subunit_testname = torture_subunit_test_name(context, tcase, test);
	if (subunit_testname == NULL) {
		torture_ui_test_start(context, tcase, test);
		torture_ui_test_result(context, TORTURE_ERROR,
				       "torture_subunit_test_name() failed");
		TALLOC_FREE(frame);
		return false;
	}
	talloc_steal(frame, subunit_testname);

	if (!test_needs_running(subunit_testname, restricted)) {
		TALLOC_FREE(frame);
		return true;
	}

	context->active_tcase = tcase;
	context->active_test = test;

	torture_ui_test_start(context, tcase, test);

	if (!already_setup) {
		struct tevent_signal *dummy_se = NULL;
		int rc;

		rc = tevent_re_initialise(context->ev);
		if (rc != 0) {
			torture_ui_test_result(context, TORTURE_ERROR,
					       "tevent_re_initialise() failed");
			TALLOC_FREE(frame);
			return false;
		}

		/*
		 * We call tevent_add_signal() in order
		 * to have tevent_common_wakeup_init()
		 * called.
		 *
		 * So that talloc_total_blocks(context->ev)
		 * gives stable results.
		 */
		dummy_se = tevent_add_signal(context->ev,
					     context,
					     SIGCONT,
					     0, /* sa_flags */
					     torture_dummy_signal0_handler,
					     NULL);
		if (dummy_se == NULL) {
			torture_ui_test_result(context, TORTURE_ERROR,
					       "tevent_add_signal() failed");
			TALLOC_FREE(frame);
			return false;
		}
		TALLOC_FREE(dummy_se);

		evtb1 = talloc_total_blocks(context->ev);
	}

	context->last_reason = NULL;
	context->last_result = TORTURE_OK;

	if (!already_setup && tcase->setup &&
	    !tcase->setup(context, &(tcase->data))) {
		if (context->last_reason == NULL)
			context->last_reason = talloc_strdup(context, "Setup failure");
		context->last_result = TORTURE_ERROR;
		success = false;
	} else if (test->dangerous &&
		   !torture_setting_bool(context, "dangerous", false)) {
		context->last_result = TORTURE_SKIP;
		context->last_reason = talloc_asprintf(context,
		"disabled %s - enable dangerous tests to use", test->name);
		success = true;
	} else {
		success = test->run(context, tcase, test);

		if (!success && context->last_result == TORTURE_OK) {
			if (context->last_reason == NULL)
				context->last_reason = talloc_strdup(context,
					"Unknown error/failure. Missing torture_fail() or torture_assert_*() call?");
			context->last_result = TORTURE_ERROR;
		}
	}

	if (!already_setup && tcase->teardown && !tcase->teardown(context, tcase->data)) {
		if (context->last_reason == NULL)
			context->last_reason = talloc_strdup(context, "Setup failure");
		context->last_result = TORTURE_ERROR;
		success = false;
	}

	torture_ui_test_result(context, context->last_result,
			       context->last_reason);

	if (!already_setup) {
		TALLOC_FREE(context);

		evtb2 = talloc_total_blocks(_context->ev);
		if (evtb1 != evtb2) {
			char *rp = talloc_report_str(frame, _context->ev);
			DBG_ERR("%s: evtb1[%zu] evtb2[%zu]\n%s\n",
				subunit_testname, evtb1, evtb2, rp);
			TALLOC_FREE(rp);
			if (success) {
				SMB_ASSERT(evtb1 == evtb2);
			}
		}
	}

	TALLOC_FREE(frame);
	if (!already_setup) {
		tevent_re_initialise(_context->ev);
	}

	return success;
}

bool torture_run_tcase(struct torture_context *context,
		       struct torture_tcase *tcase)
{
	return torture_run_tcase_restricted(context, tcase, NULL);
}

bool torture_run_tcase_restricted(struct torture_context *_context,
		       struct torture_tcase *tcase, const char **restricted)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct torture_context *context = NULL;
	struct tevent_signal *dummy_se = NULL;
	bool ret = true;
	struct torture_test *test;
	bool setup_succeeded = true;
	const char * setup_reason = "Setup failed";
	enum torture_result fail_result = TORTURE_FAIL;
	size_t evtb1 = 0;
	size_t evtb2 = 0;
	int rc;

	context = torture_context_child(frame, _context);
	if (context == NULL) {
		setup_succeeded = false;
		setup_reason = "torture_context_child() failed";
		fail_result = TORTURE_ERROR;
		context = _context;
		goto setup_failed;
	}

	rc = tevent_re_initialise(context->ev);
	if (rc != 0) {
		setup_succeeded = false;
		setup_reason = "tevent_re_initialise() failed";
		fail_result = TORTURE_ERROR;
		context = _context;
		goto setup_failed;
	}

	/*
	 * We call tevent_add_signal() in order
	 * to have tevent_common_wakeup_init()
	 * called.
	 *
	 * So that talloc_total_blocks(context->ev)
	 * gives stable results.
	 */
	dummy_se = tevent_add_signal(context->ev,
				     context,
				     SIGCONT,
				     0, /* sa_flags */
				     torture_dummy_signal0_handler,
				     NULL);
	if (dummy_se == NULL) {
		setup_succeeded = false;
		setup_reason = "tevent_add_signal() failed";
		fail_result = TORTURE_ERROR;
		context = _context;
		goto setup_failed;
	}
	TALLOC_FREE(dummy_se);

	evtb1 = talloc_total_blocks(context->ev);

setup_failed:

	context->active_tcase = tcase;
	if (context->results->ui_ops->tcase_start) 
		context->results->ui_ops->tcase_start(context, tcase);

	if (setup_succeeded && tcase->fixture_persistent && tcase->setup) {
		setup_succeeded = tcase->setup(context, &tcase->data);
	}

	if (!setup_succeeded) {
		/* Uh-oh. The setup failed, so we can't run any of the tests
		 * in this testcase. The subunit format doesn't specify what
		 * to do here, so we keep the failure reason, and manually
		 * use it to fail every test.
		 */
		if (context->last_reason != NULL) {
			setup_reason = talloc_asprintf(context,
				"Setup failed: %s", context->last_reason);
		}
	}

	for (test = tcase->tests; test; test = test->next) {
		if (setup_succeeded) {
			ret &= internal_torture_run_test(context, tcase, test,
					tcase->fixture_persistent, restricted);
		} else {
			context->active_tcase = tcase;
			context->active_test = test;
			torture_ui_test_start(context, tcase, test);
			torture_ui_test_result(context, fail_result, setup_reason);
		}
	}

	if (setup_succeeded && tcase->fixture_persistent && tcase->teardown &&
		!tcase->teardown(context, tcase->data)) {
		ret = false;
	}

	context->active_tcase = NULL;
	context->active_test = NULL;

	if (context->results->ui_ops->tcase_finish)
		context->results->ui_ops->tcase_finish(context, tcase);

	if (setup_succeeded) {
		if (context != _context) {
			TALLOC_FREE(context);
		}

		evtb2 = talloc_total_blocks(_context->ev);
		if (evtb1 != evtb2) {
			char *rp = talloc_report_str(frame, _context->ev);
			DBG_ERR("%s: evtb1[%zu] evtb2[%zu]\n%s\n",
				tcase->name, evtb1, evtb2, rp);
			TALLOC_FREE(rp);
			if (ret) {
				SMB_ASSERT(evtb1 == evtb2);
			}
		}
	}

	TALLOC_FREE(frame);
	tevent_re_initialise(_context->ev);

	return (!setup_succeeded) ? false : ret;
}

bool torture_run_test(struct torture_context *context, 
					  struct torture_tcase *tcase,
					  struct torture_test *test)
{
	return internal_torture_run_test(context, tcase, test, false, NULL);
}

bool torture_run_test_restricted(struct torture_context *context, 
					  struct torture_tcase *tcase,
					  struct torture_test *test,
					  const char **restricted)
{
	return internal_torture_run_test(context, tcase, test, false, restricted);
}

int torture_setting_int(struct torture_context *test, const char *name, 
							int default_value)
{
	return lpcfg_parm_int(test->lp_ctx, NULL, "torture", name, default_value);
}

unsigned long torture_setting_ulong(struct torture_context *test,
				    const char *name,
				    unsigned long default_value)
{
	return lpcfg_parm_ulong(test->lp_ctx, NULL, "torture", name,
			     default_value);
}

double torture_setting_double(struct torture_context *test, const char *name, 
							double default_value)
{
	return lpcfg_parm_double(test->lp_ctx, NULL, "torture", name, default_value);
}

bool torture_setting_bool(struct torture_context *test, const char *name, 
							bool default_value)
{
	return lpcfg_parm_bool(test->lp_ctx, NULL, "torture", name, default_value);
}

const char *torture_setting_string(struct torture_context *test, 
				   const char *name, 
				   const char *default_value)
{
	const char *ret;

	SMB_ASSERT(test != NULL);
	SMB_ASSERT(test->lp_ctx != NULL);
	
	ret = lpcfg_parm_string(test->lp_ctx, NULL, "torture", name);

	if (ret == NULL)
		return default_value;

	return ret;
}

static bool wrap_test_with_simple_tcase_const (
		struct torture_context *torture_ctx,
		struct torture_tcase *tcase,
		struct torture_test *test)
{
	bool (*fn) (struct torture_context *, const void *tcase_data);

	fn = test->fn;

	return fn(torture_ctx, test->data);
}

struct torture_tcase *torture_suite_add_simple_tcase_const(
		struct torture_suite *suite, const char *name,
		bool (*run) (struct torture_context *test, const void *),
		const void *data)
{
	struct torture_tcase *tcase;
	struct torture_test *test;

	tcase = torture_suite_add_tcase(suite, name);

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_test_with_simple_tcase_const;
	test->fn = run;
	test->data = data;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test);
	test->tcase = tcase;

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

	DLIST_ADD_END(tcase->tests, test);

	return tcase;
}

/**
 * Add a child testsuite to a testsuite.
 */
bool torture_suite_add_suite(struct torture_suite *suite, 
			     struct torture_suite *child)
{
	if (child == NULL)
		return false;

	DLIST_ADD_END(suite->children, child);
	child->parent = suite;

	/* FIXME: Check for duplicates and return false if the 
	 * added suite already exists as a child */

	return true;
}

/**
 * Find the child testsuite with the specified name.
 */
struct torture_suite *torture_find_suite(struct torture_suite *parent, 
					 const char *name)
{
	struct torture_suite *child;

	for (child = parent->children; child; child = child->next) 
		if (!strcmp(child->name, name))
			return child;

	return NULL;
}

static bool wrap_test_with_simple_test_const(struct torture_context *torture_ctx,
				       struct torture_tcase *tcase,
				       struct torture_test *test)
{
	bool (*fn) (struct torture_context *, const void *tcase_data);

	fn = test->fn;

	return fn(torture_ctx, tcase->data);
}

struct torture_test *torture_tcase_add_simple_test_const(
		struct torture_tcase *tcase,
		const char *name,
		bool (*run) (struct torture_context *test,
			const void *tcase_data))
{
	struct torture_test *test;

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_test_with_simple_test_const;
	test->fn = run;
	test->data = NULL;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test);

	return test;
}

static bool wrap_test_with_simple_test(struct torture_context *torture_ctx,
				       struct torture_tcase *tcase,
				       struct torture_test *test)
{
	bool (*fn) (struct torture_context *, void *tcase_data);

	fn = test->fn;

	return fn(torture_ctx, tcase->data);
}

struct torture_test *torture_tcase_add_simple_test(struct torture_tcase *tcase,
		const char *name,
		bool (*run) (struct torture_context *test, void *tcase_data))
{
	struct torture_test *test;

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_test_with_simple_test;
	test->fn = run;
	test->data = NULL;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test);

	return test;
}

void torture_ui_report_time(struct torture_context *context)
{
	if (context->results->ui_ops->report_time)
		context->results->ui_ops->report_time(context);
}
