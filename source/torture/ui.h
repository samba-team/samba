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

#ifndef __TORTURE_UI_H__
#define __TORTURE_UI_H__

struct torture_test;
struct torture_context;
struct torture_suite;
struct torture_tcase;

enum torture_result { 
	TORTURE_OK=0, 
	TORTURE_FAIL=1,
	TORTURE_ERROR=2,
	TORTURE_SKIP=3
};

/* 
 * These callbacks should be implemented by any backend that wishes 
 * to listen to reports from the torture tests.
 */
struct torture_ui_ops
{
	void (*comment) (struct torture_context *, const char *);
	void (*suite_start) (struct torture_context *, struct torture_suite *);
	void (*suite_finish) (struct torture_context *, struct torture_suite *);
	void (*tcase_start) (struct torture_context *, struct torture_tcase *); 
	void (*tcase_finish) (struct torture_context *, struct torture_tcase *);
	void (*test_start) (struct torture_context *, 
						struct torture_tcase *,
						struct torture_test *);
	void (*test_result) (struct torture_context *, 
						 enum torture_result, const char *reason);
};

void torture_ui_test_start(struct torture_context *context,
							   struct torture_tcase *tcase,
							   struct torture_test *test);

void torture_ui_test_result(struct torture_context *context,
								enum torture_result result,
								const char *comment);

/*
 * Holds information about a specific run of the testsuite. 
 * The data in this structure should be considered private to 
 * the torture tests and should only be used directly by the torture 
 * code and the ui backends.
 *
 * Torture tests should instead call the torture_*() macros and functions 
 * specified below.
 */

struct torture_context
{
	const struct torture_ui_ops *ui_ops;
	void *ui_data;

	char *active_testname;
	struct torture_test *active_test;
	struct torture_tcase *active_tcase;

	char **expected_failures;

	struct torture_results {
		int skipped;
		int todo;
		int success;
		int failed;
		int errors;

		const char **unexpected_failures;
		const char **unexpected_successes;
		const char **unexpected_errors;

		bool returncode;
	} results;

	bool quiet; /* Whether tests should avoid writing output to stdout */

	enum torture_result last_result;
	char *last_reason;

	char *outputdir;
	int level;
};

/* 
 * Describes a particular torture test
 */
struct torture_test {
	const char *name;
	const char *description;
	bool dangerous;
	/* Function to call to run this test */
	bool (*run) (struct torture_context *torture_ctx, 
				 struct torture_tcase *tcase,
				 struct torture_test *test);

	struct torture_test *prev, *next;

	/* Pointer to the actual test function. This is run by the 
	 * run() function above. */
	void *fn;
	const void *data;
};

/* 
 * Describes a particular test case.
 */
struct torture_tcase {
    const char *name;
	const char *description;
	bool (*setup) (struct torture_context *tcase, void **data);
	bool (*teardown) (struct torture_context *tcase, void *data); 
	bool fixture_persistent;
	void *data;
	struct torture_test *tests;
	struct torture_tcase *prev, *next;
};

struct torture_suite
{
	const char *name;
	const char *path; /* Used by subunit tests only */
	const char *description;
	struct torture_tcase *testcases;
	struct torture_suite *children;

	/* Pointers to siblings of this torture suite */
	struct torture_suite *prev, *next;
};

/** Create a new torture suite */
struct torture_suite *torture_suite_create(TALLOC_CTX *mem_ctx, 
										   const char *name);

/** Change the setup and teardown functions for a testcase */
void torture_tcase_set_fixture(struct torture_tcase *tcase, 
		bool (*setup) (struct torture_context *, void **),
		bool (*teardown) (struct torture_context *, void *));

/* Add another test to run for a particular testcase */
struct torture_test *torture_tcase_add_test(struct torture_tcase *tcase, 
		const char *name, 
		bool (*run) (struct torture_context *test, const void *tcase_data,
					 const void *test_data),
		const void *test_data);

/* Add a testcase to a testsuite */
struct torture_tcase *torture_suite_add_tcase(struct torture_suite *suite, 
							 const char *name);

/* Convenience wrapper that adds a testcase against only one 
 * test will be run */
struct torture_tcase *torture_suite_add_simple_tcase(
		struct torture_suite *suite, 
		const char *name,
		bool (*run) (struct torture_context *test, const void *test_data),
		const void *data);

/* Convenience wrapper that adds a test that doesn't need any 
 * testcase data */
struct torture_tcase *torture_suite_add_simple_test(
		struct torture_suite *suite, 
		const char *name,
		bool (*run) (struct torture_context *test));

/* Add a child testsuite to an existing testsuite */
bool torture_suite_add_suite(struct torture_suite *suite,
							 struct torture_suite *child);

/* Run the specified testsuite recursively */
bool torture_run_suite(struct torture_context *context, 
					   struct torture_suite *suite);

/* Run the specified testcase */
bool torture_run_tcase(struct torture_context *context, 
					   struct torture_tcase *tcase);

/* Run the specified test */
bool torture_run_test(struct torture_context *context, 
					  struct torture_tcase *tcase,
					  struct torture_test *test);

void torture_comment(struct torture_context *test, const char *comment, ...) PRINTF_ATTRIBUTE(2,3);
void torture_result(struct torture_context *test, 
			enum torture_result, const char *reason, ...) PRINTF_ATTRIBUTE(3,4);

#define torture_assert(torture_ctx,expr,cmt) \
	if (!(expr)) { \
		torture_result(torture_ctx, TORTURE_FAIL, __location__": Expression `%s' failed: %s", __STRING(expr), cmt); \
		return false; \
	}

#define torture_assert_werr_equal(torture_ctx, got, expected, cmt) \
	do { WERROR __got = got, __expected = expected; \
	if (!W_ERROR_EQUAL(__got, __expected)) { \
		torture_result(torture_ctx, TORTURE_FAIL, __location__": "#got" was %s, expected %s: %s", win_errstr(__got), win_errstr(__expected), cmt); \
		return false; \
	} \
	} while (0)

#define torture_assert_ntstatus_equal(torture_ctx,got,expected,cmt) \
	do { NTSTATUS __got = got, __expected = expected; \
	if (!NT_STATUS_EQUAL(__got, __expected)) { \
		torture_result(torture_ctx, TORTURE_FAIL, __location__": "#got" was %s, expected %s: %s", nt_errstr(__got), nt_errstr(__expected), cmt); \
		return false; \
	}\
	} while(0)


#define torture_assert_casestr_equal(torture_ctx,got,expected,cmt) \
	do { const char *__got = (got), *__expected = (expected); \
	if (!strequal(__got, __expected)) { \
		torture_result(torture_ctx, TORTURE_FAIL, __location__": "#got" was %s, expected %s: %s", __got, __expected, cmt); \
		return false; \
	} \
	} while(0)

#define torture_assert_str_equal(torture_ctx,got,expected,cmt)\
	do { const char *__got = (got), *__expected = (expected); \
	if (strcmp_safe(__got, __expected) != 0) { \
		torture_result(torture_ctx, TORTURE_FAIL, \
					   __location__": "#got" was %s, expected %s: %s", \
					   __got, __expected, cmt); \
		return false; \
	} \
	} while(0)

#define torture_assert_int_equal(torture_ctx,got,expected,cmt)\
	do { int __got = (got), __expected = (expected); \
	if (__got != __expected) { \
		torture_result(torture_ctx, TORTURE_FAIL, \
					 __location__": "#got" was %d, expected %d: %s", \
					   __got, __expected, cmt); \
		return false; \
	} \
	} while(0)

#define torture_assert_errno_equal(torture_ctx,expected,cmt)\
	do { int __expected = (expected); \
	if (errno != __expected) { \
		torture_result(torture_ctx, TORTURE_FAIL, \
			__location__": errno was %d (%s), expected %d: %s: %s", \
					   errno, strerror(errno), __expected, \
					   strerror(__expected), cmt); \
		return false; \
	} \
	} while(0)



#define torture_skip(torture_ctx,cmt) do {\
		torture_result(torture_ctx, TORTURE_SKIP, __location__": %s", cmt);\
		return true; \
	} while(0)
#define torture_fail(torture_ctx,cmt) do {\
		torture_result(torture_ctx, TORTURE_FAIL, __location__": %s", cmt);\
		return false; \
	} while (0)

#define torture_out stderr

/* Convenience macros */
#define torture_assert_ntstatus_ok(torture_ctx,expr,cmt) \
		torture_assert_ntstatus_equal(torture_ctx,expr,NT_STATUS_OK,cmt)

#define torture_assert_werr_ok(torture_ctx,expr,cmt) \
		torture_assert_werr_equal(torture_ctx,expr,WERR_OK,cmt)

/* Getting settings */
const char *torture_setting_string(struct torture_context *test, \
								   const char *name, 
								   const char *default_value);

int torture_setting_int(struct torture_context *test, 
						const char *name, 
						int default_value);

bool torture_setting_bool(struct torture_context *test, 
						  const char *name, 
						  bool default_value);

struct torture_suite *torture_find_suite(struct torture_suite *parent, 
										 const char *name);


#endif /* __TORTURE_UI_H__ */
