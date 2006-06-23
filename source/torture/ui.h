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
	TORTURE_TODO=2, 
	TORTURE_SKIP=3
};

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
	void (*test_result) (struct torture_context *, enum torture_result, 
						 const char *reason);
};

struct torture_context
{
	const struct torture_ui_ops *ui_ops;
	void *ui_data;

	struct torture_test *active_test;
	struct torture_tcase *active_tcase;

	int skipped;
	int todo;
	int success;
	int failed;

	enum torture_result last_result;
	char *last_reason;
};

struct torture_suite
{
	const char *name;
	const char *description;
	struct torture_tcase {
	    const char *name;
		const char *description;
		BOOL (*setup) (struct torture_context *tcase, void **data);
		BOOL (*teardown) (struct torture_context *tcase, void *data); 
		BOOL fixture_persistent;
		const void *data;
		struct torture_test {
			const char *name;
			const char *description;
			const void *data;
			BOOL dangerous;
			BOOL (*run) (struct torture_context *test, 
						 const void *tcase_data,
						 const void *test_data);
			struct torture_test *prev, *next;
		} *tests;
		struct torture_tcase *prev, *next;
	} *testcases;
};

struct torture_suite *torture_suite_create(TALLOC_CTX *ctx, const char *name);
void torture_tcase_set_fixture(struct torture_tcase *tcase, 
		BOOL (*setup) (struct torture_context *, void **),
		BOOL (*teardown) (struct torture_context *, void *));
struct torture_test *torture_tcase_add_test(struct torture_tcase *tcase, 
		const char *name, 
		BOOL (*run) (struct torture_context *test, const void *tcase_data,
					 const void *test_data),
		const void *test_data);
struct torture_tcase *torture_suite_add_tcase(struct torture_suite *suite, 
							 const char *name);
struct torture_tcase *torture_suite_add_simple_tcase(
		struct torture_suite *suite, 
		const char *name,
		BOOL (*run) (struct torture_context *test, const void *test_data),
		const void *data);

BOOL torture_run_suite(struct torture_context *context, 
					   struct torture_suite *suite);

BOOL torture_run_tcase(struct torture_context *context, 
					   struct torture_tcase *tcase);

BOOL torture_run_test(struct torture_context *context, 
					  struct torture_tcase *tcase,
					  struct torture_test *test);

#define torture_assert(ctx,expr,string) \
	if (!(expr)) { \
		torture_fail(ctx, "%s:%d (%s): %s", __FILE__, __LINE__, string, \
					 __STRING(expr)); \
		return False; \
	}

#define torture_assert_werr_equal(ctx,got,expected,string) \
	if (!W_ERROR_EQUAL(got, expected)) { \
		torture_fail(ctx, "%s:%d (%s): got %s, expected %s", __FILE__, \
					 __LINE__, string, win_errstr(got), win_errstr(expected)); \
		return False; \
	}

#define torture_assert_ntstatus_equal(ctx,got,expected,string) \
	if (!NT_STATUS_EQUAL(got, expected)) { \
		torture_fail(ctx, "%s:%d (%s): got %s, expected %s", __FILE__, \
					 __LINE__, string, nt_errstr(got), nt_errstr(expected)); \
		return False; \
	}

#define torture_assert_casestr_equal(ctx,got,expected,string) \
	if (strcasecmp(got, expected) != 0) { \
		torture_fail(ctx, "%s:%d (%s): got %s, expected %s", __FILE__, \
					 __LINE__, string, got, expected); \
		return False; \
	}

#define torture_assert_str_equal(ctx,got,expected,string) \
	if (strcmp(got, expected) != 0) { \
		torture_fail(ctx, "%s:%d (%s): got %s, expected %s", __FILE__, \
					 __LINE__, string, got, expected); \
		return False; \
	}


/* Convenience macros */

#define torture_assert_ntstatus_ok(ctx,expr,string) \
		torture_assert_ntstatus_equal(ctx,expr,NT_STATUS_OK,string)

#define torture_assert_werr_ok(ctx,expr,string) \
		torture_assert_werr_equal(ctx,expr,WERR_OK,string)

void torture_comment(struct torture_context *test, const char *comment, ...) PRINTF_ATTRIBUTE(2,3);
void torture_fail(struct torture_context *test, const char *reason, ...) PRINTF_ATTRIBUTE(2,3);
void torture_skip(struct torture_context *test, const char *reason, ...) PRINTF_ATTRIBUTE(2,3);
const char *torture_setting(struct torture_context *test, const char *name, 
							const char *default_value);

/* Helper function commonly used */
BOOL torture_teardown_free(struct torture_context *torture, void *data);

#endif /* __TORTURE_UI_H__ */
