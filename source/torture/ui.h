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

struct torture_test;

enum torture_result { 
	TORTURE_OK=0, 
	TORTURE_FAIL=1, 
	TORTURE_TODO=2, 
	TORTURE_SKIP=3
};

struct torture_ui_ops
{
	void (*comment) (struct torture_test *, const char *);
	void (*test_start) (struct torture_test *);
	void (*test_result) (struct torture_test *, enum torture_result, 
						 const char *reason);
};

struct torture_test
{
	char *name;
	char *description;

	void *ui_data;

	struct torture_context *context;
};

struct torture_context
{
	const struct torture_ui_ops *ui_ops;
	void *ui_data;

	int skipped;
	int todo;
	int success;
	int failed;
};

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

/* Convenience macros */

#define torture_assert_ntstatus_ok(ctx,expr,string) \
		torture_assert_ntstatus_equal(ctx,expr,NT_STATUS_OK,string)

#define torture_assert_werr_ok(ctx,expr,string) \
		torture_assert_werr_equal(ctx,expr,WERR_OK,string)

struct torture_test *torture_test(struct torture_context *ctx, const char *name, const char *description);
struct torture_test *torture_subtest(struct torture_test *parent, const char *name, const char *description);
void torture_comment(struct torture_test *test, const char *comment, ...) _PRINTF_ATTRIBUTE(2,3);
void torture_ok(struct torture_test *test);
void torture_fail(struct torture_test *test, const char *reason, ...) _PRINTF_ATTRIBUTE(2,3);
void torture_skip(struct torture_test *test, const char *reason, ...) _PRINTF_ATTRIBUTE(2,3);
