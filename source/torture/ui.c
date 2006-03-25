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

struct torture_test *torture_test(struct torture_context *ctx, const char *name, const char *description)
{
	struct torture_test *test = talloc(ctx, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = talloc_strdup(test, description);
	test->context = ctx;

	ctx->ui_ops->test_start(test);

	return test;
}

struct torture_test *torture_subtest(struct torture_test *parent, const char *name, const char *description)
{
	struct torture_test *test = talloc(parent, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = talloc_strdup(test, description);
	test->context = parent->context;

	test->context->ui_ops->test_start(test);
	
	return NULL;
}

void torture_comment(struct torture_test *test, const char *comment, ...)
{
	va_list ap;
	char *tmp;
	va_start(ap, comment);
	tmp = talloc_vasprintf(test, comment, ap);
		
	test->context->ui_ops->comment(test, tmp);
	
	talloc_free(tmp);
}

void torture_ok(struct torture_test *test)
{
	test->context->ui_ops->test_result(test, TORTURE_OK);
}

void torture_fail(struct torture_test *test)
{
	test->context->ui_ops->test_result(test, TORTURE_FAIL);
}

void torture_skip(struct torture_test *test)
{
	test->context->ui_ops->test_result(test, TORTURE_SKIP);
}
