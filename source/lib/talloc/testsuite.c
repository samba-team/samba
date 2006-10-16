/* 
   Unix SMB/CIFS implementation.

   local testing of talloc routines.

   Copyright (C) Andrew Tridgell 2004
   
     ** NOTE! The following LGPL license applies to the talloc
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "replace.h"
#include "system/time.h"
#include "talloc.h"
#ifdef _SAMBA_BUILD_
#include "includes.h"
#include "torture/ui.h"
#else
#define torture_comment printf
#define torture_assert(tctx, expr, str) if (!(expr)) { printf str; return false; }
#define torture_suite_add_simple_tcase(suite,name,fn) \
	ret &= printf("TESTING %s\n", name), fn();
#define torture_out stdout

struct torture_suite;

static struct timeval timeval_current(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv;
}

static double timeval_elapsed(struct timeval *tv)
{
	struct timeval tv2 = timeval_current();
	return (tv2.tv_sec - tv->tv_sec) + 
	       (tv2.tv_usec - tv->tv_usec)*1.0e-6;
}
#endif /* _SAMBA_BUILD_ */

#if _SAMBA_BUILD_==3
#ifdef malloc
#undef malloc
#endif
#ifdef strdup
#undef strdup
#endif
#endif

#define CHECK_SIZE(ptr, tsize) do { \
	if (talloc_total_size(ptr) != (tsize)) { \
		torture_comment(tctx, talloc_asprintf(tctx, "failed: wrong '%s' tree size: got %u  expected %u\n", \
		       #ptr, \
		       (unsigned)talloc_total_size(ptr), \
		       (unsigned)tsize)); \
		talloc_report_full(ptr, stdout); \
		return false; \
	} \
} while (0)

#define CHECK_BLOCKS(ptr, tblocks) do { \
	if (talloc_total_blocks(ptr) != (tblocks)) { \
		torture_comment(tctx, talloc_asprintf(tctx, "failed: wrong '%s' tree blocks: got %u  expected %u\n", \
		       #ptr, \
		       (unsigned)talloc_total_blocks(ptr), \
		       (unsigned)tblocks)); \
		talloc_report_full(ptr, stdout); \
		return false; \
	} \
} while (0)

#define CHECK_PARENT(ptr, parent) do { \
	if (talloc_parent(ptr) != (parent)) { \
		torture_comment(tctx, talloc_asprintf(tctx, "failed: '%s' has wrong parent: got %p  expected %p\n", \
		       #ptr, \
		       talloc_parent(ptr), \
		       (parent))); \
		talloc_report_full(ptr, stdout); \
		talloc_report_full(parent, stdout); \
		talloc_report_full(NULL, stdout); \
		return false; \
	} \
} while (0)


/*
  test references 
*/
static bool test_ref1(struct torture_context *tctx)
{
	void *root, *p1, *p2, *ref, *r1;

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	p2 = talloc_named_const(p1, 1, "p2");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 2, "x2");
	talloc_named_const(p1, 3, "x3");

	r1 = talloc_named_const(root, 1, "r1");	
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 2);

	torture_comment(tctx, "Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 1);

	torture_comment(tctx, "Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(r1, 1);

	torture_comment(tctx, "Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(NULL, torture_out);

	torture_comment(tctx, "Testing NULL\n");
	if (talloc_reference(root, NULL)) {
		return false;
	}

	CHECK_BLOCKS(root, 1);

	CHECK_SIZE(root, 0);

	talloc_free(root);
	return true;
}

/*
  test references 
*/
static bool test_ref2(struct torture_context *tctx)
{
	void *root, *p1, *p2, *ref, *r1;

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");
	p2 = talloc_named_const(p1, 1, "p2");

	r1 = talloc_named_const(root, 1, "r1");	
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 2);

	torture_comment(tctx, "Freeing ref\n");
	talloc_free(ref);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 1);

	torture_comment(tctx, "Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 4);
	CHECK_BLOCKS(r1, 1);

	torture_comment(tctx, "Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(r1, 1);

	torture_comment(tctx, "Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(root, torture_out);

	CHECK_SIZE(root, 0);

	talloc_free(root);
	return true;
}

/*
  test references 
*/
static bool test_ref3(struct torture_context *tctx)
{
	void *root, *p1, *p2, *ref, *r1;

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	p2 = talloc_named_const(root, 1, "p2");
	r1 = talloc_named_const(p1, 1, "r1");
	ref = talloc_reference(p2, r1);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 2);
	CHECK_BLOCKS(p2, 2);
	CHECK_BLOCKS(r1, 1);

	torture_comment(tctx, "Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p2, 2);
	CHECK_BLOCKS(r1, 1);

	torture_comment(tctx, "Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, torture_out);

	CHECK_SIZE(root, 0);

	talloc_free(root);
	return true;
}

/*
  test references 
*/
static bool test_ref4(struct torture_context *tctx)
{
	void *root, *p1, *p2, *ref, *r1;

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");
	p2 = talloc_named_const(p1, 1, "p2");

	r1 = talloc_named_const(root, 1, "r1");	
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 2);

	torture_comment(tctx, "Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);

	torture_comment(tctx, "Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 4);

	torture_comment(tctx, "Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, torture_out);

	CHECK_SIZE(root, 0);

	talloc_free(root);
	return true;
}


/*
  test references 
*/
static bool test_unlink1(struct torture_context *tctx)
{
	void *root, *p1, *p2, *ref, *r1;

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");
	p2 = talloc_named_const(p1, 1, "p2");

	r1 = talloc_named_const(p1, 1, "r1");	
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 7);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 2);

	torture_comment(tctx, "Unreferencing r1\n");
	talloc_unlink(r1, p2);
	talloc_report_full(root, torture_out);

	CHECK_BLOCKS(p1, 6);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 1);

	torture_comment(tctx, "Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, torture_out);

	CHECK_SIZE(root, 0);

	talloc_free(root);
	return true;
}

static int fail_destructor(void *ptr)
{
	return -1;
}

/*
  miscellaneous tests to try to get a higher test coverage percentage
*/
static bool test_misc(struct torture_context *tctx)
{
	void *root, *p1;
	char *p2;
	double *d;
	const char *name;

	root = talloc_new(NULL);

	p1 = talloc_size(root, 0x7fffffff);
	torture_assert(tctx, !p1, "failed: large talloc allowed\n");

	p1 = talloc_strdup(root, "foo");
	talloc_increase_ref_count(p1);
	talloc_increase_ref_count(p1);
	talloc_increase_ref_count(p1);
	CHECK_BLOCKS(p1, 1);
	CHECK_BLOCKS(root, 2);
	talloc_free(p1);
	CHECK_BLOCKS(p1, 1);
	CHECK_BLOCKS(root, 2);
	talloc_unlink(NULL, p1);
	CHECK_BLOCKS(p1, 1);
	CHECK_BLOCKS(root, 2);
	p2 = talloc_strdup(p1, "foo");
	torture_assert(tctx, talloc_unlink(root, p2) == -1,
				   "failed: talloc_unlink() of non-reference context should return -1\n");
	torture_assert(tctx, talloc_unlink(p1, p2) == 0,
		"failed: talloc_unlink() of parent should succeed\n");
	talloc_free(p1);
	CHECK_BLOCKS(p1, 1);
	CHECK_BLOCKS(root, 2);

	name = talloc_set_name(p1, "my name is %s", "foo");
	torture_assert_str_equal(tctx, talloc_get_name(p1), "my name is foo",
		"failed: wrong name after talloc_set_name(my name is foo)");
	CHECK_BLOCKS(p1, 2);
	CHECK_BLOCKS(root, 3);

	talloc_set_name_const(p1, NULL);
	torture_assert_str_equal (tctx, talloc_get_name(p1), "UNNAMED",
		"failed: wrong name after talloc_set_name(NULL)");
	CHECK_BLOCKS(p1, 2);
	CHECK_BLOCKS(root, 3);
	

	torture_assert(tctx, talloc_free(NULL) == -1, 
				   "talloc_free(NULL) should give -1\n");

	talloc_set_destructor(p1, fail_destructor);
	torture_assert(tctx, talloc_free(p1) == -1, 
		"Failed destructor should cause talloc_free to fail\n");
	talloc_set_destructor(p1, NULL);

	talloc_report(root, torture_out);


	p2 = (char *)talloc_zero_size(p1, 20);
	torture_assert(tctx, p2[19] == 0, "Failed to give zero memory\n");
	talloc_free(p2);

	torture_assert(tctx, talloc_strdup(root, NULL) == NULL,
		"failed: strdup on NULL should give NULL\n");

	p2 = talloc_strndup(p1, "foo", 2);
	torture_assert(tctx, strcmp("fo", p2) == 0, "failed: strndup doesn't work\n");
	p2 = talloc_asprintf_append(p2, "o%c", 'd');
	torture_assert(tctx, strcmp("food", p2) == 0, 
				   "failed: talloc_asprintf_append doesn't work\n");
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(p1, 3);

	p2 = talloc_asprintf_append(NULL, "hello %s", "world");
	torture_assert(tctx, strcmp("hello world", p2) == 0,
		"failed: talloc_asprintf_append doesn't work\n");
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(p1, 3);
	talloc_free(p2);

	d = talloc_array(p1, double, 0x20000000);
	torture_assert(tctx, !d, "failed: integer overflow not detected\n");

	d = talloc_realloc(p1, d, double, 0x20000000);
	torture_assert(tctx, !d, "failed: integer overflow not detected\n");

	talloc_free(p1);
	CHECK_BLOCKS(root, 1);

	p1 = talloc_named(root, 100, "%d bytes", 100);
	CHECK_BLOCKS(p1, 2);
	CHECK_BLOCKS(root, 3);
	talloc_unlink(root, p1);

	p1 = talloc_init("%d bytes", 200);
	p2 = talloc_asprintf(p1, "my test '%s'", "string");
	torture_assert_str_equal(tctx, p2, "my test 'string'",
		"failed: talloc_asprintf(\"my test '%%s'\", \"string\") gave: \"%s\"");
	CHECK_BLOCKS(p1, 3);
	CHECK_SIZE(p2, 17);
	CHECK_BLOCKS(root, 1);
	talloc_unlink(NULL, p1);

	p1 = talloc_named_const(root, 10, "p1");
	p2 = (char *)talloc_named_const(root, 20, "p2");
	(void)talloc_reference(p1, p2);
	talloc_report_full(root, torture_out);
	talloc_unlink(root, p2);
	talloc_report_full(root, torture_out);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(p1, 2);
	CHECK_BLOCKS(root, 3);
	talloc_unlink(p1, p2);
	talloc_unlink(root, p1);

	p1 = talloc_named_const(root, 10, "p1");
	p2 = (char *)talloc_named_const(root, 20, "p2");
	(void)talloc_reference(NULL, p2);
	talloc_report_full(root, torture_out);
	talloc_unlink(root, p2);
	talloc_report_full(root, torture_out);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(p1, 1);
	CHECK_BLOCKS(root, 2);
	talloc_unlink(NULL, p2);
	talloc_unlink(root, p1);

	/* Test that talloc_unlink is a no-op */

	torture_assert(tctx, talloc_unlink(root, NULL) == -1,
		"failed: talloc_unlink(root, NULL) == -1\n");

	talloc_report(root, torture_out);
	talloc_report(NULL, torture_out);

	CHECK_SIZE(root, 0);

	talloc_free(root);

	CHECK_SIZE(NULL, 0);

	talloc_enable_leak_report();
	talloc_enable_leak_report_full();
	return true;
}


/*
  test realloc
*/
static bool test_realloc(struct torture_context *tctx)
{
	void *root, *p1, *p2;

	root = talloc_new(NULL);

	p1 = talloc_size(root, 10);
	CHECK_SIZE(p1, 10);

	p1 = talloc_realloc_size(NULL, p1, 20);
	CHECK_SIZE(p1, 20);

	talloc_new(p1);

	p2 = talloc_realloc_size(p1, NULL, 30);

	talloc_new(p1);

	p2 = talloc_realloc_size(p1, p2, 40);

	CHECK_SIZE(p2, 40);
	CHECK_SIZE(root, 60);
	CHECK_BLOCKS(p1, 4);

	p1 = talloc_realloc_size(NULL, p1, 20);
	CHECK_SIZE(p1, 60);

	talloc_increase_ref_count(p2);
	torture_assert(tctx, talloc_realloc_size(NULL, p2, 5) == NULL,
		"failed: talloc_realloc() on a referenced pointer should fail\n");
	CHECK_BLOCKS(p1, 4);

	talloc_realloc_size(NULL, p2, 0);
	talloc_realloc_size(NULL, p2, 0);
	CHECK_BLOCKS(p1, 3);

	torture_assert(tctx, talloc_realloc_size(NULL, p1, 0x7fffffff) == NULL,
		"failed: oversize talloc should fail\n");

	talloc_realloc_size(NULL, p1, 0);

	CHECK_BLOCKS(root, 1);
	CHECK_SIZE(root, 0);

	talloc_free(root);
	return true;
}

/*
  test realloc with a child
*/
static bool test_realloc_child(struct torture_context *tctx)
{
	void *root;
	struct el2 {
		const char *name;
	} *el2;	
	struct el1 {
		int count;
		struct el2 **list, **list2, **list3;
	} *el1;

	root = talloc_new(NULL);

	el1 = talloc(root, struct el1);
	el1->list = talloc(el1, struct el2 *);
	el1->list[0] = talloc(el1->list, struct el2);
	el1->list[0]->name = talloc_strdup(el1->list[0], "testing");

	el1->list2 = talloc(el1, struct el2 *);
	el1->list2[0] = talloc(el1->list2, struct el2);
	el1->list2[0]->name = talloc_strdup(el1->list2[0], "testing2");

	el1->list3 = talloc(el1, struct el2 *);
	el1->list3[0] = talloc(el1->list3, struct el2);
	el1->list3[0]->name = talloc_strdup(el1->list3[0], "testing2");
	
	el2 = talloc(el1->list, struct el2);
	el2 = talloc(el1->list2, struct el2);
	el2 = talloc(el1->list3, struct el2);

	el1->list = talloc_realloc(el1, el1->list, struct el2 *, 100);
	el1->list2 = talloc_realloc(el1, el1->list2, struct el2 *, 200);
	el1->list3 = talloc_realloc(el1, el1->list3, struct el2 *, 300);

	talloc_free(root);
	return true;
}

/*
  test type checking
*/
static bool test_type(struct torture_context *tctx)
{
	void *root;
	struct el1 {
		int count;
	};
	struct el2 {
		int count;
	};
	struct el1 *el1;

	root = talloc_new(NULL);

	el1 = talloc(root, struct el1);

	el1->count = 1;

	torture_assert(tctx, talloc_get_type(el1, struct el1) == el1,
		"type check failed on el1\n");
	torture_assert(tctx, talloc_get_type(el1, struct el2) == NULL,
		"type check failed on el1 with el2\n");
	talloc_set_type(el1, struct el2);
	torture_assert(tctx, talloc_get_type(el1, struct el2) == (struct el2 *)el1,
		"type set failed on el1 with el2\n");

	talloc_free(root);
	return true;
}

/*
  test steal
*/
static bool test_steal(struct torture_context *tctx)
{
	void *root, *p1, *p2;

	root = talloc_new(NULL);

	p1 = talloc_array(root, char, 10);
	CHECK_SIZE(p1, 10);

	p2 = talloc_realloc(root, NULL, char, 20);
	CHECK_SIZE(p1, 10);
	CHECK_SIZE(root, 30);

	torture_assert(tctx, talloc_steal(p1, NULL) == NULL,
		"failed: stealing NULL should give NULL\n");

	torture_assert(tctx, talloc_steal(p1, p1) == p1,
		"failed: stealing to ourselves is a nop\n");
	CHECK_BLOCKS(root, 3);
	CHECK_SIZE(root, 30);

	talloc_steal(NULL, p1);
	talloc_steal(NULL, p2);
	CHECK_BLOCKS(root, 1);
	CHECK_SIZE(root, 0);

	talloc_free(p1);
	talloc_steal(root, p2);
	CHECK_BLOCKS(root, 2);
	CHECK_SIZE(root, 20);
	
	talloc_free(p2);

	CHECK_BLOCKS(root, 1);
	CHECK_SIZE(root, 0);

	talloc_free(root);

	p1 = talloc_size(NULL, 3);
	talloc_report_full(NULL, torture_out);
	CHECK_SIZE(NULL, 3);
	talloc_free(p1);
	return true;
}

/*
  test move
*/
static bool test_move(struct torture_context *tctx)
{
	void *root;
	struct t_move {
		char *p;
		int *x;
	} *t1, *t2;

	root = talloc_new(NULL);

	t1 = talloc(root, struct t_move);
	t2 = talloc(root, struct t_move);
	t1->p = talloc_strdup(t1, "foo");
	t1->x = talloc(t1, int);
	*t1->x = 42;

	t2->p = talloc_move(t2, &t1->p);
	t2->x = talloc_move(t2, &t1->x);
	torture_assert(tctx, t1->p == NULL && t1->x == NULL &&
	    strcmp(t2->p, "foo") == 0 && *t2->x == 42,
		"talloc move failed");

	talloc_free(root);

	return true;
}

/*
  test talloc_realloc_fn
*/
static bool test_realloc_fn(struct torture_context *tctx)
{
	void *root, *p1;

	root = talloc_new(NULL);

	p1 = talloc_realloc_fn(root, NULL, 10);
	CHECK_BLOCKS(root, 2);
	CHECK_SIZE(root, 10);
	p1 = talloc_realloc_fn(root, p1, 20);
	CHECK_BLOCKS(root, 2);
	CHECK_SIZE(root, 20);
	p1 = talloc_realloc_fn(root, p1, 0);
	CHECK_BLOCKS(root, 1);
	CHECK_SIZE(root, 0);

	talloc_free(root);
	return true;
}


static bool test_unref_reparent(struct torture_context *tctx)
{
	void *root, *p1, *p2, *c1;

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "orig parent");
	p2 = talloc_named_const(root, 1, "parent by reference");

	c1 = talloc_named_const(p1, 1, "child");
	talloc_reference(p2, c1);

	CHECK_PARENT(c1, p1);

	talloc_free(p1);

	CHECK_PARENT(c1, p2);

	talloc_unlink(p2, c1);

	CHECK_SIZE(root, 1);

	talloc_free(p2);
	talloc_free(root);
	return true;
}

/*
  measure the speed of talloc versus malloc
*/
static bool test_speed(struct torture_context *tctx)
{
	void *ctx = talloc_new(NULL);
	unsigned count;
	struct timeval tv;

	tv = timeval_current();
	count = 0;
	do {
		void *p1, *p2, *p3;
		p1 = talloc_size(ctx, count);
		p2 = talloc_strdup(p1, "foo bar");
		p3 = talloc_size(p1, 300);
		talloc_free(p1);
		count += 3;
	} while (timeval_elapsed(&tv) < 5.0);

	torture_comment(tctx, talloc_asprintf(tctx, "talloc: %.0f ops/sec\n", count/timeval_elapsed(&tv)));

	talloc_free(ctx);

	tv = timeval_current();
	count = 0;
	do {
		void *p1, *p2, *p3;
		p1 = malloc(count);
		p2 = strdup("foo bar");
		p3 = malloc(300);
		free(p1);
		free(p2);
		free(p3);
		count += 3;
	} while (timeval_elapsed(&tv) < 5.0);

	torture_comment(tctx, talloc_asprintf(tctx, "malloc: %.0f ops/sec\n", count/timeval_elapsed(&tv)));
	return true;
}

static bool test_lifeless(struct torture_context *tctx)
{
	void *top = talloc_new(NULL);
	char *parent, *child; 
	void *child_owner = talloc_new(NULL);

	parent = talloc_strdup(top, "parent");
	child = talloc_strdup(parent, "child");  
	(void)talloc_reference(child, parent);
	(void)talloc_reference(child_owner, child); 
	talloc_report_full(top, torture_out);
	talloc_unlink(top, parent);
	talloc_free(child);
	talloc_report_full(top, torture_out);
	talloc_free(top);
	talloc_free(child_owner);
	talloc_free(child);
	return true;
}

static int loop_destructor_count;

static int test_loop_destructor(char *ptr)
{
	loop_destructor_count++;
	return 0;
}

static bool test_loop(struct torture_context *tctx)
{
	void *top = talloc_new(NULL);
	char *parent;
	struct req1 {
		char *req2, *req3;
	} *req1;

	parent = talloc_strdup(top, "parent");
	req1 = talloc(parent, struct req1);
	req1->req2 = talloc_strdup(req1, "req2");  
	talloc_set_destructor(req1->req2, test_loop_destructor);
	req1->req3 = talloc_strdup(req1, "req3");
	(void)talloc_reference(req1->req3, req1);
	talloc_report_full(top, torture_out);
	talloc_free(parent);
	talloc_report_full(top, torture_out);
	talloc_report_full(NULL, torture_out);
	talloc_free(top);

	torture_assert(tctx, loop_destructor_count == 1, 
				   "FAILED TO FIRE LOOP DESTRUCTOR\n");
	loop_destructor_count = 0;
	return true;
}

static int fail_destructor_str(char *ptr)
{
	return -1;
}

static bool test_free_parent_deny_child(struct torture_context *tctx)
{
	void *top = talloc_new(NULL);
	char *level1;
	char *level2;
	char *level3;

	level1 = talloc_strdup(top, "level1");
	level2 = talloc_strdup(level1, "level2");
	level3 = talloc_strdup(level2, "level3");

	talloc_set_destructor(level3, fail_destructor_str);
	talloc_free(level1);
	talloc_set_destructor(level3, NULL);

	CHECK_PARENT(level3, top);

	talloc_free(top);
	return true;
}

static bool test_talloc_ptrtype(struct torture_context *tctx)
{
	void *top = talloc_new(NULL);
	struct struct1 {
		int foo;
		int bar;
	} *s1, *s2, **s3, ***s4;
	const char *location1;
	const char *location2;
	const char *location3;
	const char *location4;

	s1 = talloc_ptrtype(top, s1);location1 = __location__;

	torture_assert(tctx, talloc_get_size(s1) == sizeof(struct struct1),
				   talloc_asprintf(tctx, 
				   "talloc_ptrtype() allocated the wrong size %lu "
		           "(should be %lu)\n", (unsigned long)talloc_get_size(s1),
		           (unsigned long)sizeof(struct struct1)));

	torture_assert(tctx, strcmp(location1, talloc_get_name(s1)) == 0,
				   talloc_asprintf(tctx, 
		"talloc_ptrtype() sets the wrong name '%s' (should be '%s')\n",
			talloc_get_name(s1), location1));

	s2 = talloc_array_ptrtype(top, s2, 10);location2 = __location__;

	torture_assert(tctx, talloc_get_size(s2) == (sizeof(struct struct1) * 10),
				   talloc_asprintf(tctx, 
		"talloc_array_ptrtype() allocated the wrong size "
		       "%lu (should be %lu)\n",
			(unsigned long)talloc_get_size(s2),
		    (unsigned long)(sizeof(struct struct1)*10)));

	torture_assert(tctx, strcmp(location2, talloc_get_name(s2)) == 0,
				   talloc_asprintf(tctx, 
		"talloc_array_ptrtype() sets the wrong name '%s' (should be '%s')\n",
			talloc_get_name(s2), location2));

	s3 = talloc_array_ptrtype(top, s3, 10);location3 = __location__;

	torture_assert(tctx, talloc_get_size(s3) == (sizeof(struct struct1 *) * 10),
				   talloc_asprintf(tctx, 
			"talloc_array_ptrtype() allocated the wrong size "
		       "%lu (should be %lu)\n",
			   (unsigned long)talloc_get_size(s3),
		       (unsigned long)(sizeof(struct struct1 *)*10)));

	torture_assert_str_equal(tctx, location3, talloc_get_name(s3),
		"talloc_array_ptrtype() sets the wrong name");

	s4 = talloc_array_ptrtype(top, s4, 10);location4 = __location__;

	torture_assert(tctx, talloc_get_size(s4) == (sizeof(struct struct1 **) * 10),
				   talloc_asprintf(tctx, 
		      "talloc_array_ptrtype() allocated the wrong size "
		       "%lu (should be %lu)\n",
			   (unsigned long)talloc_get_size(s4),
		       (unsigned long)(sizeof(struct struct1 **)*10)));

	torture_assert_str_equal(tctx, location4, talloc_get_name(s4),
		"talloc_array_ptrtype() sets the wrong name");

	talloc_free(top);
	return true;
}

static bool test_autofree(struct torture_context *tctx)
{
#if _SAMBA_BUILD_>=4
	/* 
	 * we can't run this inside smbtorture in samba4
	 * as smbtorture uses talloc_autofree_context()
	 */
	torture_skip(tctx, 
		"SKIPPING TALLOC AUTOFREE CONTEXT (not supported from smbtorture)");
#else
	void *p;

	p = talloc_autofree_context();
	talloc_free(p);

	p = talloc_autofree_context();
	talloc_free(p);
#endif
	return true;
}

bool torture_local_talloc(struct torture_suite *tsuite) 
{
	bool ret = true;

	talloc_disable_null_tracking();
	talloc_enable_null_tracking();

	torture_suite_add_simple_test(tsuite, "SINGLE REFERENCE FREE", test_ref1);
	torture_suite_add_simple_test(tsuite, "DOUBLE REFERENCE FREE", test_ref2);
	torture_suite_add_simple_test(tsuite, "PARENT REFERENCE FREE", test_ref3);
	torture_suite_add_simple_test(tsuite, "REFERRER REFERENCE FREE", test_ref4);
	torture_suite_add_simple_test(tsuite, "UNLINK", test_unlink1); 
	torture_suite_add_simple_test(tsuite, "MISCELLANEOUS", test_misc);
	torture_suite_add_simple_test(tsuite, "REALLOC", test_realloc);
	torture_suite_add_simple_test(tsuite, "REALLOC WITH CHILD", 
								   test_realloc_child);
	torture_suite_add_simple_test(tsuite, "STEAL", test_steal); 
	torture_suite_add_simple_test(tsuite, "MOVE", test_move); 
	torture_suite_add_simple_test(tsuite, "UNREFERENCE AFTER PARENT FREED", 
								  test_unref_reparent);
	torture_suite_add_simple_test(tsuite, "talloc_realloc_fn", 
								  test_realloc_fn); 
	torture_suite_add_simple_test(tsuite, "talloc type checking", test_type);
	torture_suite_add_simple_test(tsuite, "TALLOC_UNLINK LOOP", test_lifeless); 
	torture_suite_add_simple_test(tsuite, "TALLOC LOOP DESTRUCTION", test_loop);
	torture_suite_add_simple_test(tsuite, "TALLOC FREE PARENT DENY CHILD", 
								  test_free_parent_deny_child); 
	torture_suite_add_simple_test(tsuite, "TALLOC PTRTYPE", 
								  test_talloc_ptrtype);

	if (ret) {
		torture_suite_add_simple_test(tsuite, "TALLOC VS MALLOC SPEED", 
									  test_speed);
	}
	torture_suite_add_simple_test(tsuite, "TALLOC AUTOFREE CONTEXT",
								  test_autofree);

	return ret;
}



#if _SAMBA_BUILD_<4
 int main(void)
{
	if (!torture_local_talloc(NULL)) {
		printf("ERROR: TESTSUITE FAILED\n");
		return -1;
	}
	return 0;
}
#endif
