/* 
   Unix SMB/CIFS implementation.

   local testing of talloc routines.

   Copyright (C) Andrew Tridgell 2004
   
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

#define CHECK_BLOCKS(ptr, tblocks) do { \
	if (talloc_total_blocks(ptr) != (tblocks)) { \
		printf(__location__ " failed: wrong '%s' tree blocks: got %u  expected %u\n", \
		       #ptr, \
		       (unsigned)talloc_total_blocks(ptr), \
		       (unsigned)tblocks); \
		talloc_report_full(ptr, stdout); \
		return False; \
	} \
} while (0)

#define CHECK_SIZE(ptr, tsize) do { \
	if (talloc_total_size(ptr) != (tsize)) { \
		printf(__location__ " failed: wrong '%s' tree size: got %u  expected %u\n", \
		       #ptr, \
		       (unsigned)talloc_total_size(ptr), \
		       (unsigned)tsize); \
		talloc_report_full(ptr, stdout); \
		return False; \
	} \
} while (0)

/*
  test references 
*/
static BOOL test_ref1(void)
{
	void *root, *p1, *p2, *ref, *r1;

	printf("TESTING SINGLE REFERENCE FREE\n");

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	p2 = talloc_named_const(p1, 1, "p2");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 2, "x2");
	talloc_named_const(p1, 3, "x3");

	r1 = talloc_named_const(root, 1, "r1");	
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 2);

	printf("Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 1);

	printf("Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(r1, 1);

	printf("Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(NULL, stdout);

	CHECK_BLOCKS(root, 1);

	CHECK_SIZE(root, 0);

	talloc_free(root);

	return True;
}

/*
  test references 
*/
static BOOL test_ref2(void)
{
	void *root, *p1, *p2, *ref, *r1;

	printf("TESTING DOUBLE REFERENCE FREE\n");

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");
	p2 = talloc_named_const(p1, 1, "p2");

	r1 = talloc_named_const(root, 1, "r1");	
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 2);

	printf("Freeing ref\n");
	talloc_free(ref);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 1);

	printf("Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 4);
	CHECK_BLOCKS(r1, 1);

	printf("Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(r1, 1);

	printf("Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(root, stdout);

	CHECK_SIZE(root, 0);

	talloc_free(root);

	return True;
}

/*
  test references 
*/
static BOOL test_ref3(void)
{
	void *root, *p1, *p2, *ref, *r1;

	printf("TESTING PARENT REFERENCE FREE\n");

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	p2 = talloc_named_const(root, 1, "p2");
	r1 = talloc_named_const(p1, 1, "r1");
	ref = talloc_reference(p2, r1);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 2);
	CHECK_BLOCKS(p2, 2);
	CHECK_BLOCKS(r1, 1);

	printf("Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p2, 2);
	CHECK_BLOCKS(r1, 1);

	printf("Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, stdout);

	CHECK_SIZE(root, 0);

	talloc_free(root);

	return True;
}

/*
  test references 
*/
static BOOL test_ref4(void)
{
	void *root, *p1, *p2, *ref, *r1;

	printf("TESTING REFERRER REFERENCE FREE\n");

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");
	p2 = talloc_named_const(p1, 1, "p2");

	r1 = talloc_named_const(root, 1, "r1");	
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 2);

	printf("Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 5);
	CHECK_BLOCKS(p2, 1);

	printf("Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 4);

	printf("Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, stdout);

	CHECK_SIZE(root, 0);

	talloc_free(root);

	return True;
}


/*
  test references 
*/
static BOOL test_unref1(void)
{
	void *root, *p1, *p2, *ref, *r1;

	printf("TESTING UNREFERENCE\n");

	root = talloc_named_const(NULL, 0, "root");
	p1 = talloc_named_const(root, 1, "p1");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");
	p2 = talloc_named_const(p1, 1, "p2");

	r1 = talloc_named_const(p1, 1, "r1");	
	ref = talloc_reference(r1, p2);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 7);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 2);

	printf("Unreferencing r1\n");
	talloc_unreference(r1, p2);
	talloc_report_full(root, stdout);

	CHECK_BLOCKS(p1, 6);
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(r1, 1);

	printf("Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(root, stdout);

	CHECK_SIZE(root, 0);

	talloc_free(root);

	return True;
}

static int fail_destructor(void *ptr)
{
	return -1;
}

/*
  miscellaneous tests to try to get a higher test coverage percentage
*/
static BOOL test_misc(void)
{
	void *root, *p1;
	char *p2;
	double *d;

	printf("TESTING MISCELLANEOUS\n");

	root = talloc(NULL, 0);

	p1 = talloc(root, 0x7fffffff);
	if (p1) {
		printf("failed: large talloc allowed\n");
		return False;
	}

	p1 = talloc_strdup(root, "foo");
	talloc_increase_ref_count(p1);
	talloc_increase_ref_count(p1);
	talloc_increase_ref_count(p1);
	CHECK_BLOCKS(p1, 1);
	CHECK_BLOCKS(root, 2);
	talloc_free(p1);
	CHECK_BLOCKS(p1, 1);
	CHECK_BLOCKS(root, 2);
	talloc_unreference(NULL, p1);
	CHECK_BLOCKS(p1, 1);
	CHECK_BLOCKS(root, 2);
	if (talloc_unreference(root, p1) != NULL) {
		printf("failed: talloc_unreference() of non-reference context should return NULL\n");
		return False;
	}
	talloc_free(p1);
	CHECK_BLOCKS(p1, 1);
	CHECK_BLOCKS(root, 2);

	talloc_set_name(p1, "my name is %s", "foo");
	if (strcmp(talloc_get_name(p1), "my name is foo") != 0) {
		printf("failed: wrong name after talloc_set_name\n");
		return False;
	}
	CHECK_BLOCKS(p1, 2);
	CHECK_BLOCKS(root, 3);

	talloc_set_name_const(p1, NULL);
	if (strcmp(talloc_get_name(p1), "UNNAMED") != 0) {
		printf("failed: wrong name after talloc_set_name(NULL)\n");
		return False;
	}
	CHECK_BLOCKS(p1, 2);
	CHECK_BLOCKS(root, 3);
	

	if (talloc_free(NULL) != -1) {
		printf("talloc_free(NULL) should give -1\n");
		return False;
	}

	talloc_set_destructor(p1, fail_destructor);
	if (talloc_free(p1) != -1) {
		printf("Failed destructor should cause talloc_free to fail\n");
		return False;
	}
	talloc_set_destructor(p1, NULL);

	talloc_report(root, stdout);


	p2 = talloc_zero(p1, 20);
	if (p2[19] != 0) {
		printf("Failed to give zero memory\n");
		return False;
	}
	talloc_free(p2);

	if (talloc_strdup(root, NULL) != NULL) {
		printf("failed: strdup on NULL should give NULL\n");
		return False;
	}

	p2 = talloc_strndup(p1, "foo", 2);
	if (strcmp("fo", p2) != 0) {
		printf("failed: strndup doesn't work\n");
		return False;
	}
	p2 = talloc_asprintf_append(p2, "o%c", 'd');
	if (strcmp("food", p2) != 0) {
		printf("failed: talloc_asprintf_append doesn't work\n");
		return False;
	}
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(p1, 3);

	p2 = talloc_asprintf_append(NULL, "hello %s", "world");
	if (strcmp("hello world", p2) != 0) {
		printf("failed: talloc_asprintf_append doesn't work\n");
		return False;
	}
	CHECK_BLOCKS(p2, 1);
	CHECK_BLOCKS(p1, 3);
	talloc_free(p2);

	d = talloc_array_p(p1, double, 0x20000000);
	if (d) {
		printf("failed: integer overflow not detected\n");
		return False;
	}

	d = talloc_realloc_p(p1, d, double, 0x20000000);
	if (d) {
		printf("failed: integer overflow not detected\n");
		return False;
	}

	talloc_free(p1);
	CHECK_BLOCKS(root, 1);

	talloc_report(root, stdout);
	talloc_report(NULL, stdout);

	CHECK_SIZE(root, 0);

	talloc_free(root);

	CHECK_SIZE(NULL, 0);

	talloc_enable_leak_report();
	talloc_enable_leak_report_full();

	return True;
}


/*
  test realloc
*/
static BOOL test_realloc(void)
{
	void *root, *p1, *p2;

	printf("TESTING REALLOC\n");

	root = talloc(NULL, 0);

	p1 = talloc(root, 10);
	CHECK_SIZE(p1, 10);

	p1 = talloc_realloc(NULL, p1, 20);
	CHECK_SIZE(p1, 20);

	talloc(p1, 0);

	p2 = talloc_realloc(p1, NULL, 30);

	talloc(p1, 0);

	p2 = talloc_realloc(p1, p2, 40);

	CHECK_SIZE(p2, 40);
	CHECK_SIZE(root, 60);
	CHECK_BLOCKS(p1, 4);

	p1 = talloc_realloc(NULL, p1, 20);
	CHECK_SIZE(p1, 60);

	talloc_increase_ref_count(p2);
	if (talloc_realloc(NULL, p2, 5) != NULL) {
		printf("failed: talloc_realloc() on a referenced pointer should fail\n");
		return False;
	}
	CHECK_BLOCKS(p1, 4);

	talloc_realloc(NULL, p2, 0);
	talloc_realloc(NULL, p2, 0);
	CHECK_BLOCKS(p1, 3);

	if (talloc_realloc(NULL, p1, 0x7fffffff) != NULL) {
		printf("failed: oversize talloc should fail\n");
		return False;
	}

	talloc_realloc(NULL, p1, 0);

	CHECK_BLOCKS(root, 1);
	CHECK_SIZE(root, 0);

	talloc_free(root);

	return True;
}

/*
  test steal
*/
static BOOL test_steal(void)
{
	void *root, *p1, *p2;

	printf("TESTING STEAL\n");

	root = talloc(NULL, 0);

	p1 = talloc_array_p(root, char, 10);
	CHECK_SIZE(p1, 10);

	p2 = talloc_realloc_p(root, NULL, char, 20);
	CHECK_SIZE(p1, 10);
	CHECK_SIZE(root, 30);

	if (talloc_steal(p1, NULL) != NULL) {
		printf("failed: stealing NULL should give NULL\n");
		return False;
	}

	if (talloc_steal(p1, p1) != p1) {
		printf("failed: stealing to ourselves is a nop\n");
		return False;
	}
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

	p1 = talloc(NULL, 3);
	CHECK_SIZE(NULL, 3);
	talloc_free(p1);

	return True;
}

/*
  test ldb alloc fn
*/
static BOOL test_ldb(void)
{
	void *root, *p1;

	printf("TESTING LDB\n");

	root = talloc(NULL, 0);

	p1 = talloc_ldb_alloc(root, NULL, 10);
	CHECK_BLOCKS(root, 2);
	CHECK_SIZE(root, 10);
	p1 = talloc_ldb_alloc(root, p1, 20);
	CHECK_BLOCKS(root, 2);
	CHECK_SIZE(root, 20);
	p1 = talloc_ldb_alloc(root, p1, 0);
	CHECK_BLOCKS(root, 1);
	CHECK_SIZE(root, 0);

	talloc_free(root);


	return True;
}

/*
  measure the speed of talloc versus malloc
*/
static BOOL test_speed(void)
{
	void *ctx = talloc(NULL, 0);
	uint_t count;

	printf("MEASURING TALLOC VS MALLOC SPEED\n");

	start_timer();
	count = 0;
	do {
		void *p1, *p2, *p3;
		p1 = talloc(ctx, count);
		p2 = talloc_strdup(p1, "foo bar");
		p3 = talloc(p1, 300);
		talloc_free(p1);
		count += 3;
	} while (end_timer() < 5.0);

	printf("talloc: %.0f ops/sec\n", count/end_timer());

	talloc_free(ctx);

	start_timer();
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
	} while (end_timer() < 5.0);

	printf("malloc: %.0f ops/sec\n", count/end_timer());

	return True;	
}


BOOL torture_local_talloc(int dummy) 
{
	BOOL ret = True;

	init_iconv();

	ret &= test_ref1();
	ret &= test_ref2();
	ret &= test_ref3();
	ret &= test_ref4();
	ret &= test_unref1();
	ret &= test_misc();
	ret &= test_realloc();
	ret &= test_steal();
	ret &= test_ldb();
	ret &= test_speed();

	return ret;
}
