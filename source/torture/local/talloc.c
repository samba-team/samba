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
		printf("(%d) failed: wrong '%s' tree size: got %u  expected %u\n", \
		       __LINE__, #ptr, \
		       (unsigned)talloc_total_blocks(ptr), \
		       (unsigned)tblocks); \
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

	if (talloc_total_size(root) != 0) {
		printf("failed: non-zero total size\n");
		return False;
	}

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

	if (talloc_total_size(root) != 0) {
		printf("failed: non-zero total size\n");
		return False;
	}

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

	if (talloc_total_size(root) != 0) {
		printf("failed: non-zero total size\n");
		return False;
	}

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

	if (talloc_total_size(root) != 0) {
		printf("failed: non-zero total size\n");
		return False;
	}

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

	if (talloc_total_size(root) != 0) {
		printf("failed: non-zero total size\n");
		return False;
	}

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
	ret &= test_speed();

	return ret;
}
