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

static struct timeval tp1,tp2;

static void start_timer(void)
{
	gettimeofday(&tp1,NULL);
}

static double end_timer(void)
{
	gettimeofday(&tp2,NULL);
	return((tp2.tv_sec - tp1.tv_sec) + 
	       (tp2.tv_usec - tp1.tv_usec)*1.0e-6);
}

/*
  test references 
*/
static BOOL test_ref1(void)
{
	void *p1, *p2, *ref, *r1;

	printf("TESTING SINGLE REFERENCE FREE\n");

	p1 = talloc_named_const(NULL, 1, "p1");
	p2 = talloc_named_const(p1, 1, "p2");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");

	r1 = talloc_named_const(NULL, 1, "r1");	
	ref = talloc_reference(r1, p2);
	talloc_report_full(NULL, stdout);

	printf("Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(NULL, stdout);

	printf("Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(NULL, stdout);

	printf("Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(NULL, stdout);

	if (talloc_total_size(NULL) != 0) {
		printf("non-zero total size\n");
		return False;
	}

	return True;
}

/*
  test references 
*/
static BOOL test_ref2(void)
{
	void *p1, *p2, *ref, *r1;

	printf("TESTING DOUBLE REFERENCE FREE\n");

	p1 = talloc_named_const(NULL, 1, "p1");
	talloc_named_const(p1, 1, "x1");
	talloc_named_const(p1, 1, "x2");
	talloc_named_const(p1, 1, "x3");
	p2 = talloc_named_const(p1, 1, "p2");

	r1 = talloc_named_const(NULL, 1, "r1");	
	ref = talloc_reference(r1, p2);
	talloc_report_full(NULL, stdout);
	printf("Freeing ref\n");
	talloc_free(ref);
	talloc_report_full(NULL, stdout);
	printf("Freeing p2\n");
	talloc_free(p2);
	talloc_report_full(NULL, stdout);
	printf("Freeing p1\n");
	talloc_free(p1);
	talloc_report_full(NULL, stdout);
	printf("Freeing r1\n");
	talloc_free(r1);
	talloc_report_full(NULL, stdout);

	if (talloc_total_size(NULL) != 0) {
		printf("non-zero total size\n");
		return False;
	}

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
	ret &= test_speed();

	return True;
}
