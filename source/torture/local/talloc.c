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


BOOL torture_local_talloc(int dummy) 
{
	BOOL ret = True;

	init_iconv();

	ret &= test_ref1();
	ret &= test_ref2();

	return True;
}
