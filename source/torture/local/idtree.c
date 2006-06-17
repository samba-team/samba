/* 
   Unix SMB/CIFS implementation.

   local testing of idtree routines.

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
#include "torture/torture.h"

static BOOL torture_local_idtree_simple(struct torture_context *test, 
								 const void *_data) 
{
	struct idr_context *idr;
	int i;
	int *ids;
	int *present;
	extern int torture_numops;
	int n = torture_numops;

	idr = idr_init(test);

	ids = talloc_zero_array(test, int, n);
	present = talloc_zero_array(test, int, n);

	for (i=0;i<n;i++) {
		ids[i] = -1;
	}

	for (i=0;i<n;i++) {
		int ii = random() % n;
		void *p = idr_find(idr, ids[ii]);
		if (present[ii]) {
			if (p != &ids[ii]) {
				torture_fail(test, "wrong ptr at %d - %p should be %p", 
				       ii, p, &ids[ii]);
			}
			if (random() % 7 == 0) {
				if (idr_remove(idr, ids[ii]) != 0) {
					torture_fail(test, "remove failed at %d (id=%d)", 
					       i, ids[ii]);
				}
				present[ii] = 0;
				ids[ii] = -1;
			}
		} else {
			if (p != NULL) {
				torture_fail(test, "non-present at %d gave %p (would be %d)", 
				       ii, p, 
				       (int)(((char *)p) - (char *)(&ids[0])) / sizeof(int));
			}
			if (random() % 5) {
				ids[ii] = idr_get_new(idr, &ids[ii], n);
				if (ids[ii] < 0) {
					torture_fail(test, "alloc failure at %d (ret=%d)", 
					       ii, ids[ii]);
				} else {
					present[ii] = 1;
				}
			}
		}
	}

	torture_comment(test, "done %d random ops", i);

	for (i=0;i<n;i++) {
		if (present[i]) {
			if (idr_remove(idr, ids[i]) != 0) {
				torture_fail(test, "delete failed on cleanup at %d (id=%d)", 
				       i, ids[i]);
			}
		}
	}

	torture_comment(test, "cleaned up");

	return True;
}

struct torture_suite *torture_local_idtree(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "LOCAL-IDTREE");
	torture_suite_add_simple_tcase(suite, "idtree", torture_local_idtree_simple,
								   NULL);
	return suite;
}
