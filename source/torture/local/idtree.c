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

BOOL torture_local_idtree(void) 
{
	struct idr_context *idr;
	int i;
	int *ids;
	int *present;
	BOOL ret = True;
	extern int torture_numops;
	int n = torture_numops;
	void *ctx = talloc(NULL, 0);

	idr = idr_init(ctx);

	ids = talloc_zero_array_p(ctx, int, n);
	present = talloc_zero_array_p(ctx, int, n);

	for (i=0;i<n;i++) {
		ids[i] = -1;
	}

	for (i=0;i<n;i++) {
		int ii = random() % n;
		void *p = idr_find(idr, ids[ii]);
		if (present[ii]) {
			if (p != &ids[ii]) {
				printf("wrong ptr at %d - %p should be %p\n", 
				       ii, p, &ids[ii]);
				ret = False;
			}
			if (random() % 7 == 0) {
				if (idr_remove(idr, ids[ii]) != 0) {
					printf("remove failed at %d (id=%d)\n", 
					       i, ids[ii]);
					ret = False;
				}
				present[ii] = 0;
				ids[ii] = -1;
			}
		} else {
			if (p != NULL) {
				printf("non-present at %d gave %p (would be %d)\n", 
				       ii, p, 
				       (((char *)p) - (char *)(&ids[0])) / sizeof(int));
				ret = False;
			}
			if (random() % 5) {
				ids[ii] = idr_get_new(idr, &ids[ii], n);
				if (ids[ii] < 0) {
					printf("alloc failure at %d (ret=%d)\n", 
					       ii, ids[ii]);
					ret = False;
				} else {
					present[ii] = 1;
				}
			}
		}
	}

	printf("done %d random ops\n", i);

	for (i=0;i<n;i++) {
		if (present[i]) {
			if (idr_remove(idr, ids[i]) != 0) {
				printf("delete failed on cleanup at %d (id=%d)\n", 
				       i, ids[i]);
				ret = False;
			}
		}
	}

	printf("cleaned up\n");

	talloc_free(ctx);

	return ret;
}
