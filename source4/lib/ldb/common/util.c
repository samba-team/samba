/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
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

/*
 *  Name: ldb
 *
 *  Component: ldb utility functions
 *
 *  Description: miscellanous utility functions for ldb
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"


/*
  find an element in a list, using the given comparison function and
  assuming that the list is already sorted using comp_fn

  return -1 if not found, or the index of the first occurance of needle if found
*/
int ldb_list_find(const void *needle, 
	      const void *base, size_t nmemb, size_t size, comparison_fn_t comp_fn)
{
	const char *base_p = base;
	size_t min_i, max_i, test_i;

	if (nmemb == 0) {
		return -1;
	}

	min_i = 0;
	max_i = nmemb-1;

	while (min_i < max_i) {
		int r;

		test_i = (min_i + max_i) / 2;
		r = comp_fn(needle, *(void * const *)(base_p + (size * test_i)));
		if (r == 0) {
			/* scan back for first element */
			while (test_i > 0 &&
			       comp_fn(needle, *(void * const *)(base_p + (size * (test_i-1)))) == 0) {
				test_i--;
			}
			return test_i;
		}
		if (r < 0) {
			if (test_i == 0) {
				return -1;
			}
			max_i = test_i - 1;
		}
		if (r > 0) {
			min_i = test_i + 1;
		}
	}

	if (comp_fn(needle, *(void * const *)(base_p + (size * min_i))) == 0) {
		return min_i;
	}

	return -1;
}
