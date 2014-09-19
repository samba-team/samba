/*
   Unix SMB/CIFS implementation.

   very efficient functions to manage mapping a id (such as a fnum) to
   a pointer. This is used for fnum and search id allocation.

   Copyright (C) Andrew Tridgell 2004

   This code is derived from lib/idr.c in the 2.6 Linux kernel, which was
   written by Jim Houston jim.houston@ccur.com, and is
   Copyright (C) 2002 by Concurrent Computer Corporation

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
  see the section marked "public interface" below for documentation
*/

/**
 * @file
 */

#include "replace.h"
#include "samba_util.h" /* generate_random() */
#include "idtree.h"
#include "idtree_random.h"

/**
  allocate a new id randomly in the given range
*/
_PUBLIC_ int idr_get_new_random(struct idr_context *idp, void *ptr, int limit)
{
	int id;

	/* first try a random starting point in the whole range, and if that fails,
	   then start randomly in the bottom half of the range. This can only
	   fail if the range is over half full, and finally fallback to any
	   free id */
	id = idr_get_new_above(idp, ptr, 1+(generate_random() % limit), limit);
	if (id == -1) {
		id = idr_get_new_above(idp, ptr, 1+(generate_random()%(limit/2)), limit);
	}
	if (id == -1) {
		id = idr_get_new_above(idp, ptr, 1, limit);
	}

	return id;
}
