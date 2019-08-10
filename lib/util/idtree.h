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

#ifndef _SAMBA_IDTREE_H_
#define _SAMBA_IDTREE_H_

#include <talloc.h>

struct idr_context;

/**
  initialise a idr tree. The context return value must be passed to
  all subsequent idr calls. To destroy the idr tree use talloc_free()
  on this context
 */
struct idr_context *idr_init(TALLOC_CTX *mem_ctx);

/**
  allocate the next available id, and assign 'ptr' into its slot.
  you can retrieve later this pointer using idr_find()
*/
int idr_get_new(struct idr_context *idp, void *ptr, int limit);

/**
   allocate a new id, giving the first available value greater than or
   equal to the given starting id
*/
int idr_get_new_above(struct idr_context *idp, void *ptr, int starting_id, int limit);

/**
  find a pointer value previously set with idr_get_new given an id
*/
void *idr_find(struct idr_context *idp, int id);

/**
  remove an id from the idr tree
*/
int idr_remove(struct idr_context *idp, int id);

#endif /* _SAMBA_IDTREE_H_ */
