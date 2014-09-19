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

#ifndef _SAMBA_IDTREE_RANDOM_H_
#define _SAMBA_IDTREE_RANDOM_H_

#include <talloc.h>
#include "idtree.h"

/**
  allocate a new id randomly in the given range
*/
int idr_get_new_random(struct idr_context *idp, void *ptr, int limit);

#endif /* _SAMBA_IDTREE_RANDOM_H_ */
