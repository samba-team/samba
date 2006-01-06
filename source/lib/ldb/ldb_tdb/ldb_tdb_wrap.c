/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2005

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

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/ldb_tdb/ldb_tdb.h"

/*
  the purpose of this code is to work around the braindead posix locking
  rules, to allow us to have a ldb open more than once while allowing 
  locking to work
*/

struct ltdb_wrap {
	struct ltdb_wrap *next, *prev;
	struct tdb_context *tdb;
	dev_t device;
	ino_t inode;
};

static struct ltdb_wrap *tdb_list;

/* destroy the last connection to a tdb */
static int ltdb_wrap_destructor(void *ctx)
{
	struct ltdb_wrap *w = talloc_get_type(ctx, struct ltdb_wrap);
	tdb_close(w->tdb);
	if (w->next) {
		w->next->prev = w->prev;
	}
	if (w->prev) {
		w->prev->next = w->next;
	}
	if (w == tdb_list) {
		tdb_list = w->next;
	}
	return 0;
}				 

/*
  wrapped connection to a tdb database. The caller should _not_ free
  this as it is not a talloc structure (as tdb does not use talloc
  yet). It will auto-close when the caller frees the mem_ctx that is
  passed to this call
 */
struct tdb_context *ltdb_wrap_open(TALLOC_CTX *mem_ctx,
				   const char *path, int hash_size, int tdb_flags,
				   int open_flags, mode_t mode)
{
	struct ltdb_wrap *w;
	struct stat st;

	if (stat(path, &st) == 0) {
		for (w=tdb_list;w;w=w->next) {
			if (st.st_dev == w->device && st.st_ino == w->inode) {
				talloc_reference(mem_ctx, w);
				return w->tdb;
			}
		}
	}

	w = talloc(mem_ctx, struct ltdb_wrap);
	if (w == NULL) {
		return NULL;
	}

	w->tdb = tdb_open(path, hash_size, tdb_flags, open_flags, mode);
	if (w->tdb == NULL) {
		talloc_free(w);
		return NULL;
	}

	if (fstat(tdb_fd(w->tdb), &st) != 0) {
		tdb_close(w->tdb);
		talloc_free(w);
		return NULL;
	}

	w->device = st.st_dev;
	w->inode  = st.st_ino;

	talloc_set_destructor(w, ltdb_wrap_destructor);

	w->next = tdb_list;
	w->prev = NULL;
	if (tdb_list) {
		tdb_list->prev = w;
	}
	tdb_list = w;
	
	return w->tdb;
}

