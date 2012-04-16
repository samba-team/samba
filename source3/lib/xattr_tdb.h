/*
 * Store posix-level xattrs in a tdb
 *
 * Copyright (C) Andrew Bartlett 2011
 *
 * extracted from vfs_xattr_tdb by
 *
 * Copyright (C) Volker Lendecke, 2007
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "librpc/gen_ndr/file_id.h"

/* The following definitions come from lib/util/xattr_tdb.c  */

ssize_t xattr_tdb_getattr(struct db_context *db_ctx,
			  TALLOC_CTX *mem_ctx,
			  const struct file_id *id,
			  const char *name, DATA_BLOB *blob);
int xattr_tdb_setattr(struct db_context *db_ctx,
		      const struct file_id *id, const char *name,
		      const void *value, size_t size, int flags);
ssize_t xattr_tdb_listattr(struct db_context *db_ctx,
			   const struct file_id *id, char *list,
			   size_t size);
int xattr_tdb_removeattr(struct db_context *db_ctx,
			 const struct file_id *id, const char *name);
void xattr_tdb_remove_all_attrs(struct db_context *db_ctx,
				const struct file_id *id);
