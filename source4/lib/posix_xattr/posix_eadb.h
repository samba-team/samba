/*
 * POSIX NTVFS backend - xattr support using a tdb
 *
 * Copyright (C) Andrew Bartlett 2011
 * Copyright (C) Andrew Tridgell 2004
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SOURCE4_LIB_POSIX_XATTR_POSIX_EADB_H__
#define __SOURCE4_LIB_POSIX_XATTR_POSIX_EADB_H__

#include "replace.h"
#include <talloc.h>
#include "lib/util/data_blob.h"
#include "libcli/util/ntstatus.h"

struct tdb_wrap;

NTSTATUS pull_xattr_blob_tdb_raw(struct tdb_wrap *ea_tdb,
				 TALLOC_CTX *mem_ctx,
				 const char *attr_name,
				 const char *fname,
				 int fd,
				 size_t estimated_size,
				 DATA_BLOB *blob);
NTSTATUS push_xattr_blob_tdb_raw(struct tdb_wrap *ea_tdb,
				 const char *attr_name,
				 const char *fname,
				 int fd,
				 const DATA_BLOB *blob);
NTSTATUS delete_posix_eadb_raw(struct tdb_wrap *ea_tdb,
			       const char *attr_name,
			       const char *fname,
			       int fd);
NTSTATUS unlink_posix_eadb_raw(struct tdb_wrap *ea_tdb,
			       const char *fname,
			       int fd);
NTSTATUS list_posix_eadb_raw(struct tdb_wrap *ea_tdb,
			     TALLOC_CTX *mem_ctx,
			     const char *fname,
			     int fd,
			     DATA_BLOB *list);

#endif
