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

#include "source3/include/includes.h"
#include "system/filesys.h"
#include "librpc/gen_ndr/xattr.h"
#include "librpc/gen_ndr/ndr_xattr.h"
#include "librpc/gen_ndr/file_id.h"
#include "dbwrap/dbwrap.h"
#include "lib/util/util_tdb.h"
#include "source3/lib/xattr_tdb.h"
#include "source3/lib/file_id.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/*
 * unmarshall tdb_xattrs
 */

static NTSTATUS xattr_tdb_pull_attrs(TALLOC_CTX *mem_ctx,
				     const TDB_DATA *data,
				     struct tdb_xattrs **presult)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	struct tdb_xattrs *result;

	if (!(result = talloc_zero(mem_ctx, struct tdb_xattrs))) {
		return NT_STATUS_NO_MEMORY;
	}

	if (data->dsize == 0) {
		*presult = result;
		return NT_STATUS_OK;
	}

	blob = data_blob_const(data->dptr, data->dsize);

	ndr_err = ndr_pull_struct_blob(&blob, result, result,
		(ndr_pull_flags_fn_t)ndr_pull_tdb_xattrs);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("ndr_pull_tdb_xattrs failed: %s\n",
			  ndr_errstr(ndr_err)));
		TALLOC_FREE(result);
		return ndr_map_error2ntstatus(ndr_err);
	}

	*presult = result;
	return NT_STATUS_OK;
}

/*
 * marshall tdb_xattrs
 */

static NTSTATUS xattr_tdb_push_attrs(TALLOC_CTX *mem_ctx,
				     const struct tdb_xattrs *attribs,
				     TDB_DATA *data)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, attribs,
		(ndr_push_flags_fn_t)ndr_push_tdb_xattrs);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("ndr_push_tdb_xattrs failed: %s\n",
			  ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);
	}

	*data = make_tdb_data(blob.data, blob.length);
	return NT_STATUS_OK;
}

/*
 * Load tdb_xattrs for a file from the tdb
 */

static NTSTATUS xattr_tdb_load_attrs(TALLOC_CTX *mem_ctx,
				     struct db_context *db_ctx,
				     const struct file_id *id,
				     struct tdb_xattrs **presult)
{
	uint8_t id_buf[16];
	NTSTATUS status;
	TDB_DATA data;

	/* For backwards compatibility only store the dev/inode. */
	push_file_id_16((char *)id_buf, id);

	status = dbwrap_fetch(db_ctx, mem_ctx,
			      make_tdb_data(id_buf, sizeof(id_buf)),
			      &data);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
			return status;
		}
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = xattr_tdb_pull_attrs(mem_ctx, &data, presult);
	TALLOC_FREE(data.dptr);
	return status;
}

/*
 * fetch_lock the tdb_ea record for a file
 */

static struct db_record *xattr_tdb_lock_attrs(TALLOC_CTX *mem_ctx,
					      struct db_context *db_ctx,
					      const struct file_id *id)
{
	uint8_t id_buf[16];

	/* For backwards compatibility only store the dev/inode. */
	push_file_id_16((char *)id_buf, id);
	return dbwrap_fetch_locked(db_ctx, mem_ctx,
				   make_tdb_data(id_buf, sizeof(id_buf)));
}

/*
 * Save tdb_xattrs to a previously fetch_locked record
 */

static NTSTATUS xattr_tdb_save_attrs(struct db_record *rec,
				     const struct tdb_xattrs *attribs)
{
	TDB_DATA data = tdb_null;
	NTSTATUS status;

	status = xattr_tdb_push_attrs(talloc_tos(), attribs, &data);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("xattr_tdb_push_attrs failed: %s\n",
			  nt_errstr(status)));
		return status;
	}

	status = dbwrap_record_store(rec, data, 0);

	TALLOC_FREE(data.dptr);

	return status;
}

/*
 * Worker routine for getxattr and fgetxattr
 */

ssize_t xattr_tdb_getattr(struct db_context *db_ctx,
			  TALLOC_CTX *mem_ctx,
			  const struct file_id *id,
			  const char *name, DATA_BLOB *blob)
{
	struct tdb_xattrs *attribs;
	uint32_t i;
	ssize_t result = -1;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	struct file_id_buf buf;

	DBG_DEBUG("xattr_tdb_getattr called for file %s, name %s\n",
		  file_id_str_buf(*id, &buf), name);

	status = xattr_tdb_load_attrs(frame, db_ctx, id, &attribs);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("xattr_tdb_fetch_attrs failed: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
	}

	for (i=0; i<attribs->num_eas; i++) {
		if (strcmp(attribs->eas[i].name, name) == 0) {
			break;
		}
	}

	if (i == attribs->num_eas) {
		errno = ENOATTR;
		goto fail;
	}

	*blob = attribs->eas[i].value;
	talloc_steal(mem_ctx, blob->data);
	result = attribs->eas[i].value.length;

 fail:
	TALLOC_FREE(frame);
	return result;
}

/*
 * Worker routine for setxattr and fsetxattr
 */

int xattr_tdb_setattr(struct db_context *db_ctx,
		      const struct file_id *id, const char *name,
		      const void *value, size_t size, int flags)
{
	NTSTATUS status;
	struct db_record *rec;
	struct tdb_xattrs *attribs;
	uint32_t i;
	TDB_DATA data;
	TALLOC_CTX *frame = talloc_stackframe();
	struct file_id_buf buf;

	DBG_DEBUG("xattr_tdb_setattr called for file %s, name %s\n",
		  file_id_str_buf(*id, &buf), name);

	rec = xattr_tdb_lock_attrs(frame, db_ctx, id);

	if (rec == NULL) {
		DEBUG(0, ("xattr_tdb_lock_attrs failed\n"));
		errno = EINVAL;
		return -1;
	}

	data = dbwrap_record_get_value(rec);

	status = xattr_tdb_pull_attrs(rec, &data, &attribs);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("xattr_tdb_fetch_attrs failed: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(frame);
		return -1;
	}

	for (i=0; i<attribs->num_eas; i++) {
		if (strcmp(attribs->eas[i].name, name) == 0) {
			if (flags & XATTR_CREATE) {
				TALLOC_FREE(frame);
				errno = EEXIST;
				return -1;
			}
			break;
		}
	}

	if (i == attribs->num_eas) {
		struct xattr_EA *tmp;

		if (flags & XATTR_REPLACE) {
			TALLOC_FREE(frame);
			errno = ENOATTR;
			return -1;
		}

		tmp = talloc_realloc(
			attribs, attribs->eas, struct xattr_EA,
			attribs->num_eas+ 1);

		if (tmp == NULL) {
			DEBUG(0, ("talloc_realloc failed\n"));
			TALLOC_FREE(frame);
			errno = ENOMEM;
			return -1;
		}

		attribs->eas = tmp;
		attribs->num_eas += 1;
	}

	attribs->eas[i].name = name;
	attribs->eas[i].value.data = discard_const_p(uint8_t, value);
	attribs->eas[i].value.length = size;

	status = xattr_tdb_save_attrs(rec, attribs);

	TALLOC_FREE(frame);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("save failed: %s\n", nt_errstr(status)));
		return -1;
	}

	return 0;
}

/*
 * Worker routine for listxattr and flistxattr
 */

ssize_t xattr_tdb_listattr(struct db_context *db_ctx,
			   const struct file_id *id, char *list,
			   size_t size)
{
	NTSTATUS status;
	struct tdb_xattrs *attribs;
	uint32_t i;
	size_t len = 0;
	TALLOC_CTX *frame = talloc_stackframe();

	status = xattr_tdb_load_attrs(frame, db_ctx, id, &attribs);

	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND))
	{
		DEBUG(0, ("xattr_tdb_fetch_attrs failed: %s\n",
			   nt_errstr(status)));
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		TALLOC_FREE(frame);
		return 0;
	}

	DEBUG(10, ("xattr_tdb_listattr: Found %d xattrs\n",
		   attribs->num_eas));

	for (i=0; i<attribs->num_eas; i++) {
		size_t tmp;

		DEBUG(10, ("xattr_tdb_listattr: xattrs[i].name: %s\n",
			   attribs->eas[i].name));

		tmp = strlen(attribs->eas[i].name);

		/*
		 * Try to protect against overflow
		 */

		if (len + (tmp+1) < len) {
			TALLOC_FREE(frame);
			errno = EINVAL;
			return -1;
		}

		/*
		 * Take care of the terminating NULL
		 */
		len += (tmp + 1);
	}

	if (len > size) {
		TALLOC_FREE(frame);
		errno = ERANGE;
		return len;
	}

	len = 0;

	for (i=0; i<attribs->num_eas; i++) {
		strlcpy(list+len, attribs->eas[i].name,
			size-len);
		len += (strlen(attribs->eas[i].name) + 1);
	}

	TALLOC_FREE(frame);
	return len;
}

/*
 * Worker routine for removexattr and fremovexattr
 */

int xattr_tdb_removeattr(struct db_context *db_ctx,
			 const struct file_id *id, const char *name)
{
	NTSTATUS status;
	struct db_record *rec;
	struct tdb_xattrs *attribs;
	uint32_t i;
	TDB_DATA value;

	rec = xattr_tdb_lock_attrs(talloc_tos(), db_ctx, id);

	if (rec == NULL) {
		DEBUG(0, ("xattr_tdb_lock_attrs failed\n"));
		errno = EINVAL;
		return -1;
	}

	value = dbwrap_record_get_value(rec);

	status = xattr_tdb_pull_attrs(rec, &value, &attribs);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("xattr_tdb_fetch_attrs failed: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(rec);
		return -1;
	}

	for (i=0; i<attribs->num_eas; i++) {
		if (strcmp(attribs->eas[i].name, name) == 0) {
			break;
		}
	}

	if (i == attribs->num_eas) {
		TALLOC_FREE(rec);
		errno = ENOATTR;
		return -1;
	}

	attribs->eas[i] =
		attribs->eas[attribs->num_eas-1];
	attribs->num_eas -= 1;

	if (attribs->num_eas == 0) {
		dbwrap_record_delete(rec);
		TALLOC_FREE(rec);
		return 0;
	}

	status = xattr_tdb_save_attrs(rec, attribs);

	TALLOC_FREE(rec);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("save failed: %s\n", nt_errstr(status)));
		return -1;
	}

	return 0;
}

/*
 * Worker routine for unlink and rmdir
 */

void xattr_tdb_remove_all_attrs(struct db_context *db_ctx,
			       const struct file_id *id)
{
	struct db_record *rec;
	rec = xattr_tdb_lock_attrs(talloc_tos(), db_ctx, id);

	/*
	 * If rec == NULL there's not much we can do about it
	 */

	if (rec != NULL) {
		dbwrap_record_delete(rec);
		TALLOC_FREE(rec);
	}
}
