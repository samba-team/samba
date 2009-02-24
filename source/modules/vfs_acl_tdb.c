/*
 * Store Windows ACLs in a tdb.
 *
 * Copyright (C) Volker Lendecke, 2008
 * Copyright (C) Jeremy Allison, 2008
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

/* NOTE: This is an experimental module, not yet finished. JRA. */

#include "includes.h"
#include "librpc/gen_ndr/xattr.h"
#include "librpc/gen_ndr/ndr_xattr.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static unsigned int ref_count;
static struct db_context *acl_db;

/*******************************************************************
 Open acl_db if not already open, increment ref count.
*******************************************************************/

static bool acl_tdb_init(struct db_context **pp_db)
{
	const char *dbname;

	if (acl_db) {
		*pp_db = acl_db;
		ref_count++;
		return true;
	}

	dbname = lock_path("file_ntacls.tdb");

	if (dbname == NULL) {
		errno = ENOSYS;
		return false;
	}

	become_root();
	*pp_db = db_open(NULL, dbname, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	unbecome_root();

	if (*pp_db == NULL) {
#if defined(ENOTSUP)
		errno = ENOTSUP;
#else
		errno = ENOSYS;
#endif
		return false;
	}

	ref_count++;
	return true;
}

/*******************************************************************
 Lower ref count and close acl_db if zero.
*******************************************************************/

static void free_acl_tdb_data(void **pptr)
{
	struct db_context **pp_db = (struct db_context **)pptr;

	ref_count--;
	if (ref_count == 0) {
		TALLOC_FREE(*pp_db);
		acl_db = NULL;
	}
}

/*******************************************************************
 Fetch_lock the tdb acl record for a file
*******************************************************************/

static struct db_record *acl_tdb_lock(TALLOC_CTX *mem_ctx,
					struct db_context *db,
					const struct file_id *id)
{
	uint8 id_buf[16];
	push_file_id_16((char *)id_buf, id);
	return db->fetch_locked(db,
				mem_ctx,
				make_tdb_data(id_buf,
					sizeof(id_buf)));
}

/*******************************************************************
 Delete the tdb acl record for a file
*******************************************************************/

static NTSTATUS acl_tdb_delete(vfs_handle_struct *handle,
				struct db_context *db,
				SMB_STRUCT_STAT *psbuf)
{
	NTSTATUS status;
	struct file_id id = vfs_file_id_from_sbuf(handle->conn, psbuf);
	struct db_record *rec = acl_tdb_lock(talloc_tos(), db, &id);

	/*
	 * If rec == NULL there's not much we can do about it
	 */

	if (rec == NULL) {
		DEBUG(10,("acl_tdb_delete: rec == NULL\n"));
		TALLOC_FREE(rec);
		return NT_STATUS_OK;
	}

	status = rec->delete_rec(rec);
	TALLOC_FREE(rec);
	return status;
}

/*******************************************************************
 Parse out a struct security_descriptor from a DATA_BLOB.
*******************************************************************/

static NTSTATUS parse_acl_blob(const DATA_BLOB *pblob,
				uint32 security_info,
				struct security_descriptor **ppdesc)
{
	TALLOC_CTX *ctx = talloc_tos();
	struct xattr_NTACL xacl;
	enum ndr_err_code ndr_err;
	size_t sd_size;

	ndr_err = ndr_pull_struct_blob(pblob, ctx, &xacl,
			(ndr_pull_flags_fn_t)ndr_pull_xattr_NTACL);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("parse_acl_blob: ndr_pull_xattr_NTACL failed: %s\n",
			ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);;
	}

	if (xacl.version != 2) {
		return NT_STATUS_REVISION_MISMATCH;
	}

	*ppdesc = make_sec_desc(ctx, SEC_DESC_REVISION, xacl.info.sd_hs->sd->type | SEC_DESC_SELF_RELATIVE,
			(security_info & OWNER_SECURITY_INFORMATION)
			? xacl.info.sd_hs->sd->owner_sid : NULL,
			(security_info & GROUP_SECURITY_INFORMATION)
			? xacl.info.sd_hs->sd->group_sid : NULL,
			(security_info & SACL_SECURITY_INFORMATION)
			? xacl.info.sd_hs->sd->sacl : NULL,
			(security_info & DACL_SECURITY_INFORMATION)
			? xacl.info.sd_hs->sd->dacl : NULL,
			&sd_size);

	TALLOC_FREE(xacl.info.sd);

	return (*ppdesc != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;
}

/*******************************************************************
 Pull a security descriptor into a DATA_BLOB from a tdb store.
*******************************************************************/

static NTSTATUS get_acl_blob(TALLOC_CTX *ctx,
			vfs_handle_struct *handle,
			files_struct *fsp,
			const char *name,
			DATA_BLOB *pblob)
{
	uint8 id_buf[16];
	TDB_DATA data;
	struct file_id id;
	struct db_context *db;
	SMB_STRUCT_STAT sbuf;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
		return NT_STATUS_INTERNAL_DB_CORRUPTION);

	if (fsp && fsp->fh->fd != -1) {
		if (SMB_VFS_FSTAT(fsp, &sbuf) == -1) {
			return map_nt_error_from_unix(errno);
		}
	} else {
		if (SMB_VFS_STAT(handle->conn, name, &sbuf) == -1) {
			return map_nt_error_from_unix(errno);
		}
	}
	id = vfs_file_id_from_sbuf(handle->conn, &sbuf);

	push_file_id_16((char *)id_buf, &id);

	if (db->fetch(db,
			ctx,
			make_tdb_data(id_buf, sizeof(id_buf)),
			&data) == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	pblob->data = data.dptr;
	pblob->length = data.dsize;

	DEBUG(10,("get_acl_blob: returned %u bytes from file %s\n",
		(unsigned int)data.dsize, name ));

	if (pblob->length == 0 || pblob->data == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	return NT_STATUS_OK;
}

/*******************************************************************
 Create a DATA_BLOB from a security descriptor.
*******************************************************************/

static NTSTATUS create_acl_blob(const struct security_descriptor *psd, DATA_BLOB *pblob)
{
	struct xattr_NTACL xacl;
	struct security_descriptor_hash sd_hs;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *ctx = talloc_tos();

	ZERO_STRUCT(xacl);
	ZERO_STRUCT(sd_hs);

	xacl.version = 2;
	xacl.info.sd_hs = &sd_hs;
	xacl.info.sd_hs->sd = CONST_DISCARD(struct security_descriptor *, psd);
	memset(&xacl.info.sd_hs->hash[0], '\0', 16);

	ndr_err = ndr_push_struct_blob(
			pblob, ctx, &xacl,
			(ndr_push_flags_fn_t)ndr_push_xattr_NTACL);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("create_acl_blob: ndr_push_xattr_NTACL failed: %s\n",
			ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Store a DATA_BLOB into a tdb record given an fsp pointer.
*******************************************************************/

static NTSTATUS store_acl_blob_fsp(vfs_handle_struct *handle,
				files_struct *fsp,
				DATA_BLOB *pblob)
{
	uint8 id_buf[16];
	struct file_id id;
	SMB_STRUCT_STAT sbuf;
	TDB_DATA data;
	struct db_context *db;
	struct db_record *rec;

	DEBUG(10,("store_acl_blob_fsp: storing blob length %u on file %s\n",
			(unsigned int)pblob->length, fsp->fsp_name));

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
		return NT_STATUS_INTERNAL_DB_CORRUPTION);

	if (fsp->fh->fd != -1) {
		if (SMB_VFS_FSTAT(fsp, &sbuf) == -1) {
			return map_nt_error_from_unix(errno);
		}
	} else {
		if (SMB_VFS_STAT(handle->conn, fsp->fsp_name, &sbuf) == -1) {
			return map_nt_error_from_unix(errno);
		}
	}
	id = vfs_file_id_from_sbuf(handle->conn, &sbuf);

	push_file_id_16((char *)id_buf, &id);
	rec = db->fetch_locked(db, talloc_tos(),
				make_tdb_data(id_buf,
					sizeof(id_buf)));
	if (rec == NULL) {
		DEBUG(0, ("store_acl_blob_fsp_tdb: fetch_lock failed\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	data.dptr = pblob->data;
	data.dsize = pblob->length;
	return rec->store(rec, data, 0);
}

/*******************************************************************
 Store a DATA_BLOB into a tdb record given a pathname.
*******************************************************************/

static NTSTATUS store_acl_blob_pathname(vfs_handle_struct *handle,
					const char *fname,
					DATA_BLOB *pblob)
{
	uint8 id_buf[16];
	struct file_id id;
	TDB_DATA data;
	SMB_STRUCT_STAT sbuf;
	struct db_context *db;
	struct db_record *rec;

	DEBUG(10,("store_acl_blob_pathname: storing blob "
			"length %u on file %s\n",
			(unsigned int)pblob->length, fname));

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
		return NT_STATUS_INTERNAL_DB_CORRUPTION);

	if (SMB_VFS_STAT(handle->conn, fname, &sbuf) == -1) {
		return map_nt_error_from_unix(errno);
	}

	id = vfs_file_id_from_sbuf(handle->conn, &sbuf);
	push_file_id_16((char *)id_buf, &id);

	rec = db->fetch_locked(db, talloc_tos(),
				make_tdb_data(id_buf,
					sizeof(id_buf)));
	if (rec == NULL) {
		DEBUG(0, ("store_acl_blob_pathname_tdb: fetch_lock failed\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	data.dptr = pblob->data;
	data.dsize = pblob->length;
	return rec->store(rec, data, 0);
}

/*******************************************************************
 Store a DATA_BLOB into an tdb given a pathname.
*******************************************************************/

static NTSTATUS get_nt_acl_tdb_internal(vfs_handle_struct *handle,
					files_struct *fsp,
					const char *name,
				        uint32 security_info,
					struct security_descriptor **ppdesc)
{
	TALLOC_CTX *ctx = talloc_tos();
	DATA_BLOB blob;
	NTSTATUS status;

	if (fsp && name == NULL) {
		name = fsp->fsp_name;
	}

	DEBUG(10, ("get_nt_acl_tdb_internal: name=%s\n", name));

	status = get_acl_blob(ctx, handle, fsp, name, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("get_acl_blob returned %s\n", nt_errstr(status)));
		return status;
	}

	status = parse_acl_blob(&blob, security_info, ppdesc);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("parse_acl_blob returned %s\n",
				nt_errstr(status)));
		return status;
	}

	TALLOC_FREE(blob.data);
	return status;
}

/*********************************************************************
 Create a default security descriptor for a file in case no inheritance
 exists. All permissions to the owner and SYSTEM.
*********************************************************************/

static struct security_descriptor *default_file_sd(TALLOC_CTX *mem_ctx,
						SMB_STRUCT_STAT *psbuf)
{
	struct dom_sid owner_sid, group_sid;
	size_t sd_size;
	struct security_ace *pace = NULL;
	struct security_acl *pacl = NULL;

	uid_to_sid(&owner_sid, psbuf->st_uid);
	gid_to_sid(&group_sid, psbuf->st_gid);

	pace = TALLOC_ARRAY(mem_ctx, struct security_ace, 2);
	if (!pace) {
		return NULL;
	}

	init_sec_ace(&pace[0], &owner_sid, SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_RIGHTS_FILE_ALL, 0);
	init_sec_ace(&pace[1], &global_sid_System, SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_RIGHTS_FILE_ALL, 0);

	pacl = make_sec_acl(mem_ctx,
				NT4_ACL_REVISION,
				2,
				pace);
	if (!pacl) {
		return NULL;
	}
	return make_sec_desc(mem_ctx,
			SECURITY_DESCRIPTOR_REVISION_1,
			SEC_DESC_SELF_RELATIVE|SEC_DESC_DACL_PRESENT,
			&owner_sid,
			&group_sid,
			NULL,
                        pacl,
			&sd_size);
}

/*********************************************************************
*********************************************************************/

static NTSTATUS inherit_new_acl(vfs_handle_struct *handle,
					const char *fname,
					files_struct *fsp,
					bool container)
{
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status;
	struct security_descriptor *parent_desc = NULL;
	struct security_descriptor *psd = NULL;
	DATA_BLOB blob;
	size_t size;
	char *parent_name;

	if (!parent_dirname_talloc(ctx,
				fname,
				&parent_name,
				NULL)) {
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(10,("inherit_new_acl: check directory %s\n",
			parent_name));

	status = get_nt_acl_tdb_internal(handle,
					NULL,
					parent_name,
					(OWNER_SECURITY_INFORMATION |
					 GROUP_SECURITY_INFORMATION |
					 DACL_SECURITY_INFORMATION),
					&parent_desc);
        if (NT_STATUS_IS_OK(status)) {
		/* Create an inherited descriptor from the parent. */

		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("inherit_new_acl: parent acl is:\n"));
			NDR_PRINT_DEBUG(security_descriptor, parent_desc);
		}

		status = se_create_child_secdesc(ctx,
				&psd,
				&size,
				parent_desc,
				&handle->conn->server_info->ptok->user_sids[PRIMARY_USER_SID_INDEX],
				&handle->conn->server_info->ptok->user_sids[PRIMARY_GROUP_SID_INDEX],
				container);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("inherit_new_acl: child acl is:\n"));
			NDR_PRINT_DEBUG(security_descriptor, psd);
		}

	} else {
		DEBUG(10,("inherit_new_acl: directory %s failed "
			"to get acl %s\n",
			parent_name,
			nt_errstr(status) ));
	}

	if (!psd || psd->dacl == NULL) {
		SMB_STRUCT_STAT sbuf;
		int ret;

		TALLOC_FREE(psd);
		if (fsp && !fsp->is_directory && fsp->fh->fd != -1) {
			ret = SMB_VFS_FSTAT(fsp, &sbuf);
		} else {
			ret = SMB_VFS_STAT(handle->conn,fname, &sbuf);
		}
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
		psd = default_file_sd(ctx, &sbuf);
		if (!psd) {
			return NT_STATUS_NO_MEMORY;
		}

		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("inherit_new_acl: default acl is:\n"));
			NDR_PRINT_DEBUG(security_descriptor, psd);
		}
	}

	status = create_acl_blob(psd, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (fsp) {
		return store_acl_blob_fsp(handle, fsp, &blob);
	} else {
		return store_acl_blob_pathname(handle, fname, &blob);
	}
}

/*********************************************************************
 Check ACL on open. For new files inherit from parent directory.
*********************************************************************/

static int open_acl_tdb(vfs_handle_struct *handle,
					const char *fname,
					files_struct *fsp,
					int flags,
					mode_t mode)
{
	uint32_t access_granted = 0;
	struct security_descriptor *pdesc = NULL;
	bool file_existed = true;
	NTSTATUS status = get_nt_acl_tdb_internal(handle,
					NULL,
					fname,
					(OWNER_SECURITY_INFORMATION |
					 GROUP_SECURITY_INFORMATION |
					 DACL_SECURITY_INFORMATION),
					&pdesc);
        if (NT_STATUS_IS_OK(status)) {
		/* See if we can access it. */
		status = smb1_file_se_access_check(pdesc,
					handle->conn->server_info->ptok,
					fsp->access_mask,
					&access_granted);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10,("open_acl_tdb: file %s open "
				"refused with error %s\n",
				fname,
				nt_errstr(status) ));
			errno = map_errno_from_nt_status(status);
			return -1;
		}
        } else if (NT_STATUS_EQUAL(status,NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		file_existed = false;
	}

	DEBUG(10,("open_acl_tdb: get_nt_acl_attr_internal for "
		"file %s returned %s\n",
		fname,
		nt_errstr(status) ));

	fsp->fh->fd = SMB_VFS_NEXT_OPEN(handle, fname, fsp, flags, mode);

	if (!file_existed && fsp->fh->fd != -1) {
		/* File was created. Inherit from parent directory. */
		string_set(&fsp->fsp_name, fname);
		inherit_new_acl(handle, fname, fsp, false);
	}

	return fsp->fh->fd;
}

/*********************************************************************
 On unlink we need to delete the tdb record (if using tdb).
*********************************************************************/

static int unlink_acl_tdb(vfs_handle_struct *handle, const char *path)
{
	SMB_STRUCT_STAT sbuf;
	struct db_context *db;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context, return -1);

	if (SMB_VFS_STAT(handle->conn, path, &sbuf) == -1) {
		return -1;
	}

	ret = SMB_VFS_NEXT_UNLINK(handle, path);

	if (ret == -1) {
		return -1;
	}

	acl_tdb_delete(handle, db, &sbuf);
	return 0;
}

/*********************************************************************
 Store an inherited SD on mkdir.
*********************************************************************/

static int mkdir_acl_tdb(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	int ret = SMB_VFS_NEXT_MKDIR(handle, path, mode);

	if (ret == -1) {
		return ret;
	}
	/* New directory - inherit from parent. */
	inherit_new_acl(handle, path, NULL, true);
	return ret;
}

/*********************************************************************
 On rmdir we need to delete the tdb record (if using tdb).
*********************************************************************/

static int rmdir_acl_tdb(vfs_handle_struct *handle, const char *path)
{

	SMB_STRUCT_STAT sbuf;
	struct db_context *db;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context, return -1);

	if (SMB_VFS_STAT(handle->conn, path, &sbuf) == -1) {
		return -1;
	}

	ret = SMB_VFS_NEXT_RMDIR(handle, path);
	if (ret == -1) {
		return -1;
	}

	acl_tdb_delete(handle, db, &sbuf);
	return 0;
}

/*********************************************************************
 Fetch a security descriptor given an fsp.
*********************************************************************/

static NTSTATUS fget_nt_acl_tdb(vfs_handle_struct *handle, files_struct *fsp,
        uint32 security_info, struct security_descriptor **ppdesc)
{
	NTSTATUS status = get_nt_acl_tdb_internal(handle, fsp,
				NULL, security_info, ppdesc);
	if (NT_STATUS_IS_OK(status)) {
		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("fget_nt_acl_tdb: returning tdb sd for file %s\n",
				fsp->fsp_name));
			NDR_PRINT_DEBUG(security_descriptor, *ppdesc);
		}
		return NT_STATUS_OK;
	}

	DEBUG(10,("fget_nt_acl_tdb: failed to get tdb sd for file %s, Error %s\n",
			fsp->fsp_name,
			nt_errstr(status) ));

	return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp,
			security_info, ppdesc);
}

/*********************************************************************
 Fetch a security descriptor given a pathname.
*********************************************************************/

static NTSTATUS get_nt_acl_tdb(vfs_handle_struct *handle,
        const char *name, uint32 security_info, struct security_descriptor **ppdesc)
{
	NTSTATUS status = get_nt_acl_tdb_internal(handle, NULL,
				name, security_info, ppdesc);
	if (NT_STATUS_IS_OK(status)) {
		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("get_nt_acl_tdb: returning tdb sd for file %s\n",
				name));
			NDR_PRINT_DEBUG(security_descriptor, *ppdesc);
		}
		return NT_STATUS_OK;
	}

	DEBUG(10,("get_nt_acl_tdb: failed to get tdb sd for file %s, Error %s\n",
			name,
			nt_errstr(status) ));

	return SMB_VFS_NEXT_GET_NT_ACL(handle, name,
			security_info, ppdesc);
}

/*********************************************************************
 Store a security descriptor given an fsp.
*********************************************************************/

static NTSTATUS fset_nt_acl_tdb(vfs_handle_struct *handle, files_struct *fsp,
        uint32 security_info_sent, const struct security_descriptor *psd)
{
	NTSTATUS status;
	DATA_BLOB blob;

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("fset_nt_acl_tdb: incoming sd for file %s\n",
			fsp->fsp_name));
		NDR_PRINT_DEBUG(security_descriptor,
			CONST_DISCARD(struct security_descriptor *,psd));
	}

	status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Ensure owner and group are set. */
	if (!psd->owner_sid || !psd->group_sid) {
		int ret;
		SMB_STRUCT_STAT sbuf;
		DOM_SID owner_sid, group_sid;
		struct security_descriptor *nc_psd = dup_sec_desc(talloc_tos(), psd);

		if (!nc_psd) {
			return NT_STATUS_OK;
		}
		if (fsp->is_directory || fsp->fh->fd == -1) {
			ret = SMB_VFS_STAT(fsp->conn,fsp->fsp_name, &sbuf);
		} else {
			ret = SMB_VFS_FSTAT(fsp, &sbuf);
		}
		if (ret == -1) {
			/* Lower level acl set succeeded,
			 * so still return OK. */
			return NT_STATUS_OK;
		}
		create_file_sids(&sbuf, &owner_sid, &group_sid);
		/* This is safe as nc_psd is discarded at fn exit. */
		nc_psd->owner_sid = &owner_sid;
		nc_psd->group_sid = &group_sid;
		security_info_sent |= (OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION);
		psd = nc_psd;
	}

#if 0
	if ((security_info_sent & DACL_SECURITY_INFORMATION) &&
			psd->dacl != NULL &&
			(psd->type & (SE_DESC_DACL_AUTO_INHERITED|
				SE_DESC_DACL_AUTO_INHERIT_REQ))==
				(SE_DESC_DACL_AUTO_INHERITED|
				SE_DESC_DACL_AUTO_INHERIT_REQ) ) {
		struct security_descriptor *new_psd = NULL;
		status = append_parent_acl(fsp, psd, &new_psd);
		if (!NT_STATUS_IS_OK(status)) {
			/* Lower level acl set succeeded,
			 * so still return OK. */
			return NT_STATUS_OK;
		}
		psd = new_psd;
	}
#endif

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("fset_nt_acl_tdb: storing tdb sd for file %s\n",
			fsp->fsp_name));
		NDR_PRINT_DEBUG(security_descriptor,
			CONST_DISCARD(struct security_descriptor *,psd));
	}
	create_acl_blob(psd, &blob);
	store_acl_blob_fsp(handle, fsp, &blob);

	return NT_STATUS_OK;
}

/*******************************************************************
 Handle opening the storage tdb if so configured.
*******************************************************************/

static int connect_acl_tdb(struct vfs_handle_struct *handle,
				const char *service,
				const char *user)
{
	struct db_context *db;
	int res;

        res = SMB_VFS_NEXT_CONNECT(handle, service, user);
        if (res < 0) {
                return res;
        }

	if (!acl_tdb_init(&db)) {
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, db, free_acl_tdb_data,
				struct db_context, return -1);

	return 0;
}

/*********************************************************************
 Remove a Windows ACL - we're setting the underlying POSIX ACL.
*********************************************************************/

static int sys_acl_set_file_tdb(vfs_handle_struct *handle,
                              const char *path,
                              SMB_ACL_TYPE_T type,
                              SMB_ACL_T theacl)
{
	SMB_STRUCT_STAT sbuf;
	struct db_context *db;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context, return -1);

	if (SMB_VFS_STAT(handle->conn, path, &sbuf) == -1) {
		return -1;
	}

	ret = SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle,
						path,
						type,
						theacl);
	if (ret == -1) {
		return -1;
	}

	acl_tdb_delete(handle, db, &sbuf);
	return 0;
}

/*********************************************************************
 Remove a Windows ACL - we're setting the underlying POSIX ACL.
*********************************************************************/

static int sys_acl_set_fd_tdb(vfs_handle_struct *handle,
                            files_struct *fsp,
                            SMB_ACL_T theacl)
{
	SMB_STRUCT_STAT sbuf;
	struct db_context *db;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context, return -1);

	if (fsp->is_directory || fsp->fh->fd == -1) {
		ret = SMB_VFS_STAT(fsp->conn,fsp->fsp_name, &sbuf);
	} else {
		ret = SMB_VFS_FSTAT(fsp, &sbuf);
	}
	if (ret == -1) {
		return -1;
	}

	ret = SMB_VFS_NEXT_SYS_ACL_SET_FD(handle,
						fsp,
						theacl);
	if (ret == -1) {
		return -1;
	}

	acl_tdb_delete(handle, db, &sbuf);
	return 0;
}

/* VFS operations structure */

static vfs_op_tuple skel_op_tuples[] =
{
	{SMB_VFS_OP(connect_acl_tdb), SMB_VFS_OP_CONNECT,  SMB_VFS_LAYER_TRANSPARENT},

	{SMB_VFS_OP(mkdir_acl_tdb), SMB_VFS_OP_MKDIR, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(rmdir_acl_tdb), SMB_VFS_OP_RMDIR, SMB_VFS_LAYER_TRANSPARENT},

	{SMB_VFS_OP(open_acl_tdb),  SMB_VFS_OP_OPEN,  SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(unlink_acl_tdb), SMB_VFS_OP_UNLINK, SMB_VFS_LAYER_TRANSPARENT},

        /* NT File ACL operations */

	{SMB_VFS_OP(fget_nt_acl_tdb),SMB_VFS_OP_FGET_NT_ACL,SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(get_nt_acl_tdb), SMB_VFS_OP_GET_NT_ACL, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(fset_nt_acl_tdb),SMB_VFS_OP_FSET_NT_ACL,SMB_VFS_LAYER_TRANSPARENT},

	/* POSIX ACL operations. */
	{SMB_VFS_OP(sys_acl_set_file_tdb), SMB_VFS_OP_SYS_ACL_SET_FILE, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(sys_acl_set_fd_tdb), SMB_VFS_OP_SYS_ACL_SET_FD, SMB_VFS_LAYER_TRANSPARENT},

	{SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_acl_tdb_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "acl_tdb", skel_op_tuples);
}
