/*
 * Store posix-level xattrs in a tdb
 *
 * Copyright (C) Volker Lendecke, 2007
 * Copyright (C) Andrew Bartlett, 2012
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

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "source3/lib/xattr_tdb.h"
#include "lib/util/tevent_unix.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static bool xattr_tdb_init(int snum, TALLOC_CTX *mem_ctx, struct db_context **p_db);

static int xattr_tdb_get_file_id(struct vfs_handle_struct *handle,
				const char *path, struct file_id *id)
{
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();
	struct smb_filename *smb_fname;

	smb_fname = synthetic_smb_fname(frame,
					path,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);

	if (ret == -1) {
		TALLOC_FREE(frame); 
		return -1;
	}

	*id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &smb_fname->st);
	TALLOC_FREE(frame);
	return 0;
}

static ssize_t xattr_tdb_getxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size)
{
	struct file_id id;
	struct db_context *db;
	ssize_t xattr_size;
	int ret;
	DATA_BLOB blob;
	TALLOC_CTX *frame = talloc_stackframe();

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	ret = xattr_tdb_get_file_id(handle, smb_fname->base_name, &id);
	if (ret == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	xattr_size = xattr_tdb_getattr(db, frame, &id, name, &blob);
	if (xattr_size < 0) {
		errno = ENOATTR;
		TALLOC_FREE(frame);
		return -1;
	}

	if (size == 0) {
		TALLOC_FREE(frame);
		return xattr_size;
	}

	if (blob.length > size) {
		TALLOC_FREE(frame);
		errno = ERANGE;
		return -1;
	}
	memcpy(value, blob.data, xattr_size);
	TALLOC_FREE(frame);
	return xattr_size;
}

struct xattr_tdb_getxattrat_state {
	struct vfs_aio_state vfs_aio_state;
	ssize_t xattr_size;
	uint8_t *xattr_value;
};

static struct tevent_req *xattr_tdb_getxattrat_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			const struct smb_filename *smb_fname,
			const char *xattr_name,
			size_t alloc_hint)
{
	struct tevent_req *req = NULL;
	struct xattr_tdb_getxattrat_state *state = NULL;
	struct smb_filename *cwd = NULL;
	struct db_context *db = NULL;
	struct file_id id;
	int ret;
	int error;
	int cwd_ret;
	DATA_BLOB xattr_blob;

	req = tevent_req_create(mem_ctx, &state,
				struct xattr_tdb_getxattrat_state);
	if (req == NULL) {
		return NULL;
	}
	state->xattr_size = -1;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, state, &db)) {
					tevent_req_error(req, EIO);
					return tevent_req_post(req, ev);
				});

	cwd = SMB_VFS_GETWD(dir_fsp->conn, state);
	if (tevent_req_nomem(cwd, req)) {
		return tevent_req_post(req, ev);
	}

	ret = SMB_VFS_CHDIR(dir_fsp->conn, dir_fsp->fsp_name);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = xattr_tdb_get_file_id(handle, smb_fname->base_name, &id);
	error = errno;

	cwd_ret = SMB_VFS_CHDIR(dir_fsp->conn, cwd);
	SMB_ASSERT(cwd_ret == 0);

	if (ret == -1) {
		tevent_req_error(req, error);
		return tevent_req_post(req, ev);
	}

	state->xattr_size = xattr_tdb_getattr(db,
					      state,
					      &id,
					      xattr_name,
					      &xattr_blob);
	if (state->xattr_size == -1) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	if (alloc_hint == 0) {
		/*
		 * The caller only wants to know the size.
		 */
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (state->xattr_size == 0) {
		/*
		 * There's no data.
		 */
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (xattr_blob.length > alloc_hint) {
		/*
		 * The data doesn't fit.
		 */
		state->xattr_size = -1;
		tevent_req_error(req, ERANGE);
		return tevent_req_post(req, ev);
	}

	/*
	 * take the whole blob.
	 */
	state->xattr_value = xattr_blob.data;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static ssize_t xattr_tdb_getxattrat_recv(struct tevent_req *req,
					 struct vfs_aio_state *aio_state,
					 TALLOC_CTX *mem_ctx,
					 uint8_t **xattr_value)
{
	struct xattr_tdb_getxattrat_state *state = tevent_req_data(
		req, struct xattr_tdb_getxattrat_state);
	ssize_t xattr_size;

	if (tevent_req_is_unix_error(req, &aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	*aio_state = state->vfs_aio_state;
	xattr_size = state->xattr_size;
	if (xattr_value != NULL) {
		*xattr_value = talloc_move(mem_ctx, &state->xattr_value);
	}

	tevent_req_received(req);
	return xattr_size;
}

static ssize_t xattr_tdb_fgetxattr(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   const char *name, void *value, size_t size)
{
	SMB_STRUCT_STAT sbuf;
	struct file_id id;
	struct db_context *db;
	ssize_t xattr_size;
	DATA_BLOB blob;
	TALLOC_CTX *frame = talloc_stackframe();

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	if (SMB_VFS_NEXT_FSTAT(handle, fsp, &sbuf) == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &sbuf);

	xattr_size = xattr_tdb_getattr(db, frame, &id, name, &blob);
	if (xattr_size < 0) {
		errno = ENOATTR;
		TALLOC_FREE(frame);
		return -1;
	}

	if (size == 0) {
		TALLOC_FREE(frame);
		return xattr_size;
	}

	if (blob.length > size) {
		TALLOC_FREE(frame);
		errno = ERANGE;
		return -1;
	}
	memcpy(value, blob.data, xattr_size);
	TALLOC_FREE(frame);
	return xattr_size;
}

static int xattr_tdb_setxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				const void *value,
				size_t size,
				int flags)
{
	struct file_id id;
	struct db_context *db;
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	ret = xattr_tdb_get_file_id(handle, smb_fname->base_name, &id);
	if (ret == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	ret = xattr_tdb_setattr(db, &id, name, value, size, flags);
	TALLOC_FREE(frame);
	return ret;
}

static int xattr_tdb_fsetxattr(struct vfs_handle_struct *handle,
			       struct files_struct *fsp,
			       const char *name, const void *value,
			       size_t size, int flags)
{
	SMB_STRUCT_STAT sbuf;
	struct file_id id;
	struct db_context *db;
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	if (SMB_VFS_NEXT_FSTAT(handle, fsp, &sbuf) == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &sbuf);

	ret = xattr_tdb_setattr(db, &id, name, value, size, flags);
	TALLOC_FREE(frame);
	return ret;

}

static ssize_t xattr_tdb_listxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				char *list,
				size_t size)
{
	struct file_id id;
	struct db_context *db;
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	ret = xattr_tdb_get_file_id(handle, smb_fname->base_name, &id);
	if (ret == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	ret = xattr_tdb_listattr(db, &id, list, size);
	TALLOC_FREE(frame);
	return ret;

}

static ssize_t xattr_tdb_flistxattr(struct vfs_handle_struct *handle,
				    struct files_struct *fsp, char *list,
				    size_t size)
{
	SMB_STRUCT_STAT sbuf;
	struct file_id id;
	struct db_context *db;
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	if (SMB_VFS_NEXT_FSTAT(handle, fsp, &sbuf) == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &sbuf);

	ret = xattr_tdb_listattr(db, &id, list, size);
	TALLOC_FREE(frame);
	return ret;
}

static int xattr_tdb_removexattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name)
{
	struct file_id id;
	struct db_context *db;
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	ret = xattr_tdb_get_file_id(handle, smb_fname->base_name, &id);
	if (ret == -1) {
		TALLOC_FREE(frame);
		return ret;
	}

	
	ret = xattr_tdb_removeattr(db, &id, name);
	TALLOC_FREE(frame);
	return ret;
}

static int xattr_tdb_fremovexattr(struct vfs_handle_struct *handle,
				  struct files_struct *fsp, const char *name)
{
	SMB_STRUCT_STAT sbuf;
	struct file_id id;
	struct db_context *db;
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	if (SMB_VFS_NEXT_FSTAT(handle, fsp, &sbuf) == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &sbuf);

	ret = xattr_tdb_removeattr(db, &id, name);
	TALLOC_FREE(frame);
	return ret;
}

/*
 * Open the tdb file upon VFS_CONNECT
 */

static bool xattr_tdb_init(int snum, TALLOC_CTX *mem_ctx, struct db_context **p_db)
{
	struct db_context *db;
	const char *dbname;
	char *def_dbname;

	def_dbname = state_path(talloc_tos(), "xattr.tdb");
	if (def_dbname == NULL) {
		errno = ENOSYS;
		return false;
	}

	dbname = lp_parm_const_string(snum, "xattr_tdb", "file", def_dbname);

	/* now we know dbname is not NULL */

	become_root();
	db = db_open(NULL, dbname, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600,
		     DBWRAP_LOCK_ORDER_2, DBWRAP_FLAG_NONE);
	unbecome_root();

	if (db == NULL) {
#if defined(ENOTSUP)
		errno = ENOTSUP;
#else
		errno = ENOSYS;
#endif
		TALLOC_FREE(def_dbname);
		return false;
	}

	*p_db = db;
	TALLOC_FREE(def_dbname);
	return true;
}

static int xattr_tdb_openat(struct vfs_handle_struct *handle,
			    const struct files_struct *dirfsp,
			    const struct smb_filename *smb_fname,
			    struct files_struct *fsp,
			    int flags,
			    mode_t mode)
{
	struct db_context *db = NULL;
	TALLOC_CTX *frame = NULL;
	SMB_STRUCT_STAT sbuf;
	int ret;

	fsp->fh->fd = SMB_VFS_NEXT_OPENAT(handle,
					  dirfsp,
					  smb_fname,
					  fsp,
					  flags,
					  mode);

	if (fsp->fh->fd < 0) {
		return fsp->fh->fd;
	}

	if ((flags & (O_CREAT|O_EXCL)) != (O_CREAT|O_EXCL)) {
		return fsp->fh->fd;
	}

	/*
	 * We know we used O_CREAT|O_EXCL and it worked.
	 * We must have created the file.
	 */

	ret = SMB_VFS_FSTAT(fsp, &sbuf);
	if (ret == -1) {
		/* Can't happen... */
		DBG_WARNING("SMB_VFS_FSTAT failed on file %s (%s)\n",
			    smb_fname_str_dbg(smb_fname),
			    strerror(errno));
		return -1;
	}

	fsp->file_id = SMB_VFS_FILE_ID_CREATE(fsp->conn, &sbuf);

	frame = talloc_stackframe();

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	xattr_tdb_remove_all_attrs(db, &fsp->file_id);

	TALLOC_FREE(frame);
	return fsp->fh->fd;
}

static int xattr_tdb_mkdirat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	struct db_context *db = NULL;
	TALLOC_CTX *frame = NULL;
	struct file_id fileid;
	int ret;
	struct smb_filename *smb_fname_tmp = NULL;

	ret = SMB_VFS_NEXT_MKDIRAT(handle,
				dirfsp,
				smb_fname,
				mode);
	if (ret < 0) {
		return ret;
	}

	frame = talloc_stackframe();
	smb_fname_tmp = cp_smb_filename(frame, smb_fname);
	if (smb_fname_tmp == NULL) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return -1;
	}

	/* Always use LSTAT here - we just creaded the directory. */
	ret = SMB_VFS_LSTAT(handle->conn, smb_fname_tmp);
	if (ret == -1) {
		/* Rename race. Let upper level take care of it. */
		TALLOC_FREE(frame);
		return -1;
	}
	if (!S_ISDIR(smb_fname_tmp->st.st_ex_mode)) {
		/* Rename race. Let upper level take care of it. */
		TALLOC_FREE(frame);
		return -1;
	}

	fileid = SMB_VFS_FILE_ID_CREATE(handle->conn, &smb_fname_tmp->st);

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	xattr_tdb_remove_all_attrs(db, &fileid);
	TALLOC_FREE(frame);
	return 0;
}

/*
 * On unlink we need to delete the tdb record
 */
static int xattr_tdb_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	struct smb_filename *smb_fname_tmp = NULL;
	struct file_id id;
	struct db_context *db;
	int ret = -1;
	bool remove_record = false;
	TALLOC_CTX *frame = talloc_stackframe();

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct db_context,
				if (!xattr_tdb_init(-1, frame, &db))
				{
					TALLOC_FREE(frame); return -1;
				});

	smb_fname_tmp = cp_smb_filename(frame, smb_fname);
	if (smb_fname_tmp == NULL) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return -1;
	}

	if (smb_fname_tmp->flags & SMB_FILENAME_POSIX_PATH) {
		ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname_tmp);
	} else {
		ret = SMB_VFS_NEXT_STAT(handle, smb_fname_tmp);
	}
	if (ret == -1) {
		goto out;
	}

	if (flags & AT_REMOVEDIR) {
		/* Always remove record when removing a directory succeeds. */
		remove_record = true;
	} else {
		if (smb_fname_tmp->st.st_ex_nlink == 1) {
			/* Only remove record on last link to file. */
			remove_record = true;
		}
	}

	ret = SMB_VFS_NEXT_UNLINKAT(handle,
				dirfsp,
				smb_fname_tmp,
				flags);

	if (ret == -1) {
		goto out;
	}

	if (!remove_record) {
		goto out;
	}

	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &smb_fname_tmp->st);

	xattr_tdb_remove_all_attrs(db, &id);

 out:
	TALLOC_FREE(frame);
	return ret;
}

/*
 * Destructor for the VFS private data
 */

static void close_xattr_db(void **data)
{
	struct db_context **p_db = (struct db_context **)data;
	TALLOC_FREE(*p_db);
}

static int xattr_tdb_connect(vfs_handle_struct *handle, const char *service,
			  const char *user)
{
	char *sname = NULL;
	int res, snum;
	struct db_context *db;

	res = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (res < 0) {
		return res;
	}

	snum = find_service(talloc_tos(), service, &sname);
	if (snum == -1 || sname == NULL) {
		/*
		 * Should not happen, but we should not fail just *here*.
		 */
		return 0;
	}

	if (!xattr_tdb_init(snum, NULL, &db)) {
		DEBUG(5, ("Could not init xattr tdb\n"));
		lp_do_parameter(snum, "ea support", "False");
		return 0;
	}

	lp_do_parameter(snum, "ea support", "True");

	SMB_VFS_HANDLE_SET_DATA(handle, db, close_xattr_db,
				struct db_context, return -1);

	return 0;
}

static struct vfs_fn_pointers vfs_xattr_tdb_fns = {
	.getxattr_fn = xattr_tdb_getxattr,
	.getxattrat_send_fn = xattr_tdb_getxattrat_send,
	.getxattrat_recv_fn = xattr_tdb_getxattrat_recv,
	.fgetxattr_fn = xattr_tdb_fgetxattr,
	.setxattr_fn = xattr_tdb_setxattr,
	.fsetxattr_fn = xattr_tdb_fsetxattr,
	.listxattr_fn = xattr_tdb_listxattr,
	.flistxattr_fn = xattr_tdb_flistxattr,
	.removexattr_fn = xattr_tdb_removexattr,
	.fremovexattr_fn = xattr_tdb_fremovexattr,
	.openat_fn = xattr_tdb_openat,
	.mkdirat_fn = xattr_tdb_mkdirat,
	.unlinkat_fn = xattr_tdb_unlinkat,
	.connect_fn = xattr_tdb_connect,
};

static_decl_vfs;
NTSTATUS vfs_xattr_tdb_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "xattr_tdb",
				&vfs_xattr_tdb_fns);
}
