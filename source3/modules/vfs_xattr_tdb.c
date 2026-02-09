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

struct xattr_tdb_config {
	struct db_context *db;
	bool ignore_user_xattr;
};

static bool xattr_tdb_init(struct vfs_handle_struct *handle,
			   struct xattr_tdb_config **_config);

static bool is_user_xattr(const char *xattr_name)
{
	int match;

	match = strncmp(xattr_name, "user.", strlen("user."));
	return (match == 0);
}

struct xattr_tdb_getxattrat_state {
	struct vfs_aio_state vfs_aio_state;
	ssize_t xattr_size;
	uint8_t *xattr_value;
};

static void xattr_tdb_getxattrat_done(struct tevent_req *subreq);

static struct tevent_req *xattr_tdb_getxattrat_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			const struct smb_filename *_smb_fname,
			const char *xattr_name,
			size_t alloc_hint)
{
	struct xattr_tdb_config *config = NULL;
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct xattr_tdb_getxattrat_state *state = NULL;
	struct smb_filename *smb_fname = NULL;
	struct file_id id;
	DATA_BLOB xattr_blob;
	NTSTATUS status;

	if (!xattr_tdb_init(handle, &config)) {
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state,
				struct xattr_tdb_getxattrat_state);
	if (req == NULL) {
		return NULL;
	}
	state->xattr_size = -1;

	if (config->ignore_user_xattr && is_user_xattr(xattr_name)) {
		subreq = SMB_VFS_NEXT_GETXATTRAT_SEND(state,
						      ev,
						      handle,
						      dir_fsp,
						      smb_fname,
						      xattr_name,
						      alloc_hint);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, xattr_tdb_getxattrat_done, req);
		return req;
	}

	smb_fname = cp_smb_filename(talloc_tos(), _smb_fname);
	if (tevent_req_nomem(smb_fname, req)) {
		return tevent_req_post(req, ev);
	}

	status = openat_pathref_fsp(dir_fsp, smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_error(req, map_errno_from_nt_status(status));
		return tevent_req_post(req, ev);
	}


	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &smb_fname->st);

	TALLOC_FREE(smb_fname);

	state->xattr_size = xattr_tdb_getattr(config->db,
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

static void xattr_tdb_getxattrat_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct xattr_tdb_getxattrat_state *state = tevent_req_data(
		req, struct xattr_tdb_getxattrat_state);

	state->xattr_size = SMB_VFS_NEXT_GETXATTRAT_RECV(subreq,
							 &state->vfs_aio_state,
							 state,
							 &state->xattr_value);
	TALLOC_FREE(subreq);
	if (state->xattr_size == -1) {
		tevent_req_error(req, state->vfs_aio_state.error);
		return;
	}

	tevent_req_done(req);
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
	struct xattr_tdb_config *config = NULL;
	SMB_STRUCT_STAT sbuf;
	struct file_id id;
	ssize_t xattr_size;
	DATA_BLOB blob;
	TALLOC_CTX *frame = NULL;

	if (!xattr_tdb_init(handle, &config)) {
		return -1;
	}

	if (config->ignore_user_xattr && is_user_xattr(name)) {
		return SMB_VFS_NEXT_FGETXATTR(
			handle, fsp, name, value, size);
	}

	if (SMB_VFS_NEXT_FSTAT(handle, fsp, &sbuf) == -1) {
		return -1;
	}

	frame = talloc_stackframe();

	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &sbuf);

	xattr_size = xattr_tdb_getattr(config->db, frame, &id, name, &blob);
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

static int xattr_tdb_fsetxattr(struct vfs_handle_struct *handle,
			       struct files_struct *fsp,
			       const char *name, const void *value,
			       size_t size, int flags)
{
	struct xattr_tdb_config *config = NULL;
	SMB_STRUCT_STAT sbuf;
	struct file_id id;
	int ret;

	if (!xattr_tdb_init(handle, &config)) {
		return -1;
	}

	if (config->ignore_user_xattr && is_user_xattr(name)) {
		return SMB_VFS_NEXT_FSETXATTR(
			handle, fsp, name, value, size, flags);
	}

	if (SMB_VFS_NEXT_FSTAT(handle, fsp, &sbuf) == -1) {
		return -1;
	}

	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &sbuf);

	ret = xattr_tdb_setattr(config->db, &id, name, value, size, flags);
	return ret;

}

static ssize_t xattr_tdb_flistxattr(struct vfs_handle_struct *handle,
				    struct files_struct *fsp, char *list,
				    size_t size)
{
	struct xattr_tdb_config *config = NULL;
	SMB_STRUCT_STAT sbuf;
	struct file_id id;
	ssize_t backend_size;
	ssize_t ret;

	if (!xattr_tdb_init(handle, &config)) {
		return -1;
	}

	if (SMB_VFS_NEXT_FSTAT(handle, fsp, &sbuf) == -1) {
		return -1;
	}

	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &sbuf);

	ret = xattr_tdb_listattr(config->db, &id, list, size);
	if (ret == -1) {
		return -1;
	}
	if (ret == size) {
		return ret;
	}
	if (!config->ignore_user_xattr) {
		return ret;
	}
	SMB_ASSERT(ret < size);

	backend_size = SMB_VFS_NEXT_FLISTXATTR(
		handle, fsp, list + ret, size - ret);
	if (backend_size == -1) {
		return -1;
	}

	return ret + backend_size;
}

static int xattr_tdb_fremovexattr(struct vfs_handle_struct *handle,
				  struct files_struct *fsp, const char *name)
{
	struct xattr_tdb_config *config = NULL;
	SMB_STRUCT_STAT sbuf;
	struct file_id id;

	if (!xattr_tdb_init(handle, &config)) {
		return -1;
	}

	if (config->ignore_user_xattr && is_user_xattr(name)) {
		return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
	}

	if (SMB_VFS_NEXT_FSTAT(handle, fsp, &sbuf) == -1) {
		return -1;
	}

	id = SMB_VFS_NEXT_FILE_ID_CREATE(handle, &sbuf);

	return xattr_tdb_removeattr(config->db, &id, name);
}

/*
 * Destructor for the VFS private data
 */

static void config_destructor(void **data)
{
	struct xattr_tdb_config **config = (struct xattr_tdb_config **)data;
	TALLOC_FREE((*config)->db);
}

/*
 * Open the tdb file upon VFS_CONNECT
 */

static bool xattr_tdb_init(struct vfs_handle_struct *handle,
			   struct xattr_tdb_config **_config)
{
	struct xattr_tdb_config *config = NULL;
	const char *dbname;
	char *def_dbname;

	if (SMB_VFS_HANDLE_TEST_DATA(handle)) {
		SMB_VFS_HANDLE_GET_DATA(handle, config, struct xattr_tdb_config,
					return false);
		if (_config != NULL) {
			*_config = config;
		}
		return true;
	}

	config = talloc_zero(handle->conn, struct xattr_tdb_config);
	if (config == NULL) {
		errno = ENOMEM;
		goto error;
	}

	def_dbname = state_path(talloc_tos(), "xattr.tdb");
	if (def_dbname == NULL) {
		errno = ENOSYS;
		goto error;
	}

	dbname = lp_parm_const_string(SNUM(handle->conn),
				      "xattr_tdb",
				      "file",
				      def_dbname);

	/* now we know dbname is not NULL */

	become_root();
	config->db = db_open(handle, dbname, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600,
			     DBWRAP_LOCK_ORDER_2, DBWRAP_FLAG_NONE);
	unbecome_root();

	if (config->db == NULL) {
#if defined(ENOTSUP)
		errno = ENOTSUP;
#else
		errno = ENOSYS;
#endif
		TALLOC_FREE(def_dbname);
		goto error;
	}
	TALLOC_FREE(def_dbname);

	config->ignore_user_xattr = lp_parm_bool(
		SNUM(handle->conn), "xattr_tdb", "ignore_user_xattr", false);

	SMB_VFS_HANDLE_SET_DATA(handle, config, config_destructor,
				struct xattr_tdb_config, return false);

	if (_config != NULL) {
		*_config = config;
	}
	return true;

error:
	DBG_WARNING("Failed to initialize config: %s\n", strerror(errno));
	lp_do_parameter(SNUM(handle->conn), "ea support", "False");
	return false;
}

static int xattr_tdb_openat(struct vfs_handle_struct *handle,
			    const struct files_struct *dirfsp,
			    const struct smb_filename *smb_fname,
			    struct files_struct *fsp,
			    const struct vfs_open_how *how)
{
	struct xattr_tdb_config *config = NULL;
	SMB_STRUCT_STAT sbuf;
	int fd;
	int ret;

	if (!xattr_tdb_init(handle, &config)) {
		return -1;
	}

	fd = SMB_VFS_NEXT_OPENAT(handle,
				 dirfsp,
				 smb_fname,
				 fsp,
				 how);
	if (fd == -1) {
		return -1;
	}

	if ((how->flags & (O_CREAT|O_EXCL)) != (O_CREAT|O_EXCL)) {
		return fd;
	}

	/*
	 * We know we used O_CREAT|O_EXCL and it worked.
	 * We must have created the file.
	 */

	fsp_set_fd(fsp, fd);
	ret = SMB_VFS_FSTAT(fsp, &sbuf);
	fsp_set_fd(fsp, -1);
	if (ret == -1) {
		/* Can't happen... */
		DBG_WARNING("SMB_VFS_FSTAT failed on file %s (%s)\n",
			    smb_fname_str_dbg(smb_fname),
			    strerror(errno));
		return -1;
	}

	fsp->file_id = SMB_VFS_FILE_ID_CREATE(fsp->conn, &sbuf);

	xattr_tdb_remove_all_attrs(config->db, &fsp->file_id);

	return fd;
}

static int xattr_tdb_mkdirat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	struct xattr_tdb_config *config = NULL;
	struct file_id fileid;
	struct stat_ex sbuf = { .st_ex_nlink = 0, };
	int ret;

	if (!xattr_tdb_init(handle, &config)) {
		return -1;
	}

	ret = SMB_VFS_NEXT_MKDIRAT(handle,
				dirfsp,
				smb_fname,
				mode);
	if (ret < 0) {
		return ret;
	}

	ret = SMB_VFS_NEXT_FSTATAT(
		handle, dirfsp, smb_fname, &sbuf, AT_SYMLINK_NOFOLLOW);

	if (ret == -1) {
		/* Rename race. Let upper level take care of it. */
		return -1;
	}
	if (!S_ISDIR(sbuf.st_ex_mode)) {
		/* Rename race. Let upper level take care of it. */
		return -1;
	}

	fileid = SMB_VFS_FILE_ID_CREATE(handle->conn, &sbuf);

	xattr_tdb_remove_all_attrs(config->db, &fileid);
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
	struct xattr_tdb_config *config = NULL;
	struct smb_filename *smb_fname_tmp = NULL;
	struct smb_filename *full_fname = NULL;
	struct file_id id;
	int ret = -1;
	bool remove_record = false;
	TALLOC_CTX *frame = NULL;

	if (!xattr_tdb_init(handle, &config)) {
		return -1;
	}

	frame = talloc_stackframe();

	smb_fname_tmp = cp_smb_filename(frame, smb_fname);
	if (smb_fname_tmp == NULL) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return -1;
	}

	/*
	 * TODO: use SMB_VFS_STATX() once we have that
	 */

	full_fname = full_path_from_dirfsp_atname(frame,
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		goto out;
	}

	if (full_fname->flags & SMB_FILENAME_POSIX_PATH) {
		ret = SMB_VFS_NEXT_LSTAT(handle, full_fname);
	} else {
		ret = SMB_VFS_NEXT_STAT(handle, full_fname);
		if (ret == -1 && (errno == ENOENT || errno == ELOOP)) {
			/*
			 * Could be trying to remove a dangling symlink.
			 */
			ret = SMB_VFS_NEXT_LSTAT(handle, full_fname);
			if (ret == 0 && !S_ISLNK(full_fname->st.st_ex_mode)) {
				ret = -1;
			}
		}
	}
	if (ret == -1) {
		goto out;
	}
	smb_fname_tmp->st = full_fname->st;

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

	xattr_tdb_remove_all_attrs(config->db, &id);

 out:
	TALLOC_FREE(frame);
	return ret;
}

static int xattr_tdb_connect(vfs_handle_struct *handle, const char *service,
			  const char *user)
{
	char *sname = NULL;
	int res, snum;

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

	if (!xattr_tdb_init(handle, NULL)) {
		DEBUG(5, ("Could not init xattr tdb\n"));
		lp_do_parameter(snum, "ea support", "False");
		return 0;
	}

	lp_do_parameter(snum, "ea support", "True");

	return 0;
}

static struct vfs_fn_pointers vfs_xattr_tdb_fns = {
	.getxattrat_send_fn = xattr_tdb_getxattrat_send,
	.getxattrat_recv_fn = xattr_tdb_getxattrat_recv,
	.fgetxattr_fn = xattr_tdb_fgetxattr,
	.fsetxattr_fn = xattr_tdb_fsetxattr,
	.flistxattr_fn = xattr_tdb_flistxattr,
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
