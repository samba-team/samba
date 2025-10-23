/*
   Unix SMB/CIFS implementation.
   Files[] structure handling
   Copyright (C) Andrew Tridgell 1998

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "smbd/smbXsrv_open.h"
#include "libcli/security/security.h"
#include "util_tdb.h"
#include "lib/util/bitmap.h"
#include "lib/util/strv.h"
#include "lib/util/memcache.h"
#include "libcli/smb/reparse.h"

#define FILE_HANDLE_OFFSET 0x1000

static NTSTATUS fsp_attach_smb_fname(struct files_struct *fsp,
				     struct smb_filename **_smb_fname);

/**
 * create new fsp to be used for file_new or a durable handle reconnect
 */
NTSTATUS fsp_new(struct connection_struct *conn, TALLOC_CTX *mem_ctx,
		 files_struct **result)
{
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	files_struct *fsp = NULL;
	struct smbd_server_connection *sconn = conn->sconn;

	fsp = talloc_zero(mem_ctx, struct files_struct);
	if (fsp == NULL) {
		goto fail;
	}

	/*
	 * This can't be a child of fsp because the file_handle can be ref'd
	 * when doing a dos/fcb open, which will then share the file_handle
	 * across multiple fsps.
	 */
	fsp->fh = fd_handle_create(mem_ctx);
	if (fsp->fh == NULL) {
		goto fail;
	}

	fsp->fsp_flags.use_ofd_locks = !lp_smbd_force_process_locks(SNUM(conn));
#ifndef HAVE_OFD_LOCKS
	fsp->fsp_flags.use_ofd_locks = false;
#endif

	fh_set_refcount(fsp->fh, 1);
	fsp_set_fd(fsp, -1);

	fsp->fnum = FNUM_FIELD_INVALID;
	fsp->conn = conn;
	fsp->close_write_time = make_omit_timespec();

	DLIST_ADD(sconn->files, fsp);
	sconn->num_files += 1;

	conn->num_files_open++;

	DBG_INFO("allocated files structure (%u used)\n",
		(unsigned int)sconn->num_files);

	*result = fsp;
	return NT_STATUS_OK;

fail:
	if (fsp != NULL) {
		TALLOC_FREE(fsp->fh);
	}
	TALLOC_FREE(fsp);

	return status;
}

void fsp_set_gen_id(files_struct *fsp)
{
	static uint64_t gen_id = UINT32_MAX;

	/*
	 * These ids are only used for internal opens, which gives us 4 billion
	 * opens until we wrap.
	 */
	gen_id++;
	if (gen_id == 0) {
		gen_id = UINT32_MAX;
	}
	fh_set_gen_id(fsp->fh, gen_id);
}

/****************************************************************************
 Find first available file slot.
****************************************************************************/

NTSTATUS fsp_bind_smb(struct files_struct *fsp, struct smb_request *req)
{
	struct smbXsrv_open *op = NULL;
	NTTIME now;
	NTSTATUS status;

	if (req == NULL) {
		DBG_DEBUG("INTERNAL_OPEN_ONLY, skipping smbXsrv_open\n");
		fsp_set_gen_id(fsp);
		return NT_STATUS_OK;
	}

	now = timeval_to_nttime(&fsp->open_time);

	status = smbXsrv_open_create(req->xconn,
				     req->session,
				     fsp->conn->tcon,
				     now,
				     &op);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	fsp->op = op;
	op->compat = fsp;
	fh_set_gen_id(fsp->fh, fsp->op->global->open_global_id);
	fsp->fnum = op->local_id;

	fsp->mid = req->mid;
	req->chain_fsp = fsp;

	DBG_DEBUG("fsp [%s] mid [%" PRIu64"]\n",
		fsp_str_dbg(fsp), fsp->mid);

	return NT_STATUS_OK;
}

NTSTATUS file_new(struct smb_request *req, connection_struct *conn,
		  files_struct **result)
{
	struct smbd_server_connection *sconn = conn->sconn;
	files_struct *fsp;
	NTSTATUS status;

	status = fsp_new(conn, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	GetTimeOfDay(&fsp->open_time);

	status = fsp_bind_smb(fsp, req);
	if (!NT_STATUS_IS_OK(status)) {
		file_free(NULL, fsp);
		return status;
	}

	/*
	 * Create an smb_filename with "" for the base_name.  There are very
	 * few NULL checks, so make sure it's initialized with something. to
	 * be safe until an audit can be done.
	 */
	fsp->fsp_name = synthetic_smb_fname(fsp,
					    "",
					    NULL,
					    NULL,
					    0,
					    0);
	if (fsp->fsp_name == NULL) {
		file_free(NULL, fsp);
		return NT_STATUS_NO_MEMORY;
	}

	DBG_INFO("new file %s\n", fsp_fnum_dbg(fsp));

	/* A new fsp invalidates the positive and
	  negative fsp_fi_cache as the new fsp is pushed
	  at the start of the list and we search from
	  a cache hit to the *end* of the list. */

	ZERO_STRUCT(sconn->fsp_fi_cache);

	*result = fsp;
	return NT_STATUS_OK;
}

NTSTATUS create_internal_fsp(connection_struct *conn,
			     const struct smb_filename *smb_fname,
			     struct files_struct **_fsp)
{
	struct files_struct *fsp = NULL;
	NTSTATUS status;

	status = file_new(NULL, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = fsp_set_smb_fname(fsp, smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		file_free(NULL, fsp);
		return status;
	}

	*_fsp = fsp;
	return NT_STATUS_OK;
}

/*
 * Create an internal fsp for an *existing* directory.
 *
 * This should only be used by callers in the VFS that need to control the
 * opening of the directory. Otherwise use open_internal_dirfsp().
 */
NTSTATUS create_internal_dirfsp(connection_struct *conn,
				const struct smb_filename *smb_dname,
				struct files_struct **_fsp)
{
	struct files_struct *fsp = NULL;
	NTSTATUS status;

	status = create_internal_fsp(conn, smb_dname, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	fsp->access_mask = FILE_LIST_DIRECTORY;
	fsp->fsp_flags.is_directory = true;
	fsp->fsp_flags.is_dirfsp = true;

	*_fsp = fsp;
	return NT_STATUS_OK;
}

/*
 * Open an internal fsp for an *existing* directory.
 */
NTSTATUS open_internal_dirfsp(connection_struct *conn,
			      const struct smb_filename *smb_dname,
			      int _open_flags,
			      struct files_struct **_fsp)
{
	struct vfs_open_how how = { .flags = _open_flags, };
	struct files_struct *fsp = NULL;
	NTSTATUS status;

	status = create_internal_dirfsp(conn, smb_dname, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

#ifdef O_DIRECTORY
	how.flags |= O_DIRECTORY;
#endif
	status = fd_openat(conn->cwd_fsp, fsp->fsp_name, fsp, &how);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("Could not open fd for %s (%s)\n",
			 smb_fname_str_dbg(smb_dname),
			 nt_errstr(status));
		file_free(NULL, fsp);
		return status;
	}

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		file_free(NULL, fsp);
		return status;
	}

	if (!S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		DBG_ERR("%s is not a directory!\n",
			smb_fname_str_dbg(smb_dname));
                file_free(NULL, fsp);
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	fsp->file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);

	*_fsp = fsp;
	return NT_STATUS_OK;
}

/*
 * The "link" in the name doesn't imply link in the filesystem
 * sense. It's a object that "links" together an fsp and an smb_fname
 * and the link allocated as talloc child of an fsp.
 *
 * The link is created for fsps that openat_pathref_fsp() returns in
 * smb_fname->fsp. When this fsp is freed by file_free() by some caller
 * somewhere, the destructor fsp_smb_fname_link_destructor() on the link object
 * will use the link to reset the reference in smb_fname->fsp that is about to
 * go away.
 *
 * This prevents smb_fname_internal_fsp_destructor() from seeing dangling fsp
 * pointers.
 */

struct fsp_smb_fname_link {
	struct fsp_smb_fname_link **smb_fname_link;
	struct files_struct **smb_fname_fsp;
};

static int fsp_smb_fname_link_destructor(struct fsp_smb_fname_link *link)
{
	if (link->smb_fname_link == NULL) {
		return 0;
	}

	*link->smb_fname_link = NULL;
	*link->smb_fname_fsp = NULL;
	return 0;
}

static NTSTATUS fsp_smb_fname_link(struct files_struct *fsp,
				   struct fsp_smb_fname_link **smb_fname_link,
				   struct files_struct **smb_fname_fsp)
{
	struct fsp_smb_fname_link *link = NULL;

	SMB_ASSERT(*smb_fname_link == NULL);
	SMB_ASSERT(*smb_fname_fsp == NULL);

	link = talloc_zero(fsp, struct fsp_smb_fname_link);
	if (link == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	link->smb_fname_link = smb_fname_link;
	link->smb_fname_fsp = smb_fname_fsp;
	*smb_fname_link = link;
	*smb_fname_fsp = fsp;

	talloc_set_destructor(link, fsp_smb_fname_link_destructor);
	return NT_STATUS_OK;
}

/*
 * Free a link, carefully avoiding to trigger the link destructor
 */
static void destroy_fsp_smb_fname_link(struct fsp_smb_fname_link **_link)
{
	struct fsp_smb_fname_link *link = *_link;

	if (link == NULL) {
		return;
	}
	talloc_set_destructor(link, NULL);
	TALLOC_FREE(link);
	*_link = NULL;
}

/*
 * Talloc destructor set on an smb_fname set by openat_pathref_fsp() used to
 * close the embedded smb_fname->fsp.
 */
static int smb_fname_fsp_destructor(struct smb_filename *smb_fname)
{
	struct files_struct *fsp = smb_fname->fsp;
	struct files_struct *base_fsp = NULL;
	NTSTATUS status;
	int saved_errno = errno;

	destroy_fsp_smb_fname_link(&smb_fname->fsp_link);

	if (fsp == NULL) {
		errno = saved_errno;
		return 0;
	}

	if (fsp_is_alternate_stream(fsp)) {
		base_fsp = fsp->base_fsp;
	}

	status = fd_close(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Closing fd for fsp [%s] failed: %s. "
			"Please check your filesystem!!!\n",
			fsp_str_dbg(fsp), nt_errstr(status));
	}
	file_free(NULL, fsp);
	smb_fname->fsp = NULL;

	if (base_fsp != NULL) {
		base_fsp->stream_fsp = NULL;
		status = fd_close(base_fsp);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Closing fd for base_fsp [%s] failed: %s. "
				"Please check your filesystem!!!\n",
				fsp_str_dbg(base_fsp), nt_errstr(status));
		}
		file_free(NULL, base_fsp);
	}

	errno = saved_errno;
	return 0;
}

static NTSTATUS openat_pathref_fullname(
	struct connection_struct *conn,
	const struct files_struct *dirfsp,
	struct smb_filename **full_fname,
	struct smb_filename *smb_fname,
	const struct vfs_open_how *how)
{
	struct files_struct *fsp = NULL;
	NTSTATUS status;

	DBG_DEBUG("smb_fname [%s]\n", smb_fname_str_dbg(smb_fname));

	SMB_ASSERT(smb_fname->fsp == NULL);

	status = fsp_new(conn, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	GetTimeOfDay(&fsp->open_time);
	ZERO_STRUCT(conn->sconn->fsp_fi_cache);

	fsp->fsp_flags.is_pathref = true;

	status = fsp_attach_smb_fname(fsp, full_fname);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = fd_openat(dirfsp, smb_fname, fsp, how);
	if (!NT_STATUS_IS_OK(status)) {

		smb_fname->st = fsp->fsp_name->st;

		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_PATH_NOT_FOUND) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK))
		{
			/*
			 * streams_xattr return NT_STATUS_NOT_FOUND for
			 * opens of not yet existing streams.
			 *
			 * ELOOP maps to NT_STATUS_OBJECT_PATH_NOT_FOUND
			 * and this will result from a open request from
			 * a POSIX client on a symlink.
			 *
			 * NT_STATUS_OBJECT_NAME_NOT_FOUND is the simple
			 * ENOENT case.
			 *
			 * NT_STATUS_STOPPED_ON_SYMLINK is returned when trying
			 * to open a symlink, our callers are not interested in
			 * this.
			 */
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		goto fail;
	}

	/*
	 * fd_openat() has done an FSTAT on the handle
	 * so update the smb_fname stat info with "truth".
	 * from the handle.
	 */
	smb_fname->st = fsp->fsp_name->st;

	fsp->fsp_flags.is_directory = S_ISDIR(fsp->fsp_name->st.st_ex_mode);

	fsp->file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);

	status = fsp_smb_fname_link(fsp,
				    &smb_fname->fsp_link,
				    &smb_fname->fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	DBG_DEBUG("fsp [%s]: OK\n", fsp_str_dbg(fsp));

	talloc_set_destructor(smb_fname, smb_fname_fsp_destructor);
	return NT_STATUS_OK;

fail:
	DBG_DEBUG("Opening pathref for [%s] failed: %s\n",
		  smb_fname_str_dbg(smb_fname),
		  nt_errstr(status));

	fd_close(fsp);
	file_free(NULL, fsp);
	return status;
}

/*
 * Open an internal O_PATH based fsp for smb_fname. If O_PATH is not
 * available, open O_RDONLY as root. Both is done in fd_open() ->
 * non_widelink_open(), triggered by setting fsp->fsp_flags.is_pathref to
 * true.
 */
NTSTATUS openat_pathref_fsp(const struct files_struct *dirfsp,
			    struct smb_filename *smb_fname)
{
	connection_struct *conn = dirfsp->conn;
	struct smb_filename *full_fname = NULL;
	struct smb_filename *base_fname = NULL;
	struct vfs_open_how how = { .flags = O_RDONLY|O_NONBLOCK, };
	NTSTATUS status;

	DBG_DEBUG("smb_fname [%s]\n", smb_fname_str_dbg(smb_fname));

	if (smb_fname->fsp != NULL) {
		/* We already have one for this name. */
		DBG_DEBUG("smb_fname [%s] already has a pathref fsp.\n",
			smb_fname_str_dbg(smb_fname));
		return NT_STATUS_OK;
	}

	if (is_named_stream(smb_fname) &&
	    ((conn->fs_capabilities & FILE_NAMED_STREAMS) == 0)) {
		DBG_DEBUG("stream open [%s] on non-stream share\n",
			  smb_fname_str_dbg(smb_fname));
		return NT_STATUS_OBJECT_NAME_INVALID;
	}

	if (!is_named_stream(smb_fname)) {
		/*
		 * openat_pathref_fullname() will make "full_fname" a
		 * talloc child of the smb_fname->fsp. Don't use
		 * talloc_tos() to allocate it to avoid making the
		 * talloc stackframe pool long-lived.
		 */
		full_fname = full_path_from_dirfsp_atname(
			conn,
			dirfsp,
			smb_fname);
		if (full_fname == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		status = openat_pathref_fullname(
			conn, dirfsp, &full_fname, smb_fname, &how);
		TALLOC_FREE(full_fname);
		return status;
	}

	/*
	 * stream open
	 */
	base_fname = cp_smb_filename_nostream(conn, smb_fname);
	if (base_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	full_fname = full_path_from_dirfsp_atname(
		conn,	/* no talloc_tos(), see comment above */
		dirfsp,
		base_fname);
	if (full_fname == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	status = openat_pathref_fullname(
		conn, dirfsp, &full_fname, base_fname, &how);
	TALLOC_FREE(full_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("openat_pathref_fullname() failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	status = open_stream_pathref_fsp(&base_fname->fsp, smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("open_stream_pathref_fsp failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	smb_fname_fsp_unlink(base_fname);
fail:
	TALLOC_FREE(base_fname);
	return status;
}

NTSTATUS open_rootdir_pathref_fsp(connection_struct *conn,
				  struct files_struct **_fsp)
{
	struct smb_filename slash = { .base_name = discard_const_p(char, "/") };
	struct vfs_open_how how = { .flags = O_RDONLY|O_DIRECTORY, };
	struct files_struct *fsp = NULL;
	NTSTATUS status;
	int fd;

	status = fsp_new(conn, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	GetTimeOfDay(&fsp->open_time);
	ZERO_STRUCT(conn->sconn->fsp_fi_cache);
	fsp->fsp_flags.is_pathref = true;

	status = fsp_set_smb_fname(fsp, &slash);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	fd = SMB_VFS_OPENAT(conn,
			    conn->cwd_fsp,
			    fsp->fsp_name,
			    fsp,
			    &how);
	if (fd == -1) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}
	fsp_set_fd(fsp, fd);

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("vfs_stat_fsp(\"/\") failed: %s\n", nt_errstr(status));
		goto close_fail;
	}
	fsp->fsp_flags.is_directory = S_ISDIR(fsp->fsp_name->st.st_ex_mode);
	if (!fsp->fsp_flags.is_directory) {
		DBG_DEBUG("\"/\" not a directory\n");
		status = NT_STATUS_UNEXPECTED_IO_ERROR;
		goto close_fail;
	}
	fsp->file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);
	*_fsp = fsp;
	return NT_STATUS_OK;

close_fail:
	fd_close(fsp);
fail:
	file_free(NULL, fsp);
	return status;
}

/*
 * Open a stream given an already opened base_fsp. Avoid
 * non_widelink_open: This is only valid for the case where we have a
 * valid non-cwd_fsp dirfsp that we can pass to SMB_VFS_OPENAT()
 */
NTSTATUS open_stream_pathref_fsp(
	struct files_struct **_base_fsp,
	struct smb_filename *smb_fname)
{
	struct files_struct *base_fsp = *_base_fsp;
	struct files_struct *fsp = NULL;
	connection_struct *conn = base_fsp->conn;
	struct smb_filename *base_fname = base_fsp->fsp_name;
	struct smb_filename *full_fname = NULL;
	struct vfs_open_how how = { .flags = O_RDONLY|O_NONBLOCK, };
	NTSTATUS status;
	int fd;

	SMB_ASSERT(smb_fname->fsp == NULL);
	SMB_ASSERT(is_named_stream(smb_fname));

	full_fname = synthetic_smb_fname(
		conn, /* no talloc_tos(), this will be long-lived */
		base_fname->base_name,
		smb_fname->stream_name,
		&smb_fname->st,
		smb_fname->twrp,
		smb_fname->flags);
	if (full_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = fsp_new(conn, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	GetTimeOfDay(&fsp->open_time);
	ZERO_STRUCT(conn->sconn->fsp_fi_cache);

	fsp->fsp_flags.is_pathref = true;

	status = fsp_attach_smb_fname(fsp, &full_fname);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	fsp_set_base_fsp(fsp, base_fsp);

	fd = SMB_VFS_OPENAT(conn,
			    NULL, /* stream open is relative to fsp->base_fsp */
			    smb_fname,
			    fsp,
			    &how);
	if (fd == -1) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}
	fsp_set_fd(fsp, fd);

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("vfs_stat_fsp failed: %s\n", nt_errstr(status));
		fd_close(fsp);
		goto fail;
	}
	smb_fname->st = fsp->fsp_name->st;

	fsp->fsp_flags.is_directory = S_ISDIR(fsp->fsp_name->st.st_ex_mode);
	fsp->file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);

	status = fsp_smb_fname_link(fsp, &smb_fname->fsp_link, &smb_fname->fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	DBG_DEBUG("fsp [%s]: OK\n", fsp_str_dbg(fsp));

	talloc_set_destructor(smb_fname, smb_fname_fsp_destructor);
	return NT_STATUS_OK;
fail:
	TALLOC_FREE(full_fname);
	if (fsp != NULL) {
		fsp_set_base_fsp(fsp, NULL);
		fd_close(fsp);
		file_free(NULL, fsp);
	}
	return status;
}

NTSTATUS readlink_talloc(
	TALLOC_CTX *mem_ctx,
	struct files_struct *dirfsp,
	struct smb_filename *smb_relname,
	char **_substitute)
{
	struct smb_filename null_fname = {
		.base_name = discard_const_p(char, ""),
	};
	char buf[PATH_MAX];
	ssize_t ret;
	char *substitute;
	NTSTATUS status;

	if (smb_relname == NULL) {
		/*
		 * We have a Linux O_PATH handle in dirfsp and want to
		 * read its value, essentially a freadlink
		 */
		smb_relname = &null_fname;
	}

	ret = SMB_VFS_READLINKAT(
		dirfsp->conn, dirfsp, smb_relname, buf, sizeof(buf));
	if (ret < 0) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("SMB_VFS_READLINKAT() failed: %s\n",
			  strerror(errno));
		return status;
	}

	if ((size_t)ret == sizeof(buf)) {
		/*
		 * Do we need symlink targets longer than PATH_MAX?
		 */
		DBG_DEBUG("Got full %zu bytes from readlink, too long\n",
			  sizeof(buf));
		return NT_STATUS_BUFFER_OVERFLOW;
	}

	substitute = talloc_strndup(mem_ctx, buf, ret);
	if (substitute == NULL) {
		DBG_DEBUG("talloc_strndup() failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	*_substitute = substitute;
	return NT_STATUS_OK;
}

NTSTATUS read_symlink_reparse(TALLOC_CTX *mem_ctx,
			      struct files_struct *dirfsp,
			      struct smb_filename *smb_relname,
			      struct reparse_data_buffer **_reparse)
{
	struct reparse_data_buffer *reparse = NULL;
	struct symlink_reparse_struct *lnk = NULL;
	NTSTATUS status;

	reparse = talloc(mem_ctx, struct reparse_data_buffer);
	if (reparse == NULL) {
		goto nomem;
	}
	*reparse = (struct reparse_data_buffer){
		.tag = IO_REPARSE_TAG_SYMLINK,
	};
	lnk = &reparse->parsed.lnk;

	status = readlink_talloc(reparse,
				 dirfsp,
				 smb_relname,
				 &lnk->substitute_name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("readlink_talloc failed: %s\n", nt_errstr(status));
		goto fail;
	}

	if (lnk->substitute_name[0] == '/') {
		size_t len = fsp_fullbasepath(dirfsp, NULL, 0);
		char subdir_path[len + 1];
		char *abs_target_canon = NULL;
		const char *relative = NULL;
		bool in_share;

		fsp_fullbasepath(dirfsp, subdir_path, sizeof(subdir_path));

		abs_target_canon = canonicalize_absolute_path(
			talloc_tos(), lnk->substitute_name);
		if (abs_target_canon == NULL) {
			goto nomem;
		}

		in_share = subdir_of(subdir_path,
				     len,
				     abs_target_canon,
				     &relative);
		if (in_share) {
			TALLOC_FREE(lnk->substitute_name);
			lnk->substitute_name = talloc_strdup(reparse,
							     relative);
			if (lnk->substitute_name == NULL) {
				goto nomem;
			}
		}
	}

	if (!IS_DIRECTORY_SEP(lnk->substitute_name[0])) {
		lnk->flags |= SYMLINK_FLAG_RELATIVE;
	}

	*_reparse = reparse;
	return NT_STATUS_OK;
nomem:
	status = NT_STATUS_NO_MEMORY;
fail:
	TALLOC_FREE(reparse);
	return status;
}

static bool full_path_extend(char **dir, const char *atname)
{
	talloc_asprintf_addbuf(dir,
			       "%s%s",
			       (*dir)[0] == '\0' ? "" : "/",
			       atname);
	return (*dir) != NULL;
}

/*
 * Create the memcache-key for GETREALFILENAME_CACHE: This supplements
 * the stat cache for the last component to be looked up. Cache
 * contents is the correctly capitalized translation of the parameter
 * "name" as it exists on disk. This is indexed by inode of the dirfsp
 * and name, and contrary to stat_cahce_lookup() it does not
 * vfs_stat() the last component. This will be taken care of by an
 * attempt to do a openat_pathref_fsp().
 */
static bool get_real_filename_cache_key(TALLOC_CTX *mem_ctx,
					struct files_struct *dirfsp,
					const char *name,
					DATA_BLOB *_key)
{
	struct file_id fid = vfs_file_id_from_sbuf(dirfsp->conn,
						   &dirfsp->fsp_name->st);
	char *upper = NULL;
	uint8_t *key = NULL;
	size_t namelen, keylen;

	upper = talloc_strdup_upper(mem_ctx, name);
	if (upper == NULL) {
		return false;
	}
	namelen = talloc_get_size(upper);

	keylen = namelen + sizeof(fid);
	if (keylen < sizeof(fid)) {
		TALLOC_FREE(upper);
		return false;
	}

	key = talloc_size(mem_ctx, keylen);
	if (key == NULL) {
		TALLOC_FREE(upper);
		return false;
	}

	memcpy(key, &fid, sizeof(fid));
	memcpy(key + sizeof(fid), upper, namelen);
	TALLOC_FREE(upper);

	*_key = (DATA_BLOB){
		.data = key,
		.length = keylen,
	};
	return true;
}

static int smb_vfs_openat_ci(TALLOC_CTX *mem_ctx,
			     bool case_sensitive,
			     struct connection_struct *conn,
			     struct files_struct *dirfsp,
			     struct smb_filename *smb_fname_rel,
			     files_struct *fsp,
			     const struct vfs_open_how *how)
{
	char *orig_base_name = smb_fname_rel->base_name;
	DATA_BLOB cache_key = {
		.data = NULL,
	};
	DATA_BLOB cache_value = {
		.data = NULL,
	};
	NTSTATUS status;
	int fd;
	bool ok;

	fd = SMB_VFS_OPENAT(conn, dirfsp, smb_fname_rel, fsp, how);
	if ((fd >= 0) || case_sensitive) {
		return fd;
	}
	if (errno != ENOENT) {
		return -1;
	}

	if (!lp_stat_cache()) {
		goto lookup;
	}

	ok = get_real_filename_cache_key(mem_ctx,
					 dirfsp,
					 orig_base_name,
					 &cache_key);
	if (!ok) {
		/*
		 * probably ENOMEM, just bail
		 */
		errno = ENOMEM;
		return -1;
	}

	DO_PROFILE_INC(statcache_lookups);

	ok = memcache_lookup(NULL,
			     GETREALFILENAME_CACHE,
			     cache_key,
			     &cache_value);
	if (!ok) {
		DO_PROFILE_INC(statcache_misses);
		goto lookup;
	}
	DO_PROFILE_INC(statcache_hits);

	smb_fname_rel->base_name = talloc_strndup(mem_ctx,
						  (char *)cache_value.data,
						  cache_value.length);
	if (smb_fname_rel->base_name == NULL) {
		TALLOC_FREE(cache_key.data);
		smb_fname_rel->base_name = orig_base_name;
		errno = ENOMEM;
		return -1;
	}

	if (IS_VETO_PATH(dirfsp->conn, smb_fname_rel->base_name)) {
		DBG_DEBUG("veto files rejecting last component %s\n",
			  smb_fname_str_dbg(smb_fname_rel));
		TALLOC_FREE(cache_key.data);
		smb_fname_rel->base_name = orig_base_name;
		errno = EPERM;
		return -1;
	}

	fd = SMB_VFS_OPENAT(conn, dirfsp, smb_fname_rel, fsp, how);
	if (fd >= 0) {
		TALLOC_FREE(cache_key.data);
		return fd;
	}

	memcache_delete(NULL, GETREALFILENAME_CACHE, cache_key);

	/*
	 * For the "new filename" case we need to preserve the
	 * capitalization the client sent us, see
	 * https://bugzilla.samba.org/show_bug.cgi?id=15481
	 */
	TALLOC_FREE(smb_fname_rel->base_name);
	smb_fname_rel->base_name = orig_base_name;

lookup:

	status = get_real_filename_at(dirfsp,
				      orig_base_name,
				      mem_ctx,
				      &smb_fname_rel->base_name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("get_real_filename_at() failed: %s\n",
			  nt_errstr(status));
		errno = ENOENT;
		return -1;
	}

	if (IS_VETO_PATH(conn, smb_fname_rel->base_name)) {
		DBG_DEBUG("found veto files path component "
			  "%s => %s\n",
			  orig_base_name,
			  smb_fname_rel->base_name);
		TALLOC_FREE(smb_fname_rel->base_name);
		smb_fname_rel->base_name = orig_base_name;
		errno = ENOENT;
		return -1;
	}

	fd = SMB_VFS_OPENAT(conn, dirfsp, smb_fname_rel, fsp, how);

	if ((fd >= 0) && (cache_key.data != NULL)) {
		DATA_BLOB value = {
			.data = (uint8_t *)smb_fname_rel->base_name,
			.length = strlen(smb_fname_rel->base_name) + 1,
		};

		memcache_add(NULL, GETREALFILENAME_CACHE, cache_key, value);
		TALLOC_FREE(cache_key.data);
	}

	return fd;
}

NTSTATUS openat_pathref_fsp_nosymlink(
	TALLOC_CTX *mem_ctx,
	struct connection_struct *conn,
	struct files_struct *in_dirfsp,
	const char *path_in,
	NTTIME twrp,
	bool posix,
	struct smb_filename **_smb_fname,
	struct reparse_data_buffer **_symlink_err)
{
	struct files_struct *dirfsp = in_dirfsp;
	struct smb_filename full_fname = {
		.base_name = NULL,
		.twrp = twrp,
		.flags = posix ? SMB_FILENAME_POSIX_PATH : 0,
	};
	struct smb_filename rel_fname = {
		.base_name = NULL,
		.twrp = twrp,
		.flags = full_fname.flags,
	};
	struct smb_filename *result = NULL;
	struct reparse_data_buffer *symlink_err = NULL;
	struct files_struct *fsp = NULL;
	char *path = NULL, *next = NULL;
	bool ok, is_toplevel;
	int fd;
	NTSTATUS status;
	struct vfs_open_how how = {
		.flags = O_NOFOLLOW | O_NONBLOCK,
		.mode = 0,
	};

	DBG_DEBUG("path_in=%s\n", path_in);

	status = fsp_new(conn, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("fsp_new() failed: %s\n", nt_errstr(status));
		goto fail;
	}

	GetTimeOfDay(&fsp->open_time);
	ZERO_STRUCT(conn->sconn->fsp_fi_cache);

	fsp->fsp_name = &full_fname;

#ifdef O_PATH
	/*
	 * Add O_PATH manually, doing this by setting
	 * fsp->fsp_flags.is_pathref will make us become_root() in the
	 * non-O_PATH case, which would cause a security problem.
	 */
	how.flags |= O_PATH;
#else
#ifdef O_SEARCH
	/*
	 * O_SEARCH just checks for the "x" bit. We are traversing
	 * directories, so we don't need the implicit O_RDONLY ("r"
	 * permissions) but only the "x"-permissions requested by
	 * O_SEARCH. We need either O_PATH or O_SEARCH to correctly
	 * function, without either we will incorrectly require also
	 * the "r" bit when traversing the directory hierarchy.
	 */
	how.flags |= O_SEARCH;
#endif
#endif

	is_toplevel = (dirfsp == dirfsp->conn->cwd_fsp);
	is_toplevel |= ISDOT(dirfsp->fsp_name->base_name);

	full_fname.base_name =
		talloc_strdup(talloc_tos(),
			      is_toplevel ? "" : dirfsp->fsp_name->base_name);
	if (full_fname.base_name == NULL) {
		DBG_DEBUG("talloc_strdup() failed\n");
		goto nomem;
	}

	/*
	 * First split the path into individual components.
	 */
	path = path_to_strv(talloc_tos(), path_in);
	if (path == NULL) {
		DBG_DEBUG("path_to_strv() failed\n");
		goto nomem;
	}

	/*
	 * First we loop over all components
	 * in order to verify, there's no '.' or '..'
	 */
	rel_fname.base_name = path;
	while (rel_fname.base_name != NULL) {

		next = strv_next(path, rel_fname.base_name);

		/*
		 * Path sanitizing further up has cleaned or rejected
		 * empty path components. Assert this here.
		 */
		SMB_ASSERT(rel_fname.base_name[0] != '\0');

		if (ISDOT(rel_fname.base_name) ||
		    ISDOTDOT(rel_fname.base_name)) {
			DBG_DEBUG("%s contains a dot\n", path_in);
			status = NT_STATUS_OBJECT_NAME_INVALID;
			goto fail;
		}

		/* Check veto files. */
		if (IS_VETO_PATH(conn, rel_fname.base_name)) {
			DBG_DEBUG("%s contains veto files path component %s\n",
				  path_in, rel_fname.base_name);
			status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
			goto fail;
		}

		rel_fname.base_name = next;
	}

	if (conn->open_how_resolve & VFS_OPEN_HOW_RESOLVE_NO_SYMLINKS) {

		/*
		 * Try a direct openat2 with RESOLVE_NO_SYMLINKS to
		 * avoid the openat/close loop further down.
		 */

		rel_fname.base_name = discard_const_p(char, path_in);
		how.resolve = VFS_OPEN_HOW_RESOLVE_NO_SYMLINKS;

		fd = SMB_VFS_OPENAT(conn, dirfsp, &rel_fname, fsp, &how);
		if (fd >= 0) {
			fsp_set_fd(fsp, fd);
			ok = full_path_extend(&full_fname.base_name,
					      rel_fname.base_name);
			if (!ok) {
				goto nomem;
			}
			goto done;
		}

		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("SMB_VFS_OPENAT(%s, %s, RESOLVE_NO_SYMLINKS) "
			  "returned %d %s => %s\n",
			  smb_fname_str_dbg(dirfsp->fsp_name), path_in,
			  errno, strerror(errno), nt_errstr(status));
		SMB_ASSERT(fd == -1);
		switch (errno) {
		case ENOSYS:
			/*
			 * We got ENOSYS, so fallback to the old code
			 * if the kernel doesn't support openat2() yet.
			 */
			break;

		case ELOOP:
		case ENOTDIR:
			/*
			 * For ELOOP we also fallback in order to
			 * return the correct information with
			 * NT_STATUS_STOPPED_ON_SYMLINK.
			 *
			 * O_NOFOLLOW|O_DIRECTORY results in
			 * ENOTDIR instead of ELOOP for the final
			 * component.
			 */
			break;

		case ENOENT:
			/*
			 * If we got ENOENT, the filesystem could
			 * be case sensitive. For now we only do
			 * the get_real_filename_at() dance in
			 * the fallback loop below.
			 */
			break;

		default:
			goto fail;
		}

		/*
		 * Just fallback to the openat loop
		 */
		how.resolve = 0;
	}

	/*
	 * Now we loop over all components
	 * opening each one and using it
	 * as dirfd for the next one.
	 *
	 * It means we can detect symlinks
	 * within the path.
	 */
	rel_fname.base_name = path;
next:
	next = strv_next(path, rel_fname.base_name);

	fd = smb_vfs_openat_ci(talloc_tos(),
			       posix || conn->case_sensitive,
			       conn,
			       dirfsp,
			       &rel_fname,
			       fsp,
			       &how);

#ifndef O_PATH
	if ((fd == -1) && (errno == ELOOP)) {
		int ret;

		/*
		 * openat() hit a symlink. With O_PATH we open the
		 * symlink and get ENOTDIR in the next round, see
		 * below.
		 */

		status = read_symlink_reparse(mem_ctx,
					      dirfsp,
					      &rel_fname,
					      &symlink_err);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("read_symlink_reparse failed: %s\n",
				  nt_errstr(status));
			goto fail;
		}

		if (next != NULL) {
			size_t parsed = next - path;
			size_t len = talloc_get_size(path);
			size_t unparsed = len - parsed;

			if (unparsed > UINT16_MAX) {
				status = NT_STATUS_BUFFER_OVERFLOW;
				goto fail;
			}
			symlink_err->parsed.lnk
				.unparsed_path_length = unparsed;
		}

		/*
		 * We know rel_fname is a symlink, now fill in the
		 * rest of the metadata for our callers.
		 */

		ret = SMB_VFS_FSTATAT(conn,
				      dirfsp,
				      &rel_fname,
				      &full_fname.st,
				      AT_SYMLINK_NOFOLLOW);
		if (ret == -1) {
			status = map_nt_error_from_unix(errno);
			DBG_DEBUG("SMB_VFS_FSTATAT(%s/%s) failed: %s\n",
				  fsp_str_dbg(dirfsp),
				  rel_fname.base_name,
				  strerror(errno));
			TALLOC_FREE(symlink_err);
			goto fail;
		}

		if (!S_ISLNK(full_fname.st.st_ex_mode)) {
			/*
			 * Hit a race: readlink_talloc() worked before
			 * the fstatat(), but rel_fname changed to
			 * something that's not a symlink.
			 */
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
			TALLOC_FREE(symlink_err);
			goto fail;
		}

		status = NT_STATUS_STOPPED_ON_SYMLINK;
		goto fail;
	}
#endif

	if ((fd == -1) && (errno == ENOTDIR)) {
		size_t parsed, len, unparsed;

		/*
		 * dirfsp does not point at a directory, try a
		 * freadlink.
		 */

		status = read_symlink_reparse(mem_ctx,
					      dirfsp,
					      NULL,
					      &symlink_err);

		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("read_symlink_reparse failed: %s\n",
				  nt_errstr(status));
			status = NT_STATUS_NOT_A_DIRECTORY;
			goto fail;
		}

		parsed = rel_fname.base_name - path;
		len = talloc_get_size(path);
		unparsed = len - parsed;

		if (unparsed > UINT16_MAX) {
			status = NT_STATUS_BUFFER_OVERFLOW;
			goto fail;
		}

		symlink_err->parsed.lnk.unparsed_path_length = unparsed;

		status = NT_STATUS_STOPPED_ON_SYMLINK;
		goto fail;
	}

	if (fd == -1) {
		/*
		 * vfs_widelink widelink_openat will update stat for fsp
		 * and return ELOOP for non-existing link, we can report
		 * the link here and let calling code decide what to do.
		 */
		if ((errno == ELOOP) && S_ISLNK(fsp->fsp_name->st.st_ex_mode)) {
			status = read_symlink_reparse(mem_ctx,
						      dirfsp,
						      &rel_fname,
						      &symlink_err);
			if (NT_STATUS_IS_OK(status)) {
				status = NT_STATUS_STOPPED_ON_SYMLINK;
			} else {
				DBG_ERR("read_symlink_reparse failed: %s\n",
					nt_errstr(status));
			}
			goto fail;
		}
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("SMB_VFS_OPENAT() failed: %s\n",
			  strerror(errno));
		goto fail;
	}
	fsp_set_fd(fsp, fd);

	ok = full_path_extend(&full_fname.base_name, rel_fname.base_name);
	if (!ok) {
		goto nomem;
	}

	if (next != NULL) {
		struct files_struct *tmp = NULL;

		if (dirfsp != in_dirfsp) {
			fd_close(dirfsp);
		}

		tmp = dirfsp;
		dirfsp = fsp;

		if (tmp == in_dirfsp) {
			status = fsp_new(conn, conn, &fsp);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_DEBUG("fsp_new() failed: %s\n",
					  nt_errstr(status));
				goto fail;
			}
			fsp->fsp_name = &full_fname;
		} else {
			fsp = tmp;
		}

		rel_fname.base_name = next;

		goto next;
	}

	if (dirfsp != in_dirfsp) {
		SMB_ASSERT(fsp_get_pathref_fd(dirfsp) != -1);
		fd_close(dirfsp);
		dirfsp->fsp_name = NULL;
		file_free(NULL, dirfsp);
		dirfsp = NULL;
	}

done:
	fsp->fsp_flags.is_pathref = true;
	fsp->fsp_name = NULL;

	status = fsp_set_smb_fname(fsp, &full_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("fsp_set_smb_fname() failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("vfs_stat_fsp(%s) failed: %s\n",
			  fsp_str_dbg(fsp),
			  nt_errstr(status));
		goto fail;
	}

	if (S_ISLNK(fsp->fsp_name->st.st_ex_mode)) {
		/*
		 * Last component was a symlink we opened with O_PATH, fail it
		 * here.
		 */
		status = read_symlink_reparse(mem_ctx,
					      fsp,
					      NULL,
					      &symlink_err);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = NT_STATUS_STOPPED_ON_SYMLINK;
		goto fail;
	}

	/*
	 * We must correctly set fsp->file_id as code inside
	 * open.c will use this to check if delete_on_close
	 * has been set on the dirfsp.
	 */
	fsp->file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);

	result = cp_smb_filename(mem_ctx, fsp->fsp_name);
	if (result == NULL) {
		DBG_DEBUG("cp_smb_filename() failed\n");
		goto nomem;
	}

	status = fsp_smb_fname_link(fsp,
					&result->fsp_link,
					&result->fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	talloc_set_destructor(result, smb_fname_fsp_destructor);

	*_smb_fname = result;

	DBG_DEBUG("returning %s\n", smb_fname_str_dbg(result));

	return NT_STATUS_OK;

nomem:
	status = NT_STATUS_NO_MEMORY;
fail:
	if (fsp != NULL) {
		if (fsp_get_pathref_fd(fsp) != -1) {
			fd_close(fsp);
		}
		file_free(NULL, fsp);
		fsp = NULL;
	}

	if ((dirfsp != NULL) && (dirfsp != in_dirfsp)) {
		SMB_ASSERT(fsp_get_pathref_fd(dirfsp) != -1);
		fd_close(dirfsp);
		dirfsp->fsp_name = NULL;
		file_free(NULL, dirfsp);
		dirfsp = NULL;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK)) {
		*_symlink_err = symlink_err;
	}

	TALLOC_FREE(path);
	return status;
}

/*
 * Open smb_fname_rel->fsp as a pathref fsp with a case insensitive
 * fallback using GETREALFILENAME_CACHE and get_real_filename_at() if
 * the first attempt based on the filename sent by the client gives
 * ENOENT.
 */
NTSTATUS openat_pathref_fsp_lcomp(struct files_struct *dirfsp,
				  struct smb_filename *smb_fname_rel,
				  uint32_t ucf_flags)
{
	struct connection_struct *conn = dirfsp->conn;
	const char *orig_rel_base_name = smb_fname_rel->base_name;
	struct files_struct *fsp = NULL;
	struct smb_filename *full_fname = NULL;
	struct vfs_open_how how = {
		.flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW,
	};
	NTSTATUS status;
	int ret, fd;

	/*
	 * Make sure we don't need of the all the magic in
	 * openat_pathref_fsp() with regards non_widelink_open etc.
	 */

	SMB_ASSERT((smb_fname_rel->fsp == NULL) &&
		   ((dirfsp != dirfsp->conn->cwd_fsp) ||
		    ISDOT(smb_fname_rel->base_name)) &&
		   (strchr_m(smb_fname_rel->base_name, '/') == NULL) &&
		   !is_named_stream(smb_fname_rel));

	SET_STAT_INVALID(smb_fname_rel->st);

	/* Check veto files - only looks at last component. */
	if (IS_VETO_PATH(dirfsp->conn, smb_fname_rel->base_name)) {
		DBG_DEBUG("veto files rejecting last component %s\n",
			  smb_fname_str_dbg(smb_fname_rel));
		return NT_STATUS_NETWORK_OPEN_RESTRICTION;
	}

	status = fsp_new(conn, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("fsp_new() failed: %s\n", nt_errstr(status));
		return status;
	}

	GetTimeOfDay(&fsp->open_time);
	ZERO_STRUCT(conn->sconn->fsp_fi_cache);

	fsp->fsp_flags.is_pathref = true;

	full_fname = full_path_from_dirfsp_atname(conn, dirfsp, smb_fname_rel);
	if (full_fname == NULL) {
		DBG_DEBUG("full_path_from_dirfsp_atname(%s/%s) failed\n",
			  fsp_str_dbg(dirfsp),
			  smb_fname_rel->base_name);
		file_free(NULL, fsp);
		return NT_STATUS_NO_MEMORY;
	}

	status = fsp_attach_smb_fname(fsp, &full_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("fsp_attach_smb_fname(fsp, %s) failed: %s\n",
			  smb_fname_str_dbg(full_fname),
			  nt_errstr(status));
		file_free(NULL, fsp);
		return status;
	}

	fd = smb_vfs_openat_ci(smb_fname_rel,
			       (ucf_flags & UCF_POSIX_PATHNAMES) ||
				       conn->case_sensitive,
			       conn,
			       dirfsp,
			       smb_fname_rel,
			       fsp,
			       &how);

	if ((fd == -1) && (errno == ENOENT)) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("smb_vfs_openat(%s/%s) failed: %s\n",
			  fsp_str_dbg(dirfsp),
			  smb_fname_rel->base_name,
			  strerror(errno));
		file_free(NULL, fsp);
		return status;
	}

	if (smb_fname_rel->base_name != orig_rel_base_name) {
		struct smb_filename new_fullname = *smb_fname_rel;

		DBG_DEBUG("rel->base_name changed from %s to %s\n",
			  orig_rel_base_name,
			  smb_fname_rel->base_name);

		new_fullname.base_name = full_path_from_dirfsp_at_basename(
			talloc_tos(), dirfsp, new_fullname.base_name);
		if (new_fullname.base_name == NULL) {
			fd_close(fsp);
			file_free(NULL, fsp);
			return NT_STATUS_NO_MEMORY;
		}

		status = fsp_set_smb_fname(fsp, &new_fullname);
		if (!NT_STATUS_IS_OK(status)) {
			fd_close(fsp);
			file_free(NULL, fsp);
			return status;
		}
	}

	fsp_set_fd(fsp, fd);

	if (fd >= 0) {
		ret = SMB_VFS_FSTAT(fsp, &fsp->fsp_name->st);
	} else {
		ret = SMB_VFS_FSTATAT(fsp->conn,
				      dirfsp,
				      smb_fname_rel,
				      &fsp->fsp_name->st,
				      AT_SYMLINK_NOFOLLOW);
	}
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("SMB_VFS_%sSTAT(%s/%s) failed: %s\n",
			  (fd >= 0) ? "F" : "",
			  fsp_str_dbg(dirfsp),
			  smb_fname_rel->base_name,
			  strerror(errno));
		fd_close(fsp);
		file_free(NULL, fsp);
		return status;
	}

	fsp->fsp_flags.is_directory = S_ISDIR(fsp->fsp_name->st.st_ex_mode);
	fsp->fsp_flags.posix_open =
		((smb_fname_rel->flags & SMB_FILENAME_POSIX_PATH) != 0);
	fsp->file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);

	smb_fname_rel->st = fsp->fsp_name->st;

	status = fsp_smb_fname_link(fsp,
				    &smb_fname_rel->fsp_link,
				    &smb_fname_rel->fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("fsp_smb_fname_link() failed: %s\n",
			  nt_errstr(status));
		fd_close(fsp);
		file_free(NULL, fsp);
		return status;
	}

	DBG_DEBUG("fsp [%s]: OK, fd=%d\n", fsp_str_dbg(fsp), fd);

	talloc_set_destructor(smb_fname_rel, smb_fname_fsp_destructor);
	return NT_STATUS_OK;
}

NTSTATUS openat_pathref_fsp_dot(TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				uint32_t flags,
				struct smb_filename **_dot)
{
	struct connection_struct *conn = dirfsp->conn;
	struct files_struct *fsp = NULL;
	struct smb_filename *full_fname = NULL;
	struct vfs_open_how how = { .flags = O_NOFOLLOW, };
        struct smb_filename *dot = NULL;
        NTSTATUS status;
        int fd;

#ifdef O_DIRECTORY
        how.flags |= O_DIRECTORY;
#endif

#ifdef O_PATH
	how.flags |= O_PATH;
#else
	how.flags |= (O_RDONLY | O_NONBLOCK);
#endif

	dot = synthetic_smb_fname(mem_ctx, ".", NULL, NULL, 0, flags);
	if (dot == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = fsp_new(conn, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("fsp_new() failed: %s\n", nt_errstr(status));
		return status;
	}

	GetTimeOfDay(&fsp->open_time);
	ZERO_STRUCT(conn->sconn->fsp_fi_cache);

	fsp->fsp_flags.is_pathref = true;

	full_fname = full_path_from_dirfsp_atname(conn, dirfsp, dot);
	if (full_fname == NULL) {
		DBG_DEBUG("full_path_from_dirfsp_atname(%s/%s) failed\n",
			  dirfsp->fsp_name->base_name,
			  dot->base_name);
		file_free(NULL, fsp);
		return NT_STATUS_NO_MEMORY;
	}

	status = fsp_attach_smb_fname(fsp, &full_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("fsp_attach_smb_fname(fsp, %s) failed: %s\n",
			  smb_fname_str_dbg(full_fname),
			  nt_errstr(status));
		file_free(NULL, fsp);
		return status;
	}

	fd = SMB_VFS_OPENAT(conn, dirfsp, dot, fsp, &how);
	if (fd == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("smb_vfs_openat(%s/%s) failed: %s\n",
			  dirfsp->fsp_name->base_name,
			  dot->base_name,
			  strerror(errno));
		file_free(NULL, fsp);
		return status;
	}

	fsp_set_fd(fsp, fd);

	status = vfs_stat_fsp(fsp);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("vfs_stat_fsp(\"/\") failed: %s\n",
			  nt_errstr(status));
		fd_close(fsp);
		file_free(NULL, fsp);
		return status;
	}

	fsp->fsp_flags.is_directory = S_ISDIR(fsp->fsp_name->st.st_ex_mode);
	fsp->fsp_flags.posix_open =
		((dot->flags & SMB_FILENAME_POSIX_PATH) != 0);
	fsp->file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);

	dot->st = fsp->fsp_name->st;

	status = fsp_smb_fname_link(fsp,
				    &dot->fsp_link,
				    &dot->fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("fsp_smb_fname_link() failed: %s\n",
			  nt_errstr(status));
		fd_close(fsp);
		file_free(NULL, fsp);
		return status;
	}

	DBG_DEBUG("fsp [%s]: OK, fd=%d\n", fsp_str_dbg(fsp), fd);

	talloc_set_destructor(dot, smb_fname_fsp_destructor);

	*_dot = dot;

	return NT_STATUS_OK;
}

void smb_fname_fsp_unlink(struct smb_filename *smb_fname)
{
	talloc_set_destructor(smb_fname, NULL);
	smb_fname->fsp = NULL;
	destroy_fsp_smb_fname_link(&smb_fname->fsp_link);
}

/*
 * Move any existing embedded fsp refs from the src name to the
 * destination. It's safe to call this on src smb_fname's that have no embedded
 * pathref fsp.
 */
NTSTATUS move_smb_fname_fsp_link(struct smb_filename *smb_fname_dst,
				 struct smb_filename *smb_fname_src)
{
	NTSTATUS status;

	/*
	 * The target should always not be linked yet!
	 */
	SMB_ASSERT(smb_fname_dst->fsp == NULL);
	SMB_ASSERT(smb_fname_dst->fsp_link == NULL);

	if (smb_fname_src->fsp == NULL) {
		return NT_STATUS_OK;
	}

	status = fsp_smb_fname_link(smb_fname_src->fsp,
				    &smb_fname_dst->fsp_link,
				    &smb_fname_dst->fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	talloc_set_destructor(smb_fname_dst, smb_fname_fsp_destructor);

	smb_fname_fsp_unlink(smb_fname_src);

	return NT_STATUS_OK;
}

static int fsp_ref_no_close_destructor(struct smb_filename *smb_fname)
{
	destroy_fsp_smb_fname_link(&smb_fname->fsp_link);
	return 0;
}

NTSTATUS reference_smb_fname_fsp_link(struct smb_filename *smb_fname_dst,
				      const struct smb_filename *smb_fname_src)
{
	NTSTATUS status;

	/*
	 * The target should always not be linked yet!
	 */
	SMB_ASSERT(smb_fname_dst->fsp == NULL);
	SMB_ASSERT(smb_fname_dst->fsp_link == NULL);

	if (smb_fname_src->fsp == NULL) {
		return NT_STATUS_OK;
	}

	status = fsp_smb_fname_link(smb_fname_src->fsp,
				    &smb_fname_dst->fsp_link,
				    &smb_fname_dst->fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	talloc_set_destructor(smb_fname_dst, fsp_ref_no_close_destructor);

	return NT_STATUS_OK;
}

/**
 * Create an smb_fname and open smb_fname->fsp pathref
 **/
NTSTATUS synthetic_pathref(TALLOC_CTX *mem_ctx,
			   const struct files_struct *dirfsp,
			   const char *base_name,
			   const char *stream_name,
			   const SMB_STRUCT_STAT *psbuf,
			   NTTIME twrp,
			   uint32_t flags,
			   struct smb_filename **_smb_fname)
{
	struct smb_filename *smb_fname = NULL;
	NTSTATUS status;

	smb_fname = synthetic_smb_fname(mem_ctx,
					base_name,
					stream_name,
					psbuf,
					twrp,
					flags);
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = openat_pathref_fsp(dirfsp, smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("opening [%s] failed\n",
			smb_fname_str_dbg(smb_fname));
		TALLOC_FREE(smb_fname);
		return status;
	}

	*_smb_fname = smb_fname;
	return NT_STATUS_OK;
}

/**
 * Turn a path into a parent pathref and atname
 *
 * This returns the parent pathref in _parent and the name relative to it. If
 * smb_fname was a pathref (ie smb_fname->fsp != NULL), then _atname will be a
 * pathref as well, ie _atname->fsp will point at the same fsp as
 * smb_fname->fsp.
 **/
NTSTATUS parent_pathref(TALLOC_CTX *mem_ctx,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			struct smb_filename **_parent,
			struct smb_filename **_atname)
{
	struct smb_filename *parent = NULL;
	struct smb_filename *atname = NULL;
	NTSTATUS status;

	status = SMB_VFS_PARENT_PATHNAME(dirfsp->conn,
					 mem_ctx,
					 smb_fname,
					 &parent,
					 &atname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * We know that the parent name must
	 * exist, and the name has been canonicalized
	 * even if this was a POSIX pathname.
	 * Ensure that we follow symlinks for
	 * the parent. See the torture test
	 * POSIX-SYMLINK-PARENT for details.
	 */
	parent->flags &= ~SMB_FILENAME_POSIX_PATH;

	status = openat_pathref_fsp(dirfsp, parent);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(parent);
		return status;
	}

	status = reference_smb_fname_fsp_link(atname, smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(parent);
		return status;
	}

	*_parent = parent;
	*_atname = atname;
	return NT_STATUS_OK;
}

static bool close_file_in_loop(struct files_struct *fsp,
			       enum file_close_type close_type)
{
	if (fsp_is_alternate_stream(fsp)) {
		/*
		 * This is a stream, it can't be a base
		 */
		SMB_ASSERT(fsp->stream_fsp == NULL);
		SMB_ASSERT(fsp->base_fsp->stream_fsp == fsp);

		/*
		 * Remove the base<->stream link so that
		 * close_file_free() does not close fsp->base_fsp as
		 * well. This would destroy walking the linked list of
		 * fsps.
		 */
		fsp->base_fsp->stream_fsp = NULL;
		fsp->base_fsp = NULL;

		close_file_free(NULL, &fsp, close_type);
		return NULL;
	}

	if (fsp->stream_fsp != NULL) {
		/*
		 * This is the base of a stream.
		 */
		SMB_ASSERT(fsp->stream_fsp->base_fsp == fsp);

		/*
		 * Remove the base<->stream link. This will make fsp
		 * look like a normal fsp for the next round.
		 */
		fsp->stream_fsp->base_fsp = NULL;
		fsp->stream_fsp = NULL;

		/*
		 * Have us called back a second time. In the second
		 * round, "fsp" now looks like a normal fsp.
		 */
		return false;
	}

	close_file_free(NULL, &fsp, close_type);
	return true;
}

/****************************************************************************
 Close all open files for a connection.
****************************************************************************/

struct file_close_conn_state {
	struct connection_struct *conn;
	enum file_close_type close_type;
	bool fsp_left_behind;
};

static struct files_struct *file_close_conn_fn(
	struct files_struct *fsp,
	void *private_data)
{
	struct file_close_conn_state *state = private_data;
	bool did_close;

	if (fsp->conn != state->conn) {
		return NULL;
	}

	if (fsp->op != NULL && fsp->op->global->durable) {
		/*
		 * A tree disconnect closes a durable handle
		 */
		fsp->op->global->durable = false;
	}

	did_close = close_file_in_loop(fsp, state->close_type);
	if (!did_close) {
		state->fsp_left_behind = true;
	}

	return NULL;
}

void file_close_conn(connection_struct *conn, enum file_close_type close_type)
{
	struct file_close_conn_state state = { .conn = conn,
					       .close_type = close_type };

	files_forall(conn->sconn, file_close_conn_fn, &state);

	if (state.fsp_left_behind) {
		state.fsp_left_behind = false;
		files_forall(conn->sconn, file_close_conn_fn, &state);
		SMB_ASSERT(!state.fsp_left_behind);
	}
}

/****************************************************************************
 Initialise file structures.
****************************************************************************/

static int files_max_open_fds;

bool file_init_global(void)
{
	int request_max = lp_max_open_files();
	int real_lim;
	int real_max;

	if (files_max_open_fds != 0) {
		return true;
	}

	/*
	 * Set the max_open files to be the requested
	 * max plus a fudgefactor to allow for the extra
	 * fd's we need such as log files etc...
	 */
	real_lim = set_maxfiles(request_max + MAX_OPEN_FUDGEFACTOR);

	real_max = real_lim - MAX_OPEN_FUDGEFACTOR;

	if (real_max + FILE_HANDLE_OFFSET + MAX_OPEN_PIPES > 65536) {
		real_max = 65536 - FILE_HANDLE_OFFSET - MAX_OPEN_PIPES;
	}

	if (real_max != request_max) {
		DEBUG(1, ("file_init_global: Information only: requested %d "
			  "open files, %d are available.\n",
			  request_max, real_max));
	}

	SMB_ASSERT(real_max > 100);

	files_max_open_fds = real_max;
	return true;
}

bool file_init(struct smbd_server_connection *sconn)
{
	bool ok;

	ok = file_init_global();
	if (!ok) {
		return false;
	}

	sconn->real_max_open_files = files_max_open_fds;

	return true;
}

/****************************************************************************
 Close files open by a specified vuid.
****************************************************************************/

struct file_close_user_state {
	uint64_t vuid;
	bool fsp_left_behind;
};

static struct files_struct *file_close_user_fn(
	struct files_struct *fsp,
	void *private_data)
{
	struct file_close_user_state *state = private_data;
	bool did_close;

	if (fsp->vuid != state->vuid) {
		return NULL;
	}

	did_close = close_file_in_loop(fsp, SHUTDOWN_CLOSE);
	if (!did_close) {
		state->fsp_left_behind = true;
	}

	return NULL;
}

void file_close_user(struct smbd_server_connection *sconn, uint64_t vuid)
{
	struct file_close_user_state state = { .vuid = vuid };

	files_forall(sconn, file_close_user_fn, &state);

	if (state.fsp_left_behind) {
		state.fsp_left_behind = false;
		files_forall(sconn, file_close_user_fn, &state);
		SMB_ASSERT(!state.fsp_left_behind);
	}
}

/*
 * Walk the files table until "fn" returns non-NULL
 */

struct files_struct *files_forall(
	struct smbd_server_connection *sconn,
	struct files_struct *(*fn)(struct files_struct *fsp,
				   void *private_data),
	void *private_data)
{
	struct files_struct *fsp, *next;

	for (fsp = sconn->files; fsp; fsp = next) {
		struct files_struct *ret;
		next = fsp->next;
		ret = fn(fsp, private_data);
		if (ret != NULL) {
			return ret;
		}
	}
	return NULL;
}

/****************************************************************************
 Find a fsp given a file descriptor.
****************************************************************************/

files_struct *file_find_fd(struct smbd_server_connection *sconn, int fd)
{
	int count=0;
	files_struct *fsp;

	for (fsp=sconn->files; fsp; fsp=fsp->next,count++) {
		if (fsp_get_pathref_fd(fsp) == fd) {
			if (count > 10) {
				DLIST_PROMOTE(sconn->files, fsp);
			}
			return fsp;
		}
	}

	return NULL;
}

/****************************************************************************
 Find a fsp given a device, inode and file_id.
****************************************************************************/

files_struct *file_find_dif(struct smbd_server_connection *sconn,
			    struct file_id id, unsigned long gen_id)
{
	int count=0;
	files_struct *fsp;

	if (gen_id == 0) {
		return NULL;
	}

	for (fsp = sconn->files; fsp; fsp = fsp->next,count++) {
		/*
		 * We can have a fsp->fh->fd == -1 here as it could be a stat
		 * open.
		 */
		if (!file_id_equal(&fsp->file_id, &id)) {
			continue;
		}
		if (!fsp->fsp_flags.is_fsa) {
			continue;
		}
		if (fh_get_gen_id(fsp->fh) != gen_id) {
			continue;
		}
		if (count > 10) {
			DLIST_PROMOTE(sconn->files, fsp);
		}
		return fsp;
	}

	return NULL;
}

/****************************************************************************
 Find the first fsp given a device and inode.
 We use a singleton cache here to speed up searching from getfilepathinfo
 calls.
****************************************************************************/

files_struct *file_find_di_first(struct smbd_server_connection *sconn,
				 struct file_id id,
				 bool need_fsa)
{
	files_struct *fsp;

	if (file_id_equal(&sconn->fsp_fi_cache.id, &id)) {
		/* Positive or negative cache hit. */
		return sconn->fsp_fi_cache.fsp;
	}

	sconn->fsp_fi_cache.id = id;

	for (fsp=sconn->files;fsp;fsp=fsp->next) {
		if (need_fsa && !fsp->fsp_flags.is_fsa) {
			continue;
		}
		if (file_id_equal(&fsp->file_id, &id)) {
			/* Setup positive cache. */
			sconn->fsp_fi_cache.fsp = fsp;
			return fsp;
		}
	}

	/* Setup negative cache. */
	sconn->fsp_fi_cache.fsp = NULL;
	return NULL;
}

/****************************************************************************
 Find the next fsp having the same device and inode.
****************************************************************************/

files_struct *file_find_di_next(files_struct *start_fsp,
				bool need_fsa)
{
	files_struct *fsp;

	for (fsp = start_fsp->next;fsp;fsp=fsp->next) {
		if (need_fsa && !fsp->fsp_flags.is_fsa) {
			continue;
		}
		if (file_id_equal(&fsp->file_id, &start_fsp->file_id)) {
			return fsp;
		}
	}

	return NULL;
}

struct files_struct *file_find_one_fsp_from_lease_key(
	struct smbd_server_connection *sconn,
	const struct smb2_lease_key *lease_key)
{
	struct files_struct *fsp;

	for (fsp = sconn->files; fsp; fsp=fsp->next) {
		if ((fsp->lease != NULL) &&
		    (fsp->lease->lease.lease_key.data[0] ==
		     lease_key->data[0]) &&
		    (fsp->lease->lease.lease_key.data[1] ==
		     lease_key->data[1])) {
			return fsp;
		}
	}
	return NULL;
}

/****************************************************************************
 Find any fsp open with a pathname below that of an already open path,
 ignoring POSIX opens.
****************************************************************************/

bool file_find_subpath(files_struct *dir_fsp)
{
	files_struct *fsp;
	size_t dlen;
	char *d_fullname = NULL;

	d_fullname = talloc_asprintf(talloc_tos(), "%s/%s",
				     dir_fsp->conn->connectpath,
				     dir_fsp->fsp_name->base_name);

	if (!d_fullname) {
		return false;
	}

	dlen = strlen(d_fullname);

	for (fsp=dir_fsp->conn->sconn->files; fsp; fsp=fsp->next) {
		char *d1_fullname;

		if (fsp == dir_fsp) {
			continue;
		}
		if (dir_fsp->fsp_flags.posix_open &&
		    fsp->fsp_flags.posix_open)
		{
			continue;
		}

		d1_fullname = talloc_asprintf(talloc_tos(),
					"%s/%s",
					fsp->conn->connectpath,
					fsp->fsp_name->base_name);

		/*
		 * If the open file has a path that is a longer
		 * component, then it's a subpath.
		 */
		if (strnequal(d_fullname, d1_fullname, dlen) &&
				(d1_fullname[dlen] == '/')) {
			TALLOC_FREE(d1_fullname);
			TALLOC_FREE(d_fullname);
			return true;
		}
		TALLOC_FREE(d1_fullname);
	}

	TALLOC_FREE(d_fullname);
	return false;
}

/****************************************************************************
 Free up a fsp.
****************************************************************************/

static void fsp_free(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;

	if (fsp == sconn->fsp_fi_cache.fsp) {
		ZERO_STRUCT(sconn->fsp_fi_cache);
	}

	DLIST_REMOVE(sconn->files, fsp);
	SMB_ASSERT(sconn->num_files > 0);
	sconn->num_files--;

	TALLOC_FREE(fsp->fake_file_handle);

	if (fh_get_refcount(fsp->fh) == 1) {
		TALLOC_FREE(fsp->fh);
	} else {
		size_t new_refcount = fh_get_refcount(fsp->fh) - 1;
		fh_set_refcount(fsp->fh, new_refcount);
	}

	if (fsp->lease != NULL) {
		if (fsp->lease->ref_count == 1) {
			TALLOC_FREE(fsp->lease);
		} else {
			fsp->lease->ref_count--;
		}
	}

	fsp->conn->num_files_open--;

	if (fsp->fsp_name != NULL &&
	    fsp->fsp_name->fsp_link != NULL)
	{
		/*
		 * Free fsp_link of fsp->fsp_name. To do this in the correct
		 * talloc destructor order we have to do it here. The
		 * talloc_free() of the link should set the fsp pointer to NULL.
		 */
		TALLOC_FREE(fsp->fsp_name->fsp_link);
		SMB_ASSERT(fsp->fsp_name->fsp == NULL);
	}

	/* this is paranoia, just in case someone tries to reuse the
	   information */
	ZERO_STRUCTP(fsp);

	/* fsp->fsp_name is a talloc child and is free'd automatically. */
	TALLOC_FREE(fsp);
}

/*
 * Rundown of all smb-related sub-structures of an fsp
 */
void fsp_unbind_smb(struct smb_request *req, files_struct *fsp)
{
	if (fsp == fsp->conn->cwd_fsp) {
		return;
	}

	if (fsp->notify) {
		size_t len = fsp_fullbasepath(fsp, NULL, 0);
		char fullpath[len+1];

		fsp_fullbasepath(fsp, fullpath, sizeof(fullpath));

		notify_remove(fsp->conn->sconn->notify_ctx, fsp, fullpath);
		TALLOC_FREE(fsp->notify);
	}

	if (fsp->op != NULL) {
		fsp->op->compat = NULL;
	}
	TALLOC_FREE(fsp->op);

	if ((req != NULL) && (fsp == req->chain_fsp)) {
		req->chain_fsp = NULL;
	}

	/*
	 * Clear all possible chained fsp
	 * pointers in the SMB2 request queue.
	 */
	remove_smb2_chained_fsp(fsp);
}

void file_free(struct smb_request *req, files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	uint64_t fnum = fsp->fnum;

	fsp_unbind_smb(req, fsp);

	/* Drop all remaining extensions. */
	vfs_remove_all_fsp_extensions(fsp);

	fsp_free(fsp);

	DBG_INFO("freed files structure %"PRIu64" (%zu used)\n",
		 fnum,
		 sconn->num_files);
}

/****************************************************************************
 Get an fsp from a packet given a 16 bit fnum.
****************************************************************************/

files_struct *file_fsp(struct smb_request *req, uint16_t fid)
{
	struct smbXsrv_open *op;
	NTSTATUS status;
	NTTIME now = 0;
	files_struct *fsp;

	if (req == NULL) {
		/*
		 * We should never get here. req==NULL could in theory
		 * only happen from internal opens with a non-zero
		 * root_dir_fid. Internal opens just don't do that, at
		 * least they are not supposed to do so. And if they
		 * start to do so, they better fake up a smb_request
		 * from which we get the right smbd_server_conn. While
		 * this should never happen, let's return NULL here.
		 */
		return NULL;
	}

	if (req->chain_fsp != NULL) {
		if (req->chain_fsp->fsp_flags.closing) {
			return NULL;
		}
		return req->chain_fsp;
	}

	if (req->xconn == NULL) {
		return NULL;
	}

	now = timeval_to_nttime(&req->request_time);

	status = smb1srv_open_lookup(req->xconn,
				     fid, now, &op);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	fsp = op->compat;
	if (fsp == NULL) {
		return NULL;
	}

	if (fsp->fsp_flags.closing) {
		return NULL;
	}

	req->chain_fsp = fsp;
	fsp->fsp_name->st.cached_dos_attributes = FILE_ATTRIBUTE_INVALID;
	return fsp;
}

struct files_struct *file_fsp_get(struct smbd_smb2_request *smb2req,
				  uint64_t persistent_id,
				  uint64_t volatile_id)
{
	struct smbXsrv_open *op;
	NTSTATUS status;
	NTTIME now = 0;
	struct files_struct *fsp;

	now = timeval_to_nttime(&smb2req->request_time);

	status = smb2srv_open_lookup(smb2req->xconn,
				     persistent_id, volatile_id,
				     now, &op);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	fsp = op->compat;
	if (fsp == NULL) {
		return NULL;
	}

	if (smb2req->tcon == NULL) {
		return NULL;
	}

	if (smb2req->tcon->compat != fsp->conn) {
		return NULL;
	}

	if (smb2req->session == NULL) {
		return NULL;
	}

	if (smb2req->session->global->session_wire_id != fsp->vuid) {
		return NULL;
	}

	if (fsp->fsp_flags.closing) {
		return NULL;
	}

	fsp->fsp_name->st.cached_dos_attributes = FILE_ATTRIBUTE_INVALID;

	return fsp;
}

struct files_struct *file_fsp_smb2(struct smbd_smb2_request *smb2req,
				   uint64_t persistent_id,
				   uint64_t volatile_id)
{
	struct files_struct *fsp;

	if (smb2req->compat_chain_fsp != NULL) {
		if (smb2req->compat_chain_fsp->fsp_flags.closing) {
			return NULL;
		}
		smb2req->compat_chain_fsp->fsp_name->st.cached_dos_attributes =
			FILE_ATTRIBUTE_INVALID;
		return smb2req->compat_chain_fsp;
	}

	fsp = file_fsp_get(smb2req, persistent_id, volatile_id);
	if (fsp == NULL) {
		return NULL;
	}

	smb2req->compat_chain_fsp = fsp;
	return fsp;
}

/**
 * Return a jenkins hash of a pathname on a connection.
 */

static NTSTATUS file_name_hash(connection_struct *conn,
			       const char *name,
			       uint32_t *p_name_hash)
{
	char tmpbuf[PATH_MAX];
	char *fullpath, *to_free;
	ssize_t len;
	TDB_DATA key;

	/* Set the hash of the full pathname. */

	if (name[0] == '/') {
		strlcpy(tmpbuf, name, sizeof(tmpbuf));
		fullpath = tmpbuf;
		len = strlen(fullpath);
		to_free = NULL;
	} else {
		len = full_path_tos(conn->connectpath,
				    name,
				    tmpbuf,
				    sizeof(tmpbuf),
				    &fullpath,
				    &to_free);
	}
	if (len == -1) {
		return NT_STATUS_NO_MEMORY;
	}
	key = (TDB_DATA) { .dptr = (uint8_t *)fullpath, .dsize = len+1 };
	*p_name_hash = tdb_jenkins_hash(&key);

	DEBUG(10,("file_name_hash: %s hash 0x%x\n",
		  fullpath,
		(unsigned int)*p_name_hash ));

	TALLOC_FREE(to_free);
	return NT_STATUS_OK;
}

static NTSTATUS fsp_attach_smb_fname(struct files_struct *fsp,
				     struct smb_filename **_smb_fname)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct smb_filename *smb_fname_new = talloc_move(fsp, _smb_fname);
	const char *name_str = NULL;
	uint32_t name_hash = 0;
	NTSTATUS status;

	name_str = smb_fname_str_dbg(smb_fname_new);
	if (name_str == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = file_name_hash(fsp->conn,
				name_str,
				&name_hash);
	TALLOC_FREE(frame);
	name_str = NULL;
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = fsp_smb_fname_link(fsp,
				    &smb_fname_new->fsp_link,
				    &smb_fname_new->fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	fsp->name_hash = name_hash;
	fsp->fsp_name = smb_fname_new;
	fsp->fsp_name->st.cached_dos_attributes = FILE_ATTRIBUTE_INVALID;
	*_smb_fname = NULL;
	return NT_STATUS_OK;
}

/**
 * The only way that the fsp->fsp_name field should ever be set.
 */
NTSTATUS fsp_set_smb_fname(struct files_struct *fsp,
			   const struct smb_filename *smb_fname_in)
{
	struct smb_filename *smb_fname_old = fsp->fsp_name;
	struct smb_filename *smb_fname_new = NULL;
	NTSTATUS status;

	smb_fname_new = cp_smb_filename(fsp, smb_fname_in);
	if (smb_fname_new == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = fsp_attach_smb_fname(fsp, &smb_fname_new);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(smb_fname_new);
		return status;
	}

	if (smb_fname_old != NULL) {
		smb_fname_fsp_unlink(smb_fname_old);
		TALLOC_FREE(smb_fname_old);
	}

	return NT_STATUS_OK;
}

size_t fsp_fullbasepath(struct files_struct *fsp, char *buf, size_t buflen)
{
	int len = 0;

	if (buf == NULL) {
		/*
		 * susv4 allows buf==NULL if buflen==0 for snprintf.
		 */
		SMB_ASSERT(buflen == 0);
	}

	if (ISDOT(fsp->fsp_name->base_name)) {
		len = snprintf(buf, buflen, "%s", fsp->conn->connectpath);
	} else {
		len = snprintf(buf,
			       buflen,
			       "%s/%s",
			       fsp->conn->connectpath,
			       fsp->fsp_name->base_name);
	}
	SMB_ASSERT(len > 0);

	return len;
}

void fsp_set_base_fsp(struct files_struct *fsp, struct files_struct *base_fsp)
{
	SMB_ASSERT(fsp->stream_fsp == NULL);
	if (base_fsp != NULL) {
		SMB_ASSERT(base_fsp->base_fsp == NULL);
		SMB_ASSERT(base_fsp->stream_fsp == NULL);
	}

	if (fsp->base_fsp != NULL) {
		SMB_ASSERT(fsp->base_fsp->stream_fsp == fsp);
		fsp->base_fsp->stream_fsp = NULL;
	}

	fsp->base_fsp = base_fsp;
	if (fsp->base_fsp != NULL) {
		fsp->base_fsp->stream_fsp = fsp;
	}
}

bool fsp_is_alternate_stream(const struct files_struct *fsp)
{
	return (fsp->base_fsp != NULL);
}

struct files_struct *metadata_fsp(struct files_struct *fsp)
{
	if (fsp_is_alternate_stream(fsp)) {
		return fsp->base_fsp;
	}
	return fsp;
}

static bool fsp_generic_ask_sharemode(struct files_struct *fsp)
{
	if (fsp == NULL) {
		return false;
	}

	if (fsp->fsp_flags.posix_open) {
		/* Always use filesystem for UNIX mtime query. */
		return false;
	}

	return true;
}

bool fsp_search_ask_sharemode(struct files_struct *fsp)
{
	if (!fsp_generic_ask_sharemode(fsp)) {
		return false;
	}

	return lp_smbd_search_ask_sharemode(SNUM(fsp->conn));
}

bool fsp_getinfo_ask_sharemode(struct files_struct *fsp)
{
	if (!fsp_generic_ask_sharemode(fsp)) {
		return false;
	}

	return lp_smbd_getinfo_ask_sharemode(SNUM(fsp->conn));
}

void fsp_apply_private_ntcreatex_flags(struct files_struct *fsp,
				       uint32_t flags)
{
	/*
	 * This might be called twice when first trying to open something as a
	 * file, which fails for directories, triggering a second open-directory
	 * attempt via open_directory(). To handle this case make sure to reset
	 * fsp_flags if the corresponding flag is not set, as we might get passed
	 * different flags in pass one and pass two.
	 */
	if (flags & NTCREATEX_FLAG_DENY_DOS) {
		fsp->fsp_flags.ntcreatex_deny_dos = true;
	} else {
		fsp->fsp_flags.ntcreatex_deny_dos = false;
	}
	if (flags & NTCREATEX_FLAG_DENY_FCB) {
		fsp->fsp_flags.ntcreatex_deny_fcb = true;
	} else {
		fsp->fsp_flags.ntcreatex_deny_fcb = false;
	}
	if (flags & NTCREATEX_FLAG_STREAM_BASEOPEN) {
		fsp->fsp_flags.ntcreatex_stream_baseopen = true;
	} else {
		fsp->fsp_flags.ntcreatex_stream_baseopen = false;
	}
}
