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
#include "libcli/security/security.h"
#include "util_tdb.h"
#include <ccan/hash/hash.h>
#include "lib/util/bitmap.h"

#define FILE_HANDLE_OFFSET 0x1000

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
	fsp->fh = talloc_zero(mem_ctx, struct fd_handle);
	if (fsp->fh == NULL) {
		goto fail;
	}

	fsp->fh->ref_count = 1;
	fsp->fh->fd = -1;

	fsp->fnum = FNUM_FIELD_INVALID;
	fsp->conn = conn;

	DLIST_ADD(sconn->files, fsp);
	sconn->num_files += 1;

	conn->num_files_open++;

	*result = fsp;
	return NT_STATUS_OK;

fail:
	if (fsp != NULL) {
		TALLOC_FREE(fsp->fh);
	}
	TALLOC_FREE(fsp);

	return status;
}

/****************************************************************************
 Find first available file slot.
****************************************************************************/

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

	if (sconn->conn) {
		struct smbXsrv_open *op = NULL;
		NTTIME now = timeval_to_nttime(&fsp->open_time);

		status = smbXsrv_open_create(sconn->conn,
					     conn->session_info,
					     now, &op);
		if (!NT_STATUS_IS_OK(status)) {
			file_free(NULL, fsp);
			return status;
		}
		fsp->op = op;
		op->compat = fsp;
		fsp->fnum = op->local_id;
		fsp->fh->gen_id = smbXsrv_open_hash(op);
	}

	/*
	 * Create an smb_filename with "" for the base_name.  There are very
	 * few NULL checks, so make sure it's initialized with something. to
	 * be safe until an audit can be done.
	 */
	status = create_synthetic_smb_fname(fsp, "", NULL, NULL,
					    &fsp->fsp_name);
	if (!NT_STATUS_IS_OK(status)) {
		file_free(NULL, fsp);
		return status;
	}

	DEBUG(5,("allocated file structure %s (%u used)\n",
		 fsp_fnum_dbg(fsp), (unsigned int)sconn->num_files));

	if (req != NULL) {
		fsp->mid = req->mid;
		req->chain_fsp = fsp;
	}

	/* A new fsp invalidates the positive and
	  negative fsp_fi_cache as the new fsp is pushed
	  at the start of the list and we search from
	  a cache hit to the *end* of the list. */

	ZERO_STRUCT(sconn->fsp_fi_cache);

	*result = fsp;
	return NT_STATUS_OK;
}

/****************************************************************************
 Close all open files for a connection.
****************************************************************************/

void file_close_conn(connection_struct *conn)
{
	files_struct *fsp, *next;

	for (fsp=conn->sconn->files; fsp; fsp=next) {
		next = fsp->next;
		if (fsp->conn != conn) {
			continue;
		}
		if (fsp->op != NULL && fsp->op->global->durable) {
			/*
			 * A tree disconnect closes a durable handle
			 */
			fsp->op->global->durable = false;
		}
		close_file(NULL, fsp, SHUTDOWN_CLOSE);
	}
}

/****************************************************************************
 Close all open files for a pid and a vuid.
****************************************************************************/

void file_close_pid(struct smbd_server_connection *sconn, uint16 smbpid,
		    uint64_t vuid)
{
	files_struct *fsp, *next;

	for (fsp=sconn->files;fsp;fsp=next) {
		next = fsp->next;
		if ((fsp->file_pid == smbpid) && (fsp->vuid == vuid)) {
			close_file(NULL, fsp, SHUTDOWN_CLOSE);
		}
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

void file_close_user(struct smbd_server_connection *sconn, uint64_t vuid)
{
	files_struct *fsp, *next;

	for (fsp=sconn->files; fsp; fsp=next) {
		next=fsp->next;
		if (fsp->vuid == vuid) {
			close_file(NULL, fsp, SHUTDOWN_CLOSE);
		}
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
		if (fsp->fh->fd == fd) {
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

	for (fsp=sconn->files; fsp; fsp=fsp->next,count++) {
		/* We can have a fsp->fh->fd == -1 here as it could be a stat open. */
		if (file_id_equal(&fsp->file_id, &id) &&
		    fsp->fh->gen_id == gen_id ) {
			if (count > 10) {
				DLIST_PROMOTE(sconn->files, fsp);
			}
			/* Paranoia check. */
			if ((fsp->fh->fd == -1) &&
			    (fsp->oplock_type != NO_OPLOCK) &&
			    (fsp->oplock_type != FAKE_LEVEL_II_OPLOCK)) {
				DEBUG(0,("file_find_dif: file %s file_id = "
					 "%s, gen = %u oplock_type = %u is a "
					 "stat open with oplock type !\n",
					 fsp_str_dbg(fsp),
					 file_id_string_tos(&fsp->file_id),
					 (unsigned int)fsp->fh->gen_id,
					 (unsigned int)fsp->oplock_type ));
				smb_panic("file_find_dif");
			}
			return fsp;
		}
	}

	return NULL;
}

/****************************************************************************
 Find the first fsp given a device and inode.
 We use a singleton cache here to speed up searching from getfilepathinfo
 calls.
****************************************************************************/

files_struct *file_find_di_first(struct smbd_server_connection *sconn,
				 struct file_id id)
{
	files_struct *fsp;

	if (file_id_equal(&sconn->fsp_fi_cache.id, &id)) {
		/* Positive or negative cache hit. */
		return sconn->fsp_fi_cache.fsp;
	}

	sconn->fsp_fi_cache.id = id;

	for (fsp=sconn->files;fsp;fsp=fsp->next) {
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

files_struct *file_find_di_next(files_struct *start_fsp)
{
	files_struct *fsp;

	for (fsp = start_fsp->next;fsp;fsp=fsp->next) {
		if (file_id_equal(&fsp->file_id, &start_fsp->file_id)) {
			return fsp;
		}
	}

	return NULL;
}

/****************************************************************************
 Find any fsp open with a pathname below that of an already open path.
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
 Sync open files on a connection.
****************************************************************************/

void file_sync_all(connection_struct *conn)
{
	files_struct *fsp, *next;

	for (fsp=conn->sconn->files; fsp; fsp=next) {
		next=fsp->next;
		if ((conn == fsp->conn) && (fsp->fh->fd != -1)) {
			sync_file(conn, fsp, True /* write through */);
		}
	}
}

/****************************************************************************
 Free up a fsp.
****************************************************************************/

void fsp_free(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;

	DLIST_REMOVE(sconn->files, fsp);
	SMB_ASSERT(sconn->num_files > 0);
	sconn->num_files--;

	TALLOC_FREE(fsp->fake_file_handle);

	if (fsp->fh->ref_count == 1) {
		TALLOC_FREE(fsp->fh);
	} else {
		fsp->fh->ref_count--;
	}

	fsp->conn->num_files_open--;

	/* this is paranoia, just in case someone tries to reuse the
	   information */
	ZERO_STRUCTP(fsp);

	/* fsp->fsp_name is a talloc child and is free'd automatically. */
	TALLOC_FREE(fsp);
}

void file_free(struct smb_request *req, files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	uint64_t fnum = fsp->fnum;

	if (fsp->notify) {
		struct notify_context *notify_ctx =
			fsp->conn->sconn->notify_ctx;
		notify_remove(notify_ctx, fsp);
		TALLOC_FREE(fsp->notify);
	}

	/* Ensure this event will never fire. */
	TALLOC_FREE(fsp->update_write_time_event);

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
	if (req != NULL && req->smb2req) {
		remove_smb2_chained_fsp(fsp);
	}

	/* Closing a file can invalidate the positive cache. */
	if (fsp == sconn->fsp_fi_cache.fsp) {
		ZERO_STRUCT(sconn->fsp_fi_cache);
	}

	/* Drop all remaining extensions. */
	vfs_remove_all_fsp_extensions(fsp);

	fsp_free(fsp);

	DEBUG(5,("freed files structure %llu (%u used)\n",
		 (unsigned long long)fnum, (unsigned int)sconn->num_files));
}

/****************************************************************************
 Get an fsp from a packet given a 16 bit fnum.
****************************************************************************/

files_struct *file_fsp(struct smb_request *req, uint16 fid)
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
		if (req->chain_fsp->deferred_close) {
			return NULL;
		}
		return req->chain_fsp;
	}

	if (req->sconn->conn == NULL) {
		return NULL;
	}

	now = timeval_to_nttime(&req->request_time);

	status = smb1srv_open_lookup(req->sconn->conn,
				     fid, now, &op);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	fsp = op->compat;
	if (fsp == NULL) {
		return NULL;
	}

	if (fsp->deferred_close) {
		return NULL;
	}

	req->chain_fsp = fsp;
	return fsp;
}

struct files_struct *file_fsp_smb2(struct smbd_smb2_request *smb2req,
				   uint64_t persistent_id,
				   uint64_t volatile_id)
{
	struct smbXsrv_open *op;
	NTSTATUS status;
	NTTIME now = 0;
	struct files_struct *fsp;

	if (smb2req->compat_chain_fsp != NULL) {
		if (smb2req->compat_chain_fsp->deferred_close) {
			return NULL;
		}
		return smb2req->compat_chain_fsp;
	}

	now = timeval_to_nttime(&smb2req->request_time);

	status = smb2srv_open_lookup(smb2req->sconn->conn,
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

	if (smb2req->session->compat == NULL) {
		return NULL;
	}

	if (smb2req->session->compat->vuid != fsp->vuid) {
		return NULL;
	}

	if (fsp->deferred_close) {
		return NULL;
	}

	smb2req->compat_chain_fsp = fsp;
	return fsp;
}

/****************************************************************************
 Duplicate the file handle part for a DOS or FCB open.
****************************************************************************/

NTSTATUS dup_file_fsp(struct smb_request *req, files_struct *from,
		      uint32 access_mask, uint32 share_access,
		      uint32 create_options, files_struct *to)
{
	/* this can never happen for print files */
	SMB_ASSERT(from->print_file == NULL);

	TALLOC_FREE(to->fh);

	to->fh = from->fh;
	to->fh->ref_count++;

	to->file_id = from->file_id;
	to->initial_allocation_size = from->initial_allocation_size;
	to->file_pid = from->file_pid;
	to->vuid = from->vuid;
	to->open_time = from->open_time;
	to->access_mask = access_mask;
	to->share_access = share_access;
	to->oplock_type = from->oplock_type;
	to->can_lock = from->can_lock;
	to->can_read = ((access_mask & FILE_READ_DATA) != 0);
	to->can_write =
		CAN_WRITE(from->conn) &&
		((access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0);
	to->modified = from->modified;
	to->is_directory = from->is_directory;
	to->aio_write_behind = from->aio_write_behind;

	return fsp_set_smb_fname(to, from->fsp_name);
}

/**
 * Return a jenkins hash of a pathname on a connection.
 */

NTSTATUS file_name_hash(connection_struct *conn,
			const char *name, uint32_t *p_name_hash)
{
	char *fullpath = NULL;

	/* Set the hash of the full pathname. */
	fullpath = talloc_asprintf(talloc_tos(),
			"%s/%s",
			conn->connectpath,
			name);
	if (!fullpath) {
		return NT_STATUS_NO_MEMORY;
	}
	*p_name_hash = hash(fullpath, talloc_get_size(fullpath), 0);

	DEBUG(10,("file_name_hash: %s hash 0x%x\n",
		fullpath,
		(unsigned int)*p_name_hash ));

	TALLOC_FREE(fullpath);
	return NT_STATUS_OK;
}

/**
 * The only way that the fsp->fsp_name field should ever be set.
 */
NTSTATUS fsp_set_smb_fname(struct files_struct *fsp,
			   const struct smb_filename *smb_fname_in)
{
	NTSTATUS status;
	struct smb_filename *smb_fname_new;

	status = copy_smb_filename(fsp, smb_fname_in, &smb_fname_new);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	TALLOC_FREE(fsp->fsp_name);
	fsp->fsp_name = smb_fname_new;

	return file_name_hash(fsp->conn,
			smb_fname_str_dbg(fsp->fsp_name),
			&fsp->name_hash);
}
