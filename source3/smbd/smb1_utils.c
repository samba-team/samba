/*
 * Unix SMB/CIFS implementation.
 * Util functions valid in the SMB1 server
 *
 * Copyright (C) Volker Lendecke 2019
 * Copyright by the authors of the functions moved here eventually
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

#include "includes.h"
#include "smb1_utils.h"
#include "libcli/security/security.h"

/****************************************************************************
 Special FCB or DOS processing in the case of a sharing violation.
 Try and find a duplicated file handle.
****************************************************************************/

struct files_struct *fcb_or_dos_open(
	struct smb_request *req,
	const struct smb_filename *smb_fname,
	uint32_t access_mask,
	uint32_t create_options,
	uint32_t private_flags)
{
	struct connection_struct *conn = req->conn;
	struct file_id id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	struct files_struct *fsp = NULL, *new_fsp = NULL;
	NTSTATUS status;

	if ((private_flags &
	     (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS|
	      NTCREATEX_OPTIONS_PRIVATE_DENY_FCB))
	    == 0) {
		return NULL;
	}

	for(fsp = file_find_di_first(conn->sconn, id);
	    fsp != NULL;
	    fsp = file_find_di_next(fsp)) {

		DBG_DEBUG("Checking file %s, fd = %d, vuid = %"PRIu64", "
			  "file_pid = %"PRIu16", "
			  "private_options = 0x%"PRIx32", "
			  "access_mask = 0x%"PRIx32"\n",
			  fsp_str_dbg(fsp),
			  fsp->fh->fd,
			  fsp->vuid,
			  fsp->file_pid,
			  fsp->fh->private_options,
			  fsp->access_mask);

		if (fsp->fh->fd != -1 &&
		    fsp->vuid == req->vuid &&
		    fsp->file_pid == req->smbpid &&
		    (fsp->fh->private_options &
		     (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS |
		      NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) &&
		    (fsp->access_mask & FILE_WRITE_DATA) &&
		    strequal(fsp->fsp_name->base_name, smb_fname->base_name) &&
		    strequal(fsp->fsp_name->stream_name,
			     smb_fname->stream_name)) {
			DBG_DEBUG("file match\n");
			break;
		}
	}

	if (fsp == NULL) {
		return NULL;
	}

	/* quite an insane set of semantics ... */
	if (is_executable(smb_fname->base_name) &&
	    (fsp->fh->private_options & NTCREATEX_OPTIONS_PRIVATE_DENY_DOS)) {
		DBG_DEBUG("file fail due to is_executable.\n");
		return NULL;
	}

	status = file_new(req, conn, &new_fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("file_new failed: %s\n", nt_errstr(status));
		return NULL;
	}

	status = dup_file_fsp(
		req,
		fsp,
		access_mask,
		create_options,
		new_fsp);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dup_file_fsp failed: %s\n", nt_errstr(status));
		file_free(req, new_fsp);
		return NULL;
	}

	return new_fsp;
}
