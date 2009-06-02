/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009

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
#include "smbd/globals.h"
#include "../source4/libcli/smb2/smb2_constants.h"

static NTSTATUS smbd_smb2_flush(struct smbd_smb2_request *req,
				uint64_t in_file_id_volatile);

NTSTATUS smbd_smb2_request_process_flush(struct smbd_smb2_request *req)
{
	const uint8_t *inhdr;
	const uint8_t *inbody;
	int i = req->current_idx;
	DATA_BLOB outbody;
	size_t expected_body_size = 0x18;
	size_t body_size;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	NTSTATUS status;

	inhdr = (const uint8_t *)req->in.vector[i+0].iov_base;
	if (req->in.vector[i+1].iov_len != (expected_body_size & 0xFFFFFFFE)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	inbody = (const uint8_t *)req->in.vector[i+1].iov_base;

	body_size = SVAL(inbody, 0x00);
	if (body_size != expected_body_size) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_file_id_persistent	= BVAL(inbody, 0x08);
	in_file_id_volatile	= BVAL(inbody, 0x10);

	if (in_file_id_persistent != 0) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	status = smbd_smb2_flush(req,
				 in_file_id_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	outbody = data_blob_talloc(req->out.vector, NULL, 0x10);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	SSVAL(outbody.data, 0x00, 0x04);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */

	return smbd_smb2_request_done(req, outbody, NULL);
}

static NTSTATUS smbd_smb2_flush(struct smbd_smb2_request *req,
				uint64_t in_file_id_volatile)
{
	NTSTATUS status;
	struct smb_request *smbreq;
	connection_struct *conn = req->tcon->compat_conn;
	files_struct *fsp;

	DEBUG(10,("smbd_smb2_flush: file_id[0x%016llX]\n",
		  (unsigned long long)in_file_id_volatile));

	smbreq = smbd_smb2_fake_smb_request(req);
	if (smbreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	fsp = file_fsp(smbreq, (uint16_t)in_file_id_volatile);
	if (fsp == NULL) {
		return NT_STATUS_FILE_CLOSED;
	}
	if (conn != fsp->conn) {
		return NT_STATUS_FILE_CLOSED;
	}
	if (req->session->vuid != fsp->vuid) {
		return NT_STATUS_FILE_CLOSED;
	}

	if (!CHECK_WRITE(fsp)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	status = sync_file(conn, fsp, true);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("smbd_smb2_flush: sync_file for %s returned %s\n",
			fsp->fsp_name, nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}
