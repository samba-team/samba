/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2010

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
#include "../libcli/smb/smb_common.h"
#include "trans2.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../librpc/gen_ndr/open_files.h"
#include "source3/lib/dbwrap/dbwrap_watch.h"
#include "messages.h"

static struct tevent_req *smbd_smb2_setinfo_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct smbd_smb2_request *smb2req,
						 struct files_struct *in_fsp,
						 uint8_t in_info_type,
						 uint8_t in_file_info_class,
						 DATA_BLOB in_input_buffer,
						 uint32_t in_additional_information);
static NTSTATUS smbd_smb2_setinfo_recv(struct tevent_req *req);

static void smbd_smb2_request_setinfo_done(struct tevent_req *subreq);
NTSTATUS smbd_smb2_request_process_setinfo(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	NTSTATUS status;
	const uint8_t *inbody;
	uint8_t in_info_type;
	uint8_t in_file_info_class;
	uint16_t in_input_buffer_offset;
	uint32_t in_input_buffer_length;
	DATA_BLOB in_input_buffer;
	uint32_t in_additional_information;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	struct files_struct *in_fsp;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(req, 0x21);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_info_type			= CVAL(inbody, 0x02);
	in_file_info_class		= CVAL(inbody, 0x03);
	in_input_buffer_length		= IVAL(inbody, 0x04);
	in_input_buffer_offset		= SVAL(inbody, 0x08);
	/* 0x0A 2 bytes reserved */
	in_additional_information	= IVAL(inbody, 0x0C);
	in_file_id_persistent		= BVAL(inbody, 0x10);
	in_file_id_volatile		= BVAL(inbody, 0x18);

	if (in_input_buffer_offset == 0 && in_input_buffer_length == 0) {
		/* This is ok */
	} else if (in_input_buffer_offset !=
		   (SMB2_HDR_BODY + SMBD_SMB2_IN_BODY_LEN(req))) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_input_buffer_length > SMBD_SMB2_IN_DYN_LEN(req)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_input_buffer.data = SMBD_SMB2_IN_DYN_PTR(req);
	in_input_buffer.length = in_input_buffer_length;

	if (in_input_buffer.length > xconn->smb2.server.max_trans) {
		DEBUG(2,("smbd_smb2_request_process_setinfo: "
			 "client ignored max trans: %s: 0x%08X: 0x%08X\n",
			 __location__, (unsigned)in_input_buffer.length,
			 (unsigned)xconn->smb2.server.max_trans));
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	status = smbd_smb2_request_verify_creditcharge(req,
						in_input_buffer.length);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	in_fsp = file_fsp_smb2(req, in_file_id_persistent, in_file_id_volatile);
	if (in_fsp == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	subreq = smbd_smb2_setinfo_send(req, req->sconn->ev_ctx,
					req, in_fsp,
					in_info_type,
					in_file_info_class,
					in_input_buffer,
					in_additional_information);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_setinfo_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 500);
}

static void smbd_smb2_request_setinfo_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	DATA_BLOB outbody;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_setinfo_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	outbody = smbd_smb2_generate_outbody(req, 0x02);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x02);	/* struct size */

	error = smbd_smb2_request_done(req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->xconn,
						 nt_errstr(error));
		return;
	}
}

struct defer_rename_state {
	struct tevent_req *req;
	struct smbd_smb2_request *smb2req;
	struct tevent_context *ev;
	struct files_struct *fsp;
	char *data;
	int data_size;
};

static int defer_rename_state_destructor(struct defer_rename_state *rename_state)
{
	SAFE_FREE(rename_state->data);
	return 0;
}

static void defer_rename_done(struct tevent_req *subreq);

static struct tevent_req *delay_rename_for_lease_break(struct tevent_req *req,
				struct smbd_smb2_request *smb2req,
				struct tevent_context *ev,
				struct files_struct *fsp,
				struct share_mode_lock *lck,
				char *data,
				int data_size)

{
	struct tevent_req *subreq;
	uint32_t i;
	struct share_mode_data *d = lck->data;
	struct defer_rename_state *rename_state;
	bool delay = false;
	struct timeval timeout;

	if (fsp->oplock_type != LEASE_OPLOCK) {
		return NULL;
	}

	for (i=0; i<d->num_share_modes; i++) {
		struct share_mode_entry *e = &d->share_modes[i];
		struct share_mode_lease *l = NULL;
		uint32_t e_lease_type = get_lease_type(d, e);
		uint32_t break_to;

		if (e->op_type != LEASE_OPLOCK) {
			continue;
		}

		l = &d->leases[e->lease_idx];

		if (smb2_lease_equal(fsp_client_guid(fsp),
				&fsp->lease->lease.lease_key,
				&l->client_guid,
				&l->lease_key)) {
			continue;
		}

		if (share_mode_stale_pid(d, i)) {
			continue;
		}

		if (!(e_lease_type & SMB2_LEASE_HANDLE)) {
			continue;
		}

		delay = true;
		break_to = (e_lease_type & ~SMB2_LEASE_HANDLE);

		send_break_message(fsp->conn->sconn->msg_ctx, e, break_to);
	}

	if (!delay) {
		return NULL;
	}

	/* Setup a watch on this record. */
	rename_state = talloc_zero(req, struct defer_rename_state);
	if (rename_state == NULL) {
		return NULL;
	}

	rename_state->req = req;
	rename_state->smb2req = smb2req;
	rename_state->ev = ev;
	rename_state->fsp = fsp;
	rename_state->data = data;
	rename_state->data_size = data_size;

	talloc_set_destructor(rename_state, defer_rename_state_destructor);

	subreq = dbwrap_record_watch_send(
				rename_state,
				ev,
				lck->data->record,
				fsp->conn->sconn->msg_ctx);

	if (subreq == NULL) {
		exit_server("Could not watch share mode record for rename\n");
	}

	tevent_req_set_callback(subreq, defer_rename_done, rename_state);

	timeout = timeval_set(OPLOCK_BREAK_TIMEOUT*2, 0);
	if (!tevent_req_set_endtime(subreq,
			ev,
			timeval_sum(&smb2req->request_time, &timeout))) {
		exit_server("Could not set rename timeout\n");
	}

	return subreq;
}

static void defer_rename_done(struct tevent_req *subreq)
{
	struct defer_rename_state *state = tevent_req_callback_data(
		subreq, struct defer_rename_state);
	NTSTATUS status;
	struct share_mode_lock *lck;
	int ret_size = 0;
	bool ok;

	status = dbwrap_record_watch_recv(subreq, state->req, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("dbwrap_record_watch_recv returned %s\n",
			nt_errstr(status)));
		tevent_req_nterror(state->req, status);
		return;
	}

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user(state->smb2req->tcon->compat,
			    state->smb2req->session->compat->vuid);
	if (!ok) {
		tevent_req_nterror(state->req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	/* should we pass FLAG_CASELESS_PATHNAMES here? */
	ok = set_current_service(state->smb2req->tcon->compat, 0, true);
	if (!ok) {
		tevent_req_nterror(state->req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	/* Do we still need to wait ? */
	lck = get_existing_share_mode_lock(state->req, state->fsp->file_id);
	if (lck == NULL) {
		tevent_req_nterror(state->req, NT_STATUS_UNSUCCESSFUL);
		return;
	}
	subreq = delay_rename_for_lease_break(state->req,
				state->smb2req,
				state->ev,
				state->fsp,
				lck,
				state->data,
				state->data_size);
	if (subreq) {
		/* Yep - keep waiting. */
		state->data = NULL;
		TALLOC_FREE(state);
		TALLOC_FREE(lck);
		return;
	}

	/* Do the rename under the lock. */
	status = smbd_do_setfilepathinfo(state->fsp->conn,
				state->smb2req->smb1req,
				state,
				SMB2_FILE_RENAME_INFORMATION_INTERNAL,
				state->fsp,
				state->fsp->fsp_name,
				&state->data,
				state->data_size,
				&ret_size);

	TALLOC_FREE(lck);
	SAFE_FREE(state->data);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(state->req, status);
		return;
	}

	tevent_req_done(state->req);
}

struct smbd_smb2_setinfo_state {
	struct smbd_smb2_request *smb2req;
};

static struct tevent_req *smbd_smb2_setinfo_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct smbd_smb2_request *smb2req,
						 struct files_struct *fsp,
						 uint8_t in_info_type,
						 uint8_t in_file_info_class,
						 DATA_BLOB in_input_buffer,
						 uint32_t in_additional_information)
{
	struct tevent_req *req = NULL;
	struct smbd_smb2_setinfo_state *state = NULL;
	struct smb_request *smbreq = NULL;
	connection_struct *conn = smb2req->tcon->compat;
	struct share_mode_lock *lck = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_setinfo_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;

	DEBUG(10,("smbd_smb2_setinfo_send: %s - %s\n",
		  fsp_str_dbg(fsp), fsp_fnum_dbg(fsp)));

	smbreq = smbd_smb2_fake_smb_request(smb2req);
	if (tevent_req_nomem(smbreq, req)) {
		return tevent_req_post(req, ev);
	}

	if (IS_IPC(conn)) {
		tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return tevent_req_post(req, ev);
	}

	switch (in_info_type) {
	case 0x01:/* SMB2_SETINFO_FILE */
	{
		uint16_t file_info_level;
		char *data;
		int data_size;
		int ret_size = 0;


		file_info_level = in_file_info_class + 1000;
		if (file_info_level == SMB_FILE_RENAME_INFORMATION) {
			/* SMB2_FILE_RENAME_INFORMATION_INTERNAL == 0xFF00 + in_file_info_class */
			file_info_level = SMB2_FILE_RENAME_INFORMATION_INTERNAL;
		}

		if (fsp->fh->fd == -1) {
			/*
			 * This is actually a SETFILEINFO on a directory
			 * handle (returned from an NT SMB). NT5.0 seems
			 * to do this call. JRA.
			 */
			if (INFO_LEVEL_IS_UNIX(file_info_level)) {
				/* Always do lstat for UNIX calls. */
				if (SMB_VFS_LSTAT(conn, fsp->fsp_name)) {
					DEBUG(3,("smbd_smb2_setinfo_send: "
						 "SMB_VFS_LSTAT of %s failed "
						 "(%s)\n", fsp_str_dbg(fsp),
						 strerror(errno)));
					status = map_nt_error_from_unix(errno);
					tevent_req_nterror(req, status);
					return tevent_req_post(req, ev);
				}
			} else {
				if (SMB_VFS_STAT(conn, fsp->fsp_name) != 0) {
					DEBUG(3,("smbd_smb2_setinfo_send: "
						 "fileinfo of %s failed (%s)\n",
						 fsp_str_dbg(fsp),
						 strerror(errno)));
					status = map_nt_error_from_unix(errno);
					tevent_req_nterror(req, status);
					return tevent_req_post(req, ev);
				}
			}
		} else if (fsp->print_file) {
			/*
			 * Doing a DELETE_ON_CLOSE should cancel a print job.
			 */
			if ((file_info_level == SMB_SET_FILE_DISPOSITION_INFO)
			    && in_input_buffer.length >= 1
			    && CVAL(in_input_buffer.data,0)) {
				fsp->fh->private_options |= NTCREATEX_OPTIONS_PRIVATE_DELETE_ON_CLOSE;

				DEBUG(3,("smbd_smb2_setinfo_send: "
					 "Cancelling print job (%s)\n",
					 fsp_str_dbg(fsp)));

				tevent_req_done(req);
				return tevent_req_post(req, ev);
			} else {
				tevent_req_nterror(req,
					NT_STATUS_OBJECT_PATH_INVALID);
				return tevent_req_post(req, ev);
			}
		} else {
			/*
			 * Original code - this is an open file.
			 */

			if (SMB_VFS_FSTAT(fsp, &fsp->fsp_name->st) != 0) {
				DEBUG(3,("smbd_smb2_setinfo_send: fstat "
					 "of %s failed (%s)\n",
					 fsp_fnum_dbg(fsp),
					 strerror(errno)));
				status = map_nt_error_from_unix(errno);
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
		}

		data = NULL;
		data_size = in_input_buffer.length;
		if (data_size > 0) {
			data = (char *)SMB_MALLOC_ARRAY(char, data_size);
			if (tevent_req_nomem(data, req)) {
				return tevent_req_post(req, ev);
			}
			memcpy(data, in_input_buffer.data, data_size);
		}

		if (file_info_level == SMB2_FILE_RENAME_INFORMATION_INTERNAL) {
			struct tevent_req *subreq;

			lck = get_existing_share_mode_lock(mem_ctx,
							fsp->file_id);
			if (lck == NULL) {
				tevent_req_nterror(req,
					NT_STATUS_UNSUCCESSFUL);
				return tevent_req_post(req, ev);
			}

			subreq = delay_rename_for_lease_break(req,
							smb2req,
							ev,
							fsp,
							lck,
							data,
							data_size);
			if (subreq) {
				/* Wait for lease break response. */

				/* Ensure we can't be closed in flight. */
				if (!aio_add_req_to_fsp(fsp, req)) {
					TALLOC_FREE(lck);
					tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
					return tevent_req_post(req, ev);
				}

				TALLOC_FREE(lck);
				return req;
			}
		}

		status = smbd_do_setfilepathinfo(conn, smbreq, state,
						 file_info_level,
						 fsp,
						 fsp->fsp_name,
						 &data,
						 data_size,
						 &ret_size);
		TALLOC_FREE(lck);
		SAFE_FREE(data);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_LEVEL)) {
				status = NT_STATUS_INVALID_INFO_CLASS;
			}
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
		break;
	}

	case 0x03:/* SMB2_SETINFO_SECURITY */
	{
		if (!CAN_WRITE(conn)) {
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}

		status = set_sd_blob(fsp,
				in_input_buffer.data,
				in_input_buffer.length,
				in_additional_information &
				SMB_SUPPORTED_SECINFO_FLAGS);
		if (!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
		break;
	}

	default:
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS smbd_smb2_setinfo_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}
