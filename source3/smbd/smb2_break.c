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
#include "../lib/util/tevent_ntstatus.h"
#include "locking/leases_db.h"

static NTSTATUS smbd_smb2_request_process_lease_break(
	struct smbd_smb2_request *req);

static struct tevent_req *smbd_smb2_oplock_break_send(TALLOC_CTX *mem_ctx,
						      struct tevent_context *ev,
						      struct smbd_smb2_request *smb2req,
						      struct files_struct *in_fsp,
						      uint8_t in_oplock_level);
static NTSTATUS smbd_smb2_oplock_break_recv(struct tevent_req *req,
					    uint8_t *out_oplock_level);

static void smbd_smb2_request_oplock_break_done(struct tevent_req *subreq);
NTSTATUS smbd_smb2_request_process_break(struct smbd_smb2_request *req)
{
	NTSTATUS status;
	const uint8_t *inbody;
	uint8_t in_oplock_level;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	struct files_struct *in_fsp;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(req, 0x18);
	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		/*
		 * Retry as a lease break
		 */
		return smbd_smb2_request_process_lease_break(req);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_oplock_level		= CVAL(inbody, 0x02);

	/* 0x03 1 bytes reserved */
	/* 0x04 4 bytes reserved */
	in_file_id_persistent		= BVAL(inbody, 0x08);
	in_file_id_volatile		= BVAL(inbody, 0x10);

	in_fsp = file_fsp_smb2(req, in_file_id_persistent, in_file_id_volatile);
	if (in_fsp == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	/* Are we awaiting a break message ? */
	if (in_fsp->oplock_timeout == NULL) {
		return smbd_smb2_request_error(
			req, NT_STATUS_INVALID_OPLOCK_PROTOCOL);
	}

	if (in_oplock_level != SMB2_OPLOCK_LEVEL_NONE &&
	    in_oplock_level != SMB2_OPLOCK_LEVEL_II) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	subreq = smbd_smb2_oplock_break_send(req, req->sconn->ev_ctx,
					     req, in_fsp, in_oplock_level);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_oplock_break_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 500);
}

static void smbd_smb2_request_oplock_break_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	const uint8_t *inbody;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint8_t out_oplock_level = 0;
	DATA_BLOB outbody;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_oplock_break_recv(subreq, &out_oplock_level);
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

	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_file_id_persistent	= BVAL(inbody, 0x08);
	in_file_id_volatile	= BVAL(inbody, 0x10);

	outbody = smbd_smb2_generate_outbody(req, 0x18);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x18);	/* struct size */
	SCVAL(outbody.data, 0x02,
	      out_oplock_level);		/* SMB2 oplock level */
	SCVAL(outbody.data, 0x03, 0);		/* reserved */
	SIVAL(outbody.data, 0x04, 0);		/* reserved */
	SBVAL(outbody.data, 0x08,
	      in_file_id_persistent);		/* file id (persistent) */
	SBVAL(outbody.data, 0x10,
	      in_file_id_volatile);		/* file id (volatile) */

	error = smbd_smb2_request_done(req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->xconn,
						 nt_errstr(error));
		return;
	}
}

struct smbd_smb2_oplock_break_state {
	struct smbd_smb2_request *smb2req;
	uint8_t out_oplock_level; /* SMB2 oplock level. */
};

static struct tevent_req *smbd_smb2_oplock_break_send(TALLOC_CTX *mem_ctx,
						      struct tevent_context *ev,
						      struct smbd_smb2_request *smb2req,
						      struct files_struct *fsp,
						      uint8_t in_oplock_level)
{
	struct tevent_req *req;
	struct smbd_smb2_oplock_break_state *state;
	struct smb_request *smbreq;
	int oplocklevel = map_smb2_oplock_levels_to_samba(in_oplock_level);
	bool break_to_none = (oplocklevel == NO_OPLOCK);
	bool result;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_oplock_break_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;
	state->out_oplock_level = SMB2_OPLOCK_LEVEL_NONE;

	DEBUG(10,("smbd_smb2_oplock_break_send: %s - %s, "
		  "samba level %d\n",
		  fsp_str_dbg(fsp), fsp_fnum_dbg(fsp),
		  oplocklevel));

	smbreq = smbd_smb2_fake_smb_request(smb2req);
	if (tevent_req_nomem(smbreq, req)) {
		return tevent_req_post(req, ev);
	}

	DEBUG(5,("smbd_smb2_oplock_break_send: got SMB2 oplock break (%u) from client "
		"for file %s, %s\n",
		(unsigned int)in_oplock_level,
		fsp_str_dbg(fsp),
		fsp_fnum_dbg(fsp)));

	if ((fsp->sent_oplock_break == BREAK_TO_NONE_SENT) ||
			(break_to_none)) {
		result = remove_oplock(fsp);
		state->out_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
	} else {
		result = downgrade_oplock(fsp);
		state->out_oplock_level = SMB2_OPLOCK_LEVEL_II;
	}

	if (!result) {
		DEBUG(0, ("smbd_smb2_oplock_break_send: error in removing "
			"oplock on file %s\n", fsp_str_dbg(fsp)));
		/* Hmmm. Is this panic justified? */
		smb_panic("internal tdb error");
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS smbd_smb2_oplock_break_recv(struct tevent_req *req,
					    uint8_t *out_oplock_level)
{
	NTSTATUS status;
	struct smbd_smb2_oplock_break_state *state =
		tevent_req_data(req,
		struct smbd_smb2_oplock_break_state);

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_oplock_level = state->out_oplock_level;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static void smbd_smb2_request_lease_break_done(struct tevent_req *subreq);

static struct tevent_req *smbd_smb2_lease_break_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct smbd_smb2_request *smb2_req, struct smb2_lease_key in_lease_key,
	uint32_t in_lease_state);
static NTSTATUS smbd_smb2_lease_break_recv(struct tevent_req *req,
					   uint32_t *out_lease_state);


static NTSTATUS smbd_smb2_request_process_lease_break(
	struct smbd_smb2_request *req)
{
	NTSTATUS status;
	const uint8_t *inbody;
	struct smb2_lease_key in_lease_key;
	uint32_t in_lease_state;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(req, 0x24);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_lease_key.data[0] = BVAL(inbody, 8);
	in_lease_key.data[1] = BVAL(inbody, 16);
	in_lease_state = IVAL(inbody, 24);

	subreq = smbd_smb2_lease_break_send(req, req->sconn->ev_ctx, req,
					    in_lease_key, in_lease_state);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_lease_break_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 500);
}

static void smbd_smb2_request_lease_break_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(
		subreq, struct smbd_smb2_request);
	const uint8_t *inbody;
	struct smb2_lease_key in_lease_key;
	uint32_t out_lease_state = 0;
	DATA_BLOB outbody;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_lease_break_recv(subreq, &out_lease_state);
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

	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_lease_key.data[0] = BVAL(inbody, 8);
	in_lease_key.data[1] = BVAL(inbody, 16);

	outbody = smbd_smb2_generate_outbody(req, 0x24);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x24);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */
	SIVAL(outbody.data, 0x04, 0);		/* flags, must be 0 */
	SBVAL(outbody.data, 0x08, in_lease_key.data[0]);
	SBVAL(outbody.data, 0x10, in_lease_key.data[1]);
	SIVAL(outbody.data, 0x18, out_lease_state);
	SBVAL(outbody.data, 0x1c, 0);           /* leaseduration, must be 0 */

	error = smbd_smb2_request_done(req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->xconn,
						 nt_errstr(error));
		return;
	}
}

struct smbd_smb2_lease_break_state {
	uint32_t lease_state;
};

struct lease_lookup_state {
	TALLOC_CTX *mem_ctx;
	/* Return parameters. */
	uint32_t num_file_ids;
	struct file_id *ids;
	NTSTATUS status;
};

static void lease_parser(
	uint32_t num_files,
	const struct leases_db_file *files,
	void *private_data)
{
	struct lease_lookup_state *lls =
		(struct lease_lookup_state *)private_data;

	lls->status = NT_STATUS_OK;
	lls->num_file_ids = num_files;
	lls->status = leases_db_copy_file_ids(lls->mem_ctx,
				num_files,
				files,
				&lls->ids);
}

static struct tevent_req *smbd_smb2_lease_break_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct smbd_smb2_request *smb2_req, struct smb2_lease_key in_lease_key,
	uint32_t in_lease_state)
{
	struct tevent_req *req;
	struct smbd_smb2_lease_break_state *state;
	struct lease_lookup_state lls = {.mem_ctx = mem_ctx};
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_lease_break_state);
	if (req == NULL) {
		return NULL;
	}
	state->lease_state = in_lease_state;

	/* Find any file ids with this lease key. */
	status = leases_db_parse(&smb2_req->xconn->smb2.client.guid,
				 &in_lease_key,
				 lease_parser,
				 &lls);

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
			DEBUG(10, ("No record for lease key found\n"));
		}
	} else if (!NT_STATUS_IS_OK(lls.status)) {
		status = lls.status;
	} else if (lls.num_file_ids == 0) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	status = downgrade_lease(smb2_req->xconn,
				lls.num_file_ids,
				lls.ids,
				&in_lease_key,
				in_lease_state);

	if (NT_STATUS_EQUAL(status, NT_STATUS_OPLOCK_BREAK_IN_PROGRESS)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (tevent_req_nterror(req, status)) {
		DEBUG(10, ("downgrade_lease returned %s\n",
			   nt_errstr(status)));
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS smbd_smb2_lease_break_recv(struct tevent_req *req,
					   uint32_t *out_lease_state)
{
	struct smbd_smb2_lease_break_state *state = tevent_req_data(
		req, struct smbd_smb2_lease_break_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*out_lease_state = state->lease_state;
	return NT_STATUS_OK;
}

/*********************************************************
 Create and send an asynchronous
 SMB2 OPLOCK_BREAK_NOTIFICATION.
*********************************************************/

void send_break_message_smb2(files_struct *fsp,
			     uint32_t break_from,
			     uint32_t break_to)
{
	NTSTATUS status;
	struct smbXsrv_connection *xconn = NULL;
	struct smbXsrv_session *session = NULL;
	struct timeval tv = timeval_current();
	NTTIME now = timeval_to_nttime(&tv);

	/*
	 * TODO: in future we should have a better algorithm
	 * to find the correct connection for a break message.
	 * Then we also need some retries if a channel gets disconnected.
	 */
	xconn = fsp->conn->sconn->client->connections;

	status = smb2srv_session_lookup(xconn,
					fsp->vuid,
					now,
					&session);
	if (NT_STATUS_EQUAL(status, NT_STATUS_USER_SESSION_DELETED) ||
	    (session == NULL))
	{

		DEBUG(10,("send_break_message_smb2: skip oplock break "
			"for file %s, %s, smb2 level %u session %llu not found\n",
			fsp_str_dbg(fsp),
			fsp_fnum_dbg(fsp),
			(unsigned int)break_to,
			(unsigned long long)fsp->vuid));
		return;
	}

	DEBUG(10,("send_break_message_smb2: sending oplock break "
		"for file %s, %s, smb2 level %u\n",
		fsp_str_dbg(fsp),
		fsp_fnum_dbg(fsp),
		(unsigned int)break_to ));

	if (fsp->oplock_type == LEASE_OPLOCK) {
		uint32_t break_flags = 0;
		uint16_t new_epoch;

		if (fsp->lease->lease.lease_state != SMB2_LEASE_NONE) {
			break_flags = SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED;
		}

		if (fsp->lease->lease.lease_version > 1) {
			new_epoch = fsp->lease->lease.lease_epoch;
		} else {
			new_epoch = 0;
		}

		status = smbd_smb2_send_lease_break(xconn, new_epoch, break_flags,
						    &fsp->lease->lease.lease_key,
						    break_from, break_to);
	} else {
		uint8_t smb2_oplock_level;
		smb2_oplock_level = (break_to & SMB2_LEASE_READ) ?
			SMB2_OPLOCK_LEVEL_II : SMB2_OPLOCK_LEVEL_NONE;
		status = smbd_smb2_send_oplock_break(xconn,
						     session,
						     fsp->conn->tcon,
						     fsp->op,
						     smb2_oplock_level);
	}
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(xconn,
						 nt_errstr(status));
		return;
	}
}
