/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2021

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
#include "include/ntioctl.h"
#include "smb2_ioctl_private.h"
#include "librpc/gen_ndr/ioctl.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

struct async_sleep_state {
	struct smbd_server_connection *sconn;
	files_struct *fsp;
};

static void smbd_fsctl_torture_async_sleep_done(struct tevent_req *subreq);

static struct tevent_req *smbd_fsctl_torture_async_sleep_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				files_struct *fsp,
				uint8_t msecs)
{
	struct async_sleep_state *state = NULL;
	struct tevent_req *subreq = NULL;
	bool ok;

	subreq = tevent_req_create(mem_ctx,
				&state,
				struct async_sleep_state);
	if (!subreq) {
		return NULL;
	}

	/*
	 * Store the conn separately, as the test is to
	 * see if fsp is still a valid pointer, so we can't
	 * do anything other than test it for entry in the
	 * open files on this server connection.
	 */
	state->sconn = fsp->conn->sconn;
	state->fsp = fsp;

	/*
	 * Just wait for the specified number of micro seconds,
	 * to allow the client time to close fsp.
	 */
	ok = tevent_req_set_endtime(subreq,
				    ev,
				    timeval_current_ofs(0, msecs));
	if (!ok) {
		tevent_req_nterror(subreq, NT_STATUS_NO_MEMORY);
		return tevent_req_post(subreq, ev);
	}

	return subreq;
}

static files_struct *find_my_fsp(struct files_struct *fsp,
				 void *private_data)
{
	struct files_struct *myfsp = (struct files_struct *)private_data;

	if (fsp == myfsp) {
		return myfsp;
	}
	return NULL;
}

static bool smbd_fsctl_torture_async_sleep_recv(struct tevent_req *subreq)
{
	tevent_req_received(subreq);
	return true;
}

static void smbd_fsctl_torture_async_sleep_done(struct tevent_req *subreq)
{
	struct files_struct *found_fsp;
	struct tevent_req *req = tevent_req_callback_data(
					subreq,
					struct tevent_req);
	struct async_sleep_state *state = tevent_req_data(
					subreq,
					struct async_sleep_state);

	/* Does state->fsp still exist on state->sconn ? */
	found_fsp = files_forall(state->sconn,
				 find_my_fsp,
				 state->fsp);

	smbd_fsctl_torture_async_sleep_recv(subreq);
	TALLOC_FREE(subreq);

	if (found_fsp == NULL) {
		/*
		 * We didn't find it - return an error to the
		 * smb2 ioctl request. Use NT_STATUS_FILE_CLOSED so
		 * the client can tell the difference between
		 * a bad fsp handle and
		 *
		 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=14769
		 *
		 * This request should block file closure until it
		 * has completed.
		 */
		tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
		return;
	}
	tevent_req_done(req);
}

struct tevent_req *smb2_ioctl_smbtorture(uint32_t ctl_code,
					 struct tevent_context *ev,
					 struct tevent_req *req,
					 struct smbd_smb2_ioctl_state *state)
{
	NTSTATUS status;
	bool ok;

	ok = lp_parm_bool(-1, "smbd", "FSCTL_SMBTORTURE", false);
	if (!ok) {
		goto not_supported;
	}

	switch (ctl_code) {
	case FSCTL_SMBTORTURE_FORCE_UNACKED_TIMEOUT:
		if (state->in_input.length != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		state->smb2req->xconn->ack.force_unacked_timeout = true;
		tevent_req_done(req);
		return tevent_req_post(req, ev);

	case FSCTL_SMBTORTURE_IOCTL_RESPONSE_BODY_PADDING8:
		if (state->in_input.length != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		if (state->in_max_output > 0) {
			uint32_t size = state->in_max_output;

			state->out_output = data_blob_talloc(state, NULL, size);
			if (tevent_req_nomem(state->out_output.data, req)) {
				return tevent_req_post(req, ev);
			}
			memset(state->out_output.data, 8, size);
		}

		state->body_padding = 8;
		tevent_req_done(req);
		return tevent_req_post(req, ev);

	case FSCTL_SMBTORTURE_GLOBAL_READ_RESPONSE_BODY_PADDING8:
		if (state->in_input.length != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		state->smb2req->xconn->smb2.smbtorture.read_body_padding = 8;
		tevent_req_done(req);
		return tevent_req_post(req, ev);

	case FSCTL_SMBTORTURE_FSP_ASYNC_SLEEP: {
		struct tevent_req *subreq = NULL;

		/* Data is 1 byte of CVAL stored seconds to delay for. */
		if (state->in_input.length != 1) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		if (state->fsp == NULL) {
			tevent_req_nterror(req, NT_STATUS_INVALID_HANDLE);
			return tevent_req_post(req, ev);
		}

		subreq = smbd_fsctl_torture_async_sleep_send(
						req,
						ev,
						state->fsp,
						CVAL(state->in_input.data,0));
		if (subreq == NULL) {
			tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					smbd_fsctl_torture_async_sleep_done,
					req);
		return req;
        }

	default:
		goto not_supported;
	}

not_supported:
	if (IS_IPC(state->smbreq->conn)) {
		status = NT_STATUS_FS_DRIVER_REQUIRED;
	} else {
		status = NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	tevent_req_nterror(req, status);
	return tevent_req_post(req, ev);
}
