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
