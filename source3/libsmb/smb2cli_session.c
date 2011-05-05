/*
   Unix SMB/CIFS implementation.
   smb2 lib
   Copyright (C) Volker Lendecke 2011

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
#include "client.h"
#include "async_smb.h"
#include "smb2cli_base.h"
#include "smb2cli.h"
#include "libsmb/proto.h"
#include "lib/util/tevent_ntstatus.h"
#include "../libcli/auth/spnego.h"

struct smb2cli_sesssetup_blob_state {
	struct ntlmssp_state *ntlmssp;
	uint8_t fixed[24];
	uint64_t uid;
	DATA_BLOB out;
};

static void smb2cli_sesssetup_blob_done(struct tevent_req *subreq);

static struct tevent_req *smb2cli_sesssetup_blob_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct cli_state *cli,
						DATA_BLOB *blob)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_sesssetup_blob_state *state;
	uint8_t *buf;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_sesssetup_blob_state);
	if (req == NULL) {
		return NULL;
	}

	buf = state->fixed;

	SSVAL(buf, 0, 25);
	SCVAL(buf, 2, 0); /* VcNumber */
	SCVAL(buf, 3, 0); /* SecurityMode */
	SIVAL(buf, 4, 0); /* Capabilities */
	SIVAL(buf, 8, 0); /* Channel */
	SSVAL(buf, 12, SMB2_HDR_BODY + 24); /* SecurityBufferOffset */
	SSVAL(buf, 14, blob->length);
	SBVAL(buf, 16, 0); /* PreviousSessionId */

	subreq = smb2cli_req_send(state, ev, cli, SMB2_OP_SESSSETUP, 0,
				  state->fixed, sizeof(state->fixed),
				  blob->data, blob->length);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_sesssetup_blob_done, req);
	return req;
}

static void smb2cli_sesssetup_blob_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_sesssetup_blob_state *state =
		tevent_req_data(req,
		struct smb2cli_sesssetup_blob_state);
	NTSTATUS status;
	struct iovec *iov;
	uint16_t offset, length;

	status = smb2cli_req_recv(subreq, talloc_tos(), &iov, 9);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		TALLOC_FREE(subreq);
		tevent_req_nterror(req, status);
		return;
	}

	offset = SVAL(iov[1].iov_base, 4);
	length = SVAL(iov[1].iov_base, 6);

	if ((offset != SMB2_HDR_BODY + 8) || (length > iov[2].iov_len)) {
		TALLOC_FREE(subreq);
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}
	state->uid = BVAL(iov[0].iov_base, SMB2_HDR_SESSION_ID);
	state->out.data = (uint8_t *)iov[2].iov_base;
	state->out.length = length;
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS smb2cli_sesssetup_blob_recv(struct tevent_req *req,
					    uint64_t *uid, DATA_BLOB *out)
{
	struct smb2cli_sesssetup_blob_state *state =
		tevent_req_data(req,
		struct smb2cli_sesssetup_blob_state);
	NTSTATUS status = NT_STATUS_OK;

	if (tevent_req_is_nterror(req, &status)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return status;
	}
	*uid = state->uid;
	*out = state->out;
	return status;
}

struct smb2cli_sesssetup_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	struct ntlmssp_state *ntlmssp;
	struct iovec iov[2];
	uint8_t fixed[24];
	DATA_BLOB msg;
	int turn;
};

static void smb2cli_sesssetup_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_sesssetup_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct cli_state *cli,
					  const char *user,
					  const char *domain,
					  const char *pass)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_sesssetup_state *state;
	NTSTATUS status;
	DATA_BLOB blob_out;
	const char *OIDs_ntlm[] = {OID_NTLMSSP, NULL};

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_sesssetup_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	status = ntlmssp_client_start(state,
				      lp_netbios_name(),
				      lp_workgroup(),
				      lp_client_ntlmv2_auth(),
				      &state->ntlmssp);
	if (!NT_STATUS_IS_OK(status)) {
		goto post_status;
	}
	status = ntlmssp_set_username(state->ntlmssp, user);
	if (!NT_STATUS_IS_OK(status)) {
		goto post_status;
	}
	status = ntlmssp_set_domain(state->ntlmssp, domain);
	if (!NT_STATUS_IS_OK(status)) {
		goto post_status;
	}
	status = ntlmssp_set_password(state->ntlmssp, pass);
	if (!NT_STATUS_IS_OK(status)) {
		goto post_status;
	}

	status = ntlmssp_update(state->ntlmssp, data_blob_null, &blob_out);
	if (!NT_STATUS_IS_OK(status)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto post_status;
	}

	blob_out = spnego_gen_negTokenInit(state, OIDs_ntlm, &blob_out, NULL);
	state->turn = 1;

	subreq = smb2cli_sesssetup_blob_send(
		state, state->ev, state->cli, &blob_out);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_sesssetup_done, req);
	return req;
post_status:
	tevent_req_nterror(req, status);
	return tevent_req_post(req, ev);
}

static void smb2cli_sesssetup_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_sesssetup_state *state =
		tevent_req_data(req,
		struct smb2cli_sesssetup_state);
	NTSTATUS status;
	uint64_t uid = 0;
	DATA_BLOB blob, blob_in, blob_out, spnego_blob;
	bool ret;

	status = smb2cli_sesssetup_blob_recv(subreq, &uid, &blob);
	if (!NT_STATUS_IS_OK(status)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		TALLOC_FREE(subreq);
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(subreq);
		tevent_req_done(req);
		return;
	}

	if (state->turn == 1) {
		DATA_BLOB tmp_blob = data_blob_null;
		ret = spnego_parse_challenge(state, blob, &blob_in, &tmp_blob);
		data_blob_free(&tmp_blob);
	} else {
		ret = spnego_parse_auth_response(state, blob, status,
						 OID_NTLMSSP, &blob_in);
	}
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	status = ntlmssp_update(state->ntlmssp, blob_in, &blob_out);
	data_blob_free(&blob_in);
	state->turn += 1;

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	state->cli->smb2.uid = uid;

	spnego_blob = spnego_gen_auth(state, blob_out);
	TALLOC_FREE(subreq);
	if (tevent_req_nomem(spnego_blob.data, req)) {
		return;
	}

	subreq = smb2cli_sesssetup_blob_send(
		state, state->ev, state->cli, &spnego_blob);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smb2cli_sesssetup_done, req);
}

NTSTATUS smb2cli_sesssetup_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb2cli_sesssetup(struct cli_state *cli, const char *user,
			   const char *domain, const char *pass)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = event_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_sesssetup_send(frame, ev, cli, user, domain, pass);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_sesssetup_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct smb2cli_logoff_state {
	uint8_t fixed[4];
};

static void smb2cli_logoff_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_logoff_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct cli_state *cli)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_logoff_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_logoff_state);
	if (req == NULL) {
		return NULL;
	}
	SSVAL(state->fixed, 0, 4);

	subreq = smb2cli_req_send(state, ev, cli, SMB2_OP_LOGOFF, 0,
				  state->fixed, sizeof(state->fixed),
				  NULL, 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_logoff_done, req);
	return req;
}

static void smb2cli_logoff_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	NTSTATUS status;
	struct iovec *iov;

	status = smb2cli_req_recv(subreq, talloc_tos(), &iov, 4);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS smb2cli_logoff_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb2cli_logoff(struct cli_state *cli)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = event_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_logoff_send(frame, ev, cli);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_logoff_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}
