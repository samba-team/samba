/*
   Unix SMB/CIFS implementation.
   client security descriptor functions
   Copyright (C) Andrew Tridgell 2000

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
#include "source3/include/client.h"
#include "source3/libsmb/proto.h"
#include "source3/libsmb/cli_smb2_fnum.h"
#include "../libcli/security/secdesc.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/util/tevent_ntstatus.h"

struct cli_query_security_descriptor_state {
	uint8_t param[8];
	DATA_BLOB outbuf;
};

static void cli_query_security_descriptor_done1(struct tevent_req *subreq);
static void cli_query_security_descriptor_done2(struct tevent_req *subreq);

struct tevent_req *cli_query_security_descriptor_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint32_t sec_info)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_query_security_descriptor_state *state = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct cli_query_security_descriptor_state);
	if (req == NULL) {
		return NULL;
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		subreq = cli_smb2_query_info_fnum_send(
			state,		      /* mem_ctx */
			ev,		      /* ev */
			cli,		      /* cli */
			fnum,		      /* fnum */
			SMB2_0_INFO_SECURITY, /* in_info_type */
			0,		      /* in_info_class */
			0xFFFF,		      /* in_max_output_length */
			NULL,		      /* in_input_buffer */
			sec_info,	      /* in_additional_info */
			0);		      /* in_flags */
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, cli_query_security_descriptor_done2, req);
		return req;
	}

	PUSH_LE_U32(state->param, 0, fnum);
	PUSH_LE_U32(state->param, 4, sec_info);

	subreq = cli_trans_send(
		state, 		/* mem_ctx */
		ev,		/* ev */
		cli, 		/* cli */
		0,		/* additional_flags2 */
		SMBnttrans,	/* cmd */
		NULL,		/* pipe_name */
		-1,		/* fid */
		NT_TRANSACT_QUERY_SECURITY_DESC, /* function */
		0,		/* flags */
		NULL,		/* setup */
		0,		/* num_setup */
		0,		/* max_setup */
		state->param,	/* param */
		8,		/* num_param */
		4,		/* max_param */
		NULL,		/* data */
		0,		/* num_data */
		0x10000);	/* max_data */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(
		subreq, cli_query_security_descriptor_done1, req);
	return req;
}

static void cli_query_security_descriptor_done1(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_query_security_descriptor_state *state = tevent_req_data(
		req, struct cli_query_security_descriptor_state);
	NTSTATUS status;
	uint32_t len;

	status = cli_trans_recv(
		subreq,		/* req */
		state,		/* mem_ctx */
		NULL,		/* recv_flags2 */
		NULL,		/* setup */
		0,		/* min_setup */
		NULL,		/* num_setup */
		NULL,		/* param */
		0,		/* min_param */
		NULL,		/* num_param */
		&state->outbuf.data, /* data */
		0,		/* min_data */
		&len);		/* num_data */
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	state->outbuf.length = len; /* uint32_t -> size_t */
	tevent_req_done(req);
}

static void cli_query_security_descriptor_done2(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_query_security_descriptor_state *state = tevent_req_data(
		req, struct cli_query_security_descriptor_state);
	NTSTATUS status;

	status = cli_smb2_query_info_fnum_recv(subreq, state, &state->outbuf);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_query_security_descriptor_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct security_descriptor **sd)
{
	struct cli_query_security_descriptor_state *state = tevent_req_data(
		req, struct cli_query_security_descriptor_state);
	NTSTATUS status = NT_STATUS_OK;

	if (tevent_req_is_nterror(req, &status)) {
		goto done;
	}
	if (sd != NULL) {
		status = unmarshall_sec_desc(
			mem_ctx, state->outbuf.data, state->outbuf.length, sd);
	}
done:
	tevent_req_received(req);
	return status;
}

NTSTATUS cli_query_security_descriptor(struct cli_state *cli,
				       uint16_t fnum,
				       uint32_t sec_info,
				       TALLOC_CTX *mem_ctx,
				       struct security_descriptor **sd)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_query_security_descriptor_send(
		frame, ev, cli, fnum, sec_info);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_query_security_descriptor_recv(req, mem_ctx, sd);
 fail:
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS cli_query_secdesc(struct cli_state *cli, uint16_t fnum,
			   TALLOC_CTX *mem_ctx, struct security_descriptor **sd)
{
	uint32_t sec_info = SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL;

	return cli_query_security_descriptor(cli, fnum, sec_info, mem_ctx, sd);
}

NTSTATUS cli_query_mxac(struct cli_state *cli,
			const char *filename,
			uint32_t *mxac)
{
	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	return cli_smb2_query_mxac(cli, filename, mxac);
}

struct cli_set_security_descriptor_state {
	uint8_t param[8];
	DATA_BLOB buf;
};

static void cli_set_security_descriptor_done1(struct tevent_req *subreq);
static void cli_set_security_descriptor_done2(struct tevent_req *subreq);

struct tevent_req *cli_set_security_descriptor_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint32_t sec_info,
	const struct security_descriptor *sd)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_set_security_descriptor_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(
		mem_ctx, &state, struct cli_set_security_descriptor_state);
	if (req == NULL) {
		return NULL;
	}

	status = marshall_sec_desc(
		state, sd, &state->buf.data, &state->buf.length);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		subreq = cli_smb2_set_info_fnum_send(
			state,		      /* mem_ctx */
			ev,		      /* ev */
			cli,		      /* cli */
			fnum,		      /* fnum */
			SMB2_0_INFO_SECURITY, /* in_info_type */
			0,		      /* in_file_info_class */
			&state->buf,	      /* in_input_buffer */
			sec_info);	      /* in_additional_info */
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq,	cli_set_security_descriptor_done2, req);
		return req;
	}

	SIVAL(state->param, 0, fnum);
	SIVAL(state->param, 4, sec_info);

	subreq = cli_trans_send(
		state, 		/* mem_ctx */
		ev,		/* ev */
		cli, 		/* cli */
		0,		/* additional_flags2 */
		SMBnttrans,	/* cmd */
		NULL,		/* pipe_name */
		-1,		/* fid */
		NT_TRANSACT_SET_SECURITY_DESC, /* function */
		0,		/* flags */
		NULL,		/* setup */
		0,		/* num_setup */
		0,		/* max_setup */
		state->param,	/* param */
		8,		/* num_param */
		0,		/* max_param */
		state->buf.data, /* data */
		state->buf.length, /* num_data */
		0);		/* max_data */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(
		subreq, cli_set_security_descriptor_done1, req);
	return req;
}

static void cli_set_security_descriptor_done1(struct tevent_req *subreq)
{
	NTSTATUS status = cli_trans_recv(
		subreq,	NULL, NULL, NULL, 0, NULL, NULL, 0, NULL,
		NULL, 0, NULL);
	return tevent_req_simple_finish_ntstatus(subreq, status);
}

static void cli_set_security_descriptor_done2(struct tevent_req *subreq)
{
	NTSTATUS status = cli_smb2_set_info_fnum_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_set_security_descriptor_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/****************************************************************************
  set the security descriptor for a open file
 ****************************************************************************/
NTSTATUS cli_set_security_descriptor(struct cli_state *cli,
				     uint16_t fnum,
				     uint32_t sec_info,
				     const struct security_descriptor *sd)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_set_security_descriptor_send(
		frame, ev, cli, fnum, sec_info, sd);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_set_security_descriptor_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS cli_set_secdesc(struct cli_state *cli, uint16_t fnum,
			 const struct security_descriptor *sd)
{
	uint32_t sec_info = 0;

	if (sd->dacl || (sd->type & SEC_DESC_DACL_PRESENT)) {
		sec_info |= SECINFO_DACL;
	}
	if (sd->sacl || (sd->type & SEC_DESC_SACL_PRESENT)) {
		sec_info |= SECINFO_SACL;
	}
	if (sd->owner_sid) {
		sec_info |= SECINFO_OWNER;
	}
	if (sd->group_sid) {
		sec_info |= SECINFO_GROUP;
	}

	return cli_set_security_descriptor(cli, fnum, sec_info, sd);
}
