/* 
   Unix SMB/CIFS implementation.
   FS info functions
   Copyright (C) Stefan (metze) Metzmacher	2003
   Copyright (C) Jeremy Allison 2007
   Copyright (C) Andrew Bartlett 2011

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
#include "libsmb/libsmb.h"
#include "../lib/util/tevent_ntstatus.h"
#include "async_smb.h"
#include "trans2.h"
#include "auth_generic.h"
#include "auth/gensec/gensec.h"
#include "../libcli/smb/smbXcli_base.h"
#include "auth/credentials/credentials.h"
#include "../librpc/gen_ndr/ndr_security.h"

/****************************************************************************
 Get UNIX extensions version info.
****************************************************************************/

struct cli_unix_extensions_version_state {
	struct cli_state *cli;
	uint16_t setup[1];
	uint8_t param[2];
	uint16_t major, minor;
	uint32_t caplow, caphigh;
};

static void cli_unix_extensions_version_done(struct tevent_req *subreq);

struct tevent_req *cli_unix_extensions_version_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct cli_state *cli)
{
	struct tevent_req *req, *subreq;
	struct cli_unix_extensions_version_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_unix_extensions_version_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	SSVAL(state->setup, 0, TRANSACT2_QFSINFO);
	SSVAL(state->param, 0, SMB_QUERY_CIFS_UNIX_INFO);

	subreq = cli_trans_send(state, ev, cli, 0, SMBtrans2,
				NULL, 0, 0, 0,
				state->setup, 1, 0,
				state->param, 2, 0,
				NULL, 0, 560);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_unix_extensions_version_done, req);
	return req;
}

static void cli_unix_extensions_version_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_unix_extensions_version_state *state = tevent_req_data(
		req, struct cli_unix_extensions_version_state);
	uint8_t *data;
	uint32_t num_data;
	NTSTATUS status;

	status = cli_trans_recv(subreq, state, NULL, NULL, 0, NULL,
				NULL, 0, NULL, &data, 12, &num_data);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	state->major = SVAL(data, 0);
	state->minor = SVAL(data, 2);
	state->caplow = IVAL(data, 4);
	state->caphigh = IVAL(data, 8);
	TALLOC_FREE(data);
	tevent_req_done(req);
}

NTSTATUS cli_unix_extensions_version_recv(struct tevent_req *req,
					  uint16_t *pmajor, uint16_t *pminor,
					  uint32_t *pcaplow,
					  uint32_t *pcaphigh)
{
	struct cli_unix_extensions_version_state *state = tevent_req_data(
		req, struct cli_unix_extensions_version_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pmajor = state->major;
	*pminor = state->minor;
	*pcaplow = state->caplow;
	*pcaphigh = state->caphigh;
	state->cli->server_posix_capabilities = *pcaplow;
	return NT_STATUS_OK;
}

NTSTATUS cli_unix_extensions_version(struct cli_state *cli, uint16_t *pmajor,
				     uint16_t *pminor, uint32_t *pcaplow,
				     uint32_t *pcaphigh)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_unix_extensions_version_send(frame, ev, cli);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = cli_unix_extensions_version_recv(req, pmajor, pminor, pcaplow,
						  pcaphigh);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/****************************************************************************
 Set UNIX extensions capabilities.
****************************************************************************/

struct cli_set_unix_extensions_capabilities_state {
	struct cli_state *cli;
	uint16_t setup[1];
	uint8_t param[4];
	uint8_t data[12];
};

static void cli_set_unix_extensions_capabilities_done(
	struct tevent_req *subreq);

struct tevent_req *cli_set_unix_extensions_capabilities_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	uint16_t major, uint16_t minor, uint32_t caplow, uint32_t caphigh)
{
	struct tevent_req *req, *subreq;
	struct cli_set_unix_extensions_capabilities_state *state;

	req = tevent_req_create(
		mem_ctx, &state,
		struct cli_set_unix_extensions_capabilities_state);
	if (req == NULL) {
		return NULL;
	}

	state->cli = cli;
	SSVAL(state->setup+0, 0, TRANSACT2_SETFSINFO);

	SSVAL(state->param, 0, 0);
	SSVAL(state->param, 2, SMB_SET_CIFS_UNIX_INFO);

	SSVAL(state->data, 0, major);
	SSVAL(state->data, 2, minor);
	SIVAL(state->data, 4, caplow);
	SIVAL(state->data, 8, caphigh);

	subreq = cli_trans_send(state, ev, cli, 0, SMBtrans2,
				NULL, 0, 0, 0,
				state->setup, 1, 0,
				state->param, 4, 0,
				state->data, 12, 560);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(
		subreq, cli_set_unix_extensions_capabilities_done, req);
	return req;
}

static void cli_set_unix_extensions_capabilities_done(
	struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_set_unix_extensions_capabilities_state *state = tevent_req_data(
		req, struct cli_set_unix_extensions_capabilities_state);

	NTSTATUS status = cli_trans_recv(subreq, NULL, NULL, NULL, 0, NULL,
					 NULL, 0, NULL, NULL, 0, NULL);
	if (NT_STATUS_IS_OK(status)) {
		state->cli->requested_posix_capabilities = IVAL(state->data, 4);
	}
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_set_unix_extensions_capabilities_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_set_unix_extensions_capabilities(struct cli_state *cli,
					      uint16_t major, uint16_t minor,
					      uint32_t caplow, uint32_t caphigh)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_set_unix_extensions_capabilities_send(
		ev, ev, cli, major, minor, caplow, caphigh);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_set_unix_extensions_capabilities_recv(req);
fail:
	TALLOC_FREE(ev);
	return status;
}

struct cli_get_fs_attr_info_state {
	uint16_t setup[1];
	uint8_t param[2];
	uint32_t fs_attr;
};

static void cli_get_fs_attr_info_done(struct tevent_req *subreq);

struct tevent_req *cli_get_fs_attr_info_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct cli_state *cli)
{
	struct tevent_req *subreq, *req;
	struct cli_get_fs_attr_info_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_get_fs_attr_info_state);
	if (req == NULL) {
		return NULL;
	}
	SSVAL(state->setup+0, 0, TRANSACT2_QFSINFO);
	SSVAL(state->param+0, 0, SMB_QUERY_FS_ATTRIBUTE_INFO);

	subreq = cli_trans_send(state, ev, cli, 0, SMBtrans2,
				NULL, 0, 0, 0,
				state->setup, 1, 0,
				state->param, 2, 0,
				NULL, 0, 560);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_get_fs_attr_info_done, req);
	return req;
}

static void cli_get_fs_attr_info_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_get_fs_attr_info_state *state = tevent_req_data(
		req, struct cli_get_fs_attr_info_state);
	uint8_t *data;
	uint32_t num_data;
	NTSTATUS status;

	status = cli_trans_recv(subreq, talloc_tos(), NULL, NULL, 0, NULL,
				NULL, 0, NULL, &data, 12, &num_data);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	state->fs_attr = IVAL(data, 0);
	TALLOC_FREE(data);
	tevent_req_done(req);
}

NTSTATUS cli_get_fs_attr_info_recv(struct tevent_req *req, uint32_t *fs_attr)
{
	struct cli_get_fs_attr_info_state *state = tevent_req_data(
		req, struct cli_get_fs_attr_info_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*fs_attr = state->fs_attr;
	return NT_STATUS_OK;
}

NTSTATUS cli_get_fs_attr_info(struct cli_state *cli, uint32_t *fs_attr)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_get_fs_attr_info(cli, fs_attr);
	}

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_get_fs_attr_info_send(ev, ev, cli);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_get_fs_attr_info_recv(req, fs_attr);
fail:
	TALLOC_FREE(ev);
	return status;
}

NTSTATUS cli_get_fs_volume_info(struct cli_state *cli,
				TALLOC_CTX *mem_ctx,
				char **_volume_name,
				uint32_t *pserial_number,
				time_t *pdate)
{
	NTSTATUS status;
	uint16_t recv_flags2;
	uint16_t setup[1];
	uint8_t param[2];
	uint8_t *rdata;
	uint32_t rdata_count;
	unsigned int nlen;
	char *volume_name = NULL;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_get_fs_volume_info(cli,
						mem_ctx,
						_volume_name,
						pserial_number,
						pdate);
	}

	SSVAL(setup, 0, TRANSACT2_QFSINFO);
	SSVAL(param,0,SMB_QUERY_FS_VOLUME_INFO);

	status = cli_trans(talloc_tos(), cli, SMBtrans2,
			   NULL, 0, 0, 0,
			   setup, 1, 0,
			   param, 2, 0,
			   NULL, 0, 560,
			   &recv_flags2,
			   NULL, 0, NULL,
			   NULL, 0, NULL,
			   &rdata, 18, &rdata_count);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (pdate) {
		struct timespec ts;
		ts = interpret_long_date((char *)rdata);
		*pdate = ts.tv_sec;
	}
	if (pserial_number) {
		*pserial_number = IVAL(rdata,8);
	}
	nlen = IVAL(rdata,12);
	if (nlen > (rdata_count - 18)) {
		TALLOC_FREE(rdata);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	pull_string_talloc(mem_ctx,
			   (const char *)rdata,
			   recv_flags2,
			   &volume_name,
			   rdata + 18,
			   nlen, STR_UNICODE);
	if (volume_name == NULL) {
		status = map_nt_error_from_unix(errno);
		TALLOC_FREE(rdata);
		return status;
	}

	/* todo: but not yet needed
	 *       return the other stuff
	 */

	*_volume_name = volume_name;
	TALLOC_FREE(rdata);
	return NT_STATUS_OK;
}

NTSTATUS cli_get_fs_full_size_info(struct cli_state *cli,
				   uint64_t *total_allocation_units,
				   uint64_t *caller_allocation_units,
				   uint64_t *actual_allocation_units,
				   uint64_t *sectors_per_allocation_unit,
				   uint64_t *bytes_per_sector)
{
	uint16_t setup[1];
	uint8_t param[2];
	uint8_t *rdata = NULL;
	uint32_t rdata_count;
	NTSTATUS status;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_get_fs_full_size_info(cli,
						total_allocation_units,
						caller_allocation_units,
						actual_allocation_units,
						sectors_per_allocation_unit,
						bytes_per_sector);
	}

	SSVAL(setup, 0, TRANSACT2_QFSINFO);
	SSVAL(param, 0, SMB_FS_FULL_SIZE_INFORMATION);

	status = cli_trans(talloc_tos(), cli, SMBtrans2,
			   NULL, 0, 0, 0,
			   setup, 1, 0, /* setup */
			   param, 2, 0,	 /* param */
			   NULL, 0, 560, /* data */
			   NULL,
			   NULL, 0, NULL, /* rsetup */
			   NULL, 0, NULL, /* rparam */
			   &rdata, 32, &rdata_count);  /* rdata */
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	if (total_allocation_units) {
                *total_allocation_units = BIG_UINT(rdata, 0);
	}
	if (caller_allocation_units) {
		*caller_allocation_units = BIG_UINT(rdata,8);
	}
	if (actual_allocation_units) {
		*actual_allocation_units = BIG_UINT(rdata,16);
	}
	if (sectors_per_allocation_unit) {
		*sectors_per_allocation_unit = IVAL(rdata,24);
	}
	if (bytes_per_sector) {
		*bytes_per_sector = IVAL(rdata,28);
	}

fail:
	TALLOC_FREE(rdata);
	return status;
}

NTSTATUS cli_get_posix_fs_info(struct cli_state *cli,
			       uint32_t *optimal_transfer_size,
			       uint32_t *block_size,
			       uint64_t *total_blocks,
			       uint64_t *blocks_available,
			       uint64_t *user_blocks_available,
			       uint64_t *total_file_nodes,
			       uint64_t *free_file_nodes,
			       uint64_t *fs_identifier)
{
	uint16_t setup[1];
	uint8_t param[2];
	uint8_t *rdata = NULL;
	uint32_t rdata_count;
	NTSTATUS status;

	SSVAL(setup, 0, TRANSACT2_QFSINFO);
	SSVAL(param,0,SMB_QUERY_POSIX_FS_INFO);

	status = cli_trans(talloc_tos(), cli, SMBtrans2, NULL, 0, 0, 0,
			   setup, 1, 0,
			   param, 2, 0,
			   NULL, 0, 560,
			   NULL,
			   NULL, 0, NULL, /* rsetup */
			   NULL, 0, NULL, /* rparam */
			   &rdata, 56, &rdata_count);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (optimal_transfer_size) {
                *optimal_transfer_size = IVAL(rdata, 0);
	}
	if (block_size) {
		*block_size = IVAL(rdata,4);
	}
	if (total_blocks) {
		*total_blocks = BIG_UINT(rdata,8);
	}
	if (blocks_available) {
		*blocks_available = BIG_UINT(rdata,16);
	}
	if (user_blocks_available) {
		*user_blocks_available = BIG_UINT(rdata,24);
	}
	if (total_file_nodes) {
		*total_file_nodes = BIG_UINT(rdata,32);
	}
	if (free_file_nodes) {
		*free_file_nodes = BIG_UINT(rdata,40);
	}
	if (fs_identifier) {
		*fs_identifier = BIG_UINT(rdata,48);
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Do a UNIX extensions SMB_QUERY_POSIX_WHOAMI call.
****************************************************************************/

struct posix_whoami_state {
	uint16_t setup[1];
	uint8_t param[2];
	uint32_t max_rdata;
	bool guest;
	uint64_t uid;
	uint64_t gid;
	uint32_t num_gids;
	uint64_t *gids;
	uint32_t num_sids;
	struct dom_sid *sids;
};

static void cli_posix_whoami_done(struct tevent_req *subreq);

static const uint32_t posix_whoami_max_rdata = 62*1024;

struct tevent_req *cli_posix_whoami_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct posix_whoami_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct posix_whoami_state);
	if (req == NULL) {
		return NULL;
	}

	/* Setup setup word. */
	SSVAL(state->setup, 0, TRANSACT2_QFSINFO);
	SSVAL(state->param, 0, SMB_QUERY_POSIX_WHOAMI);

	state->max_rdata = posix_whoami_max_rdata;

	subreq = cli_trans_send(state,                  /* mem ctx. */
				ev,                     /* event ctx. */
				cli,                    /* cli_state. */
				0,			/* additional_flags2 */
				SMBtrans2,              /* cmd. */
				NULL,                   /* pipe name. */
				-1,                     /* fid. */
				0,                      /* function. */
				0,                      /* flags. */
				state->setup,           /* setup. */
				1,                      /* num setup uint16_t words. */
				0,                      /* max returned setup. */
				state->param,           /* param. */
				2,                      /* num param. */
				0,                      /* max returned param. */
				NULL,	                /* data. */
				0,                      /* num data. */
				state->max_rdata);      /* max returned data. */

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_posix_whoami_done, req);
	return req;
}

static void cli_posix_whoami_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct posix_whoami_state *state = tevent_req_data(
			req, struct posix_whoami_state);
	uint8_t *rdata = NULL;
	uint8_t *p = NULL;
	uint32_t num_rdata = 0;
	uint32_t i;
	NTSTATUS status;

	status = cli_trans_recv(subreq,
				state,
				NULL,
				NULL,
				0,
				NULL,
                                NULL,
				0,
				NULL,
				&rdata,
				40,
				&num_rdata);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * Not strictly needed - cli_trans_recv()
	 * will ensure at least 40 bytes here. Added
	 * as more of a reminder to be careful when
	 * parsing network packets in C.
	 */

	if (num_rdata < 40 || num_rdata > posix_whoami_max_rdata) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	state->guest = (IVAL(rdata, 0) & SMB_WHOAMI_GUEST);
	state->uid = BVAL(rdata, 8);
	state->gid = BVAL(rdata, 16);
	state->num_gids = IVAL(rdata, 24);
	state->num_sids = IVAL(rdata, 28);

	/* Ensure the gid array doesn't overflow */
	if (state->num_gids > (num_rdata - 40) / sizeof(uint64_t)) {
		tevent_req_nterror(req,
			NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	state->gids = talloc_array(state, uint64_t, state->num_gids);
	if (tevent_req_nomem(state->gids, req)) {
		return;
	}
	state->sids = talloc_array(state, struct dom_sid, state->num_sids);
	if (tevent_req_nomem(state->sids, req)) {
		return;
	}

	p = rdata + 40;

	for (i = 0; i < state->num_gids; i++) {
		state->gids[i] = BVAL(p, 0);
		p += 8;
	}

	num_rdata -= (p - rdata);

	for (i = 0; i < state->num_sids; i++) {
		size_t sid_size;
		DATA_BLOB in = data_blob_const(p, num_rdata);
		enum ndr_err_code ndr_err;

		ndr_err = ndr_pull_struct_blob(&in,
				state,
				&state->sids[i],
				(ndr_pull_flags_fn_t)ndr_pull_dom_sid);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			tevent_req_nterror(req,
				NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		sid_size = ndr_size_dom_sid(&state->sids[i], 0);

		if (sid_size > num_rdata) {
			tevent_req_nterror(req,
				NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		p += sid_size;
		num_rdata -= sid_size;
	}

	if (num_rdata != 0) {
		tevent_req_nterror(req,
			NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS cli_posix_whoami_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx,
			uint64_t *puid,
			uint64_t *pgid,
			uint32_t *pnum_gids,
			uint64_t **pgids,
			uint32_t *pnum_sids,
			struct dom_sid **psids,
			bool *pguest)
{
	NTSTATUS status;
	struct posix_whoami_state *state = tevent_req_data(
			req, struct posix_whoami_state);

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (puid) {
		*puid = state->uid;
	}
	if (pgid) {
		*pgid = state->gid;
	}
	if (pnum_gids) {
		*pnum_gids = state->num_gids;
	}
	if (pgids) {
		*pgids = talloc_move(mem_ctx, &state->gids);
	}
	if (pnum_sids) {
		*pnum_sids = state->num_sids;
	}
	if (psids) {
		*psids = talloc_move(mem_ctx, &state->sids);
	}
	if (pguest) {
		*pguest = state->guest;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_posix_whoami(struct cli_state *cli,
			TALLOC_CTX *mem_ctx,
			uint64_t *puid,
			uint64_t *pgid,
			uint32_t *num_gids,
			uint64_t **gids,
			uint32_t *num_sids,
			struct dom_sid **sids,
			bool *pguest)
{
        TALLOC_CTX *frame = talloc_stackframe();
        struct tevent_context *ev = NULL;
        struct tevent_req *req = NULL;
        NTSTATUS status = NT_STATUS_OK;

        if (smbXcli_conn_has_async_calls(cli->conn)) {
                /*
                 * Can't use sync call while an async call is in flight
                 */
                status = NT_STATUS_INVALID_PARAMETER;
                goto fail;
        }

        ev = samba_tevent_context_init(frame);
        if (ev == NULL) {
                status = NT_STATUS_NO_MEMORY;
                goto fail;
        }

        req = cli_posix_whoami_send(frame,
                                ev,
                                cli);
        if (req == NULL) {
                status = NT_STATUS_NO_MEMORY;
                goto fail;
        }

        if (!tevent_req_poll_ntstatus(req, ev, &status)) {
                goto fail;
        }

        status = cli_posix_whoami_recv(req,
			mem_ctx,
			puid,
			pgid,
			num_gids,
			gids,
			num_sids,
			sids,
			pguest);

 fail:
	TALLOC_FREE(frame);
	return status;
}
