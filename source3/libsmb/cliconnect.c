/* 
   Unix SMB/CIFS implementation.
   client connect/disconnect routines
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Andrew Bartlett 2001-2003
   Copyright (C) Volker Lendecke 2011
   Copyright (C) Jeremy Allison 2011

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
#include "auth_info.h"
#include "../libcli/auth/libcli_auth.h"
#include "../libcli/auth/spnego.h"
#include "smb_krb5.h"
#include "../auth/ntlmssp/ntlmssp.h"
#include "libads/kerberos_proto.h"
#include "krb5_env.h"
#include "../lib/util/tevent_ntstatus.h"
#include "async_smb.h"
#include "libsmb/nmblib.h"
#include "librpc/ndr/libndr.h"
#include "../libcli/smb/smbXcli_base.h"
#include "smb2cli.h"

#define STAR_SMBSERVER "*SMBSERVER"

/********************************************************
 Utility function to ensure we always return at least
 a valid char * pointer to an empty string for the
 cli->server_os, cli->server_type and cli->server_domain
 strings.
*******************************************************/

static NTSTATUS smb_bytes_talloc_string(TALLOC_CTX *mem_ctx,
					const uint8_t *hdr,
					char **dest,
					uint8_t *src,
					size_t srclen,
					ssize_t *destlen)
{
	*destlen = clistr_pull_talloc(mem_ctx,
				(const char *)hdr,
				SVAL(hdr, HDR_FLG2),
				dest,
				(char *)src,
				srclen,
				STR_TERMINATE);
	if (*destlen == -1) {
		return NT_STATUS_NO_MEMORY;
	}

	if (*dest == NULL) {
		*dest = talloc_strdup(mem_ctx, "");
		if (*dest == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Do an old lanman2 style session setup.
****************************************************************************/

struct cli_session_setup_lanman2_state {
	struct cli_state *cli;
	uint16_t vwv[10];
	const char *user;
};

static void cli_session_setup_lanman2_done(struct tevent_req *subreq);

static struct tevent_req *cli_session_setup_lanman2_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct cli_state *cli, const char *user,
	const char *pass, size_t passlen,
	const char *workgroup)
{
	struct tevent_req *req, *subreq;
	struct cli_session_setup_lanman2_state *state;
	DATA_BLOB lm_response = data_blob_null;
	uint16_t *vwv;
	uint8_t *bytes;
	char *tmp;
	uint16_t sec_mode = smb1cli_conn_server_security_mode(cli->conn);

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_lanman2_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->user = user;
	vwv = state->vwv;

	/*
	 * if in share level security then don't send a password now
	 */
	if (!(sec_mode & NEGOTIATE_SECURITY_USER_LEVEL)) {
		passlen = 0;
	}

	if (passlen > 0
	    && (sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE)
	    && passlen != 24) {
		/*
		 * Encrypted mode needed, and non encrypted password
		 * supplied.
		 */
		lm_response = data_blob(NULL, 24);
		if (tevent_req_nomem(lm_response.data, req)) {
			return tevent_req_post(req, ev);
		}

		if (!SMBencrypt(pass, smb1cli_conn_server_challenge(cli->conn),
				(uint8_t *)lm_response.data)) {
			DEBUG(1, ("Password is > 14 chars in length, and is "
				  "therefore incompatible with Lanman "
				  "authentication\n"));
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}
	} else if ((sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE)
		   && passlen == 24) {
		/*
		 * Encrypted mode needed, and encrypted password
		 * supplied.
		 */
		lm_response = data_blob(pass, passlen);
		if (tevent_req_nomem(lm_response.data, req)) {
			return tevent_req_post(req, ev);
		}
	} else if (passlen > 0) {
		uint8_t *buf;
		size_t converted_size;
		/*
		 * Plaintext mode needed, assume plaintext supplied.
		 */
		buf = talloc_array(talloc_tos(), uint8_t, 0);
		buf = smb_bytes_push_str(buf, smbXcli_conn_use_unicode(cli->conn), pass, passlen+1,
					 &converted_size);
		if (tevent_req_nomem(buf, req)) {
			return tevent_req_post(req, ev);
		}
		lm_response = data_blob(pass, passlen);
		TALLOC_FREE(buf);
		if (tevent_req_nomem(lm_response.data, req)) {
			return tevent_req_post(req, ev);
		}
	}

	SCVAL(vwv+0, 0, 0xff);
	SCVAL(vwv+0, 1, 0);
	SSVAL(vwv+1, 0, 0);
	SSVAL(vwv+2, 0, CLI_BUFFER_SIZE);
	SSVAL(vwv+3, 0, 2);
	SSVAL(vwv+4, 0, 1);
	SIVAL(vwv+5, 0, smb1cli_conn_server_session_key(cli->conn));
	SSVAL(vwv+7, 0, lm_response.length);

	bytes = talloc_array(state, uint8_t, lm_response.length);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	if (lm_response.length != 0) {
		memcpy(bytes, lm_response.data, lm_response.length);
	}
	data_blob_free(&lm_response);

	tmp = talloc_strdup_upper(talloc_tos(), user);
	if (tevent_req_nomem(tmp, req)) {
		return tevent_req_post(req, ev);
	}
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), tmp, strlen(tmp)+1,
				   NULL);
	TALLOC_FREE(tmp);

	tmp = talloc_strdup_upper(talloc_tos(), workgroup);
	if (tevent_req_nomem(tmp, req)) {
		return tevent_req_post(req, ev);
	}
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), tmp, strlen(tmp)+1,
				   NULL);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), "Unix", 5, NULL);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), "Samba", 6, NULL);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBsesssetupX, 0, 10, vwv,
			      talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_session_setup_lanman2_done, req);
	return req;
}

static void cli_session_setup_lanman2_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_setup_lanman2_state *state = tevent_req_data(
		req, struct cli_session_setup_lanman2_state);
	struct cli_state *cli = state->cli;
	uint32_t num_bytes;
	uint8_t *in;
	uint8_t *inhdr;
	uint8_t *bytes;
	uint8_t *p;
	NTSTATUS status;
	ssize_t ret;
	uint8_t wct;
	uint16_t *vwv;

	status = cli_smb_recv(subreq, state, &in, 3, &wct, &vwv,
			      &num_bytes, &bytes);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	inhdr = in + NBT_HDR_SIZE;
	p = bytes;

	cli_state_set_uid(state->cli, SVAL(inhdr, HDR_UID));
	cli->is_guestlogin = ((SVAL(vwv+2, 0) & 1) != 0);

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_os,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_type,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_domain,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = cli_set_username(cli, state->user);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS cli_session_setup_lanman2_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS cli_session_setup_lanman2(struct cli_state *cli, const char *user,
					  const char *pass, size_t passlen,
					  const char *workgroup)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
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
	req = cli_session_setup_lanman2_send(frame, ev, cli, user, pass, passlen,
					     workgroup);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_session_setup_lanman2_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/****************************************************************************
 Work out suitable capabilities to offer the server.
****************************************************************************/

static uint32_t cli_session_setup_capabilities(struct cli_state *cli,
					       uint32_t sesssetup_capabilities)
{
	uint32_t client_capabilities = smb1cli_conn_capabilities(cli->conn);

	/*
	 * We only send capabilities based on the mask for:
	 * - client only flags
	 * - flags used in both directions
	 *
	 * We do not echo the server only flags, except some legacy flags.
	 *
	 * SMB_CAP_LEGACY_CLIENT_MASK contains CAP_LARGE_READX and
	 * CAP_LARGE_WRITEX in order to allow us to do large reads
	 * against old Samba releases (<= 3.6.x).
	 */
	client_capabilities &= (SMB_CAP_BOTH_MASK | SMB_CAP_LEGACY_CLIENT_MASK);

	/*
	 * Session Setup specific flags CAP_DYNAMIC_REAUTH
	 * and CAP_EXTENDED_SECURITY are passed by the caller.
	 * We need that in order to do guest logins even if
	 * CAP_EXTENDED_SECURITY is negotiated.
	 */
	client_capabilities &= ~(CAP_DYNAMIC_REAUTH|CAP_EXTENDED_SECURITY);
	sesssetup_capabilities &= (CAP_DYNAMIC_REAUTH|CAP_EXTENDED_SECURITY);
	client_capabilities |= sesssetup_capabilities;

	return client_capabilities;
}

/****************************************************************************
 Do a NT1 guest session setup.
****************************************************************************/

struct cli_session_setup_guest_state {
	struct cli_state *cli;
	uint16_t vwv[13];
	struct iovec bytes;
};

static void cli_session_setup_guest_done(struct tevent_req *subreq);

struct tevent_req *cli_session_setup_guest_create(TALLOC_CTX *mem_ctx,
						  struct event_context *ev,
						  struct cli_state *cli,
						  struct tevent_req **psmbreq)
{
	struct tevent_req *req, *subreq;
	struct cli_session_setup_guest_state *state;
	uint16_t *vwv;
	uint8_t *bytes;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_guest_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	vwv = state->vwv;

	SCVAL(vwv+0, 0, 0xFF);
	SCVAL(vwv+0, 1, 0);
	SSVAL(vwv+1, 0, 0);
	SSVAL(vwv+2, 0, CLI_BUFFER_SIZE);
	SSVAL(vwv+3, 0, 2);
	SSVAL(vwv+4, 0, cli_state_get_vc_num(cli));
	SIVAL(vwv+5, 0, smb1cli_conn_server_session_key(cli->conn));
	SSVAL(vwv+7, 0, 0);
	SSVAL(vwv+8, 0, 0);
	SSVAL(vwv+9, 0, 0);
	SSVAL(vwv+10, 0, 0);
	SIVAL(vwv+11, 0, cli_session_setup_capabilities(cli, 0));

	bytes = talloc_array(state, uint8_t, 0);

	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), "",  1, /* username */
				   NULL);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), "", 1, /* workgroup */
				   NULL);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), "Unix", 5, NULL);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), "Samba", 6, NULL);

	if (bytes == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}

	state->bytes.iov_base = (void *)bytes;
	state->bytes.iov_len = talloc_get_size(bytes);

	subreq = cli_smb_req_create(state, ev, cli, SMBsesssetupX, 0, 13, vwv,
				    1, &state->bytes);
	if (subreq == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}
	tevent_req_set_callback(subreq, cli_session_setup_guest_done, req);
	*psmbreq = subreq;
	return req;
}

struct tevent_req *cli_session_setup_guest_send(TALLOC_CTX *mem_ctx,
						struct event_context *ev,
						struct cli_state *cli)
{
	struct tevent_req *req, *subreq;
	NTSTATUS status;

	req = cli_session_setup_guest_create(mem_ctx, ev, cli, &subreq);
	if (req == NULL) {
		return NULL;
	}

	status = smb1cli_req_chain_submit(&subreq, 1);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}
	return req;
}

static void cli_session_setup_guest_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_setup_guest_state *state = tevent_req_data(
		req, struct cli_session_setup_guest_state);
	struct cli_state *cli = state->cli;
	uint32_t num_bytes;
	uint8_t *in;
	uint8_t *inhdr;
	uint8_t *bytes;
	uint8_t *p;
	NTSTATUS status;
	ssize_t ret;
	uint8_t wct;
	uint16_t *vwv;

	status = cli_smb_recv(subreq, state, &in, 3, &wct, &vwv,
			      &num_bytes, &bytes);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	inhdr = in + NBT_HDR_SIZE;
	p = bytes;

	cli_state_set_uid(state->cli, SVAL(inhdr, HDR_UID));
	cli->is_guestlogin = ((SVAL(vwv+2, 0) & 1) != 0);

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_os,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_type,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_domain,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = cli_set_username(cli, "");
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_session_setup_guest_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS cli_session_setup_guest(struct cli_state *cli)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_session_setup_guest_send(frame, ev, cli);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_session_setup_guest_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/****************************************************************************
 Do a NT1 plaintext session setup.
****************************************************************************/

struct cli_session_setup_plain_state {
	struct cli_state *cli;
	uint16_t vwv[13];
	const char *user;
};

static void cli_session_setup_plain_done(struct tevent_req *subreq);

static struct tevent_req *cli_session_setup_plain_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct cli_state *cli,
	const char *user, const char *pass, const char *workgroup)
{
	struct tevent_req *req, *subreq;
	struct cli_session_setup_plain_state *state;
	uint16_t *vwv;
	uint8_t *bytes;
	size_t passlen;
	char *version;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_plain_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->user = user;
	vwv = state->vwv;

	SCVAL(vwv+0, 0, 0xff);
	SCVAL(vwv+0, 1, 0);
	SSVAL(vwv+1, 0, 0);
	SSVAL(vwv+2, 0, CLI_BUFFER_SIZE);
	SSVAL(vwv+3, 0, 2);
	SSVAL(vwv+4, 0, cli_state_get_vc_num(cli));
	SIVAL(vwv+5, 0, smb1cli_conn_server_session_key(cli->conn));
	SSVAL(vwv+7, 0, 0);
	SSVAL(vwv+8, 0, 0);
	SSVAL(vwv+9, 0, 0);
	SSVAL(vwv+10, 0, 0);
	SIVAL(vwv+11, 0, cli_session_setup_capabilities(cli, 0));

	bytes = talloc_array(state, uint8_t, 0);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), pass, strlen(pass)+1,
				   &passlen);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	SSVAL(vwv + (smbXcli_conn_use_unicode(cli->conn) ? 8 : 7), 0, passlen);

	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   user, strlen(user)+1, NULL);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   workgroup, strlen(workgroup)+1, NULL);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   "Unix", 5, NULL);

	version = talloc_asprintf(talloc_tos(), "Samba %s",
				  samba_version_string());
	if (tevent_req_nomem(version, req)){
		return tevent_req_post(req, ev);
	}
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   version, strlen(version)+1, NULL);
	TALLOC_FREE(version);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBsesssetupX, 0, 13, vwv,
			      talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_session_setup_plain_done, req);
	return req;
}

static void cli_session_setup_plain_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_setup_plain_state *state = tevent_req_data(
		req, struct cli_session_setup_plain_state);
	struct cli_state *cli = state->cli;
	uint32_t num_bytes;
	uint8_t *in;
	uint8_t *inhdr;
	uint8_t *bytes;
	uint8_t *p;
	NTSTATUS status;
	ssize_t ret;
	uint8_t wct;
	uint16_t *vwv;

	status = cli_smb_recv(subreq, state, &in, 3, &wct, &vwv,
			      &num_bytes, &bytes);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	inhdr = in + NBT_HDR_SIZE;
	p = bytes;

	cli_state_set_uid(state->cli, SVAL(inhdr, HDR_UID));
	cli->is_guestlogin = ((SVAL(vwv+2, 0) & 1) != 0);

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_os,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_type,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_domain,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = cli_set_username(cli, state->user);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS cli_session_setup_plain_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS cli_session_setup_plain(struct cli_state *cli,
					const char *user, const char *pass,
					const char *workgroup)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
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
	req = cli_session_setup_plain_send(frame, ev, cli, user, pass,
					   workgroup);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_session_setup_plain_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/****************************************************************************
   do a NT1 NTLM/LM encrypted session setup - for when extended security
   is not negotiated.
   @param cli client state to create do session setup on
   @param user username
   @param pass *either* cleartext password (passlen !=24) or LM response.
   @param ntpass NT response, implies ntpasslen >=24, implies pass is not clear
   @param workgroup The user's domain.
****************************************************************************/

struct cli_session_setup_nt1_state {
	struct cli_state *cli;
	uint16_t vwv[13];
	DATA_BLOB response;
	DATA_BLOB session_key;
	const char *user;
};

static void cli_session_setup_nt1_done(struct tevent_req *subreq);

static struct tevent_req *cli_session_setup_nt1_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct cli_state *cli, const char *user,
	const char *pass, size_t passlen,
	const char *ntpass, size_t ntpasslen,
	const char *workgroup)
{
	struct tevent_req *req, *subreq;
	struct cli_session_setup_nt1_state *state;
	DATA_BLOB lm_response = data_blob_null;
	DATA_BLOB nt_response = data_blob_null;
	DATA_BLOB session_key = data_blob_null;
	uint16_t *vwv;
	uint8_t *bytes;
	char *workgroup_upper;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_nt1_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->user = user;
	vwv = state->vwv;

	if (passlen == 0) {
		/* do nothing - guest login */
	} else if (passlen != 24) {
		if (lp_client_ntlmv2_auth()) {
			DATA_BLOB server_chal;
			DATA_BLOB names_blob;

			server_chal =
				data_blob_const(smb1cli_conn_server_challenge(cli->conn),
						8);

			/*
			 * note that the 'workgroup' here is a best
			 * guess - we don't know the server's domain
			 * at this point. Windows clients also don't
			 * use hostname...
			 */
			names_blob = NTLMv2_generate_names_blob(
				NULL, NULL, workgroup);

			if (tevent_req_nomem(names_blob.data, req)) {
				return tevent_req_post(req, ev);
			}

			if (!SMBNTLMv2encrypt(NULL, user, workgroup, pass,
					      &server_chal, &names_blob,
					      &lm_response, &nt_response,
					      NULL, &session_key)) {
				data_blob_free(&names_blob);
				tevent_req_nterror(
					req, NT_STATUS_ACCESS_DENIED);
				return tevent_req_post(req, ev);
			}
			data_blob_free(&names_blob);

		} else {
			uchar nt_hash[16];
			E_md4hash(pass, nt_hash);

#ifdef LANMAN_ONLY
			nt_response = data_blob_null;
#else
			nt_response = data_blob(NULL, 24);
			if (tevent_req_nomem(nt_response.data, req)) {
				return tevent_req_post(req, ev);
			}

			SMBNTencrypt(pass, smb1cli_conn_server_challenge(cli->conn),
				     nt_response.data);
#endif
			/* non encrypted password supplied. Ignore ntpass. */
			if (lp_client_lanman_auth()) {

				lm_response = data_blob(NULL, 24);
				if (tevent_req_nomem(lm_response.data, req)) {
					return tevent_req_post(req, ev);
				}

				if (!SMBencrypt(pass,
						smb1cli_conn_server_challenge(cli->conn),
						lm_response.data)) {
					/*
					 * Oops, the LM response is
					 * invalid, just put the NT
					 * response there instead
					 */
					data_blob_free(&lm_response);
					lm_response = data_blob(
						nt_response.data,
						nt_response.length);
				}
			} else {
				/*
				 * LM disabled, place NT# in LM field
				 * instead
				 */
				lm_response = data_blob(
					nt_response.data, nt_response.length);
			}

			if (tevent_req_nomem(lm_response.data, req)) {
				return tevent_req_post(req, ev);
			}

			session_key = data_blob(NULL, 16);
			if (tevent_req_nomem(session_key.data, req)) {
				return tevent_req_post(req, ev);
			}
#ifdef LANMAN_ONLY
			E_deshash(pass, session_key.data);
			memset(&session_key.data[8], '\0', 8);
#else
			SMBsesskeygen_ntv1(nt_hash, session_key.data);
#endif
		}
	} else {
		/* pre-encrypted password supplied.  Only used for 
		   security=server, can't do
		   signing because we don't have original key */

		lm_response = data_blob(pass, passlen);
		if (tevent_req_nomem(lm_response.data, req)) {
			return tevent_req_post(req, ev);
		}

		nt_response = data_blob(ntpass, ntpasslen);
		if (tevent_req_nomem(nt_response.data, req)) {
			return tevent_req_post(req, ev);
		}
	}

#ifdef LANMAN_ONLY
	state->response = data_blob_talloc(
		state, lm_response.data, lm_response.length);
#else
	state->response = data_blob_talloc(
		state, nt_response.data, nt_response.length);
#endif
	if (tevent_req_nomem(state->response.data, req)) {
		return tevent_req_post(req, ev);
	}

	if (session_key.data) {
		state->session_key = data_blob_talloc(
			state, session_key.data, session_key.length);
		if (tevent_req_nomem(state->session_key.data, req)) {
			return tevent_req_post(req, ev);
		}
	}
	data_blob_free(&session_key);

	SCVAL(vwv+0, 0, 0xff);
	SCVAL(vwv+0, 1, 0);
	SSVAL(vwv+1, 0, 0);
	SSVAL(vwv+2, 0, CLI_BUFFER_SIZE);
	SSVAL(vwv+3, 0, 2);
	SSVAL(vwv+4, 0, cli_state_get_vc_num(cli));
	SIVAL(vwv+5, 0, smb1cli_conn_server_session_key(cli->conn));
	SSVAL(vwv+7, 0, lm_response.length);
	SSVAL(vwv+8, 0, nt_response.length);
	SSVAL(vwv+9, 0, 0);
	SSVAL(vwv+10, 0, 0);
	SIVAL(vwv+11, 0, cli_session_setup_capabilities(cli, 0));

	bytes = talloc_array(state, uint8_t,
			     lm_response.length + nt_response.length);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	if (lm_response.length != 0) {
		memcpy(bytes, lm_response.data, lm_response.length);
	}
	if (nt_response.length != 0) {
		memcpy(bytes + lm_response.length,
		       nt_response.data, nt_response.length);
	}
	data_blob_free(&lm_response);
	data_blob_free(&nt_response);

	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   user, strlen(user)+1, NULL);

	/*
	 * Upper case here might help some NTLMv2 implementations
	 */
	workgroup_upper = talloc_strdup_upper(talloc_tos(), workgroup);
	if (tevent_req_nomem(workgroup_upper, req)) {
		return tevent_req_post(req, ev);
	}
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   workgroup_upper, strlen(workgroup_upper)+1,
				   NULL);
	TALLOC_FREE(workgroup_upper);

	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), "Unix", 5, NULL);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), "Samba", 6, NULL);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBsesssetupX, 0, 13, vwv,
			      talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_session_setup_nt1_done, req);
	return req;
}

static void cli_session_setup_nt1_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_setup_nt1_state *state = tevent_req_data(
		req, struct cli_session_setup_nt1_state);
	struct cli_state *cli = state->cli;
	uint32_t num_bytes;
	uint8_t *in;
	uint8_t *inhdr;
	uint8_t *bytes;
	uint8_t *p;
	NTSTATUS status;
	ssize_t ret;
	uint8_t wct;
	uint16_t *vwv;

	status = cli_smb_recv(subreq, state, &in, 3, &wct, &vwv,
			      &num_bytes, &bytes);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	inhdr = in + NBT_HDR_SIZE;
	p = bytes;

	cli_state_set_uid(state->cli, SVAL(inhdr, HDR_UID));
	cli->is_guestlogin = ((SVAL(vwv+2, 0) & 1) != 0);

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_os,
					p,
					bytes+num_bytes-p,
					&ret);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_type,
					p,
					bytes+num_bytes-p,
					&ret);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_domain,
					p,
					bytes+num_bytes-p,
					&ret);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = cli_set_username(cli, state->user);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if (smb1cli_conn_activate_signing(cli->conn, state->session_key, state->response)
	    && !smb1cli_conn_check_signing(cli->conn, (uint8_t *)in, 1)) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}
	if (state->session_key.data) {
		struct smbXcli_session *session = state->cli->smb1.session;

		status = smb1cli_session_set_session_key(session,
				state->session_key);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}
	tevent_req_done(req);
}

static NTSTATUS cli_session_setup_nt1_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS cli_session_setup_nt1(struct cli_state *cli, const char *user,
				      const char *pass, size_t passlen,
				      const char *ntpass, size_t ntpasslen,
				      const char *workgroup)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
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
	req = cli_session_setup_nt1_send(frame, ev, cli, user, pass, passlen,
					 ntpass, ntpasslen, workgroup);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_session_setup_nt1_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/* The following is calculated from :
 * (smb_size-4) = 35
 * (smb_wcnt * 2) = 24 (smb_wcnt == 12 in cli_session_setup_blob_send() )
 * (strlen("Unix") + 1 + strlen("Samba") + 1) * 2 = 22 (unicode strings at
 * end of packet.
 */

#define BASE_SESSSETUP_BLOB_PACKET_SIZE (35 + 24 + 22)

struct cli_sesssetup_blob_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	DATA_BLOB blob;
	uint16_t max_blob_size;
	uint16_t vwv[12];
	uint8_t *buf;

	DATA_BLOB smb2_blob;
	struct iovec *recv_iov;

	NTSTATUS status;
	uint8_t *inbuf;
	DATA_BLOB ret_blob;
};

static bool cli_sesssetup_blob_next(struct cli_sesssetup_blob_state *state,
				    struct tevent_req **psubreq);
static void cli_sesssetup_blob_done(struct tevent_req *subreq);

static struct tevent_req *cli_sesssetup_blob_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct cli_state *cli,
						  DATA_BLOB blob)
{
	struct tevent_req *req, *subreq;
	struct cli_sesssetup_blob_state *state;
	uint32_t usable_space;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_sesssetup_blob_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->blob = blob;
	state->cli = cli;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		usable_space = UINT16_MAX;
	} else {
		usable_space = cli_state_available_size(cli,
				BASE_SESSSETUP_BLOB_PACKET_SIZE);
	}

	if (usable_space == 0) {
		DEBUG(1, ("cli_session_setup_blob: cli->max_xmit too small "
			  "(not possible to send %u bytes)\n",
			  BASE_SESSSETUP_BLOB_PACKET_SIZE + 1));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}
	state->max_blob_size = MIN(usable_space, 0xFFFF);

	if (!cli_sesssetup_blob_next(state, &subreq)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_sesssetup_blob_done, req);
	return req;
}

static bool cli_sesssetup_blob_next(struct cli_sesssetup_blob_state *state,
				    struct tevent_req **psubreq)
{
	struct tevent_req *subreq;
	uint16_t thistime;

	thistime = MIN(state->blob.length, state->max_blob_size);

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {

		state->smb2_blob.data = state->blob.data;
		state->smb2_blob.length = thistime;

		state->blob.data += thistime;
		state->blob.length -= thistime;

		subreq = smb2cli_session_setup_send(state, state->ev,
						    state->cli->conn,
						    state->cli->timeout,
						    state->cli->smb2.session,
						    0, /* in_flags */
						    SMB2_CAP_DFS, /* in_capabilities */
						    0, /* in_channel */
						    0, /* in_previous_session_id */
						    &state->smb2_blob);
		if (subreq == NULL) {
			return false;
		}
		*psubreq = subreq;
		return true;
	}

	SCVAL(state->vwv+0, 0, 0xFF);
	SCVAL(state->vwv+0, 1, 0);
	SSVAL(state->vwv+1, 0, 0);
	SSVAL(state->vwv+2, 0, CLI_BUFFER_SIZE);
	SSVAL(state->vwv+3, 0, 2);
	SSVAL(state->vwv+4, 0, 1);
	SIVAL(state->vwv+5, 0, 0);

	SSVAL(state->vwv+7, 0, thistime);

	SSVAL(state->vwv+8, 0, 0);
	SSVAL(state->vwv+9, 0, 0);
	SIVAL(state->vwv+10, 0,
		cli_session_setup_capabilities(state->cli, CAP_EXTENDED_SECURITY));

	state->buf = (uint8_t *)talloc_memdup(state, state->blob.data,
					      thistime);
	if (state->buf == NULL) {
		return false;
	}
	state->blob.data += thistime;
	state->blob.length -= thistime;

	state->buf = smb_bytes_push_str(state->buf, smbXcli_conn_use_unicode(state->cli->conn),
					"Unix", 5, NULL);
	state->buf = smb_bytes_push_str(state->buf, smbXcli_conn_use_unicode(state->cli->conn),
					"Samba", 6, NULL);
	if (state->buf == NULL) {
		return false;
	}
	subreq = cli_smb_send(state, state->ev, state->cli, SMBsesssetupX, 0,
			      12, state->vwv,
			      talloc_get_size(state->buf), state->buf);
	if (subreq == NULL) {
		return false;
	}
	*psubreq = subreq;
	return true;
}

static void cli_sesssetup_blob_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_sesssetup_blob_state *state = tevent_req_data(
		req, struct cli_sesssetup_blob_state);
	struct cli_state *cli = state->cli;
	uint8_t wct;
	uint16_t *vwv;
	uint32_t num_bytes;
	uint8_t *bytes;
	NTSTATUS status;
	uint8_t *p;
	uint16_t blob_length;
	uint8_t *in;
	uint8_t *inhdr;
	ssize_t ret;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		status = smb2cli_session_setup_recv(subreq, state,
						    &state->recv_iov,
						    &state->ret_blob);
	} else {
		status = cli_smb_recv(subreq, state, &in, 4, &wct, &vwv,
				      &num_bytes, &bytes);
		TALLOC_FREE(state->buf);
	}
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return;
	}

	state->status = status;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		goto next;
	}

	state->inbuf = in;
	inhdr = in + NBT_HDR_SIZE;
	cli_state_set_uid(state->cli, SVAL(inhdr, HDR_UID));
	cli->is_guestlogin = ((SVAL(vwv+2, 0) & 1) != 0);

	blob_length = SVAL(vwv+3, 0);
	if (blob_length > num_bytes) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}
	state->ret_blob = data_blob_const(bytes, blob_length);

	p = bytes + blob_length;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_os,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_type,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

	status = smb_bytes_talloc_string(cli,
					inhdr,
					&cli->server_domain,
					p,
					bytes+num_bytes-p,
					&ret);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	p += ret;

next:
	if (state->blob.length != 0) {
		/*
		 * More to send
		 */
		if (!cli_sesssetup_blob_next(state, &subreq)) {
			tevent_req_oom(req);
			return;
		}
		tevent_req_set_callback(subreq, cli_sesssetup_blob_done, req);
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS cli_sesssetup_blob_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *pblob,
					uint8_t **pinbuf,
					struct iovec **precv_iov)
{
	struct cli_sesssetup_blob_state *state = tevent_req_data(
		req, struct cli_sesssetup_blob_state);
	NTSTATUS status;
	uint8_t *inbuf;
	struct iovec *recv_iov;

	if (tevent_req_is_nterror(req, &status)) {
		TALLOC_FREE(state->cli->smb2.session);
		cli_state_set_uid(state->cli, UID_FIELD_INVALID);
		return status;
	}

	inbuf = talloc_move(mem_ctx, &state->inbuf);
	recv_iov = talloc_move(mem_ctx, &state->recv_iov);
	if (pblob != NULL) {
		*pblob = state->ret_blob;
	}
	if (pinbuf != NULL) {
		*pinbuf = inbuf;
	}
	if (precv_iov != NULL) {
		*precv_iov = recv_iov;
	}
        /* could be NT_STATUS_MORE_PROCESSING_REQUIRED */
	return state->status;
}

#ifdef HAVE_KRB5

/****************************************************************************
 Use in-memory credentials cache
****************************************************************************/

static void use_in_memory_ccache(void) {
	setenv(KRB5_ENV_CCNAME, "MEMORY:cliconnect", 1);
}

/****************************************************************************
 Do a spnego/kerberos encrypted session setup.
****************************************************************************/

struct cli_session_setup_kerberos_state {
	struct cli_state *cli;
	DATA_BLOB negTokenTarg;
	DATA_BLOB session_key_krb5;
	ADS_STATUS ads_status;
};

static void cli_session_setup_kerberos_done(struct tevent_req *subreq);

static struct tevent_req *cli_session_setup_kerberos_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	const char *principal)
{
	struct tevent_req *req, *subreq;
	struct cli_session_setup_kerberos_state *state;
	int rc;

	DEBUG(2,("Doing kerberos session setup\n"));

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_kerberos_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->ads_status = ADS_SUCCESS;

	/*
	 * Ok, this is cheating: spnego_gen_krb5_negTokenInit can block if
	 * we have to acquire a ticket. To be fixed later :-)
	 */
	rc = spnego_gen_krb5_negTokenInit(state, principal, 0, &state->negTokenTarg,
				     &state->session_key_krb5, 0, NULL, NULL);
	if (rc) {
		DEBUG(1, ("cli_session_setup_kerberos: "
			  "spnego_gen_krb5_negTokenInit failed: %s\n",
			  error_message(rc)));
		state->ads_status = ADS_ERROR_KRB5(rc);
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return tevent_req_post(req, ev);
	}

#if 0
	file_save("negTokenTarg.dat", state->negTokenTarg.data,
		  state->negTokenTarg.length);
#endif

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		state->cli->smb2.session = smbXcli_session_create(cli,
								  cli->conn);
		if (tevent_req_nomem(state->cli->smb2.session, req)) {
			return tevent_req_post(req, ev);
		}
	}

	subreq = cli_sesssetup_blob_send(state, ev, cli, state->negTokenTarg);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_session_setup_kerberos_done, req);
	return req;
}

static void cli_session_setup_kerberos_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_setup_kerberos_state *state = tevent_req_data(
		req, struct cli_session_setup_kerberos_state);
	uint8_t *inbuf = NULL;
	struct iovec *recv_iov = NULL;
	NTSTATUS status;

	status = cli_sesssetup_blob_recv(subreq, state,
					 NULL, &inbuf, &recv_iov);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		struct smbXcli_session *session = state->cli->smb2.session;
		status = smb2cli_session_set_session_key(session,
						state->session_key_krb5,
						recv_iov);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	} else {
		struct smbXcli_session *session = state->cli->smb1.session;

		status = smb1cli_session_set_session_key(session,
							 state->session_key_krb5);
		if (tevent_req_nterror(req, status)) {
			return;
		}

		if (smb1cli_conn_activate_signing(state->cli->conn, state->session_key_krb5,
					   data_blob_null)
		    && !smb1cli_conn_check_signing(state->cli->conn, inbuf, 1)) {
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}
	}

	tevent_req_done(req);
}

static ADS_STATUS cli_session_setup_kerberos_recv(struct tevent_req *req)
{
	struct cli_session_setup_kerberos_state *state = tevent_req_data(
		req, struct cli_session_setup_kerberos_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return ADS_ERROR_NT(status);
	}
	return state->ads_status;
}

static ADS_STATUS cli_session_setup_kerberos(struct cli_state *cli,
					     const char *principal)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	ADS_STATUS status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}
	ev = tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_session_setup_kerberos_send(ev, ev, cli, principal);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		status = ADS_ERROR_SYSTEM(errno);
		goto fail;
	}
	status = cli_session_setup_kerberos_recv(req);
fail:
	TALLOC_FREE(ev);
	return status;
}
#endif	/* HAVE_KRB5 */

/****************************************************************************
 Do a spnego/NTLMSSP encrypted session setup.
****************************************************************************/

struct cli_session_setup_ntlmssp_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	struct ntlmssp_state *ntlmssp_state;
	int turn;
	DATA_BLOB blob_out;
};

static int cli_session_setup_ntlmssp_state_destructor(
	struct cli_session_setup_ntlmssp_state *state)
{
	if (state->ntlmssp_state != NULL) {
		TALLOC_FREE(state->ntlmssp_state);
	}
	return 0;
}

static void cli_session_setup_ntlmssp_done(struct tevent_req *req);

static struct tevent_req *cli_session_setup_ntlmssp_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	const char *user, const char *pass, const char *domain)
{
	struct tevent_req *req, *subreq;
	struct cli_session_setup_ntlmssp_state *state;
	NTSTATUS status;
	DATA_BLOB blob_out;
	const char *OIDs_ntlm[] = {OID_NTLMSSP, NULL};

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_ntlmssp_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->turn = 1;

	state->ntlmssp_state = NULL;
	talloc_set_destructor(
		state, cli_session_setup_ntlmssp_state_destructor);

	status = ntlmssp_client_start(state,
				      lp_netbios_name(),
				      lp_workgroup(),
				      lp_client_ntlmv2_auth(),
				      &state->ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	ntlmssp_want_feature(state->ntlmssp_state,
			     NTLMSSP_FEATURE_SESSION_KEY);
	if (cli->use_ccache) {
		ntlmssp_want_feature(state->ntlmssp_state,
				     NTLMSSP_FEATURE_CCACHE);
	}
	status = ntlmssp_set_username(state->ntlmssp_state, user);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = ntlmssp_set_domain(state->ntlmssp_state, domain);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	if (cli->pw_nt_hash) {
		status = ntlmssp_set_password_hash(state->ntlmssp_state, pass);
	} else {
		status = ntlmssp_set_password(state->ntlmssp_state, pass);
	}
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = ntlmssp_update(state->ntlmssp_state, data_blob_null,
				&blob_out);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto fail;
	}

	state->blob_out = spnego_gen_negTokenInit(state, OIDs_ntlm, &blob_out, NULL);
	data_blob_free(&blob_out);

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		state->cli->smb2.session = smbXcli_session_create(cli,
								  cli->conn);
		if (tevent_req_nomem(state->cli->smb2.session, req)) {
			return tevent_req_post(req, ev);
		}
	}

	subreq = cli_sesssetup_blob_send(state, ev, cli, state->blob_out);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_session_setup_ntlmssp_done, req);
	return req;
fail:
	tevent_req_nterror(req, status);
	return tevent_req_post(req, ev);
}

static void cli_session_setup_ntlmssp_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_setup_ntlmssp_state *state = tevent_req_data(
		req, struct cli_session_setup_ntlmssp_state);
	DATA_BLOB blob_in, msg_in, blob_out;
	uint8_t *inbuf = NULL;
	struct iovec *recv_iov = NULL;
	bool parse_ret;
	NTSTATUS status;

	status = cli_sesssetup_blob_recv(subreq, talloc_tos(), &blob_in,
					 &inbuf, &recv_iov);
	TALLOC_FREE(subreq);
	data_blob_free(&state->blob_out);

	if (NT_STATUS_IS_OK(status)) {
		if (state->cli->server_domain[0] == '\0') {
			TALLOC_FREE(state->cli->server_domain);
			state->cli->server_domain = talloc_strdup(state->cli,
						state->ntlmssp_state->server.netbios_domain);
			if (state->cli->server_domain == NULL) {
				tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
				return;
			}
		}

		if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
			struct smbXcli_session *session = state->cli->smb2.session;

			if (ntlmssp_is_anonymous(state->ntlmssp_state)) {
				/*
				 * Windows server does not set the
				 * SMB2_SESSION_FLAG_IS_GUEST nor
				 * SMB2_SESSION_FLAG_IS_NULL flag.
				 *
				 * This fix makes sure we do not try
				 * to verify a signature on the final
				 * session setup response.
				 */
				TALLOC_FREE(state->ntlmssp_state);
				tevent_req_done(req);
				return;
			}

			status = smb2cli_session_set_session_key(session,
						state->ntlmssp_state->session_key,
						recv_iov);
			if (tevent_req_nterror(req, status)) {
				return;
			}
		} else {
			struct smbXcli_session *session = state->cli->smb1.session;

			status = smb1cli_session_set_session_key(session,
					state->ntlmssp_state->session_key);
			if (tevent_req_nterror(req, status)) {
				return;
			}

			if (smb1cli_conn_activate_signing(
				    state->cli->conn, state->ntlmssp_state->session_key,
				    data_blob_null)
			    && !smb1cli_conn_check_signing(state->cli->conn, inbuf, 1)) {
				tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
				return;
			}
		}
		TALLOC_FREE(state->ntlmssp_state);
		tevent_req_done(req);
		return;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (blob_in.length == 0) {
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return;
	}

	if ((state->turn == 1)
	    && NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DATA_BLOB tmp_blob = data_blob_null;
		/* the server might give us back two challenges */
		parse_ret = spnego_parse_challenge(state, blob_in, &msg_in,
						   &tmp_blob);
		data_blob_free(&tmp_blob);
	} else {
		parse_ret = spnego_parse_auth_response(state, blob_in, status,
						       OID_NTLMSSP, &msg_in);
	}
	state->turn += 1;

	if (!parse_ret) {
		DEBUG(3,("Failed to parse auth response\n"));
		if (NT_STATUS_IS_OK(status)
		    || NT_STATUS_EQUAL(status,
				       NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			tevent_req_nterror(
				req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}
	}

	status = ntlmssp_update(state->ntlmssp_state, msg_in, &blob_out);

	if (!NT_STATUS_IS_OK(status)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		TALLOC_FREE(state->ntlmssp_state);
		tevent_req_nterror(req, status);
		return;
	}

	state->blob_out = spnego_gen_auth(state, blob_out);
	if (tevent_req_nomem(state->blob_out.data, req)) {
		return;
	}

	subreq = cli_sesssetup_blob_send(state, state->ev, state->cli,
					 state->blob_out);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_session_setup_ntlmssp_done, req);
}

static NTSTATUS cli_session_setup_ntlmssp_recv(struct tevent_req *req)
{
	struct cli_session_setup_ntlmssp_state *state = tevent_req_data(
		req, struct cli_session_setup_ntlmssp_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		cli_state_set_uid(state->cli, UID_FIELD_INVALID);
		return status;
	}
	return NT_STATUS_OK;
}

static NTSTATUS cli_session_setup_ntlmssp(struct cli_state *cli,
					  const char *user,
					  const char *pass,
					  const char *domain)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	ev = tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_session_setup_ntlmssp_send(ev, ev, cli, user, pass, domain);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_session_setup_ntlmssp_recv(req);
fail:
	TALLOC_FREE(ev);
	return status;
}

/****************************************************************************
 Do a spnego encrypted session setup.

 user_domain: The shortname of the domain the user/machine is a member of.
 dest_realm: The realm we're connecting to, if NULL we use our default realm.
****************************************************************************/

static ADS_STATUS cli_session_setup_spnego(struct cli_state *cli,
			      const char *user,
			      const char *pass,
			      const char *user_domain,
			      const char * dest_realm)
{
	char *principal = NULL;
	char *OIDs[ASN1_MAX_OIDS];
	int i;
	const DATA_BLOB *server_blob;
	DATA_BLOB blob = data_blob_null;
	const char *p = NULL;
	char *account = NULL;
	NTSTATUS status;

	server_blob = smbXcli_conn_server_gss_blob(cli->conn);
	if (server_blob) {
		blob = data_blob(server_blob->data, server_blob->length);
	}

	DEBUG(3,("Doing spnego session setup (blob length=%lu)\n", (unsigned long)blob.length));

	/* the server might not even do spnego */
	if (blob.length == 0) {
		DEBUG(3,("server didn't supply a full spnego negprot\n"));
		goto ntlmssp;
	}

#if 0
	file_save("negprot.dat", cli->secblob.data, cli->secblob.length);
#endif

	/* The server sent us the first part of the SPNEGO exchange in the
	 * negprot reply. It is WRONG to depend on the principal sent in the
	 * negprot reply, but right now we do it. If we don't receive one,
	 * we try to best guess, then fall back to NTLM.  */
	if (!spnego_parse_negTokenInit(talloc_tos(), blob, OIDs, &principal, NULL) ||
			OIDs[0] == NULL) {
		data_blob_free(&blob);
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}
	data_blob_free(&blob);

	/* make sure the server understands kerberos */
	for (i=0;OIDs[i];i++) {
		if (i == 0)
			DEBUG(3,("got OID=%s\n", OIDs[i]));
		else
			DEBUGADD(3,("got OID=%s\n", OIDs[i]));
		if (strcmp(OIDs[i], OID_KERBEROS5_OLD) == 0 ||
		    strcmp(OIDs[i], OID_KERBEROS5) == 0) {
			cli->got_kerberos_mechanism = True;
		}
		talloc_free(OIDs[i]);
	}

	DEBUG(3,("got principal=%s\n", principal ? principal : "<null>"));

	status = cli_set_username(cli, user);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(principal);
		return ADS_ERROR_NT(status);
	}

#ifdef HAVE_KRB5
	/* If password is set we reauthenticate to kerberos server
	 * and do not store results */

	if (user && *user && cli->got_kerberos_mechanism && cli->use_kerberos) {
		ADS_STATUS rc;
		const char *remote_name = smbXcli_conn_remote_name(cli->conn);

		if (pass && *pass) {
			int ret;

			use_in_memory_ccache();
			ret = kerberos_kinit_password(user, pass, 0 /* no time correction for now */, NULL);

			if (ret){
				TALLOC_FREE(principal);
				DEBUG(0, ("Kinit failed: %s\n", error_message(ret)));
				if (cli->fallback_after_kerberos)
					goto ntlmssp;
				return ADS_ERROR_KRB5(ret);
			}
		}

		/* We may not be allowed to use the server-supplied SPNEGO principal, or it may not have been supplied to us
		 */
		if (!lp_client_use_spnego_principal() || strequal(principal, ADS_IGNORE_PRINCIPAL)) {
			TALLOC_FREE(principal);
		}

		if (principal == NULL &&
			!is_ipaddress(remote_name) &&
			!strequal(STAR_SMBSERVER,
				  remote_name)) {
			DEBUG(3,("cli_session_setup_spnego: using target "
				 "hostname not SPNEGO principal\n"));

			if (dest_realm) {
				char *realm = strupper_talloc(talloc_tos(), dest_realm);
				if (realm) {
					principal = talloc_asprintf(talloc_tos(),
								    "cifs/%s@%s",
								    remote_name,
								    realm);
					TALLOC_FREE(realm);
				}
			} else {
				principal = kerberos_get_principal_from_service_hostname(talloc_tos(),
											 "cifs",
											 remote_name,
											 lp_realm());
			}

			if (!principal) {
				return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			}
			DEBUG(3,("cli_session_setup_spnego: guessed "
				"server principal=%s\n",
				principal ? principal : "<null>"));
		}

		if (principal) {
			rc = cli_session_setup_kerberos(cli, principal);
			if (ADS_ERR_OK(rc) || !cli->fallback_after_kerberos) {
				TALLOC_FREE(principal);
				return rc;
			}
		}
	}
#endif

	TALLOC_FREE(principal);

ntlmssp:

	account = talloc_strdup(talloc_tos(), user);
	if (!account) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	/* when falling back to ntlmssp while authenticating with a machine
	 * account strip off the realm - gd */

	if ((p = strchr_m(user, '@')) != NULL) {
		account[PTR_DIFF(p,user)] = '\0';
	}

	return ADS_ERROR_NT(cli_session_setup_ntlmssp(cli, account, pass, user_domain));
}

/****************************************************************************
 Send a session setup. The username and workgroup is in UNIX character
 format and must be converted to DOS codepage format before sending. If the
 password is in plaintext, the same should be done.
****************************************************************************/

NTSTATUS cli_session_setup(struct cli_state *cli,
			   const char *user,
			   const char *pass, int passlen,
			   const char *ntpass, int ntpasslen,
			   const char *workgroup)
{
	char *p;
	char *user2;
	uint16_t sec_mode = smb1cli_conn_server_security_mode(cli->conn);

	if (user) {
		user2 = talloc_strdup(talloc_tos(), user);
	} else {
		user2 = talloc_strdup(talloc_tos(), "");
	}
	if (user2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!workgroup) {
		workgroup = "";
	}

	/* allow for workgroups as part of the username */
	if ((p=strchr_m(user2,'\\')) || (p=strchr_m(user2,'/')) ||
	    (p=strchr_m(user2,*lp_winbind_separator()))) {
		*p = 0;
		user = p+1;
		if (!strupper_m(user2)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		workgroup = user2;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_LANMAN1) {
		return NT_STATUS_OK;
	}

	/* now work out what sort of session setup we are going to
           do. I have split this into separate functions to make the
           flow a bit easier to understand (tridge) */

	/* if its an older server then we have to use the older request format */

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_NT1) {
		if (!lp_client_lanman_auth() && passlen != 24 && (*pass)) {
			DEBUG(1, ("Server requested LM password but 'client lanman auth = no'"
				  " or 'client ntlmv2 auth = yes'\n"));
			return NT_STATUS_ACCESS_DENIED;
		}

		if ((sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) == 0 &&
		    !lp_client_plaintext_auth() && (*pass)) {
			DEBUG(1, ("Server requested PLAINTEXT password but 'client plaintext auth = no'"
				  " or 'client ntlmv2 auth = yes'\n"));
			return NT_STATUS_ACCESS_DENIED;
		}

		return cli_session_setup_lanman2(cli, user, pass, passlen,
						 workgroup);
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		const char *remote_realm = cli_state_remote_realm(cli);
		ADS_STATUS status = cli_session_setup_spnego(cli, user, pass,
							     workgroup,
							     remote_realm);
		if (!ADS_ERR_OK(status)) {
			DEBUG(3, ("SMB2-SPNEGO login failed: %s\n", ads_errstr(status)));
			return ads_ntstatus(status);
		}
		return NT_STATUS_OK;
	}

	/* if no user is supplied then we have to do an anonymous connection.
	   passwords are ignored */

	if (!user || !*user)
		return cli_session_setup_guest(cli);

	/* if the server is share level then send a plaintext null
           password at this point. The password is sent in the tree
           connect */

	if ((sec_mode & NEGOTIATE_SECURITY_USER_LEVEL) == 0)
		return cli_session_setup_plain(cli, user, "", workgroup);

	/* if the server doesn't support encryption then we have to use 
	   plaintext. The second password is ignored */

	if ((sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) == 0) {
		if (!lp_client_plaintext_auth() && (*pass)) {
			DEBUG(1, ("Server requested PLAINTEXT password but 'client plaintext auth = no'"
				  " or 'client ntlmv2 auth = yes'\n"));
			return NT_STATUS_ACCESS_DENIED;
		}
		return cli_session_setup_plain(cli, user, pass, workgroup);
	}

	/* if the server supports extended security then use SPNEGO */

	if (smb1cli_conn_capabilities(cli->conn) & CAP_EXTENDED_SECURITY) {
		const char *remote_realm = cli_state_remote_realm(cli);
		ADS_STATUS status = cli_session_setup_spnego(cli, user, pass,
							     workgroup,
							     remote_realm);
		if (!ADS_ERR_OK(status)) {
			DEBUG(3, ("SPNEGO login failed: %s\n", ads_errstr(status)));
			return ads_ntstatus(status);
		}
	} else {
		NTSTATUS status;

		/* otherwise do a NT1 style session setup */
		status = cli_session_setup_nt1(cli, user, pass, passlen,
					       ntpass, ntpasslen, workgroup);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3,("cli_session_setup: NT1 session setup "
				 "failed: %s\n", nt_errstr(status)));
			return status;
		}
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Send a uloggoff.
*****************************************************************************/

struct cli_ulogoff_state {
	struct cli_state *cli;
	uint16_t vwv[3];
};

static void cli_ulogoff_done(struct tevent_req *subreq);

struct tevent_req *cli_ulogoff_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli)
{
	struct tevent_req *req, *subreq;
	struct cli_ulogoff_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_ulogoff_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	SCVAL(state->vwv+0, 0, 0xFF);
	SCVAL(state->vwv+1, 0, 0);
	SSVAL(state->vwv+2, 0, 0);

	subreq = cli_smb_send(state, ev, cli, SMBulogoffX, 0, 2, state->vwv,
			      0, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_ulogoff_done, req);
	return req;
}

static void cli_ulogoff_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_ulogoff_state *state = tevent_req_data(
		req, struct cli_ulogoff_state);
	NTSTATUS status;

	status = cli_smb_recv(subreq, NULL, NULL, 0, NULL, NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	cli_state_set_uid(state->cli, UID_FIELD_INVALID);
	tevent_req_done(req);
}

NTSTATUS cli_ulogoff_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_ulogoff(struct cli_state *cli)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	ev = tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_ulogoff_send(ev, ev, cli);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_ulogoff_recv(req);
fail:
	TALLOC_FREE(ev);
	return status;
}

/****************************************************************************
 Send a tconX.
****************************************************************************/

struct cli_tcon_andx_state {
	struct cli_state *cli;
	uint16_t vwv[4];
	struct iovec bytes;
};

static void cli_tcon_andx_done(struct tevent_req *subreq);

struct tevent_req *cli_tcon_andx_create(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *share, const char *dev,
					const char *pass, int passlen,
					struct tevent_req **psmbreq)
{
	struct tevent_req *req, *subreq;
	struct cli_tcon_andx_state *state;
	uint8_t p24[24];
	uint16_t *vwv;
	char *tmp = NULL;
	uint8_t *bytes;
	uint16_t sec_mode = smb1cli_conn_server_security_mode(cli->conn);
	uint16_t tcon_flags = 0;

	*psmbreq = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_tcon_andx_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	vwv = state->vwv;

	cli->share = talloc_strdup(cli, share);
	if (!cli->share) {
		return NULL;
	}

	/* in user level security don't send a password now */
	if (sec_mode & NEGOTIATE_SECURITY_USER_LEVEL) {
		passlen = 1;
		pass = "";
	} else if (pass == NULL) {
		DEBUG(1, ("Server not using user level security and no "
			  "password supplied.\n"));
		goto access_denied;
	}

	if ((sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) &&
	    *pass && passlen != 24) {
		if (!lp_client_lanman_auth()) {
			DEBUG(1, ("Server requested LANMAN password "
				  "(share-level security) but "
				  "'client lanman auth = no' or 'client ntlmv2 auth = yes'\n"));
			goto access_denied;
		}

		/*
		 * Non-encrypted passwords - convert to DOS codepage before
		 * encryption.
		 */
		SMBencrypt(pass, smb1cli_conn_server_challenge(cli->conn), p24);
		passlen = 24;
		pass = (const char *)p24;
	} else {
		if((sec_mode & (NEGOTIATE_SECURITY_USER_LEVEL
				     |NEGOTIATE_SECURITY_CHALLENGE_RESPONSE))
		   == 0) {
			uint8_t *tmp_pass;

			if (!lp_client_plaintext_auth() && (*pass)) {
				DEBUG(1, ("Server requested PLAINTEXT "
					  "password but "
					  "'client plaintext auth = no' or 'client ntlmv2 auth = yes'\n"));
				goto access_denied;
			}

			/*
			 * Non-encrypted passwords - convert to DOS codepage
			 * before using.
			 */
			tmp_pass = talloc_array(talloc_tos(), uint8, 0);
			if (tevent_req_nomem(tmp_pass, req)) {
				return tevent_req_post(req, ev);
			}
			tmp_pass = trans2_bytes_push_str(tmp_pass,
							 false, /* always DOS */
							 pass,
							 passlen,
							 NULL);
			if (tevent_req_nomem(tmp_pass, req)) {
				return tevent_req_post(req, ev);
			}
			pass = (const char *)tmp_pass;
			passlen = talloc_get_size(tmp_pass);
		}
	}

	tcon_flags |= TCONX_FLAG_EXTENDED_RESPONSE;
	tcon_flags |= TCONX_FLAG_EXTENDED_SIGNATURES;

	SCVAL(vwv+0, 0, 0xFF);
	SCVAL(vwv+0, 1, 0);
	SSVAL(vwv+1, 0, 0);
	SSVAL(vwv+2, 0, tcon_flags);
	SSVAL(vwv+3, 0, passlen);

	if (passlen && pass) {
		bytes = (uint8_t *)talloc_memdup(state, pass, passlen);
	} else {
		bytes = talloc_array(state, uint8_t, 0);
	}

	/*
	 * Add the sharename
	 */
	tmp = talloc_asprintf_strupper_m(talloc_tos(), "\\\\%s\\%s",
					 smbXcli_conn_remote_name(cli->conn), share);
	if (tmp == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), tmp, strlen(tmp)+1,
				   NULL);
	TALLOC_FREE(tmp);

	/*
	 * Add the devicetype
	 */
	tmp = talloc_strdup_upper(talloc_tos(), dev);
	if (tmp == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}
	bytes = smb_bytes_push_str(bytes, false, tmp, strlen(tmp)+1, NULL);
	TALLOC_FREE(tmp);

	if (bytes == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}

	state->bytes.iov_base = (void *)bytes;
	state->bytes.iov_len = talloc_get_size(bytes);

	subreq = cli_smb_req_create(state, ev, cli, SMBtconX, 0, 4, vwv,
				    1, &state->bytes);
	if (subreq == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}
	tevent_req_set_callback(subreq, cli_tcon_andx_done, req);
	*psmbreq = subreq;
	return req;

 access_denied:
	tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
	return tevent_req_post(req, ev);
}

struct tevent_req *cli_tcon_andx_send(TALLOC_CTX *mem_ctx,
				      struct event_context *ev,
				      struct cli_state *cli,
				      const char *share, const char *dev,
				      const char *pass, int passlen)
{
	struct tevent_req *req, *subreq;
	NTSTATUS status;

	req = cli_tcon_andx_create(mem_ctx, ev, cli, share, dev, pass, passlen,
				   &subreq);
	if (req == NULL) {
		return NULL;
	}
	if (subreq == NULL) {
		return req;
	}
	status = smb1cli_req_chain_submit(&subreq, 1);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}
	return req;
}

static void cli_tcon_andx_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_tcon_andx_state *state = tevent_req_data(
		req, struct cli_tcon_andx_state);
	struct cli_state *cli = state->cli;
	uint8_t *in;
	uint8_t *inhdr;
	uint8_t wct;
	uint16_t *vwv;
	uint32_t num_bytes;
	uint8_t *bytes;
	NTSTATUS status;
	uint16_t optional_support = 0;

	status = cli_smb_recv(subreq, state, &in, 0, &wct, &vwv,
			      &num_bytes, &bytes);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	inhdr = in + NBT_HDR_SIZE;

	if (num_bytes) {
		if (clistr_pull_talloc(cli,
				(const char *)inhdr,
				SVAL(inhdr, HDR_FLG2),
				&cli->dev,
				bytes,
				num_bytes,
				STR_TERMINATE|STR_ASCII) == -1) {
			tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
			return;
		}
	} else {
		cli->dev = talloc_strdup(cli, "");
		if (cli->dev == NULL) {
			tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
			return;
		}
	}

	if ((smbXcli_conn_protocol(cli->conn) >= PROTOCOL_NT1) && (num_bytes == 3)) {
		/* almost certainly win95 - enable bug fixes */
		cli->win95 = True;
	}

	/*
	 * Make sure that we have the optional support 16-bit field. WCT > 2.
	 * Avoids issues when connecting to Win9x boxes sharing files
	 */

	cli->dfsroot = false;

	if ((wct > 2) && (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_LANMAN2)) {
		optional_support = SVAL(vwv+2, 0);
	}

	if (optional_support & SMB_SHARE_IN_DFS) {
		cli->dfsroot = true;
	}

	if (optional_support & SMB_EXTENDED_SIGNATURES) {
		smb1cli_session_protect_session_key(cli->smb1.session);
	}

	cli_state_set_tid(cli, SVAL(inhdr, HDR_TID));
	tevent_req_done(req);
}

NTSTATUS cli_tcon_andx_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_tcon_andx(struct cli_state *cli, const char *share,
		       const char *dev, const char *pass, int passlen)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_tcon_andx_send(frame, ev, cli, share, dev, pass, passlen);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_tcon_andx_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS cli_tree_connect(struct cli_state *cli, const char *share,
			  const char *dev, const char *pass, int passlen)
{
	NTSTATUS status;
	uint16_t max_xmit = 0;
	uint16_t tid = 0;

	cli->share = talloc_strdup(cli, share);
	if (!cli->share) {
		return NT_STATUS_NO_MEMORY;
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return smb2cli_tcon(cli, share);
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_LANMAN1) {
		return cli_tcon_andx(cli, share, dev, pass, passlen);
	}

	status = cli_raw_tcon(cli, share, pass, dev, &max_xmit, &tid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	cli_state_set_tid(cli, tid);

	return NT_STATUS_OK;
}

/****************************************************************************
 Send a tree disconnect.
****************************************************************************/

struct cli_tdis_state {
	struct cli_state *cli;
};

static void cli_tdis_done(struct tevent_req *subreq);

struct tevent_req *cli_tdis_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct cli_state *cli)
{
	struct tevent_req *req, *subreq;
	struct cli_tdis_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_tdis_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	subreq = cli_smb_send(state, ev, cli, SMBtdis, 0, 0, NULL, 0, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_tdis_done, req);
	return req;
}

static void cli_tdis_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_tdis_state *state = tevent_req_data(
		req, struct cli_tdis_state);
	NTSTATUS status;

	status = cli_smb_recv(subreq, NULL, NULL, 0, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	cli_state_set_tid(state->cli, UINT16_MAX);
	tevent_req_done(req);
}

NTSTATUS cli_tdis_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_tdis(struct cli_state *cli)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	ev = tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_tdis_send(ev, ev, cli);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_tdis_recv(req);
fail:
	TALLOC_FREE(ev);
	return status;
}

static NTSTATUS cli_connect_sock(const char *host, int name_type,
				 const struct sockaddr_storage *pss,
				 const char *myname, uint16_t port,
				 int sec_timeout, int *pfd, uint16_t *pport)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *prog;
	unsigned int i, num_addrs;
	const char **called_names;
	const char **calling_names;
	int *called_types;
	NTSTATUS status;
	int fd;

	prog = getenv("LIBSMB_PROG");
	if (prog != NULL) {
		fd = sock_exec(prog);
		if (fd == -1) {
			return map_nt_error_from_unix(errno);
		}
		port = 0;
		goto done;
	}

	if ((pss == NULL) || is_zero_addr(pss)) {
		struct sockaddr_storage *addrs;
		status = resolve_name_list(talloc_tos(), host, name_type,
					   &addrs, &num_addrs);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		pss = addrs;
	} else {
		num_addrs = 1;
	}

	called_names = talloc_array(talloc_tos(), const char *, num_addrs);
	if (called_names == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	called_types = talloc_array(talloc_tos(), int, num_addrs);
	if (called_types == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	calling_names = talloc_array(talloc_tos(), const char *, num_addrs);
	if (calling_names == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	for (i=0; i<num_addrs; i++) {
		called_names[i] = host;
		called_types[i] = name_type;
		calling_names[i] = myname;
	}
	status = smbsock_any_connect(pss, called_names, called_types,
				     calling_names, NULL, num_addrs, port,
				     sec_timeout, &fd, NULL, &port);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	set_socket_options(fd, lp_socket_options());
done:
	*pfd = fd;
	*pport = port;
	status = NT_STATUS_OK;
fail:
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS cli_connect_nb(const char *host, const struct sockaddr_storage *dest_ss,
			uint16_t port, int name_type, const char *myname,
			int signing_state, int flags, struct cli_state **pcli)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct cli_state *cli;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	int fd = -1;
	char *desthost;
	char *p;

	desthost = talloc_strdup(talloc_tos(), host);
	if (desthost == NULL) {
		goto fail;
	}

	p = strchr(host, '#');
	if (p != NULL) {
		name_type = strtol(p+1, NULL, 16);
		host = talloc_strndup(talloc_tos(), host, p - host);
		if (host == NULL) {
			goto fail;
		}
	}

	status = cli_connect_sock(host, name_type, dest_ss, myname, port,
				  20, &fd, &port);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	cli = cli_state_create(NULL, fd, desthost, NULL, signing_state, flags);
	if (cli == NULL) {
		close(fd);
		fd = -1;
		goto fail;
	}

	*pcli = cli;
	status = NT_STATUS_OK;
fail:
	TALLOC_FREE(frame);
	return status;
}

/**
   establishes a connection to after the negprot. 
   @param output_cli A fully initialised cli structure, non-null only on success
   @param dest_host The netbios name of the remote host
   @param dest_ss (optional) The the destination IP, NULL for name based lookup
   @param port (optional) The destination port (0 for default)
*/
NTSTATUS cli_start_connection(struct cli_state **output_cli, 
			      const char *my_name, 
			      const char *dest_host, 
			      const struct sockaddr_storage *dest_ss, int port,
			      int signing_state, int flags)
{
	NTSTATUS nt_status;
	struct cli_state *cli;

	nt_status = cli_connect_nb(dest_host, dest_ss, port, 0x20, my_name,
				   signing_state, flags, &cli);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(10, ("cli_connect_nb failed: %s\n",
			   nt_errstr(nt_status)));
		return nt_status;
	}

	nt_status = smbXcli_negprot(cli->conn, cli->timeout, PROTOCOL_CORE,
				    PROTOCOL_NT1);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("failed negprot: %s\n", nt_errstr(nt_status)));
		cli_shutdown(cli);
		return nt_status;
	}

	*output_cli = cli;
	return NT_STATUS_OK;
}


/**
   establishes a connection right up to doing tconX, password specified.
   @param output_cli A fully initialised cli structure, non-null only on success
   @param dest_host The netbios name of the remote host
   @param dest_ip (optional) The the destination IP, NULL for name based lookup
   @param port (optional) The destination port (0 for default)
   @param service (optional) The share to make the connection to.  Should be 'unqualified' in any way.
   @param service_type The 'type' of serivice. 
   @param user Username, unix string
   @param domain User's domain
   @param password User's password, unencrypted unix string.
*/

NTSTATUS cli_full_connection(struct cli_state **output_cli, 
			     const char *my_name, 
			     const char *dest_host, 
			     const struct sockaddr_storage *dest_ss, int port,
			     const char *service, const char *service_type,
			     const char *user, const char *domain, 
			     const char *password, int flags,
			     int signing_state)
{
	NTSTATUS nt_status;
	struct cli_state *cli = NULL;
	int pw_len = password ? strlen(password)+1 : 0;

	*output_cli = NULL;

	if (password == NULL) {
		password = "";
	}

	nt_status = cli_start_connection(&cli, my_name, dest_host,
					 dest_ss, port, signing_state,
					 flags);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = cli_session_setup(cli, user, password, pw_len, password,
				      pw_len, domain);
	if (!NT_STATUS_IS_OK(nt_status)) {

		if (!(flags & CLI_FULL_CONNECTION_ANONYMOUS_FALLBACK)) {
			DEBUG(1,("failed session setup with %s\n",
				 nt_errstr(nt_status)));
			cli_shutdown(cli);
			return nt_status;
		}

		nt_status = cli_session_setup(cli, "", "", 0, "", 0, domain);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1,("anonymous failed session setup with %s\n",
				 nt_errstr(nt_status)));
			cli_shutdown(cli);
			return nt_status;
		}
	}

	if (service) {
		nt_status = cli_tree_connect(cli, service, service_type,
					     password, pw_len);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(1,("failed tcon_X with %s\n", nt_errstr(nt_status)));
			cli_shutdown(cli);
			if (NT_STATUS_IS_OK(nt_status)) {
				nt_status = NT_STATUS_UNSUCCESSFUL;
			}
			return nt_status;
		}
	}

	nt_status = cli_init_creds(cli, user, domain, password);
	if (!NT_STATUS_IS_OK(nt_status)) {
		cli_shutdown(cli);
		return nt_status;
	}

	*output_cli = cli;
	return NT_STATUS_OK;
}

/****************************************************************************
 Send an old style tcon.
****************************************************************************/
NTSTATUS cli_raw_tcon(struct cli_state *cli, 
		      const char *service, const char *pass, const char *dev,
		      uint16 *max_xmit, uint16 *tid)
{
	struct tevent_req *req;
	uint16_t *ret_vwv;
	uint8_t *bytes;
	NTSTATUS status;

	if (!lp_client_plaintext_auth() && (*pass)) {
		DEBUG(1, ("Server requested PLAINTEXT password but 'client plaintext auth = no'"
			  " or 'client ntlmv2 auth = yes'\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	bytes = talloc_array(talloc_tos(), uint8_t, 0);
	bytes = smb_bytes_push_bytes(bytes, 4, NULL, 0);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   service, strlen(service)+1, NULL);
	bytes = smb_bytes_push_bytes(bytes, 4, NULL, 0);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   pass, strlen(pass)+1, NULL);
	bytes = smb_bytes_push_bytes(bytes, 4, NULL, 0);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   dev, strlen(dev)+1, NULL);

	status = cli_smb(talloc_tos(), cli, SMBtcon, 0, 0, NULL,
			 talloc_get_size(bytes), bytes, &req,
			 2, NULL, &ret_vwv, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*max_xmit = SVAL(ret_vwv + 0, 0);
	*tid = SVAL(ret_vwv + 1, 0);

	return NT_STATUS_OK;
}

/* Return a cli_state pointing at the IPC$ share for the given server */

struct cli_state *get_ipc_connect(char *server,
				struct sockaddr_storage *server_ss,
				const struct user_auth_info *user_info)
{
        struct cli_state *cli;
	NTSTATUS nt_status;
	uint32_t flags = CLI_FULL_CONNECTION_ANONYMOUS_FALLBACK;

	if (user_info->use_kerberos) {
		flags |= CLI_FULL_CONNECTION_USE_KERBEROS;
	}

	nt_status = cli_full_connection(&cli, NULL, server, server_ss, 0, "IPC$", "IPC", 
					user_info->username ? user_info->username : "",
					lp_workgroup(),
					user_info->password ? user_info->password : "",
					flags,
					SMB_SIGNING_DEFAULT);

	if (NT_STATUS_IS_OK(nt_status)) {
		return cli;
	} else if (is_ipaddress(server)) {
	    /* windows 9* needs a correct NMB name for connections */
	    fstring remote_name;

	    if (name_status_find("*", 0, 0, server_ss, remote_name)) {
		cli = get_ipc_connect(remote_name, server_ss, user_info);
		if (cli)
		    return cli;
	    }
	}
	return NULL;
}

/*
 * Given the IP address of a master browser on the network, return its
 * workgroup and connect to it.
 *
 * This function is provided to allow additional processing beyond what
 * get_ipc_connect_master_ip_bcast() does, e.g. to retrieve the list of master
 * browsers and obtain each master browsers' list of domains (in case the
 * first master browser is recently on the network and has not yet
 * synchronized with other master browsers and therefore does not yet have the
 * entire network browse list)
 */

struct cli_state *get_ipc_connect_master_ip(TALLOC_CTX *ctx,
				struct sockaddr_storage *mb_ip,
				const struct user_auth_info *user_info,
				char **pp_workgroup_out)
{
	char addr[INET6_ADDRSTRLEN];
        fstring name;
	struct cli_state *cli;
	struct sockaddr_storage server_ss;

	*pp_workgroup_out = NULL;

	print_sockaddr(addr, sizeof(addr), mb_ip);
        DEBUG(99, ("Looking up name of master browser %s\n",
                   addr));

        /*
         * Do a name status query to find out the name of the master browser.
         * We use <01><02>__MSBROWSE__<02>#01 if *#00 fails because a domain
         * master browser will not respond to a wildcard query (or, at least,
         * an NT4 server acting as the domain master browser will not).
         *
         * We might be able to use ONLY the query on MSBROWSE, but that's not
         * yet been tested with all Windows versions, so until it is, leave
         * the original wildcard query as the first choice and fall back to
         * MSBROWSE if the wildcard query fails.
         */
        if (!name_status_find("*", 0, 0x1d, mb_ip, name) &&
            !name_status_find(MSBROWSE, 1, 0x1d, mb_ip, name)) {

                DEBUG(99, ("Could not retrieve name status for %s\n",
                           addr));
                return NULL;
        }

        if (!find_master_ip(name, &server_ss)) {
                DEBUG(99, ("Could not find master ip for %s\n", name));
                return NULL;
        }

	*pp_workgroup_out = talloc_strdup(ctx, name);

	DEBUG(4, ("found master browser %s, %s\n", name, addr));

	print_sockaddr(addr, sizeof(addr), &server_ss);
	cli = get_ipc_connect(addr, &server_ss, user_info);

	return cli;
}

/*
 * Return the IP address and workgroup of a master browser on the network, and
 * connect to it.
 */

struct cli_state *get_ipc_connect_master_ip_bcast(TALLOC_CTX *ctx,
					const struct user_auth_info *user_info,
					char **pp_workgroup_out)
{
	struct sockaddr_storage *ip_list;
	struct cli_state *cli;
	int i, count;
	NTSTATUS status;

	*pp_workgroup_out = NULL;

        DEBUG(99, ("Do broadcast lookup for workgroups on local network\n"));

        /* Go looking for workgroups by broadcasting on the local network */

	status = name_resolve_bcast(MSBROWSE, 1, talloc_tos(),
				    &ip_list, &count);
        if (!NT_STATUS_IS_OK(status)) {
                DEBUG(99, ("No master browsers responded: %s\n",
			   nt_errstr(status)));
                return NULL;
        }

	for (i = 0; i < count; i++) {
		char addr[INET6_ADDRSTRLEN];
		print_sockaddr(addr, sizeof(addr), &ip_list[i]);
		DEBUG(99, ("Found master browser %s\n", addr));

		cli = get_ipc_connect_master_ip(ctx, &ip_list[i],
				user_info, pp_workgroup_out);
		if (cli)
			return(cli);
	}

	return NULL;
}
