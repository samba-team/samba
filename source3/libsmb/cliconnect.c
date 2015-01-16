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
						  struct tevent_context *ev,
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
						struct tevent_context *ev,
						struct cli_state *cli)
{
	struct tevent_req *req, *subreq;
	NTSTATUS status;

	req = cli_session_setup_guest_create(mem_ctx, ev, cli, &subreq);
	if (req == NULL) {
		return NULL;
	}

	status = smb1cli_req_chain_submit(&subreq, 1);
	if (!NT_STATUS_IS_OK(status)) {
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

#ifdef HAVE_KRB5

static char *cli_session_setup_get_principal(
	TALLOC_CTX *mem_ctx, const char *spnego_principal,
	const char *remote_name, const char *dest_realm)
{
	char *principal = NULL;

	if (!lp_client_use_spnego_principal() ||
	    strequal(principal, ADS_IGNORE_PRINCIPAL)) {
		spnego_principal = NULL;
	}
	if (spnego_principal != NULL) {
		DEBUG(3, ("cli_session_setup_spnego: using spnego provided "
			  "principal %s\n", spnego_principal));
		return talloc_strdup(mem_ctx, spnego_principal);
	}
	if (is_ipaddress(remote_name) ||
	    strequal(remote_name, STAR_SMBSERVER)) {
		return NULL;
	}

	DEBUG(3, ("cli_session_setup_spnego: using target "
		  "hostname not SPNEGO principal\n"));

	if (dest_realm) {
		char *realm = strupper_talloc(talloc_tos(), dest_realm);
		if (realm == NULL) {
			return NULL;
		}
		principal = talloc_asprintf(talloc_tos(), "cifs/%s@%s",
					    remote_name, realm);
		TALLOC_FREE(realm);
	} else {
		principal = kerberos_get_principal_from_service_hostname(
			talloc_tos(), "cifs", remote_name, lp_realm());
	}
	DEBUG(3, ("cli_session_setup_spnego: guessed server principal=%s\n",
		  principal ? principal : "<null>"));

	return principal;
}
#endif

static char *cli_session_setup_get_account(TALLOC_CTX *mem_ctx,
					   const char *principal)
{
	char *account, *p;

	account = talloc_strdup(mem_ctx, principal);
	if (account == NULL) {
		return NULL;
	}
	p = strchr_m(account, '@');
	if (p != NULL) {
		*p = '\0';
	}
	return account;
}

/****************************************************************************
 Do a spnego encrypted session setup.

 user_domain: The shortname of the domain the user/machine is a member of.
 dest_realm: The realm we're connecting to, if NULL we use our default realm.
****************************************************************************/

struct cli_session_setup_spnego_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	const char *user;
	const char *account;
	const char *pass;
	const char *user_domain;
	const char *dest_realm;
	ADS_STATUS result;
};

#ifdef HAVE_KRB5
static void cli_session_setup_spnego_done_krb(struct tevent_req *subreq);
#endif

static void cli_session_setup_spnego_done_ntlmssp(struct tevent_req *subreq);

static struct tevent_req *cli_session_setup_spnego_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	const char *user, const char *pass, const char *user_domain,
	const char *dest_realm)
{
	struct tevent_req *req, *subreq;
	struct cli_session_setup_spnego_state *state;
	char *principal = NULL;
	char *OIDs[ASN1_MAX_OIDS];
	int i;
	const DATA_BLOB *server_blob;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_spnego_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->user = user;
	state->pass = pass;
	state->user_domain = user_domain;
	state->dest_realm = dest_realm;

	state->account = cli_session_setup_get_account(state, user);
	if (tevent_req_nomem(state->account, req)) {
		return tevent_req_post(req, ev);
	}

	server_blob = smbXcli_conn_server_gss_blob(cli->conn);

	DEBUG(3,("Doing spnego session setup (blob length=%lu)\n",
		 (unsigned long)server_blob->length));

	/* the server might not even do spnego */
	if (server_blob->length == 0) {
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
	if (!spnego_parse_negTokenInit(state, *server_blob, OIDs,
				       &principal, NULL) ||
			OIDs[0] == NULL) {
		state->result = ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

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
		state->result = ADS_ERROR_NT(status);
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

#ifdef HAVE_KRB5
	/* If password is set we reauthenticate to kerberos server
	 * and do not store results */

	if (user && *user && cli->got_kerberos_mechanism && cli->use_kerberos) {
		const char *remote_name = smbXcli_conn_remote_name(cli->conn);
		char *tmp;

		if (pass && *pass) {
			int ret;

			use_in_memory_ccache();
			ret = kerberos_kinit_password(user, pass, 0 /* no time correction for now */, NULL);

			if (ret){
				TALLOC_FREE(principal);
				DEBUG(0, ("Kinit failed: %s\n", error_message(ret)));
				if (cli->fallback_after_kerberos)
					goto ntlmssp;
				state->result = ADS_ERROR_KRB5(ret);
				tevent_req_done(req);
				return tevent_req_post(req, ev);
			}
		}

		tmp = cli_session_setup_get_principal(
			talloc_tos(), principal, remote_name, dest_realm);
		TALLOC_FREE(principal);
		principal = tmp;

		if (principal) {
			subreq = cli_session_setup_kerberos_send(
				state, ev, cli, principal);
			if (tevent_req_nomem(subreq, req)) {
				return tevent_req_post(req, ev);
			}
			tevent_req_set_callback(
				subreq, cli_session_setup_spnego_done_krb,
				req);
			return req;
		}
	}
#endif

ntlmssp:
	subreq = cli_session_setup_ntlmssp_send(
		state, ev, cli, state->account, pass, user_domain);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(
		subreq, cli_session_setup_spnego_done_ntlmssp, req);
	return req;
}

#ifdef HAVE_KRB5
static void cli_session_setup_spnego_done_krb(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_setup_spnego_state *state = tevent_req_data(
		req, struct cli_session_setup_spnego_state);

	state->result = cli_session_setup_kerberos_recv(subreq);
	TALLOC_FREE(subreq);

	if (ADS_ERR_OK(state->result) ||
	    !state->cli->fallback_after_kerberos) {
		tevent_req_done(req);
		return;
	}

	subreq = cli_session_setup_ntlmssp_send(
		state, state->ev, state->cli, state->account, state->pass,
		state->user_domain);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_session_setup_spnego_done_ntlmssp,
				req);
}
#endif

static void cli_session_setup_spnego_done_ntlmssp(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_setup_spnego_state *state = tevent_req_data(
		req, struct cli_session_setup_spnego_state);
	NTSTATUS status;

	status = cli_session_setup_ntlmssp_recv(subreq);
	TALLOC_FREE(subreq);
	state->result = ADS_ERROR_NT(status);
	tevent_req_done(req);
}

static ADS_STATUS cli_session_setup_spnego_recv(struct tevent_req *req)
{
	struct cli_session_setup_spnego_state *state = tevent_req_data(
		req, struct cli_session_setup_spnego_state);

	return state->result;
}

struct cli_session_setup_state {
	uint8_t dummy;
};

static void cli_session_setup_done_lanman2(struct tevent_req *subreq);
static void cli_session_setup_done_spnego(struct tevent_req *subreq);
static void cli_session_setup_done_guest(struct tevent_req *subreq);
static void cli_session_setup_done_plain(struct tevent_req *subreq);
static void cli_session_setup_done_nt1(struct tevent_req *subreq);

/****************************************************************************
 Send a session setup. The username and workgroup is in UNIX character
 format and must be converted to DOS codepage format before sending. If the
 password is in plaintext, the same should be done.
****************************************************************************/

struct tevent_req *cli_session_setup_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct cli_state *cli,
					  const char *user,
					  const char *pass, int passlen,
					  const char *ntpass, int ntpasslen,
					  const char *workgroup)
{
	struct tevent_req *req, *subreq;
	struct cli_session_setup_state *state;
	char *p;
	char *user2;
	uint16_t sec_mode = smb1cli_conn_server_security_mode(cli->conn);

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_state);
	if (req == NULL) {
		return NULL;
	}

	if (user) {
		user2 = talloc_strdup(state, user);
	} else {
		user2 = talloc_strdup(state, "");
	}
	if (user2 == NULL) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
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
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		workgroup = user2;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_LANMAN1) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	/* now work out what sort of session setup we are going to
           do. I have split this into separate functions to make the
           flow a bit easier to understand (tridge) */

	/* if its an older server then we have to use the older request format */

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_NT1) {
		if (!lp_client_lanman_auth() && passlen != 24 && (*pass)) {
			DEBUG(1, ("Server requested LM password but 'client lanman auth = no'"
				  " or 'client ntlmv2 auth = yes'\n"));
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}

		if ((sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) == 0 &&
		    !lp_client_plaintext_auth() && (*pass)) {
			DEBUG(1, ("Server requested PLAINTEXT password but 'client plaintext auth = no'"
				  " or 'client ntlmv2 auth = yes'\n"));
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}

		subreq = cli_session_setup_lanman2_send(
			state, ev, cli, user, pass, passlen, workgroup);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_session_setup_done_lanman2,
					req);
		return req;
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		const char *remote_realm = cli_state_remote_realm(cli);

		subreq = cli_session_setup_spnego_send(
			state, ev, cli, user, pass, workgroup, remote_realm);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_session_setup_done_spnego,
					req);
		return req;
	}

	/* if no user is supplied then we have to do an anonymous connection.
	   passwords are ignored */

	if (!user || !*user) {
		subreq = cli_session_setup_guest_send(state, ev, cli);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_session_setup_done_guest,
					req);
		return req;
	}

	/* if the server is share level then send a plaintext null
           password at this point. The password is sent in the tree
           connect */

	if ((sec_mode & NEGOTIATE_SECURITY_USER_LEVEL) == 0) {
		subreq = cli_session_setup_plain_send(
			state, ev, cli, user, "", workgroup);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_session_setup_done_plain,
					req);
		return req;
	}

	/* if the server doesn't support encryption then we have to use 
	   plaintext. The second password is ignored */

	if ((sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) == 0) {
		if (!lp_client_plaintext_auth() && (*pass)) {
			DEBUG(1, ("Server requested PLAINTEXT password but 'client plaintext auth = no'"
				  " or 'client ntlmv2 auth = yes'\n"));
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}
		subreq = cli_session_setup_plain_send(
			state, ev, cli, user, pass, workgroup);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_session_setup_done_plain,
					req);
		return req;
	}

	/* if the server supports extended security then use SPNEGO */

	if (smb1cli_conn_capabilities(cli->conn) & CAP_EXTENDED_SECURITY) {
		const char *remote_realm = cli_state_remote_realm(cli);

		subreq = cli_session_setup_spnego_send(
			state, ev, cli, user, pass, workgroup, remote_realm);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_session_setup_done_spnego,
					req);
		return req;
	} else {
		/* otherwise do a NT1 style session setup */

		subreq = cli_session_setup_nt1_send(
			state, ev, cli, user, pass, passlen, ntpass, ntpasslen,
			workgroup);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_session_setup_done_nt1,
					req);
		return req;
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void cli_session_setup_done_lanman2(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_session_setup_lanman2_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

static void cli_session_setup_done_spnego(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	ADS_STATUS status;

	status = cli_session_setup_spnego_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ADS_ERR_OK(status)) {
		DEBUG(3, ("SPNEGO login failed: %s\n", ads_errstr(status)));
		tevent_req_nterror(req, ads_ntstatus(status));
		return;
	}
	tevent_req_done(req);
}

static void cli_session_setup_done_guest(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_session_setup_guest_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

static void cli_session_setup_done_plain(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_session_setup_plain_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

static void cli_session_setup_done_nt1(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_session_setup_nt1_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("cli_session_setup: NT1 session setup "
			  "failed: %s\n", nt_errstr(status)));
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_session_setup_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_session_setup(struct cli_state *cli,
			   const char *user,
			   const char *pass, int passlen,
			   const char *ntpass, int ntpasslen,
			   const char *workgroup)
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
	req = cli_session_setup_send(ev, ev, cli, user, pass, passlen,
				     ntpass, ntpasslen, workgroup);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_session_setup_recv(req);
 fail:
	TALLOC_FREE(ev);
	return status;
}

/****************************************************************************
 Send a uloggoff.
*****************************************************************************/

struct cli_ulogoff_state {
	struct cli_state *cli;
	uint16_t vwv[3];
};

static void cli_ulogoff_done(struct tevent_req *subreq);

static struct tevent_req *cli_ulogoff_send(TALLOC_CTX *mem_ctx,
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

static NTSTATUS cli_ulogoff_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_ulogoff(struct cli_state *cli)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		status = smb2cli_logoff(cli->conn,
					cli->timeout,
					cli->smb2.session);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		smb2cli_session_set_id_and_flags(cli->smb2.session,
						 UINT64_MAX, 0);
		return NT_STATUS_OK;
	}

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	ev = samba_tevent_context_init(talloc_tos());
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
					struct tevent_context *ev,
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
				      struct tevent_context *ev,
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

	if ((wct > 2) && (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_LANMAN2)) {
		optional_support = SVAL(vwv+2, 0);
	}

	if (optional_support & SMB_EXTENDED_SIGNATURES) {
		smb1cli_session_protect_session_key(cli->smb1.session);
	}

	smb1cli_tcon_set_values(state->cli->smb1.tcon,
				SVAL(inhdr, HDR_TID),
				optional_support,
				0, /* maximal_access */
				0, /* guest_maximal_access */
				NULL, /* service */
				NULL); /* fs_type */

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
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}

	req = cli_tcon_andx_send(frame, ev, cli, share, dev, pass, passlen);
	if (req == NULL) {
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = cli_tcon_andx_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct cli_tree_connect_state {
	struct cli_state *cli;
};

static struct tevent_req *cli_raw_tcon_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	const char *service, const char *pass, const char *dev);
static NTSTATUS cli_raw_tcon_recv(struct tevent_req *req,
				  uint16 *max_xmit, uint16 *tid);

static void cli_tree_connect_smb2_done(struct tevent_req *subreq);
static void cli_tree_connect_andx_done(struct tevent_req *subreq);
static void cli_tree_connect_raw_done(struct tevent_req *subreq);

static struct tevent_req *cli_tree_connect_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	const char *share, const char *dev, const char *pass, int passlen)
{
	struct tevent_req *req, *subreq;
	struct cli_tree_connect_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_tree_connect_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	cli->share = talloc_strdup(cli, share);
	if (tevent_req_nomem(cli->share, req)) {
		return tevent_req_post(req, ev);
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		char *unc;

		cli->smb2.tcon = smbXcli_tcon_create(cli);
		if (tevent_req_nomem(cli->smb2.tcon, req)) {
			return tevent_req_post(req, ev);
		}

		unc = talloc_asprintf(state, "\\\\%s\\%s",
				      smbXcli_conn_remote_name(cli->conn),
				      share);
		if (tevent_req_nomem(unc, req)) {
			return tevent_req_post(req, ev);
		}

		subreq = smb2cli_tcon_send(state, ev, cli->conn, cli->timeout,
					   cli->smb2.session, cli->smb2.tcon,
					   0, /* flags */
					   unc);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_tree_connect_smb2_done,
					req);
		return req;
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_LANMAN1) {
		subreq = cli_tcon_andx_send(state, ev, cli, share, dev,
					    pass, passlen);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_tree_connect_andx_done,
					req);
		return req;
	}

	subreq = cli_raw_tcon_send(state, ev, cli, share, pass, dev);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_tree_connect_raw_done, req);

	return req;
}

static void cli_tree_connect_smb2_done(struct tevent_req *subreq)
{
	tevent_req_simple_finish_ntstatus(
		subreq, smb2cli_tcon_recv(subreq));
}

static void cli_tree_connect_andx_done(struct tevent_req *subreq)
{
	tevent_req_simple_finish_ntstatus(
		subreq, cli_tcon_andx_recv(subreq));
}

static void cli_tree_connect_raw_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_tree_connect_state *state = tevent_req_data(
		req, struct cli_tree_connect_state);
	NTSTATUS status;
	uint16_t max_xmit = 0;
	uint16_t tid = 0;

	status = cli_raw_tcon_recv(subreq, &max_xmit, &tid);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	smb1cli_tcon_set_values(state->cli->smb1.tcon,
				tid,
				0, /* optional_support */
				0, /* maximal_access */
				0, /* guest_maximal_access */
				NULL, /* service */
				NULL); /* fs_type */

	tevent_req_done(req);
}

static NTSTATUS cli_tree_connect_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_tree_connect(struct cli_state *cli, const char *share,
			  const char *dev, const char *pass, int passlen)
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
	req = cli_tree_connect_send(ev, ev, cli, share, dev, pass, passlen);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_tree_connect_recv(req);
fail:
	TALLOC_FREE(ev);
	return status;
}

/****************************************************************************
 Send a tree disconnect.
****************************************************************************/

struct cli_tdis_state {
	struct cli_state *cli;
};

static void cli_tdis_done(struct tevent_req *subreq);

static struct tevent_req *cli_tdis_send(TALLOC_CTX *mem_ctx,
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

static NTSTATUS cli_tdis_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_tdis(struct cli_state *cli)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return smb2cli_tdis(cli->conn,
				    cli->timeout,
				    cli->smb2.session,
				    cli->smb2.tcon);
	}

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	ev = samba_tevent_context_init(talloc_tos());
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

struct cli_connect_sock_state {
	const char **called_names;
	const char **calling_names;
	int *called_types;
	int fd;
	uint16_t port;
};

static void cli_connect_sock_done(struct tevent_req *subreq);

/*
 * Async only if we don't have to look up the name, i.e. "pss" is set with a
 * nonzero address.
 */

static struct tevent_req *cli_connect_sock_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *host, int name_type, const struct sockaddr_storage *pss,
	const char *myname, uint16_t port)
{
	struct tevent_req *req, *subreq;
	struct cli_connect_sock_state *state;
	const char *prog;
	struct sockaddr_storage *addrs;
	unsigned i, num_addrs;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_connect_sock_state);
	if (req == NULL) {
		return NULL;
	}

	prog = getenv("LIBSMB_PROG");
	if (prog != NULL) {
		state->fd = sock_exec(prog);
		if (state->fd == -1) {
			status = map_nt_error_from_unix(errno);
			tevent_req_nterror(req, status);
		} else {
			state->port = 0;
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
	}

	if ((pss == NULL) || is_zero_addr(pss)) {

		/*
		 * Here we cheat. resolve_name_list is not async at all. So
		 * this call will only be really async if the name lookup has
		 * been done externally.
		 */

		status = resolve_name_list(state, host, name_type,
					   &addrs, &num_addrs);
		if (!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
	} else {
		addrs = talloc_array(state, struct sockaddr_storage, 1);
		if (tevent_req_nomem(addrs, req)) {
			return tevent_req_post(req, ev);
		}
		addrs[0] = *pss;
		num_addrs = 1;
	}

	state->called_names = talloc_array(state, const char *, num_addrs);
	if (tevent_req_nomem(state->called_names, req)) {
		return tevent_req_post(req, ev);
	}
	state->called_types = talloc_array(state, int, num_addrs);
	if (tevent_req_nomem(state->called_types, req)) {
		return tevent_req_post(req, ev);
	}
	state->calling_names = talloc_array(state, const char *, num_addrs);
	if (tevent_req_nomem(state->calling_names, req)) {
		return tevent_req_post(req, ev);
	}
	for (i=0; i<num_addrs; i++) {
		state->called_names[i] = host;
		state->called_types[i] = name_type;
		state->calling_names[i] = myname;
	}

	subreq = smbsock_any_connect_send(
		state, ev, addrs, state->called_names, state->called_types,
		state->calling_names, NULL, num_addrs, port);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_connect_sock_done, req);
	return req;
}

static void cli_connect_sock_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_connect_sock_state *state = tevent_req_data(
		req, struct cli_connect_sock_state);
	NTSTATUS status;

	status = smbsock_any_connect_recv(subreq, &state->fd, NULL,
					  &state->port);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	set_socket_options(state->fd, lp_socket_options());
	tevent_req_done(req);
}

static NTSTATUS cli_connect_sock_recv(struct tevent_req *req,
				      int *pfd, uint16_t *pport)
{
	struct cli_connect_sock_state *state = tevent_req_data(
		req, struct cli_connect_sock_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pfd = state->fd;
	*pport = state->port;
	return NT_STATUS_OK;
}

struct cli_connect_nb_state {
	const char *desthost;
	int signing_state;
	int flags;
	struct cli_state *cli;
};

static void cli_connect_nb_done(struct tevent_req *subreq);

static struct tevent_req *cli_connect_nb_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *host, const struct sockaddr_storage *dest_ss,
	uint16_t port, int name_type, const char *myname,
	int signing_state, int flags)
{
	struct tevent_req *req, *subreq;
	struct cli_connect_nb_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_connect_nb_state);
	if (req == NULL) {
		return NULL;
	}
	state->signing_state = signing_state;
	state->flags = flags;

	if (host != NULL) {
		char *p = strchr(host, '#');

		if (p != NULL) {
			name_type = strtol(p+1, NULL, 16);
			host = talloc_strndup(state, host, p - host);
			if (tevent_req_nomem(host, req)) {
				return tevent_req_post(req, ev);
			}
		}

		state->desthost = host;
	} else {
		state->desthost = print_canonical_sockaddr(state, dest_ss);
		if (tevent_req_nomem(state->desthost, req)) {
			return tevent_req_post(req, ev);
		}
	}

	subreq = cli_connect_sock_send(state, ev, host, name_type, dest_ss,
				       myname, port);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_connect_nb_done, req);
	return req;
}

static void cli_connect_nb_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_connect_nb_state *state = tevent_req_data(
		req, struct cli_connect_nb_state);
	NTSTATUS status;
	int fd = 0;
	uint16_t port;

	status = cli_connect_sock_recv(subreq, &fd, &port);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->cli = cli_state_create(state, fd, state->desthost, NULL,
				      state->signing_state, state->flags);
	if (tevent_req_nomem(state->cli, req)) {
		close(fd);
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS cli_connect_nb_recv(struct tevent_req *req,
				    struct cli_state **pcli)
{
	struct cli_connect_nb_state *state = tevent_req_data(
		req, struct cli_connect_nb_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pcli = talloc_move(NULL, &state->cli);
	return NT_STATUS_OK;
}

NTSTATUS cli_connect_nb(const char *host, const struct sockaddr_storage *dest_ss,
			uint16_t port, int name_type, const char *myname,
			int signing_state, int flags, struct cli_state **pcli)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_connect_nb_send(ev, ev, host, dest_ss, port, name_type,
				  myname, signing_state, flags);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_set_endtime(req, ev, timeval_current_ofs(20, 0))) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_connect_nb_recv(req, pcli);
fail:
	TALLOC_FREE(ev);
	return status;
}

struct cli_start_connection_state {
	struct tevent_context *ev;
	struct cli_state *cli;
};

static void cli_start_connection_connected(struct tevent_req *subreq);
static void cli_start_connection_done(struct tevent_req *subreq);

/**
   establishes a connection to after the negprot. 
   @param output_cli A fully initialised cli structure, non-null only on success
   @param dest_host The netbios name of the remote host
   @param dest_ss (optional) The the destination IP, NULL for name based lookup
   @param port (optional) The destination port (0 for default)
*/

static struct tevent_req *cli_start_connection_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *my_name, const char *dest_host,
	const struct sockaddr_storage *dest_ss, int port,
	int signing_state, int flags)
{
	struct tevent_req *req, *subreq;
	struct cli_start_connection_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_start_connection_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	subreq = cli_connect_nb_send(state, ev, dest_host, dest_ss, port,
				     0x20, my_name, signing_state, flags);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_start_connection_connected, req);
	return req;
}

static void cli_start_connection_connected(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_start_connection_state *state = tevent_req_data(
		req, struct cli_start_connection_state);
	NTSTATUS status;

	status = cli_connect_nb_recv(subreq, &state->cli);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = smbXcli_negprot_send(state, state->ev, state->cli->conn,
				      state->cli->timeout,
				      lp_client_min_protocol(),
				      lp_client_max_protocol());
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_start_connection_done, req);
}

static void cli_start_connection_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_start_connection_state *state = tevent_req_data(
		req, struct cli_start_connection_state);
	NTSTATUS status;

	status = smbXcli_negprot_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		/* Ensure we ask for some initial credits. */
		smb2cli_conn_set_max_credits(state->cli->conn,
					     DEFAULT_SMB2_MAX_CREDITS);
	}

	tevent_req_done(req);
}

static NTSTATUS cli_start_connection_recv(struct tevent_req *req,
					  struct cli_state **output_cli)
{
	struct cli_start_connection_state *state = tevent_req_data(
		req, struct cli_start_connection_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*output_cli = state->cli;

	return NT_STATUS_OK;
}

NTSTATUS cli_start_connection(struct cli_state **output_cli, 
			      const char *my_name, 
			      const char *dest_host, 
			      const struct sockaddr_storage *dest_ss, int port,
			      int signing_state, int flags)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_start_connection_send(ev, ev, my_name, dest_host, dest_ss,
					port, signing_state, flags);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_start_connection_recv(req, output_cli);
fail:
	TALLOC_FREE(ev);
	return status;
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

struct cli_full_connection_state {
	struct tevent_context *ev;
	const char *service;
	const char *service_type;
	const char *user;
	const char *domain;
	const char *password;
	int pw_len;
	int flags;
	struct cli_state *cli;
};

static int cli_full_connection_state_destructor(
	struct cli_full_connection_state *s);
static void cli_full_connection_started(struct tevent_req *subreq);
static void cli_full_connection_sess_set_up(struct tevent_req *subreq);
static void cli_full_connection_done(struct tevent_req *subreq);

struct tevent_req *cli_full_connection_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *my_name, const char *dest_host,
	const struct sockaddr_storage *dest_ss, int port,
	const char *service, const char *service_type,
	const char *user, const char *domain,
	const char *password, int flags, int signing_state)
{
	struct tevent_req *req, *subreq;
	struct cli_full_connection_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_full_connection_state);
	if (req == NULL) {
		return NULL;
	}
	talloc_set_destructor(state, cli_full_connection_state_destructor);

	state->ev = ev;
	state->service = service;
	state->service_type = service_type;
	state->user = user;
	state->domain = domain;
	state->password = password;
	state->flags = flags;

	state->pw_len = state->password ? strlen(state->password)+1 : 0;
	if (state->password == NULL) {
		state->password = "";
	}

	subreq = cli_start_connection_send(
		state, ev, my_name, dest_host, dest_ss, port,
		signing_state, flags);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_full_connection_started, req);
	return req;
}

static int cli_full_connection_state_destructor(
	struct cli_full_connection_state *s)
{
	if (s->cli != NULL) {
		cli_shutdown(s->cli);
		s->cli = NULL;
	}
	return 0;
}

static void cli_full_connection_started(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_full_connection_state *state = tevent_req_data(
		req, struct cli_full_connection_state);
	NTSTATUS status;

	status = cli_start_connection_recv(subreq, &state->cli);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = cli_session_setup_send(
		state, state->ev, state->cli, state->user,
		state->password, state->pw_len, state->password, state->pw_len,
		state->domain);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_full_connection_sess_set_up, req);
}

static void cli_full_connection_sess_set_up(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_full_connection_state *state = tevent_req_data(
		req, struct cli_full_connection_state);
	NTSTATUS status;

	status = cli_session_setup_recv(subreq);
	TALLOC_FREE(subreq);

	if (!NT_STATUS_IS_OK(status) &&
	    (state->flags & CLI_FULL_CONNECTION_ANONYMOUS_FALLBACK)) {

		state->flags &= ~CLI_FULL_CONNECTION_ANONYMOUS_FALLBACK;

		subreq = cli_session_setup_send(
			state, state->ev, state->cli, "", "", 0, "", 0,
			state->domain);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(
			subreq, cli_full_connection_sess_set_up, req);
		return;
	}

	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->service != NULL) {
		subreq = cli_tree_connect_send(
			state, state->ev, state->cli,
			state->service, state->service_type,
			state->password, state->pw_len);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, cli_full_connection_done, req);
		return;
	}

	status = cli_init_creds(state->cli, state->user, state->domain,
				state->password);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static void cli_full_connection_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_full_connection_state *state = tevent_req_data(
		req, struct cli_full_connection_state);
	NTSTATUS status;

	status = cli_tree_connect_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	status = cli_init_creds(state->cli, state->user, state->domain,
				state->password);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_full_connection_recv(struct tevent_req *req,
				  struct cli_state **output_cli)
{
	struct cli_full_connection_state *state = tevent_req_data(
		req, struct cli_full_connection_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*output_cli = state->cli;
	talloc_set_destructor(state, NULL);
	return NT_STATUS_OK;
}

NTSTATUS cli_full_connection(struct cli_state **output_cli,
			     const char *my_name,
			     const char *dest_host,
			     const struct sockaddr_storage *dest_ss, int port,
			     const char *service, const char *service_type,
			     const char *user, const char *domain,
			     const char *password, int flags,
			     int signing_state)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_full_connection_send(
		ev, ev, my_name, dest_host, dest_ss, port, service,
		service_type, user, domain, password, flags, signing_state);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_full_connection_recv(req, output_cli);
 fail:
	TALLOC_FREE(ev);
	return status;
}

/****************************************************************************
 Send an old style tcon.
****************************************************************************/
struct cli_raw_tcon_state {
	uint16_t *ret_vwv;
};

static void cli_raw_tcon_done(struct tevent_req *subreq);

static struct tevent_req *cli_raw_tcon_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	const char *service, const char *pass, const char *dev)
{
	struct tevent_req *req, *subreq;
	struct cli_raw_tcon_state *state;
	uint8_t *bytes;

	req = tevent_req_create(mem_ctx, &state, struct cli_raw_tcon_state);
	if (req == NULL) {
		return NULL;
	}

	if (!lp_client_plaintext_auth() && (*pass)) {
		DEBUG(1, ("Server requested PLAINTEXT password but 'client plaintext auth = no'"
			  " or 'client ntlmv2 auth = yes'\n"));
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return tevent_req_post(req, ev);
	}

	bytes = talloc_array(state, uint8_t, 0);
	bytes = smb_bytes_push_bytes(bytes, 4, NULL, 0);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   service, strlen(service)+1, NULL);
	bytes = smb_bytes_push_bytes(bytes, 4, NULL, 0);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   pass, strlen(pass)+1, NULL);
	bytes = smb_bytes_push_bytes(bytes, 4, NULL, 0);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn),
				   dev, strlen(dev)+1, NULL);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBtcon, 0, 0, NULL,
			      talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_raw_tcon_done, req);
	return req;
}

static void cli_raw_tcon_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_raw_tcon_state *state = tevent_req_data(
		req, struct cli_raw_tcon_state);
	NTSTATUS status;

	status = cli_smb_recv(subreq, state, NULL, 2, NULL, &state->ret_vwv,
			      NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS cli_raw_tcon_recv(struct tevent_req *req,
				  uint16 *max_xmit, uint16 *tid)
{
	struct cli_raw_tcon_state *state = tevent_req_data(
		req, struct cli_raw_tcon_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*max_xmit = SVAL(state->ret_vwv + 0, 0);
	*tid = SVAL(state->ret_vwv + 1, 0);
	return NT_STATUS_OK;
}

NTSTATUS cli_raw_tcon(struct cli_state *cli,
		      const char *service, const char *pass, const char *dev,
		      uint16 *max_xmit, uint16 *tid)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_raw_tcon_send(ev, ev, cli, service, pass, dev);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_raw_tcon_recv(req, max_xmit, tid);
fail:
	TALLOC_FREE(ev);
	return status;
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
