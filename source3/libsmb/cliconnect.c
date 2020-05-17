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
#include "libsmb/namequery.h"
#include "auth_info.h"
#include "../libcli/auth/libcli_auth.h"
#include "../libcli/auth/spnego.h"
#include "smb_krb5.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "auth_generic.h"
#include "libads/kerberos_proto.h"
#include "krb5_env.h"
#include "../lib/util/tevent_ntstatus.h"
#include "async_smb.h"
#include "libsmb/nmblib.h"
#include "librpc/ndr/libndr.h"
#include "../libcli/smb/smbXcli_base.h"
#include "../libcli/smb/smb_seal.h"
#include "lib/param/param.h"
#include "../libcli/smb/smb2_negotiate_context.h"

#define STAR_SMBSERVER "*SMBSERVER"

static char *cli_session_setup_get_account(TALLOC_CTX *mem_ctx,
					   const char *principal);

struct cli_credentials *cli_session_creds_init(TALLOC_CTX *mem_ctx,
					       const char *username,
					       const char *domain,
					       const char *realm,
					       const char *password,
					       bool use_kerberos,
					       bool fallback_after_kerberos,
					       bool use_ccache,
					       bool password_is_nt_hash)
{
	struct loadparm_context *lp_ctx = NULL;
	struct cli_credentials *creds = NULL;
	const char *principal = NULL;
	char *tmp = NULL;
	char *p = NULL;
	bool ok;

	creds = cli_credentials_init(mem_ctx);
	if (creds == NULL) {
		return NULL;
	}

	lp_ctx = loadparm_init_s3(creds, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		goto fail;
	}
	cli_credentials_set_conf(creds, lp_ctx);

	if (username == NULL) {
		username = "";
	}

	if (strlen(username) == 0) {
		if (password != NULL && strlen(password) == 0) {
			/*
			 * some callers pass "" as no password
			 *
			 * gensec only handles NULL as no password.
			 */
			password = NULL;
		}
		if (password == NULL) {
			cli_credentials_set_anonymous(creds);
			return creds;
		}
	}

	tmp = talloc_strdup(creds, username);
	if (tmp == NULL) {
		goto fail;
	}
	username = tmp;

	/* allow for workgroups as part of the username */
	if ((p = strchr_m(tmp, '\\')) ||
	    (p = strchr_m(tmp, '/')) ||
	    (p = strchr_m(tmp, *lp_winbind_separator()))) {
		*p = 0;
		username = p + 1;
		domain = tmp;
	}

	principal = username;
	username = cli_session_setup_get_account(creds, principal);
	if (username == NULL) {
		goto fail;
	}
	ok = strequal(username, principal);
	if (ok) {
		/*
		 * Ok still the same, so it's not a principal
		 */
		principal = NULL;
	}

	if (use_kerberos && fallback_after_kerberos) {
		cli_credentials_set_kerberos_state(creds,
						   CRED_AUTO_USE_KERBEROS);
	} else if (use_kerberos) {
		cli_credentials_set_kerberos_state(creds,
						   CRED_MUST_USE_KERBEROS);
	} else {
		cli_credentials_set_kerberos_state(creds,
						   CRED_DONT_USE_KERBEROS);
	}

	if (use_ccache) {
		uint32_t features;

		features = cli_credentials_get_gensec_features(creds);
		features |= GENSEC_FEATURE_NTLM_CCACHE;
		cli_credentials_set_gensec_features(creds, features);

		if (password != NULL && strlen(password) == 0) {
			/*
			 * some callers pass "" as no password
			 *
			 * GENSEC_FEATURE_NTLM_CCACHE only handles
			 * NULL as no password.
			 */
			password = NULL;
		}
	}

	ok = cli_credentials_set_username(creds,
					  username,
					  CRED_SPECIFIED);
	if (!ok) {
		goto fail;
	}

	if (domain != NULL) {
		ok = cli_credentials_set_domain(creds,
						domain,
						CRED_SPECIFIED);
		if (!ok) {
			goto fail;
		}
	}

	if (principal != NULL) {
		ok = cli_credentials_set_principal(creds,
						   principal,
						   CRED_SPECIFIED);
		if (!ok) {
			goto fail;
		}
	}

	if (realm != NULL) {
		ok = cli_credentials_set_realm(creds,
					       realm,
					       CRED_SPECIFIED);
		if (!ok) {
			goto fail;
		}
	}

	if (password != NULL && strlen(password) > 0) {
		if (password_is_nt_hash) {
			struct samr_Password nt_hash;
			size_t converted;

			converted = strhex_to_str((char *)nt_hash.hash,
						  sizeof(nt_hash.hash),
						  password,
						  strlen(password));
			if (converted != sizeof(nt_hash.hash)) {
				goto fail;
			}

			ok = cli_credentials_set_nt_hash(creds,
							 &nt_hash,
							 CRED_SPECIFIED);
			if (!ok) {
				goto fail;
			}
		} else {
			ok = cli_credentials_set_password(creds,
							  password,
							  CRED_SPECIFIED);
			if (!ok) {
				goto fail;
			}
		}
	}

	return creds;
fail:
	TALLOC_FREE(creds);
	return NULL;
}

NTSTATUS cli_session_creds_prepare_krb5(struct cli_state *cli,
					struct cli_credentials *creds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *user_principal = NULL;
	const char *user_account = NULL;
	const char *user_domain = NULL;
	const char *pass = NULL;
	char *canon_principal = NULL;
	char *canon_realm = NULL;
	const char *target_hostname = NULL;
	enum credentials_use_kerberos krb5_state;
	bool try_kerberos = false;
	bool need_kinit = false;
	bool auth_requested = true;
	int ret;
	bool ok;

	target_hostname = smbXcli_conn_remote_name(cli->conn);

	auth_requested = cli_credentials_authentication_requested(creds);
	if (auth_requested) {
		errno = 0;
		user_principal = cli_credentials_get_principal(creds, frame);
		if (errno != 0) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}
	user_account = cli_credentials_get_username(creds);
	user_domain = cli_credentials_get_domain(creds);
	pass = cli_credentials_get_password(creds);

	krb5_state = cli_credentials_get_kerberos_state(creds);

	if (krb5_state != CRED_DONT_USE_KERBEROS) {
		try_kerberos = true;
	}

	if (user_principal == NULL) {
		try_kerberos = false;
	}

	if (target_hostname == NULL) {
		try_kerberos = false;
	} else if (is_ipaddress(target_hostname)) {
		try_kerberos = false;
	} else if (strequal(target_hostname, "localhost")) {
		try_kerberos = false;
	} else if (strequal(target_hostname, STAR_SMBSERVER)) {
		try_kerberos = false;
	} else if (!auth_requested) {
		try_kerberos = false;
	}

	if (krb5_state == CRED_MUST_USE_KERBEROS && !try_kerberos) {
		DEBUG(0, ("Kerberos auth with '%s' (%s\\%s) to access "
			  "'%s' not possible\n",
			  user_principal, user_domain, user_account,
			  target_hostname));
		TALLOC_FREE(frame);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (pass == NULL || strlen(pass) == 0) {
		need_kinit = false;
	} else if (krb5_state == CRED_MUST_USE_KERBEROS) {
		need_kinit = try_kerberos;
	} else {
		need_kinit = try_kerberos;
	}

	if (!need_kinit) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	DBG_INFO("Doing kinit for %s to access %s\n",
		 user_principal, target_hostname);

	/*
	 * TODO: This should be done within the gensec layer
	 * only if required!
	 */
	setenv(KRB5_ENV_CCNAME, "MEMORY:cliconnect", 1);
	ret = kerberos_kinit_password_ext(user_principal,
					  pass,
					  0,
					  0,
					  0,
					  NULL,
					  false,
					  false,
					  0,
					  frame,
					  &canon_principal,
					  &canon_realm,
					  NULL);
	if (ret != 0) {
		int dbglvl = DBGLVL_NOTICE;

		if (krb5_state == CRED_MUST_USE_KERBEROS) {
			dbglvl = DBGLVL_ERR;
		}

		DEBUG(dbglvl, ("Kinit for %s to access %s failed: %s\n",
			       user_principal, target_hostname,
			       error_message(ret)));
		if (krb5_state == CRED_MUST_USE_KERBEROS) {
			TALLOC_FREE(frame);
			return krb5_to_nt_status(ret);
		}

		/*
		 * Ignore the error and hope that NTLM will work
		 */
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	ok = cli_credentials_set_principal(creds,
					   canon_principal,
					   CRED_SPECIFIED);
	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ok = cli_credentials_set_realm(creds,
				       canon_realm,
				       CRED_SPECIFIED);
	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	DBG_DEBUG("Successfully authenticated as %s (%s) to access %s using "
		  "Kerberos\n",
		  user_principal,
		  canon_principal,
		  target_hostname);

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static NTSTATUS cli_state_update_after_sesssetup(struct cli_state *cli,
						 const char *native_os,
						 const char *native_lm,
						 const char *primary_domain)
{
#define _VALID_STR(p) ((p) != NULL && (p)[0] != '\0')

	if (!_VALID_STR(cli->server_os) && _VALID_STR(native_os)) {
		cli->server_os = talloc_strdup(cli, native_os);
		if (cli->server_os == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (!_VALID_STR(cli->server_type) && _VALID_STR(native_lm)) {
		cli->server_type = talloc_strdup(cli, native_lm);
		if (cli->server_type == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (!_VALID_STR(cli->server_domain) && _VALID_STR(primary_domain)) {
		cli->server_domain = talloc_strdup(cli, primary_domain);
		if (cli->server_domain == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

#undef _VALID_STRING
	return NT_STATUS_OK;
}

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
	*destlen = pull_string_talloc(mem_ctx,
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

	subreq = cli_smb_req_create(state, ev, cli, SMBsesssetupX, 0, 0, 13,
			vwv, 1, &state->bytes);
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
	smb1cli_session_set_action(cli->smb1.session, SVAL(vwv+2, 0));

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

	tevent_req_done(req);
}

NTSTATUS cli_session_setup_guest_recv(struct tevent_req *req)
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

	DATA_BLOB this_blob;
	struct iovec *recv_iov;

	NTSTATUS status;
	const uint8_t *inbuf;
	DATA_BLOB ret_blob;

	char *out_native_os;
	char *out_native_lm;
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

	state->this_blob.data = state->blob.data;
	state->this_blob.length = thistime;

	state->blob.data += thistime;
	state->blob.length -= thistime;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		subreq = smb2cli_session_setup_send(state, state->ev,
						    state->cli->conn,
						    state->cli->timeout,
						    state->cli->smb2.session,
						    0, /* in_flags */
						    SMB2_CAP_DFS, /* in_capabilities */
						    0, /* in_channel */
						    0, /* in_previous_session_id */
						    &state->this_blob);
		if (subreq == NULL) {
			return false;
		}
	} else {
		uint16_t in_buf_size = 0;
		uint16_t in_mpx_max = 0;
		uint16_t in_vc_num = 0;
		uint32_t in_sess_key = 0;
		uint32_t in_capabilities = 0;
		const char *in_native_os = NULL;
		const char *in_native_lm = NULL;

		in_buf_size = CLI_BUFFER_SIZE;
		in_mpx_max = smbXcli_conn_max_requests(state->cli->conn);
		in_vc_num = cli_state_get_vc_num(state->cli);
		in_sess_key = smb1cli_conn_server_session_key(state->cli->conn);
		in_capabilities = cli_session_setup_capabilities(state->cli,
								CAP_EXTENDED_SECURITY);
		in_native_os = "Unix";
		in_native_lm = "Samba";

		/*
		 * For now we keep the same values as before,
		 * we may remove these in a separate commit later.
		 */
		in_mpx_max = 2;
		in_vc_num = 1;
		in_sess_key = 0;

		subreq = smb1cli_session_setup_ext_send(state, state->ev,
							state->cli->conn,
							state->cli->timeout,
							state->cli->smb1.pid,
							state->cli->smb1.session,
							in_buf_size,
							in_mpx_max,
							in_vc_num,
							in_sess_key,
							state->this_blob,
							in_capabilities,
							in_native_os,
							in_native_lm);
		if (subreq == NULL) {
			return false;
		}
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
	NTSTATUS status;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		status = smb2cli_session_setup_recv(subreq, state,
						    &state->recv_iov,
						    &state->ret_blob);
	} else {
		status = smb1cli_session_setup_ext_recv(subreq, state,
							&state->recv_iov,
							&state->inbuf,
							&state->ret_blob,
							&state->out_native_os,
							&state->out_native_lm);
	}
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return;
	}

	state->status = status;

	status = cli_state_update_after_sesssetup(state->cli,
						  state->out_native_os,
						  state->out_native_lm,
						  NULL);
	if (tevent_req_nterror(req, status)) {
		return;
	}

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
					const uint8_t **pinbuf,
					struct iovec **precv_iov)
{
	struct cli_sesssetup_blob_state *state = tevent_req_data(
		req, struct cli_sesssetup_blob_state);
	NTSTATUS status;
	struct iovec *recv_iov;

	if (tevent_req_is_nterror(req, &status)) {
		TALLOC_FREE(state->cli->smb2.session);
		cli_state_set_uid(state->cli, UID_FIELD_INVALID);
		tevent_req_received(req);
		return status;
	}

	recv_iov = talloc_move(mem_ctx, &state->recv_iov);
	if (pblob != NULL) {
		*pblob = state->ret_blob;
	}
	if (pinbuf != NULL) {
		*pinbuf = state->inbuf;
	}
	if (precv_iov != NULL) {
		*precv_iov = recv_iov;
	}
        /* could be NT_STATUS_MORE_PROCESSING_REQUIRED */
	status = state->status;
	tevent_req_received(req);
	return status;
}

/****************************************************************************
 Do a spnego/NTLMSSP encrypted session setup.
****************************************************************************/

struct cli_session_setup_gensec_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	struct auth_generic_state *auth_generic;
	bool is_anonymous;
	DATA_BLOB blob_in;
	const uint8_t *inbuf;
	struct iovec *recv_iov;
	DATA_BLOB blob_out;
	bool local_ready;
	bool remote_ready;
	DATA_BLOB session_key;
};

static int cli_session_setup_gensec_state_destructor(
	struct cli_session_setup_gensec_state *state)
{
	TALLOC_FREE(state->auth_generic);
	data_blob_clear_free(&state->session_key);
	return 0;
}

static void cli_session_setup_gensec_local_next(struct tevent_req *req);
static void cli_session_setup_gensec_local_done(struct tevent_req *subreq);
static void cli_session_setup_gensec_remote_next(struct tevent_req *req);
static void cli_session_setup_gensec_remote_done(struct tevent_req *subreq);
static void cli_session_setup_gensec_ready(struct tevent_req *req);

static struct tevent_req *cli_session_setup_gensec_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	struct cli_credentials *creds,
	const char *target_service,
	const char *target_hostname)
{
	struct tevent_req *req;
	struct cli_session_setup_gensec_state *state;
	NTSTATUS status;
	const DATA_BLOB *b = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_gensec_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	talloc_set_destructor(
		state, cli_session_setup_gensec_state_destructor);

	status = auth_generic_client_prepare(state, &state->auth_generic);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = auth_generic_set_creds(state->auth_generic, creds);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	gensec_want_feature(state->auth_generic->gensec_security,
			    GENSEC_FEATURE_SESSION_KEY);

	if (target_service != NULL) {
		status = gensec_set_target_service(
				state->auth_generic->gensec_security,
				target_service);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	if (target_hostname != NULL) {
		status = gensec_set_target_hostname(
				state->auth_generic->gensec_security,
				target_hostname);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	b = smbXcli_conn_server_gss_blob(cli->conn);
	if (b != NULL) {
		state->blob_in = *b;
	}

	state->is_anonymous = cli_credentials_is_anonymous(state->auth_generic->credentials);

	status = auth_generic_client_start(state->auth_generic,
					   GENSEC_OID_SPNEGO);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		state->cli->smb2.session = smbXcli_session_create(cli,
								  cli->conn);
		if (tevent_req_nomem(state->cli->smb2.session, req)) {
			return tevent_req_post(req, ev);
		}
	}

	cli_session_setup_gensec_local_next(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void cli_session_setup_gensec_local_next(struct tevent_req *req)
{
	struct cli_session_setup_gensec_state *state =
		tevent_req_data(req,
		struct cli_session_setup_gensec_state);
	struct tevent_req *subreq = NULL;

	if (state->local_ready) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	subreq = gensec_update_send(state, state->ev,
			state->auth_generic->gensec_security,
			state->blob_in);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_session_setup_gensec_local_done, req);
}

static void cli_session_setup_gensec_local_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct cli_session_setup_gensec_state *state =
		tevent_req_data(req,
		struct cli_session_setup_gensec_state);
	NTSTATUS status;

	status = gensec_update_recv(subreq, state, &state->blob_out);
	TALLOC_FREE(subreq);
	state->blob_in = data_blob_null;
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED))
	{
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_IS_OK(status)) {
		state->local_ready = true;
	}

	if (state->local_ready && state->remote_ready) {
		cli_session_setup_gensec_ready(req);
		return;
	}

	cli_session_setup_gensec_remote_next(req);
}

static void cli_session_setup_gensec_remote_next(struct tevent_req *req)
{
	struct cli_session_setup_gensec_state *state =
		tevent_req_data(req,
		struct cli_session_setup_gensec_state);
	struct tevent_req *subreq = NULL;

	if (state->remote_ready) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	subreq = cli_sesssetup_blob_send(state, state->ev,
					 state->cli, state->blob_out);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				cli_session_setup_gensec_remote_done,
				req);
}

static void cli_session_setup_gensec_remote_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct cli_session_setup_gensec_state *state =
		tevent_req_data(req,
		struct cli_session_setup_gensec_state);
	NTSTATUS status;

	state->inbuf = NULL;
	TALLOC_FREE(state->recv_iov);

	status = cli_sesssetup_blob_recv(subreq, state, &state->blob_in,
					 &state->inbuf, &state->recv_iov);
	TALLOC_FREE(subreq);
	data_blob_free(&state->blob_out);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED))
	{
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_IS_OK(status)) {
		struct smbXcli_session *session = NULL;
		bool is_guest = false;

		if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
			session = state->cli->smb2.session;
		} else {
			session = state->cli->smb1.session;
		}

		is_guest = smbXcli_session_is_guest(session);
		if (is_guest) {
			/*
			 * We can't finish the gensec handshake, we don't
			 * have a negotiated session key.
			 *
			 * So just pretend we are completely done,
			 * we need to continue as anonymous from this point,
			 * as we can't get a session key.
			 *
			 * Note that smbXcli_session_is_guest()
			 * always returns false if we require signing.
			 */
			state->blob_in = data_blob_null;
			state->local_ready = true;
			state->is_anonymous = true;
		}

		state->remote_ready = true;
	}

	if (state->local_ready && state->remote_ready) {
		cli_session_setup_gensec_ready(req);
		return;
	}

	cli_session_setup_gensec_local_next(req);
}

static void cli_session_dump_keys(TALLOC_CTX *mem_ctx,
				  struct smbXcli_session *session,
				  DATA_BLOB session_key)
{
	NTSTATUS status;
	DATA_BLOB sig = data_blob_null;
	DATA_BLOB app = data_blob_null;
	DATA_BLOB enc = data_blob_null;
	DATA_BLOB dec = data_blob_null;
	uint64_t sid = smb2cli_session_current_id(session);

	status = smb2cli_session_signing_key(session, mem_ctx, &sig);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	status = smbXcli_session_application_key(session, mem_ctx, &app);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	status = smb2cli_session_encryption_key(session, mem_ctx, &enc);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	status = smb2cli_session_decryption_key(session, mem_ctx, &dec);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	DEBUG(0, ("debug encryption: dumping generated session keys\n"));
	DEBUGADD(0, ("Session Id    "));
	dump_data(0, (uint8_t*)&sid, sizeof(sid));
	DEBUGADD(0, ("Session Key   "));
	dump_data(0, session_key.data, session_key.length);
	DEBUGADD(0, ("Signing Key   "));
	dump_data(0, sig.data, sig.length);
	DEBUGADD(0, ("App Key       "));
	dump_data(0, app.data, app.length);

	/* In client code, ServerIn is the encryption key */

	DEBUGADD(0, ("ServerIn Key  "));
	dump_data(0, enc.data, enc.length);
	DEBUGADD(0, ("ServerOut Key "));
	dump_data(0, dec.data, dec.length);

out:
	data_blob_clear_free(&sig);
	data_blob_clear_free(&app);
	data_blob_clear_free(&enc);
	data_blob_clear_free(&dec);
}

static void cli_session_setup_gensec_ready(struct tevent_req *req)
{
	struct cli_session_setup_gensec_state *state =
		tevent_req_data(req,
		struct cli_session_setup_gensec_state);
	const char *server_domain = NULL;
	NTSTATUS status;

	if (state->blob_in.length != 0) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (state->blob_out.length != 0) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	/*
	 * gensec_ntlmssp_server_domain() returns NULL
	 * if NTLMSSP is not used.
	 *
	 * We can remove this later
	 * and leave the server domain empty for SMB2 and above
	 * in future releases.
	 */
	server_domain = gensec_ntlmssp_server_domain(
				state->auth_generic->gensec_security);

	if (state->cli->server_domain[0] == '\0' && server_domain != NULL) {
		TALLOC_FREE(state->cli->server_domain);
		state->cli->server_domain = talloc_strdup(state->cli,
					server_domain);
		if (state->cli->server_domain == NULL) {
			tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
			return;
		}
	}

	if (state->is_anonymous) {
		/*
		 * Windows server does not set the
		 * SMB2_SESSION_FLAG_IS_NULL flag.
		 *
		 * This fix makes sure we do not try
		 * to verify a signature on the final
		 * session setup response.
		 */
		tevent_req_done(req);
		return;
	}

	status = gensec_session_key(state->auth_generic->gensec_security,
				    state, &state->session_key);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		struct smbXcli_session *session = state->cli->smb2.session;

		status = smb2cli_session_set_session_key(session,
							 state->session_key,
							 state->recv_iov);
		if (tevent_req_nterror(req, status)) {
			return;
		}
		if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB3_00
		    && lp_debug_encryption())
		{
			cli_session_dump_keys(state, session, state->session_key);
		}
	} else {
		struct smbXcli_session *session = state->cli->smb1.session;
		bool active;

		status = smb1cli_session_set_session_key(session,
							 state->session_key);
		if (tevent_req_nterror(req, status)) {
			return;
		}

		active = smb1cli_conn_activate_signing(state->cli->conn,
						       state->session_key,
						       data_blob_null);
		if (active) {
			bool ok;

			ok = smb1cli_conn_check_signing(state->cli->conn,
							state->inbuf, 1);
			if (!ok) {
				tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
				return;
			}
		}
	}

	tevent_req_done(req);
}

static NTSTATUS cli_session_setup_gensec_recv(struct tevent_req *req)
{
	struct cli_session_setup_gensec_state *state =
		tevent_req_data(req,
		struct cli_session_setup_gensec_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		cli_state_set_uid(state->cli, UID_FIELD_INVALID);
		return status;
	}
	return NT_STATUS_OK;
}

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
	ADS_STATUS result;
};

static void cli_session_setup_spnego_done(struct tevent_req *subreq);

static struct tevent_req *cli_session_setup_spnego_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	struct cli_credentials *creds)
{
	struct tevent_req *req, *subreq;
	struct cli_session_setup_spnego_state *state;
	const char *target_service = NULL;
	const char *target_hostname = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_spnego_state);
	if (req == NULL) {
		return NULL;
	}

	target_service = "cifs";
	target_hostname = smbXcli_conn_remote_name(cli->conn);

	status = cli_session_creds_prepare_krb5(cli, creds);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	DBG_INFO("Connect to %s as %s using SPNEGO\n",
		 target_hostname,
		 cli_credentials_get_principal(creds, talloc_tos()));

	subreq = cli_session_setup_gensec_send(state, ev, cli, creds,
					       target_service, target_hostname);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(
		subreq, cli_session_setup_spnego_done, req);
	return req;
}

static void cli_session_setup_spnego_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_session_setup_gensec_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

static ADS_STATUS cli_session_setup_spnego_recv(struct tevent_req *req)
{
	struct cli_session_setup_spnego_state *state = tevent_req_data(
		req, struct cli_session_setup_spnego_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		state->result = ADS_ERROR_NT(status);
	}

	return state->result;
}

struct cli_session_setup_creds_state {
	struct cli_state *cli;
	DATA_BLOB apassword_blob;
	DATA_BLOB upassword_blob;
	DATA_BLOB lm_session_key;
	DATA_BLOB session_key;
	char *out_native_os;
	char *out_native_lm;
	char *out_primary_domain;
};

static void cli_session_setup_creds_cleanup(struct tevent_req *req,
					    enum tevent_req_state req_state)
{
	struct cli_session_setup_creds_state *state = tevent_req_data(
		req, struct cli_session_setup_creds_state);

	if (req_state != TEVENT_REQ_RECEIVED) {
		return;
	}

	/*
	 * We only call data_blob_clear() as
	 * some of the blobs point to the same memory.
	 *
	 * We let the talloc hierarchy free the memory.
	 */
	data_blob_clear(&state->apassword_blob);
	data_blob_clear(&state->upassword_blob);
	data_blob_clear(&state->lm_session_key);
	data_blob_clear(&state->session_key);
	ZERO_STRUCTP(state);
}

static void cli_session_setup_creds_done_spnego(struct tevent_req *subreq);
static void cli_session_setup_creds_done_nt1(struct tevent_req *subreq);
static void cli_session_setup_creds_done_lm21(struct tevent_req *subreq);

/****************************************************************************
 Send a session setup. The username and workgroup is in UNIX character
 format and must be converted to DOS codepage format before sending. If the
 password is in plaintext, the same should be done.
****************************************************************************/

struct tevent_req *cli_session_setup_creds_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					struct cli_credentials *creds)
{
	struct tevent_req *req, *subreq;
	struct cli_session_setup_creds_state *state;
	uint16_t sec_mode = smb1cli_conn_server_security_mode(cli->conn);
	bool use_spnego = false;
	int flags = 0;
	const char *username = "";
	const char *domain = "";
	DATA_BLOB target_info = data_blob_null;
	DATA_BLOB challenge = data_blob_null;
	uint16_t in_buf_size = 0;
	uint16_t in_mpx_max = 0;
	uint16_t in_vc_num = 0;
	uint32_t in_sess_key = 0;
	const char *in_native_os = NULL;
	const char *in_native_lm = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_setup_creds_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	tevent_req_set_cleanup_fn(req, cli_session_setup_creds_cleanup);

	/*
	 * Now work out what sort of session setup we are going to
	 * do. I have split this into separate functions to make the flow a bit
	 * easier to understand (tridge).
	 */
	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_NT1) {
		use_spnego = false;
	} else if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		use_spnego = true;
	} else if (smb1cli_conn_capabilities(cli->conn) & CAP_EXTENDED_SECURITY) {
		/*
		 * if the server supports extended security then use SPNEGO
		 * even for anonymous connections.
		 */
		use_spnego = true;
	} else {
		use_spnego = false;
	}

	if (use_spnego) {
		subreq = cli_session_setup_spnego_send(
			state, ev, cli, creds);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_session_setup_creds_done_spnego,
					req);
		return req;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_LANMAN1) {
		/*
		 * SessionSetupAndX was introduced by LANMAN 1.0. So we skip
		 * this step against older servers.
		 */
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (cli_credentials_is_anonymous(creds)) {
		/*
		 * Do an anonymous session setup
		 */
		goto non_spnego_creds_done;
	}

	if ((sec_mode & NEGOTIATE_SECURITY_USER_LEVEL) == 0) {
		/*
		 * Do an anonymous session setup,
		 * the password is passed via the tree connect.
		 */
		goto non_spnego_creds_done;
	}

	cli_credentials_get_ntlm_username_domain(creds, state,
						 &username,
						 &domain);
	if (tevent_req_nomem(username, req)) {
		return tevent_req_post(req, ev);
	}
	if (tevent_req_nomem(domain, req)) {
		return tevent_req_post(req, ev);
	}

	DBG_INFO("Connect to %s as %s using NTLM\n", domain, username);

	if ((sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) == 0) {
		bool use_unicode = smbXcli_conn_use_unicode(cli->conn);
		uint8_t *bytes = NULL;
		size_t bytes_len = 0;
		const char *pw = cli_credentials_get_password(creds);
		size_t pw_len = 0;

		if (pw == NULL) {
			pw = "";
		}
		pw_len = strlen(pw) + 1;

		if (!lp_client_plaintext_auth()) {
			DEBUG(1, ("Server requested PLAINTEXT password but "
				  "'client plaintext auth = no'\n"));
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}

		bytes = talloc_array(state, uint8_t, 0);
		bytes = trans2_bytes_push_str(bytes, use_unicode,
					      pw, pw_len, &bytes_len);
		if (tevent_req_nomem(bytes, req)) {
			return tevent_req_post(req, ev);
		}

		if (use_unicode) {
			/*
			 * CAP_UNICODE, can only be negotiated by NT1.
			 */
			state->upassword_blob = data_blob_const(bytes,
								bytes_len);
		} else {
			state->apassword_blob = data_blob_const(bytes,
								bytes_len);
		}

		goto non_spnego_creds_done;
	}

	challenge = data_blob_const(smb1cli_conn_server_challenge(cli->conn), 8);

	if (smbXcli_conn_protocol(cli->conn) == PROTOCOL_NT1) {
		if (lp_client_ntlmv2_auth() && lp_client_use_spnego()) {
			/*
			 * Don't send an NTLMv2 response without NTLMSSP if we
			 * want to use spnego support.
			 */
			DEBUG(1, ("Server does not support EXTENDED_SECURITY "
				  " but 'client use spnego = yes'"
				  " and 'client ntlmv2 auth = yes' is set\n"));
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}

		if (lp_client_ntlmv2_auth()) {
			flags |= CLI_CRED_NTLMv2_AUTH;

			/*
			 * note that the 'domain' here is a best
			 * guess - we don't know the server's domain
			 * at this point. Windows clients also don't
			 * use hostname...
			 */
			target_info = NTLMv2_generate_names_blob(state,
								 NULL,
								 domain);
			if (tevent_req_nomem(target_info.data, req)) {
				return tevent_req_post(req, ev);
			}
		} else {
			flags |= CLI_CRED_NTLM_AUTH;
			if (lp_client_lanman_auth()) {
				flags |= CLI_CRED_LANMAN_AUTH;
			}
		}
	} else {
		if (!lp_client_lanman_auth()) {
			DEBUG(1, ("Server requested user level LM password but "
				  "'client lanman auth = no' is set.\n"));
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}

		flags |= CLI_CRED_LANMAN_AUTH;
	}

	status = cli_credentials_get_ntlm_response(creds, state, &flags,
						   challenge, NULL,
						   target_info,
						   &state->apassword_blob,
						   &state->upassword_blob,
						   &state->lm_session_key,
						   &state->session_key);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

non_spnego_creds_done:

	in_buf_size = CLI_BUFFER_SIZE;
	in_mpx_max = smbXcli_conn_max_requests(cli->conn);
	in_vc_num = cli_state_get_vc_num(cli);
	in_sess_key = smb1cli_conn_server_session_key(cli->conn);
	in_native_os = "Unix";
	in_native_lm = "Samba";

	if (smbXcli_conn_protocol(cli->conn) == PROTOCOL_NT1) {
		uint32_t in_capabilities = 0;

		in_capabilities = cli_session_setup_capabilities(cli, 0);

		/*
		 * For now we keep the same values as before,
		 * we may remove these in a separate commit later.
		 */
		in_mpx_max = 2;

		subreq = smb1cli_session_setup_nt1_send(state, ev,
							cli->conn,
							cli->timeout,
							cli->smb1.pid,
							cli->smb1.session,
							in_buf_size,
							in_mpx_max,
							in_vc_num,
							in_sess_key,
							username,
							domain,
							state->apassword_blob,
							state->upassword_blob,
							in_capabilities,
							in_native_os,
							in_native_lm);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_session_setup_creds_done_nt1,
					req);
		return req;
	}

	/*
	 * For now we keep the same values as before,
	 * we may remove these in a separate commit later.
	 */
	in_mpx_max = 2;
	in_vc_num = 1;

	subreq = smb1cli_session_setup_lm21_send(state, ev,
						 cli->conn,
						 cli->timeout,
						 cli->smb1.pid,
						 cli->smb1.session,
						 in_buf_size,
						 in_mpx_max,
						 in_vc_num,
						 in_sess_key,
						 username,
						 domain,
						 state->apassword_blob,
						 in_native_os,
						 in_native_lm);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_session_setup_creds_done_lm21,
				req);
	return req;
}

static void cli_session_setup_creds_done_spnego(struct tevent_req *subreq)
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

static void cli_session_setup_creds_done_nt1(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_setup_creds_state *state = tevent_req_data(
		req, struct cli_session_setup_creds_state);
	struct cli_state *cli = state->cli;
	NTSTATUS status;
	struct iovec *recv_iov = NULL;
	const uint8_t *inbuf = NULL;
	bool ok;

	status = smb1cli_session_setup_nt1_recv(subreq, state,
						&recv_iov,
						&inbuf,
						&state->out_native_os,
						&state->out_native_lm,
						&state->out_primary_domain);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("NT1 login failed: %s\n", nt_errstr(status)));
		tevent_req_nterror(req, status);
		return;
	}

	status = cli_state_update_after_sesssetup(state->cli,
						  state->out_native_os,
						  state->out_native_lm,
						  state->out_primary_domain);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	ok = smb1cli_conn_activate_signing(cli->conn,
					   state->session_key,
					   state->upassword_blob);
	if (ok) {
		ok = smb1cli_conn_check_signing(cli->conn, inbuf, 1);
		if (!ok) {
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}
	}

	if (state->session_key.data) {
		struct smbXcli_session *session = cli->smb1.session;

		status = smb1cli_session_set_session_key(session,
							 state->session_key);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	tevent_req_done(req);
}

static void cli_session_setup_creds_done_lm21(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_setup_creds_state *state = tevent_req_data(
		req, struct cli_session_setup_creds_state);
	NTSTATUS status;

	status = smb1cli_session_setup_lm21_recv(subreq, state,
						 &state->out_native_os,
						 &state->out_native_lm);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("LM21 login failed: %s\n", nt_errstr(status)));
		tevent_req_nterror(req, status);
		return;
	}

	status = cli_state_update_after_sesssetup(state->cli,
						  state->out_native_os,
						  state->out_native_lm,
						  NULL);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS cli_session_setup_creds_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_session_setup_creds(struct cli_state *cli,
				 struct cli_credentials *creds)
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
	req = cli_session_setup_creds_send(ev, ev, cli, creds);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_session_setup_creds_recv(req);
 fail:
	TALLOC_FREE(ev);
	return status;
}

NTSTATUS cli_session_setup_anon(struct cli_state *cli)
{
	NTSTATUS status;
	struct cli_credentials *creds = NULL;

	creds = cli_credentials_init_anon(cli);
	if (creds == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = cli_session_setup_creds(cli, creds);
	TALLOC_FREE(creds);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
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

	subreq = cli_smb_send(state, ev, cli, SMBulogoffX, 0, 0, 2, state->vwv,
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

	TALLOC_FREE(cli->smb1.tcon);
	cli->smb1.tcon = smbXcli_tcon_create(cli);
	if (tevent_req_nomem(cli->smb1.tcon, req)) {
		return tevent_req_post(req, ev);
	}
	smb1cli_tcon_set_id(cli->smb1.tcon, UINT16_MAX);

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
			tmp_pass = talloc_array(talloc_tos(), uint8_t, 0);
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

	subreq = cli_smb_req_create(state, ev, cli, SMBtconX, 0, 0, 4, vwv,
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
		if (pull_string_talloc(cli,
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
				  uint16_t *max_xmit, uint16_t *tid);

static void cli_tree_connect_smb2_done(struct tevent_req *subreq);
static void cli_tree_connect_andx_done(struct tevent_req *subreq);
static void cli_tree_connect_raw_done(struct tevent_req *subreq);

static struct tevent_req *cli_tree_connect_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	const char *share, const char *dev, const char *pass)
{
	struct tevent_req *req, *subreq;
	struct cli_tree_connect_state *state;
	int passlen;

	if (pass == NULL) {
		pass = "";
	}
	passlen = strlen(pass) + 1;

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

		TALLOC_FREE(cli->smb2.tcon);
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
			  const char *dev, const char *pass)
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
	req = cli_tree_connect_send(ev, ev, cli, share, dev, pass);
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

NTSTATUS cli_tree_connect_creds(struct cli_state *cli,
				const char *share, const char *dev,
				struct cli_credentials *creds)
{
	const char *pw = NULL;

	if (creds != NULL) {
		pw = cli_credentials_get_password(creds);
	}

	return cli_tree_connect(cli, share, dev, pw);
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

	subreq = cli_smb_send(state, ev, cli, SMBtdis, 0, 0, 0, NULL, 0, NULL);
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
	TALLOC_FREE(state->cli->smb1.tcon);
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
		status = smb2cli_tdis(cli->conn,
				    cli->timeout,
				    cli->smb2.session,
				    cli->smb2.tcon);
		if (NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(cli->smb2.tcon);
		}
		return status;
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
	struct sockaddr_storage *addrs;
	unsigned i, num_addrs;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_connect_sock_state);
	if (req == NULL) {
		return NULL;
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
	} else if (dest_ss != NULL) {
		state->desthost = print_canonical_sockaddr(state, dest_ss);
		if (tevent_req_nomem(state->desthost, req)) {
			return tevent_req_post(req, ev);
		}
	} else {
		/* No host or dest_ss given. Error out. */
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
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

	state->cli = cli_state_create(state, fd, state->desthost,
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
	int min_protocol;
	int max_protocol;
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

	if (signing_state == SMB_SIGNING_IPC_DEFAULT) {
		state->min_protocol = lp_client_ipc_min_protocol();
		state->max_protocol = lp_client_ipc_max_protocol();
	} else {
		state->min_protocol = lp_client_min_protocol();
		state->max_protocol = lp_client_max_protocol();
	}

	if (flags & CLI_FULL_CONNECTION_FORCE_SMB1) {
		state->max_protocol = MIN(state->max_protocol, PROTOCOL_NT1);
	}

	if (flags & CLI_FULL_CONNECTION_DISABLE_SMB1) {
		state->min_protocol = MAX(state->max_protocol, PROTOCOL_SMB2_02);
		state->max_protocol = MAX(state->max_protocol, PROTOCOL_LATEST);
	}

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
				      state->min_protocol,
				      state->max_protocol,
				      WINDOWS_CLIENT_PURE_SMB2_NEGPROT_INITIAL_CREDIT_ASK);
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

struct cli_smb1_setup_encryption_blob_state {
	uint16_t setup[1];
	uint8_t param[4];
	NTSTATUS status;
	DATA_BLOB out;
	uint16_t enc_ctx_id;
};

static void cli_smb1_setup_encryption_blob_done(struct tevent_req *subreq);

static struct tevent_req *cli_smb1_setup_encryption_blob_send(TALLOC_CTX *mem_ctx,
							struct tevent_context *ev,
							struct cli_state *cli,
							const DATA_BLOB in)
{
	struct tevent_req *req = NULL;
	struct cli_smb1_setup_encryption_blob_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb1_setup_encryption_blob_state);
	if (req == NULL) {
		return NULL;
	}

	if (in.length > CLI_BUFFER_SIZE) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	SSVAL(state->setup+0,  0, TRANSACT2_SETFSINFO);
	SSVAL(state->param, 0, 0);
	SSVAL(state->param, 2, SMB_REQUEST_TRANSPORT_ENCRYPTION);

	subreq = smb1cli_trans_send(state, ev, cli->conn,
				    SMBtrans2,
				    0, 0, /* _flags */
				    0, 0, /* _flags2 */
				    cli->timeout,
				    cli->smb1.pid,
				    cli->smb1.tcon,
				    cli->smb1.session,
				    NULL, /* pipe_name */
				    0, /* fid */
				    0, /* function */
				    0, /* flags */
				    state->setup, 1, 0,
				    state->param, 4, 2,
				    in.data, in.length, CLI_BUFFER_SIZE);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				cli_smb1_setup_encryption_blob_done,
				req);

	return req;
}

static void cli_smb1_setup_encryption_blob_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
				struct tevent_req);
	struct cli_smb1_setup_encryption_blob_state *state =
		tevent_req_data(req,
		struct cli_smb1_setup_encryption_blob_state);
	uint8_t *rparam=NULL, *rdata=NULL;
	uint32_t num_rparam, num_rdata;
	NTSTATUS status;

	status = smb1cli_trans_recv(subreq, state,
				    NULL, /* recv_flags */
				    NULL, 0, NULL, /* rsetup */
				    &rparam, 0, &num_rparam,
				    &rdata, 0, &num_rdata);
	TALLOC_FREE(subreq);
	state->status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (num_rparam == 2) {
		state->enc_ctx_id = SVAL(rparam, 0);
	}
	TALLOC_FREE(rparam);

	state->out = data_blob_const(rdata, num_rdata);

	tevent_req_done(req);
}

static NTSTATUS cli_smb1_setup_encryption_blob_recv(struct tevent_req *req,
						    TALLOC_CTX *mem_ctx,
						    DATA_BLOB *out,
						    uint16_t *enc_ctx_id)
{
	struct cli_smb1_setup_encryption_blob_state *state =
		tevent_req_data(req,
		struct cli_smb1_setup_encryption_blob_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	status = state->status;

	*out = state->out;
	talloc_steal(mem_ctx, out->data);

	*enc_ctx_id = state->enc_ctx_id;

	tevent_req_received(req);
	return status;
}

struct cli_smb1_setup_encryption_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	struct smb_trans_enc_state *es;
	DATA_BLOB blob_in;
	DATA_BLOB blob_out;
	bool local_ready;
	bool remote_ready;
};

static void cli_smb1_setup_encryption_local_next(struct tevent_req *req);
static void cli_smb1_setup_encryption_local_done(struct tevent_req *subreq);
static void cli_smb1_setup_encryption_remote_next(struct tevent_req *req);
static void cli_smb1_setup_encryption_remote_done(struct tevent_req *subreq);
static void cli_smb1_setup_encryption_ready(struct tevent_req *req);

static struct tevent_req *cli_smb1_setup_encryption_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct cli_state *cli,
						struct cli_credentials *creds)
{
	struct tevent_req *req = NULL;
	struct cli_smb1_setup_encryption_state *state = NULL;
	struct auth_generic_state *ags = NULL;
	const DATA_BLOB *b = NULL;
	bool auth_requested = false;
	const char *target_service = NULL;
	const char *target_hostname = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb1_setup_encryption_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	auth_requested = cli_credentials_authentication_requested(creds);
	if (!auth_requested) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	target_service = "cifs";
	target_hostname = smbXcli_conn_remote_name(cli->conn);

	status = cli_session_creds_prepare_krb5(cli, creds);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->es = talloc_zero(state, struct smb_trans_enc_state);
	if (tevent_req_nomem(state->es, req)) {
		return tevent_req_post(req, ev);
	}

	status = auth_generic_client_prepare(state->es, &ags);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	gensec_want_feature(ags->gensec_security,
			    GENSEC_FEATURE_SIGN);
	gensec_want_feature(ags->gensec_security,
			    GENSEC_FEATURE_SEAL);

	status = auth_generic_set_creds(ags, creds);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (target_service != NULL) {
		status = gensec_set_target_service(ags->gensec_security,
						   target_service);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	if (target_hostname != NULL) {
		status = gensec_set_target_hostname(ags->gensec_security,
						    target_hostname);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	gensec_set_max_update_size(ags->gensec_security,
				   CLI_BUFFER_SIZE);

	b = smbXcli_conn_server_gss_blob(state->cli->conn);
	if (b != NULL) {
		state->blob_in = *b;
	}

	status = auth_generic_client_start(ags, GENSEC_OID_SPNEGO);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * We only need the gensec_security part from here.
	 */
	state->es->gensec_security = talloc_move(state->es,
						 &ags->gensec_security);
	TALLOC_FREE(ags);

	cli_smb1_setup_encryption_local_next(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void cli_smb1_setup_encryption_local_next(struct tevent_req *req)
{
	struct cli_smb1_setup_encryption_state *state =
		tevent_req_data(req,
		struct cli_smb1_setup_encryption_state);
	struct tevent_req *subreq = NULL;

	if (state->local_ready) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	subreq = gensec_update_send(state, state->ev,
			state->es->gensec_security,
			state->blob_in);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb1_setup_encryption_local_done, req);
}

static void cli_smb1_setup_encryption_local_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct cli_smb1_setup_encryption_state *state =
		tevent_req_data(req,
		struct cli_smb1_setup_encryption_state);
	NTSTATUS status;

	status = gensec_update_recv(subreq, state, &state->blob_out);
	TALLOC_FREE(subreq);
	state->blob_in = data_blob_null;
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED))
	{
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_IS_OK(status)) {
		state->local_ready = true;
	}

	/*
	 * We always get NT_STATUS_OK from the server even if it is not ready.
	 * So guess the server is ready when we are ready and already sent
	 * our last blob to the server.
	 */
	if (state->local_ready && state->blob_out.length == 0) {
		state->remote_ready = true;
	}

	if (state->local_ready && state->remote_ready) {
		cli_smb1_setup_encryption_ready(req);
		return;
	}

	cli_smb1_setup_encryption_remote_next(req);
}

static void cli_smb1_setup_encryption_remote_next(struct tevent_req *req)
{
	struct cli_smb1_setup_encryption_state *state =
		tevent_req_data(req,
		struct cli_smb1_setup_encryption_state);
	struct tevent_req *subreq = NULL;

	if (state->remote_ready) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	subreq = cli_smb1_setup_encryption_blob_send(state, state->ev,
						     state->cli, state->blob_out);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				cli_smb1_setup_encryption_remote_done,
				req);
}

static void cli_smb1_setup_encryption_remote_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct cli_smb1_setup_encryption_state *state =
		tevent_req_data(req,
		struct cli_smb1_setup_encryption_state);
	NTSTATUS status;

	status = cli_smb1_setup_encryption_blob_recv(subreq, state,
						     &state->blob_in,
						     &state->es->enc_ctx_num);
	TALLOC_FREE(subreq);
	data_blob_free(&state->blob_out);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED))
	{
		tevent_req_nterror(req, status);
		return;
	}

	/*
	 * We always get NT_STATUS_OK even if the server is not ready.
	 * So guess the server is ready when we are ready and sent
	 * our last blob to the server.
	 */
	if (state->local_ready) {
		state->remote_ready = true;
	}

	if (state->local_ready && state->remote_ready) {
		cli_smb1_setup_encryption_ready(req);
		return;
	}

	cli_smb1_setup_encryption_local_next(req);
}

static void cli_smb1_setup_encryption_ready(struct tevent_req *req)
{
	struct cli_smb1_setup_encryption_state *state =
		tevent_req_data(req,
		struct cli_smb1_setup_encryption_state);
	struct smb_trans_enc_state *es = NULL;

	if (state->blob_in.length != 0) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (state->blob_out.length != 0) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	es = talloc_move(state->cli->conn, &state->es);
	es->enc_on = true;
	smb1cli_conn_set_encryption(state->cli->conn, es);
	es = NULL;

	tevent_req_done(req);
}

static NTSTATUS cli_smb1_setup_encryption_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_smb1_setup_encryption(struct cli_state *cli,
				   struct cli_credentials *creds)
{
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_smb1_setup_encryption_send(ev, ev, cli, creds);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_smb1_setup_encryption_recv(req);
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
   @param creds The used user credentials
*/

struct cli_full_connection_creds_state {
	struct tevent_context *ev;
	const char *service;
	const char *service_type;
	struct cli_credentials *creds;
	int flags;
	struct cli_state *cli;
};

static int cli_full_connection_creds_state_destructor(
	struct cli_full_connection_creds_state *s)
{
	if (s->cli != NULL) {
		cli_shutdown(s->cli);
		s->cli = NULL;
	}
	return 0;
}

static void cli_full_connection_creds_conn_done(struct tevent_req *subreq);
static void cli_full_connection_creds_sess_start(struct tevent_req *req);
static void cli_full_connection_creds_sess_done(struct tevent_req *subreq);
static void cli_full_connection_creds_tcon_start(struct tevent_req *req);
static void cli_full_connection_creds_tcon_done(struct tevent_req *subreq);

struct tevent_req *cli_full_connection_creds_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *my_name, const char *dest_host,
	const struct sockaddr_storage *dest_ss, int port,
	const char *service, const char *service_type,
	struct cli_credentials *creds,
	int flags, int signing_state)
{
	struct tevent_req *req, *subreq;
	struct cli_full_connection_creds_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_full_connection_creds_state);
	if (req == NULL) {
		return NULL;
	}
	talloc_set_destructor(state, cli_full_connection_creds_state_destructor);

	state->ev = ev;
	state->service = service;
	state->service_type = service_type;
	state->creds = creds;
	state->flags = flags;

	subreq = cli_start_connection_send(
		state, ev, my_name, dest_host, dest_ss, port,
		signing_state, flags);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				cli_full_connection_creds_conn_done,
				req);
	return req;
}

static void cli_full_connection_creds_conn_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_full_connection_creds_state *state = tevent_req_data(
		req, struct cli_full_connection_creds_state);
	NTSTATUS status;

	status = cli_start_connection_recv(subreq, &state->cli);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	cli_full_connection_creds_sess_start(req);
}

static void cli_full_connection_creds_sess_start(struct tevent_req *req)
{
	struct cli_full_connection_creds_state *state = tevent_req_data(
		req, struct cli_full_connection_creds_state);
	struct tevent_req *subreq = NULL;

	subreq = cli_session_setup_creds_send(
		state, state->ev, state->cli, state->creds);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				cli_full_connection_creds_sess_done,
				req);
}

static void cli_full_connection_creds_sess_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_full_connection_creds_state *state = tevent_req_data(
		req, struct cli_full_connection_creds_state);
	NTSTATUS status;

	status = cli_session_setup_creds_recv(subreq);
	TALLOC_FREE(subreq);

	if (!NT_STATUS_IS_OK(status) &&
	    (state->flags & CLI_FULL_CONNECTION_ANONYMOUS_FALLBACK)) {

		state->flags &= ~CLI_FULL_CONNECTION_ANONYMOUS_FALLBACK;

		state->creds = cli_credentials_init_anon(state);
		if (tevent_req_nomem(state->creds, req)) {
			return;
		}

		cli_full_connection_creds_sess_start(req);
		return;
	}

	if (tevent_req_nterror(req, status)) {
		return;
	}

	cli_full_connection_creds_tcon_start(req);
}

static void cli_full_connection_creds_tcon_start(struct tevent_req *req)
{
	struct cli_full_connection_creds_state *state = tevent_req_data(
		req, struct cli_full_connection_creds_state);
	struct tevent_req *subreq = NULL;
	const char *password = NULL;

	if (state->service == NULL) {
		tevent_req_done(req);
		return;
	}

	password = cli_credentials_get_password(state->creds);

	subreq = cli_tree_connect_send(state, state->ev,
				       state->cli,
				       state->service,
				       state->service_type,
				       password);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				cli_full_connection_creds_tcon_done,
				req);
}

static void cli_full_connection_creds_tcon_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_tree_connect_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS cli_full_connection_creds_recv(struct tevent_req *req,
				  struct cli_state **output_cli)
{
	struct cli_full_connection_creds_state *state = tevent_req_data(
		req, struct cli_full_connection_creds_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*output_cli = state->cli;
	talloc_set_destructor(state, NULL);
	return NT_STATUS_OK;
}

NTSTATUS cli_full_connection_creds(struct cli_state **output_cli,
				   const char *my_name,
				   const char *dest_host,
				   const struct sockaddr_storage *dest_ss, int port,
				   const char *service, const char *service_type,
				   struct cli_credentials *creds,
				   int flags,
				   int signing_state)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cli_full_connection_creds_send(
		ev, ev, my_name, dest_host, dest_ss, port, service,
		service_type, creds, flags, signing_state);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_full_connection_creds_recv(req, output_cli);
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

	TALLOC_FREE(cli->smb1.tcon);
	cli->smb1.tcon = smbXcli_tcon_create(cli);
	if (tevent_req_nomem(cli->smb1.tcon, req)) {
		return tevent_req_post(req, ev);
	}
	smb1cli_tcon_set_id(cli->smb1.tcon, UINT16_MAX);

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

	subreq = cli_smb_send(state, ev, cli, SMBtcon, 0, 0, 0, NULL,
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
				  uint16_t *max_xmit, uint16_t *tid)
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
		      uint16_t *max_xmit, uint16_t *tid)
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

	flags |= CLI_FULL_CONNECTION_FORCE_SMB1;

	nt_status = cli_full_connection_creds(&cli, NULL, server, server_ss, 0, "IPC$", "IPC",
					get_cmdline_auth_info_creds(user_info),
					flags,
					SMB_SIGNING_DEFAULT);

	if (NT_STATUS_IS_OK(nt_status)) {
		return cli;
	}
	if (is_ipaddress(server)) {
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
