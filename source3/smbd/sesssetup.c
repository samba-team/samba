/*
   Unix SMB/CIFS implementation.
   handle SMBsessionsetup
   Copyright (C) Andrew Tridgell 1998-2001
   Copyright (C) Andrew Bartlett      2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   Copyright (C) Luke Howard          2003
   Copyright (C) Volker Lendecke      2007
   Copyright (C) Jeremy Allison	      2007

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
#include "../lib/tsocket/tsocket.h"
#include "lib/util/server_id.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "auth.h"
#include "messages.h"
#include "smbprofile.h"
#include "../libcli/security/security.h"
#include "auth/gensec/gensec.h"
#include "../libcli/smb/smb_signing.h"

/****************************************************************************
 Add the standard 'Samba' signature to the end of the session setup.
****************************************************************************/

static int push_signature(uint8_t **outbuf)
{
	char *lanman;
	int result, tmp;
	fstring native_os;

	result = 0;

	fstr_sprintf(native_os, "Windows %d.%d", SAMBA_MAJOR_NBT_ANNOUNCE_VERSION,
		SAMBA_MINOR_NBT_ANNOUNCE_VERSION);

	tmp = message_push_string(outbuf, native_os, STR_TERMINATE);

	if (tmp == -1) return -1;
	result += tmp;

	if (asprintf(&lanman, "Samba %s", samba_version_string()) != -1) {
		tmp = message_push_string(outbuf, lanman, STR_TERMINATE);
		SAFE_FREE(lanman);
	}
	else {
		tmp = message_push_string(outbuf, "Samba", STR_TERMINATE);
	}

	if (tmp == -1) return -1;
	result += tmp;

	tmp = message_push_string(outbuf, lp_workgroup(), STR_TERMINATE);

	if (tmp == -1) return -1;
	result += tmp;

	return result;
}

/****************************************************************************
 Reply to a session setup command.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

static void reply_sesssetup_and_X_spnego(struct smb_request *req)
{
	const uint8_t *p;
	DATA_BLOB in_blob;
	DATA_BLOB out_blob = data_blob_null;
	size_t bufrem;
	char *tmp;
	const char *native_os;
	const char *native_lanman;
	const char *primary_domain;
	uint16_t data_blob_len = SVAL(req->vwv+7, 0);
	enum remote_arch_types ra_type = get_remote_arch();
	uint64_t vuid = req->vuid;
	NTSTATUS status = NT_STATUS_OK;
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbd_server_connection *sconn = req->sconn;
	uint16_t action = 0;
	bool is_authenticated = false;
	NTTIME now = timeval_to_nttime(&req->request_time);
	struct smbXsrv_session *session = NULL;
	uint16_t smb_bufsize = SVAL(req->vwv+2, 0);
	uint32_t client_caps = IVAL(req->vwv+10, 0);
	struct smbXsrv_session_auth0 *auth;

	DEBUG(3,("Doing spnego session setup\n"));

	if (!xconn->smb1.sessions.done_sesssetup) {
		global_client_caps = client_caps;

		if (!(global_client_caps & CAP_STATUS32)) {
			remove_from_common_flags2(FLAGS2_32_BIT_ERROR_CODES);
		}
	}

	p = req->buf;

	if (data_blob_len == 0) {
		/* an invalid request */
		reply_nterror(req, nt_status_squash(NT_STATUS_LOGON_FAILURE));
		return;
	}

	bufrem = smbreq_bufrem(req, p);
	/* pull the spnego blob */
	in_blob = data_blob_const(p, MIN(bufrem, data_blob_len));

#if 0
	file_save("negotiate.dat", in_blob.data, in_blob.length);
#endif

	p = req->buf + in_blob.length;

	p += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p,
				     STR_TERMINATE);
	native_os = tmp ? tmp : "";

	p += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p,
				     STR_TERMINATE);
	native_lanman = tmp ? tmp : "";

	p += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p,
				     STR_TERMINATE);
	primary_domain = tmp ? tmp : "";

	DEBUG(3,("NativeOS=[%s] NativeLanMan=[%s] PrimaryDomain=[%s]\n",
		native_os, native_lanman, primary_domain));

	if ( ra_type == RA_WIN2K ) {
		/* Vista sets neither the OS or lanman strings */

		if ( !strlen(native_os) && !strlen(native_lanman) )
			set_remote_arch(RA_VISTA);

		/* Windows 2003 doesn't set the native lanman string,
		   but does set primary domain which is a bug I think */

		if ( !strlen(native_lanman) ) {
			ra_lanman_string( primary_domain );
		} else {
			ra_lanman_string( native_lanman );
		}
	} else if ( ra_type == RA_VISTA ) {
		if ( strncmp(native_os, "Mac OS X", 8) == 0 ) {
			set_remote_arch(RA_OSX);
		}
	}

	if (vuid != 0) {
		status = smb1srv_session_lookup(xconn,
						vuid, now,
						&session);
		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_SESSION_DELETED)) {
			reply_force_doserror(req, ERRSRV, ERRbaduid);
			return;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
			status = NT_STATUS_OK;
		}
		if (NT_STATUS_IS_OK(status)) {
			session->status = NT_STATUS_MORE_PROCESSING_REQUIRED;
			status = NT_STATUS_MORE_PROCESSING_REQUIRED;
			TALLOC_FREE(session->pending_auth);
		}
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			reply_nterror(req, nt_status_squash(status));
			return;
		}
	}

	if (session == NULL) {
		/* create a new session */
		status = smbXsrv_session_create(xconn,
					        now, &session);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, nt_status_squash(status));
			return;
		}
	}

	status = smbXsrv_session_find_auth(session, xconn, now, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		status = smbXsrv_session_create_auth(session, xconn, now,
						     0, /* flags */
						     0, /* security */
						     &auth);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, nt_status_squash(status));
			return;
		}
	}

	if (auth->gensec == NULL) {
		status = auth_generic_prepare(session,
					      xconn->remote_address,
					      xconn->local_address,
					      "SMB",
					      &auth->gensec);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(session);
			reply_nterror(req, nt_status_squash(status));
			return;
		}

		gensec_want_feature(auth->gensec, GENSEC_FEATURE_SESSION_KEY);
		gensec_want_feature(auth->gensec, GENSEC_FEATURE_UNIX_TOKEN);
		gensec_want_feature(auth->gensec, GENSEC_FEATURE_SMB_TRANSPORT);

		status = gensec_start_mech_by_oid(auth->gensec,
						  GENSEC_OID_SPNEGO);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Failed to start SPNEGO handler!\n"));
			TALLOC_FREE(session);;
			reply_nterror(req, nt_status_squash(status));
			return;
		}
	}

	become_root();
	status = gensec_update(auth->gensec,
			       talloc_tos(),
			       in_blob, &out_blob);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		TALLOC_FREE(session);
		reply_nterror(req, nt_status_squash(status));
		return;
	}

	if (NT_STATUS_IS_OK(status) && session->global->auth_session_info == NULL) {
		struct auth_session_info *session_info = NULL;

		status = gensec_session_info(auth->gensec,
					     session,
					     &session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1,("Failed to generate session_info "
				 "(user and group token) for session setup: %s\n",
				 nt_errstr(status)));
			data_blob_free(&out_blob);
			TALLOC_FREE(session);
			reply_nterror(req, nt_status_squash(status));
			return;
		}

		if (security_session_user_level(session_info, NULL) == SECURITY_GUEST) {
			action |= SMB_SETUP_GUEST;
		}

		if (session_info->session_key.length > 0) {
			struct smbXsrv_session *x = session;

			/*
			 * Note: the SMB1 signing key is not truncated to 16 byte!
			 */
			x->global->signing_key =
				talloc_zero(x->global, struct smb2_signing_key);
			if (x->global->signing_key == NULL) {
				data_blob_free(&out_blob);
				TALLOC_FREE(session);
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				return;
			}
			/* TODO: setup destructor once we cache the hmac handle */

			x->global->signing_key->blob =
				x->global->signing_key_blob =
				data_blob_dup_talloc(x->global->signing_key,
						     session_info->session_key);
			if (!smb2_signing_key_valid(x->global->signing_key)) {
				data_blob_free(&out_blob);
				TALLOC_FREE(session);
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				return;
			}
			talloc_keep_secret(x->global->signing_key->blob.data);

			/*
			 * clear the session key
			 * the first tcon will add setup the application key
			 */
			data_blob_clear_free(&session_info->session_key);
		}

		sconn->num_users++;

		if (security_session_user_level(session_info, NULL) >= SECURITY_USER) {
			is_authenticated = true;
			session->homes_snum =
				register_homes_share(session_info->unix_info->unix_name);
		}

		if (srv_is_signing_negotiated(xconn) &&
		    is_authenticated &&
		    smb2_signing_key_valid(session->global->signing_key))
		{
			/*
			 * Try and turn on server signing on the first non-guest
			 * sessionsetup.
			 */
			srv_set_signing(xconn,
				session->global->signing_key->blob,
				data_blob_null);
		}

		set_current_user_info(session_info->unix_info->sanitized_username,
				      session_info->unix_info->unix_name,
				      session_info->info->domain_name);

		session->status = NT_STATUS_OK;
		session->global->auth_session_info = talloc_move(session->global,
								 &session_info);
		session->global->auth_session_info_seqnum += 1;
		session->global->channels[0].auth_session_info_seqnum =
			session->global->auth_session_info_seqnum;
		session->global->auth_time = now;
		if (client_caps & CAP_DYNAMIC_REAUTH) {
			session->global->expiration_time =
				gensec_expire_time(auth->gensec);
		} else {
			session->global->expiration_time =
				GENSEC_EXPIRE_TIME_INFINITY;
		}

		if (!session_claim(session)) {
			DEBUG(1, ("smb1: Failed to claim session for vuid=%llu\n",
				  (unsigned long long)session->global->session_wire_id));
			data_blob_free(&out_blob);
			TALLOC_FREE(session);
			reply_nterror(req, NT_STATUS_LOGON_FAILURE);
			return;
		}

		status = smbXsrv_session_update(session);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("smb1: Failed to update session for vuid=%llu - %s\n",
				  (unsigned long long)session->global->session_wire_id,
				  nt_errstr(status)));
			data_blob_free(&out_blob);
			TALLOC_FREE(session);
			reply_nterror(req, NT_STATUS_LOGON_FAILURE);
			return;
		}

		if (!xconn->smb1.sessions.done_sesssetup) {
			if (smb_bufsize < SMB_BUFFER_SIZE_MIN) {
				reply_force_doserror(req, ERRSRV, ERRerror);
				return;
			}
			xconn->smb1.sessions.max_send = smb_bufsize;
			xconn->smb1.sessions.done_sesssetup = true;
		}

		/* current_user_info is changed on new vuid */
		reload_services(sconn, conn_snum_used, true);
	} else if (NT_STATUS_IS_OK(status)) {
		struct auth_session_info *session_info = NULL;

		status = gensec_session_info(auth->gensec,
					     session,
					     &session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1,("Failed to generate session_info "
				 "(user and group token) for session setup: %s\n",
				 nt_errstr(status)));
			data_blob_free(&out_blob);
			TALLOC_FREE(session);
			reply_nterror(req, nt_status_squash(status));
			return;
		}

		if (security_session_user_level(session_info, NULL) == SECURITY_GUEST) {
			action |= SMB_SETUP_GUEST;
		}

		/*
		 * Keep the application key
		 */
		data_blob_clear_free(&session_info->session_key);
		session_info->session_key =
			session->global->auth_session_info->session_key;
		talloc_steal(session_info, session_info->session_key.data);
		TALLOC_FREE(session->global->auth_session_info);

		if (security_session_user_level(session_info, NULL) >= SECURITY_USER) {
			session->homes_snum =
				register_homes_share(session_info->unix_info->unix_name);
		}

		set_current_user_info(session_info->unix_info->sanitized_username,
				      session_info->unix_info->unix_name,
				      session_info->info->domain_name);

		session->status = NT_STATUS_OK;
		session->global->auth_session_info = talloc_move(session->global,
								 &session_info);
		session->global->auth_session_info_seqnum += 1;
		session->global->channels[0].auth_session_info_seqnum =
			session->global->auth_session_info_seqnum;
		session->global->auth_time = now;
		if (client_caps & CAP_DYNAMIC_REAUTH) {
			session->global->expiration_time =
				gensec_expire_time(auth->gensec);
		} else {
			session->global->expiration_time =
				GENSEC_EXPIRE_TIME_INFINITY;
		}

		status = smbXsrv_session_update(session);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("smb1: Failed to update session for vuid=%llu - %s\n",
				  (unsigned long long)session->global->session_wire_id,
				  nt_errstr(status)));
			data_blob_free(&out_blob);
			TALLOC_FREE(session);
			reply_nterror(req, NT_STATUS_LOGON_FAILURE);
			return;
		}

		conn_clear_vuid_caches(sconn, session->global->session_wire_id);

		/* current_user_info is changed on new vuid */
		reload_services(sconn, conn_snum_used, true);
	}

	vuid = session->global->session_wire_id;

	reply_outbuf(req, 4, 0);

	SSVAL(req->outbuf, smb_uid, vuid);
	SIVAL(req->outbuf, smb_rcls, NT_STATUS_V(status));
	SSVAL(req->outbuf, smb_vwv0, 0xFF); /* no chaining possible */
	SSVAL(req->outbuf, smb_vwv2, action);
	SSVAL(req->outbuf, smb_vwv3, out_blob.length);

	if (message_push_blob(&req->outbuf, out_blob) == -1) {
		data_blob_free(&out_blob);
		TALLOC_FREE(session);
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	data_blob_free(&out_blob);

	if (push_signature(&req->outbuf) == -1) {
		TALLOC_FREE(session);
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
}

/****************************************************************************
 On new VC == 0, shutdown *all* old connections and users.
 It seems that only NT4.x does this. At W2K and above (XP etc.).
 a new session setup with VC==0 is ignored.
****************************************************************************/

struct shutdown_state {
	const char *ip;
	size_t ip_length;
	struct messaging_context *msg_ctx;
};

static int shutdown_other_smbds(struct smbXsrv_session_global0 *session,
				void *private_data)
{
	struct shutdown_state *state = (struct shutdown_state *)private_data;
	struct server_id self_pid = messaging_server_id(state->msg_ctx);
	struct server_id pid = session->channels[0].server_id;
	const char *addr = session->channels[0].remote_address;
	const char *port_colon;
	size_t addr_len;
	struct server_id_buf tmp;

	DEBUG(10, ("shutdown_other_smbds: %s, %s\n",
		   server_id_str_buf(pid, &tmp), addr));

	if (!process_exists(pid)) {
		DEBUG(10, ("process does not exist\n"));
		return 0;
	}

	if (server_id_equal(&pid, &self_pid)) {
		DEBUG(10, ("It's me\n"));
		return 0;
	}

	port_colon = strrchr(addr, ':');
	if (port_colon == NULL) {
		DBG_DEBUG("addr %s in contains no port\n", addr);
		return 0;
	}
	addr_len = port_colon - addr;

	if ((addr_len != state->ip_length) ||
	    (strncmp(addr, state->ip, state->ip_length) != 0)) {
		DEBUG(10, ("%s (%zu) does not match %s (%zu)\n",
			   state->ip, state->ip_length, addr, addr_len));
		return 0;
	}

	DEBUG(1, ("shutdown_other_smbds: shutting down pid %u "
		  "(IP %s)\n", (unsigned int)procid_to_pid(&pid),
		  state->ip));

	messaging_send(state->msg_ctx, pid, MSG_SHUTDOWN,
		       &data_blob_null);
	return 0;
}

static void setup_new_vc_session(struct smbd_server_connection *sconn)
{
	DEBUG(2,("setup_new_vc_session: New VC == 0, if NT4.x "
		"compatible we would close all old resources.\n"));

	if (lp_reset_on_zero_vc()) {
		char *addr;
		const char *port_colon;
		struct shutdown_state state;

		addr = tsocket_address_string(
			sconn->remote_address, talloc_tos());
		if (addr == NULL) {
			return;
		}
		state.ip = addr;

		port_colon = strrchr(addr, ':');
		if (port_colon == NULL) {
			return;
		}
		state.ip_length = port_colon - addr;
		state.msg_ctx = sconn->msg_ctx;
		smbXsrv_session_global_traverse(shutdown_other_smbds, &state);
		TALLOC_FREE(addr);
	}
}

/****************************************************************************
 Reply to a session setup command.
****************************************************************************/

struct reply_sesssetup_and_X_state {
	struct smb_request *req;
	struct auth4_context *auth_context;
	struct auth_usersupplied_info *user_info;
	const char *user;
	const char *domain;
	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;
	DATA_BLOB plaintext_password;
};

static int reply_sesssetup_and_X_state_destructor(
		struct reply_sesssetup_and_X_state *state)
{
	data_blob_clear_free(&state->nt_resp);
	data_blob_clear_free(&state->lm_resp);
	data_blob_clear_free(&state->plaintext_password);
	return 0;
}

void reply_sesssetup_and_X(struct smb_request *req)
{
	struct reply_sesssetup_and_X_state *state = NULL;
	uint64_t sess_vuid;
	uint16_t smb_bufsize;
	char *tmp;
	fstring sub_user; /* Sanitised username for substituion */
	const char *native_os;
	const char *native_lanman;
	const char *primary_domain;
	struct auth_session_info *session_info = NULL;
	uint16_t smb_flag2 = req->flags2;
	uint16_t action = 0;
	bool is_authenticated = false;
	NTTIME now = timeval_to_nttime(&req->request_time);
	struct smbXsrv_session *session = NULL;
	NTSTATUS nt_status;
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbd_server_connection *sconn = req->sconn;
	bool doencrypt = xconn->smb1.negprot.encrypted_passwords;
	bool signing_allowed = false;
	bool signing_mandatory = smb_signing_is_mandatory(
		xconn->smb1.signing_state);

	START_PROFILE(SMBsesssetupX);

	DEBUG(3,("wct=%d flg2=0x%x\n", req->wct, req->flags2));

	state = talloc_zero(req, struct reply_sesssetup_and_X_state);
	if (state == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBsesssetupX);
		return;
	}
	state->req = req;
	talloc_set_destructor(state, reply_sesssetup_and_X_state_destructor);

	if (req->flags2 & FLAGS2_SMB_SECURITY_SIGNATURES) {
		signing_allowed = true;
	}
	if (req->flags2 & FLAGS2_SMB_SECURITY_SIGNATURES_REQUIRED) {
		signing_mandatory = true;
	}

	/*
	 * We can call srv_set_signing_negotiated() each time.
	 * It finds out when it needs to turn into a noop
	 * itself.
	 */
	srv_set_signing_negotiated(xconn,
				   signing_allowed,
				   signing_mandatory);

	/* a SPNEGO session setup has 12 command words, whereas a normal
	   NT1 session setup has 13. See the cifs spec. */
	if (req->wct == 12 &&
	    (req->flags2 & FLAGS2_EXTENDED_SECURITY)) {

		if (!xconn->smb1.negprot.spnego) {
			DEBUG(0,("reply_sesssetup_and_X:  Rejecting attempt "
				 "at SPNEGO session setup when it was not "
				 "negotiated.\n"));
			reply_nterror(req, nt_status_squash(
					      NT_STATUS_LOGON_FAILURE));
			END_PROFILE(SMBsesssetupX);
			return;
		}

		if (SVAL(req->vwv+4, 0) == 0) {
			setup_new_vc_session(req->sconn);
		}

		reply_sesssetup_and_X_spnego(req);
		END_PROFILE(SMBsesssetupX);
		return;
	}

	smb_bufsize = SVAL(req->vwv+2, 0);

	if (get_Protocol() < PROTOCOL_NT1) {
		uint16_t passlen1 = SVAL(req->vwv+7, 0);

		/* Never do NT status codes with protocols before NT1 as we
		 * don't get client caps. */
		remove_from_common_flags2(FLAGS2_32_BIT_ERROR_CODES);

		if ((passlen1 > MAX_PASS_LEN) || (passlen1 > req->buflen)) {
			reply_nterror(req, nt_status_squash(
					      NT_STATUS_INVALID_PARAMETER));
			END_PROFILE(SMBsesssetupX);
			return;
		}

		if (doencrypt) {
			state->lm_resp = data_blob_talloc(state,
							  req->buf,
							  passlen1);
		} else {
			state->plaintext_password = data_blob_talloc(state,
								req->buf,
								passlen1+1);
			/* Ensure null termination */
			state->plaintext_password.data[passlen1] = 0;
		}

		srvstr_pull_req_talloc(state, req, &tmp,
				       req->buf + passlen1, STR_TERMINATE);
		state->user = tmp ? tmp : "";

		state->domain = "";

	} else {
		uint16_t passlen1 = SVAL(req->vwv+7, 0);
		uint16_t passlen2 = SVAL(req->vwv+8, 0);
		enum remote_arch_types ra_type = get_remote_arch();
		const uint8_t *p = req->buf;
		const uint8_t *save_p = req->buf;
		uint16_t byte_count;

		if (!xconn->smb1.sessions.done_sesssetup) {
			global_client_caps = IVAL(req->vwv+11, 0);

			if (!(global_client_caps & CAP_STATUS32)) {
				remove_from_common_flags2(
						FLAGS2_32_BIT_ERROR_CODES);
			}

			/* client_caps is used as final determination if
			 * client is NT or Win95. This is needed to return
			 * the correct error codes in some circumstances.
			*/

			if(ra_type == RA_WINNT || ra_type == RA_WIN2K ||
					ra_type == RA_WIN95) {
				if(!(global_client_caps & (CAP_NT_SMBS|
							CAP_STATUS32))) {
					set_remote_arch( RA_WIN95);
				}
			}
		}

		if (!doencrypt) {
			/* both Win95 and WinNT stuff up the password
			 * lengths for non-encrypting systems. Uggh.

			   if passlen1==24 its a win95 system, and its setting
			   the password length incorrectly. Luckily it still
			   works with the default code because Win95 will null
			   terminate the password anyway

			   if passlen1>0 and passlen2>0 then maybe its a NT box
			   and its setting passlen2 to some random value which
			   really stuffs things up. we need to fix that one.  */

			if (passlen1 > 0 && passlen2 > 0 && passlen2 != 24 &&
					passlen2 != 1) {
				passlen2 = 0;
			}
		}

		/* check for nasty tricks */
		if (passlen1 > MAX_PASS_LEN
		    || passlen1 > smbreq_bufrem(req, p)) {
			reply_nterror(req, nt_status_squash(
					      NT_STATUS_INVALID_PARAMETER));
			END_PROFILE(SMBsesssetupX);
			return;
		}

		if (passlen2 > MAX_PASS_LEN
		    || passlen2 > smbreq_bufrem(req, p+passlen1)) {
			reply_nterror(req, nt_status_squash(
					      NT_STATUS_INVALID_PARAMETER));
			END_PROFILE(SMBsesssetupX);
			return;
		}

		/* Save the lanman2 password and the NT md4 password. */

		if ((doencrypt) && (passlen1 != 0) && (passlen1 != 24)) {
			doencrypt = False;
		}

		if (doencrypt) {
			state->lm_resp = data_blob_talloc(state, p, passlen1);
			state->nt_resp = data_blob_talloc(state, p+passlen1, passlen2);
		} else {
			char *pass = NULL;
			bool unic= smb_flag2 & FLAGS2_UNICODE_STRINGS;

			if (unic && (passlen2 == 0) && passlen1) {
				/* Only a ascii plaintext password was sent. */
				(void)srvstr_pull_talloc(state,
							req->inbuf,
							req->flags2,
							&pass,
							req->buf,
							passlen1,
							STR_TERMINATE|STR_ASCII);
			} else {
				(void)srvstr_pull_talloc(state,
							req->inbuf,
							req->flags2,
							&pass,
							req->buf,
							unic ? passlen2 : passlen1,
							STR_TERMINATE);
			}
			if (!pass) {
				reply_nterror(req, nt_status_squash(
					      NT_STATUS_INVALID_PARAMETER));
				END_PROFILE(SMBsesssetupX);
				return;
			}
			state->plaintext_password = data_blob_talloc(state,
								pass,
								strlen(pass)+1);
		}

		p += passlen1 + passlen2;

		p += srvstr_pull_req_talloc(state, req, &tmp, p,
					    STR_TERMINATE);
		state->user = tmp ? tmp : "";

		p += srvstr_pull_req_talloc(state, req, &tmp, p,
					    STR_TERMINATE);
		state->domain = tmp ? tmp : "";

		p += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p,
					    STR_TERMINATE);
		native_os = tmp ? tmp : "";

		p += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p,
					    STR_TERMINATE);
		native_lanman = tmp ? tmp : "";

		/* not documented or decoded by Ethereal but there is one more
		 * string in the extra bytes which is the same as the
		 * PrimaryDomain when using extended security.  Windows NT 4
		 * and 2003 use this string to store the native lanman string.
		 * Windows 9x does not include a string here at all so we have
		 * to check if we have any extra bytes left */

		byte_count = SVAL(req->vwv+13, 0);
		if ( PTR_DIFF(p, save_p) < byte_count) {
			p += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p,
						    STR_TERMINATE);
			primary_domain = tmp ? tmp : "";
		} else {
			primary_domain = talloc_strdup(talloc_tos(), "null");
		}

		DEBUG(3,("Domain=[%s]  NativeOS=[%s] NativeLanMan=[%s] "
			"PrimaryDomain=[%s]\n",
			state->domain, native_os, native_lanman, primary_domain));

		if ( ra_type == RA_WIN2K ) {
			if ( strlen(native_lanman) == 0 )
				ra_lanman_string( primary_domain );
			else
				ra_lanman_string( native_lanman );
		}

	}

	if (SVAL(req->vwv+4, 0) == 0) {
		setup_new_vc_session(req->sconn);
	}

	DEBUG(3,("sesssetupX:name=[%s]\\[%s]@[%s]\n",
		 state->domain, state->user, get_remote_machine_name()));

	if (*state->user) {
		if (xconn->smb1.negprot.spnego) {

			/* This has to be here, because this is a perfectly
			 * valid behaviour for guest logons :-( */

			DEBUG(0,("reply_sesssetup_and_X:  Rejecting attempt "
				"at 'normal' session setup after "
				"negotiating spnego.\n"));
			reply_nterror(req, nt_status_squash(
					      NT_STATUS_LOGON_FAILURE));
			END_PROFILE(SMBsesssetupX);
			return;
		}
		fstrcpy(sub_user, state->user);
	} else {
		fstrcpy(sub_user, "");
	}

	if (!*state->user) {
		DEBUG(3,("Got anonymous request\n"));

		nt_status = make_auth4_context(state, &state->auth_context);
		if (NT_STATUS_IS_OK(nt_status)) {
			uint8_t chal[8];

			state->auth_context->get_ntlm_challenge(
					state->auth_context, chal);

			if (!make_user_info_guest(state,
						  sconn->remote_address,
						  sconn->local_address,
						  "SMB", &state->user_info)) {
				nt_status =  NT_STATUS_NO_MEMORY;
			}

			if (NT_STATUS_IS_OK(nt_status)) {
				state->user_info->auth_description = "guest";
			}
		}
	} else if (doencrypt) {
		state->auth_context = xconn->smb1.negprot.auth_context;
		if (state->auth_context == NULL) {
			DEBUG(0, ("reply_sesssetup_and_X:  Attempted encrypted "
				"session setup without negprot denied!\n"));
			reply_nterror(req, nt_status_squash(
					      NT_STATUS_LOGON_FAILURE));
			END_PROFILE(SMBsesssetupX);
			return;
		}
		nt_status = make_user_info_for_reply_enc(state,
							 &state->user_info,
							 state->user,
							 state->domain,
							 sconn->remote_address,
							 sconn->local_address,
							 "SMB",
							 state->lm_resp,
							 state->nt_resp);

		if (NT_STATUS_IS_OK(nt_status)) {
			state->user_info->auth_description = "bare-NTLM";
		}
	} else {
		nt_status = make_auth4_context(state, &state->auth_context);
		if (NT_STATUS_IS_OK(nt_status)) {
			uint8_t chal[8];

			state->auth_context->get_ntlm_challenge(
					state->auth_context, chal);

			if (!make_user_info_for_reply(state,
						      &state->user_info,
						      state->user,
						      state->domain,
						      sconn->remote_address,
						      sconn->local_address,
						      "SMB",
						      chal,
						      state->plaintext_password)) {
				nt_status = NT_STATUS_NO_MEMORY;
			}

			if (NT_STATUS_IS_OK(nt_status)) {
				state->user_info->auth_description = "plaintext";
			}
		}
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		reply_nterror(req, nt_status_squash(nt_status));
		END_PROFILE(SMBsesssetupX);
		return;
	}

	nt_status = auth_check_password_session_info(state->auth_context,
						     req, state->user_info,
						     &session_info);
	TALLOC_FREE(state->user_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		reply_nterror(req, nt_status_squash(nt_status));
		END_PROFILE(SMBsesssetupX);
		return;
	}

	/* it's ok - setup a reply */
	reply_outbuf(req, 3, 0);
	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	if (get_Protocol() >= PROTOCOL_NT1) {
		push_signature(&req->outbuf);
		/* perhaps grab OS version here?? */
	}

	if (security_session_user_level(session_info, NULL) == SECURITY_GUEST) {
		action |= SMB_SETUP_GUEST;
	}

	/* register the name and uid as being validated, so further connections
	   to a uid can get through without a password, on the same VC */

	nt_status = smbXsrv_session_create(xconn,
					   now, &session);
	if (!NT_STATUS_IS_OK(nt_status)) {
		reply_nterror(req, nt_status_squash(nt_status));
		END_PROFILE(SMBsesssetupX);
		return;
	}

	if (session_info->session_key.length > 0) {
		uint8_t session_key[16];

		/*
		 * Note: the SMB1 signing key is not truncated to 16 byte!
		 */
		session->global->signing_key =
			talloc_zero(session->global, struct smb2_signing_key);
		if (session->global->signing_key == NULL) {
			TALLOC_FREE(session);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBsesssetupX);
			return;
		}
		/* TODO: setup destructor once we cache the hmac handle */

		session->global->signing_key->blob =
			session->global->signing_key_blob =
			data_blob_dup_talloc(session->global->signing_key,
					     session_info->session_key);
		if (!smb2_signing_key_valid(session->global->signing_key)) {
			TALLOC_FREE(session);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBsesssetupX);
			return;
		}
		talloc_keep_secret(session->global->signing_key->blob.data);

		/*
		 * The application key is truncated/padded to 16 bytes
		 */
		ZERO_STRUCT(session_key);
		memcpy(session_key, session->global->signing_key->blob.data,
		       MIN(session->global->signing_key->blob.length,
			   sizeof(session_key)));
		session->global->application_key =
			data_blob_talloc(session->global,
					 session_key,
					 sizeof(session_key));
		ZERO_STRUCT(session_key);
		if (session->global->application_key.data == NULL) {
			TALLOC_FREE(session);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBsesssetupX);
			return;
		}

		/*
		 * Place the application key into the session_info
		 */
		data_blob_clear_free(&session_info->session_key);
		session_info->session_key = data_blob_dup_talloc(session_info,
						session->global->application_key);
		if (session_info->session_key.data == NULL) {
			TALLOC_FREE(session);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBsesssetupX);
			return;
		}
	}

	sconn->num_users++;

	if (security_session_user_level(session_info, NULL) >= SECURITY_USER) {
		is_authenticated = true;
		session->homes_snum =
			register_homes_share(session_info->unix_info->unix_name);
	}

	if (srv_is_signing_negotiated(xconn) &&
	    is_authenticated &&
	    smb2_signing_key_valid(session->global->signing_key))
	{
		/*
		 * Try and turn on server signing on the first non-guest
		 * sessionsetup.
		 */
		srv_set_signing(xconn,
			session->global->signing_key->blob,
			state->nt_resp.data ? state->nt_resp : state->lm_resp);
	}

	set_current_user_info(session_info->unix_info->sanitized_username,
			      session_info->unix_info->unix_name,
			      session_info->info->domain_name);

	session->status = NT_STATUS_OK;
	session->global->auth_session_info = talloc_move(session->global,
							 &session_info);
	session->global->auth_session_info_seqnum += 1;
	session->global->channels[0].auth_session_info_seqnum =
		session->global->auth_session_info_seqnum;
	session->global->auth_time = now;
	session->global->expiration_time = GENSEC_EXPIRE_TIME_INFINITY;

	nt_status = smbXsrv_session_update(session);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("smb1: Failed to update session for vuid=%llu - %s\n",
			  (unsigned long long)session->global->session_wire_id,
			  nt_errstr(nt_status)));
		TALLOC_FREE(session);
		reply_nterror(req, nt_status_squash(nt_status));
		END_PROFILE(SMBsesssetupX);
		return;
	}

	if (!session_claim(session)) {
		DEBUG(1, ("smb1: Failed to claim session for vuid=%llu\n",
			  (unsigned long long)session->global->session_wire_id));
		TALLOC_FREE(session);
		reply_nterror(req, NT_STATUS_LOGON_FAILURE);
		END_PROFILE(SMBsesssetupX);
		return;
	}

	/* current_user_info is changed on new vuid */
	reload_services(sconn, conn_snum_used, true);

	sess_vuid = session->global->session_wire_id;

	SSVAL(req->outbuf,smb_vwv2,action);
	SSVAL(req->outbuf,smb_uid,sess_vuid);
	SSVAL(discard_const_p(char, req->inbuf),smb_uid,sess_vuid);
	req->vuid = sess_vuid;

	if (!xconn->smb1.sessions.done_sesssetup) {
		if (smb_bufsize < SMB_BUFFER_SIZE_MIN) {
			reply_force_doserror(req, ERRSRV, ERRerror);
			END_PROFILE(SMBsesssetupX);
			return;
		}
		xconn->smb1.sessions.max_send = smb_bufsize;
		xconn->smb1.sessions.done_sesssetup = true;
	}

	TALLOC_FREE(state);
	END_PROFILE(SMBsesssetupX);
}
