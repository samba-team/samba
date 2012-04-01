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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/auth/spnego.h"
#include "../auth/ntlmssp/ntlmssp.h"
#include "../librpc/gen_ndr/krb5pac.h"
#include "libads/kerberos_proto.h"
#include "../lib/util/asn1.h"
#include "auth.h"
#include "messages.h"
#include "smbprofile.h"
#include "../libcli/security/security.h"
#include "auth/gensec/gensec.h"

/****************************************************************************
 Add the standard 'Samba' signature to the end of the session setup.
****************************************************************************/

static int push_signature(uint8 **outbuf)
{
	char *lanman;
	int result, tmp;

	result = 0;

	tmp = message_push_string(outbuf, "Unix", STR_TERMINATE);

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
 Do a 'guest' logon, getting back the
****************************************************************************/

static NTSTATUS check_guest_password(const struct tsocket_address *remote_address,
				     TALLOC_CTX *mem_ctx, 
				     struct auth_session_info **session_info)
{
	struct auth4_context *auth_context;
	struct auth_usersupplied_info *user_info = NULL;
	uint8_t chal[8];
	NTSTATUS nt_status;

	DEBUG(3,("Got anonymous request\n"));

	nt_status = make_auth4_context(talloc_tos(), &auth_context);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	auth_context->get_ntlm_challenge(auth_context,
					 chal);

	if (!make_user_info_guest(remote_address, &user_info)) {
		TALLOC_FREE(auth_context);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = auth_check_password_session_info(auth_context, 
						     mem_ctx, user_info, session_info);
	free_user_info(&user_info);
	TALLOC_FREE(auth_context);
	return nt_status;
}

/****************************************************************************
 Reply to a session setup command.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

static void reply_sesssetup_and_X_spnego(struct smb_request *req)
{
	const uint8 *p;
	DATA_BLOB in_blob;
	DATA_BLOB out_blob = data_blob_null;
	size_t bufrem;
	char *tmp;
	const char *native_os;
	const char *native_lanman;
	const char *primary_domain;
	const char *p2;
	uint16 data_blob_len = SVAL(req->vwv+7, 0);
	enum remote_arch_types ra_type = get_remote_arch();
	int vuid = req->vuid;
	user_struct *vuser = NULL;
	NTSTATUS status = NT_STATUS_OK;
	struct smbd_server_connection *sconn = req->sconn;
	uint16_t action = 0;

	DEBUG(3,("Doing spnego session setup\n"));

	if (global_client_caps == 0) {
		global_client_caps = IVAL(req->vwv+10, 0);

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

	p2 = (const char *)req->buf + in_blob.length;

	p2 += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p2,
				     STR_TERMINATE);
	native_os = tmp ? tmp : "";

	p2 += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p2,
				     STR_TERMINATE);
	native_lanman = tmp ? tmp : "";

	p2 += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p2,
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

	vuser = get_valid_user_struct(sconn, vuid);
	if (vuser != NULL) {
		reply_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
		return;
	}

	/* Do we have a valid vuid now ? */
	if (!is_partial_auth_vuid(sconn, vuid)) {
		/* No, start a new authentication setup. */
		vuid = register_initial_vuid(sconn);
		if (vuid == UID_FIELD_INVALID) {
			reply_nterror(req, nt_status_squash(
					      NT_STATUS_INVALID_PARAMETER));
			return;
		}
	}

	vuser = get_partial_auth_user_struct(sconn, vuid);
	/* This MUST be valid. */
	if (!vuser) {
		smb_panic("reply_sesssetup_and_X_spnego: invalid vuid.");
	}

	if (!vuser->gensec_security) {
		status = auth_generic_prepare(vuser, sconn->remote_address,
					      &vuser->gensec_security);
		if (!NT_STATUS_IS_OK(status)) {
			/* Kill the intermediate vuid */
			invalidate_vuid(sconn, vuid);
			reply_nterror(req, nt_status_squash(status));
			return;
		}

		gensec_want_feature(vuser->gensec_security, GENSEC_FEATURE_SESSION_KEY);
		gensec_want_feature(vuser->gensec_security, GENSEC_FEATURE_UNIX_TOKEN);

		status = gensec_start_mech_by_oid(vuser->gensec_security, GENSEC_OID_SPNEGO);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Failed to start SPNEGO handler!\n"));
			/* Kill the intermediate vuid */
			invalidate_vuid(sconn, vuid);
			reply_nterror(req, nt_status_squash(status));
			return;
		}
	}

	status = gensec_update(vuser->gensec_security,
			       talloc_tos(), NULL,
			       in_blob, &out_blob);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		/* Kill the intermediate vuid */
		invalidate_vuid(sconn, vuid);
		reply_nterror(req, nt_status_squash(status));
		return;
	}

	if (NT_STATUS_IS_OK(status)) {
		struct auth_session_info *session_info = NULL;
		int tmp_vuid;

		status = gensec_session_info(vuser->gensec_security,
					     talloc_tos(),
					     &session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1,("Failed to generate session_info "
				 "(user and group token) for session setup: %s\n",
				 nt_errstr(status)));
			/* Kill the intermediate vuid */
			data_blob_free(&out_blob);
			invalidate_vuid(sconn, vuid);
			reply_nterror(req, nt_status_squash(status));
			return;
		}

		if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
			action = 1;
		}

		/* register_existing_vuid keeps the server info */
		tmp_vuid = register_existing_vuid(sconn, vuid,
						  session_info,
						  data_blob_null);
		if (tmp_vuid != vuid) {
			data_blob_free(&out_blob);
			invalidate_vuid(sconn, vuid);
			reply_nterror(req, NT_STATUS_LOGON_FAILURE);
			return;
		}

		/* current_user_info is changed on new vuid */
		reload_services(sconn, conn_snum_used, true);
	}

	reply_outbuf(req, 4, 0);

	SSVAL(req->outbuf, smb_uid, vuid);
	SIVAL(req->outbuf, smb_rcls, NT_STATUS_V(status));
	SSVAL(req->outbuf, smb_vwv0, 0xFF); /* no chaining possible */
	SSVAL(req->outbuf, smb_vwv2, action);
	SSVAL(req->outbuf, smb_vwv3, out_blob.length);

	if (message_push_blob(&req->outbuf, out_blob) == -1) {
		data_blob_free(&out_blob);
		invalidate_vuid(sconn, vuid);
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	data_blob_free(&out_blob);

	if (push_signature(&req->outbuf) == -1) {
		invalidate_vuid(sconn, vuid);
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
	struct messaging_context *msg_ctx;
};

static int shutdown_other_smbds(const struct connections_key *key,
				const struct connections_data *crec,
				void *private_data)
{
	struct shutdown_state *state = (struct shutdown_state *)private_data;

	DEBUG(10, ("shutdown_other_smbds: %s, %s\n",
		   server_id_str(talloc_tos(), &crec->pid), crec->addr));

	if (!process_exists(crec->pid)) {
		DEBUG(10, ("process does not exist\n"));
		return 0;
	}

	if (procid_is_me(&crec->pid)) {
		DEBUG(10, ("It's me\n"));
		return 0;
	}

	if (strcmp(state->ip, crec->addr) != 0) {
		DEBUG(10, ("%s does not match %s\n", state->ip, crec->addr));
		return 0;
	}

	DEBUG(1, ("shutdown_other_smbds: shutting down pid %u "
		  "(IP %s)\n", (unsigned int)procid_to_pid(&crec->pid),
		  state->ip));

	messaging_send(state->msg_ctx, crec->pid, MSG_SHUTDOWN,
		       &data_blob_null);
	return 0;
}

static void setup_new_vc_session(struct smbd_server_connection *sconn)
{
	DEBUG(2,("setup_new_vc_session: New VC == 0, if NT4.x "
		"compatible we would close all old resources.\n"));
#if 0
	conn_close_all();
	invalidate_all_vuids();
#endif
	if (lp_reset_on_zero_vc()) {
		char *addr;
		struct shutdown_state state;

		addr = tsocket_address_inet_addr_string(
			sconn->remote_address, talloc_tos());
		if (addr == NULL) {
			return;
		}
		state.ip = addr;
		state.msg_ctx = sconn->msg_ctx;
		connections_forall_read(shutdown_other_smbds, &state);
		TALLOC_FREE(addr);
	}
}

/****************************************************************************
 Reply to a session setup command.
****************************************************************************/

void reply_sesssetup_and_X(struct smb_request *req)
{
	int sess_vuid;
	int smb_bufsize;
	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;
	DATA_BLOB plaintext_password;
	char *tmp;
	const char *user;
	fstring sub_user; /* Sanitised username for substituion */
	const char *domain;
	const char *native_os;
	const char *native_lanman;
	const char *primary_domain;
	struct auth_usersupplied_info *user_info = NULL;
	struct auth_session_info *session_info = NULL;
	uint16 smb_flag2 = req->flags2;
	uint16_t action = 0;

	NTSTATUS nt_status;
	struct smbd_server_connection *sconn = req->sconn;

	bool doencrypt = sconn->smb1.negprot.encrypted_passwords;
	bool signing_allowed = false;
	bool signing_mandatory = false;

	START_PROFILE(SMBsesssetupX);

	ZERO_STRUCT(lm_resp);
	ZERO_STRUCT(nt_resp);
	ZERO_STRUCT(plaintext_password);

	DEBUG(3,("wct=%d flg2=0x%x\n", req->wct, req->flags2));

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
	srv_set_signing_negotiated(req->sconn,
				   signing_allowed,
				   signing_mandatory);

	/* a SPNEGO session setup has 12 command words, whereas a normal
	   NT1 session setup has 13. See the cifs spec. */
	if (req->wct == 12 &&
	    (req->flags2 & FLAGS2_EXTENDED_SECURITY)) {

		if (!sconn->smb1.negprot.spnego) {
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
		uint16 passlen1 = SVAL(req->vwv+7, 0);

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
			lm_resp = data_blob(req->buf, passlen1);
		} else {
			plaintext_password = data_blob(req->buf, passlen1+1);
			/* Ensure null termination */
			plaintext_password.data[passlen1] = 0;
		}

		srvstr_pull_req_talloc(talloc_tos(), req, &tmp,
				       req->buf + passlen1, STR_TERMINATE);
		user = tmp ? tmp : "";

		domain = "";

	} else {
		uint16 passlen1 = SVAL(req->vwv+7, 0);
		uint16 passlen2 = SVAL(req->vwv+8, 0);
		enum remote_arch_types ra_type = get_remote_arch();
		const uint8_t *p = req->buf;
		const uint8_t *save_p = req->buf;
		uint16 byte_count;


		if(global_client_caps == 0) {
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
			lm_resp = data_blob(p, passlen1);
			nt_resp = data_blob(p+passlen1, passlen2);
		} else {
			char *pass = NULL;
			bool unic= smb_flag2 & FLAGS2_UNICODE_STRINGS;

			if (unic && (passlen2 == 0) && passlen1) {
				/* Only a ascii plaintext password was sent. */
				(void)srvstr_pull_talloc(talloc_tos(),
							req->inbuf,
							req->flags2,
							&pass,
							req->buf,
							passlen1,
							STR_TERMINATE|STR_ASCII);
			} else {
				(void)srvstr_pull_talloc(talloc_tos(),
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
			plaintext_password = data_blob(pass, strlen(pass)+1);
		}

		p += passlen1 + passlen2;

		p += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p,
					    STR_TERMINATE);
		user = tmp ? tmp : "";

		p += srvstr_pull_req_talloc(talloc_tos(), req, &tmp, p,
					    STR_TERMINATE);
		domain = tmp ? tmp : "";

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
			domain, native_os, native_lanman, primary_domain));

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
				domain, user, get_remote_machine_name()));

	if (*user) {
		if (sconn->smb1.negprot.spnego) {

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
		fstrcpy(sub_user, user);
	} else {
		fstrcpy(sub_user, "");
	}

	sub_set_smb_name(sub_user);

	reload_services(sconn, conn_snum_used, true);

	if (!*user) {

		nt_status = check_guest_password(sconn->remote_address, req, &session_info);

	} else if (doencrypt) {
		struct auth4_context *negprot_auth_context = NULL;
		negprot_auth_context = sconn->smb1.negprot.auth_context;
		if (!negprot_auth_context) {
			DEBUG(0, ("reply_sesssetup_and_X:  Attempted encrypted "
				"session setup without negprot denied!\n"));
			reply_nterror(req, nt_status_squash(
					      NT_STATUS_LOGON_FAILURE));
			END_PROFILE(SMBsesssetupX);
			return;
		}
		nt_status = make_user_info_for_reply_enc(&user_info, user,
						domain,
						sconn->remote_address,
						lm_resp, nt_resp);
		if (NT_STATUS_IS_OK(nt_status)) {
			nt_status = auth_check_password_session_info(negprot_auth_context, 
								     req, user_info, &session_info);
		}
	} else {
		struct auth4_context *plaintext_auth_context = NULL;

		nt_status = make_auth4_context(
			talloc_tos(), &plaintext_auth_context);

		if (NT_STATUS_IS_OK(nt_status)) {
			uint8_t chal[8];

			plaintext_auth_context->get_ntlm_challenge(
					plaintext_auth_context, chal);

			if (!make_user_info_for_reply(&user_info,
						      user, domain,
						      sconn->remote_address,
						      chal,
						      plaintext_password)) {
				nt_status = NT_STATUS_NO_MEMORY;
			}

			if (NT_STATUS_IS_OK(nt_status)) {
				nt_status = auth_check_password_session_info(plaintext_auth_context, 
									     req, user_info, &session_info);
			}
			TALLOC_FREE(plaintext_auth_context);
		}
	}

	free_user_info(&user_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		data_blob_free(&nt_resp);
		data_blob_free(&lm_resp);
		data_blob_clear_free(&plaintext_password);
		reply_nterror(req, nt_status_squash(nt_status));
		END_PROFILE(SMBsesssetupX);
		return;
	}

	data_blob_clear_free(&plaintext_password);

	/* it's ok - setup a reply */
	reply_outbuf(req, 3, 0);
	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	if (get_Protocol() >= PROTOCOL_NT1) {
		push_signature(&req->outbuf);
		/* perhaps grab OS version here?? */
	}

	if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
		action = 1;
	}

	/* register the name and uid as being validated, so further connections
	   to a uid can get through without a password, on the same VC */

	/* Ignore the initial vuid. */
	sess_vuid = register_initial_vuid(sconn);
	if (sess_vuid == UID_FIELD_INVALID) {
		data_blob_free(&nt_resp);
		data_blob_free(&lm_resp);
		reply_nterror(req, nt_status_squash(
				      NT_STATUS_LOGON_FAILURE));
		END_PROFILE(SMBsesssetupX);
		return;
	}
	/* register_existing_vuid keeps the session_info */
	sess_vuid = register_existing_vuid(sconn, sess_vuid,
					   session_info,
					   nt_resp.data ? nt_resp : lm_resp);
	if (sess_vuid == UID_FIELD_INVALID) {
		data_blob_free(&nt_resp);
		data_blob_free(&lm_resp);
		reply_nterror(req, nt_status_squash(
				      NT_STATUS_LOGON_FAILURE));
		END_PROFILE(SMBsesssetupX);
		return;
	}

	/* current_user_info is changed on new vuid */
	reload_services(sconn, conn_snum_used, true);

	data_blob_free(&nt_resp);
	data_blob_free(&lm_resp);

	SSVAL(req->outbuf,smb_vwv2,action);
	SSVAL(req->outbuf,smb_uid,sess_vuid);
	SSVAL(discard_const_p(char, req->inbuf),smb_uid,sess_vuid);
	req->vuid = sess_vuid;

	if (!sconn->smb1.sessions.done_sesssetup) {
		sconn->smb1.sessions.max_send =
			MIN(sconn->smb1.sessions.max_send,smb_bufsize);
	}
	sconn->smb1.sessions.done_sesssetup = true;

	END_PROFILE(SMBsesssetupX);
}
