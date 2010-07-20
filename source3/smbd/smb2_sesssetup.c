/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2010

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
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "../libcli/auth/spnego.h"
#include "../libcli/auth/ntlmssp.h"
#include "ntlmssp_wrap.h"

static NTSTATUS smbd_smb2_session_setup(struct smbd_smb2_request *smb2req,
					uint64_t in_session_id,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id);

NTSTATUS smbd_smb2_request_process_sesssetup(struct smbd_smb2_request *smb2req)
{
	const uint8_t *inhdr;
	const uint8_t *inbody;
	int i = smb2req->current_idx;
	uint8_t *outhdr;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	size_t expected_body_size = 0x19;
	size_t body_size;
	uint64_t in_session_id;
	uint8_t in_security_mode;
	uint16_t in_security_offset;
	uint16_t in_security_length;
	DATA_BLOB in_security_buffer;
	uint16_t out_session_flags;
	uint64_t out_session_id;
	uint16_t out_security_offset;
	DATA_BLOB out_security_buffer;
	NTSTATUS status;

	inhdr = (const uint8_t *)smb2req->in.vector[i+0].iov_base;

	if (smb2req->in.vector[i+1].iov_len != (expected_body_size & 0xFFFFFFFE)) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	inbody = (const uint8_t *)smb2req->in.vector[i+1].iov_base;

	body_size = SVAL(inbody, 0x00);
	if (body_size != expected_body_size) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	in_security_offset = SVAL(inbody, 0x0C);
	in_security_length = SVAL(inbody, 0x0E);

	if (in_security_offset != (SMB2_HDR_BODY + (body_size & 0xFFFFFFFE))) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_security_length > smb2req->in.vector[i+2].iov_len) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	in_security_mode = CVAL(inbody, 0x03);
	in_security_buffer.data = (uint8_t *)smb2req->in.vector[i+2].iov_base;
	in_security_buffer.length = in_security_length;

	status = smbd_smb2_session_setup(smb2req,
					 in_session_id,
					 in_security_mode,
					 in_security_buffer,
					 &out_session_flags,
					 &out_security_buffer,
					 &out_session_id);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = nt_status_squash(status);
		return smbd_smb2_request_error(smb2req, status);
	}

	out_security_offset = SMB2_HDR_BODY + 0x08;

	outhdr = (uint8_t *)smb2req->out.vector[i].iov_base;

	outbody = data_blob_talloc(smb2req->out.vector, NULL, 0x08);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
	}

	SBVAL(outhdr, SMB2_HDR_SESSION_ID, out_session_id);

	SSVAL(outbody.data, 0x00, 0x08 + 1);	/* struct size */
	SSVAL(outbody.data, 0x02,
	      out_session_flags);		/* session flags */
	SSVAL(outbody.data, 0x04,
	      out_security_offset);		/* security buffer offset */
	SSVAL(outbody.data, 0x06,
	      out_security_buffer.length);	/* security buffer length */

	outdyn = out_security_buffer;

	return smbd_smb2_request_done_ex(smb2req, status, outbody, &outdyn,
					 __location__);
}

static int smbd_smb2_session_destructor(struct smbd_smb2_session *session)
{
	if (session->sconn == NULL) {
		return 0;
	}

	/* first free all tcons */
	while (session->tcons.list) {
		talloc_free(session->tcons.list);
	}

	idr_remove(session->sconn->smb2.sessions.idtree, session->vuid);
	DLIST_REMOVE(session->sconn->smb2.sessions.list, session);
	invalidate_vuid(session->sconn, session->vuid);

	session->vuid = 0;
	session->status = NT_STATUS_USER_SESSION_DELETED;
	session->sconn = NULL;

	return 0;
}

static NTSTATUS setup_ntlmssp_server_info(struct smbd_smb2_session *session,
				NTSTATUS status)
{
	if (NT_STATUS_IS_OK(status)) {
		status = auth_ntlmssp_steal_server_info(session,
				session->auth_ntlmssp_state,
				&session->server_info);
	} else {
		/* Note that this server_info won't have a session
		 * key.  But for map to guest, that's exactly the right
		 * thing - we can't reasonably guess the key the
		 * client wants, as the password was wrong */
		status = do_map_to_guest(status,
			&session->server_info,
			auth_ntlmssp_get_username(session->auth_ntlmssp_state),
			auth_ntlmssp_get_domain(session->auth_ntlmssp_state));
	}
	return status;
}

#ifdef HAVE_KRB5
static NTSTATUS smbd_smb2_session_setup_krb5(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					const DATA_BLOB *secblob,
					const char *mechOID,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	DATA_BLOB ap_rep = data_blob_null;
	DATA_BLOB ap_rep_wrapped = data_blob_null;
	DATA_BLOB ticket = data_blob_null;
	DATA_BLOB session_key = data_blob_null;
	DATA_BLOB secblob_out = data_blob_null;
	uint8 tok_id[2];
	struct PAC_LOGON_INFO *logon_info = NULL;
	char *client = NULL;
	char *p = NULL;
	char *domain = NULL;
	struct passwd *pw = NULL;
	NTSTATUS status;
	fstring user;
	fstring real_username;
	fstring tmp;
	bool username_was_mapped = false;
	bool map_domainuser_to_guest = false;

	if (!spnego_parse_krb5_wrap(talloc_tos(), *secblob, &ticket, tok_id)) {
		status = NT_STATUS_LOGON_FAILURE;
		goto fail;
	}

	status = ads_verify_ticket(smb2req, lp_realm(), 0, &ticket,
				&client, &logon_info, &ap_rep,
				&session_key, true);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("smb2: Failed to verify incoming ticket with error %s!\n",
			nt_errstr(status)));
		if (!NT_STATUS_EQUAL(status, NT_STATUS_TIME_DIFFERENCE_AT_DC)) {
			status = NT_STATUS_LOGON_FAILURE;
		}
		goto fail;
	}

	DEBUG(3,("smb2: Ticket name is [%s]\n", client));

	p = strchr_m(client, '@');
	if (!p) {
		DEBUG(3,("smb2: %s Doesn't look like a valid principal\n",
			client));
		status = NT_STATUS_LOGON_FAILURE;
		goto fail;
	}

	*p = 0;

	/* save the PAC data if we have it */

	if (logon_info) {
		netsamlogon_cache_store(client, &logon_info->info3);
	}

	if (!strequal(p+1, lp_realm())) {
		DEBUG(3,("smb2: Ticket for foreign realm %s@%s\n", client, p+1));
		if (!lp_allow_trusted_domains()) {
			status = NT_STATUS_LOGON_FAILURE;
			goto fail;
		}
	}

	/* this gives a fully qualified user name (ie. with full realm).
	   that leads to very long usernames, but what else can we do? */

	domain = p+1;

	if (logon_info && logon_info->info3.base.domain.string) {
		domain = talloc_strdup(talloc_tos(),
					logon_info->info3.base.domain.string);
		if (!domain) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		DEBUG(10, ("smb2: Mapped to [%s] (using PAC)\n", domain));
	} else {

		/* If we have winbind running, we can (and must) shorten the
		   username by using the short netbios name. Otherwise we will
		   have inconsistent user names. With Kerberos, we get the
		   fully qualified realm, with ntlmssp we get the short
		   name. And even w2k3 does use ntlmssp if you for example
		   connect to an ip address. */

		wbcErr wbc_status;
		struct wbcDomainInfo *info = NULL;

		DEBUG(10, ("smb2: Mapping [%s] to short name\n", domain));

		wbc_status = wbcDomainInfo(domain, &info);

		if (WBC_ERROR_IS_OK(wbc_status)) {
			domain = talloc_strdup(talloc_tos(), info->short_name);

			wbcFreeMemory(info);
			if (!domain) {
				status = NT_STATUS_NO_MEMORY;
				goto fail;
			}
			DEBUG(10, ("smb2: Mapped to [%s] (using Winbind)\n", domain));
		} else {
			DEBUG(3, ("smb2: Could not find short name: %s\n",
				wbcErrorString(wbc_status)));
		}
	}

	/* We have to use fstring for this - map_username requires it. */
	fstr_sprintf(user, "%s%c%s", domain, *lp_winbind_separator(), client);

	/* lookup the passwd struct, create a new user if necessary */

	username_was_mapped = map_username(user);

	pw = smb_getpwnam(talloc_tos(), user, real_username, true );
	if (pw) {
		/* if a real user check pam account restrictions */
		/* only really perfomed if "obey pam restriction" is true */
		/* do this before an eventual mapping to guest occurs */
		status = smb_pam_accountcheck(pw->pw_name);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1,("smb2: PAM account restriction "
				"prevents user login\n"));
			goto fail;
		}
	}

	if (!pw) {

		/* this was originally the behavior of Samba 2.2, if a user
		   did not have a local uid but has been authenticated, then
		   map them to a guest account */

		if (lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_UID){
			map_domainuser_to_guest = true;
			fstrcpy(user,lp_guestaccount());
			pw = smb_getpwnam(talloc_tos(), user, real_username, true );
		}

		/* extra sanity check that the guest account is valid */

		if (!pw) {
			DEBUG(1,("smb2: Username %s is invalid on this system\n",
				user));
			status = NT_STATUS_LOGON_FAILURE;
			goto fail;
		}
	}

	/* setup the string used by %U */

	sub_set_smb_name(real_username);
	reload_services(true);

	if (map_domainuser_to_guest) {
		make_server_info_guest(session, &session->server_info);
	} else if (logon_info) {
		/* pass the unmapped username here since map_username()
		   will be called again from inside make_server_info_info3() */

		status = make_server_info_info3(session,
						client,
						domain,
						&session->server_info,
						&logon_info->info3);
		if (!NT_STATUS_IS_OK(status) ) {
			DEBUG(1,("smb2: make_server_info_info3 failed: %s!\n",
				nt_errstr(status)));
			goto fail;
		}

	} else {
		/*
		 * We didn't get a PAC, we have to make up the user
		 * ourselves. Try to ask the pdb backend to provide
		 * SID consistency with ntlmssp session setup
		 */
		struct samu *sampass;
		/* The stupid make_server_info_XX functions here
		   don't take a talloc context. */
		struct auth_serversupplied_info *tmp_server_info = NULL;

		sampass = samu_new(talloc_tos());
		if (sampass == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		if (pdb_getsampwnam(sampass, real_username)) {
			DEBUG(10, ("smb2: found user %s in passdb, calling "
				"make_server_info_sam\n", real_username));
			status = make_server_info_sam(&tmp_server_info, sampass);
			TALLOC_FREE(sampass);
		} else {
			/*
			 * User not in passdb, make it up artificially
			 */
			TALLOC_FREE(sampass);
			DEBUG(10, ("smb2: didn't find user %s in passdb, calling "
				"make_server_info_pw\n", real_username));
			status = make_server_info_pw(&tmp_server_info,
					real_username,
					pw);
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1,("smb2: make_server_info_[sam|pw] failed: %s!\n",
				nt_errstr(status)));
			goto fail;
                }

		/* Steal tmp_server_info into the session->server_info
		   pointer. */
		session->server_info = talloc_move(session, &tmp_server_info);

		/* make_server_info_pw does not set the domain. Without this
		 * we end up with the local netbios name in substitutions for
		 * %D. */

		if (session->server_info->info3 != NULL) {
			session->server_info->info3->base.domain.string =
				talloc_strdup(session->server_info->info3, domain);
		}

	}

	session->server_info->nss_token |= username_was_mapped;

	/* we need to build the token for the user. make_server_info_guest()
	   already does this */

	if (!session->server_info->ptok ) {
		status = create_local_token(session->server_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10,("smb2: failed to create local token: %s\n",
				nt_errstr(status)));
			goto fail;
		}
	}

	if ((in_security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) ||
	     lp_server_signing() == Required) {
		session->do_signing = true;
	}

	if (session->server_info->guest) {
		/* we map anonymous to guest internally */
		*out_session_flags |= SMB2_SESSION_FLAG_IS_GUEST;
		*out_session_flags |= SMB2_SESSION_FLAG_IS_NULL;
		/* force no signing */
		session->do_signing = false;
	}

	data_blob_free(&session->server_info->user_session_key);
	session->server_info->user_session_key =
			data_blob_talloc(
				session->server_info,
				session_key.data,
				session_key.length);
        if (session_key.length > 0) {
		if (session->server_info->user_session_key.data == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}
	session->session_key = session->server_info->user_session_key;

	session->compat_vuser = talloc_zero(session, user_struct);
	if (session->compat_vuser == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	session->compat_vuser->auth_ntlmssp_state = NULL;
	session->compat_vuser->homes_snum = -1;
	session->compat_vuser->server_info = session->server_info;
	session->compat_vuser->session_keystr = NULL;
	session->compat_vuser->vuid = session->vuid;
	DLIST_ADD(session->sconn->smb1.sessions.validated_users, session->compat_vuser);

	/* This is a potentially untrusted username */
	alpha_strcpy(tmp,
		client,
		". _-$",
		sizeof(tmp));
	session->server_info->sanitized_username = talloc_strdup(
			session->server_info, tmp);

	if (!session->server_info->guest) {
		session->compat_vuser->homes_snum =
			register_homes_share(session->server_info->unix_name);
	}

	if (!session_claim(sconn_server_id(session->sconn),
			   session->compat_vuser)) {
		DEBUG(1, ("smb2: Failed to claim session "
			"for vuid=%d\n",
			session->compat_vuser->vuid));
		goto fail;
	}

	session->status = NT_STATUS_OK;

	/*
	 * we attach the session to the request
	 * so that the response can be signed
	 */
	smb2req->session = session;
	if (session->do_signing) {
		smb2req->do_signing = true;
	}

	global_client_caps |= (CAP_LEVEL_II_OPLOCKS|CAP_STATUS32);
        status = NT_STATUS_OK;

	/* wrap that up in a nice GSS-API wrapping */
	ap_rep_wrapped = spnego_gen_krb5_wrap(talloc_tos(), ap_rep,
				TOK_ID_KRB_AP_REP);

	secblob_out = spnego_gen_auth_response(
					talloc_tos(),
					&ap_rep_wrapped,
					status,
					mechOID);

	*out_security_buffer = data_blob_talloc(smb2req,
						secblob_out.data,
						secblob_out.length);
	if (secblob_out.data && out_security_buffer->data == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	data_blob_free(&ap_rep);
	data_blob_free(&ap_rep_wrapped);
	data_blob_free(&ticket);
	data_blob_free(&session_key);
	data_blob_free(&secblob_out);

	*out_session_id = session->vuid;

	return NT_STATUS_OK;

  fail:

	data_blob_free(&ap_rep);
	data_blob_free(&ap_rep_wrapped);
	data_blob_free(&ticket);
	data_blob_free(&session_key);
	data_blob_free(&secblob_out);

	ap_rep_wrapped = data_blob_null;
	secblob_out = spnego_gen_auth_response(
					talloc_tos(),
					&ap_rep_wrapped,
					status,
					mechOID);

	*out_security_buffer = data_blob_talloc(smb2req,
						secblob_out.data,
						secblob_out.length);
	data_blob_free(&secblob_out);
	return status;
}
#endif

static NTSTATUS smbd_smb2_spnego_negotiate(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	DATA_BLOB secblob_in = data_blob_null;
	DATA_BLOB chal_out = data_blob_null;
	char *kerb_mech = NULL;
	NTSTATUS status;

	/* Ensure we have no old NTLM state around. */
	TALLOC_FREE(session->auth_ntlmssp_state);

	status = parse_spnego_mechanisms(talloc_tos(), in_security_buffer,
			&secblob_in, &kerb_mech);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

#ifdef HAVE_KRB5
	if (kerb_mech && ((lp_security()==SEC_ADS) ||
				USE_KERBEROS_KEYTAB) ) {
		status = smbd_smb2_session_setup_krb5(session,
				smb2req,
				in_security_mode,
				&secblob_in,
				kerb_mech,
				out_session_flags,
				out_security_buffer,
				out_session_id);

		goto out;
	}
#endif

	if (kerb_mech) {
		/* The mechtoken is a krb5 ticket, but
		 * we need to fall back to NTLM. */

		DEBUG(3,("smb2: Got krb5 ticket in SPNEGO "
			"but set to downgrade to NTLMSSP\n"));

		status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	} else {
		/* Fall back to NTLMSSP. */
		status = auth_ntlmssp_start(&session->auth_ntlmssp_state);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = auth_ntlmssp_update(session->auth_ntlmssp_state,
					     secblob_in,
					     &chal_out);
	}

	if (!NT_STATUS_IS_OK(status) &&
			!NT_STATUS_EQUAL(status,
				NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto out;
	}

	*out_security_buffer = spnego_gen_auth_response(smb2req,
						&chal_out,
						status,
						OID_NTLMSSP);
	if (out_security_buffer->data == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	*out_session_id = session->vuid;

  out:

	data_blob_free(&secblob_in);
	data_blob_free(&chal_out);
	TALLOC_FREE(kerb_mech);
	if (!NT_STATUS_IS_OK(status) &&
			!NT_STATUS_EQUAL(status,
				NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		TALLOC_FREE(session->auth_ntlmssp_state);
		TALLOC_FREE(session);
	}
	return status;
}

static NTSTATUS smbd_smb2_common_ntlmssp_auth_return(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					uint64_t *out_session_id)
{
	fstring tmp;

	if ((in_security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) ||
	    lp_server_signing() == Required) {
		session->do_signing = true;
	}

	if (session->server_info->guest) {
		/* we map anonymous to guest internally */
		*out_session_flags |= SMB2_SESSION_FLAG_IS_GUEST;
		*out_session_flags |= SMB2_SESSION_FLAG_IS_NULL;
		/* force no signing */
		session->do_signing = false;
	}

	session->session_key = session->server_info->user_session_key;

	session->compat_vuser = talloc_zero(session, user_struct);
	if (session->compat_vuser == NULL) {
		TALLOC_FREE(session->auth_ntlmssp_state);
		TALLOC_FREE(session);
		return NT_STATUS_NO_MEMORY;
	}
	session->compat_vuser->auth_ntlmssp_state = session->auth_ntlmssp_state;
	session->compat_vuser->homes_snum = -1;
	session->compat_vuser->server_info = session->server_info;
	session->compat_vuser->session_keystr = NULL;
	session->compat_vuser->vuid = session->vuid;
	DLIST_ADD(session->sconn->smb1.sessions.validated_users, session->compat_vuser);

	/* This is a potentially untrusted username */
	alpha_strcpy(tmp,
		     auth_ntlmssp_get_username(session->auth_ntlmssp_state),
		     ". _-$",
		     sizeof(tmp));
	session->server_info->sanitized_username = talloc_strdup(
		session->server_info, tmp);

	if (!session->compat_vuser->server_info->guest) {
		session->compat_vuser->homes_snum =
			register_homes_share(session->server_info->unix_name);
	}

	if (!session_claim(sconn_server_id(session->sconn),
			   session->compat_vuser)) {
		DEBUG(1, ("smb2: Failed to claim session "
			"for vuid=%d\n",
			session->compat_vuser->vuid));
		TALLOC_FREE(session->auth_ntlmssp_state);
		TALLOC_FREE(session);
		return NT_STATUS_LOGON_FAILURE;
	}


	session->status = NT_STATUS_OK;

	/*
	 * we attach the session to the request
	 * so that the response can be signed
	 */
	smb2req->session = session;
	if (session->do_signing) {
		smb2req->do_signing = true;
	}

	global_client_caps |= (CAP_LEVEL_II_OPLOCKS|CAP_STATUS32);

	*out_session_id = session->vuid;

	return NT_STATUS_OK;
}

static NTSTATUS smbd_smb2_spnego_auth(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	DATA_BLOB auth = data_blob_null;
	DATA_BLOB auth_out = data_blob_null;
	NTSTATUS status;

	if (!spnego_parse_auth(talloc_tos(), in_security_buffer, &auth)) {
		TALLOC_FREE(session);
		return NT_STATUS_LOGON_FAILURE;
	}

	if (auth.data[0] == ASN1_APPLICATION(0)) {
		/* Might be a second negTokenTarg packet */
		DATA_BLOB secblob_in = data_blob_null;
		char *kerb_mech = NULL;

		status = parse_spnego_mechanisms(talloc_tos(),
				in_security_buffer,
				&secblob_in, &kerb_mech);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(session);
			return status;
		}

#ifdef HAVE_KRB5
		if (kerb_mech && ((lp_security()==SEC_ADS) ||
					USE_KERBEROS_KEYTAB) ) {
			status = smbd_smb2_session_setup_krb5(session,
					smb2req,
					in_security_mode,
					&secblob_in,
					kerb_mech,
					out_session_flags,
					out_security_buffer,
					out_session_id);

			data_blob_free(&secblob_in);
			TALLOC_FREE(kerb_mech);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(session);
			}
			return status;
		}
#endif

		/* Can't blunder into NTLMSSP auth if we have
		 * a krb5 ticket. */

		if (kerb_mech) {
			DEBUG(3,("smb2: network "
				"misconfiguration, client sent us a "
				"krb5 ticket and kerberos security "
				"not enabled\n"));
			TALLOC_FREE(session);
			data_blob_free(&secblob_in);
			TALLOC_FREE(kerb_mech);
			return NT_STATUS_LOGON_FAILURE;
		}

		data_blob_free(&secblob_in);
	}

	if (session->auth_ntlmssp_state == NULL) {
		status = auth_ntlmssp_start(&session->auth_ntlmssp_state);
		if (!NT_STATUS_IS_OK(status)) {
			data_blob_free(&auth);
			TALLOC_FREE(session);
			return status;
		}
	}

	status = auth_ntlmssp_update(session->auth_ntlmssp_state,
				     auth,
				     &auth_out);
	if (!NT_STATUS_IS_OK(status) &&
			!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = setup_ntlmssp_server_info(session, status);
	}

	if (!NT_STATUS_IS_OK(status) &&
			!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		TALLOC_FREE(session->auth_ntlmssp_state);
		data_blob_free(&auth);
		TALLOC_FREE(session);
		return status;
	}

	data_blob_free(&auth);

	*out_security_buffer = spnego_gen_auth_response(smb2req,
				&auth_out, status, NULL);

	if (out_security_buffer->data == NULL) {
		TALLOC_FREE(session->auth_ntlmssp_state);
		TALLOC_FREE(session);
		return NT_STATUS_NO_MEMORY;
	}

	*out_session_id = session->vuid;

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}

	/* We're done - claim the session. */
	return smbd_smb2_common_ntlmssp_auth_return(session,
						smb2req,
						in_security_mode,
						in_security_buffer,
						out_session_flags,
						out_session_id);
}

static NTSTATUS smbd_smb2_raw_ntlmssp_auth(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	NTSTATUS status;
	DATA_BLOB secblob_out = data_blob_null;

	if (session->auth_ntlmssp_state == NULL) {
		status = auth_ntlmssp_start(&session->auth_ntlmssp_state);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(session);
			return status;
		}
	}

	/* RAW NTLMSSP */
	status = auth_ntlmssp_update(session->auth_ntlmssp_state,
				     in_security_buffer,
				     &secblob_out);

	if (NT_STATUS_IS_OK(status) ||
			NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		*out_security_buffer = data_blob_talloc(smb2req,
						secblob_out.data,
						secblob_out.length);
		if (secblob_out.data && out_security_buffer->data == NULL) {
			TALLOC_FREE(session->auth_ntlmssp_state);
			TALLOC_FREE(session);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		*out_session_id = session->vuid;
		return status;
	}

	status = setup_ntlmssp_server_info(session, status);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(session->auth_ntlmssp_state);
		TALLOC_FREE(session);
		return status;
	}
	*out_session_id = session->vuid;

	return smbd_smb2_common_ntlmssp_auth_return(session,
						smb2req,
						in_security_mode,
						in_security_buffer,
						out_session_flags,
						out_session_id);
}

static NTSTATUS smbd_smb2_session_setup(struct smbd_smb2_request *smb2req,
					uint64_t in_session_id,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	struct smbd_smb2_session *session;

	*out_session_flags = 0;
	*out_session_id = 0;

	if (in_session_id == 0) {
		int id;

		/* create a new session */
		session = talloc_zero(smb2req->sconn, struct smbd_smb2_session);
		if (session == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		session->status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		id = idr_get_new_random(smb2req->sconn->smb2.sessions.idtree,
					session,
					smb2req->sconn->smb2.sessions.limit);
		if (id == -1) {
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}
		session->vuid = id;

		session->tcons.idtree = idr_init(session);
		if (session->tcons.idtree == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		session->tcons.limit = 0x0000FFFE;
		session->tcons.list = NULL;

		DLIST_ADD_END(smb2req->sconn->smb2.sessions.list, session,
			      struct smbd_smb2_session *);
		session->sconn = smb2req->sconn;
		talloc_set_destructor(session, smbd_smb2_session_destructor);
	} else {
		void *p;

		/* lookup an existing session */
		p = idr_find(smb2req->sconn->smb2.sessions.idtree, in_session_id);
		if (p == NULL) {
			return NT_STATUS_USER_SESSION_DELETED;
		}
		session = talloc_get_type_abort(p, struct smbd_smb2_session);
	}

	if (NT_STATUS_IS_OK(session->status)) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	if (in_security_buffer.data[0] == ASN1_APPLICATION(0)) {
		return smbd_smb2_spnego_negotiate(session,
						smb2req,
						in_security_mode,
						in_security_buffer,
						out_session_flags,
						out_security_buffer,
						out_session_id);
	} else if (in_security_buffer.data[0] == ASN1_CONTEXT(1)) {
		return smbd_smb2_spnego_auth(session,
						smb2req,
						in_security_mode,
						in_security_buffer,
						out_session_flags,
						out_security_buffer,
						out_session_id);
	} else if (strncmp((char *)(in_security_buffer.data), "NTLMSSP", 7) == 0) {
		return smbd_smb2_raw_ntlmssp_auth(session,
						smb2req,
						in_security_mode,
						in_security_buffer,
						out_session_flags,
						out_security_buffer,
						out_session_id);
	}

	/* Unknown packet type. */
	DEBUG(1,("Unknown packet type %u in smb2 sessionsetup\n",
		(unsigned int)in_security_buffer.data[0] ));
	TALLOC_FREE(session->auth_ntlmssp_state);
	TALLOC_FREE(session);
	return NT_STATUS_LOGON_FAILURE;
}

NTSTATUS smbd_smb2_request_check_session(struct smbd_smb2_request *req)
{
	const uint8_t *inhdr;
	const uint8_t *outhdr;
	int i = req->current_idx;
	uint64_t in_session_id;
	void *p;
	struct smbd_smb2_session *session;
	bool chained_fixup = false;

	inhdr = (const uint8_t *)req->in.vector[i+0].iov_base;

	in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);

	if (in_session_id == (0xFFFFFFFFFFFFFFFFLL)) {
		if (req->async) {
			/*
			 * async request - fill in session_id from
			 * already setup request out.vector[].iov_base.
			 */
			outhdr = (const uint8_t *)req->out.vector[i].iov_base;
			in_session_id = BVAL(outhdr, SMB2_HDR_SESSION_ID);
		} else if (i > 2) {
			/*
			 * Chained request - fill in session_id from
			 * the previous request out.vector[].iov_base.
			 */
			outhdr = (const uint8_t *)req->out.vector[i-3].iov_base;
			in_session_id = BVAL(outhdr, SMB2_HDR_SESSION_ID);
			chained_fixup = true;
		}
	}

	/* lookup an existing session */
	p = idr_find(req->sconn->smb2.sessions.idtree, in_session_id);
	if (p == NULL) {
		return NT_STATUS_USER_SESSION_DELETED;
	}
	session = talloc_get_type_abort(p, struct smbd_smb2_session);

	if (!NT_STATUS_IS_OK(session->status)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	set_current_user_info(session->server_info->sanitized_username,
			      session->server_info->unix_name,
			      session->server_info->info3->base.domain.string);

	req->session = session;

	if (chained_fixup) {
		/* Fix up our own outhdr. */
		outhdr = (const uint8_t *)req->out.vector[i].iov_base;
		SBVAL(outhdr, SMB2_HDR_SESSION_ID, in_session_id);
	}
	return NT_STATUS_OK;
}

NTSTATUS smbd_smb2_request_process_logoff(struct smbd_smb2_request *req)
{
	const uint8_t *inbody;
	int i = req->current_idx;
	DATA_BLOB outbody;
	size_t expected_body_size = 0x04;
	size_t body_size;

	if (req->in.vector[i+1].iov_len != (expected_body_size & 0xFFFFFFFE)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	inbody = (const uint8_t *)req->in.vector[i+1].iov_base;

	body_size = SVAL(inbody, 0x00);
	if (body_size != expected_body_size) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	/*
	 * TODO: cancel all outstanding requests on the session
	 *       and delete all tree connections.
	 */
	smbd_smb2_session_destructor(req->session);
	/*
	 * we may need to sign the response, so we need to keep
	 * the session until the response is sent to the wire.
	 */
	talloc_steal(req, req->session);

	outbody = data_blob_talloc(req->out.vector, NULL, 0x04);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	SSVAL(outbody.data, 0x00, 0x04);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */

	return smbd_smb2_request_done(req, outbody, NULL);
}
