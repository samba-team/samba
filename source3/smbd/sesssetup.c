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
 Send a security blob via a session setup reply.
****************************************************************************/

static void reply_sesssetup_blob(struct smb_request *req,
				 DATA_BLOB blob,
				 NTSTATUS nt_status)
{
	if (!NT_STATUS_IS_OK(nt_status) &&
	    !NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		reply_nterror(req, nt_status_squash(nt_status));
		return;
	}

	nt_status = nt_status_squash(nt_status);
	SIVAL(req->outbuf, smb_rcls, NT_STATUS_V(nt_status));
	SSVAL(req->outbuf, smb_vwv0, 0xFF); /* no chaining possible */
	SSVAL(req->outbuf, smb_vwv3, blob.length);

	if ((message_push_blob(&req->outbuf, blob) == -1)
	    || (push_signature(&req->outbuf) == -1)) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
	}
}

/****************************************************************************
 Do a 'guest' logon, getting back the
****************************************************************************/

static NTSTATUS check_guest_password(const struct tsocket_address *remote_address,
				     struct auth_serversupplied_info **server_info)
{
	struct auth_context *auth_context;
	struct auth_usersupplied_info *user_info = NULL;

	NTSTATUS nt_status;
	static unsigned char chal[8] = { 0, };

	DEBUG(3,("Got anonymous request\n"));

	nt_status = make_auth_context_fixed(talloc_tos(), &auth_context, chal);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (!make_user_info_guest(remote_address, &user_info)) {
		TALLOC_FREE(auth_context);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = auth_context->check_ntlm_password(auth_context,
						user_info,
						server_info);
	TALLOC_FREE(auth_context);
	free_user_info(&user_info);
	return nt_status;
}


#ifdef HAVE_KRB5

#if 0
/* Experiment that failed. See "only happens with a KDC" comment below. */
/****************************************************************************
 Cerate a clock skew error blob for a Windows client.
****************************************************************************/

static bool make_krb5_skew_error(DATA_BLOB *pblob_out)
{
	krb5_context context = NULL;
	krb5_error_code kerr = 0;
	krb5_data reply;
	krb5_principal host_princ = NULL;
	char *host_princ_s = NULL;
	bool ret = False;

	*pblob_out = data_blob_null;

	initialize_krb5_error_table();
	kerr = krb5_init_context(&context);
	if (kerr) {
		return False;
	}
	/* Create server principal. */
	asprintf(&host_princ_s, "%s$@%s", lp_netbios_name(), lp_realm());
	if (!host_princ_s) {
		goto out;
	}
	strlower_m(host_princ_s);

	kerr = smb_krb5_parse_name(context, host_princ_s, &host_princ);
	if (kerr) {
		DEBUG(10,("make_krb5_skew_error: smb_krb5_parse_name failed "
			"for name %s: Error %s\n",
			host_princ_s, error_message(kerr) ));
		goto out;
	}

	kerr = smb_krb5_mk_error(context, KRB5KRB_AP_ERR_SKEW,
			host_princ, &reply);
	if (kerr) {
		DEBUG(10,("make_krb5_skew_error: smb_krb5_mk_error "
			"failed: Error %s\n",
			error_message(kerr) ));
		goto out;
	}

	*pblob_out = data_blob(reply.data, reply.length);
	kerberos_free_data_contents(context,&reply);
	ret = True;

  out:

	if (host_princ_s) {
		SAFE_FREE(host_princ_s);
	}
	if (host_princ) {
		krb5_free_principal(context, host_princ);
	}
	krb5_free_context(context);
	return ret;
}
#endif

/****************************************************************************
 Reply to a session setup spnego negotiate packet for kerberos.
****************************************************************************/

static void reply_spnego_kerberos(struct smb_request *req,
				  DATA_BLOB *secblob,
				  const char *mechOID,
				  uint16 vuid,
				  bool *p_invalidate_vuid)
{
	TALLOC_CTX *mem_ctx;
	DATA_BLOB ticket;
	struct passwd *pw;
	int sess_vuid = req->vuid;
	NTSTATUS ret = NT_STATUS_OK;
	DATA_BLOB ap_rep, ap_rep_wrapped, response;
	struct auth_session_info *session_info = NULL;
	DATA_BLOB session_key = data_blob_null;
	uint8 tok_id[2];
	DATA_BLOB nullblob = data_blob_null;
	bool map_domainuser_to_guest = False;
	bool username_was_mapped;
	struct PAC_LOGON_INFO *logon_info = NULL;
	struct smbd_server_connection *sconn = req->sconn;
	char *principal;
	char *user;
	char *domain;
	char *real_username;

	ZERO_STRUCT(ticket);
	ZERO_STRUCT(ap_rep);
	ZERO_STRUCT(ap_rep_wrapped);
	ZERO_STRUCT(response);

	/* Normally we will always invalidate the intermediate vuid. */
	*p_invalidate_vuid = True;

	mem_ctx = talloc_init("reply_spnego_kerberos");
	if (mem_ctx == NULL) {
		reply_nterror(req, nt_status_squash(NT_STATUS_NO_MEMORY));
		return;
	}

	if (!spnego_parse_krb5_wrap(mem_ctx, *secblob, &ticket, tok_id)) {
		talloc_destroy(mem_ctx);
		reply_nterror(req, nt_status_squash(NT_STATUS_LOGON_FAILURE));
		return;
	}

	ret = ads_verify_ticket(mem_ctx, lp_realm(), 0, &ticket,
				&principal, &logon_info, &ap_rep,
				&session_key, True);

	data_blob_free(&ticket);

	if (!NT_STATUS_IS_OK(ret)) {
#if 0
		/* Experiment that failed.
		 * See "only happens with a KDC" comment below. */

		if (NT_STATUS_EQUAL(ret, NT_STATUS_TIME_DIFFERENCE_AT_DC)) {

			/*
			 * Windows in this case returns
			 * NT_STATUS_MORE_PROCESSING_REQUIRED
			 * with a negTokenTarg blob containing an krb5_error
			 * struct ASN1 encoded containing KRB5KRB_AP_ERR_SKEW.
			 * The client then fixes its clock and continues rather
			 * than giving an error. JRA.
			 * -- Looks like this only happens with a KDC. JRA.
			 */

			bool ok = make_krb5_skew_error(&ap_rep);
			if (!ok) {
				talloc_destroy(mem_ctx);
				return ERROR_NT(nt_status_squash(
						NT_STATUS_LOGON_FAILURE));
			}
			ap_rep_wrapped = spnego_gen_krb5_wrap(ap_rep,
					TOK_ID_KRB_ERROR);
			response = spnego_gen_auth_response(&ap_rep_wrapped,
					ret, OID_KERBEROS5_OLD);
			reply_sesssetup_blob(conn, inbuf, outbuf, response,
					NT_STATUS_MORE_PROCESSING_REQUIRED);

			/*
			 * In this one case we don't invalidate the
			 * intermediate vuid as we're expecting the client
			 * to re-use it for the next sessionsetupX packet. JRA.
			 */

			*p_invalidate_vuid = False;

			data_blob_free(&ap_rep);
			data_blob_free(&ap_rep_wrapped);
			data_blob_free(&response);
			talloc_destroy(mem_ctx);
			return -1; /* already replied */
		}
#else
		if (!NT_STATUS_EQUAL(ret, NT_STATUS_TIME_DIFFERENCE_AT_DC)) {
			ret = NT_STATUS_LOGON_FAILURE;
		}
#endif
		DEBUG(1,("Failed to verify incoming ticket with error %s!\n",
				nt_errstr(ret)));
		talloc_destroy(mem_ctx);
		reply_nterror(req, nt_status_squash(ret));
		return;
	}

	ret = get_user_from_kerberos_info(talloc_tos(),
					  sconn->remote_hostname,
					  principal, logon_info,
					  &username_was_mapped,
					  &map_domainuser_to_guest,
					  &user, &domain,
					  &real_username, &pw);
	if (!NT_STATUS_IS_OK(ret)) {
		data_blob_free(&ap_rep);
		data_blob_free(&session_key);
		talloc_destroy(mem_ctx);
		reply_nterror(req,nt_status_squash(NT_STATUS_LOGON_FAILURE));
		return;
	}

	/* save the PAC data if we have it */
	if (logon_info) {
		netsamlogon_cache_store(user, &logon_info->info3);
	}

	/* setup the string used by %U */
	sub_set_smb_name(real_username);

	/* reload services so that the new %U is taken into account */
	reload_services(sconn, conn_snum_used, true);

	ret = make_session_info_krb5(mem_ctx,
				     user, domain, real_username, pw,
				     logon_info, map_domainuser_to_guest,
				     username_was_mapped,
				     &session_key,
				     &session_info);
	data_blob_free(&session_key);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("make_server_info_krb5 failed!\n"));
		data_blob_free(&ap_rep);
		TALLOC_FREE(mem_ctx);
		reply_nterror(req, nt_status_squash(ret));
		return;
	}

	if (!is_partial_auth_vuid(sconn, sess_vuid)) {
		sess_vuid = register_initial_vuid(sconn);
	}

	/* register_existing_vuid keeps the server info */
	/* register_existing_vuid takes ownership of session_key on success,
	 * no need to free after this on success. A better interface would copy
	 * it.... */

	sess_vuid = register_existing_vuid(sconn, sess_vuid,
					   session_info, nullblob);

	reply_outbuf(req, 4, 0);
	SSVAL(req->outbuf,smb_uid,sess_vuid);

	if (sess_vuid == UID_FIELD_INVALID ) {
		ret = NT_STATUS_LOGON_FAILURE;
	} else {
		/* current_user_info is changed on new vuid */
		reload_services(sconn, conn_snum_used, true);

		SSVAL(req->outbuf, smb_vwv3, 0);

		if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
			SSVAL(req->outbuf,smb_vwv2,1);
		}

		SSVAL(req->outbuf, smb_uid, sess_vuid);

		/* Successful logon. Keep this vuid. */
		*p_invalidate_vuid = False;
	}

        /* wrap that up in a nice GSS-API wrapping */
	if (NT_STATUS_IS_OK(ret)) {
		ap_rep_wrapped = spnego_gen_krb5_wrap(talloc_tos(), ap_rep,
				TOK_ID_KRB_AP_REP);
	} else {
		ap_rep_wrapped = data_blob_null;
	}
	response = spnego_gen_auth_response(talloc_tos(), &ap_rep_wrapped, ret,
			mechOID);
	reply_sesssetup_blob(req, response, ret);

	data_blob_free(&ap_rep);
	data_blob_free(&ap_rep_wrapped);
	data_blob_free(&response);
	TALLOC_FREE(mem_ctx);
}

#endif

/****************************************************************************
 Send a session setup reply, wrapped in SPNEGO.
 Get vuid and check first.
 End the NTLMSSP exchange context if we are OK/complete fail
 This should be split into two functions, one to handle each
 leg of the NTLM auth steps.
***************************************************************************/

static void reply_spnego_ntlmssp(struct smb_request *req,
				 uint16 vuid,
				 struct gensec_security **gensec_security,
				 DATA_BLOB *ntlmssp_blob, NTSTATUS nt_status,
				 const char *OID,
				 bool wrap)
{
	bool do_invalidate = true;
	DATA_BLOB response;
	struct auth_session_info *session_info = NULL;
	struct smbd_server_connection *sconn = req->sconn;

	if (NT_STATUS_IS_OK(nt_status)) {
		nt_status = gensec_session_info(*gensec_security,
						talloc_tos(),
						&session_info);
	}

	reply_outbuf(req, 4, 0);

	SSVAL(req->outbuf, smb_uid, vuid);

	if (NT_STATUS_IS_OK(nt_status)) {
		DATA_BLOB nullblob = data_blob_null;

		if (!is_partial_auth_vuid(sconn, vuid)) {
			nt_status = NT_STATUS_LOGON_FAILURE;
			goto out;
		}

		/* register_existing_vuid keeps the server info */
		if (register_existing_vuid(sconn, vuid,
					   session_info, nullblob) !=
					   vuid) {
			/* The problem is, *gensec_security points
			 * into the vuser this will have
			 * talloc_free()'ed in
			 * register_existing_vuid() */
			do_invalidate = false;
			nt_status = NT_STATUS_LOGON_FAILURE;
			goto out;
		}

		/* current_user_info is changed on new vuid */
		reload_services(sconn, conn_snum_used, true);

		SSVAL(req->outbuf, smb_vwv3, 0);

		if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
			SSVAL(req->outbuf,smb_vwv2,1);
		}
	}

  out:

	if (wrap) {
		response = spnego_gen_auth_response(talloc_tos(),
				ntlmssp_blob,
				nt_status, OID);
	} else {
		response = *ntlmssp_blob;
	}

	reply_sesssetup_blob(req, response, nt_status);
	if (wrap) {
		data_blob_free(&response);
	}

	/* NT_STATUS_MORE_PROCESSING_REQUIRED from our NTLMSSP code tells us,
	   and the other end, that we are not finished yet. */

	if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		/* NB. This is *NOT* an error case. JRA */
		if (do_invalidate) {
			TALLOC_FREE(*gensec_security);
			if (!NT_STATUS_IS_OK(nt_status)) {
				/* Kill the intermediate vuid */
				invalidate_vuid(sconn, vuid);
			}
		}
	}
}

/****************************************************************************
 Is this a krb5 mechanism ?
****************************************************************************/

NTSTATUS parse_spnego_mechanisms(TALLOC_CTX *ctx,
		DATA_BLOB blob_in,
		DATA_BLOB *pblob_out,
		char **kerb_mechOID)
{
	char *OIDs[ASN1_MAX_OIDS];
	int i;
	NTSTATUS ret = NT_STATUS_OK;

	*kerb_mechOID = NULL;

	/* parse out the OIDs and the first sec blob */
	if (!spnego_parse_negTokenInit(ctx, blob_in, OIDs, NULL, pblob_out) ||
			(OIDs[0] == NULL)) {
		return NT_STATUS_LOGON_FAILURE;
	}

	/* only look at the first OID for determining the mechToken --
	   according to RFC2478, we should choose the one we want
	   and renegotiate, but i smell a client bug here..

	   Problem observed when connecting to a member (samba box)
	   of an AD domain as a user in a Samba domain.  Samba member
	   server sent back krb5/mskrb5/ntlmssp as mechtypes, but the
	   client (2ksp3) replied with ntlmssp/mskrb5/krb5 and an
	   NTLMSSP mechtoken.                 --jerry              */

#ifdef HAVE_KRB5
	if (strcmp(OID_KERBEROS5, OIDs[0]) == 0 ||
	    strcmp(OID_KERBEROS5_OLD, OIDs[0]) == 0) {
		*kerb_mechOID = talloc_strdup(ctx, OIDs[0]);
		if (*kerb_mechOID == NULL) {
			ret = NT_STATUS_NO_MEMORY;
		}
	}
#endif

	for (i=0;OIDs[i];i++) {
		DEBUG(5,("parse_spnego_mechanisms: Got OID %s\n", OIDs[i]));
		talloc_free(OIDs[i]);
	}
	return ret;
}

/****************************************************************************
 Fall back from krb5 to NTLMSSP.
****************************************************************************/

static void reply_spnego_downgrade_to_ntlmssp(struct smb_request *req,
						uint16 vuid)
{
	DATA_BLOB response;

	reply_outbuf(req, 4, 0);
        SSVAL(req->outbuf,smb_uid,vuid);

	DEBUG(3,("reply_spnego_downgrade_to_ntlmssp: Got krb5 ticket in SPNEGO "
		"but set to downgrade to NTLMSSP\n"));

	response = spnego_gen_auth_response(talloc_tos(), NULL,
			NT_STATUS_MORE_PROCESSING_REQUIRED,
			OID_NTLMSSP);
	reply_sesssetup_blob(req, response, NT_STATUS_MORE_PROCESSING_REQUIRED);
	data_blob_free(&response);
}

/****************************************************************************
 Reply to a session setup spnego negotiate packet.
****************************************************************************/

static void reply_spnego_negotiate(struct smb_request *req,
				   uint16 vuid,
				   DATA_BLOB blob1,
				   struct gensec_security **gensec_security)
{
	DATA_BLOB secblob;
	DATA_BLOB chal;
	char *kerb_mech = NULL;
	NTSTATUS status;
	struct smbd_server_connection *sconn = req->sconn;

	status = parse_spnego_mechanisms(talloc_tos(),
			blob1, &secblob, &kerb_mech);
	if (!NT_STATUS_IS_OK(status)) {
		/* Kill the intermediate vuid */
		invalidate_vuid(sconn, vuid);
		reply_nterror(req, nt_status_squash(status));
		return;
	}

	DEBUG(3,("reply_spnego_negotiate: Got secblob of size %lu\n",
				(unsigned long)secblob.length));

#ifdef HAVE_KRB5
	if (kerb_mech && ((lp_security()==SEC_ADS) ||
				USE_KERBEROS_KEYTAB) ) {
		bool destroy_vuid = True;
		reply_spnego_kerberos(req, &secblob, kerb_mech,
				      vuid, &destroy_vuid);
		data_blob_free(&secblob);
		if (destroy_vuid) {
			/* Kill the intermediate vuid */
			invalidate_vuid(sconn, vuid);
		}
		TALLOC_FREE(kerb_mech);
		return;
	}
#endif

	TALLOC_FREE(*gensec_security);

	if (kerb_mech) {
		data_blob_free(&secblob);
		/* The mechtoken is a krb5 ticket, but
		 * we need to fall back to NTLM. */
		reply_spnego_downgrade_to_ntlmssp(req, vuid);
		TALLOC_FREE(kerb_mech);
		return;
	}

	status = auth_generic_prepare(NULL, sconn->remote_address,
				      gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		/* Kill the intermediate vuid */
		invalidate_vuid(sconn, vuid);
		reply_nterror(req, nt_status_squash(status));
		return;
	}

	gensec_want_feature(*gensec_security, GENSEC_FEATURE_SESSION_KEY);
	gensec_want_feature(*gensec_security, GENSEC_FEATURE_UNIX_TOKEN);

	status = gensec_start_mech_by_oid(*gensec_security, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		/* Kill the intermediate vuid */
		invalidate_vuid(sconn, vuid);
		reply_nterror(req, nt_status_squash(status));
		return;
	}

	status = gensec_update(*gensec_security, talloc_tos(),
			       NULL, secblob, &chal);

	data_blob_free(&secblob);

	reply_spnego_ntlmssp(req, vuid, gensec_security,
			     &chal, status, OID_NTLMSSP, true);

	data_blob_free(&chal);

	/* already replied */
	return;
}

/****************************************************************************
 Reply to a session setup spnego auth packet.
****************************************************************************/

static void reply_spnego_auth(struct smb_request *req,
			      uint16 vuid,
			      DATA_BLOB blob1,
			      struct gensec_security **gensec_security)
{
	DATA_BLOB auth = data_blob_null;
	DATA_BLOB auth_reply = data_blob_null;
	DATA_BLOB secblob = data_blob_null;
	NTSTATUS status = NT_STATUS_LOGON_FAILURE;
	struct smbd_server_connection *sconn = req->sconn;

	if (!spnego_parse_auth(talloc_tos(), blob1, &auth)) {
#if 0
		file_save("auth.dat", blob1.data, blob1.length);
#endif
		/* Kill the intermediate vuid */
		invalidate_vuid(sconn, vuid);

		reply_nterror(req, nt_status_squash(
				      NT_STATUS_LOGON_FAILURE));
		return;
	}

	if (auth.data[0] == ASN1_APPLICATION(0)) {
		/* Might be a second negTokenTarg packet */
		char *kerb_mech = NULL;

		status = parse_spnego_mechanisms(talloc_tos(),
				auth, &secblob, &kerb_mech);

		if (!NT_STATUS_IS_OK(status)) {
			/* Kill the intermediate vuid */
			invalidate_vuid(sconn, vuid);
			reply_nterror(req, nt_status_squash(status));
			return;
		}

		DEBUG(3,("reply_spnego_auth: Got secblob of size %lu\n",
				(unsigned long)secblob.length));
#ifdef HAVE_KRB5
		if (kerb_mech && ((lp_security()==SEC_ADS) ||
					USE_KERBEROS_KEYTAB)) {
			bool destroy_vuid = True;
			reply_spnego_kerberos(req, &secblob, kerb_mech,
					      vuid, &destroy_vuid);
			data_blob_free(&secblob);
			data_blob_free(&auth);
			if (destroy_vuid) {
				/* Kill the intermediate vuid */
				invalidate_vuid(sconn, vuid);
			}
			TALLOC_FREE(kerb_mech);
			return;
		}
#endif
		/* Can't blunder into NTLMSSP auth if we have
		 * a krb5 ticket. */

		if (kerb_mech) {
			/* Kill the intermediate vuid */
			invalidate_vuid(sconn, vuid);
			DEBUG(3,("reply_spnego_auth: network "
				"misconfiguration, client sent us a "
				"krb5 ticket and kerberos security "
				"not enabled\n"));
			reply_nterror(req, nt_status_squash(
					NT_STATUS_LOGON_FAILURE));
			TALLOC_FREE(kerb_mech);
		}
	}

	/* If we get here it wasn't a negTokenTarg auth packet. */
	data_blob_free(&secblob);

	if (!*gensec_security) {
		status = auth_generic_prepare(NULL, sconn->remote_address,
					      gensec_security);
		if (!NT_STATUS_IS_OK(status)) {
			/* Kill the intermediate vuid */
			invalidate_vuid(sconn, vuid);
			reply_nterror(req, nt_status_squash(status));
			return;
		}

		gensec_want_feature(*gensec_security, GENSEC_FEATURE_SESSION_KEY);
		gensec_want_feature(*gensec_security, GENSEC_FEATURE_UNIX_TOKEN);

		status = gensec_start_mech_by_oid(*gensec_security, GENSEC_OID_NTLMSSP);
		if (!NT_STATUS_IS_OK(status)) {
			/* Kill the intermediate vuid */
			invalidate_vuid(sconn, vuid);
			reply_nterror(req, nt_status_squash(status));
			return;
		}
	}

	status = gensec_update(*gensec_security, talloc_tos(),
			       NULL, auth, &auth_reply);

	data_blob_free(&auth);

	/* Don't send the mechid as we've already sent this (RFC4178). */

	reply_spnego_ntlmssp(req, vuid,
			     gensec_security,
			     &auth_reply, status, NULL, true);

	data_blob_free(&auth_reply);

	/* and tell smbd that we have already replied to this packet */
	return;
}

/****************************************************************************
 Reply to a session setup command.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

static void reply_sesssetup_and_X_spnego(struct smb_request *req)
{
	const uint8 *p;
	DATA_BLOB blob1;
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
	DATA_BLOB chal;

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
	blob1 = data_blob(p, MIN(bufrem, data_blob_len));

#if 0
	file_save("negotiate.dat", blob1.data, blob1.length);
#endif

	p2 = (const char *)req->buf + blob1.length;

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

	/* Do we have a valid vuid now ? */
	if (!is_partial_auth_vuid(sconn, vuid)) {
		/* No, start a new authentication setup. */
		vuid = register_initial_vuid(sconn);
		if (vuid == UID_FIELD_INVALID) {
			data_blob_free(&blob1);
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
			data_blob_free(&blob1);
			reply_nterror(req, nt_status_squash(status));
			return;
		}

		gensec_want_feature(vuser->gensec_security, GENSEC_FEATURE_SESSION_KEY);
		gensec_want_feature(vuser->gensec_security, GENSEC_FEATURE_UNIX_TOKEN);

		if (sconn->use_gensec_hook) {
			status = gensec_start_mech_by_oid(vuser->gensec_security, GENSEC_OID_SPNEGO);
		} else {
			status = gensec_start_mech_by_oid(vuser->gensec_security, GENSEC_OID_NTLMSSP);
		}
		if (!NT_STATUS_IS_OK(status)) {
			/* Kill the intermediate vuid */
			invalidate_vuid(sconn, vuid);
			data_blob_free(&blob1);
			reply_nterror(req, nt_status_squash(status));
			return;
		}
	}

	status = gensec_update(vuser->gensec_security,
			       talloc_tos(), NULL,
			       blob1, &chal);

	data_blob_free(&blob1);

	reply_spnego_ntlmssp(req, vuid,
			     &vuser->gensec_security,
			     &chal, status, NULL, false);
	data_blob_free(&chal);
	return;
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
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_session_info *session_info = NULL;
	uint16 smb_flag2 = req->flags2;

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
		} else if (lp_security() != SEC_SHARE) {
			/*
			 * In share level we should ignore any passwords, so
 			 * only read them if we're not.
 			 */
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

	if (lp_security() == SEC_SHARE) {
		char *sub_user_mapped = NULL;
		/* In share level we should ignore any passwords */

		data_blob_free(&lm_resp);
		data_blob_free(&nt_resp);
		data_blob_clear_free(&plaintext_password);

		(void)map_username(talloc_tos(), sub_user, &sub_user_mapped);
		if (!sub_user_mapped) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBsesssetupX);
			return;
		}
		fstrcpy(sub_user, sub_user_mapped);
		add_session_user(sconn, sub_user);
		add_session_workgroup(sconn, domain);
		/* Then force it to null for the benfit of the code below */
		user = "";
	}

	if (!*user) {

		nt_status = check_guest_password(sconn->remote_address, &server_info);

	} else if (doencrypt) {
		struct auth_context *negprot_auth_context = NULL;
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
			nt_status = negprot_auth_context->check_ntlm_password(
					negprot_auth_context,
					user_info,
					&server_info);
		}
	} else {
		struct auth_context *plaintext_auth_context = NULL;

		nt_status = make_auth_context_subsystem(
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
				nt_status = plaintext_auth_context->check_ntlm_password(
						plaintext_auth_context,
						user_info,
						&server_info);

				TALLOC_FREE(plaintext_auth_context);
			}
		}
	}

	free_user_info(&user_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		nt_status = do_map_to_guest_server_info(nt_status, &server_info,
							user, domain);
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		data_blob_free(&nt_resp);
		data_blob_free(&lm_resp);
		data_blob_clear_free(&plaintext_password);
		reply_nterror(req, nt_status_squash(nt_status));
		END_PROFILE(SMBsesssetupX);
		return;
	}

	nt_status = create_local_token(req, server_info, NULL, sub_user, &session_info);
	TALLOC_FREE(server_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(10, ("create_local_token failed: %s\n",
			   nt_errstr(nt_status)));
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
	if (get_Protocol() >= PROTOCOL_NT1) {
		push_signature(&req->outbuf);
		/* perhaps grab OS version here?? */
	}

	if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
		SSVAL(req->outbuf,smb_vwv2,1);
	}

	/* register the name and uid as being validated, so further connections
	   to a uid can get through without a password, on the same VC */

	if (lp_security() == SEC_SHARE) {
		sess_vuid = UID_FIELD_INVALID;
		TALLOC_FREE(session_info);
	} else {
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
	}

	data_blob_free(&nt_resp);
	data_blob_free(&lm_resp);

	SSVAL(req->outbuf,smb_uid,sess_vuid);
	SSVAL(discard_const_p(char, req->inbuf),smb_uid,sess_vuid);
	req->vuid = sess_vuid;

	if (!sconn->smb1.sessions.done_sesssetup) {
		sconn->smb1.sessions.max_send =
			MIN(sconn->smb1.sessions.max_send,smb_bufsize);
	}
	sconn->smb1.sessions.done_sesssetup = true;

	END_PROFILE(SMBsesssetupX);
	chain_reply(req);
	return;
}
