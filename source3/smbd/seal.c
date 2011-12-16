/* 
   Unix SMB/CIFS implementation.
   SMB Transport encryption (sealing) code - server code.
   Copyright (C) Jeremy Allison 2007.

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/auth/spnego.h"
#include "../auth/ntlmssp/ntlmssp.h"
#include "ntlmssp_wrap.h"
#include "../libcli/smb/smb_seal.h"
#include "../lib/util/asn1.h"
#include "auth.h"
#include "libsmb/libsmb.h"
#include "../lib/tsocket/tsocket.h"
#include "auth/gensec/gensec.h"

/******************************************************************************
 Server side encryption.
******************************************************************************/

/******************************************************************************
 Return global enc context - this must change if we ever do multiple contexts.
******************************************************************************/

static uint16_t srv_enc_ctx(const struct smb_trans_enc_state *es)
{
	return es->enc_ctx_num;
}

/******************************************************************************
 Is this an incoming encrypted packet ?
******************************************************************************/

bool is_encrypted_packet(struct smbd_server_connection *sconn,
			 const uint8_t *inbuf)
{
	NTSTATUS status;
	uint16_t enc_num;

	/* Ignore non-session messages or non 0xFF'E' messages. */
	if(CVAL(inbuf,0)
	   || (smb_len(inbuf) < 8)
	   || !(inbuf[4] == 0xFF && inbuf[5] == 'E')) {
		return false;
	}

	status = get_enc_ctx_num(inbuf, &enc_num);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	/* Encrypted messages are 0xFF'E'<ctx> */
	if (srv_trans_enc_ctx && enc_num == srv_enc_ctx(srv_trans_enc_ctx)) {
		return true;
	}
	return false;
}

/******************************************************************************
 Create an auth_ntlmssp_state and ensure pointer copy is correct.
******************************************************************************/

static NTSTATUS make_auth_ntlmssp(const struct tsocket_address *remote_address,
				  struct smb_trans_enc_state *es)
{
	struct auth_generic_state *auth_ntlmssp_state;
	NTSTATUS status = auth_generic_prepare(remote_address,
					       &auth_ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	gensec_want_feature(auth_ntlmssp_state->gensec_security, GENSEC_FEATURE_SEAL);

	status = auth_ntlmssp_start(auth_ntlmssp_state);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(auth_ntlmssp_state);
		return nt_status_squash(status);
	}

	/* We do not need the auth_ntlmssp layer any more, which was
	 * allocated on NULL, so promote gensec_security to the NULL
	 * context */
	es->s.gensec_security = talloc_move(NULL, &auth_ntlmssp_state->gensec_security);
	TALLOC_FREE(auth_ntlmssp_state);

	return status;
}

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)

/******************************************************************************
 Import a name.
******************************************************************************/

static NTSTATUS get_srv_gss_creds(const char *service,
				const char *name,
				gss_cred_usage_t cred_type,
				gss_cred_id_t *p_srv_cred)
{
	OM_uint32 ret;
	OM_uint32 min;
	gss_name_t srv_name;
	gss_buffer_desc input_name;
	char *host_princ_s = NULL;
	NTSTATUS status = NT_STATUS_OK;

	gss_OID_desc nt_hostbased_service =
	{10, discard_const_p(char, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04")};

	if (asprintf(&host_princ_s, "%s@%s", service, name) == -1) {
		return NT_STATUS_NO_MEMORY;
	}

	input_name.value = host_princ_s;
	input_name.length = strlen(host_princ_s) + 1;

	ret = gss_import_name(&min,
				&input_name,
				&nt_hostbased_service,
				&srv_name);

	DEBUG(10,("get_srv_gss_creds: imported name %s\n",
		host_princ_s ));

	if (ret != GSS_S_COMPLETE) {
		SAFE_FREE(host_princ_s);
		return map_nt_error_from_gss(ret, min);
	}

	/*
	 * We're accessing the krb5.keytab file here.
 	 * ensure we have permissions to do so.
 	 */
	become_root();

	ret = gss_acquire_cred(&min,
				srv_name,
				GSS_C_INDEFINITE,
				GSS_C_NULL_OID_SET,
				cred_type,
				p_srv_cred,
				NULL,
				NULL);
	unbecome_root();

	if (ret != GSS_S_COMPLETE) {
		ADS_STATUS adss = ADS_ERROR_GSS(ret, min);
		DEBUG(10,("get_srv_gss_creds: gss_acquire_cred failed with %s\n",
			ads_errstr(adss)));
		status = map_nt_error_from_gss(ret, min);
	}

	SAFE_FREE(host_princ_s);
	gss_release_name(&min, &srv_name);
	return status;
}

/******************************************************************************
 Create a gss state.
 Try and get the cifs/server@realm principal first, then fall back to
 host/server@realm.
******************************************************************************/

static NTSTATUS make_auth_gss(struct smb_trans_enc_state *es)
{
	NTSTATUS status;
	gss_cred_id_t srv_cred;
	fstring fqdn;

	name_to_fqdn(fqdn, lp_netbios_name());
	strlower_m(fqdn);

	status = get_srv_gss_creds("cifs", fqdn, GSS_C_ACCEPT, &srv_cred);
	if (!NT_STATUS_IS_OK(status)) {
		status = get_srv_gss_creds("host", fqdn, GSS_C_ACCEPT, &srv_cred);
		if (!NT_STATUS_IS_OK(status)) {
			return nt_status_squash(status);
		}
	}

	es->s.gss_state = SMB_MALLOC_P(struct smb_tran_enc_state_gss);
	if (!es->s.gss_state) {
		OM_uint32 min;
		gss_release_cred(&min, &srv_cred);
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(es->s.gss_state);
	es->s.gss_state->creds = srv_cred;

	/* No context yet. */
	es->s.gss_state->gss_ctx = GSS_C_NO_CONTEXT;

	return NT_STATUS_OK;
}
#endif

/******************************************************************************
 Shutdown a server encryption context.
******************************************************************************/

static void srv_free_encryption_context(struct smb_trans_enc_state **pp_es)
{
	struct smb_trans_enc_state *es = *pp_es;

	if (!es) {
		return;
	}

	common_free_encryption_state(&es);

	SAFE_FREE(es);
	*pp_es = NULL;
}

/******************************************************************************
 Create a server encryption context.
******************************************************************************/

static NTSTATUS make_srv_encryption_context(const struct tsocket_address *remote_address,
					    enum smb_trans_enc_type smb_enc_type,
					    struct smb_trans_enc_state **pp_es)
{
	struct smb_trans_enc_state *es;

	*pp_es = NULL;

	ZERO_STRUCTP(partial_srv_trans_enc_ctx);
	es = SMB_MALLOC_P(struct smb_trans_enc_state);
	if (!es) {
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(es);
	es->smb_enc_type = smb_enc_type;
	switch (smb_enc_type) {
		case SMB_TRANS_ENC_NTLM:
			{
				NTSTATUS status = make_auth_ntlmssp(remote_address,
								    es);
				if (!NT_STATUS_IS_OK(status)) {
					srv_free_encryption_context(&es);
					return status;
				}
			}
			break;

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
		case SMB_TRANS_ENC_GSS:
			/* Acquire our credentials by calling gss_acquire_cred here. */
			{
				NTSTATUS status = make_auth_gss(es);
				if (!NT_STATUS_IS_OK(status)) {
					srv_free_encryption_context(&es);
					return status;
				}
			}
			break;
#endif
		default:
			srv_free_encryption_context(&es);
			return NT_STATUS_INVALID_PARAMETER;
	}
	*pp_es = es;
	return NT_STATUS_OK;
}

/******************************************************************************
 Free an encryption-allocated buffer.
******************************************************************************/

void srv_free_enc_buffer(struct smbd_server_connection *sconn, char *buf)
{
	/* We know this is an smb buffer, and we
	 * didn't malloc, only copy, for a keepalive,
	 * so ignore non-session messages. */

	if(CVAL(buf,0)) {
		return;
	}

	if (srv_trans_enc_ctx) {
		common_free_enc_buffer(srv_trans_enc_ctx, buf);
	}
}

/******************************************************************************
 Decrypt an incoming buffer.
******************************************************************************/

NTSTATUS srv_decrypt_buffer(struct smbd_server_connection *sconn, char *buf)
{
	/* Ignore non-session messages. */
	if(CVAL(buf,0)) {
		return NT_STATUS_OK;
	}

	if (srv_trans_enc_ctx) {
		return common_decrypt_buffer(srv_trans_enc_ctx, buf);
	}

	return NT_STATUS_OK;
}

/******************************************************************************
 Encrypt an outgoing buffer. Return the encrypted pointer in buf_out.
******************************************************************************/

NTSTATUS srv_encrypt_buffer(struct smbd_server_connection *sconn, char *buf,
			    char **buf_out)
{
	*buf_out = buf;

	/* Ignore non-session messages. */
	if(CVAL(buf,0)) {
		return NT_STATUS_OK;
	}

	if (srv_trans_enc_ctx) {
		return common_encrypt_buffer(srv_trans_enc_ctx, buf, buf_out);
	}
	/* Not encrypting. */
	return NT_STATUS_OK;
}

/******************************************************************************
 Do the gss encryption negotiation. Parameters are in/out.
 Until success we do everything on the partial enc ctx.
******************************************************************************/

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
static NTSTATUS srv_enc_spnego_gss_negotiate(const struct tsocket_address *remote_address,
					     unsigned char **ppdata,
					     size_t *p_data_size,
					     DATA_BLOB secblob)
{
	OM_uint32 ret;
	OM_uint32 min;
	OM_uint32 flags = 0;
	gss_buffer_desc in_buf, out_buf;
	struct smb_tran_enc_state_gss *gss_state;
	DATA_BLOB auth_reply = data_blob_null;
	DATA_BLOB response = data_blob_null;
	NTSTATUS status;

	if (!partial_srv_trans_enc_ctx) {
		status = make_srv_encryption_context(remote_address,
						     SMB_TRANS_ENC_GSS,
						     &partial_srv_trans_enc_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	gss_state = partial_srv_trans_enc_ctx->s.gss_state;

	in_buf.value = secblob.data;
	in_buf.length = secblob.length;

	out_buf.value = NULL;
	out_buf.length = 0;

	become_root();

	ret = gss_accept_sec_context(&min,
				&gss_state->gss_ctx,
				gss_state->creds,
				&in_buf,
				GSS_C_NO_CHANNEL_BINDINGS,
				NULL,
				NULL,		/* Ignore oids. */
				&out_buf,	/* To return. */
				&flags,
				NULL,		/* Ingore time. */
				NULL);		/* Ignore delegated creds. */
	unbecome_root();

	status = gss_err_to_ntstatus(ret, min);
	if (ret != GSS_S_COMPLETE && ret != GSS_S_CONTINUE_NEEDED) {
		return status;
	}

	/* Ensure we've got sign+seal available. */
	if (ret == GSS_S_COMPLETE) {
		if ((flags & (GSS_C_INTEG_FLAG|GSS_C_CONF_FLAG|GSS_C_REPLAY_FLAG|GSS_C_SEQUENCE_FLAG)) !=
				(GSS_C_INTEG_FLAG|GSS_C_CONF_FLAG|GSS_C_REPLAY_FLAG|GSS_C_SEQUENCE_FLAG)) {
			DEBUG(0,("srv_enc_spnego_gss_negotiate: quality of service not good enough "
				"for SMB sealing.\n"));
			gss_release_buffer(&min, &out_buf);
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	auth_reply = data_blob(out_buf.value, out_buf.length);
	gss_release_buffer(&min, &out_buf);

	/* Wrap in SPNEGO. */
	response = spnego_gen_auth_response(talloc_tos(), &auth_reply, status, OID_KERBEROS5);
	data_blob_free(&auth_reply);

	SAFE_FREE(*ppdata);
	*ppdata = (unsigned char *)memdup(response.data, response.length);
	if ((*ppdata) == NULL && response.length > 0) {
		status = NT_STATUS_NO_MEMORY;
	}
	*p_data_size = response.length;

	data_blob_free(&response);

	return status;
}
#endif

/******************************************************************************
 Do the NTLM SPNEGO (or raw) encryption negotiation. Parameters are in/out.
 Until success we do everything on the partial enc ctx.
******************************************************************************/

static NTSTATUS srv_enc_ntlm_negotiate(const struct tsocket_address *remote_address,
				       unsigned char **ppdata,
				       size_t *p_data_size,
				       DATA_BLOB secblob,
				       bool spnego_wrap)
{
	NTSTATUS status;
	DATA_BLOB chal = data_blob_null;
	DATA_BLOB response = data_blob_null;

	status = make_srv_encryption_context(remote_address,
					     SMB_TRANS_ENC_NTLM,
					     &partial_srv_trans_enc_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = gensec_update(partial_srv_trans_enc_ctx->s.gensec_security,
			       talloc_tos(), NULL,
			       secblob, &chal);

	/* status here should be NT_STATUS_MORE_PROCESSING_REQUIRED
	 * for success ... */

	if (spnego_wrap) {
		response = spnego_gen_auth_response(talloc_tos(), &chal, status, OID_NTLMSSP);
		data_blob_free(&chal);
	} else {
		/* Return the raw blob. */
		response = chal;
	}

	SAFE_FREE(*ppdata);
	*ppdata = (unsigned char *)memdup(response.data, response.length);
	if ((*ppdata) == NULL && response.length > 0) {
		status = NT_STATUS_NO_MEMORY;
	}
	*p_data_size = response.length;
	data_blob_free(&response);

	return status;
}

/******************************************************************************
 Do the SPNEGO encryption negotiation. Parameters are in/out.
 Based off code in smbd/sesssionsetup.c
 Until success we do everything on the partial enc ctx.
******************************************************************************/

static NTSTATUS srv_enc_spnego_negotiate(connection_struct *conn,
					unsigned char **ppdata,
					size_t *p_data_size,
					unsigned char **pparam,
					size_t *p_param_size)
{
	NTSTATUS status;
	DATA_BLOB blob = data_blob_null;
	DATA_BLOB secblob = data_blob_null;
	char *kerb_mech = NULL;

	blob = data_blob_const(*ppdata, *p_data_size);

	status = parse_spnego_mechanisms(talloc_tos(), blob, &secblob, &kerb_mech);
	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	/* We should have no partial context at this point. */

	srv_free_encryption_context(&partial_srv_trans_enc_ctx);

	if (kerb_mech) {
		TALLOC_FREE(kerb_mech);

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
		status = srv_enc_spnego_gss_negotiate(conn->sconn->remote_address,
						      ppdata,
						      p_data_size,
						      secblob);
#else
		/* Currently we don't SPNEGO negotiate
		 * back to NTLMSSP as we do in sessionsetupX. We should... */
		return NT_STATUS_LOGON_FAILURE;
#endif
	} else {
		status = srv_enc_ntlm_negotiate(conn->sconn->remote_address,
						ppdata,
						p_data_size,
						secblob,
						true);
	}

	data_blob_free(&secblob);

	if (!NT_STATUS_EQUAL(status,NT_STATUS_MORE_PROCESSING_REQUIRED) && !NT_STATUS_IS_OK(status)) {
		srv_free_encryption_context(&partial_srv_trans_enc_ctx);
		return nt_status_squash(status);
	}

	if (NT_STATUS_IS_OK(status)) {
		/* Return the context we're using for this encryption state. */
		if (!(*pparam = SMB_MALLOC_ARRAY(unsigned char, 2))) {
			return NT_STATUS_NO_MEMORY;
		}
		SSVAL(*pparam,0,partial_srv_trans_enc_ctx->enc_ctx_num);
		*p_param_size = 2;
	}

	return status;
}

/******************************************************************************
 Complete a SPNEGO encryption negotiation. Parameters are in/out.
 We only get this for a NTLM auth second stage.
******************************************************************************/

static NTSTATUS srv_enc_spnego_ntlm_auth(connection_struct *conn,
					unsigned char **ppdata,
					size_t *p_data_size,
					unsigned char **pparam,
					size_t *p_param_size)
{
	NTSTATUS status;
	DATA_BLOB blob = data_blob_null;
	DATA_BLOB auth = data_blob_null;
	DATA_BLOB auth_reply = data_blob_null;
	DATA_BLOB response = data_blob_null;
	struct smb_trans_enc_state *es = partial_srv_trans_enc_ctx;

	/* We must have a partial context here. */

	if (!es || es->s.gensec_security == NULL || es->smb_enc_type != SMB_TRANS_ENC_NTLM) {
		srv_free_encryption_context(&partial_srv_trans_enc_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	blob = data_blob_const(*ppdata, *p_data_size);
	if (!spnego_parse_auth(talloc_tos(), blob, &auth)) {
		srv_free_encryption_context(&partial_srv_trans_enc_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = gensec_update(es->s.gensec_security, talloc_tos(), NULL, auth, &auth_reply);
	data_blob_free(&auth);

	/* From RFC4178.
	 *
	 *    supportedMech
	 *
	 *          This field SHALL only be present in the first reply from the
	 *                target.
	 * So set mechOID to NULL here.
	 */

	response = spnego_gen_auth_response(talloc_tos(), &auth_reply, status, NULL);
	data_blob_free(&auth_reply);

	if (NT_STATUS_IS_OK(status)) {
		/* Return the context we're using for this encryption state. */
		if (!(*pparam = SMB_MALLOC_ARRAY(unsigned char, 2))) {
			return NT_STATUS_NO_MEMORY;
		}
		SSVAL(*pparam,0,es->enc_ctx_num);
		*p_param_size = 2;
	}

	SAFE_FREE(*ppdata);
	*ppdata = (unsigned char *)memdup(response.data, response.length);
	if ((*ppdata) == NULL && response.length > 0)
		return NT_STATUS_NO_MEMORY;
	*p_data_size = response.length;
	data_blob_free(&response);
	return status;
}

/******************************************************************************
 Raw NTLM encryption negotiation. Parameters are in/out.
 This function does both steps.
******************************************************************************/

static NTSTATUS srv_enc_raw_ntlm_auth(connection_struct *conn,
					unsigned char **ppdata,
					size_t *p_data_size,
					unsigned char **pparam,
					size_t *p_param_size)
{
	NTSTATUS status;
	DATA_BLOB blob = data_blob_const(*ppdata, *p_data_size);
	DATA_BLOB response = data_blob_null;
	struct smb_trans_enc_state *es;

	if (!partial_srv_trans_enc_ctx) {
		/* This is the initial step. */
		status = srv_enc_ntlm_negotiate(conn->sconn->remote_address,
						ppdata,
						p_data_size,
						blob,
						false);
		if (!NT_STATUS_EQUAL(status,NT_STATUS_MORE_PROCESSING_REQUIRED) && !NT_STATUS_IS_OK(status)) {
			srv_free_encryption_context(&partial_srv_trans_enc_ctx);
			return nt_status_squash(status);
		}
		return status;
	}

	es = partial_srv_trans_enc_ctx;
	if (!es || es->s.gensec_security == NULL || es->smb_enc_type != SMB_TRANS_ENC_NTLM) {
		srv_free_encryption_context(&partial_srv_trans_enc_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Second step. */
	status = gensec_update(partial_srv_trans_enc_ctx->s.gensec_security,
			       talloc_tos(), NULL,
			       blob, &response);

	if (NT_STATUS_IS_OK(status)) {
		/* Return the context we're using for this encryption state. */
		if (!(*pparam = SMB_MALLOC_ARRAY(unsigned char, 2))) {
			return NT_STATUS_NO_MEMORY;
		}
		SSVAL(*pparam, 0, es->enc_ctx_num);
		*p_param_size = 2;
	}

	/* Return the raw blob. */
	SAFE_FREE(*ppdata);
	*ppdata = (unsigned char *)memdup(response.data, response.length);
	if ((*ppdata) == NULL && response.length > 0)
		return NT_STATUS_NO_MEMORY;
	*p_data_size = response.length;
	data_blob_free(&response);
	return status;
}

/******************************************************************************
 Do the SPNEGO encryption negotiation. Parameters are in/out.
******************************************************************************/

NTSTATUS srv_request_encryption_setup(connection_struct *conn,
					unsigned char **ppdata,
					size_t *p_data_size,
					unsigned char **pparam,
					size_t *p_param_size)
{
	unsigned char *pdata = *ppdata;

	SAFE_FREE(*pparam);
	*p_param_size = 0;

	if (*p_data_size < 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (pdata[0] == ASN1_APPLICATION(0)) {
		/* its a negTokenTarg packet */
		return srv_enc_spnego_negotiate(conn, ppdata, p_data_size, pparam, p_param_size);
	}

	if (pdata[0] == ASN1_CONTEXT(1)) {
		/* It's an auth packet */
		return srv_enc_spnego_ntlm_auth(conn, ppdata, p_data_size, pparam, p_param_size);
	}

	/* Maybe it's a raw unwrapped auth ? */
	if (*p_data_size < 7) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (strncmp((char *)pdata, "NTLMSSP", 7) == 0) {
		return srv_enc_raw_ntlm_auth(conn, ppdata, p_data_size, pparam, p_param_size);
	}

	DEBUG(1,("srv_request_encryption_setup: Unknown packet\n"));

	return NT_STATUS_LOGON_FAILURE;
}

/******************************************************************************
 Negotiation was successful - turn on server-side encryption.
******************************************************************************/

static NTSTATUS check_enc_good(struct smb_trans_enc_state *es)
{
	if (!es) {
		return NT_STATUS_LOGON_FAILURE;
	}

	if (es->smb_enc_type == SMB_TRANS_ENC_NTLM) {
		if (!gensec_have_feature(es->s.gensec_security, GENSEC_FEATURE_SIGN)) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (!gensec_have_feature(es->s.gensec_security, GENSEC_FEATURE_SEAL)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	/* Todo - check gssapi case. */

	return NT_STATUS_OK;
}

/******************************************************************************
 Negotiation was successful - turn on server-side encryption.
******************************************************************************/

NTSTATUS srv_encryption_start(connection_struct *conn)
{
	NTSTATUS status;

	/* Check that we are really doing sign+seal. */
	status = check_enc_good(partial_srv_trans_enc_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	/* Throw away the context we're using currently (if any). */
	srv_free_encryption_context(&srv_trans_enc_ctx);

	/* Steal the partial pointer. Deliberate shallow copy. */
	srv_trans_enc_ctx = partial_srv_trans_enc_ctx;
	srv_trans_enc_ctx->enc_on = true;

	partial_srv_trans_enc_ctx = NULL;

	DEBUG(1,("srv_encryption_start: context negotiated\n"));
	return NT_STATUS_OK;
}

/******************************************************************************
 Shutdown all server contexts.
******************************************************************************/

void server_encryption_shutdown(struct smbd_server_connection *sconn)
{
	srv_free_encryption_context(&partial_srv_trans_enc_ctx);
	srv_free_encryption_context(&srv_trans_enc_ctx);
}
