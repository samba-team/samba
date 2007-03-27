/* 
   Unix SMB/CIFS implementation.
   SMB Transport encryption (sealing) code - server code.
   Copyright (C) Jeremy Allison 2007.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/******************************************************************************
 Server side encryption.
******************************************************************************/

/******************************************************************************
 Global server state.
******************************************************************************/

struct smb_srv_trans_enc_ctx {
	struct smb_trans_enc_state *es;
	AUTH_NTLMSSP_STATE *auth_ntlmssp_state; /* Must be kept in sync with pointer in ec->ntlmssp_state. */
};

static struct smb_srv_trans_enc_ctx *partial_srv_trans_enc_ctx;
static struct smb_srv_trans_enc_ctx *srv_trans_enc_ctx;

/******************************************************************************
 Is server encryption on ?
******************************************************************************/

BOOL srv_encryption_on(void)
{
	if (srv_trans_enc_ctx) {
		return common_encryption_on(srv_trans_enc_ctx->es);
	}
	return False;
}

/******************************************************************************
 Create an auth_ntlmssp_state and ensure pointer copy is correct.
******************************************************************************/

static NTSTATUS make_auth_ntlmssp(struct smb_srv_trans_enc_ctx *ec)
{
	NTSTATUS status = auth_ntlmssp_start(&ec->auth_ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	/*
	 * We must remember to update the pointer copy for the common
	 * functions after any auth_ntlmssp_start/auth_ntlmssp_end.
	 */
	ec->es->s.ntlmssp_state = ec->auth_ntlmssp_state->ntlmssp_state;
	return status;
}

/******************************************************************************
 Destroy an auth_ntlmssp_state and ensure pointer copy is correct.
******************************************************************************/

static void destroy_auth_ntlmssp(struct smb_srv_trans_enc_ctx *ec)
{
	/*
	 * We must remember to update the pointer copy for the common
	 * functions after any auth_ntlmssp_start/auth_ntlmssp_end.
	 */

	if (ec->auth_ntlmssp_state) {
		auth_ntlmssp_end(&ec->auth_ntlmssp_state);
		/* The auth_ntlmssp_end killed this already. */
		ec->es->s.ntlmssp_state = NULL;
	}
}

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)

/******************************************************************************
 Import a name.
******************************************************************************/

static NTSTATUS get_gss_creds(const char *service,
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

	asprintf(&host_princ_s, "%s@%s", service, name);
	if (host_princ_s == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	input_name.value = host_princ_s;
	input_name.length = strlen(host_princ_s) + 1;

	ret = gss_import_name(&min,
				&input_name,
				GSS_C_NT_HOSTBASED_SERVICE,
				&srv_name);

	if (ret != GSS_S_COMPLETE) {
		SAFE_FREE(host_princ_s);
		return map_nt_error_from_gss(ret, min);
	}

	ret = gss_acquire_cred(&min,
				&srv_name,
				GSS_C_INDEFINITE,
				GSS_C_NULL_OID_SET,
				cred_type,
				p_srv_cred,
				NULL,
				NULL);

	if (ret != GSS_S_COMPLETE) {
		status = map_nt_error_from_gss(ret, min);
	}

	SAFE_FREE(host_princ_s);
	gss_release_name(&min, &srv_name);
	return status;
}

/******************************************************************************
 Create a gss state.
******************************************************************************/

static NTSTATUS make_auth_gss(struct smb_srv_trans_enc_ctx *ec)
{
	NTSTATUS status;
	gss_cred_id_t srv_cred;
	fstring fqdn;

	name_to_fqdn(fqdn, global_myname());
	strlower_m(fqdn);

	status = get_gss_creds("cifs", fqdn, GSS_C_ACCEPT, &srv_cred);
	if (!NT_STATUS_IS_OK(status)) {
		status = get_gss_creds("host", fqdn, GSS_C_ACCEPT, &srv_cred);
		if (!NT_STATUS_IS_OK(status)) {
			return nt_status_squash(status);
		}
	}

	return NT_STATUS_OK;
}
#endif

/******************************************************************************
 Shutdown a server encryption context.
******************************************************************************/

static void srv_free_encryption_context(struct smb_srv_trans_enc_ctx **pp_ec)
{
	struct smb_srv_trans_enc_ctx *ec = *pp_ec;

	if (!ec) {
		return;
	}

	if (ec->es) {
		switch (ec->es->smb_enc_type) {
			case SMB_TRANS_ENC_NTLM:
				destroy_auth_ntlmssp(ec);
				break;
#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
			case SMB_TRANS_ENC_GSS:
				break;
#endif
		}
		common_free_encryption_state(&ec->es);
	}

	SAFE_FREE(ec);
	*pp_ec = NULL;
}

/******************************************************************************
 Create a server encryption context.
******************************************************************************/

static struct smb_srv_trans_enc_ctx *make_srv_encryption_context(enum smb_trans_enc_type smb_enc_type)
{
	struct smb_srv_trans_enc_ctx *ec;

	ec = SMB_MALLOC_P(struct smb_srv_trans_enc_ctx);
	if (!ec) {
		return NULL;
	}
	ZERO_STRUCTP(partial_srv_trans_enc_ctx);
	ec->es = SMB_MALLOC_P(struct smb_trans_enc_state);
	if (!ec->es) {
		SAFE_FREE(ec);
		return NULL;
	}
	ZERO_STRUCTP(ec->es);
	ec->es->smb_enc_type = smb_enc_type;
	switch (smb_enc_type) {
		case SMB_TRANS_ENC_NTLM:
			{
				NTSTATUS status = make_auth_ntlmssp(ec);
				if (!NT_STATUS_IS_OK(status)) {
					srv_free_encryption_context(&ec);
					return NULL;
				}
			}
			break;

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
		case SMB_TRANS_ENC_GSS:
			/* Acquire our credentials by calling gss_acquire_cred here. */
			{
				NTSTATUS status = make_auth_gss(ec);
				if (!NT_STATUS_IS_OK(status)) {
					srv_free_encryption_context(&ec);
					return NULL;
				}
			}
			break;
#endif
		default:
			srv_free_encryption_context(&ec);
			return NULL;
	}
	return ec;
}

/******************************************************************************
 Free an encryption-allocated buffer.
******************************************************************************/

void srv_free_enc_buffer(char *buf)
{
	/* We know this is an smb buffer, and we
	 * didn't malloc, only copy, for a keepalive,
	 * so ignore session keepalives. */

	if(CVAL(buf,0) == SMBkeepalive) {
		return;
	}

	if (srv_trans_enc_ctx) {
		common_free_enc_buffer(srv_trans_enc_ctx->es, buf);
	}
}

/******************************************************************************
 Decrypt an incoming buffer.
******************************************************************************/

NTSTATUS srv_decrypt_buffer(char *buf)
{
	/* Ignore session keepalives. */
	if(CVAL(buf,0) == SMBkeepalive) {
		return NT_STATUS_OK;
	}

	if (srv_trans_enc_ctx) {
		return common_decrypt_buffer(srv_trans_enc_ctx->es, buf);
	}

	return NT_STATUS_OK;
}

/******************************************************************************
 Encrypt an outgoing buffer. Return the encrypted pointer in buf_out.
******************************************************************************/

NTSTATUS srv_encrypt_buffer(char *buf, char **buf_out)
{
	*buf_out = buf;

	/* Ignore session keepalives. */
	if(CVAL(buf,0) == SMBkeepalive) {
		return NT_STATUS_OK;
	}

	if (srv_trans_enc_ctx) {
		return common_encrypt_buffer(srv_trans_enc_ctx->es, buf, buf_out);
	}
	/* Not encrypting. */
	return NT_STATUS_OK;
}

/******************************************************************************
 Do the gss encryption negotiation. Parameters are in/out.
 Until success we do everything on the partial enc ctx.
******************************************************************************/

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
static NTSTATUS srv_enc_spnego_gss_negotiate(unsigned char **ppdata, size_t *p_data_size, DATA_BLOB secblob)
{
	if (!partial_srv_trans_enc_ctx) {
		partial_srv_trans_enc_ctx = make_srv_encryption_context(SMB_TRANS_ENC_GSS);
		if (!partial_srv_trans_enc_ctx) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	return NT_STATUS_NOT_SUPPORTED;
}
#endif

/******************************************************************************
 Do the NTLM SPNEGO (or raw) encryption negotiation. Parameters are in/out.
 Until success we do everything on the partial enc ctx.
******************************************************************************/

static NTSTATUS srv_enc_ntlm_negotiate(unsigned char **ppdata, size_t *p_data_size, DATA_BLOB secblob, BOOL spnego_wrap)
{
	NTSTATUS status;
	DATA_BLOB chal = data_blob(NULL, 0);
	DATA_BLOB response = data_blob(NULL, 0);

	partial_srv_trans_enc_ctx = make_srv_encryption_context(SMB_TRANS_ENC_NTLM);
	if (!partial_srv_trans_enc_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	status = auth_ntlmssp_update(partial_srv_trans_enc_ctx->auth_ntlmssp_state, secblob, &chal);

	/* status here should be NT_STATUS_MORE_PROCESSING_REQUIRED
	 * for success ... */

	if (spnego_wrap) {
		response = spnego_gen_auth_response(&chal, status, OID_NTLMSSP);
		data_blob_free(&chal);
	} else {
		/* Return the raw blob. */
		response = chal;
	}

	SAFE_FREE(*ppdata);
	*ppdata = response.data;
	*p_data_size = response.length;
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
	DATA_BLOB blob = data_blob(NULL,0);
	DATA_BLOB secblob = data_blob(NULL, 0);
	BOOL got_kerberos_mechanism = False;

	blob = data_blob_const(*ppdata, *p_data_size);

	status = parse_spnego_mechanisms(blob, &secblob, &got_kerberos_mechanism);
	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	/* We should have no partial context at this point. */

	srv_free_encryption_context(&partial_srv_trans_enc_ctx);

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
	if (got_kerberos_mechanism && lp_use_kerberos_keytab() ) {
		status = srv_enc_spnego_gss_negotiate(ppdata, p_data_size, secblob);
	} else 
#endif
	{
		status = srv_enc_ntlm_negotiate(ppdata, p_data_size, secblob, True);
	}

	data_blob_free(&secblob);

	if (!NT_STATUS_EQUAL(status,NT_STATUS_MORE_PROCESSING_REQUIRED) && !NT_STATUS_IS_OK(status)) {
		srv_free_encryption_context(&partial_srv_trans_enc_ctx);
		return nt_status_squash(status);
	}

	if (NT_STATUS_IS_OK(status)) {
		/* Return the context we're using for this encryption state. */
		*pparam = SMB_MALLOC(2);
		if (!*pparam) {
			return NT_STATUS_NO_MEMORY;
		}
		SSVAL(*pparam,0,partial_srv_trans_enc_ctx->es->enc_ctx_num);
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
	DATA_BLOB blob = data_blob(NULL,0);
	DATA_BLOB auth = data_blob(NULL,0);
	DATA_BLOB auth_reply = data_blob(NULL,0);
	DATA_BLOB response = data_blob(NULL,0);
	struct smb_srv_trans_enc_ctx *ec = partial_srv_trans_enc_ctx;

	/* We must have a partial context here. */

	if (!ec || !ec->es || ec->auth_ntlmssp_state == NULL || ec->es->smb_enc_type != SMB_TRANS_ENC_NTLM) {
		srv_free_encryption_context(&partial_srv_trans_enc_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	blob = data_blob_const(*ppdata, *p_data_size);
	if (!spnego_parse_auth(blob, &auth)) {
		srv_free_encryption_context(&partial_srv_trans_enc_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = auth_ntlmssp_update(ec->auth_ntlmssp_state, auth, &auth_reply);
	data_blob_free(&auth);

	response = spnego_gen_auth_response(&auth_reply, status, OID_NTLMSSP);
	data_blob_free(&auth_reply);

	if (NT_STATUS_IS_OK(status)) {
		/* Return the context we're using for this encryption state. */
		*pparam = SMB_MALLOC(2);
		if (!*pparam) {
			return NT_STATUS_NO_MEMORY;
		}
		SSVAL(*pparam,0,ec->es->enc_ctx_num);
		*p_param_size = 2;
	}

	SAFE_FREE(*ppdata);
	*ppdata = response.data;
	*p_data_size = response.length;
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
	DATA_BLOB response = data_blob(NULL,0);
	struct smb_srv_trans_enc_ctx *ec;

	if (!partial_srv_trans_enc_ctx) {
		/* This is the initial step. */
		status = srv_enc_ntlm_negotiate(ppdata, p_data_size, blob, False);
		if (!NT_STATUS_EQUAL(status,NT_STATUS_MORE_PROCESSING_REQUIRED) && !NT_STATUS_IS_OK(status)) {
			srv_free_encryption_context(&partial_srv_trans_enc_ctx);
			return nt_status_squash(status);
		}
		return status;
	}

	ec = partial_srv_trans_enc_ctx;
	if (!ec || !ec->es || ec->auth_ntlmssp_state == NULL || ec->es->smb_enc_type != SMB_TRANS_ENC_NTLM) {
		srv_free_encryption_context(&partial_srv_trans_enc_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Second step. */
	status = auth_ntlmssp_update(partial_srv_trans_enc_ctx->auth_ntlmssp_state, blob, &response);

	if (NT_STATUS_IS_OK(status)) {
		/* Return the context we're using for this encryption state. */
		*pparam = SMB_MALLOC(2);
		if (!*pparam) {
			return NT_STATUS_NO_MEMORY;
		}
		SSVAL(*pparam,0,ec->es->enc_ctx_num);
		*p_param_size = 2;
	}

	/* Return the raw blob. */
	SAFE_FREE(*ppdata);
	*ppdata = response.data;
	*p_data_size = response.length;
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

static NTSTATUS check_enc_good(struct smb_srv_trans_enc_ctx *ec)
{
	if (!ec || !ec->es) {
		return NT_STATUS_LOGON_FAILURE;
	}

	if (ec->es->smb_enc_type == SMB_TRANS_ENC_NTLM) {
		if ((ec->es->s.ntlmssp_state->neg_flags & (NTLMSSP_NEGOTIATE_SIGN|NTLMSSP_NEGOTIATE_SEAL)) !=
				(NTLMSSP_NEGOTIATE_SIGN|NTLMSSP_NEGOTIATE_SEAL)) {
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
	srv_trans_enc_ctx->es->enc_on = True;

	partial_srv_trans_enc_ctx = NULL;
	return NT_STATUS_OK;
}

/******************************************************************************
 Shutdown all server contexts.
******************************************************************************/

void server_encryption_shutdown(void)
{
	srv_free_encryption_context(&partial_srv_trans_enc_ctx);
	srv_free_encryption_context(&srv_trans_enc_ctx);
}
