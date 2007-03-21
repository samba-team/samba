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
	ec->es->ntlmssp_state = ec->auth_ntlmssp_state->ntlmssp_state;
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
		ec->es->ntlmssp_state = NULL;
	}
}

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
		if (ec->es->smb_enc_type == SMB_TRANS_ENC_NTLM) {
			destroy_auth_ntlmssp(ec);
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
	if (smb_enc_type == SMB_TRANS_ENC_NTLM) {
		NTSTATUS status = make_auth_ntlmssp(ec);
		if (!NT_STATUS_IS_OK(status)) {
			srv_free_encryption_context(&ec);
			return NULL;
		}
	}
	return ec;
}

/******************************************************************************
 Free an encryption-allocated buffer.
******************************************************************************/

void srv_free_enc_buffer(char *buf)
{
	if (srv_trans_enc_ctx) {
		return common_free_enc_buffer(srv_trans_enc_ctx->es, buf);
	}
}

/******************************************************************************
 Decrypt an incoming buffer.
******************************************************************************/

NTSTATUS srv_decrypt_buffer(char *buf)
{
	if (srv_trans_enc_ctx) {
		return common_decrypt_buffer(srv_trans_enc_ctx->es, buf);
	}
	return NT_STATUS_OK;
}

/******************************************************************************
 Encrypt an outgoing buffer. Return the encrypted pointer in buf_out.
******************************************************************************/

NTSTATUS srv_encrypt_buffer(char *buffer, char **buf_out)
{
	if (srv_trans_enc_ctx) {
		return common_encrypt_buffer(srv_trans_enc_ctx->es, buffer, buf_out);
	}
	/* Not encrypting. */
	*buf_out = buffer;
	return NT_STATUS_OK;
}

/******************************************************************************
 Do the gss encryption negotiation. Parameters are in/out.
 Until success we do everything on the partial enc ctx.
******************************************************************************/

#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
static NTSTATUS srv_enc_spnego_gss_negotiate(char **ppdata, size_t *p_data_size, DATA_BLOB secblob)
{
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

static NTSTATUS srv_enc_spnego_negotiate(unsigned char **ppdata, size_t *p_data_size)
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

#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
	if (got_kerberos_mechanism && lp_use_kerberos_keytab()) ) {
		status = srv_enc_spnego_gss_negotiate(ppdata, p_data_size, secblob);
	} else 
#endif
	{
		status = srv_enc_ntlm_negotiate(ppdata, p_data_size, secblob, True);
	}

	data_blob_free(&secblob);

	if (!NT_STATUS_EQUAL(status,NT_STATUS_MORE_PROCESSING_REQUIRED) && !NT_STATUS_IS_OK(status)) {
		srv_free_encryption_context(&partial_srv_trans_enc_ctx);
	}

	return status;
}

/******************************************************************************
 Complete a SPNEGO encryption negotiation. Parameters are in/out.
 We only get this for a NTLM auth second stage.
******************************************************************************/

static NTSTATUS srv_enc_spnego_ntlm_auth(unsigned char **ppdata, size_t *p_data_size)
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

	SAFE_FREE(*ppdata);
	*ppdata = response.data;
	*p_data_size = response.length;
	return status;
}

/******************************************************************************
 Raw NTLM encryption negotiation. Parameters are in/out.
 This function does both steps.
******************************************************************************/

static NTSTATUS srv_enc_raw_ntlm_auth(unsigned char **ppdata, size_t *p_data_size)
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

	/* Return the raw blob. */
	SAFE_FREE(*ppdata);
	*ppdata = response.data;
	*p_data_size = response.length;
	return status;
}

/******************************************************************************
 Do the SPNEGO encryption negotiation. Parameters are in/out.
******************************************************************************/

NTSTATUS srv_request_encryption_setup(unsigned char **ppdata, size_t *p_data_size)
{
	unsigned char *pdata = *ppdata;

	if (*p_data_size < 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (pdata[0] == ASN1_APPLICATION(0)) {
		/* 
		 * Until success we do everything on the partial
		 * enc state.
		 */
		/* its a negTokenTarg packet */
		return srv_enc_spnego_negotiate(ppdata, p_data_size);
	}

	if (pdata[0] == ASN1_CONTEXT(1)) {
		/* It's an auth packet */
		return srv_enc_spnego_ntlm_auth(ppdata, p_data_size);
	}

	/* Maybe it's a raw unwrapped auth ? */
	if (*p_data_size < 7) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (strncmp((char *)pdata, "NTLMSSP", 7) == 0) {
		return srv_enc_raw_ntlm_auth(ppdata, p_data_size);
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
		if ((ec->es->ntlmssp_state->neg_flags & (NTLMSSP_NEGOTIATE_SIGN|NTLMSSP_NEGOTIATE_SEAL)) !=
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

NTSTATUS srv_encryption_start(void)
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
