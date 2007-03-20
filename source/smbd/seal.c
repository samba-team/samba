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
 Shutdown a server encryption state.
******************************************************************************/

static void srv_free_encryption_context(struct smb_srv_trans_enc_ctx **pp_ec)
{
	struct smb_srv_trans_enc_ctx *ec = *pp_ec;

	if (!ec) {
		return;
	}

	if (ec->es) {
		struct smb_trans_enc_state *es = ec->es;
		if (es->smb_enc_type == SMB_TRANS_ENC_NTLM &&
				ec->auth_ntlmssp_state) {
			auth_ntlmssp_end(&ec->auth_ntlmssp_state);
			/* The auth_ntlmssp_end killed this already. */
			es->ntlmssp_state = NULL;
		}
		common_free_encryption_state(&ec->es);
	}

	SAFE_FREE(ec);
	*pp_ec = NULL;
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
static NTSTATUS srv_enc_spnego_gss_negotiate(char **ppdata, size_t *p_data_size, DATA_BLOB *psecblob)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif

/******************************************************************************
 Do the SPNEGO encryption negotiation. Parameters are in/out.
 Covers the NTLM case. Based off code in smbd/sesssionsetup.c
 Until success we do everything on the partial enc ctx.
******************************************************************************/

static NTSTATUS srv_enc_spnego_negotiate(unsigned char **ppdata, size_t *p_data_size)
{
	NTSTATUS status;
	DATA_BLOB blob = data_blob(NULL,0);
	DATA_BLOB secblob = data_blob(NULL, 0);
	DATA_BLOB chal = data_blob(NULL, 0);
	DATA_BLOB response = data_blob(NULL, 0);
	BOOL got_kerberos_mechanism = False;
	struct smb_srv_trans_enc_ctx *ec = NULL;

	blob = data_blob_const(*ppdata, *p_data_size);

	status = parse_spnego_mechanisms(blob, &secblob, &got_kerberos_mechanism);
	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	/* We should have no partial context at this point. */

	srv_free_encryption_context(&partial_srv_trans_enc_ctx);

	partial_srv_trans_enc_ctx = SMB_MALLOC_P(struct smb_srv_trans_enc_ctx);
	if (!partial_srv_trans_enc_ctx) {
		data_blob_free(&secblob);
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(partial_srv_trans_enc_ctx);

#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
	if (got_kerberos_mechanism && lp_use_kerberos_keytab()) ) {
		status = srv_enc_spnego_gss_negotiate(ppdata, p_data_size, &secblob);
		if (!NT_STATUS_IS_OK(status)) {
			data_blob_free(&secblob);
			srv_free_encryption_context(&partial_srv_trans_enc_ctx);
		}
		return status;
	}
#endif

	/* Deal with an NTLM enc. setup. */
	ec = partial_srv_trans_enc_ctx;

	status = auth_ntlmssp_start(&ec->auth_ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		srv_free_encryption_context(&partial_srv_trans_enc_ctx);
		return nt_status_squash(status);
	}

	status = auth_ntlmssp_update(ec->auth_ntlmssp_state, secblob, &chal);
	data_blob_free(&secblob);

	/* status here should be NT_STATUS_MORE_PROCESSING_REQUIRED
	 * for success ... */

	response = spnego_gen_auth_response(&chal, status, OID_NTLMSSP);
	data_blob_free(&chal);

	SAFE_FREE(*ppdata);
	*ppdata = response.data;
	*p_data_size = response.length;

	return status;
}

/******************************************************************************
 Complete a SPNEGO encryption negotiation. Parameters are in/out.
******************************************************************************/

static NTSTATUS srv_enc_spnego_auth(unsigned char **ppdata, size_t *p_data_size)
{
	return NT_STATUS_NOT_SUPPORTED;
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
		/* Its a auth packet */
		return srv_enc_spnego_auth(ppdata, p_data_size);
	}

	return NT_STATUS_INVALID_PARAMETER;
}

/******************************************************************************
 Negotiation was successful - turn on server-side encryption.
******************************************************************************/

void srv_encryption_start(void)
{
	srv_free_encryption_context(&srv_trans_enc_ctx);
	/* Steal the partial pointer. Deliberate shallow copy. */
	srv_trans_enc_ctx = partial_srv_trans_enc_ctx;
	srv_trans_enc_ctx->es->enc_on = True;

	partial_srv_trans_enc_ctx = NULL;
}

/******************************************************************************
 Shutdown all server contexts.
******************************************************************************/

void server_encryption_shutdown(void)
{
	srv_free_encryption_context(&partial_srv_trans_enc_ctx);
	srv_free_encryption_context(&srv_trans_enc_ctx);
}
