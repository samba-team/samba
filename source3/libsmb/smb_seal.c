/* 
   Unix SMB/CIFS implementation.
   SMB Transport encryption (sealing) code.
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

NTSTATUS cli_decrypt_message(struct cli_state *cli)
{
	return NT_STATUS_OK;
}

NTSTATUS cli_encrypt_message(struct cli_state *cli)
{
	return NT_STATUS_OK;
}

/* Server state if we're encrypting SMBs. If NULL then enc is off. */

static struct smb_trans_enc_state *srv_trans_enc_state;

/******************************************************************************
 Is server encryption on ?
******************************************************************************/

BOOL srv_encryption_on(void)
{
	return srv_trans_enc_state != NULL;
}

/******************************************************************************
 Free an encryption-allocated buffer.
******************************************************************************/

void srv_free_buffer(char *buf_out)
{
	if (!srv_trans_enc_state) {
		return;
	}

	if (srv_trans_enc_state->smb_enc_type == SMB_TRANS_ENC_NTLM) {
		SAFE_FREE(buf_out);
		return;
	}

#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
	/* gss-api free buffer.... */
#endif
}

/******************************************************************************
 gss-api decrypt an incoming buffer.
******************************************************************************/

#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
static NTSTATUS srv_gss_decrypt_buffer(gss_ctx_id_t context_handle, char *buf)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif

/******************************************************************************
 NTLM decrypt an incoming buffer.
******************************************************************************/

static NTSTATUS srv_ntlm_decrypt_buffer(NTLMSSP_STATE *ntlmssp_state, char *buf)
{
	NTSTATUS status;
	size_t orig_len = smb_len(buf);
	size_t new_len = orig_len - NTLMSSP_SIG_SIZE;
	DATA_BLOB sig;

	if (orig_len < 8 + NTLMSSP_SIG_SIZE) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	/* Save off the signature. */
	sig = data_blob(buf+orig_len-NTLMSSP_SIG_SIZE, NTLMSSP_SIG_SIZE);

	status = ntlmssp_unseal_packet(ntlmssp_state,
		(unsigned char *)buf + 8, /* 4 byte len + 0xFF 'S' 'M' 'B' */
		new_len - 8,
		(unsigned char *)buf,
		new_len,
		&sig);

	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&sig);
		return status;
	}
	/* Reset the length. */
	smb_setlen(buf, new_len);
	return NT_STATUS_OK;
}

/******************************************************************************
 Decrypt an incoming buffer.
******************************************************************************/

NTSTATUS srv_decrypt_buffer(char *buf)
{
	if (!srv_trans_enc_state) {
		/* Not decrypting. */
		return NT_STATUS_OK;
	}
	if (srv_trans_enc_state->smb_enc_type == SMB_TRANS_ENC_NTLM) {
		return srv_ntlm_decrypt_buffer(srv_trans_enc_state->ntlmssp_state, buf);
	} else {
#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
		return srv_gss_decrypt_buffer(srv_trans_enc_state->context_handle, buf);
#else
		return NT_STATUS_NOT_SUPPORTED;
#endif
	}
}

/******************************************************************************
 gss-api encrypt an outgoing buffer. Return the encrypted pointer in buf_out.
******************************************************************************/

#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
static NTSTATUS srv_gss_encrypt_buffer(gss_ctx_id_t context_handle, char *buf, char **buf_out)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif

/******************************************************************************
 NTLM encrypt an outgoing buffer. Return the encrypted pointer in ppbuf_out.
******************************************************************************/

static NTSTATUS srv_ntlm_encrypt_buffer(NTLMSSP_STATE *ntlmssp_state, char *buf, char **ppbuf_out)
{
	NTSTATUS status;
	char *buf_out;
	size_t orig_len = smb_len(buf);
	size_t new_len = orig_len + NTLMSSP_SIG_SIZE;
	DATA_BLOB sig;

	*ppbuf_out = NULL;

	if (orig_len < 8) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	/* 
	 * We know smb_len can't return a value > 128k, so no int overflow
	 * check needed.
	 */

	/* Copy the original buffer. */

	buf_out = SMB_XMALLOC_ARRAY(char, new_len);
	memcpy(buf_out, buf, orig_len);
	/* Last 16 bytes undefined here... */

	smb_setlen(buf_out, new_len);

	sig = data_blob(NULL, NTLMSSP_SIG_SIZE);

	status = ntlmssp_seal_packet(ntlmssp_state,
		(unsigned char *)buf_out + 8, /* 4 byte len + 0xFF 'S' 'M' 'B' */
		orig_len - 8,
		(unsigned char *)buf_out,
		orig_len,
		&sig);

	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&sig);
		SAFE_FREE(buf_out);
		return status;
	}

	memcpy(buf_out+orig_len, sig.data, NTLMSSP_SIG_SIZE);
	*ppbuf_out = buf_out;
	return NT_STATUS_OK;
}

/******************************************************************************
 Encrypt an outgoing buffer. Return the encrypted pointer in buf_out.
******************************************************************************/

NTSTATUS srv_encrypt_buffer(char *buffer, char **buf_out)
{
	if (!srv_trans_enc_state) {
		/* Not encrypting. */
		*buf_out = buffer;
		return NT_STATUS_OK;
	}

	if (srv_trans_enc_state->smb_enc_type == SMB_TRANS_ENC_NTLM) {
		return srv_ntlm_encrypt_buffer(srv_trans_enc_state->ntlmssp_state, buffer, buf_out);
	} else {
#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
		return srv_gss_encrypt_buffer(srv_trans_enc_state->context_handle, buffer, buf_out);
#else
		return NT_STATUS_NOT_SUPPORTED;
#endif
	}
}
