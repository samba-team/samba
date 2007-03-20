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

/******************************************************************************
 Generic code for client and server.
 Is encryption turned on ?
******************************************************************************/

BOOL common_encryption_on(struct smb_trans_enc_state *es)
{
	return ((es != NULL) && es->enc_on);
}

/******************************************************************************
 Generic code for client and server.
 NTLM decrypt an incoming buffer.
******************************************************************************/

NTSTATUS common_ntlm_decrypt_buffer(NTLMSSP_STATE *ntlmssp_state, char *buf)
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
 Generic code for client and server.
 NTLM encrypt an outgoing buffer. Return the encrypted pointer in ppbuf_out.
******************************************************************************/

NTSTATUS common_ntlm_encrypt_buffer(NTLMSSP_STATE *ntlmssp_state, char *buf, char **ppbuf_out)
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
 Generic code for client and server.
 gss-api decrypt an incoming buffer.
******************************************************************************/

#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
 NTSTATUS common_gss_decrypt_buffer(gss_ctx_id_t context_handle, char *buf)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif

/******************************************************************************
 Generic code for client and server.
 gss-api encrypt an outgoing buffer. Return the alloced encrypted pointer in buf_out.
******************************************************************************/

#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
 NTSTATUS common_gss_encrypt_buffer(gss_ctx_id_t context_handle, char *buf, char **buf_out)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif

/******************************************************************************
 Generic code for client and server.
 Encrypt an outgoing buffer. Return the alloced encrypted pointer in buf_out.
******************************************************************************/

NTSTATUS common_encrypt_buffer(struct smb_trans_enc_state *es, char *buffer, char **buf_out)
{
	if (!common_encryption_on(es)) {
		/* Not encrypting. */
		*buf_out = buffer;
		return NT_STATUS_OK;
	}

	if (es->smb_enc_type == SMB_TRANS_ENC_NTLM) {
		return common_ntlm_encrypt_buffer(es->ntlmssp_state, buffer, buf_out);
	} else {
#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
		return common_gss_encrypt_buffer(es->context_handle, buffer, buf_out);
#else
		return NT_STATUS_NOT_SUPPORTED;
#endif
	}
}

/******************************************************************************
 Generic code for client and server.
 Decrypt an incoming SMB buffer. Replaces the data within it.
 New data must be less than or equal to the current length.
******************************************************************************/

NTSTATUS common_decrypt_buffer(struct smb_trans_enc_state *es, char *buf)
{
	if (!common_encryption_on(es)) {
		/* Not decrypting. */
		return NT_STATUS_OK;
	}
	if (es->smb_enc_type == SMB_TRANS_ENC_NTLM) {
		return common_ntlm_decrypt_buffer(es->ntlmssp_state, buf);
	} else {
#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
		return common_gss_decrypt_buffer(es->context_handle, buf);
#else
		return NT_STATUS_NOT_SUPPORTED;
#endif
	}
}

/******************************************************************************
 Shutdown an encryption state.
******************************************************************************/

void common_free_encryption_state(struct smb_trans_enc_state **pp_es)
{
	struct smb_trans_enc_state *es = *pp_es;

	if (es == NULL) {
		return;
	}

	if (es->smb_enc_type == SMB_TRANS_ENC_NTLM) {
		if (es->ntlmssp_state) {
			ntlmssp_end(&es->ntlmssp_state);
		}
	}
#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
	if (es->smb_enc_type == SMB_TRANS_ENC_GSS) {
		/* Free the gss context handle. */
	}
#endif
	SAFE_FREE(es);
	*pp_es = NULL;
}

/******************************************************************************
 Free an encryption-allocated buffer.
******************************************************************************/

void common_free_enc_buffer(struct smb_trans_enc_state *es, char *buf)
{
	if (!common_encryption_on(es)) {
		return;
	}

	if (es->smb_enc_type == SMB_TRANS_ENC_NTLM) {
		SAFE_FREE(buf);
		return;
	}

#if defined(HAVE_GSSAPI_SUPPORT) && defined(HAVE_KRB5)
	/* gss-api free buffer.... */
#endif
}

/******************************************************************************
 Client side encryption.
******************************************************************************/

/******************************************************************************
 Is client encryption on ?
******************************************************************************/

BOOL cli_encryption_on(struct cli_state *cli)
{
	return common_encryption_on(cli->trans_enc_state);
}

/******************************************************************************
 Shutdown a client encryption state.
******************************************************************************/

void cli_free_encryption_context(struct cli_state *cli)
{
	return common_free_encryption_state(&cli->trans_enc_state);
}

/******************************************************************************
 Free an encryption-allocated buffer.
******************************************************************************/

void cli_free_enc_buffer(struct cli_state *cli, char *buf)
{
	return common_free_enc_buffer(cli->trans_enc_state, buf);
}

/******************************************************************************
 Decrypt an incoming buffer.
******************************************************************************/

NTSTATUS cli_decrypt_message(struct cli_state *cli)
{
	return common_decrypt_buffer(cli->trans_enc_state, cli->inbuf);
}

/******************************************************************************
 Encrypt an outgoing buffer. Return the encrypted pointer in buf_out.
******************************************************************************/

NTSTATUS cli_encrypt_message(struct cli_state *cli, char **buf_out)
{
	return common_encrypt_buffer(cli->trans_enc_state, cli->outbuf, buf_out);
}
