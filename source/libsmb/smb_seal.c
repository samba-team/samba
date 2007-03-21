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
	size_t buf_len = smb_len(buf) + 4; /* Don't forget the 4 length bytes. */
	DATA_BLOB sig;

	if (buf_len < 8 + NTLMSSP_SIG_SIZE) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	/* Adjust for the signature. */
	buf_len -= NTLMSSP_SIG_SIZE;

	/* Save off the signature. */
	sig = data_blob(buf+buf_len, NTLMSSP_SIG_SIZE);

	status = ntlmssp_unseal_packet(ntlmssp_state,
		(unsigned char *)buf + 8, /* 4 byte len + 0xFF 'S' 'M' 'B' */
		buf_len - 8,
		(unsigned char *)buf + 8,
		buf_len - 8,
		&sig);

	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&sig);
		return status;
	}

	/* Reset the length. */
	smb_setlen(buf, smb_len(buf) - NTLMSSP_SIG_SIZE);
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
	size_t buf_len = smb_len(buf) + 4; /* Don't forget the 4 length bytes. */
	DATA_BLOB sig;

	*ppbuf_out = NULL;

	if (buf_len < 8) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	/* 
	 * We know smb_len can't return a value > 128k, so no int overflow
	 * check needed.
	 */

	/* Copy the original buffer. */

	buf_out = SMB_XMALLOC_ARRAY(char, buf_len + NTLMSSP_SIG_SIZE);
	memcpy(buf_out, buf, buf_len);
	/* Last 16 bytes undefined here... */

	smb_setlen(buf_out, smb_len(buf) + NTLMSSP_SIG_SIZE);

	sig = data_blob(NULL, NTLMSSP_SIG_SIZE);

	status = ntlmssp_seal_packet(ntlmssp_state,
		(unsigned char *)buf_out + 8, /* 4 byte len + 0xFF 'S' 'M' 'B' */
		buf_len - 8,
		(unsigned char *)buf_out + 8,
		buf_len - 8,
		&sig);

	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&sig);
		SAFE_FREE(buf_out);
		return status;
	}

	memcpy(buf_out+buf_len, sig.data, NTLMSSP_SIG_SIZE);
	*ppbuf_out = buf_out;
	return NT_STATUS_OK;
}

/******************************************************************************
 Generic code for client and server.
 gss-api decrypt an incoming buffer.
******************************************************************************/

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
 NTSTATUS common_gss_decrypt_buffer(gss_ctx_id_t context_handle, char *buf)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif

/******************************************************************************
 Generic code for client and server.
 gss-api encrypt an outgoing buffer. Return the alloced encrypted pointer in buf_out.
******************************************************************************/

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
 NTSTATUS common_gss_encrypt_buffer(gss_ctx_id_t context_handle, char *buf, char **ppbuf_out)
{
	OM_uint32 ret = 0;
	OM_uint32 minor = 0;
	int flags_got = 0;
	gss_buffer_desc in_buf, out_buf;
	size_t buf_len = smb_len(buf) + 4; /* Don't forget the 4 length bytes. */

	*ppbuf_out = NULL;

	if (buf_len < 8) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	in_buf.value = buf + 8;
	in_buf.length = buf_len - 8;

	ret = gss_wrap(&minor,
			context_handle,
			True,			/* we want sign+seal. */
			GSS_C_QOP_DEFAULT,
			&in_buf,
			&flags_got,		/* did we get sign+seal ? */
			&out_buf);

	if (ret != GSS_S_COMPLETE) {
		/* Um - no mapping for gss-errs to NTSTATUS yet. */
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!flags_got) {
		/* Sign+seal not supported. */
		gss_release_buffer(&minor, &out_buf);
		return NT_STATUS_NOT_SUPPORTED;
	}

	/* Ya see - this is why I *hate* gss-api. I don't 
	 * want to have to malloc another buffer of the
	 * same size + 8 bytes just to get a continuous
	 * header + buffer, but gss won't let me pass in
	 * a pre-allocated buffer. Bastards (and you know
	 * who you are....). I might fix this by
	 * going to "encrypt_and_send" passing in a file
	 * descriptor and doing scatter-gather write with
	 * TCP cork on Linux. But I shouldn't have to
	 * bother :-*(. JRA.
	 */

	*ppbuf_out = SMB_MALLOC(out_buf.length + 8); /* We know this can't wrap. */
	if (!*ppbuf_out) {
		gss_release_buffer(&minor, &out_buf);
		return NT_STATUS_NO_MEMORY;
	}

	smb_setlen(*ppbuf_out, out_buf.length + 8);
	memcpy(*ppbuf_out+8, out_buf.value, out_buf.length);
	gss_release_buffer(&minor, &out_buf);
	return NT_STATUS_OK;
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

	/* Ignore session keepalives. */
	if(CVAL(buffer,0) == SMBkeepalive) {
		*buf_out = buffer;
		return NT_STATUS_OK;
	}

	switch (es->smb_enc_type) {
		case SMB_TRANS_ENC_NTLM:
			return common_ntlm_encrypt_buffer(es->ntlmssp_state, buffer, buf_out);
#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
		case SMB_TRANS_ENC_GSS:
			return common_gss_encrypt_buffer(es->context_handle, buffer, buf_out);
#endif
		default:
			return NT_STATUS_NOT_SUPPORTED;
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

	/* Ignore session keepalives. */
	if(CVAL(buf,0) == SMBkeepalive) {
		return NT_STATUS_OK;
	}

	switch (es->smb_enc_type) {
		case SMB_TRANS_ENC_NTLM:
			return common_ntlm_decrypt_buffer(es->ntlmssp_state, buf);
#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
		case SMB_TRANS_ENC_GSS:
			return common_gss_decrypt_buffer(es->context_handle, buf);
#endif
		default:
			return NT_STATUS_NOT_SUPPORTED;
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
#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
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

	/* We know this is an smb buffer, and we
	 * didn't malloc, only copy, for a keepalive,
	 * so ignore session keepalives. */

	if(CVAL(buf,0) == SMBkeepalive) {
		return;
	}

	if (es->smb_enc_type == SMB_TRANS_ENC_NTLM) {
		SAFE_FREE(buf);
		return;
	}

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
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
	common_free_encryption_state(&cli->trans_enc_state);
}

/******************************************************************************
 Free an encryption-allocated buffer.
******************************************************************************/

void cli_free_enc_buffer(struct cli_state *cli, char *buf)
{
	common_free_enc_buffer(cli->trans_enc_state, buf);
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
