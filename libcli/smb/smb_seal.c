/*
   Unix SMB/CIFS implementation.
   SMB Transport encryption (sealing) code.
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
#include "smb_common.h"
#if HAVE_KRB5
#include "lib/krb5_wrap/krb5_samba.h"
#endif
#include "auth/gensec/gensec.h"
#include "libcli/smb/smb_seal.h"

#undef malloc

/******************************************************************************
 Pull out the encryption context for this packet. 0 means global context.
******************************************************************************/

NTSTATUS get_enc_ctx_num(const uint8_t *buf, uint16_t *p_enc_ctx_num)
{
	if (smb_len_nbt(buf) < 8) {
		return NT_STATUS_INVALID_BUFFER_SIZE;
	}

	if (buf[4] == 0xFF) {
		if (buf[5] == 'S' && buf [6] == 'M' && buf[7] == 'B') {
			/* Not an encrypted buffer. */
			return NT_STATUS_NOT_FOUND;
		}
		if (buf[5] == 'E') {
			*p_enc_ctx_num = SVAL(buf,6);
			return NT_STATUS_OK;
		}
	}
	return NT_STATUS_INVALID_NETWORK_RESPONSE;
}

/*******************************************************************
 Set the length and marker of an encrypted smb packet.
********************************************************************/

static void smb_set_enclen(char *buf,int len,uint16_t enc_ctx_num)
{
	_smb_setlen_tcp(buf,len);

	SCVAL(buf,4,0xFF);
	SCVAL(buf,5,'E');
	SSVAL(buf,6,enc_ctx_num);
}

/******************************************************************************
 Generic code for client and server.
 Is encryption turned on ?
******************************************************************************/

bool common_encryption_on(struct smb_trans_enc_state *es)
{
	return ((es != NULL) && es->enc_on);
}

/******************************************************************************
 Generic code for client and server.
 GENSEC decrypt an incoming buffer.
******************************************************************************/

static NTSTATUS common_gensec_decrypt_buffer(struct gensec_security *gensec,
					     char *buf)
{
	NTSTATUS status;
	size_t buf_len = smb_len_nbt(buf) + 4; /* Don't forget the 4 length bytes. */
	DATA_BLOB in_buf, out_buf;
	TALLOC_CTX *frame;

	if (buf_len < 8) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	frame = talloc_stackframe();

	in_buf = data_blob_const(buf + 8, buf_len - 8);

	status = gensec_unwrap(gensec, frame, &in_buf, &out_buf);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("common_gensec_decrypt_buffer: gensec_unwrap failed. Error %s\n",
			 nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	if (out_buf.length > in_buf.length) {
		DEBUG(0,("common_gensec_decrypt_buffer: gensec_unwrap size (%u) too large (%u) !\n",
			(unsigned int)out_buf.length,
			(unsigned int)in_buf.length ));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}

	memcpy(buf + 8, out_buf.data, out_buf.length);

	/* Reset the length and overwrite the header. */
	smb_setlen_nbt(buf, out_buf.length + 4);

	TALLOC_FREE(frame);

	return NT_STATUS_OK;
}

/******************************************************************************
 Generic code for client and server.
 NTLM encrypt an outgoing buffer. Return the encrypted pointer in ppbuf_out.
******************************************************************************/

static NTSTATUS common_gensec_encrypt_buffer(struct gensec_security *gensec,
				      uint16_t enc_ctx_num,
				      char *buf,
				      char **ppbuf_out)
{
	NTSTATUS status;
	DATA_BLOB in_buf, out_buf;
	size_t buf_len = smb_len_nbt(buf) + 4; /* Don't forget the 4 length bytes. */
	TALLOC_CTX *frame;

	*ppbuf_out = NULL;

	if (buf_len < 8) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}
	in_buf = data_blob_const(buf + 8, buf_len - 8);

	frame = talloc_stackframe();

	status = gensec_wrap(gensec, frame, &in_buf, &out_buf);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("common_gensec_encrypt_buffer: gensec_wrap failed. Error %s\n",
			 nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	*ppbuf_out = (char *)malloc(out_buf.length + 8); /* We know this can't wrap. */
	if (!*ppbuf_out) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	memcpy(*ppbuf_out+8, out_buf.data, out_buf.length);
	smb_set_enclen(*ppbuf_out, out_buf.length + 4, enc_ctx_num);

	TALLOC_FREE(frame);

	return NT_STATUS_OK;
}

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

	return common_gensec_encrypt_buffer(es->gensec_security, es->enc_ctx_num, buffer, buf_out);
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

	return common_gensec_decrypt_buffer(es->gensec_security, buf);
}

/******************************************************************************
 Free an encryption-allocated buffer.
******************************************************************************/

void common_free_enc_buffer(struct smb_trans_enc_state *es, char *buf)
{
	uint16_t enc_ctx_num;

	if (!common_encryption_on(es)) {
		return;
	}

	if (!NT_STATUS_IS_OK(get_enc_ctx_num((const uint8_t *)buf,
			&enc_ctx_num))) {
		return;
	}

	SAFE_FREE(buf);
}
