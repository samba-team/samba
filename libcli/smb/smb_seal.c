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
#include "libcli/auth/krb5_wrap.h"
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
	_smb_setlen_nbt(buf,len);

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
 gss-api decrypt an incoming buffer. We insist that the size of the
 unwrapped buffer must be smaller or identical to the incoming buffer.
******************************************************************************/

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
static NTSTATUS common_gss_decrypt_buffer(struct smb_tran_enc_state_gss *gss_state, char *buf)
{
	gss_ctx_id_t gss_ctx = gss_state->gss_ctx;
	OM_uint32 ret = 0;
	OM_uint32 minor = 0;
	int flags_got = 0;
	gss_buffer_desc in_buf, out_buf;
	size_t buf_len = smb_len_nbt(buf) + 4; /* Don't forget the 4 length bytes. */

	if (buf_len < 8) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	in_buf.value = buf + 8;
	in_buf.length = buf_len - 8;

	ret = gss_unwrap(&minor,
			gss_ctx,
			&in_buf,
			&out_buf,
			&flags_got,		/* did we get sign+seal ? */
			(gss_qop_t *) NULL);

	if (ret != GSS_S_COMPLETE) {
		NTSTATUS status = NT_STATUS_ACCESS_DENIED;
		char *gss_err;

		gss_err = gssapi_error_string(talloc_tos(),
					      ret, minor,
					      GSS_C_NULL_OID);
		DEBUG(0,("common_gss_decrypt_buffer: gss_unwrap failed. "
			 "Error [%d/%d] - %s - %s\n",
			 ret, minor, nt_errstr(status),
			 gss_err ? gss_err : "<unknown>"));
		talloc_free(gss_err);

		return status;
	}

	if (out_buf.length > in_buf.length) {
		DEBUG(0,("common_gss_decrypt_buffer: gss_unwrap size (%u) too large (%u) !\n",
			(unsigned int)out_buf.length,
			(unsigned int)in_buf.length ));
		gss_release_buffer(&minor, &out_buf);
		return NT_STATUS_INVALID_PARAMETER;
	}

	memcpy(buf + 8, out_buf.value, out_buf.length);
	/* Reset the length and overwrite the header. */
	smb_setlen_nbt(buf, out_buf.length + 4);

	gss_release_buffer(&minor, &out_buf);
	return NT_STATUS_OK;
}

/******************************************************************************
 Generic code for client and server.
 gss-api encrypt an outgoing buffer. Return the alloced encrypted pointer in buf_out.
******************************************************************************/

static NTSTATUS common_gss_encrypt_buffer(struct smb_tran_enc_state_gss *gss_state,
					uint16_t enc_ctx_num,
					char *buf,
					char **ppbuf_out)
{
	gss_ctx_id_t gss_ctx = gss_state->gss_ctx;
	OM_uint32 ret = 0;
	OM_uint32 minor = 0;
	int flags_got = 0;
	gss_buffer_desc in_buf, out_buf;
	size_t buf_len = smb_len_nbt(buf) + 4; /* Don't forget the 4 length bytes. */

	*ppbuf_out = NULL;

	if (buf_len < 8) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	in_buf.value = buf + 8;
	in_buf.length = buf_len - 8;

	ret = gss_wrap(&minor,
			gss_ctx,
			true,			/* we want sign+seal. */
			GSS_C_QOP_DEFAULT,
			&in_buf,
			&flags_got,		/* did we get sign+seal ? */
			&out_buf);

	if (ret != GSS_S_COMPLETE) {
		NTSTATUS status = NT_STATUS_ACCESS_DENIED;
		char *gss_err;

		gss_err = gssapi_error_string(talloc_tos(),
					      ret, minor,
					      GSS_C_NULL_OID);
		DEBUG(0,("common_gss_encrypt_buffer: gss_unwrap failed. "
			 "Error [%d/%d] - %s - %s\n",
			 ret, minor, nt_errstr(status),
			 gss_err ? gss_err : "<unknown>"));
		talloc_free(gss_err);

		return status;
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

	*ppbuf_out = (char *)malloc(out_buf.length + 8); /* We know this can't wrap. */
	if (!*ppbuf_out) {
		gss_release_buffer(&minor, &out_buf);
		return NT_STATUS_NO_MEMORY;
	}

	memcpy(*ppbuf_out+8, out_buf.value, out_buf.length);
	smb_set_enclen(*ppbuf_out, out_buf.length + 4, enc_ctx_num);

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

	switch (es->smb_enc_type) {
		case SMB_TRANS_ENC_NTLM:
			return common_gensec_encrypt_buffer(es->s.gensec_security, es->enc_ctx_num, buffer, buf_out);
#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
		case SMB_TRANS_ENC_GSS:
			return common_gss_encrypt_buffer(es->s.gss_state, es->enc_ctx_num, buffer, buf_out);
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

	switch (es->smb_enc_type) {
		case SMB_TRANS_ENC_NTLM:
			return common_gensec_decrypt_buffer(es->s.gensec_security, buf);
#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
		case SMB_TRANS_ENC_GSS:
			return common_gss_decrypt_buffer(es->s.gss_state, buf);
#endif
		default:
			return NT_STATUS_NOT_SUPPORTED;
	}
}

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
/******************************************************************************
 Shutdown a gss encryption state.
******************************************************************************/

static void common_free_gss_state(struct smb_tran_enc_state_gss **pp_gss_state)
{
	OM_uint32 minor = 0;
	struct smb_tran_enc_state_gss *gss_state = *pp_gss_state;

	if (gss_state->creds != GSS_C_NO_CREDENTIAL) {
		gss_release_cred(&minor, &gss_state->creds);
	}
	if (gss_state->gss_ctx != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&minor, &gss_state->gss_ctx, NULL);
	}
	SAFE_FREE(*pp_gss_state);
}
#endif

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
		if (es->s.gensec_security) {
			TALLOC_FREE(es->s.gensec_security);
		}
	}
#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
	if (es->smb_enc_type == SMB_TRANS_ENC_GSS) {
		/* Free the gss context handle. */
		if (es->s.gss_state) {
			common_free_gss_state(&es->s.gss_state);
		}
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
