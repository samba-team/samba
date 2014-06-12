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

bool is_encrypted_packet(const uint8_t *inbuf)
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
 Create an gensec_security and ensure pointer copy is correct.
******************************************************************************/

static NTSTATUS make_auth_gensec(const struct tsocket_address *remote_address,
				 struct smb_trans_enc_state *es)
{
	NTSTATUS status;

	status = auth_generic_prepare(es, remote_address,
				      &es->gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	gensec_want_feature(es->gensec_security, GENSEC_FEATURE_SEAL);

	/*
	 * We could be accessing the secrets.tdb or krb5.keytab file here.
 	 * ensure we have permissions to do so.
 	 */
	become_root();

	status = gensec_start_mech_by_oid(es->gensec_security, GENSEC_OID_SPNEGO);

	unbecome_root();

	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	return status;
}

/******************************************************************************
 Create a server encryption context.
******************************************************************************/

static NTSTATUS make_srv_encryption_context(const struct tsocket_address *remote_address,
					    struct smb_trans_enc_state **pp_es)
{
	NTSTATUS status;
	struct smb_trans_enc_state *es;

	*pp_es = NULL;

	ZERO_STRUCTP(partial_srv_trans_enc_ctx);
	es = talloc_zero(NULL, struct smb_trans_enc_state);
	if (!es) {
		return NT_STATUS_NO_MEMORY;
	}
	status = make_auth_gensec(remote_address,
				  es);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(es);
		return status;
	}
	*pp_es = es;
	return NT_STATUS_OK;
}

/******************************************************************************
 Free an encryption-allocated buffer.
******************************************************************************/

void srv_free_enc_buffer(struct smbXsrv_connection *xconn, char *buf)
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

NTSTATUS srv_decrypt_buffer(struct smbXsrv_connection *xconn, char *buf)
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

NTSTATUS srv_encrypt_buffer(struct smbXsrv_connection *xconn, char *buf,
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
 Do the SPNEGO encryption negotiation. Parameters are in/out.
******************************************************************************/

NTSTATUS srv_request_encryption_setup(connection_struct *conn,
					unsigned char **ppdata,
					size_t *p_data_size,
					unsigned char **pparam,
					size_t *p_param_size)
{
	NTSTATUS status;
	DATA_BLOB blob = data_blob_const(*ppdata, *p_data_size);
	DATA_BLOB response = data_blob_null;
	struct smb_trans_enc_state *es;

	SAFE_FREE(*pparam);
	*p_param_size = 0;

	if (!partial_srv_trans_enc_ctx) {
		/* This is the initial step. */
		status = make_srv_encryption_context(conn->sconn->remote_address,
					&partial_srv_trans_enc_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	es = partial_srv_trans_enc_ctx;
	if (!es || es->gensec_security == NULL) {
		TALLOC_FREE(partial_srv_trans_enc_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Second step. */
	become_root();
	status = gensec_update(es->gensec_security,
			       talloc_tos(),
			       blob, &response);
	unbecome_root();
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) &&
	    !NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(partial_srv_trans_enc_ctx);
		return nt_status_squash(status);
	}

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
	*ppdata = (unsigned char *)smb_memdup(response.data, response.length);
	if ((*ppdata) == NULL && response.length > 0)
		return NT_STATUS_NO_MEMORY;
	*p_data_size = response.length;
	data_blob_free(&response);
	return status;
}

/******************************************************************************
 Negotiation was successful - turn on server-side encryption.
******************************************************************************/

static NTSTATUS check_enc_good(struct smb_trans_enc_state *es)
{
	if (!es) {
		return NT_STATUS_LOGON_FAILURE;
	}

	if (!gensec_have_feature(es->gensec_security, GENSEC_FEATURE_SIGN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!gensec_have_feature(es->gensec_security, GENSEC_FEATURE_SEAL)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
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
	TALLOC_FREE(srv_trans_enc_ctx);

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

void server_encryption_shutdown(struct smbXsrv_connection *xconn)
{
	TALLOC_FREE(partial_srv_trans_enc_ctx);
	TALLOC_FREE(srv_trans_enc_ctx);
}
