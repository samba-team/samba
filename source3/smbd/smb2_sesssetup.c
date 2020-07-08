/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2010

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
#include "../libcli/smb/smb_common.h"
#include "../auth/gensec/gensec.h"
#include "auth.h"
#include "../lib/tsocket/tsocket.h"
#include "../libcli/security/security.h"
#include "../lib/util/tevent_ntstatus.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

static struct tevent_req *smbd_smb2_session_setup_wrap_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req,
					uint64_t in_session_id,
					uint8_t in_flags,
					uint8_t in_security_mode,
					uint64_t in_previous_session_id,
					DATA_BLOB in_security_buffer);
static NTSTATUS smbd_smb2_session_setup_wrap_recv(struct tevent_req *req,
					uint16_t *out_session_flags,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id);

static void smbd_smb2_request_sesssetup_done(struct tevent_req *subreq);

NTSTATUS smbd_smb2_request_process_sesssetup(struct smbd_smb2_request *smb2req)
{
	const uint8_t *inhdr;
	const uint8_t *inbody;
	uint64_t in_session_id;
	uint8_t in_flags;
	uint8_t in_security_mode;
	uint64_t in_previous_session_id;
	uint16_t in_security_offset;
	uint16_t in_security_length;
	DATA_BLOB in_security_buffer;
	NTSTATUS status;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(smb2req, 0x19);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(smb2req, status);
	}
	inhdr = SMBD_SMB2_IN_HDR_PTR(smb2req);
	inbody = SMBD_SMB2_IN_BODY_PTR(smb2req);

	in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);

	in_flags = CVAL(inbody, 0x02);
	in_security_mode = CVAL(inbody, 0x03);
	/* Capabilities = IVAL(inbody, 0x04) */
	/* Channel = IVAL(inbody, 0x08) */
	in_security_offset = SVAL(inbody, 0x0C);
	in_security_length = SVAL(inbody, 0x0E);
	in_previous_session_id = BVAL(inbody, 0x10);

	if (in_security_offset != (SMB2_HDR_BODY + SMBD_SMB2_IN_BODY_LEN(smb2req))) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_security_length > SMBD_SMB2_IN_DYN_LEN(smb2req)) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	in_security_buffer.data = SMBD_SMB2_IN_DYN_PTR(smb2req);
	in_security_buffer.length = in_security_length;

	subreq = smbd_smb2_session_setup_wrap_send(smb2req,
						   smb2req->sconn->ev_ctx,
						   smb2req,
						   in_session_id,
						   in_flags,
						   in_security_mode,
						   in_previous_session_id,
						   in_security_buffer);
	if (subreq == NULL) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_sesssetup_done, smb2req);

	/*
	 * Avoid sending a STATUS_PENDING message, which
	 * matches a Windows Server and avoids problems with
	 * MacOS clients.
	 *
	 * Even after 90 seconds a Windows Server doesn't return
	 * STATUS_PENDING if using NTLMSSP against a non reachable
	 * trusted domain.
	 */
	return smbd_smb2_request_pending_queue(smb2req, subreq, 0);
}

static void smbd_smb2_request_sesssetup_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *smb2req =
		tevent_req_callback_data(subreq,
		struct smbd_smb2_request);
	uint8_t *outhdr;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	uint16_t out_session_flags = 0;
	uint64_t out_session_id = 0;
	uint16_t out_security_offset;
	DATA_BLOB out_security_buffer = data_blob_null;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_session_setup_wrap_recv(subreq,
						   &out_session_flags,
						   smb2req,
						   &out_security_buffer,
						   &out_session_id);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = nt_status_squash(status);
		error = smbd_smb2_request_error(smb2req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	out_security_offset = SMB2_HDR_BODY + 0x08;

	outhdr = SMBD_SMB2_OUT_HDR_PTR(smb2req);

	outbody = smbd_smb2_generate_outbody(smb2req, 0x08);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SBVAL(outhdr, SMB2_HDR_SESSION_ID, out_session_id);

	SSVAL(outbody.data, 0x00, 0x08 + 1);	/* struct size */
	SSVAL(outbody.data, 0x02,
	      out_session_flags);		/* session flags */
	SSVAL(outbody.data, 0x04,
	      out_security_offset);		/* security buffer offset */
	SSVAL(outbody.data, 0x06,
	      out_security_buffer.length);	/* security buffer length */

	outdyn = out_security_buffer;

	error = smbd_smb2_request_done_ex(smb2req, status, outbody, &outdyn,
					   __location__);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(smb2req->xconn,
						 nt_errstr(error));
		return;
	}
}

static NTSTATUS smbd_smb2_auth_generic_return(struct smbXsrv_session *session,
					struct smbXsrv_session_auth0 **_auth,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					struct auth_session_info *session_info,
					uint16_t *out_session_flags,
					uint64_t *out_session_id)
{
	NTSTATUS status;
	bool guest = false;
	uint8_t session_key[16];
	struct smbXsrv_session *x = session;
	struct smbXsrv_session_auth0 *auth = *_auth;
	struct smbXsrv_connection *xconn = smb2req->xconn;
	size_t i;
	struct _derivation {
		DATA_BLOB label;
		DATA_BLOB context;
	};
	struct {
		struct _derivation signing;
		struct _derivation encryption;
		struct _derivation decryption;
		struct _derivation application;
	} derivation = { };

	*_auth = NULL;

	if (xconn->protocol >= PROTOCOL_SMB3_10) {
		struct smbXsrv_preauth *preauth;
		struct _derivation *d;
		DATA_BLOB p;
		gnutls_hash_hd_t hash_hnd;
		int rc;

		preauth = talloc_move(smb2req, &auth->preauth);

		rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_SHA512);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}
		rc = gnutls_hash(hash_hnd,
				 preauth->sha512_value,
				 sizeof(preauth->sha512_value));
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			return NT_STATUS_ACCESS_DENIED;
		}
		for (i = 1; i < smb2req->in.vector_count; i++) {
			rc = gnutls_hash(hash_hnd,
					 smb2req->in.vector[i].iov_base,
					 smb2req->in.vector[i].iov_len);
			if (rc < 0) {
				gnutls_hash_deinit(hash_hnd, NULL);
				return NT_STATUS_ACCESS_DENIED;
			}
		}
		gnutls_hash_deinit(hash_hnd, preauth->sha512_value);

		p = data_blob_const(preauth->sha512_value,
				    sizeof(preauth->sha512_value));

		d = &derivation.signing;
		d->label = data_blob_string_const_null("SMBSigningKey");
		d->context = p;

		d = &derivation.decryption;
		d->label = data_blob_string_const_null("SMBC2SCipherKey");
		d->context = p;

		d = &derivation.encryption;
		d->label = data_blob_string_const_null("SMBS2CCipherKey");
		d->context = p;

		d = &derivation.application;
		d->label = data_blob_string_const_null("SMBAppKey");
		d->context = p;

	} else if (xconn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d;

		d = &derivation.signing;
		d->label = data_blob_string_const_null("SMB2AESCMAC");
		d->context = data_blob_string_const_null("SmbSign");

		d = &derivation.decryption;
		d->label = data_blob_string_const_null("SMB2AESCCM");
		d->context = data_blob_string_const_null("ServerIn ");

		d = &derivation.encryption;
		d->label = data_blob_string_const_null("SMB2AESCCM");
		d->context = data_blob_string_const_null("ServerOut");

		d = &derivation.application;
		d->label = data_blob_string_const_null("SMB2APP");
		d->context = data_blob_string_const_null("SmbRpc");
	}

	if ((in_security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) ||
	    (xconn->smb2.server.security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED))
	{
		x->global->signing_flags = SMBXSRV_SIGNING_REQUIRED;
	}

	if ((lp_smb_encrypt(-1) >= SMB_SIGNING_DESIRED) &&
	    (xconn->smb2.client.capabilities & SMB2_CAP_ENCRYPTION)) {
		x->global->encryption_flags = SMBXSRV_ENCRYPTION_DESIRED;
	}

	if (lp_smb_encrypt(-1) == SMB_SIGNING_REQUIRED) {
		x->global->encryption_flags = SMBXSRV_ENCRYPTION_REQUIRED |
			SMBXSRV_ENCRYPTION_DESIRED;
	}

	if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
		if (security_session_user_level(session_info, NULL) == SECURITY_GUEST) {
			*out_session_flags |= SMB2_SESSION_FLAG_IS_GUEST;
		}
		/* force no signing */
		x->global->signing_flags &= ~SMBXSRV_SIGNING_REQUIRED;
		/* we map anonymous to guest internally */
		guest = true;
	}

	if (guest && (x->global->encryption_flags & SMBXSRV_ENCRYPTION_REQUIRED)) {
		DEBUG(1,("reject guest session as encryption is required\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (xconn->smb2.server.cipher == 0) {
		if (x->global->encryption_flags & SMBXSRV_ENCRYPTION_REQUIRED) {
			DEBUG(1,("reject session with dialect[0x%04X] "
				 "as encryption is required\n",
				 xconn->smb2.server.dialect));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else {
		x->global->channels[0].encryption_cipher = xconn->smb2.server.cipher;
	}

	if (x->global->encryption_flags & SMBXSRV_ENCRYPTION_DESIRED) {
		*out_session_flags |= SMB2_SESSION_FLAG_ENCRYPT_DATA;
	}

	ZERO_STRUCT(session_key);
	memcpy(session_key, session_info->session_key.data,
	       MIN(session_info->session_key.length, sizeof(session_key)));

	x->global->signing_key = talloc_zero(x->global,
					     struct smb2_signing_key);
	if (x->global->signing_key == NULL) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(x->global->signing_key,
			      smb2_signing_key_destructor);

	x->global->signing_key->blob =
		x->global->signing_key_blob =
			data_blob_talloc(x->global,
					 session_key,
					 sizeof(session_key));
	if (!smb2_signing_key_valid(x->global->signing_key)) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}

	if (xconn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d = &derivation.signing;

		status = smb2_key_derivation(session_key, sizeof(session_key),
					     d->label.data, d->label.length,
					     d->context.data, d->context.length,
					     x->global->signing_key->blob.data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (xconn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d = &derivation.decryption;

		x->global->decryption_key =
			talloc_zero(x->global, struct smb2_signing_key);
		if (x->global->decryption_key == NULL) {
			ZERO_STRUCT(session_key);
			return NT_STATUS_NO_MEMORY;
		}

		x->global->decryption_key->blob =
			x->global->decryption_key_blob =
				data_blob_talloc(x->global->decryption_key,
						 session_key,
						 sizeof(session_key));
		if (!smb2_signing_key_valid(x->global->decryption_key)) {
			ZERO_STRUCT(session_key);
			return NT_STATUS_NO_MEMORY;
		}
		talloc_keep_secret(x->global->decryption_key->blob.data);

		status = smb2_key_derivation(session_key, sizeof(session_key),
					     d->label.data, d->label.length,
					     d->context.data, d->context.length,
					     x->global->decryption_key->blob.data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (xconn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d = &derivation.encryption;
		size_t nonce_size;

		x->global->encryption_key =
			talloc_zero(x->global, struct smb2_signing_key);
		if (x->global->encryption_key == NULL) {
			ZERO_STRUCT(session_key);
			return NT_STATUS_NO_MEMORY;
		}

		x->global->encryption_key->blob =
			x->global->encryption_key_blob =
				data_blob_talloc(x->global->encryption_key,
						 session_key,
						 sizeof(session_key));
		if (!smb2_signing_key_valid(x->global->encryption_key)) {
			ZERO_STRUCT(session_key);
			return NT_STATUS_NO_MEMORY;
		}
		talloc_keep_secret(x->global->encryption_key->blob.data);

		status = smb2_key_derivation(session_key, sizeof(session_key),
					     d->label.data, d->label.length,
					     d->context.data, d->context.length,
					     x->global->encryption_key->blob.data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/*
		 * CCM and GCM algorithms must never have their
		 * nonce wrap, or the security of the whole
		 * communication and the keys is destroyed.
		 * We must drop the connection once we have
		 * transfered too much data.
		 *
		 * NOTE: We assume nonces greater than 8 bytes.
		 */
		generate_nonce_buffer((uint8_t *)&x->nonce_high_random,
				      sizeof(x->nonce_high_random));
		switch (xconn->smb2.server.cipher) {
		case SMB2_ENCRYPTION_AES128_CCM:
			nonce_size = SMB2_AES_128_CCM_NONCE_SIZE;
			break;
		case SMB2_ENCRYPTION_AES128_GCM:
			nonce_size = gnutls_cipher_get_iv_size(GNUTLS_CIPHER_AES_128_GCM);
			break;
		default:
			nonce_size = 0;
			break;
		}
		x->nonce_high_max = SMB2_NONCE_HIGH_MAX(nonce_size);
		x->nonce_high = 0;
		x->nonce_low = 0;
	}

	x->global->application_key =
		data_blob_dup_talloc(x->global, x->global->signing_key->blob);
	if (x->global->application_key.data == NULL) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_keep_secret(x->global->application_key.data);

	if (xconn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d = &derivation.application;

		status = smb2_key_derivation(session_key, sizeof(session_key),
					     d->label.data, d->label.length,
					     d->context.data, d->context.length,
					     x->global->application_key.data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (xconn->protocol >= PROTOCOL_SMB3_00 && lp_debug_encryption()) {
		DEBUG(0, ("debug encryption: dumping generated session keys\n"));
		DEBUGADD(0, ("Session Id    "));
		dump_data(0, (uint8_t*)&session->global->session_wire_id,
			  sizeof(session->global->session_wire_id));
		DEBUGADD(0, ("Session Key   "));
		dump_data(0, session_key, sizeof(session_key));
		DEBUGADD(0, ("Signing Key   "));
		dump_data(0, x->global->signing_key->blob.data,
			  x->global->signing_key->blob.length);
		DEBUGADD(0, ("App Key       "));
		dump_data(0, x->global->application_key.data,
			  x->global->application_key.length);

		/* In server code, ServerIn is the decryption key */

		DEBUGADD(0, ("ServerIn Key  "));
		dump_data(0, x->global->decryption_key->blob.data,
			  x->global->decryption_key->blob.length);
		DEBUGADD(0, ("ServerOut Key "));
		dump_data(0, x->global->encryption_key->blob.data,
			  x->global->encryption_key->blob.length);
	}

	ZERO_STRUCT(session_key);

	x->global->channels[0].signing_key =
		talloc_zero(x->global->channels, struct smb2_signing_key);
	if (x->global->channels[0].signing_key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(x->global->channels[0].signing_key,
			      smb2_signing_key_destructor);

	x->global->channels[0].signing_key->blob =
		x->global->channels[0].signing_key_blob =
			data_blob_dup_talloc(x->global->channels[0].signing_key,
					     x->global->signing_key->blob);
	if (!smb2_signing_key_valid(x->global->channels[0].signing_key)) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_keep_secret(x->global->channels[0].signing_key->blob.data);

	data_blob_clear_free(&session_info->session_key);
	session_info->session_key = data_blob_dup_talloc(session_info,
						x->global->application_key);
	if (session_info->session_key.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_keep_secret(session_info->session_key.data);

	smb2req->sconn->num_users++;

	if (security_session_user_level(session_info, NULL) >= SECURITY_USER) {
		session->homes_snum =
			register_homes_share(session_info->unix_info->unix_name);
	}

	set_current_user_info(session_info->unix_info->sanitized_username,
			      session_info->unix_info->unix_name,
			      session_info->info->domain_name);

	reload_services(smb2req->sconn, conn_snum_used, true);

	session->status = NT_STATUS_OK;
	session->global->auth_session_info = talloc_move(session->global,
							 &session_info);
	session->global->auth_session_info_seqnum += 1;
	for (i=0; i < session->global->num_channels; i++) {
		struct smbXsrv_channel_global0 *_c =
			&session->global->channels[i];

		_c->auth_session_info_seqnum =
			session->global->auth_session_info_seqnum;
	}
	session->global->auth_time = timeval_to_nttime(&smb2req->request_time);
	session->global->expiration_time = gensec_expire_time(auth->gensec);

	if (!session_claim(session)) {
		DEBUG(1, ("smb2: Failed to claim session "
			"for vuid=%llu\n",
			(unsigned long long)session->global->session_wire_id));
		return NT_STATUS_LOGON_FAILURE;
	}

	TALLOC_FREE(auth);
	status = smbXsrv_session_update(session);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smb2: Failed to update session for vuid=%llu - %s\n",
			  (unsigned long long)session->global->session_wire_id,
			  nt_errstr(status)));
		return NT_STATUS_LOGON_FAILURE;
	}

	/*
	 * we attach the session to the request
	 * so that the response can be signed
	 */
	if (!guest) {
		smb2req->do_signing = true;
	}

	global_client_caps |= (CAP_LEVEL_II_OPLOCKS|CAP_STATUS32);

	*out_session_id = session->global->session_wire_id;
	smb2req->last_session_id = session->global->session_wire_id;

	return NT_STATUS_OK;
}

static NTSTATUS smbd_smb2_reauth_generic_return(struct smbXsrv_session *session,
					struct smbXsrv_session_auth0 **_auth,
					struct smbd_smb2_request *smb2req,
					struct auth_session_info *session_info,
					uint16_t *out_session_flags,
					uint64_t *out_session_id)
{
	NTSTATUS status;
	struct smbXsrv_session *x = session;
	struct smbXsrv_session_auth0 *auth = *_auth;
	struct smbXsrv_connection *xconn = smb2req->xconn;
	size_t i;

	*_auth = NULL;

	data_blob_clear_free(&session_info->session_key);
	session_info->session_key = data_blob_dup_talloc(session_info,
						x->global->application_key);
	if (session_info->session_key.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_keep_secret(session_info->session_key.data);

	session->homes_snum =
			register_homes_share(session_info->unix_info->unix_name);

	set_current_user_info(session_info->unix_info->sanitized_username,
			      session_info->unix_info->unix_name,
			      session_info->info->domain_name);

	reload_services(smb2req->sconn, conn_snum_used, true);

	if (security_session_user_level(session_info, NULL) >= SECURITY_USER) {
		smb2req->do_signing = true;
	}

	session->status = NT_STATUS_OK;
	TALLOC_FREE(session->global->auth_session_info);
	session->global->auth_session_info = talloc_move(session->global,
							 &session_info);
	session->global->auth_session_info_seqnum += 1;
	for (i=0; i < session->global->num_channels; i++) {
		struct smbXsrv_channel_global0 *_c =
			&session->global->channels[i];

		_c->auth_session_info_seqnum =
			session->global->auth_session_info_seqnum;
	}
	session->global->auth_time = timeval_to_nttime(&smb2req->request_time);
	session->global->expiration_time = gensec_expire_time(auth->gensec);

	TALLOC_FREE(auth);
	status = smbXsrv_session_update(session);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smb2: Failed to update session for vuid=%llu - %s\n",
			  (unsigned long long)session->global->session_wire_id,
			  nt_errstr(status)));
		return NT_STATUS_LOGON_FAILURE;
	}

	conn_clear_vuid_caches(xconn->client->sconn,
			       session->global->session_wire_id);

	*out_session_id = session->global->session_wire_id;

	return NT_STATUS_OK;
}

static NTSTATUS smbd_smb2_bind_auth_return(struct smbXsrv_session *session,
					   struct smbXsrv_session_auth0 **_auth,
					   struct smbd_smb2_request *smb2req,
					   struct auth_session_info *session_info,
					   uint16_t *out_session_flags,
					   uint64_t *out_session_id)
{
	NTSTATUS status;
	struct smbXsrv_session *x = session;
	struct smbXsrv_session_auth0 *auth = *_auth;
	struct smbXsrv_connection *xconn = smb2req->xconn;
	struct smbXsrv_channel_global0 *c = NULL;
	uint8_t session_key[16];
	size_t i;
	struct _derivation {
		DATA_BLOB label;
		DATA_BLOB context;
	};
	struct {
		struct _derivation signing;
	} derivation = { };
	bool ok;

	*_auth = NULL;

	if (xconn->protocol >= PROTOCOL_SMB3_10) {
		struct smbXsrv_preauth *preauth;
		struct _derivation *d;
		DATA_BLOB p;
		gnutls_hash_hd_t hash_hnd = NULL;
		int rc;

		preauth = talloc_move(smb2req, &auth->preauth);

		rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_SHA512);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}

		rc = gnutls_hash(hash_hnd,
				 preauth->sha512_value,
				 sizeof(preauth->sha512_value));
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}
		for (i = 1; i < smb2req->in.vector_count; i++) {
			rc = gnutls_hash(hash_hnd,
					 smb2req->in.vector[i].iov_base,
					 smb2req->in.vector[i].iov_len);
			if (rc < 0) {
				gnutls_hash_deinit(hash_hnd, NULL);
				return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
			}
		}
		gnutls_hash_deinit(hash_hnd, preauth->sha512_value);

		p = data_blob_const(preauth->sha512_value,
				    sizeof(preauth->sha512_value));

		d = &derivation.signing;
		d->label = data_blob_string_const_null("SMBSigningKey");
		d->context = p;

	} else if (xconn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d;

		d = &derivation.signing;
		d->label = data_blob_string_const_null("SMB2AESCMAC");
		d->context = data_blob_string_const_null("SmbSign");
	}

	status = smbXsrv_session_find_channel(session, xconn, &c);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ok = security_token_is_sid(session_info->security_token,
			&x->global->auth_session_info->security_token->sids[0]);
	if (!ok) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (session_info->session_key.length == 0) {
		/* See [MS-SMB2] 3.3.5.2.4 for the return code. */
		return NT_STATUS_NOT_SUPPORTED;
	}

	ZERO_STRUCT(session_key);
	memcpy(session_key, session_info->session_key.data,
	       MIN(session_info->session_key.length, sizeof(session_key)));

	c->signing_key = talloc_zero(x->global, struct smb2_signing_key);
	if (c->signing_key == NULL) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(c->signing_key,
			      smb2_signing_key_destructor);

	c->signing_key->blob =
		c->signing_key_blob =
			data_blob_talloc(c->signing_key,
					 session_key,
					 sizeof(session_key));
	if (!smb2_signing_key_valid(c->signing_key)) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_keep_secret(c->signing_key->blob.data);

	if (xconn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d = &derivation.signing;

		status = smb2_key_derivation(session_key, sizeof(session_key),
					     d->label.data, d->label.length,
					     d->context.data, d->context.length,
					     c->signing_key->blob.data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	ZERO_STRUCT(session_key);

	TALLOC_FREE(auth);
	status = smbXsrv_session_update(session);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smb2: Failed to update session for vuid=%llu - %s\n",
			  (unsigned long long)session->global->session_wire_id,
			  nt_errstr(status)));
		return NT_STATUS_LOGON_FAILURE;
	}

	*out_session_id = session->global->session_wire_id;

	return NT_STATUS_OK;
}

struct smbd_smb2_session_setup_state {
	struct tevent_context *ev;
	struct smbd_smb2_request *smb2req;
	uint64_t in_session_id;
	uint8_t in_flags;
	uint8_t in_security_mode;
	uint64_t in_previous_session_id;
	DATA_BLOB in_security_buffer;
	struct smbXsrv_session *session;
	struct smbXsrv_session_auth0 *auth;
	struct auth_session_info *session_info;
	uint16_t out_session_flags;
	DATA_BLOB out_security_buffer;
	uint64_t out_session_id;
};

static void smbd_smb2_session_setup_gensec_done(struct tevent_req *subreq);
static void smbd_smb2_session_setup_previous_done(struct tevent_req *subreq);
static void smbd_smb2_session_setup_auth_return(struct tevent_req *req);

static struct tevent_req *smbd_smb2_session_setup_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req,
					uint64_t in_session_id,
					uint8_t in_flags,
					uint8_t in_security_mode,
					uint64_t in_previous_session_id,
					DATA_BLOB in_security_buffer)
{
	struct tevent_req *req;
	struct smbd_smb2_session_setup_state *state;
	NTSTATUS status;
	NTTIME now = timeval_to_nttime(&smb2req->request_time);
	struct tevent_req *subreq;
	struct smbXsrv_channel_global0 *c = NULL;
	enum security_user_level seclvl;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_session_setup_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->smb2req = smb2req;
	state->in_session_id = in_session_id;
	state->in_flags = in_flags;
	state->in_security_mode = in_security_mode;
	state->in_previous_session_id = in_previous_session_id;
	state->in_security_buffer = in_security_buffer;

	if (in_flags & SMB2_SESSION_FLAG_BINDING) {
		if (smb2req->xconn->protocol < PROTOCOL_SMB2_22) {
			tevent_req_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
			return tevent_req_post(req, ev);
		}

		if (!smb2req->xconn->client->server_multi_channel_enabled) {
			tevent_req_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
			return tevent_req_post(req, ev);
		}

		if (in_session_id == 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		if (smb2req->session == NULL) {
			tevent_req_nterror(req, NT_STATUS_USER_SESSION_DELETED);
			return tevent_req_post(req, ev);
		}

		if (!smb2req->do_signing) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		status = smbXsrv_session_find_channel(smb2req->session,
						      smb2req->xconn,
						      &c);
		if (NT_STATUS_IS_OK(status)) {
			if (!smb2_signing_key_valid(c->signing_key)) {
				goto auth;
			}
			tevent_req_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
			return tevent_req_post(req, ev);
		}

		/*
		 * OLD: 3.00 NEW 3.02 => INVALID_PARAMETER
		 * OLD: 3.02 NEW 3.00 => INVALID_PARAMETER
		 * OLD: 2.10 NEW 3.02 => ACCESS_DENIED
		 * OLD: 3.02 NEW 2.10 => ACCESS_DENIED
		 */
		if (smb2req->session->global->connection_dialect
		    < SMB2_DIALECT_REVISION_222)
		{
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}
		if (smb2req->xconn->smb2.server.dialect
		    < SMB2_DIALECT_REVISION_222)
		{
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}
		if (smb2req->session->global->connection_dialect
		    != smb2req->xconn->smb2.server.dialect)
		{
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		seclvl = security_session_user_level(
				smb2req->session->global->auth_session_info,
				NULL);
		if (seclvl < SECURITY_USER) {
			tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
			return tevent_req_post(req, ev);
		}

		status = smbXsrv_session_add_channel(smb2req->session,
						     smb2req->xconn,
						     now,
						     &c);
		if (!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}

		status = smbXsrv_session_update(smb2req->session);
		if (!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
	}

auth:

	if (state->in_session_id == 0) {
		/* create a new session */
		status = smbXsrv_session_create(state->smb2req->xconn,
					        now, &state->session);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
		smb2req->session = state->session;
	} else {
		if (smb2req->session == NULL) {
			tevent_req_nterror(req, NT_STATUS_USER_SESSION_DELETED);
			return tevent_req_post(req, ev);
		}

		state->session = smb2req->session;
		status = state->session->status;
		if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
			status = NT_STATUS_OK;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			status = NT_STATUS_OK;
		}
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
		if (!(in_flags & SMB2_SESSION_FLAG_BINDING)) {
			state->session->status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		}
	}

	status = smbXsrv_session_find_channel(smb2req->session,
					      smb2req->xconn, &c);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	status = smbXsrv_session_find_auth(state->session, smb2req->xconn,
					   now, &state->auth);
	if (!NT_STATUS_IS_OK(status)) {
		status = smbXsrv_session_create_auth(state->session,
						     smb2req->xconn, now,
						     in_flags, in_security_mode,
						     &state->auth);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	if (state->auth->gensec == NULL) {
		status = auth_generic_prepare(state->auth,
					      state->smb2req->xconn->remote_address,
					      state->smb2req->xconn->local_address,
					      "SMB2",
					      &state->auth->gensec);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		gensec_want_feature(state->auth->gensec, GENSEC_FEATURE_SESSION_KEY);
		gensec_want_feature(state->auth->gensec, GENSEC_FEATURE_UNIX_TOKEN);
		gensec_want_feature(state->auth->gensec, GENSEC_FEATURE_SMB_TRANSPORT);

		status = gensec_start_mech_by_oid(state->auth->gensec,
						  GENSEC_OID_SPNEGO);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	status = smbXsrv_session_update(state->session);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	become_root();
	subreq = gensec_update_send(state, state->ev,
				    state->auth->gensec,
				    state->in_security_buffer);
	unbecome_root();
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbd_smb2_session_setup_gensec_done, req);

	return req;
}

static void smbd_smb2_session_setup_gensec_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbd_smb2_session_setup_state *state =
		tevent_req_data(req,
		struct smbd_smb2_session_setup_state);
	NTSTATUS status;

	become_root();
	status = gensec_update_recv(subreq, state,
				    &state->out_security_buffer);
	unbecome_root();
	TALLOC_FREE(subreq);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) &&
	    !NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		state->out_session_id = state->session->global->session_wire_id;
		state->smb2req->preauth = state->auth->preauth;
		tevent_req_nterror(req, status);
		return;
	}

	status = gensec_session_info(state->auth->gensec,
				     state,
				     &state->session_info);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if ((state->in_previous_session_id != 0) &&
	     (state->session->global->session_wire_id !=
	      state->in_previous_session_id))
	{
		subreq = smb2srv_session_close_previous_send(state, state->ev,
						state->smb2req->xconn,
						state->session_info,
						state->in_previous_session_id,
						state->session->global->session_wire_id);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					smbd_smb2_session_setup_previous_done,
					req);
		return;
	}

	smbd_smb2_session_setup_auth_return(req);
}

static void smbd_smb2_session_setup_previous_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	NTSTATUS status;

	status = smb2srv_session_close_previous_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	smbd_smb2_session_setup_auth_return(req);
}

static void smbd_smb2_session_setup_auth_return(struct tevent_req *req)
{
	struct smbd_smb2_session_setup_state *state =
		tevent_req_data(req,
		struct smbd_smb2_session_setup_state);
	NTSTATUS status;

	if (state->in_flags & SMB2_SESSION_FLAG_BINDING) {
		status = smbd_smb2_bind_auth_return(state->session,
						    &state->auth,
						    state->smb2req,
						    state->session_info,
						    &state->out_session_flags,
						    &state->out_session_id);
		if (tevent_req_nterror(req, status)) {
			return;
		}
		tevent_req_done(req);
		return;
	}

	if (state->session->global->auth_session_info != NULL) {
		status = smbd_smb2_reauth_generic_return(state->session,
							 &state->auth,
							 state->smb2req,
							 state->session_info,
							 &state->out_session_flags,
							 &state->out_session_id);
		if (tevent_req_nterror(req, status)) {
			return;
		}
		tevent_req_done(req);
		return;
	}

	status = smbd_smb2_auth_generic_return(state->session,
					       &state->auth,
					       state->smb2req,
					       state->in_security_mode,
					       state->session_info,
					       &state->out_session_flags,
					       &state->out_session_id);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
	return;
}

static NTSTATUS smbd_smb2_session_setup_recv(struct tevent_req *req,
					uint16_t *out_session_flags,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	struct smbd_smb2_session_setup_state *state =
		tevent_req_data(req,
		struct smbd_smb2_session_setup_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			tevent_req_received(req);
			return nt_status_squash(status);
		}
	} else {
		status = NT_STATUS_OK;
	}

	*out_session_flags = state->out_session_flags;
	*out_security_buffer = state->out_security_buffer;
	*out_session_id = state->out_session_id;

	talloc_steal(mem_ctx, out_security_buffer->data);
	tevent_req_received(req);
	return status;
}

struct smbd_smb2_session_setup_wrap_state {
	struct tevent_context *ev;
	struct smbd_smb2_request *smb2req;
	uint64_t in_session_id;
	uint8_t in_flags;
	uint8_t in_security_mode;
	uint64_t in_previous_session_id;
	DATA_BLOB in_security_buffer;
	uint16_t out_session_flags;
	DATA_BLOB out_security_buffer;
	uint64_t out_session_id;
	NTSTATUS error;
};

static void smbd_smb2_session_setup_wrap_setup_done(struct tevent_req *subreq);
static void smbd_smb2_session_setup_wrap_shutdown_done(struct tevent_req *subreq);

static struct tevent_req *smbd_smb2_session_setup_wrap_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req,
					uint64_t in_session_id,
					uint8_t in_flags,
					uint8_t in_security_mode,
					uint64_t in_previous_session_id,
					DATA_BLOB in_security_buffer)
{
	struct tevent_req *req;
	struct smbd_smb2_session_setup_wrap_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_session_setup_wrap_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->smb2req = smb2req;
	state->in_session_id = in_session_id;
	state->in_flags = in_flags;
	state->in_security_mode = in_security_mode;
	state->in_previous_session_id = in_previous_session_id;
	state->in_security_buffer = in_security_buffer;

	subreq = smbd_smb2_session_setup_send(state, state->ev,
					      state->smb2req,
					      state->in_session_id,
					      state->in_flags,
					      state->in_security_mode,
					      state->in_previous_session_id,
					      state->in_security_buffer);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				smbd_smb2_session_setup_wrap_setup_done, req);

	return req;
}

static void smbd_smb2_session_setup_wrap_setup_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbd_smb2_session_setup_wrap_state *state =
		tevent_req_data(req,
		struct smbd_smb2_session_setup_wrap_state);
	NTSTATUS status;

	status = smbd_smb2_session_setup_recv(subreq,
					      &state->out_session_flags,
					      state,
					      &state->out_security_buffer,
					      &state->out_session_id);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		return;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (state->smb2req->session == NULL) {
		tevent_req_nterror(req, status);
		return;
	}

	state->error = status;

	subreq = smb2srv_session_shutdown_send(state, state->ev,
					       state->smb2req->session,
					       state->smb2req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				smbd_smb2_session_setup_wrap_shutdown_done,
				req);
}

static void smbd_smb2_session_setup_wrap_shutdown_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbd_smb2_session_setup_wrap_state *state =
		tevent_req_data(req,
		struct smbd_smb2_session_setup_wrap_state);
	NTSTATUS status;

	status = smb2srv_session_shutdown_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * we may need to sign the response, so we need to keep
	 * the session until the response is sent to the wire.
	 */
	talloc_steal(state->smb2req, state->smb2req->session);

	tevent_req_nterror(req, state->error);
}

static NTSTATUS smbd_smb2_session_setup_wrap_recv(struct tevent_req *req,
					uint16_t *out_session_flags,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	struct smbd_smb2_session_setup_wrap_state *state =
		tevent_req_data(req,
		struct smbd_smb2_session_setup_wrap_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			tevent_req_received(req);
			return nt_status_squash(status);
		}
	} else {
		status = NT_STATUS_OK;
	}

	*out_session_flags = state->out_session_flags;
	*out_security_buffer = state->out_security_buffer;
	*out_session_id = state->out_session_id;

	talloc_steal(mem_ctx, out_security_buffer->data);
	tevent_req_received(req);
	return status;
}

static struct tevent_req *smbd_smb2_logoff_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req);
static NTSTATUS smbd_smb2_logoff_recv(struct tevent_req *req);
static void smbd_smb2_request_logoff_done(struct tevent_req *subreq);

NTSTATUS smbd_smb2_request_process_logoff(struct smbd_smb2_request *req)
{
	NTSTATUS status;
	struct tevent_req *subreq = NULL;

	status = smbd_smb2_request_verify_sizes(req, 0x04);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	subreq = smbd_smb2_logoff_send(req, req->sconn->ev_ctx, req);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_logoff_done, req);

	/*
	 * Avoid sending a STATUS_PENDING message, it's very likely
	 * the client won't expect that.
	 */
	return smbd_smb2_request_pending_queue(req, subreq, 0);
}

static void smbd_smb2_request_logoff_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *smb2req =
		tevent_req_callback_data(subreq,
		struct smbd_smb2_request);
	DATA_BLOB outbody;
	NTSTATUS status;
	NTSTATUS error;

	status = smbd_smb2_logoff_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(smb2req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							nt_errstr(error));
			return;
		}
		return;
	}

	outbody = smbd_smb2_generate_outbody(smb2req, 0x04);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x04);        /* struct size */
	SSVAL(outbody.data, 0x02, 0);           /* reserved */

	error = smbd_smb2_request_done(smb2req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(smb2req->xconn,
						nt_errstr(error));
		return;
	}
}

struct smbd_smb2_logoff_state {
	struct smbd_smb2_request *smb2req;
};

static void smbd_smb2_logoff_shutdown_done(struct tevent_req *subreq);

static struct tevent_req *smbd_smb2_logoff_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req)
{
	struct tevent_req *req;
	struct smbd_smb2_logoff_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
			struct smbd_smb2_logoff_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;

	subreq = smb2srv_session_shutdown_send(state, ev,
					       smb2req->session,
					       smb2req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbd_smb2_logoff_shutdown_done, req);

	return req;
}

static void smbd_smb2_logoff_shutdown_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_smb2_logoff_state *state = tevent_req_data(
		req, struct smbd_smb2_logoff_state);
	NTSTATUS status;
	bool ok;
	const struct GUID *client_guid =
		&state->smb2req->session->client->global->client_guid;

	status = smb2srv_session_shutdown_recv(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	TALLOC_FREE(subreq);

	if (!GUID_all_zero(client_guid)) {
		ok = remote_arch_cache_delete(client_guid);
		if (!ok) {
			/* Most likely not an error, but not in cache */
			DBG_DEBUG("Deletion from remote arch cache failed\n");
		}
	}

	/*
	 * As we've been awoken, we may have changed
	 * uid in the meantime. Ensure we're still
	 * root (SMB2_OP_LOGOFF has .as_root = true).
	 */
	change_to_root_user();

	status = smbXsrv_session_logoff(state->smb2req->session);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * we may need to sign the response, so we need to keep
	 * the session until the response is sent to the wire.
	 */
	talloc_steal(state->smb2req, state->smb2req->session);

	tevent_req_done(req);
}

static NTSTATUS smbd_smb2_logoff_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}
