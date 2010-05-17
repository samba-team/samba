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
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "../libcli/auth/spnego.h"
#include "ntlmssp.h"

static NTSTATUS smbd_smb2_session_setup(struct smbd_smb2_request *smb2req,
					uint64_t in_session_id,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id);

NTSTATUS smbd_smb2_request_process_sesssetup(struct smbd_smb2_request *smb2req)
{
	const uint8_t *inhdr;
	const uint8_t *inbody;
	int i = smb2req->current_idx;
	uint8_t *outhdr;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	size_t expected_body_size = 0x19;
	size_t body_size;
	uint64_t in_session_id;
	uint8_t in_security_mode;
	uint16_t in_security_offset;
	uint16_t in_security_length;
	DATA_BLOB in_security_buffer;
	uint16_t out_session_flags;
	uint64_t out_session_id;
	uint16_t out_security_offset;
	DATA_BLOB out_security_buffer;
	NTSTATUS status;

	inhdr = (const uint8_t *)smb2req->in.vector[i+0].iov_base;

	if (smb2req->in.vector[i+1].iov_len != (expected_body_size & 0xFFFFFFFE)) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	inbody = (const uint8_t *)smb2req->in.vector[i+1].iov_base;

	body_size = SVAL(inbody, 0x00);
	if (body_size != expected_body_size) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	in_security_offset = SVAL(inbody, 0x0C);
	in_security_length = SVAL(inbody, 0x0E);

	if (in_security_offset != (SMB2_HDR_BODY + (body_size & 0xFFFFFFFE))) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_security_length > smb2req->in.vector[i+2].iov_len) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	in_security_mode = CVAL(inbody, 0x03);
	in_security_buffer.data = (uint8_t *)smb2req->in.vector[i+2].iov_base;
	in_security_buffer.length = in_security_length;

	status = smbd_smb2_session_setup(smb2req,
					 in_session_id,
					 in_security_mode,
					 in_security_buffer,
					 &out_session_flags,
					 &out_security_buffer,
					 &out_session_id);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = nt_status_squash(status);
		return smbd_smb2_request_error(smb2req, status);
	}

	out_security_offset = SMB2_HDR_BODY + 0x08;

	outhdr = (uint8_t *)smb2req->out.vector[i].iov_base;

	outbody = data_blob_talloc(smb2req->out.vector, NULL, 0x08);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
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

	return smbd_smb2_request_done_ex(smb2req, status, outbody, &outdyn,
					 __location__);
}

static int smbd_smb2_session_destructor(struct smbd_smb2_session *session)
{
	if (session->sconn == NULL) {
		return 0;
	}

	/* first free all tcons */
	while (session->tcons.list) {
		talloc_free(session->tcons.list);
	}

	idr_remove(session->sconn->smb2.sessions.idtree, session->vuid);
	DLIST_REMOVE(session->sconn->smb2.sessions.list, session);
	invalidate_vuid(session->sconn, session->vuid);

	session->vuid = 0;
	session->status = NT_STATUS_USER_SESSION_DELETED;
	session->sconn = NULL;

	return 0;
}

static NTSTATUS smbd_smb2_session_setup_krb5(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					const DATA_BLOB *psecblob_in,
					const char *kerb_mech,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS smbd_smb2_spnego_negotiate(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	DATA_BLOB secblob_in = data_blob_null;
	DATA_BLOB chal_out = data_blob_null;
	DATA_BLOB secblob_out = data_blob_null;
	char *kerb_mech = NULL;
	NTSTATUS status;

	/* Ensure we have no old NTLM state around. */
	auth_ntlmssp_end(&session->auth_ntlmssp_state);

	status = parse_spnego_mechanisms(in_security_buffer,
			&secblob_in, &kerb_mech);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

#ifdef HAVE_KRB5
	if (kerb_mech && ((lp_security()==SEC_ADS) ||
				USE_KERBEROS_KEYTAB) ) {
		status = smbd_smb2_session_setup_krb5(session,
				smb2req,
				&secblob_in,
				kerb_mech,
				out_session_flags,
				out_security_buffer,
				out_session_id);

		goto out;
	}
#endif

	status = auth_ntlmssp_start(&session->auth_ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = auth_ntlmssp_update(session->auth_ntlmssp_state,
				     secblob_in,
				     &chal_out);

	if (!NT_STATUS_IS_OK(status) &&
			!NT_STATUS_EQUAL(status,
				NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto out;
	}

	secblob_out = spnego_gen_auth_response(&chal_out,
						status,
						OID_NTLMSSP);
	*out_security_buffer = data_blob_talloc(smb2req,
						secblob_out.data,
						secblob_out.length);
	if (out_security_buffer->data == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	*out_session_id = session->vuid;

  out:

	data_blob_free(&secblob_in);
	data_blob_free(&secblob_out);
	data_blob_free(&chal_out);
	SAFE_FREE(kerb_mech);
	if (!NT_STATUS_IS_OK(status) &&
			!NT_STATUS_EQUAL(status,
				NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		auth_ntlmssp_end(&session->auth_ntlmssp_state);
		TALLOC_FREE(session);
	}
	return status;
}

static NTSTATUS smbd_smb2_common_ntlmssp_auth_return(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags)
{
	if ((in_security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) ||
	    lp_server_signing() == Required) {
		session->do_signing = true;
	}

	if (session->auth_ntlmssp_state->server_info->guest) {
		/* we map anonymous to guest internally */
		*out_session_flags |= SMB2_SESSION_FLAG_IS_GUEST;
		*out_session_flags |= SMB2_SESSION_FLAG_IS_NULL;
		/* force no signing */
		session->do_signing = false;
	}

	session->server_info = session->auth_ntlmssp_state->server_info;
	data_blob_free(&session->server_info->user_session_key);
	session->server_info->user_session_key =
			data_blob_talloc(
			session->server_info,
			session->auth_ntlmssp_state->ntlmssp_state->session_key.data,
			session->auth_ntlmssp_state->ntlmssp_state->session_key.length);
	if (session->auth_ntlmssp_state->ntlmssp_state->session_key.length > 0) {
		if (session->server_info->user_session_key.data == NULL) {
			auth_ntlmssp_end(&session->auth_ntlmssp_state);
			TALLOC_FREE(session);
			return NT_STATUS_NO_MEMORY;
		}
	}
	session->session_key = session->server_info->user_session_key;

	session->compat_vuser = talloc_zero(session, user_struct);
	if (session->compat_vuser == NULL) {
		auth_ntlmssp_end(&session->auth_ntlmssp_state);
		TALLOC_FREE(session);
		return NT_STATUS_NO_MEMORY;
	}
	session->compat_vuser->auth_ntlmssp_state = session->auth_ntlmssp_state;
	session->compat_vuser->homes_snum = -1;
	session->compat_vuser->server_info = session->server_info;
	session->compat_vuser->session_keystr = NULL;
	session->compat_vuser->vuid = session->vuid;
	DLIST_ADD(session->sconn->smb1.sessions.validated_users, session->compat_vuser);

	session->status = NT_STATUS_OK;

	/*
	 * we attach the session to the request
	 * so that the response can be signed
	 */
	smb2req->session = session;
	if (session->do_signing) {
		smb2req->do_signing = true;
	}

	global_client_caps |= (CAP_LEVEL_II_OPLOCKS|CAP_STATUS32);
	return NT_STATUS_OK;
}

static NTSTATUS smbd_smb2_spnego_auth(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	DATA_BLOB auth = data_blob_null;
	DATA_BLOB auth_out = data_blob_null;
	DATA_BLOB secblob_out = data_blob_null;
	NTSTATUS status;

	if (!spnego_parse_auth(in_security_buffer, &auth)) {
		TALLOC_FREE(session);
		return NT_STATUS_LOGON_FAILURE;
	}

	status = auth_ntlmssp_update(session->auth_ntlmssp_state,
				     auth,
				     &auth_out);
	if (!NT_STATUS_IS_OK(status)) {
		auth_ntlmssp_end(&session->auth_ntlmssp_state);
		data_blob_free(&auth);
		TALLOC_FREE(session);
		return status;
	}

	data_blob_free(&auth);

	secblob_out = spnego_gen_auth_response(&auth_out,
                               status, NULL);

	*out_security_buffer = data_blob_talloc(smb2req,
						secblob_out.data,
						secblob_out.length);
	if (out_security_buffer->data == NULL) {
		auth_ntlmssp_end(&session->auth_ntlmssp_state);
		TALLOC_FREE(session);
		return NT_STATUS_NO_MEMORY;
	}

	*out_session_id = session->vuid;

	return smbd_smb2_common_ntlmssp_auth_return(session,
						smb2req,
						in_security_mode,
						in_security_buffer,
						out_session_flags);
}

static NTSTATUS smbd_smb2_raw_ntlmssp_auth(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	NTSTATUS status;
	DATA_BLOB secblob_out = data_blob_null;

	if (session->auth_ntlmssp_state == NULL) {
		status = auth_ntlmssp_start(&session->auth_ntlmssp_state);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(session);
			return status;
		}
	}

	/* RAW NTLMSSP */
	status = auth_ntlmssp_update(session->auth_ntlmssp_state,
				     in_security_buffer,
				     &secblob_out);

	if (NT_STATUS_IS_OK(status) ||
			NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		*out_security_buffer = data_blob_talloc(smb2req,
						secblob_out.data,
						secblob_out.length);
		if (out_security_buffer->data == NULL) {
			auth_ntlmssp_end(&session->auth_ntlmssp_state);
			TALLOC_FREE(session);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		*out_session_id = session->vuid;
		return status;
	}
	if (!NT_STATUS_IS_OK(status)) {
		auth_ntlmssp_end(&session->auth_ntlmssp_state);
		TALLOC_FREE(session);
		return status;
	}
	*out_session_id = session->vuid;

	return smbd_smb2_common_ntlmssp_auth_return(session,
						smb2req,
						in_security_mode,
						in_security_buffer,
						out_session_flags);
}

static NTSTATUS smbd_smb2_session_setup(struct smbd_smb2_request *smb2req,
					uint64_t in_session_id,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	struct smbd_smb2_session *session;

	*out_session_flags = 0;
	*out_session_id = 0;

	if (in_session_id == 0) {
		int id;

		/* create a new session */
		session = talloc_zero(smb2req->sconn, struct smbd_smb2_session);
		if (session == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		session->status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		id = idr_get_new_random(smb2req->sconn->smb2.sessions.idtree,
					session,
					smb2req->sconn->smb2.sessions.limit);
		if (id == -1) {
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}
		session->vuid = id;

		session->tcons.idtree = idr_init(session);
		if (session->tcons.idtree == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		session->tcons.limit = 0x0000FFFE;
		session->tcons.list = NULL;

		DLIST_ADD_END(smb2req->sconn->smb2.sessions.list, session,
			      struct smbd_smb2_session *);
		session->sconn = smb2req->sconn;
		talloc_set_destructor(session, smbd_smb2_session_destructor);
	} else {
		void *p;

		/* lookup an existing session */
		p = idr_find(smb2req->sconn->smb2.sessions.idtree, in_session_id);
		if (p == NULL) {
			return NT_STATUS_USER_SESSION_DELETED;
		}
		session = talloc_get_type_abort(p, struct smbd_smb2_session);
	}

	if (NT_STATUS_IS_OK(session->status)) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	if (in_security_buffer.data[0] == ASN1_APPLICATION(0)) {
		return smbd_smb2_spnego_negotiate(session,
						smb2req,
						in_security_buffer,
						out_session_flags,
						out_security_buffer,
						out_session_id);
	} else if (in_security_buffer.data[0] == ASN1_CONTEXT(1)) {
		return smbd_smb2_spnego_auth(session,
						smb2req,
						in_security_mode,
						in_security_buffer,
						out_session_flags,
						out_security_buffer,
						out_session_id);
	} else if (strncmp((char *)(in_security_buffer.data), "NTLMSSP", 7) == 0) {
		return smbd_smb2_raw_ntlmssp_auth(session,
						smb2req,
						in_security_mode,
						in_security_buffer,
						out_session_flags,
						out_security_buffer,
						out_session_id);
	}

	/* Unknown packet type. */
	DEBUG(1,("Unknown packet type %u in smb2 sessionsetup\n",
		(unsigned int)in_security_buffer.data[0] ));
	auth_ntlmssp_end(&session->auth_ntlmssp_state);
	TALLOC_FREE(session);
	return NT_STATUS_LOGON_FAILURE;
}

NTSTATUS smbd_smb2_request_check_session(struct smbd_smb2_request *req)
{
	const uint8_t *inhdr;
	const uint8_t *outhdr;
	int i = req->current_idx;
	uint64_t in_session_id;
	void *p;
	struct smbd_smb2_session *session;
	bool chained_fixup = false;

	inhdr = (const uint8_t *)req->in.vector[i+0].iov_base;

	in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);

	if (in_session_id == (0xFFFFFFFFFFFFFFFFLL)) {
		if (req->async) {
			/*
			 * async request - fill in session_id from
			 * already setup request out.vector[].iov_base.
			 */
			outhdr = (const uint8_t *)req->out.vector[i].iov_base;
			in_session_id = BVAL(outhdr, SMB2_HDR_SESSION_ID);
		} else if (i > 2) {
			/*
			 * Chained request - fill in session_id from
			 * the previous request out.vector[].iov_base.
			 */
			outhdr = (const uint8_t *)req->out.vector[i-3].iov_base;
			in_session_id = BVAL(outhdr, SMB2_HDR_SESSION_ID);
			chained_fixup = true;
		}
	}

	/* lookup an existing session */
	p = idr_find(req->sconn->smb2.sessions.idtree, in_session_id);
	if (p == NULL) {
		return NT_STATUS_USER_SESSION_DELETED;
	}
	session = talloc_get_type_abort(p, struct smbd_smb2_session);

	if (!NT_STATUS_IS_OK(session->status)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	set_current_user_info(session->server_info->sanitized_username,
			      session->server_info->unix_name,
			      pdb_get_domain(session->server_info->sam_account));

	req->session = session;

	if (chained_fixup) {
		/* Fix up our own outhdr. */
		outhdr = (const uint8_t *)req->out.vector[i].iov_base;
		SBVAL(outhdr, SMB2_HDR_SESSION_ID, in_session_id);
	}
	return NT_STATUS_OK;
}

NTSTATUS smbd_smb2_request_process_logoff(struct smbd_smb2_request *req)
{
	const uint8_t *inbody;
	int i = req->current_idx;
	DATA_BLOB outbody;
	size_t expected_body_size = 0x04;
	size_t body_size;

	if (req->in.vector[i+1].iov_len != (expected_body_size & 0xFFFFFFFE)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	inbody = (const uint8_t *)req->in.vector[i+1].iov_base;

	body_size = SVAL(inbody, 0x00);
	if (body_size != expected_body_size) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	/*
	 * TODO: cancel all outstanding requests on the session
	 *       and delete all tree connections.
	 */
	smbd_smb2_session_destructor(req->session);
	/*
	 * we may need to sign the response, so we need to keep
	 * the session until the response is sent to the wire.
	 */
	talloc_steal(req, req->session);

	outbody = data_blob_talloc(req->out.vector, NULL, 0x04);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	SSVAL(outbody.data, 0x00, 0x04);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */

	return smbd_smb2_request_done(req, outbody, NULL);
}
