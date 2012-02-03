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
	uint64_t in_session_id;
	uint8_t in_security_mode;
	uint16_t in_security_offset;
	uint16_t in_security_length;
	DATA_BLOB in_security_buffer;
	uint16_t out_session_flags;
	uint64_t out_session_id;
	uint16_t out_security_offset;
	DATA_BLOB out_security_buffer = data_blob_null;
	NTSTATUS status;

	status = smbd_smb2_request_verify_sizes(smb2req, 0x19);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(smb2req, status);
	}
	inhdr = (const uint8_t *)smb2req->in.vector[i+0].iov_base;
	inbody = (const uint8_t *)smb2req->in.vector[i+1].iov_base;

	in_security_offset = SVAL(inbody, 0x0C);
	in_security_length = SVAL(inbody, 0x0E);

	if (in_security_offset != (SMB2_HDR_BODY + smb2req->in.vector[i+1].iov_len)) {
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

static NTSTATUS smbd_smb2_auth_generic_return(struct smbd_smb2_session *session,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					DATA_BLOB in_security_buffer,
					uint16_t *out_session_flags,
					uint64_t *out_session_id)
{
	bool guest = false;

	if ((in_security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) ||
	    lp_server_signing() == SMB_SIGNING_REQUIRED) {
		session->do_signing = true;
	}

	if (security_session_user_level(session->session_info, NULL) < SECURITY_USER) {
		/* we map anonymous to guest internally */
		*out_session_flags |= SMB2_SESSION_FLAG_IS_GUEST;
		*out_session_flags |= SMB2_SESSION_FLAG_IS_NULL;
		/* force no signing */
		session->do_signing = false;
		guest = true;
	}

	session->session_key = session->session_info->session_key;

	session->compat_vuser = talloc_zero(session, user_struct);
	if (session->compat_vuser == NULL) {
		TALLOC_FREE(session);
		return NT_STATUS_NO_MEMORY;
	}
	session->compat_vuser->gensec_security = session->gensec_security;
	session->compat_vuser->homes_snum = -1;
	session->compat_vuser->session_info = session->session_info;
	session->compat_vuser->session_keystr = NULL;
	session->compat_vuser->vuid = session->vuid;
	DLIST_ADD(session->sconn->smb1.sessions.validated_users, session->compat_vuser);

	if (security_session_user_level(session->session_info, NULL) >= SECURITY_USER) {
		session->compat_vuser->homes_snum =
			register_homes_share(session->session_info->unix_info->unix_name);
	}

	if (!session_claim(session->sconn, session->compat_vuser)) {
		DEBUG(1, ("smb2: Failed to claim session "
			"for vuid=%d\n",
			session->compat_vuser->vuid));
		TALLOC_FREE(session);
		return NT_STATUS_LOGON_FAILURE;
	}

	set_current_user_info(session->session_info->unix_info->sanitized_username,
			      session->session_info->unix_info->unix_name,
			      session->session_info->info->domain_name);

	reload_services(smb2req->sconn, conn_snum_used, true);

	session->status = NT_STATUS_OK;

	/*
	 * we attach the session to the request
	 * so that the response can be signed
	 */
	smb2req->session = session;
	if (!guest) {
		smb2req->do_signing = true;
	}

	global_client_caps |= (CAP_LEVEL_II_OPLOCKS|CAP_STATUS32);

	*out_session_id = session->vuid;

	return NT_STATUS_OK;
}

static NTSTATUS smbd_smb2_auth_generic(struct smbd_smb2_session *session,
				       struct smbd_smb2_request *smb2req,
				       uint8_t in_security_mode,
				       DATA_BLOB in_security_buffer,
				       uint16_t *out_session_flags,
				       DATA_BLOB *out_security_buffer,
				       uint64_t *out_session_id)
{
	NTSTATUS status;

	*out_security_buffer = data_blob_null;

	if (session->gensec_security == NULL) {
		status = auth_generic_prepare(session, session->sconn->remote_address,
					    &session->gensec_security);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(session);
			return status;
		}

		gensec_want_feature(session->gensec_security, GENSEC_FEATURE_SESSION_KEY);
		gensec_want_feature(session->gensec_security, GENSEC_FEATURE_UNIX_TOKEN);

		status = gensec_start_mech_by_oid(session->gensec_security, GENSEC_OID_SPNEGO);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(session);
			return status;
		}
	}

	become_root();
	status = gensec_update(session->gensec_security,
			       smb2req, NULL,
			       in_security_buffer,
			       out_security_buffer);
	unbecome_root();
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) &&
	    !NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(session);
		return nt_status_squash(status);
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		*out_session_id = session->vuid;
		return status;
	}

	status = gensec_session_info(session->gensec_security,
				     session,
				     &session->session_info);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(session);
		return status;
	}
	*out_session_id = session->vuid;

	return smbd_smb2_auth_generic_return(session,
					     smb2req,
					     in_security_mode,
					     in_security_buffer,
					     out_session_flags,
					     out_session_id);
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

	return smbd_smb2_auth_generic(session,
				      smb2req,
				      in_security_mode,
				      in_security_buffer,
				      out_session_flags,
				      out_security_buffer,
				      out_session_id);
}

NTSTATUS smbd_smb2_request_process_logoff(struct smbd_smb2_request *req)
{
	NTSTATUS status;
	DATA_BLOB outbody;

	status = smbd_smb2_request_verify_sizes(req, 0x04);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
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
