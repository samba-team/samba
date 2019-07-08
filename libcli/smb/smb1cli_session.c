/*
   Unix SMB/CIFS implementation.
   client connect/disconnect routines
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Andrew Bartlett 2001-2003
   Copyright (C) Volker Lendecke 2011
   Copyright (C) Jeremy Allison 2011
   Copyright (C) Stefan Metzmacher 2016

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
#include "system/network.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../libcli/smb/smb_common.h"
#include "../libcli/smb/smbXcli_base.h"


struct smb1cli_session_setup_lm21_state {
	struct smbXcli_session *session;
	uint16_t vwv[10];
	struct iovec *recv_iov;
	uint16_t out_session_id;
	uint16_t out_action;
	char *out_native_os;
	char *out_native_lm;
};

static void smb1cli_session_setup_lm21_done(struct tevent_req *subreq);

struct tevent_req *smb1cli_session_setup_lm21_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct smbXcli_conn *conn,
				uint32_t timeout_msec,
				uint32_t pid,
				struct smbXcli_session *session,
				uint16_t in_buf_size,
				uint16_t in_mpx_max,
				uint16_t in_vc_num,
				uint32_t in_sess_key,
				const char *in_user,
				const char *in_domain,
				const DATA_BLOB in_apassword,
				const char *in_native_os,
				const char *in_native_lm)
{
	struct tevent_req *req = NULL;
	struct smb1cli_session_setup_lm21_state *state = NULL;
	struct tevent_req *subreq = NULL;
	uint16_t *vwv = NULL;
	uint8_t *bytes = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb1cli_session_setup_lm21_state);
	if (req == NULL) {
		return NULL;
	}
	state->session = session;
	vwv = state->vwv;

	if (in_user == NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (in_domain == NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (in_apassword.length > UINT16_MAX) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (in_native_os == NULL && in_native_lm != NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	SCVAL(vwv+0, 0, 0xff);
	SCVAL(vwv+0, 1, 0);
	SSVAL(vwv+1, 0, 0);
	SSVAL(vwv+2, 0, in_buf_size);
	SSVAL(vwv+3, 0, in_mpx_max);
	SSVAL(vwv+4, 0, in_vc_num);
	SIVAL(vwv+5, 0, in_sess_key);
	SSVAL(vwv+7, 0, in_apassword.length);
	SSVAL(vwv+8, 0, 0); /* reserved */
	SSVAL(vwv+9, 0, 0); /* reserved */

	bytes = talloc_array(state, uint8_t,
			     in_apassword.length);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	if (in_apassword.length != 0) {
		memcpy(bytes,
		       in_apassword.data,
		       in_apassword.length);
	}

	bytes = smb_bytes_push_str(bytes,
				   smbXcli_conn_use_unicode(conn),
				   in_user, strlen(in_user)+1,
				   NULL);
	bytes = smb_bytes_push_str(bytes,
				   smbXcli_conn_use_unicode(conn),
				   in_domain, strlen(in_domain)+1,
				   NULL);
	if (in_native_os != NULL) {
		bytes = smb_bytes_push_str(bytes,
					   smbXcli_conn_use_unicode(conn),
					   in_native_os, strlen(in_native_os)+1,
					   NULL);
	}
	if (in_native_lm != NULL) {
		bytes = smb_bytes_push_str(bytes,
					   smbXcli_conn_use_unicode(conn),
					   in_native_lm, strlen(in_native_lm)+1,
					   NULL);
	}
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = smb1cli_req_send(state, ev, conn,
				  SMBsesssetupX,
				  0, /*  additional_flags */
				  0, /*  clear_flags */
				  0, /*  additional_flags2 */
				  0, /*  clear_flags2 */
				  timeout_msec,
				  pid,
				  NULL, /* tcon */
				  session,
				  10, /* wct */
				  vwv,
				  talloc_get_size(bytes),
				  bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb1cli_session_setup_lm21_done, req);

	return req;
}

static void smb1cli_session_setup_lm21_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb1cli_session_setup_lm21_state *state =
		tevent_req_data(req,
		struct smb1cli_session_setup_lm21_state);
	NTSTATUS status;
	uint8_t *inhdr = NULL;
	uint8_t wct;
	uint16_t *vwv = NULL;
	uint32_t num_bytes;
	uint8_t *bytes = NULL;
	const uint8_t *p = NULL;
	size_t ret = 0;
	uint16_t flags2;
	bool use_unicode = false;
	struct smb1cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.wct    = 3,
	},
	};

	status = smb1cli_req_recv(subreq, state,
				  &state->recv_iov,
				  &inhdr,
				  &wct,
				  &vwv,
				  NULL, /* pvwv_offset */
				  &num_bytes,
				  &bytes,
				  NULL, /* pbytes_offset */
				  NULL, /* pinbuf */
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	flags2 = SVAL(inhdr, HDR_FLG2);
	if (flags2 & FLAGS2_UNICODE_STRINGS) {
		use_unicode = true;
	}

	state->out_session_id = SVAL(inhdr, HDR_UID);
	state->out_action = SVAL(vwv+2, 0);

	p = bytes;

	status = smb_bytes_pull_str(state, &state->out_native_os,
				    use_unicode, bytes, num_bytes,
				    p, &ret);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	p += ret;

	status = smb_bytes_pull_str(state, &state->out_native_lm,
				    use_unicode, bytes, num_bytes,
				    p, &ret);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	smb1cli_session_set_id(state->session, state->out_session_id);
	smb1cli_session_set_action(state->session, state->out_action);

	tevent_req_done(req);
}

NTSTATUS smb1cli_session_setup_lm21_recv(struct tevent_req *req,
					 TALLOC_CTX *mem_ctx,
					 char **out_native_os,
					 char **out_native_lm)
{
	struct smb1cli_session_setup_lm21_state *state =
		tevent_req_data(req,
		struct smb1cli_session_setup_lm21_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	if (out_native_os != NULL) {
		*out_native_os = talloc_move(mem_ctx, &state->out_native_os);
	}

	if (out_native_lm != NULL) {
		*out_native_lm = talloc_move(mem_ctx, &state->out_native_lm);
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct smb1cli_session_setup_nt1_state {
	struct smbXcli_session *session;
	uint16_t vwv[13];
	struct iovec *recv_iov;
	uint8_t *inbuf;
	uint16_t out_session_id;
	uint16_t out_action;
	char *out_native_os;
	char *out_native_lm;
	char *out_primary_domain;
};

static void smb1cli_session_setup_nt1_done(struct tevent_req *subreq);

struct tevent_req *smb1cli_session_setup_nt1_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct smbXcli_conn *conn,
				uint32_t timeout_msec,
				uint32_t pid,
				struct smbXcli_session *session,
				uint16_t in_buf_size,
				uint16_t in_mpx_max,
				uint16_t in_vc_num,
				uint32_t in_sess_key,
				const char *in_user,
				const char *in_domain,
				const DATA_BLOB in_apassword,
				const DATA_BLOB in_upassword,
				uint32_t in_capabilities,
				const char *in_native_os,
				const char *in_native_lm)
{
	struct tevent_req *req = NULL;
	struct smb1cli_session_setup_nt1_state *state = NULL;
	struct tevent_req *subreq = NULL;
	uint16_t *vwv = NULL;
	uint8_t *bytes = NULL;
	size_t align_upassword = 0;
	size_t apassword_ofs = 0;
	size_t upassword_ofs = 0;

	req = tevent_req_create(mem_ctx, &state,
				struct smb1cli_session_setup_nt1_state);
	if (req == NULL) {
		return NULL;
	}
	state->session = session;
	vwv = state->vwv;

	if (in_user == NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (in_domain == NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (in_apassword.length > UINT16_MAX) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (in_upassword.length > UINT16_MAX) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (in_native_os == NULL && in_native_lm != NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	SCVAL(vwv+0,  0, 0xff);
	SCVAL(vwv+0,  1, 0);
	SSVAL(vwv+1,  0, 0);
	SSVAL(vwv+2,  0, in_buf_size);
	SSVAL(vwv+3,  0, in_mpx_max);
	SSVAL(vwv+4,  0, in_vc_num);
	SIVAL(vwv+5,  0, in_sess_key);
	SSVAL(vwv+7,  0, in_apassword.length);
	SSVAL(vwv+8,  0, in_upassword.length);
	SSVAL(vwv+9,  0, 0); /* reserved */
	SSVAL(vwv+10, 0, 0); /* reserved */
	SIVAL(vwv+11, 0, in_capabilities);

	if (in_apassword.length == 0 && in_upassword.length > 0) {
		/*
		 * This is plaintext auth with a unicode password,
		 * we need to align the buffer.
		 *
		 * This is what smbclient and Windows XP send as
		 * a client. And what smbd expects.
		 *
		 * But it doesn't follow [MS-CIFS] (v20160714)
		 * 2.2.4.53.1 SMB_COM_SESSION_SETUP_ANDX Request:
		 *
		 * ...
		 *
		 *  If SMB_FLAGS2_UNICODE is set (1), the value of OEMPasswordLen
		 *  MUST be 0x0000 and the password MUST be encoded using
		 *  UTF-16LE Unicode. Padding MUST NOT be added to
		 *  align this plaintext Unicode string to a word boundary.
		 *
		 * ...
		 */
		uint16_t security_mode = smb1cli_conn_server_security_mode(conn);

		if (!(security_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE)) {
			align_upassword = 1;
		}
	}

	bytes = talloc_array(state, uint8_t,
			     in_apassword.length +
			     align_upassword +
			     in_upassword.length);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	if (in_apassword.length != 0) {
		memcpy(bytes + apassword_ofs,
		       in_apassword.data,
		       in_apassword.length);
		upassword_ofs += in_apassword.length;
	}
	if (align_upassword != 0) {
		memset(bytes + upassword_ofs, 0, align_upassword);
		upassword_ofs += align_upassword;
	}
	if (in_upassword.length != 0) {
		memcpy(bytes + upassword_ofs,
		       in_upassword.data,
		       in_upassword.length);
	}

	bytes = smb_bytes_push_str(bytes,
				   smbXcli_conn_use_unicode(conn),
				   in_user, strlen(in_user)+1,
				   NULL);
	bytes = smb_bytes_push_str(bytes,
				   smbXcli_conn_use_unicode(conn),
				   in_domain, strlen(in_domain)+1,
				   NULL);
	if (in_native_os != NULL) {
		bytes = smb_bytes_push_str(bytes,
					   smbXcli_conn_use_unicode(conn),
					   in_native_os, strlen(in_native_os)+1,
					   NULL);
	}
	if (in_native_lm != NULL) {
		bytes = smb_bytes_push_str(bytes,
					   smbXcli_conn_use_unicode(conn),
					   in_native_lm, strlen(in_native_lm)+1,
					   NULL);
	}
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = smb1cli_req_send(state, ev, conn,
				  SMBsesssetupX,
				  0, /*  additional_flags */
				  0, /*  clear_flags */
				  0, /*  additional_flags2 */
				  0, /*  clear_flags2 */
				  timeout_msec,
				  pid,
				  NULL, /* tcon */
				  session,
				  13, /* wct */
				  vwv,
				  talloc_get_size(bytes),
				  bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb1cli_session_setup_nt1_done, req);

	return req;
}

static void smb1cli_session_setup_nt1_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb1cli_session_setup_nt1_state *state =
		tevent_req_data(req,
		struct smb1cli_session_setup_nt1_state);
	NTSTATUS status;
	uint8_t *inhdr = NULL;
	uint8_t wct;
	uint16_t *vwv = NULL;
	uint32_t num_bytes;
	uint8_t *bytes = NULL;
	const uint8_t *p = NULL;
	size_t ret = 0;
	uint16_t flags2;
	bool use_unicode = false;
	struct smb1cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.wct    = 3,
	},
	};

	status = smb1cli_req_recv(subreq, state,
				  &state->recv_iov,
				  &inhdr,
				  &wct,
				  &vwv,
				  NULL, /* pvwv_offset */
				  &num_bytes,
				  &bytes,
				  NULL, /* pbytes_offset */
				  &state->inbuf,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	flags2 = SVAL(inhdr, HDR_FLG2);
	if (flags2 & FLAGS2_UNICODE_STRINGS) {
		use_unicode = true;
	}

	state->out_session_id = SVAL(inhdr, HDR_UID);
	state->out_action = SVAL(vwv+2, 0);

	p = bytes;

	status = smb_bytes_pull_str(state, &state->out_native_os,
				    use_unicode, bytes, num_bytes,
				    p, &ret);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	p += ret;

	status = smb_bytes_pull_str(state, &state->out_native_lm,
				    use_unicode, bytes, num_bytes,
				    p, &ret);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	p += ret;

	status = smb_bytes_pull_str(state, &state->out_primary_domain,
				    use_unicode, bytes, num_bytes,
				    p, &ret);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	smb1cli_session_set_id(state->session, state->out_session_id);
	smb1cli_session_set_action(state->session, state->out_action);

	tevent_req_done(req);
}

NTSTATUS smb1cli_session_setup_nt1_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					struct iovec **precv_iov,
					const uint8_t **precv_inbuf,
					char **out_native_os,
					char **out_native_lm,
					char **out_primary_domain)
{
	struct smb1cli_session_setup_nt1_state *state =
		tevent_req_data(req,
		struct smb1cli_session_setup_nt1_state);
	NTSTATUS status;
	struct iovec *recv_iov = NULL;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	recv_iov = talloc_move(mem_ctx, &state->recv_iov);
	if (precv_iov != NULL) {
		*precv_iov = recv_iov;
	}
	if (precv_inbuf != NULL) {
		*precv_inbuf = state->inbuf;
	}

	if (out_native_os != NULL) {
		*out_native_os = talloc_move(mem_ctx, &state->out_native_os);
	}

	if (out_native_lm != NULL) {
		*out_native_lm = talloc_move(mem_ctx, &state->out_native_lm);
	}

	if (out_primary_domain != NULL) {
		*out_primary_domain = talloc_move(mem_ctx,
						  &state->out_primary_domain);
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct smb1cli_session_setup_ext_state {
	struct smbXcli_session *session;
	uint16_t vwv[12];
	struct iovec *recv_iov;
	uint8_t *inbuf;
	NTSTATUS status;
	uint16_t out_session_id;
	uint16_t out_action;
	DATA_BLOB out_security_blob;
	char *out_native_os;
	char *out_native_lm;
};

static void smb1cli_session_setup_ext_done(struct tevent_req *subreq);

struct tevent_req *smb1cli_session_setup_ext_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct smbXcli_conn *conn,
				uint32_t timeout_msec,
				uint32_t pid,
				struct smbXcli_session *session,
				uint16_t in_buf_size,
				uint16_t in_mpx_max,
				uint16_t in_vc_num,
				uint32_t in_sess_key,
				const DATA_BLOB in_security_blob,
				uint32_t in_capabilities,
				const char *in_native_os,
				const char *in_native_lm)
{
	struct tevent_req *req = NULL;
	struct smb1cli_session_setup_ext_state *state = NULL;
	struct tevent_req *subreq = NULL;
	uint16_t *vwv = NULL;
	uint8_t *bytes = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb1cli_session_setup_ext_state);
	if (req == NULL) {
		return NULL;
	}
	state->session = session;
	vwv = state->vwv;

	if (in_security_blob.length > UINT16_MAX) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (in_native_os == NULL && in_native_lm != NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	SCVAL(vwv+0,  0, 0xff);
	SCVAL(vwv+0,  1, 0);
	SSVAL(vwv+1,  0, 0);
	SSVAL(vwv+2,  0, in_buf_size);
	SSVAL(vwv+3,  0, in_mpx_max);
	SSVAL(vwv+4,  0, in_vc_num);
	SIVAL(vwv+5,  0, in_sess_key);
	SSVAL(vwv+7,  0, in_security_blob.length);
	SSVAL(vwv+8,  0, 0); /* reserved */
	SSVAL(vwv+9,  0, 0); /* reserved */
	SIVAL(vwv+10, 0, in_capabilities);

	bytes = talloc_array(state, uint8_t,
			     in_security_blob.length);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	if (in_security_blob.length != 0) {
		memcpy(bytes,
		       in_security_blob.data,
		       in_security_blob.length);
	}

	if (in_native_os != NULL) {
		bytes = smb_bytes_push_str(bytes,
					   smbXcli_conn_use_unicode(conn),
					   in_native_os, strlen(in_native_os)+1,
					   NULL);
	}
	if (in_native_lm != NULL) {
		bytes = smb_bytes_push_str(bytes,
					   smbXcli_conn_use_unicode(conn),
					   in_native_lm, strlen(in_native_lm)+1,
					   NULL);
	}
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = smb1cli_req_send(state, ev, conn,
				  SMBsesssetupX,
				  0, /*  additional_flags */
				  0, /*  clear_flags */
				  0, /*  additional_flags2 */
				  0, /*  clear_flags2 */
				  timeout_msec,
				  pid,
				  NULL, /* tcon */
				  session,
				  12, /* wct */
				  vwv,
				  talloc_get_size(bytes),
				  bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb1cli_session_setup_ext_done, req);

	return req;
}

static void smb1cli_session_setup_ext_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb1cli_session_setup_ext_state *state =
		tevent_req_data(req,
		struct smb1cli_session_setup_ext_state);
	NTSTATUS status;
	uint8_t *inhdr = NULL;
	uint8_t wct;
	uint16_t *vwv = NULL;
	uint32_t num_bytes;
	uint8_t *bytes = NULL;
	const uint8_t *p = NULL;
	size_t ret = 0;
	uint16_t flags2;
	uint16_t out_security_blob_length = 0;
	bool use_unicode = false;
	struct smb1cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.wct    = 4,
	},
	{
		.status = NT_STATUS_MORE_PROCESSING_REQUIRED,
		.wct    = 4,
	},
	};

	status = smb1cli_req_recv(subreq, state,
				  &state->recv_iov,
				  &inhdr,
				  &wct,
				  &vwv,
				  NULL, /* pvwv_offset */
				  &num_bytes,
				  &bytes,
				  NULL, /* pbytes_offset */
				  &state->inbuf,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	state->status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	flags2 = SVAL(inhdr, HDR_FLG2);
	if (flags2 & FLAGS2_UNICODE_STRINGS) {
		use_unicode = true;
	}

	state->out_session_id = SVAL(inhdr, HDR_UID);
	state->out_action = SVAL(vwv+2, 0);
	out_security_blob_length = SVAL(vwv+3, 0);

	if (out_security_blob_length > num_bytes) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	p = bytes;

	/*
	 * Note: this points into state->recv_iov!
	 */
	state->out_security_blob = data_blob_const(p, out_security_blob_length);
	p += out_security_blob_length;

	status = smb_bytes_pull_str(state, &state->out_native_os,
				    use_unicode, bytes, num_bytes,
				    p, &ret);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	p += ret;

	status = smb_bytes_pull_str(state, &state->out_native_lm,
				    use_unicode, bytes, num_bytes,
				    p, &ret);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	/* p += ret; */

	smb1cli_session_set_id(state->session, state->out_session_id);
	smb1cli_session_set_action(state->session, state->out_action);

	tevent_req_done(req);
}

NTSTATUS smb1cli_session_setup_ext_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					struct iovec **precv_iov,
					const uint8_t **precv_inbuf,
					DATA_BLOB *out_security_blob,
					char **out_native_os,
					char **out_native_lm)
{
	struct smb1cli_session_setup_ext_state *state =
		tevent_req_data(req,
		struct smb1cli_session_setup_ext_state);
	NTSTATUS status;
	struct iovec *recv_iov = NULL;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	recv_iov = talloc_move(mem_ctx, &state->recv_iov);
	if (precv_iov != NULL) {
		*precv_iov = recv_iov;
	}
	if (precv_inbuf != NULL) {
		*precv_inbuf = state->inbuf;
	}

	*out_security_blob = state->out_security_blob;

	if (out_native_os != NULL) {
		*out_native_os = talloc_move(mem_ctx, &state->out_native_os);
	}

	if (out_native_lm != NULL) {
		*out_native_lm = talloc_move(mem_ctx, &state->out_native_lm);
	}

	/*
	 * Return the status from the server:
	 * NT_STATUS_MORE_PROCESSING_REQUIRED or
	 * NT_STATUS_OK.
	 */
	status = state->status;
	tevent_req_received(req);
	return status;
}
