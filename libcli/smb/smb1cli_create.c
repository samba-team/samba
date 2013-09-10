/*
   Unix SMB/CIFS implementation.

   Copyright (C) Gregor Beck 2013
   Copyright (C) Stefan Metzmacher 2013

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
#include "lib/util/tevent_ntstatus.h"
#include "smb_common.h"
#include "smbXcli_base.h"

static uint8_t *internal_bytes_push_str(uint8_t *buf, bool ucs2,
					const char *str, size_t str_len,
					bool align_odd,
					size_t *pconverted_size)
{
	TALLOC_CTX *frame = talloc_stackframe();
	size_t buflen;
	char *converted;
	size_t converted_size;

	/*
	 * This check prevents us from
	 * (re)alloc buf on a NULL TALLOC_CTX.
	 */
	if (buf == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	buflen = talloc_get_size(buf);

	if (ucs2 &&
	    ((align_odd && (buflen % 2 == 0)) ||
	     (!align_odd && (buflen % 2 == 1)))) {
		/*
		 * We're pushing into an SMB buffer, align odd
		 */
		buf = talloc_realloc(NULL, buf, uint8_t, buflen + 1);
		if (buf == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
		buf[buflen] = '\0';
		buflen += 1;
	}

	if (!convert_string_talloc(frame, CH_UNIX,
				   ucs2 ? CH_UTF16LE : CH_DOS,
				   str, str_len, &converted,
				   &converted_size)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	buf = talloc_realloc(NULL, buf, uint8_t,
			     buflen + converted_size);
	if (buf == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	memcpy(buf + buflen, converted, converted_size);

	TALLOC_FREE(converted);

	if (pconverted_size) {
		*pconverted_size = converted_size;
	}

	TALLOC_FREE(frame);
	return buf;
}

static uint8_t *smb_bytes_push_str(uint8_t *buf, bool ucs2,
				   const char *str, size_t str_len,
				   size_t *pconverted_size)
{
	return internal_bytes_push_str(buf, ucs2, str, str_len,
				       true, pconverted_size);
}

struct smb1cli_ntcreatex_state {
	uint16_t vwv[24];
	uint16_t fnum;
};

static void smb1cli_ntcreatex_done(struct tevent_req *subreq);

/**
 * Send an asynchronous SMB_COM_NT_CREATE_ANDX request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee442175.aspx">MS-CIFS 2.2.4.64.1</a>
 * @see smb1cli_ntcreatex_recv(), smb1cli_ntcreatex()
 *
 * @param[in] mem_ctx The memory context for the result.
 * @param[in] ev The event context to work on.
 * @param[in] conn The smb connection.
 * @param[in] timeout_msec If positiv a timeout for the request.
 * @param[in] pid The process identifier
 * @param[in] tcon The smb tree connect.
 * @param[in] session The smb session.
 * @param[in] fname The name of the file or directory to be opened or created.
 * @param[in] CreatFlags
 * @param[in] RootDirectoryFid The file id of an opened root directory fname is based on. 0 means root of the share.
 * @param[in] DesiredAccess A field of flags that indicate standard, specific, and generic access rights to be requested.
 * @param[in] AllocationSize Number of Bytes to allocate if the file is to be created or overwritten.
 * @param[in] FileAttributes <a href="http://msdn.microsoft.com/en-us/library/ee878573.aspx">Extended file attributes</a>
 * @param[in] ShareAccess A field that specifies how the file should be shared with other processes.
 * @param[in] CreateDisposition A value that represents the action to take if the file already exists or if the file is a new file and does not already exist.
 * @param[in] CreateOptions  A field of flag options to use if creating a file or directory.
 * @param[in] ImpersonationLevel
 * @param[in] SecurityFlags
 *
 * @return a tevent_req or NULL
 */
struct tevent_req *smb1cli_ntcreatex_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct smbXcli_conn *conn,
					  uint32_t timeout_msec,
					  uint32_t pid,
					  struct smbXcli_tcon *tcon,
					  struct smbXcli_session *session,
					  const char *fname,
					  uint32_t CreatFlags,
					  uint32_t RootDirectoryFid,
					  uint32_t DesiredAccess,
					  uint64_t AllocationSize,
					  uint32_t FileAttributes,
					  uint32_t ShareAccess,
					  uint32_t CreateDisposition,
					  uint32_t CreateOptions,
					  uint32_t ImpersonationLevel,
					  uint8_t SecurityFlags)
{
	struct tevent_req *req, *subreq;
	struct smb1cli_ntcreatex_state *state;
	uint8_t *bytes;
	size_t converted_len;

	req = tevent_req_create(mem_ctx, &state, struct smb1cli_ntcreatex_state);
	if (req == NULL) {
		return NULL;
	}

	SCVAL(state->vwv+0, 0, 0xFF);
	SCVAL(state->vwv+0, 1, 0);
	SSVAL(state->vwv+1, 0, 0);
	SCVAL(state->vwv+2, 0, 0);
	SIVAL(state->vwv+3, 1, CreatFlags);
	SIVAL(state->vwv+5, 1, RootDirectoryFid);
	SIVAL(state->vwv+7, 1, DesiredAccess);
	SBVAL(state->vwv+9, 1, AllocationSize);
	SIVAL(state->vwv+13, 1, FileAttributes);
	SIVAL(state->vwv+15, 1, ShareAccess);
	SIVAL(state->vwv+17, 1, CreateDisposition);
	SIVAL(state->vwv+19, 1, CreateOptions);
	SIVAL(state->vwv+21, 1, ImpersonationLevel);
	SCVAL(state->vwv+23, 1, SecurityFlags);

	bytes = talloc_array(state, uint8_t, 0);
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(conn),
				   fname, strlen(fname)+1,
				   &converted_len);

	/* sigh. this copes with broken netapp filer behaviour */
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(conn), "", 1, NULL);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	SSVAL(state->vwv+2, 1, converted_len);

	subreq = smb1cli_req_send(state, ev, conn, SMBntcreateX,
				  0, 0, /* *_flags */
				  0, 0, /* *_flags2 */
				  timeout_msec, pid, tcon, session,
				  ARRAY_SIZE(state->vwv), state->vwv,
				  talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb1cli_ntcreatex_done, req);

	return req;
}

static void smb1cli_ntcreatex_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb1cli_ntcreatex_state *state = tevent_req_data(
		req, struct smb1cli_ntcreatex_state);
	struct iovec *recv_iov = NULL;
	uint8_t wct;
	uint16_t *vwv;
	NTSTATUS status;
	static const struct smb1cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.wct = 0x22
	},
	{
		/*
		 * This is the broken version see from
		 * [MS-SMB]:
		 * Windows-based SMB servers send 50 (0x32) words in the extended
		 * response although they set the WordCount field to 0x2A.
		 *
		 * And Samba does the same...
		 */
		.status = NT_STATUS_OK,
		.wct = 0x2a
	},
	{
		.status = NT_STATUS_OK,
		.wct = 0x32
	},
	};

	status = smb1cli_req_recv(subreq, state,
				  &recv_iov,
				  NULL, /* phdr */
				  &wct,
				  &vwv,
				  NULL, /* pvwv_offset */
				  NULL, /* num_bytes */
				  NULL, /* bytes */
				  NULL, /* pbytes_offset */
				  NULL, /* inbuf */
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->fnum = SVAL(vwv+2, 1);
	tevent_req_done(req);
}

/**
 * Receive the response to an asynchronous SMB_COM_NT_CREATE_ANDX request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee441612.aspx">MS-CIFS 2.2.4.64.2</a>
 *
 * @param[in] req A tevent request created with smb1cli_ntcreatex_send()
 * @param[out] pfnum The file id of the opened file or directory.
 *
 * @return NT_STATUS_OK on succsess
 */
NTSTATUS smb1cli_ntcreatex_recv(struct tevent_req *req, uint16_t *pfnum)
{
	struct smb1cli_ntcreatex_state *state = tevent_req_data(
		req, struct smb1cli_ntcreatex_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*pfnum = state->fnum;
	tevent_req_received(req);
	return NT_STATUS_OK;
}


/**
 * Send a synchronous SMB_COM_NT_CREATE_ANDX request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee442091.aspx">MS-CIFS 2.2.4.64</a>
 * @see smb1cli_ntcreatex_send() smb1cli_ntcreatex_recv()
 *
 * @param[in] conn The smb connection.
 * @param[in] timeout_msec If positiv a timeout for the request.
 * @param[in] pid The process identifier
 * @param[in] tcon The smb tree connect.
 * @param[in] session The smb session.
 * @param[in] fname The name of the file or directory to be opened or created.
 * @param[in] CreatFlags
 * @param[in] RootDirectoryFid The file id of an opened root directory fname is based on. 0 means root of the share.
 * @param[in] DesiredAccess A field of flags that indicate standard, specific, and generic access rights to be requested.
 * @param[in] AllocationSize Number of Bytes to allocate if the file is to be created or overwritten.
 * @param[in] FileAttributes <a href="http://msdn.microsoft.com/en-us/library/ee878573.aspx">Extended file attributes</a>
 * @param[in] ShareAccess A field that specifies how the file should be shared with other processes.
 * @param[in] CreateDisposition A value that represents the action to take if the file already exists or if the file is a new file and does not already exist.
 * @param[in] CreateOptions  A field of flag options to use if creating a file or directory.
 * @param[in] ImpersonationLevel
 * @param[in] SecurityFlags
 * @param[out] pfnum The file id representing the file or directory created or opened.
 *
 * @return  NT_STATUS_OK on succsess
 */
NTSTATUS smb1cli_ntcreatex(struct smbXcli_conn *conn,
			   uint32_t timeout_msec,
			   uint32_t pid,
			   struct smbXcli_tcon *tcon,
			   struct smbXcli_session *session,
			   const char *fname,
			   uint32_t CreatFlags,
			   uint32_t RootDirectoryFid,
			   uint32_t DesiredAccess,
			   uint64_t AllocationSize,
			   uint32_t FileAttributes,
			   uint32_t ShareAccess,
			   uint32_t CreateDisposition,
			   uint32_t CreateOptions,
			   uint32_t ImpersonationLevel,
			   uint8_t SecurityFlags,
			   uint16_t *pfnum)
{
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = smb1cli_ntcreatex_send(frame, ev, conn,
				     timeout_msec,
				     pid, tcon, session,
				     fname, CreatFlags, RootDirectoryFid,
				     DesiredAccess, AllocationSize,
				     FileAttributes, ShareAccess,
				     CreateDisposition, CreateOptions,
				     ImpersonationLevel, SecurityFlags);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = smb1cli_ntcreatex_recv(req, pfnum);
fail:
	TALLOC_FREE(frame);
	return status;
}
