/*
 * Unix SMB/CIFS implementation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "system/network.h"
#include "lib/util/tevent_ntstatus.h"
#include "smb_common.h"
#include "smbXcli_base.h"
#include "lib/util/bytearray.h"

static uint8_t *smb1cli_lockingx_put_locks(
	uint8_t *buf,
	bool large,
	uint16_t num_locks,
	const struct smb1_lock_element *locks)
{
	uint16_t i;

	for (i = 0; i < num_locks; i++) {
		const struct smb1_lock_element *e = &locks[i];
		if (large) {
			/*
			 * [MS-CIFS] 2.2.4.26.1
			 * LOCKING_ANDX_RANGE64: High 32 bits first
			 */
			PUSH_LE_U16(buf, 0, e->pid);
			PUSH_LE_U16(buf, 2, 0);
			PUSH_LE_U32(buf, 4, e->offset >> 32);
			PUSH_LE_U32(buf, 8, e->offset & 0xFFFFFFFF);
			PUSH_LE_U32(buf, 12, e->length >> 32);
			PUSH_LE_U32(buf, 16, e->length & 0xFFFFFFFF);
			buf += 20;
		} else {
			PUSH_LE_U16(buf, 0, e->pid);
			PUSH_LE_U32(buf, 2, e->offset);
			PUSH_LE_U32(buf, 6, e->length);
			buf += 10;
		}
	}
	return buf;
}

struct smb1cli_lockingx_state {
	uint16_t vwv[8];
	struct iovec bytes;
	struct tevent_req *subreq;
};

static void smb1cli_lockingx_done(struct tevent_req *subreq);
static bool smb1cli_lockingx_cancel(struct tevent_req *req);

/*
 * Create an SMB1 LockingX request without sending it. *psmbreq is the
 * request to pass to smb1cli_req_chain_submit(), possibly chained with
 * other requests.
 */
struct tevent_req *smb1cli_lockingx_create(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct smbXcli_conn *conn,
	uint32_t timeout_msec,
	uint32_t pid,
	struct smbXcli_tcon *tcon,
	struct smbXcli_session *session,
	uint16_t fnum,
	uint8_t typeoflock,
	uint8_t newoplocklevel,
	int32_t timeout,
	uint16_t num_unlocks,
	const struct smb1_lock_element *unlocks,
	uint16_t num_locks,
	const struct smb1_lock_element *locks,
	struct tevent_req **psmbreq)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct smb1cli_lockingx_state *state = NULL;
	uint16_t *vwv = NULL;
	uint8_t *p = NULL;
	const bool large = (typeoflock & LOCKING_ANDX_LARGE_FILES);
	const size_t element_len = large ? 20 : 10;

	/*
	 * uint16_t -> size_t, no overflow
	 */
	const size_t num_elements = (size_t)num_locks + (size_t)num_unlocks;

	/*
	 * at most 20*2*65535 = 2621400, no overflow
	 */
	const size_t num_bytes = num_elements * element_len;

	req = tevent_req_create(mem_ctx,
				&state,
				struct smb1cli_lockingx_state);
	if (req == NULL) {
		return NULL;
	}
	vwv = state->vwv;

	PUSH_LE_U8(vwv, 0, 0xFF); /* AndXCommand */
	PUSH_LE_U8(vwv, 1, 0);	  /* AndXReserved */
	PUSH_LE_U16(vwv, 2, 0);	  /* AndXOffset */
	PUSH_LE_U16(vwv, 4, fnum);
	PUSH_LE_U8(vwv, 6, typeoflock);
	PUSH_LE_U8(vwv, 7, newoplocklevel);
	PUSH_LE_I32(vwv, 8, timeout);
	PUSH_LE_U16(vwv, 12, num_unlocks);
	PUSH_LE_U16(vwv, 14, num_locks);

	state->bytes.iov_len = num_bytes;
	state->bytes.iov_base = talloc_array(state, uint8_t, num_bytes);
	if (tevent_req_nomem(state->bytes.iov_base, req)) {
		return tevent_req_post(req, ev);
	}

	p = smb1cli_lockingx_put_locks(state->bytes.iov_base,
				       large,
				       num_unlocks,
				       unlocks);
	smb1cli_lockingx_put_locks(p, large, num_locks, locks);

	subreq = smb1cli_req_create(state,
				    ev,
				    conn,
				    SMBlockingX,
				    0,
				    0, /* *_flags */
				    0,
				    0, /* *_flags2 */
				    timeout_msec,
				    pid,
				    tcon,
				    session,
				    ARRAY_SIZE(state->vwv),
				    state->vwv,
				    1,
				    &state->bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb1cli_lockingx_done, req);
	state->subreq = subreq;
	tevent_req_set_cancel_fn(req, smb1cli_lockingx_cancel);

	*psmbreq = subreq;
	return req;
}

struct tevent_req *smb1cli_lockingx_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct smbXcli_conn *conn,
	uint32_t timeout_msec,
	uint32_t pid,
	struct smbXcli_tcon *tcon,
	struct smbXcli_session *session,
	uint16_t fnum,
	uint8_t typeoflock,
	uint8_t newoplocklevel,
	int32_t timeout,
	uint16_t num_unlocks,
	const struct smb1_lock_element *unlocks,
	uint16_t num_locks,
	const struct smb1_lock_element *locks)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	NTSTATUS status;

	req = smb1cli_lockingx_create(mem_ctx,
				      ev,
				      conn,
				      timeout_msec,
				      pid,
				      tcon,
				      session,
				      fnum,
				      typeoflock,
				      newoplocklevel,
				      timeout,
				      num_unlocks,
				      unlocks,
				      num_locks,
				      locks,
				      &subreq);
	if (req == NULL) {
		return NULL;
	}
	if (!tevent_req_is_in_progress(req)) {
		return req;
	}

	status = smb1cli_req_chain_submit(&subreq, 1);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void smb1cli_lockingx_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct smb1cli_lockingx_state *state = tevent_req_data(
		req, struct smb1cli_lockingx_state);
	NTSTATUS status;
	static const struct smb1cli_req_expected_response expected[] = {
		{
			/*
			 * An oplock release is one-way, there is no
			 * response with the 2 words of a reply
			 */
			.status = NT_STATUS_OK,
			.wct = 0,
		},
	};

	status = smb1cli_req_recv(subreq,
				  state,
				  NULL, /* recv_iov */
				  NULL, /* phdr */
				  NULL, /* wct */
				  NULL, /* vwv */
				  NULL, /* pvwv_offset */
				  NULL, /* num_bytes */
				  NULL, /* bytes */
				  NULL, /* pbytes_offset */
				  NULL, /* inbuf */
				  expected,
				  ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	state->subreq = NULL;
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static bool smb1cli_lockingx_cancel(struct tevent_req *req)
{
	struct smb1cli_lockingx_state *state = tevent_req_data(
		req, struct smb1cli_lockingx_state);

	if (state->subreq == NULL) {
		return false;
	}
	return tevent_req_cancel(state->subreq);
}

NTSTATUS smb1cli_lockingx_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb1cli_lockingx(struct smbXcli_conn *conn,
			  uint32_t timeout_msec,
			  uint32_t pid,
			  struct smbXcli_tcon *tcon,
			  struct smbXcli_session *session,
			  uint16_t fnum,
			  uint8_t typeoflock,
			  uint8_t newoplocklevel,
			  int32_t timeout,
			  uint16_t num_unlocks,
			  const struct smb1_lock_element *unlocks,
			  uint16_t num_locks,
			  const struct smb1_lock_element *locks)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	bool ok;

	if (smbXcli_conn_has_async_calls(conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb1cli_lockingx_send(frame,
				    ev,
				    conn,
				    timeout_msec,
				    pid,
				    tcon,
				    session,
				    fnum,
				    typeoflock,
				    newoplocklevel,
				    timeout,
				    num_unlocks,
				    unlocks,
				    num_locks,
				    locks);
	if (req == NULL) {
		goto fail;
	}
	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		goto fail;
	}
	status = smb1cli_lockingx_recv(req);
fail:
	TALLOC_FREE(frame);
	return status;
}
