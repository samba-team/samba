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

#define SMB2_LOCK_ELEMENT_SIZE 24

struct smb2cli_lock_state {
	uint8_t fixed[48];
};

static void smb2cli_lock_put_element(uint8_t *p,
				     const struct smb2_lock_element *lock)
{
	PUSH_LE_U64(p, 0, lock->offset);
	PUSH_LE_U64(p, 8, lock->length);
	PUSH_LE_U32(p, 16, lock->flags);
	PUSH_LE_U32(p, 20, 0); /* reserved */
}

static void smb2cli_lock_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_lock_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct smbXcli_conn *conn,
				     uint32_t timeout_msec,
				     struct smbXcli_session *session,
				     struct smbXcli_tcon *tcon,
				     uint64_t fid_persistent,
				     uint64_t fid_volatile,
				     uint32_t lock_sequence,
				     uint16_t num_locks,
				     const struct smb2_lock_element *locks)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct smb2cli_lock_state *state = NULL;
	uint8_t *fixed = NULL;
	uint8_t *dyn = NULL;
	size_t dyn_len = 0;
	uint16_t i;

	req = tevent_req_create(mem_ctx, &state, struct smb2cli_lock_state);
	if (req == NULL) {
		return NULL;
	}

	if (num_locks == 0) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	fixed = state->fixed;
	PUSH_LE_U16(fixed, 0, 48);
	PUSH_LE_U16(fixed, 2, num_locks);
	PUSH_LE_U32(fixed, 4, lock_sequence);
	PUSH_LE_U64(fixed, 8, fid_persistent);
	PUSH_LE_U64(fixed, 16, fid_volatile);

	/*
	 * The first lock element is part of the fixed body, the
	 * others follow as the dynamic part
	 */
	smb2cli_lock_put_element(fixed + 24, &locks[0]);

	if (num_locks > 1) {
		dyn_len = (num_locks - 1) * SMB2_LOCK_ELEMENT_SIZE;
		dyn = talloc_array(state, uint8_t, dyn_len);
		if (tevent_req_nomem(dyn, req)) {
			return tevent_req_post(req, ev);
		}
		for (i = 1; i < num_locks; i++) {
			smb2cli_lock_put_element(
				dyn + (i - 1) * SMB2_LOCK_ELEMENT_SIZE,
				&locks[i]);
		}
	}

	subreq = smb2cli_req_send(state,
				  ev,
				  conn,
				  SMB2_OP_LOCK,
				  0,
				  0, /* flags */
				  timeout_msec,
				  tcon,
				  session,
				  state->fixed,
				  sizeof(state->fixed),
				  dyn,
				  dyn_len,
				  0); /* max_dyn_len */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_lock_done, req);
	return req;
}

static void smb2cli_lock_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	NTSTATUS status;
	static const struct smb2cli_req_expected_response expected[] = {
		{
			.status = NT_STATUS_OK,
			.body_size = 0x04,
		},
	};

	status = smb2cli_req_recv(
		subreq, NULL, NULL, expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS smb2cli_lock_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb2cli_lock(struct smbXcli_conn *conn,
		      uint32_t timeout_msec,
		      struct smbXcli_session *session,
		      struct smbXcli_tcon *tcon,
		      uint64_t fid_persistent,
		      uint64_t fid_volatile,
		      uint32_t lock_sequence,
		      uint16_t num_locks,
		      const struct smb2_lock_element *locks)
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
	req = smb2cli_lock_send(frame,
				ev,
				conn,
				timeout_msec,
				session,
				tcon,
				fid_persistent,
				fid_volatile,
				lock_sequence,
				num_locks,
				locks);
	if (req == NULL) {
		goto fail;
	}
	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		goto fail;
	}
	status = smb2cli_lock_recv(req);
fail:
	TALLOC_FREE(frame);
	return status;
}
