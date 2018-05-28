/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 leases

   Copyright (C) Zachary Loafman 2009

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
#include <tevent.h>
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "torture/util.h"
#include "libcli/smb/smbXcli_base.h"
#include "lease_break_handler.h"

struct lease_break_info lease_break_info;

void torture_lease_break_callback(struct smb2_request *req)
{
	NTSTATUS status;

	status = smb2_lease_break_ack_recv(req, &lease_break_info.lease_break_ack);
	if (!NT_STATUS_IS_OK(status))
		lease_break_info.failures++;

	return;
}

/* a lease break request handler */
bool torture_lease_handler(struct smb2_transport *transport,
			   const struct smb2_lease_break *lb,
			   void *private_data)
{
	struct smb2_tree *tree = private_data;
	struct smb2_lease_break_ack io;
	struct smb2_request *req;

	lease_break_info.lease_transport = transport;
	lease_break_info.lease_break = *lb;
	lease_break_info.count++;

	if (lease_break_info.lease_skip_ack) {
		return true;
	}

	if (lb->break_flags & SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED) {
		ZERO_STRUCT(io);
		io.in.lease.lease_key = lb->current_lease.lease_key;
		io.in.lease.lease_state = lb->new_lease_state;

		req = smb2_lease_break_ack_send(tree, &io);
		req->async.fn = torture_lease_break_callback;
		req->async.private_data = NULL;
	}

	return true;
}

/*
 * A lease break handler which ignores incoming lease break requests
 * To be used in cases where the client is expected to ignore incoming
 * lease break requests
 */
bool torture_lease_ignore_handler(struct smb2_transport *transport,
			   const struct smb2_lease_break *lb,
			   void *private_data)
{
	return true;
}

/*
   Timer handler function notifies the registering function that time is up
*/
static void timeout_cb(struct tevent_context *ev,
		       struct tevent_timer *te,
		       struct timeval current_time,
		       void *private_data)
{
	bool *timesup = (bool *)private_data;
	*timesup = true;
	return;
}

/*
   Wait a short period of time to receive a single oplock break request
*/
void torture_wait_for_lease_break(struct torture_context *tctx)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	struct tevent_timer *te = NULL;
	struct timeval ne;
	bool timesup = false;
	int old_count = lease_break_info.count;

	/* Wait 1 second for an lease break */
	ne = tevent_timeval_current_ofs(0, 1000000);

	te = tevent_add_timer(tctx->ev, tmp_ctx, ne, timeout_cb, &timesup);
	if (te == NULL) {
		torture_comment(tctx, "Failed to wait for an oplock break. "
				      "test results may not be accurate.");
		goto done;
	}

	while (!timesup && lease_break_info.count < old_count + 1) {
		if (tevent_loop_once(tctx->ev) != 0) {
			torture_comment(tctx, "Failed to wait for an oplock "
					      "break. test results may not be "
					      "accurate.");
			goto done;
		}
	}

done:
	/* We don't know if the timed event fired and was freed, we received
	 * our oplock break, or some other event triggered the loop.  Thus,
	 * we create a tmp_ctx to be able to safely free/remove the timed
	 * event in all 3 cases. */
	talloc_free(tmp_ctx);

	return;
}
