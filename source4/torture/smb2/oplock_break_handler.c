/*
 * Unix SMB/CIFS implementation.
 *
 * test suite for SMB2 replay
 *
 * Copyright (C) Anubhav Rakshit 2014
 * Copyright (C) Stefan Metzmacher 2014
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "../libcli/smb/smbXcli_base.h"
#include "oplock_break_handler.h"
#include "lib/events/events.h"

struct break_info break_info;

static void torture_oplock_ack_callback(struct smb2_request *req)
{
	NTSTATUS status;

	status = smb2_break_recv(req, &break_info.br);
	if (!NT_STATUS_IS_OK(status)) {
		break_info.failures++;
		break_info.failure_status = status;
	}
}

/**
 * A general oplock break notification handler.  This should be used when a
 * test expects to break from batch or exclusive to a lower level.
 */

bool torture_oplock_ack_handler(struct smb2_transport *transport,
				const struct smb2_handle *handle,
				uint8_t level,
				void *private_data)
{
	struct smb2_tree *tree = private_data;
	const char *name;
	struct smb2_request *req;

	ZERO_STRUCT(break_info.br);

	break_info.handle	= *handle;
	break_info.level	= level;
	break_info.count++;

	switch (level) {
	case SMB2_OPLOCK_LEVEL_II:
		name = "level II";
		break;
	case SMB2_OPLOCK_LEVEL_NONE:
		name = "none";
		break;
	default:
		name = "unknown";
		break_info.failures++;
	}
	torture_comment(break_info.tctx,
			"transport[%p] Acking to %s [0x%02X] in oplock handler\n",
			transport, name, level);

	break_info.br.in.file.handle	= *handle;
	break_info.br.in.oplock_level	= level;
	break_info.br.in.reserved	= 0;
	break_info.br.in.reserved2	= 0;
	break_info.received_transport = tree->session->transport;
	SMB_ASSERT(tree->session->transport == transport);

	if (break_info.oplock_skip_ack) {
		return true;
	}

	req = smb2_break_send(tree, &break_info.br);
	req->async.fn = torture_oplock_ack_callback;
	req->async.private_data = NULL;

	return true;
}

/**
 * A oplock break handler designed to ignore incoming break requests.
 * This is used when incoming oplock break requests need to be ignored
 */
bool torture_oplock_ignore_handler(struct smb2_transport *transport,
				   const struct smb2_handle *handle,
				   uint8_t level, void *private_data)
{
	return true;
}

/*
 * Timer handler function notifies the registering function that time is up
 */
static void timeout_cb(struct tevent_context *ev,
		       struct tevent_timer *te,
		       struct timeval current_time,
		       void *private_data)
{
	bool *timesup = (bool *)private_data;
	*timesup = true;
}

/*
 * Wait a short period of time to receive a single oplock break request
 */
void torture_wait_for_oplock_break(struct torture_context *tctx)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	struct tevent_timer *te = NULL;
	struct timeval ne;
	bool timesup = false;
	int old_count = break_info.count;

	/* Wait 1 second for an oplock break */
	ne = tevent_timeval_current_ofs(0, 1000000);

	te = tevent_add_timer(tctx->ev, tmp_ctx, ne, timeout_cb, &timesup);
	if (te == NULL) {
		torture_comment(tctx, "Failed to wait for an oplock break. "
				      "test results may not be accurate.");
		goto done;
	}

	while (!timesup && break_info.count < old_count + 1) {
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
	 * event in all 3 cases.
	 */
	talloc_free(tmp_ctx);
}
