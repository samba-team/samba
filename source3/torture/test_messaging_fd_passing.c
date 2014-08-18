/*
   Unix SMB/CIFS implementation.
   Test for fd passing with messaging

   Copyright (C) Michael Adam 2014

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
#include "torture/proto.h"
#include "lib/util/tevent_unix.h"
#include "messages.h"

/**
 * test fdpass1:
 *
 * Try to pass an fd to the sending process - fails.
 */
bool run_messaging_fdpass1(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	bool retval = false;
	int pipe_fds[2];
	int pass_fds[1] = { 0 };
	int ret;
	NTSTATUS status;
	struct server_id dst;
	TALLOC_CTX *frame = talloc_stackframe();

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		goto fail;
	}
	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		goto fail;
	}

	dst = messaging_server_id(msg_ctx);

	ret = pipe(pipe_fds);
	if (ret != 0) {
		perror("pipe failed");
		goto fail;
	}

	pass_fds[0] = pipe_fds[0];

	status = messaging_send_iov(msg_ctx, dst, MSG_PING, NULL, 0,
				    pass_fds, 1);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
		fprintf(stderr,
			"messaging_send_iov gave: %s\n", nt_errstr(status));
		goto fail;
	}

	retval = true;

fail:
	TALLOC_FREE(frame);
	return retval;
}
