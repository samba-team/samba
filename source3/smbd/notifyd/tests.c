/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Volker Lendecke 2014
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

#include "replace.h"
#include "notifyd.h"
#include "messages.h"
#include "lib/util/server_id_db.h"

int main(int argc, const char *argv[])
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	struct server_id_db *names;
	struct server_id notifyd;
	struct tevent_req *req;
	unsigned i;
	bool ok;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <smb.conf-file>\n", argv[0]);
		exit(1);
	}

	setup_logging(argv[0], DEBUG_STDOUT);
	lp_load_global(argv[1]);

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		exit(1);
	}

	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		exit(1);
	}

	names = messaging_names_db(msg_ctx);

	ok = server_id_db_lookup_one(names, "notify-daemon", &notifyd);
	if (!ok) {
		fprintf(stderr, "no notifyd\n");
		exit(1);
	}

	for (i=0; i<50000; i++) {
		struct notify_rec_change_msg msg = {
			.instance.filter = UINT32_MAX,
			.instance.subdir_filter = UINT32_MAX
		};
		char path[64];
		size_t len;
		struct iovec iov[2];
		NTSTATUS status;

		len = snprintf(path, sizeof(path), "/tmp%u", i);

		iov[0].iov_base = &msg;
		iov[0].iov_len = offsetof(struct notify_rec_change_msg, path);
		iov[1].iov_base = path;
		iov[1].iov_len = len+1;

		status = messaging_send_iov(
			msg_ctx, notifyd, MSG_SMB_NOTIFY_REC_CHANGE,
			iov, ARRAY_SIZE(iov), NULL, 0);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "messaging_send_iov returned %s\n",
				nt_errstr(status));
			exit(1);
		}

		msg.instance.filter = 0;
		msg.instance.subdir_filter = 0;

		status = messaging_send_iov(
			msg_ctx, notifyd, MSG_SMB_NOTIFY_REC_CHANGE,
			iov, ARRAY_SIZE(iov), NULL, 0);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "messaging_send_iov returned %s\n",
				nt_errstr(status));
			exit(1);
		}
	}

	req = messaging_read_send(ev, ev, msg_ctx, MSG_PONG);
	if (req == NULL) {
		fprintf(stderr, "messaging_read_send failed\n");
		exit(1);
	}
	messaging_send_buf(msg_ctx, notifyd, MSG_PING, NULL, 0);

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		fprintf(stderr, "tevent_req_poll failed\n");
		exit(1);
	}

	TALLOC_FREE(frame);
	return 0;
}
