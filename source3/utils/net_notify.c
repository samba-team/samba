/*
 * Samba Unix/Linux notifyd client code
 * Copyright (C) 2015 Volker Lendecke <vl@samba.org>
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
#include "utils/net.h"
#include "lib/util/server_id.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/server_id_db.h"
#include "messages.h"
#include "source3/smbd/notifyd/notifyd.h"

static void net_notify_got_event(struct messaging_context *msg,
				 void *private_data,
				 uint32_t msg_type,
				 struct server_id server_id,
				 DATA_BLOB *data)
{
	struct notify_event_msg *event_msg;

	if (data->length < offsetof(struct notify_event_msg, path) + 1) {
		d_fprintf(stderr, "message too short\n");
		return;
	}
	if (data->data[data->length-1] != 0) {
		d_fprintf(stderr, "path not 0-terminated\n");
		return;
	}

	event_msg = (struct notify_event_msg *)data->data;

	d_printf("%u %s\n", (unsigned)event_msg->action,
		 event_msg->path);
}

static int net_notify_listen(struct net_context *c, int argc,
			     const char **argv)
{
	struct messaging_context *msg_ctx = c->msg_ctx;
	struct tevent_context *ev = messaging_tevent_context(msg_ctx);
	struct server_id_db *names_db = messaging_names_db(msg_ctx);
	struct server_id notifyd;
	struct server_id_buf idbuf;
	struct notify_rec_change_msg msg;
	struct iovec iov[2];
	NTSTATUS status;
	bool ok;

	if (argc != 3) {
		d_printf("Usage: net notify listen <path> <filter> "
			 "<subdir-filter>\n");
		return -1;
	}

	ok = server_id_db_lookup_one(names_db, "notify-daemon", &notifyd);
	if (!ok) {
		fprintf(stderr, "no notify daemon found\n");
		return -1;
	}

	printf("notify daemon: %s\n", server_id_str_buf(notifyd, &idbuf));

	msg = (struct notify_rec_change_msg) {
		.instance.filter = atoi(argv[1]),
		.instance.subdir_filter = atoi(argv[2])
	};
	iov[0] = (struct iovec) {
		.iov_base = &msg,
		.iov_len = offsetof(struct notify_rec_change_msg, path)
	};
	iov[1] = (struct iovec) {
		.iov_base = discard_const_p(char, argv[0]),
		.iov_len = strlen(argv[0])+1
	};

	status = messaging_register(c->msg_ctx, NULL, MSG_PVFS_NOTIFY,
				    net_notify_got_event);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "messaging_register failed: %s\n",
			  nt_errstr(status));
		return -1;
	}

	status = messaging_send_iov(
		c->msg_ctx, notifyd, MSG_SMB_NOTIFY_REC_CHANGE,
		iov, ARRAY_SIZE(iov), NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Sending rec_change to %s returned %s\n",
			  server_id_str_buf(notifyd, &idbuf),
			  nt_errstr(status));
		return -1;
	}

	while (true) {
		int ret;

		ret = tevent_loop_once(ev);
		if (ret != 0) {
			d_fprintf(stderr, "tevent_loop_once failed: %s\n",
				  strerror(errno));
			break;
		}
	}

	return 0;
}

static int net_notify_trigger(struct net_context *c, int argc,
			      const char **argv)
{
	struct messaging_context *msg_ctx = c->msg_ctx;
	struct server_id_db *names_db = messaging_names_db(msg_ctx);
	struct server_id notifyd;
	struct server_id_buf idbuf;
	struct notify_trigger_msg msg;
	struct iovec iov[2];
	NTSTATUS status;
	bool ok;

	if (argc != 3) {
		d_printf("Usage: net notify trigger <path> <action> "
			 "<filter>\n");
		return -1;
	}

	ok = server_id_db_lookup_one(names_db, "notify-daemon", &notifyd);
	if (!ok) {
		fprintf(stderr, "no notify daemon found\n");
		return -1;
	}

	printf("notify daemon: %s\n", server_id_str_buf(notifyd, &idbuf));

	msg = (struct notify_trigger_msg) {
		.action = atoi(argv[1]), .filter = atoi(argv[2])
	};

	iov[0] = (struct iovec) {
		.iov_base = &msg,
		.iov_len = offsetof(struct notify_trigger_msg, path)
	};
	iov[1] = (struct iovec) {
		.iov_base = discard_const_p(char, argv[0]),
		.iov_len = strlen(argv[0])+1
	};

	status = messaging_send_iov(
		c->msg_ctx, notifyd, MSG_SMB_NOTIFY_TRIGGER,
		iov, ARRAY_SIZE(iov), NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Sending rec_change to %s returned %s\n",
			 server_id_str_buf(notifyd, &idbuf),
			 nt_errstr(status));
		return -1;
	}

	return 0;
}

int net_notify(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{ "listen",
		  net_notify_listen,
		  NET_TRANSPORT_LOCAL,
		  N_("Register for a path and listen for changes"),
		  N_("net notify listen <path>")
		},
		{ "trigger",
		  net_notify_trigger,
		  NET_TRANSPORT_LOCAL,
		  N_("Simulate a trigger action"),
		  N_("net notify trigger <path> <action> <filter>")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	if (c->msg_ctx == NULL) {
		d_fprintf(stderr, "No connection to messaging, need to run "
			  "as root\n");
		return -1;
	}

	return net_run_function(c, argc, argv, "net notify", func);
}
