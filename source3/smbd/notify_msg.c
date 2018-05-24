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

#include "includes.h"
#include "librpc/gen_ndr/notify.h"
#include "librpc/gen_ndr/messaging.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "lib/util/server_id.h"
#include "messages.h"
#include "proto.h"
#include "globals.h"
#include "tdb.h"
#include "util_tdb.h"
#include "lib/util/server_id_db.h"
#include "smbd/notifyd/notifyd.h"

struct notify_context {
	struct server_id notifyd;
	struct messaging_context *msg_ctx;

	struct smbd_server_connection *sconn;
	void (*callback)(struct smbd_server_connection *sconn,
			 void *private_data, struct timespec when,
			 const struct notify_event *ctx);
};

static void notify_handler(struct messaging_context *msg, void *private_data,
			   uint32_t msg_type, struct server_id src,
			   DATA_BLOB *data);
static int notify_context_destructor(struct notify_context *ctx);

struct notify_context *notify_init(
	TALLOC_CTX *mem_ctx, struct messaging_context *msg,
	struct smbd_server_connection *sconn,
	void (*callback)(struct smbd_server_connection *sconn,
			 void *, struct timespec,
			 const struct notify_event *))
{
	struct server_id_db *names_db;
	struct notify_context *ctx;
	NTSTATUS status;

	ctx = talloc(mem_ctx, struct notify_context);
	if (ctx == NULL) {
		return NULL;
	}
	ctx->msg_ctx = msg;

	ctx->sconn = sconn;
	ctx->callback = callback;

	names_db = messaging_names_db(msg);
	if (!server_id_db_lookup_one(names_db, "notify-daemon",
				     &ctx->notifyd)) {
		DEBUG(1, ("No notify daemon around\n"));
		TALLOC_FREE(ctx);
		return NULL;
	}

	{
		struct server_id_buf tmp;
		DBG_DEBUG("notifyd=%s\n",
			  server_id_str_buf(ctx->notifyd, &tmp));
	}

	if (callback != NULL) {
		status = messaging_register(msg, ctx, MSG_PVFS_NOTIFY,
					    notify_handler);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("messaging_register failed: %s\n",
				  nt_errstr(status)));
			TALLOC_FREE(ctx);
			return NULL;
		}
	}

	talloc_set_destructor(ctx, notify_context_destructor);

	return ctx;
}

static int notify_context_destructor(struct notify_context *ctx)
{
	if (ctx->callback != NULL) {
		messaging_deregister(ctx->msg_ctx, MSG_PVFS_NOTIFY, ctx);
	}

	return 0;
}

static void notify_handler(struct messaging_context *msg, void *private_data,
			   uint32_t msg_type, struct server_id src,
			   DATA_BLOB *data)
{
	struct notify_context *ctx = talloc_get_type_abort(
		private_data, struct notify_context);
	struct notify_event_msg *event_msg;
	struct notify_event event;

	if (data->length < offsetof(struct notify_event_msg, path) + 1) {
		DEBUG(1, ("message too short: %u\n", (unsigned)data->length));
		return;
	}
	if (data->data[data->length-1] != 0) {
		DEBUG(1, ("%s: path not 0-terminated\n", __func__));
		return;
	}

	event_msg = (struct notify_event_msg *)data->data;

	event.action = event_msg->action;
	event.path = event_msg->path;
	event.private_data = event_msg->private_data;

	DEBUG(10, ("%s: Got notify_event action=%u, private_data=%p, "
		   "path=%s\n", __func__, (unsigned)event.action,
		   event.private_data, event.path));

	ctx->callback(ctx->sconn, event.private_data, event_msg->when, &event);
}

NTSTATUS notify_add(struct notify_context *ctx,
		    const char *path, uint32_t filter, uint32_t subdir_filter,
		    void *private_data)
{
	struct notify_rec_change_msg msg = {};
	struct iovec iov[2];
	size_t pathlen;
	NTSTATUS status;

	if (ctx == NULL) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	DEBUG(10, ("%s: path=[%s], filter=%u, subdir_filter=%u, "
		   "private_data=%p\n", __func__, path, (unsigned)filter,
		   (unsigned)subdir_filter, private_data));

	pathlen = strlen(path)+1;

	clock_gettime_mono(&msg.instance.creation_time);
	msg.instance.filter = filter;
	msg.instance.subdir_filter = subdir_filter;
	msg.instance.private_data = private_data;

	iov[0].iov_base = &msg;
	iov[0].iov_len = offsetof(struct notify_rec_change_msg, path);
	iov[1].iov_base = discard_const_p(char, path);
	iov[1].iov_len = pathlen;

	status =  messaging_send_iov(
		ctx->msg_ctx, ctx->notifyd, MSG_SMB_NOTIFY_REC_CHANGE,
		iov, ARRAY_SIZE(iov), NULL, 0);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("messaging_send_iov returned %s\n",
			   nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS notify_remove(struct notify_context *ctx, void *private_data,
		       char *path)
{
	struct notify_rec_change_msg msg = {};
	struct iovec iov[2];
	NTSTATUS status;

	/* see if change notify is enabled at all */
	if (ctx == NULL) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	msg.instance.private_data = private_data;

	iov[0].iov_base = &msg;
	iov[0].iov_len = offsetof(struct notify_rec_change_msg, path);
	iov[1].iov_base = path;
	iov[1].iov_len = strlen(path)+1;

	status = messaging_send_iov(
		ctx->msg_ctx, ctx->notifyd, MSG_SMB_NOTIFY_REC_CHANGE,
		iov, ARRAY_SIZE(iov), NULL, 0);

	return status;
}

void notify_trigger(struct notify_context *ctx,
		    uint32_t action, uint32_t filter,
		    const char *dir, const char *name)
{
	struct notify_trigger_msg msg;
	struct iovec iov[4];
	char slash = '/';

	DEBUG(10, ("notify_trigger called action=0x%x, filter=0x%x, "
		   "dir=%s, name=%s\n", (unsigned)action, (unsigned)filter,
		   dir, name));

	if (ctx == NULL) {
		return;
	}

	msg.when = timespec_current();
	msg.action = action;
	msg.filter = filter;

	iov[0].iov_base = &msg;
	iov[0].iov_len = offsetof(struct notify_trigger_msg, path);
	iov[1].iov_base = discard_const_p(char, dir);
	iov[1].iov_len = strlen(dir);
	iov[2].iov_base = &slash;
	iov[2].iov_len = 1;
	iov[3].iov_base = discard_const_p(char, name);
	iov[3].iov_len = strlen(name)+1;

	messaging_send_iov(
		ctx->msg_ctx, ctx->notifyd, MSG_SMB_NOTIFY_TRIGGER,
		iov, ARRAY_SIZE(iov), NULL, 0);
}

NTSTATUS notify_walk(struct notify_context *notify,
		     bool (*fn)(const char *path, struct server_id server,
				const struct notify_instance *instance,
				void *private_data),
		     void *private_data)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	struct messaging_rec *rec;
	uint64_t log_idx;
	NTSTATUS status;
	int ret;
	bool ok;

	ev = samba_tevent_context_init(notify);
	if (ev == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	req = messaging_read_send(ev, ev, notify->msg_ctx, MSG_SMB_NOTIFY_DB);
	if (req == NULL) {
		TALLOC_FREE(ev);
		return NT_STATUS_NO_MEMORY;
	}

	ok = tevent_req_set_endtime(req, ev, timeval_current_ofs(10, 0));
	if (!ok) {
		TALLOC_FREE(ev);
		return NT_STATUS_NO_MEMORY;
	}

	status = messaging_send_buf(notify->msg_ctx, notify->notifyd,
				    MSG_SMB_NOTIFY_GET_DB, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("%s: messaging_send_buf failed\n",
			   nt_errstr(status)));
		TALLOC_FREE(ev);
		return status;
	}

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		DEBUG(10, ("%s: tevent_req_poll failed\n", __func__));
		TALLOC_FREE(ev);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = messaging_read_recv(req, ev, &rec);
	if (ret != 0) {
		DEBUG(10, ("%s: messaging_read_recv failed: %s\n",
			   __func__, strerror(ret)));
		TALLOC_FREE(ev);
		return map_nt_error_from_unix(ret);
	}

	ret = notifyd_parse_db(rec->buf.data, rec->buf.length, &log_idx,
			       fn, private_data);
	if (ret != 0) {
		DEBUG(10, ("%s: notifyd_parse_db failed: %s\n",
			   __func__, strerror(ret)));
		TALLOC_FREE(ev);
		return map_nt_error_from_unix(ret);
	}

	TALLOC_FREE(ev);
	return NT_STATUS_OK;
}
