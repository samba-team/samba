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
#include <tevent.h>
#include "lib/util/server_id.h"
#include "lib/util/data_blob.h"
#include "librpc/gen_ndr/notify.h"
#include "librpc/gen_ndr/messaging.h"
#include "librpc/gen_ndr/server_id.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "messages.h"
#include "tdb.h"
#include "util_tdb.h"
#include "notifyd.h"
#include "lib/util/server_id_db.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"
#include "ctdbd_conn.h"
#include "ctdb_srvids.h"
#include "server_id_db_util.h"
#include "lib/util/iov_buf.h"
#include "messages_util.h"

#ifdef CLUSTER_SUPPORT
#include "ctdb_protocol.h"
#endif

struct notifyd_peer;

/*
 * All of notifyd's state
 */

struct notifyd_state {
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	struct ctdbd_connection *ctdbd_conn;

	/*
	 * Database of everything clients show interest in. Indexed by
	 * absolute path. The database keys are not 0-terminated
	 * to allow the criticial operation, notifyd_trigger, to walk
	 * the structure from the top without adding intermediate 0s.
	 * The database records contain an array of
	 *
	 * struct notifyd_instance
	 *
	 * to be maintained and parsed by notifyd_entry_parse()
	 */
	struct db_context *entries;

	/*
	 * In the cluster case, this is the place where we store a log
	 * of all MSG_SMB_NOTIFY_REC_CHANGE messages. We just 1:1
	 * forward them to our peer notifyd's in the cluster once a
	 * second or when the log grows too large.
	 */

	struct messaging_reclog *log;

	/*
	 * Array of companion notifyd's in a cluster. Every notifyd
	 * broadcasts its messaging_reclog to every other notifyd in
	 * the cluster. This is done by making ctdb send a message to
	 * srvid CTDB_SRVID_SAMBA_NOTIFY_PROXY with destination node
	 * number CTDB_BROADCAST_CONNECTED. Everybody in the cluster who
	 * had called register_with_ctdbd this srvid will receive the
	 * broadcasts.
	 *
	 * Database replication happens via these broadcasts. Also,
	 * they serve as liveness indication. If a notifyd receives a
	 * broadcast from an unknown peer, it will create one for this
	 * srvid. Also when we don't hear anything from a peer for a
	 * while, we will discard it.
	 */

	struct notifyd_peer **peers;
	size_t num_peers;

	sys_notify_watch_fn sys_notify_watch;
	struct sys_notify_context *sys_notify_ctx;
};

/*
 * notifyd's representation of a notify instance
 */
struct notifyd_instance {
	struct server_id client;
	struct notify_instance instance;

	void *sys_watch; /* inotify/fam/etc handle */

	/*
	 * Filters after sys_watch took responsibility of some bits
	 */
	uint32_t internal_filter;
	uint32_t internal_subdir_filter;
};

struct notifyd_peer {
	struct notifyd_state *state;
	struct server_id pid;
	uint64_t rec_index;
	struct db_context *db;
	time_t last_broadcast;
};

static void notifyd_rec_change(struct messaging_context *msg_ctx,
			       void *private_data, uint32_t msg_type,
			       struct server_id src, DATA_BLOB *data);
static void notifyd_trigger(struct messaging_context *msg_ctx,
			    void *private_data, uint32_t msg_type,
			    struct server_id src, DATA_BLOB *data);
static void notifyd_get_db(struct messaging_context *msg_ctx,
			   void *private_data, uint32_t msg_type,
			   struct server_id src, DATA_BLOB *data);

#ifdef CLUSTER_SUPPORT
static void notifyd_got_db(struct messaging_context *msg_ctx,
			   void *private_data, uint32_t msg_type,
			   struct server_id src, DATA_BLOB *data);
static void notifyd_broadcast_reclog(struct ctdbd_connection *ctdbd_conn,
				     struct server_id src,
				     struct messaging_reclog *log);
#endif
static void notifyd_sys_callback(struct sys_notify_context *ctx,
				 void *private_data, struct notify_event *ev,
				 uint32_t filter);

#ifdef CLUSTER_SUPPORT
static struct tevent_req *notifyd_broadcast_reclog_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct ctdbd_connection *ctdbd_conn, struct server_id src,
	struct messaging_reclog *log);
static int notifyd_broadcast_reclog_recv(struct tevent_req *req);

static struct tevent_req *notifyd_clean_peers_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct notifyd_state *notifyd);
static int notifyd_clean_peers_recv(struct tevent_req *req);
#endif

static int sys_notify_watch_dummy(
	TALLOC_CTX *mem_ctx,
	struct sys_notify_context *ctx,
	const char *path,
	uint32_t *filter,
	uint32_t *subdir_filter,
	void (*callback)(struct sys_notify_context *ctx,
			 void *private_data,
			 struct notify_event *ev,
			 uint32_t filter),
	void *private_data,
	void *handle_p)
{
	void **handle = handle_p;
	*handle = NULL;
	return 0;
}

#ifdef CLUSTER_SUPPORT
static void notifyd_broadcast_reclog_finished(struct tevent_req *subreq);
static void notifyd_clean_peers_finished(struct tevent_req *subreq);
static int notifyd_snoop_broadcast(struct tevent_context *ev,
				   uint32_t src_vnn, uint32_t dst_vnn,
				   uint64_t dst_srvid,
				   const uint8_t *msg, size_t msglen,
				   void *private_data);
#endif

struct tevent_req *notifyd_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct messaging_context *msg_ctx,
				struct ctdbd_connection *ctdbd_conn,
				sys_notify_watch_fn sys_notify_watch,
				struct sys_notify_context *sys_notify_ctx)
{
	struct tevent_req *req;
#ifdef CLUSTER_SUPPORT
	struct tevent_req *subreq;
#endif
	struct notifyd_state *state;
	struct server_id_db *names_db;
	NTSTATUS status;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct notifyd_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->msg_ctx = msg_ctx;
	state->ctdbd_conn = ctdbd_conn;

	if (sys_notify_watch == NULL) {
		sys_notify_watch = sys_notify_watch_dummy;
	}

	state->sys_notify_watch = sys_notify_watch;
	state->sys_notify_ctx = sys_notify_ctx;

	state->entries = db_open_rbt(state);
	if (tevent_req_nomem(state->entries, req)) {
		return tevent_req_post(req, ev);
	}

	status = messaging_register(msg_ctx, state, MSG_SMB_NOTIFY_REC_CHANGE,
				    notifyd_rec_change);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = messaging_register(msg_ctx, state, MSG_SMB_NOTIFY_TRIGGER,
				    notifyd_trigger);
	if (tevent_req_nterror(req, status)) {
		goto deregister_rec_change;
	}

	status = messaging_register(msg_ctx, state, MSG_SMB_NOTIFY_GET_DB,
				    notifyd_get_db);
	if (tevent_req_nterror(req, status)) {
		goto deregister_trigger;
	}

	names_db = messaging_names_db(msg_ctx);

	ret = server_id_db_set_exclusive(names_db, "notify-daemon");
	if (ret != 0) {
		DEBUG(10, ("%s: server_id_db_add failed: %s\n",
			   __func__, strerror(ret)));
		tevent_req_error(req, ret);
		goto deregister_get_db;
	}

	if (ctdbd_conn == NULL) {
		/*
		 * No cluster around, skip the database replication
		 * engine
		 */
		return req;
	}

#ifdef CLUSTER_SUPPORT
	status = messaging_register(msg_ctx, state, MSG_SMB_NOTIFY_DB,
				    notifyd_got_db);
	if (tevent_req_nterror(req, status)) {
		goto deregister_get_db;
	}

	state->log = talloc_zero(state, struct messaging_reclog);
	if (tevent_req_nomem(state->log, req)) {
		goto deregister_db;
	}

	subreq = notifyd_broadcast_reclog_send(
		state->log, ev, ctdbd_conn,
		messaging_server_id(msg_ctx),
		state->log);
	if (tevent_req_nomem(subreq, req)) {
		goto deregister_db;
	}
	tevent_req_set_callback(subreq,
				notifyd_broadcast_reclog_finished,
				req);

	subreq = notifyd_clean_peers_send(state, ev, state);
	if (tevent_req_nomem(subreq, req)) {
		goto deregister_db;
	}
	tevent_req_set_callback(subreq, notifyd_clean_peers_finished,
				req);

	ret = register_with_ctdbd(ctdbd_conn,
				  CTDB_SRVID_SAMBA_NOTIFY_PROXY,
				  notifyd_snoop_broadcast, state);
	if (ret != 0) {
		tevent_req_error(req, ret);
		goto deregister_db;
	}
#endif

	return req;

#ifdef CLUSTER_SUPPORT
deregister_db:
	messaging_deregister(msg_ctx, MSG_SMB_NOTIFY_DB, state);
#endif
deregister_get_db:
	messaging_deregister(msg_ctx, MSG_SMB_NOTIFY_GET_DB, state);
deregister_trigger:
	messaging_deregister(msg_ctx, MSG_SMB_NOTIFY_TRIGGER, state);
deregister_rec_change:
	messaging_deregister(msg_ctx, MSG_SMB_NOTIFY_REC_CHANGE, state);
	return tevent_req_post(req, ev);
}

#ifdef CLUSTER_SUPPORT

static void notifyd_broadcast_reclog_finished(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;

	ret = notifyd_broadcast_reclog_recv(subreq);
	TALLOC_FREE(subreq);
	tevent_req_error(req, ret);
}

static void notifyd_clean_peers_finished(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;

	ret = notifyd_clean_peers_recv(subreq);
	TALLOC_FREE(subreq);
	tevent_req_error(req, ret);
}

#endif

int notifyd_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

/*
 * Parse an entry in the notifyd_context->entries database
 */

static bool notifyd_parse_entry(uint8_t *buf, size_t buflen,
				struct notifyd_instance **instances,
				size_t *num_instances)
{
	if ((buflen % sizeof(struct notifyd_instance)) != 0) {
		DEBUG(1, ("%s: invalid buffer size: %u\n",
			  __func__, (unsigned)buflen));
		return false;
	}

	if (instances != NULL) {
		*instances = (struct notifyd_instance *)buf;
	}
	if (num_instances != NULL) {
		*num_instances = buflen / sizeof(struct notifyd_instance);
	}
	return true;
}

static bool notifyd_apply_rec_change(
	const struct server_id *client,
	const char *path, size_t pathlen,
	const struct notify_instance *chg,
	struct db_context *entries,
	sys_notify_watch_fn sys_notify_watch,
	struct sys_notify_context *sys_notify_ctx,
	struct messaging_context *msg_ctx)
{
	struct db_record *rec;
	struct notifyd_instance *instances;
	size_t num_instances;
	size_t i;
	struct notifyd_instance *instance;
	TDB_DATA value;
	NTSTATUS status;
	bool ok = false;

	if (pathlen == 0) {
		DEBUG(1, ("%s: pathlen==0\n", __func__));
		return false;
	}
	if (path[pathlen-1] != '\0') {
		DEBUG(1, ("%s: path not 0-terminated\n", __func__));
		return false;
	}

	DEBUG(10, ("%s: path=%s, filter=%u, subdir_filter=%u, "
		   "private_data=%p\n", __func__, path,
		   (unsigned)chg->filter, (unsigned)chg->subdir_filter,
		   chg->private_data));

	rec = dbwrap_fetch_locked(
		entries, entries,
		make_tdb_data((const uint8_t *)path, pathlen-1));

	if (rec == NULL) {
		DEBUG(1, ("%s: dbwrap_fetch_locked failed\n", __func__));
		goto fail;
	}

	num_instances = 0;
	value = dbwrap_record_get_value(rec);

	if (value.dsize != 0) {
		if (!notifyd_parse_entry(value.dptr, value.dsize, NULL,
					 &num_instances)) {
			goto fail;
		}
	}

	/*
	 * Overallocate by one instance to avoid a realloc when adding
	 */
	instances = talloc_array(rec, struct notifyd_instance,
				 num_instances + 1);
	if (instances == NULL) {
		DEBUG(1, ("%s: talloc failed\n", __func__));
		goto fail;
	}

	if (value.dsize != 0) {
		memcpy(instances, value.dptr, value.dsize);
	}

	for (i=0; i<num_instances; i++) {
		instance = &instances[i];

		if (server_id_equal(&instance->client, client) &&
		    (instance->instance.private_data == chg->private_data)) {
			break;
		}
	}

	if (i < num_instances) {
		instance->instance = *chg;
	} else {
		/*
		 * We've overallocated for one instance
		 */
		instance = &instances[num_instances];

		*instance = (struct notifyd_instance) {
			.client = *client,
			.instance = *chg,
			.internal_filter = chg->filter,
			.internal_subdir_filter = chg->subdir_filter
		};

		num_instances += 1;
	}

	if ((instance->instance.filter != 0) ||
	    (instance->instance.subdir_filter != 0)) {
		int ret;

		TALLOC_FREE(instance->sys_watch);

		ret = sys_notify_watch(entries, sys_notify_ctx, path,
				       &instance->internal_filter,
				       &instance->internal_subdir_filter,
				       notifyd_sys_callback, msg_ctx,
				       &instance->sys_watch);
		if (ret != 0) {
			DBG_WARNING("sys_notify_watch for [%s] returned %s\n",
				    path, strerror(errno));
		}
	}

	if ((instance->instance.filter == 0) &&
	    (instance->instance.subdir_filter == 0)) {
		/* This is a delete request */
		TALLOC_FREE(instance->sys_watch);
		*instance = instances[num_instances-1];
		num_instances -= 1;
	}

	DEBUG(10, ("%s: %s has %u instances\n", __func__,
		   path, (unsigned)num_instances));

	if (num_instances == 0) {
		status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("%s: dbwrap_record_delete returned %s\n",
				  __func__, nt_errstr(status)));
			goto fail;
		}
	} else {
		value = make_tdb_data(
			(uint8_t *)instances,
			sizeof(struct notifyd_instance) * num_instances);

		status = dbwrap_record_store(rec, value, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("%s: dbwrap_record_store returned %s\n",
				  __func__, nt_errstr(status)));
			goto fail;
		}
	}

	ok = true;
fail:
	TALLOC_FREE(rec);
	return ok;
}

static void notifyd_sys_callback(struct sys_notify_context *ctx,
				 void *private_data, struct notify_event *ev,
				 uint32_t filter)
{
	struct messaging_context *msg_ctx = talloc_get_type_abort(
		private_data, struct messaging_context);
	struct notify_trigger_msg msg;
	struct iovec iov[4];
	char slash = '/';

	msg = (struct notify_trigger_msg) {
		.when = timespec_current(),
		.action = ev->action,
		.filter = filter,
	};

	iov[0].iov_base = &msg;
	iov[0].iov_len = offsetof(struct notify_trigger_msg, path);
	iov[1].iov_base = discard_const_p(char, ev->dir);
	iov[1].iov_len = strlen(ev->dir);
	iov[2].iov_base = &slash;
	iov[2].iov_len = 1;
	iov[3].iov_base = discard_const_p(char, ev->path);
	iov[3].iov_len = strlen(ev->path)+1;

	messaging_send_iov(
		msg_ctx, messaging_server_id(msg_ctx),
		MSG_SMB_NOTIFY_TRIGGER, iov, ARRAY_SIZE(iov), NULL, 0);
}

static bool notifyd_parse_rec_change(uint8_t *buf, size_t bufsize,
				     struct notify_rec_change_msg **pmsg,
				     size_t *pathlen)
{
	struct notify_rec_change_msg *msg;

	if (bufsize < offsetof(struct notify_rec_change_msg, path) + 1) {
		DEBUG(1, ("%s: message too short, ignoring: %u\n", __func__,
			  (unsigned)bufsize));
		return false;
	}

	*pmsg = msg = (struct notify_rec_change_msg *)buf;
	*pathlen = bufsize - offsetof(struct notify_rec_change_msg, path);

	DEBUG(10, ("%s: Got rec_change_msg filter=%u, subdir_filter=%u, "
		   "private_data=%p, path=%.*s\n",
		   __func__, (unsigned)msg->instance.filter,
		   (unsigned)msg->instance.subdir_filter,
		   msg->instance.private_data, (int)(*pathlen), msg->path));

	return true;
}

static void notifyd_rec_change(struct messaging_context *msg_ctx,
			       void *private_data, uint32_t msg_type,
			       struct server_id src, DATA_BLOB *data)
{
	struct notifyd_state *state = talloc_get_type_abort(
		private_data, struct notifyd_state);
	struct server_id_buf idbuf;
	struct notify_rec_change_msg *msg;
	size_t pathlen;
	bool ok;
	struct notify_instance instance;

	DBG_DEBUG("Got %zu bytes from %s\n", data->length,
		  server_id_str_buf(src, &idbuf));

	ok = notifyd_parse_rec_change(data->data, data->length,
				      &msg, &pathlen);
	if (!ok) {
		return;
	}

	memcpy(&instance, &msg->instance, sizeof(instance)); /* avoid SIGBUS */

	ok = notifyd_apply_rec_change(
		&src, msg->path, pathlen, &instance,
		state->entries, state->sys_notify_watch, state->sys_notify_ctx,
		state->msg_ctx);
	if (!ok) {
		DEBUG(1, ("%s: notifyd_apply_rec_change failed, ignoring\n",
			  __func__));
		return;
	}

	if ((state->log == NULL) || (state->ctdbd_conn == NULL)) {
		return;
	}

#ifdef CLUSTER_SUPPORT
	{

	struct messaging_rec **tmp;
	struct messaging_reclog *log;
	struct iovec iov = { .iov_base = data->data, .iov_len = data->length };

	log = state->log;

	tmp = talloc_realloc(log, log->recs, struct messaging_rec *,
			     log->num_recs+1);
	if (tmp == NULL) {
		DEBUG(1, ("%s: talloc_realloc failed, ignoring\n", __func__));
		return;
	}
	log->recs = tmp;

	log->recs[log->num_recs] = messaging_rec_create(
		log->recs, src, messaging_server_id(msg_ctx),
		msg_type, &iov, 1, NULL, 0);

	if (log->recs[log->num_recs] == NULL) {
		DBG_WARNING("messaging_rec_create failed, ignoring\n");
		return;
	}

	log->num_recs += 1;

	if (log->num_recs >= 100) {
		/*
		 * Don't let the log grow too large
		 */
		notifyd_broadcast_reclog(state->ctdbd_conn,
					 messaging_server_id(msg_ctx), log);
	}

	}
#endif
}

struct notifyd_trigger_state {
	struct messaging_context *msg_ctx;
	struct notify_trigger_msg *msg;
	bool recursive;
	bool covered_by_sys_notify;
};

static void notifyd_trigger_parser(TDB_DATA key, TDB_DATA data,
				   void *private_data);

static void notifyd_trigger(struct messaging_context *msg_ctx,
			    void *private_data, uint32_t msg_type,
			    struct server_id src, DATA_BLOB *data)
{
	struct notifyd_state *state = talloc_get_type_abort(
		private_data, struct notifyd_state);
	struct server_id my_id = messaging_server_id(msg_ctx);
	struct notifyd_trigger_state tstate;
	const char *path;
	const char *p, *next_p;

	if (data->length < offsetof(struct notify_trigger_msg, path) + 1) {
		DBG_WARNING("message too short, ignoring: %zu\n",
			    data->length);
		return;
	}
	if (data->data[data->length-1] != 0) {
		DEBUG(1, ("%s: path not 0-terminated, ignoring\n", __func__));
		return;
	}

	tstate.msg_ctx = msg_ctx;

	tstate.covered_by_sys_notify = (src.vnn == my_id.vnn);
	tstate.covered_by_sys_notify &= !server_id_equal(&src, &my_id);

	tstate.msg = (struct notify_trigger_msg *)data->data;
	path = tstate.msg->path;

	DEBUG(10, ("%s: Got trigger_msg action=%u, filter=%u, path=%s\n",
		   __func__, (unsigned)tstate.msg->action,
		   (unsigned)tstate.msg->filter, path));

	if (path[0] != '/') {
		DEBUG(1, ("%s: path %s does not start with /, ignoring\n",
			  __func__, path));
		return;
	}

	for (p = strchr(path+1, '/'); p != NULL; p = next_p) {
		ptrdiff_t path_len = p - path;
		TDB_DATA key;
		uint32_t i;

		next_p = strchr(p+1, '/');
		tstate.recursive = (next_p != NULL);

		DEBUG(10, ("%s: Trying path %.*s\n", __func__,
			   (int)path_len, path));

		key = (TDB_DATA) { .dptr = discard_const_p(uint8_t, path),
				   .dsize = path_len };

		dbwrap_parse_record(state->entries, key,
				    notifyd_trigger_parser, &tstate);

		if (state->peers == NULL) {
			continue;
		}

		if (src.vnn != my_id.vnn) {
			continue;
		}

		for (i=0; i<state->num_peers; i++) {
			if (state->peers[i]->db == NULL) {
				/*
				 * Inactive peer, did not get a db yet
				 */
				continue;
			}
			dbwrap_parse_record(state->peers[i]->db, key,
					    notifyd_trigger_parser, &tstate);
		}
	}
}

static void notifyd_send_delete(struct messaging_context *msg_ctx,
				TDB_DATA key,
				struct notifyd_instance *instance);

static void notifyd_trigger_parser(TDB_DATA key, TDB_DATA data,
				   void *private_data)

{
	struct notifyd_trigger_state *tstate = private_data;
	struct notify_event_msg msg = { .action = tstate->msg->action,
					.when = tstate->msg->when };
	struct iovec iov[2];
	size_t path_len = key.dsize;
	struct notifyd_instance *instances = NULL;
	size_t num_instances = 0;
	size_t i;

	if (!notifyd_parse_entry(data.dptr, data.dsize, &instances,
				 &num_instances)) {
		DEBUG(1, ("%s: Could not parse notifyd_entry\n", __func__));
		return;
	}

	DEBUG(10, ("%s: Found %u instances for %.*s\n", __func__,
		   (unsigned)num_instances, (int)key.dsize,
		   (char *)key.dptr));

	iov[0].iov_base = &msg;
	iov[0].iov_len = offsetof(struct notify_event_msg, path);
	iov[1].iov_base = tstate->msg->path + path_len + 1;
	iov[1].iov_len = strlen((char *)(iov[1].iov_base)) + 1;

	for (i=0; i<num_instances; i++) {
		struct notifyd_instance *instance = &instances[i];
		struct server_id_buf idbuf;
		uint32_t i_filter;
		NTSTATUS status;

		if (tstate->covered_by_sys_notify) {
			if (tstate->recursive) {
				i_filter = instance->internal_subdir_filter;
			} else {
				i_filter = instance->internal_filter;
			}
		} else {
			if (tstate->recursive) {
				i_filter = instance->instance.subdir_filter;
			} else {
				i_filter = instance->instance.filter;
			}
		}

		if ((i_filter & tstate->msg->filter) == 0) {
			continue;
		}

		msg.private_data = instance->instance.private_data;

		status = messaging_send_iov(
			tstate->msg_ctx, instance->client,
			MSG_PVFS_NOTIFY, iov, ARRAY_SIZE(iov), NULL, 0);

		DEBUG(10, ("%s: messaging_send_iov to %s returned %s\n",
			   __func__,
			   server_id_str_buf(instance->client, &idbuf),
			   nt_errstr(status)));

		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND) &&
		    procid_is_local(&instance->client)) {
			/*
			 * That process has died
			 */
			notifyd_send_delete(tstate->msg_ctx, key, instance);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("%s: messaging_send_iov returned %s\n",
				  __func__, nt_errstr(status)));
		}
	}
}

/*
 * Send a delete request to ourselves to properly discard a notify
 * record for an smbd that has died.
 */

static void notifyd_send_delete(struct messaging_context *msg_ctx,
				TDB_DATA key,
				struct notifyd_instance *instance)
{
	struct notify_rec_change_msg msg = {
		.instance.private_data = instance->instance.private_data
	};
	uint8_t nul = 0;
	struct iovec iov[3];
	int ret;

	/*
	 * Send a rec_change to ourselves to delete a dead entry
	 */

	iov[0] = (struct iovec) {
		.iov_base = &msg,
		.iov_len = offsetof(struct notify_rec_change_msg, path) };
	iov[1] = (struct iovec) { .iov_base = key.dptr, .iov_len = key.dsize };
	iov[2] = (struct iovec) { .iov_base = &nul, .iov_len = sizeof(nul) };

	ret = messaging_send_iov_from(
		msg_ctx, instance->client, messaging_server_id(msg_ctx),
		MSG_SMB_NOTIFY_REC_CHANGE, iov, ARRAY_SIZE(iov), NULL, 0);

	if (ret != 0) {
		DEBUG(10, ("%s: messaging_send_iov_from returned %s\n",
			   __func__, strerror(ret)));
	}
}

static void notifyd_get_db(struct messaging_context *msg_ctx,
			   void *private_data, uint32_t msg_type,
			   struct server_id src, DATA_BLOB *data)
{
	struct notifyd_state *state = talloc_get_type_abort(
		private_data, struct notifyd_state);
	struct server_id_buf id1, id2;
	NTSTATUS status;
	uint64_t rec_index = UINT64_MAX;
	uint8_t index_buf[sizeof(uint64_t)];
	size_t dbsize;
	uint8_t *buf;
	struct iovec iov[2];

	dbsize = dbwrap_marshall(state->entries, NULL, 0);

	buf = talloc_array(talloc_tos(), uint8_t, dbsize);
	if (buf == NULL) {
		DEBUG(1, ("%s: talloc_array(%ju) failed\n",
			  __func__, (uintmax_t)dbsize));
		return;
	}

	dbsize = dbwrap_marshall(state->entries, buf, dbsize);

	if (dbsize != talloc_get_size(buf)) {
		DEBUG(1, ("%s: dbsize changed: %ju->%ju\n", __func__,
			  (uintmax_t)talloc_get_size(buf),
			  (uintmax_t)dbsize));
		TALLOC_FREE(buf);
		return;
	}

	if (state->log != NULL) {
		rec_index = state->log->rec_index;
	}
	SBVAL(index_buf, 0, rec_index);

	iov[0] = (struct iovec) { .iov_base = index_buf,
				  .iov_len = sizeof(index_buf) };
	iov[1] = (struct iovec) { .iov_base = buf,
				  .iov_len = dbsize };

	DEBUG(10, ("%s: Sending %ju bytes to %s->%s\n", __func__,
		   (uintmax_t)iov_buflen(iov, ARRAY_SIZE(iov)),
		   server_id_str_buf(messaging_server_id(msg_ctx), &id1),
		   server_id_str_buf(src, &id2)));

	status = messaging_send_iov(msg_ctx, src, MSG_SMB_NOTIFY_DB,
				    iov, ARRAY_SIZE(iov), NULL, 0);
	TALLOC_FREE(buf);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("%s: messaging_send_iov failed: %s\n",
			  __func__, nt_errstr(status)));
	}
}

#ifdef CLUSTER_SUPPORT

static int notifyd_add_proxy_syswatches(struct db_record *rec,
					void *private_data);

static void notifyd_got_db(struct messaging_context *msg_ctx,
			   void *private_data, uint32_t msg_type,
			   struct server_id src, DATA_BLOB *data)
{
	struct notifyd_state *state = talloc_get_type_abort(
		private_data, struct notifyd_state);
	struct notifyd_peer *p = NULL;
	struct server_id_buf idbuf;
	NTSTATUS status;
	int count;
	size_t i;

	for (i=0; i<state->num_peers; i++) {
		if (server_id_equal(&src, &state->peers[i]->pid)) {
			p = state->peers[i];
			break;
		}
	}

	if (p == NULL) {
		DBG_DEBUG("Did not find peer for db from %s\n",
			  server_id_str_buf(src, &idbuf));
		return;
	}

	if (data->length < 8) {
		DBG_DEBUG("Got short db length %zu from %s\n", data->length,
			   server_id_str_buf(src, &idbuf));
		TALLOC_FREE(p);
		return;
	}

	p->rec_index = BVAL(data->data, 0);

	p->db = db_open_rbt(p);
	if (p->db == NULL) {
		DEBUG(10, ("%s: db_open_rbt failed\n", __func__));
		TALLOC_FREE(p);
		return;
	}

	status = dbwrap_unmarshall(p->db, data->data + 8,
				   data->length - 8);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("%s: dbwrap_unmarshall returned %s for db %s\n",
			   __func__, nt_errstr(status),
			   server_id_str_buf(src, &idbuf)));
		TALLOC_FREE(p);
		return;
	}

	dbwrap_traverse_read(p->db, notifyd_add_proxy_syswatches, state,
			     &count);

	DEBUG(10, ("%s: Database from %s contained %d records\n", __func__,
		   server_id_str_buf(src, &idbuf), count));
}

static void notifyd_broadcast_reclog(struct ctdbd_connection *ctdbd_conn,
				     struct server_id src,
				     struct messaging_reclog *log)
{
	enum ndr_err_code ndr_err;
	uint8_t msghdr[MESSAGE_HDR_LENGTH];
	DATA_BLOB blob;
	struct iovec iov[2];
	int ret;

	if (log == NULL) {
		return;
	}

	DEBUG(10, ("%s: rec_index=%ju, num_recs=%u\n", __func__,
		   (uintmax_t)log->rec_index, (unsigned)log->num_recs));

	message_hdr_put(msghdr, MSG_SMB_NOTIFY_REC_CHANGES, src,
			(struct server_id) {0 });
	iov[0] = (struct iovec) { .iov_base = msghdr,
				  .iov_len = sizeof(msghdr) };

	ndr_err = ndr_push_struct_blob(
		&blob, log, log,
		(ndr_push_flags_fn_t)ndr_push_messaging_reclog);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("%s: ndr_push_messaging_recs failed: %s\n",
			  __func__, ndr_errstr(ndr_err)));
		goto done;
	}
	iov[1] = (struct iovec) { .iov_base = blob.data,
				  .iov_len = blob.length };

	ret = ctdbd_messaging_send_iov(
		ctdbd_conn, CTDB_BROADCAST_CONNECTED,
		CTDB_SRVID_SAMBA_NOTIFY_PROXY, iov, ARRAY_SIZE(iov));
	TALLOC_FREE(blob.data);
	if (ret != 0) {
		DEBUG(1, ("%s: ctdbd_messaging_send failed: %s\n",
			  __func__, strerror(ret)));
		goto done;
	}

	log->rec_index += 1;

done:
	log->num_recs = 0;
	TALLOC_FREE(log->recs);
}

struct notifyd_broadcast_reclog_state {
	struct tevent_context *ev;
	struct ctdbd_connection *ctdbd_conn;
	struct server_id src;
	struct messaging_reclog *log;
};

static void notifyd_broadcast_reclog_next(struct tevent_req *subreq);

static struct tevent_req *notifyd_broadcast_reclog_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct ctdbd_connection *ctdbd_conn, struct server_id src,
	struct messaging_reclog *log)
{
	struct tevent_req *req, *subreq;
	struct notifyd_broadcast_reclog_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct notifyd_broadcast_reclog_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->ctdbd_conn = ctdbd_conn;
	state->src = src;
	state->log = log;

	subreq = tevent_wakeup_send(state, state->ev,
				    timeval_current_ofs_msec(1000));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, notifyd_broadcast_reclog_next, req);
	return req;
}

static void notifyd_broadcast_reclog_next(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notifyd_broadcast_reclog_state *state = tevent_req_data(
		req, struct notifyd_broadcast_reclog_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_oom(req);
		return;
	}

	notifyd_broadcast_reclog(state->ctdbd_conn, state->src, state->log);

	subreq = tevent_wakeup_send(state, state->ev,
				    timeval_current_ofs_msec(1000));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notifyd_broadcast_reclog_next, req);
}

static int notifyd_broadcast_reclog_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

struct notifyd_clean_peers_state {
	struct tevent_context *ev;
	struct notifyd_state *notifyd;
};

static void notifyd_clean_peers_next(struct tevent_req *subreq);

static struct tevent_req *notifyd_clean_peers_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct notifyd_state *notifyd)
{
	struct tevent_req *req, *subreq;
	struct notifyd_clean_peers_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct notifyd_clean_peers_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->notifyd = notifyd;

	subreq = tevent_wakeup_send(state, state->ev,
				    timeval_current_ofs_msec(30000));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, notifyd_clean_peers_next, req);
	return req;
}

static void notifyd_clean_peers_next(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notifyd_clean_peers_state *state = tevent_req_data(
		req, struct notifyd_clean_peers_state);
	struct notifyd_state *notifyd = state->notifyd;
	size_t i;
	bool ok;
	time_t now = time(NULL);

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_oom(req);
		return;
	}

	i = 0;
	while (i < notifyd->num_peers) {
		struct notifyd_peer *p = notifyd->peers[i];

		if ((now - p->last_broadcast) > 60) {
			struct server_id_buf idbuf;

			/*
			 * Haven't heard for more than 60 seconds. Call this
			 * peer dead
			 */

			DEBUG(10, ("%s: peer %s died\n", __func__,
				   server_id_str_buf(p->pid, &idbuf)));
			/*
			 * This implicitly decrements notifyd->num_peers
			 */
			TALLOC_FREE(p);
		} else {
			i += 1;
		}
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    timeval_current_ofs_msec(30000));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notifyd_clean_peers_next, req);
}

static int notifyd_clean_peers_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

static int notifyd_add_proxy_syswatches(struct db_record *rec,
					void *private_data)
{
	struct notifyd_state *state = talloc_get_type_abort(
		private_data, struct notifyd_state);
	struct db_context *db = dbwrap_record_get_db(rec);
	TDB_DATA key = dbwrap_record_get_key(rec);
	TDB_DATA value = dbwrap_record_get_value(rec);
	struct notifyd_instance *instances = NULL;
	size_t num_instances = 0;
	size_t i;
	char path[key.dsize+1];
	bool ok;

	memcpy(path, key.dptr, key.dsize);
	path[key.dsize] = '\0';

	ok = notifyd_parse_entry(value.dptr, value.dsize, &instances,
				 &num_instances);
	if (!ok) {
		DEBUG(1, ("%s: Could not parse notifyd entry for %s\n",
			  __func__, path));
		return 0;
	}

	for (i=0; i<num_instances; i++) {
		struct notifyd_instance *instance = &instances[i];
		uint32_t filter = instance->instance.filter;
		uint32_t subdir_filter = instance->instance.subdir_filter;
		int ret;

		/*
		 * This is a remote database. Pointers that we were
		 * given don't make sense locally. Initialize to NULL
		 * in case sys_notify_watch fails.
		 */
		instances[i].sys_watch = NULL;

		ret = state->sys_notify_watch(
			db, state->sys_notify_ctx, path,
			&filter, &subdir_filter,
			notifyd_sys_callback, state->msg_ctx,
			&instance->sys_watch);
		if (ret != 0) {
			DEBUG(1, ("%s: inotify_watch returned %s\n",
				  __func__, strerror(errno)));
		}
	}

	return 0;
}

static int notifyd_db_del_syswatches(struct db_record *rec, void *private_data)
{
	TDB_DATA key = dbwrap_record_get_key(rec);
	TDB_DATA value = dbwrap_record_get_value(rec);
	struct notifyd_instance *instances = NULL;
	size_t num_instances = 0;
	size_t i;
	bool ok;

	ok = notifyd_parse_entry(value.dptr, value.dsize, &instances,
				 &num_instances);
	if (!ok) {
		DEBUG(1, ("%s: Could not parse notifyd entry for %.*s\n",
			  __func__, (int)key.dsize, (char *)key.dptr));
		return 0;
	}
	for (i=0; i<num_instances; i++) {
		TALLOC_FREE(instances[i].sys_watch);
	}
	return 0;
}

static int notifyd_peer_destructor(struct notifyd_peer *p)
{
	struct notifyd_state *state = p->state;
	size_t i;

	if (p->db != NULL) {
		dbwrap_traverse_read(p->db, notifyd_db_del_syswatches,
				     NULL, NULL);
	}

	for (i = 0; i<state->num_peers; i++) {
		if (p == state->peers[i]) {
			state->peers[i] = state->peers[state->num_peers-1];
			state->num_peers -= 1;
			break;
		}
	}
	return 0;
}

static struct notifyd_peer *notifyd_peer_new(
	struct notifyd_state *state, struct server_id pid)
{
	struct notifyd_peer *p, **tmp;

	tmp = talloc_realloc(state, state->peers, struct notifyd_peer *,
			     state->num_peers+1);
	if (tmp == NULL) {
		return NULL;
	}
	state->peers = tmp;

	p = talloc_zero(state->peers, struct notifyd_peer);
	if (p == NULL) {
		return NULL;
	}
	p->state = state;
	p->pid = pid;

	state->peers[state->num_peers] = p;
	state->num_peers += 1;

	talloc_set_destructor(p, notifyd_peer_destructor);

	return p;
}

static void notifyd_apply_reclog(struct notifyd_peer *peer,
				 const uint8_t *msg, size_t msglen)
{
	struct notifyd_state *state = peer->state;
	DATA_BLOB blob = { .data = discard_const_p(uint8_t, msg),
			   .length = msglen };
	struct server_id_buf idbuf;
	struct messaging_reclog *log;
	enum ndr_err_code ndr_err;
	uint32_t i;

	if (peer->db == NULL) {
		/*
		 * No db yet
		 */
		return;
	}

	log = talloc(peer, struct messaging_reclog);
	if (log == NULL) {
		DEBUG(10, ("%s: talloc failed\n", __func__));
		return;
	}

	ndr_err = ndr_pull_struct_blob_all(
		&blob, log, log,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_reclog);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("%s: ndr_pull_messaging_reclog failed: %s\n",
			   __func__, ndr_errstr(ndr_err)));
		goto fail;
	}

	DEBUG(10, ("%s: Got %u recs index %ju from %s\n", __func__,
		   (unsigned)log->num_recs, (uintmax_t)log->rec_index,
		   server_id_str_buf(peer->pid, &idbuf)));

	if (log->rec_index != peer->rec_index) {
		DEBUG(3, ("%s: Got rec index %ju from %s, expected %ju\n",
			  __func__, (uintmax_t)log->rec_index,
			  server_id_str_buf(peer->pid, &idbuf),
			  (uintmax_t)peer->rec_index));
		goto fail;
	}

	for (i=0; i<log->num_recs; i++) {
		struct messaging_rec *r = log->recs[i];
		struct notify_rec_change_msg *chg;
		size_t pathlen;
		bool ok;
		struct notify_instance instance;

		ok = notifyd_parse_rec_change(r->buf.data, r->buf.length,
					      &chg, &pathlen);
		if (!ok) {
			DEBUG(3, ("%s: notifyd_parse_rec_change failed\n",
				  __func__));
			goto fail;
		}

		/* avoid SIGBUS */
		memcpy(&instance, &chg->instance, sizeof(instance));

		ok = notifyd_apply_rec_change(&r->src, chg->path, pathlen,
					      &instance, peer->db,
					      state->sys_notify_watch,
					      state->sys_notify_ctx,
					      state->msg_ctx);
		if (!ok) {
			DEBUG(3, ("%s: notifyd_apply_rec_change failed\n",
				  __func__));
			goto fail;
		}
	}

	peer->rec_index += 1;
	peer->last_broadcast = time(NULL);

	TALLOC_FREE(log);
	return;

fail:
	DEBUG(10, ("%s: Dropping peer %s\n", __func__,
		   server_id_str_buf(peer->pid, &idbuf)));
	TALLOC_FREE(peer);
}

/*
 * Receive messaging_reclog (log of MSG_SMB_NOTIFY_REC_CHANGE
 * messages) broadcasts by other notifyds. Several cases:
 *
 * We don't know the source. This creates a new peer. Creating a peer
 * involves asking the peer for its full database. We assume ordered
 * messages, so the new database will arrive before the next broadcast
 * will.
 *
 * We know the source and the log index matches. We will apply the log
 * locally to our peer's db as if we had received it from a local
 * client.
 *
 * We know the source but the log index does not match. This means we
 * lost a message. We just drop the whole peer and wait for the next
 * broadcast, which will then trigger a fresh database pull.
 */

static int notifyd_snoop_broadcast(struct tevent_context *ev,
				   uint32_t src_vnn, uint32_t dst_vnn,
				   uint64_t dst_srvid,
				   const uint8_t *msg, size_t msglen,
				   void *private_data)
{
	struct notifyd_state *state = talloc_get_type_abort(
		private_data, struct notifyd_state);
	struct server_id my_id = messaging_server_id(state->msg_ctx);
	struct notifyd_peer *p;
	uint32_t i;
	uint32_t msg_type;
	struct server_id src, dst;
	struct server_id_buf idbuf;
	NTSTATUS status;

	if (msglen < MESSAGE_HDR_LENGTH) {
		DEBUG(10, ("%s: Got short broadcast\n", __func__));
		return 0;
	}
	message_hdr_get(&msg_type, &src, &dst, msg);

	if (msg_type != MSG_SMB_NOTIFY_REC_CHANGES) {
		DEBUG(10, ("%s Got message %u, ignoring\n", __func__,
			   (unsigned)msg_type));
		return 0;
	}
	if (server_id_equal(&src, &my_id)) {
		DEBUG(10, ("%s: Ignoring my own broadcast\n", __func__));
		return 0;
	}

	DEBUG(10, ("%s: Got MSG_SMB_NOTIFY_REC_CHANGES from %s\n",
		   __func__, server_id_str_buf(src, &idbuf)));

	for (i=0; i<state->num_peers; i++) {
		if (server_id_equal(&state->peers[i]->pid, &src)) {

			DEBUG(10, ("%s: Applying changes to peer %u\n",
				   __func__, (unsigned)i));

			notifyd_apply_reclog(state->peers[i],
					     msg + MESSAGE_HDR_LENGTH,
					     msglen - MESSAGE_HDR_LENGTH);
			return 0;
		}
	}

	DEBUG(10, ("%s: Creating new peer for %s\n", __func__,
		   server_id_str_buf(src, &idbuf)));

	p = notifyd_peer_new(state, src);
	if (p == NULL) {
		DEBUG(10, ("%s: notifyd_peer_new failed\n", __func__));
		return 0;
	}

	status = messaging_send_buf(state->msg_ctx, src, MSG_SMB_NOTIFY_GET_DB,
				    NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("%s: messaging_send_buf failed: %s\n",
			   __func__, nt_errstr(status)));
		TALLOC_FREE(p);
		return 0;
	}

	return 0;
}
#endif

struct notifyd_parse_db_state {
	bool (*fn)(const char *path,
		   struct server_id server,
		   const struct notify_instance *instance,
		   void *private_data);
	void *private_data;
};

static bool notifyd_parse_db_parser(TDB_DATA key, TDB_DATA value,
				    void *private_data)
{
	struct notifyd_parse_db_state *state = private_data;
	char path[key.dsize+1];
	struct notifyd_instance *instances = NULL;
	size_t num_instances = 0;
	size_t i;
	bool ok;

	memcpy(path, key.dptr, key.dsize);
	path[key.dsize] = 0;

	ok = notifyd_parse_entry(value.dptr, value.dsize, &instances,
				 &num_instances);
	if (!ok) {
		DEBUG(10, ("%s: Could not parse entry for path %s\n",
			   __func__, path));
		return true;
	}

	for (i=0; i<num_instances; i++) {
		ok = state->fn(path, instances[i].client,
			       &instances[i].instance,
			       state->private_data);
		if (!ok) {
			return false;
		}
	}

	return true;
}

int notifyd_parse_db(const uint8_t *buf, size_t buflen,
		     uint64_t *log_index,
		     bool (*fn)(const char *path,
				struct server_id server,
				const struct notify_instance *instance,
				void *private_data),
		     void *private_data)
{
	struct notifyd_parse_db_state state = {
		.fn = fn, .private_data = private_data
	};
	NTSTATUS status;

	if (buflen < 8) {
		return EINVAL;
	}
	*log_index = BVAL(buf, 0);

	buf += 8;
	buflen -= 8;

	status = dbwrap_parse_marshall_buf(
		buf, buflen, notifyd_parse_db_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return map_errno_from_nt_status(status);
	}

	return 0;
}
