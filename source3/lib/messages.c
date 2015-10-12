/* 
   Unix SMB/CIFS implementation.
   Samba internal messaging functions
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) 2001 by Martin Pool
   Copyright (C) 2002 by Jeremy Allison
   Copyright (C) 2007 by Volker Lendecke

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

/**
  @defgroup messages Internal messaging framework
  @{
  @file messages.c

  @brief  Module for internal messaging between Samba daemons. 

   The idea is that if a part of Samba wants to do communication with
   another Samba process then it will do a message_register() of a
   dispatch function, and use message_send_pid() to send messages to
   that process.

   The dispatch function is given the pid of the sender, and it can
   use that to reply by message_send_pid().  See ping_message() for a
   simple example.

   @caution Dispatch functions must be able to cope with incoming
   messages on an *odd* byte boundary.

   This system doesn't have any inherent size limitations but is not
   very efficient for large messages or when messages are sent in very
   quick succession.

*/

#include "includes.h"
#include "dbwrap/dbwrap.h"
#include "serverid.h"
#include "messages.h"
#include "lib/util/tevent_unix.h"
#include "lib/background.h"
#include "lib/messages_dgm.h"
#include "lib/util/iov_buf.h"
#include "lib/util/server_id_db.h"
#include "lib/messages_dgm_ref.h"
#include "lib/messages_util.h"

struct messaging_callback {
	struct messaging_callback *prev, *next;
	uint32_t msg_type;
	void (*fn)(struct messaging_context *msg, void *private_data, 
		   uint32_t msg_type, 
		   struct server_id server_id, DATA_BLOB *data);
	void *private_data;
};

struct messaging_context {
	struct server_id id;
	struct tevent_context *event_ctx;
	struct messaging_callback *callbacks;

	struct tevent_req **new_waiters;
	unsigned num_new_waiters;

	struct tevent_req **waiters;
	unsigned num_waiters;

	void *msg_dgm_ref;
	struct messaging_backend *remote;

	struct server_id_db *names_db;
};

static void messaging_dispatch_rec(struct messaging_context *msg_ctx,
				   struct messaging_rec *rec);

/****************************************************************************
 A useful function for testing the message system.
****************************************************************************/

static void ping_message(struct messaging_context *msg_ctx,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id src,
			 DATA_BLOB *data)
{
	struct server_id_buf idbuf;

	DEBUG(1, ("INFO: Received PING message from PID %s [%.*s]\n",
		  server_id_str_buf(src, &idbuf), (int)data->length,
		  data->data ? (char *)data->data : ""));

	messaging_send(msg_ctx, src, MSG_PONG, data);
}

/****************************************************************************
 Register/replace a dispatch function for a particular message type.
 JRA changed Dec 13 2006. Only one message handler now permitted per type.
 *NOTE*: Dispatch functions must be able to cope with incoming
 messages on an *odd* byte boundary.
****************************************************************************/

struct msg_all {
	struct messaging_context *msg_ctx;
	int msg_type;
	uint32_t msg_flag;
	const void *buf;
	size_t len;
	int n_sent;
};

/****************************************************************************
 Send one of the messages for the broadcast.
****************************************************************************/

static int traverse_fn(struct db_record *rec, const struct server_id *id,
		       uint32_t msg_flags, void *state)
{
	struct msg_all *msg_all = (struct msg_all *)state;
	NTSTATUS status;

	/* Don't send if the receiver hasn't registered an interest. */

	if((msg_flags & msg_all->msg_flag) == 0) {
		return 0;
	}

	/* If the msg send fails because the pid was not found (i.e. smbd died), 
	 * the msg has already been deleted from the messages.tdb.*/

	status = messaging_send_buf(msg_all->msg_ctx, *id, msg_all->msg_type,
				    (const uint8_t *)msg_all->buf, msg_all->len);

	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		struct server_id_buf idbuf;

		/*
		 * If the pid was not found delete the entry from
		 * serverid.tdb
		 */

		DEBUG(2, ("pid %s doesn't exist\n",
			  server_id_str_buf(*id, &idbuf)));

		dbwrap_record_delete(rec);
	}
	msg_all->n_sent++;
	return 0;
}

/**
 * Send a message to all smbd processes.
 *
 * It isn't very efficient, but should be OK for the sorts of
 * applications that use it. When we need efficient broadcast we can add
 * it.
 *
 * @param n_sent Set to the number of messages sent.  This should be
 * equal to the number of processes, but be careful for races.
 *
 * @retval True for success.
 **/
bool message_send_all(struct messaging_context *msg_ctx,
		      int msg_type,
		      const void *buf, size_t len,
		      int *n_sent)
{
	struct msg_all msg_all;

	msg_all.msg_type = msg_type;
	if (msg_type < 0x100) {
		msg_all.msg_flag = FLAG_MSG_GENERAL;
	} else if (msg_type > 0x100 && msg_type < 0x200) {
		msg_all.msg_flag = FLAG_MSG_NMBD;
	} else if (msg_type > 0x200 && msg_type < 0x300) {
		msg_all.msg_flag = FLAG_MSG_PRINT_GENERAL;
	} else if (msg_type > 0x300 && msg_type < 0x400) {
		msg_all.msg_flag = FLAG_MSG_SMBD;
	} else if (msg_type > 0x400 && msg_type < 0x600) {
		msg_all.msg_flag = FLAG_MSG_WINBIND;
	} else if (msg_type > 4000 && msg_type < 5000) {
		msg_all.msg_flag = FLAG_MSG_DBWRAP;
	} else {
		return false;
	}

	msg_all.buf = buf;
	msg_all.len = len;
	msg_all.n_sent = 0;
	msg_all.msg_ctx = msg_ctx;

	serverid_traverse(traverse_fn, &msg_all);
	if (n_sent)
		*n_sent = msg_all.n_sent;
	return true;
}

static void messaging_recv_cb(const uint8_t *msg, size_t msg_len,
			      int *fds, size_t num_fds,
			      void *private_data)
{
	struct messaging_context *msg_ctx = talloc_get_type_abort(
		private_data, struct messaging_context);
	struct server_id_buf idbuf;
	struct messaging_rec rec;
	int64_t fds64[MIN(num_fds, INT8_MAX)];
	size_t i;

	if (msg_len < MESSAGE_HDR_LENGTH) {
		DEBUG(1, ("message too short: %u\n", (unsigned)msg_len));
		goto close_fail;
	}

	if (num_fds > INT8_MAX) {
		DEBUG(1, ("too many fds: %u\n", (unsigned)num_fds));
		goto close_fail;
	}

	/*
	 * "consume" the fds by copying them and setting
	 * the original variable to -1
	 */
	for (i=0; i < num_fds; i++) {
		fds64[i] = fds[i];
		fds[i] = -1;
	}

	rec = (struct messaging_rec) {
		.msg_version = MESSAGE_VERSION,
		.buf.data = discard_const_p(uint8_t, msg) + MESSAGE_HDR_LENGTH,
		.buf.length = msg_len - MESSAGE_HDR_LENGTH,
		.num_fds = num_fds,
		.fds = fds64,
	};

	message_hdr_get(&rec.msg_type, &rec.src, &rec.dest, msg);

	DEBUG(10, ("%s: Received message 0x%x len %u (num_fds:%u) from %s\n",
		   __func__, (unsigned)rec.msg_type,
		   (unsigned)rec.buf.length,
		   (unsigned)num_fds,
		   server_id_str_buf(rec.src, &idbuf)));

	messaging_dispatch_rec(msg_ctx, &rec);
	return;

close_fail:
	for (i=0; i < num_fds; i++) {
		close(fds[i]);
	}
}

static int messaging_context_destructor(struct messaging_context *ctx)
{
	unsigned i;

	for (i=0; i<ctx->num_new_waiters; i++) {
		if (ctx->new_waiters[i] != NULL) {
			tevent_req_set_cleanup_fn(ctx->new_waiters[i], NULL);
			ctx->new_waiters[i] = NULL;
		}
	}
	for (i=0; i<ctx->num_waiters; i++) {
		if (ctx->waiters[i] != NULL) {
			tevent_req_set_cleanup_fn(ctx->waiters[i], NULL);
			ctx->waiters[i] = NULL;
		}
	}

	return 0;
}

static const char *private_path(const char *name)
{
	return talloc_asprintf(talloc_tos(), "%s/%s", lp_private_dir(), name);
}

struct messaging_context *messaging_init(TALLOC_CTX *mem_ctx, 
					 struct tevent_context *ev)
{
	struct messaging_context *ctx;
	int ret;
	const char *lck_path;
	const char *priv_path;
	bool ok;

	if (!(ctx = talloc_zero(mem_ctx, struct messaging_context))) {
		return NULL;
	}

	ctx->id = (struct server_id) {
		.pid = getpid(), .vnn = NONCLUSTER_VNN
	};

	ctx->event_ctx = ev;

	sec_init();

	lck_path = lock_path("msg.lock");
	if (lck_path == NULL) {
		TALLOC_FREE(ctx);
		return NULL;
	}

	ok = directory_create_or_exist_strict(lck_path, sec_initial_uid(),
					      0755);
	if (!ok) {
		DEBUG(10, ("%s: Could not create lock directory: %s\n",
			   __func__, strerror(errno)));
		TALLOC_FREE(ctx);
		return NULL;
	}

	priv_path = private_path("msg.sock");
	if (priv_path == NULL) {
		TALLOC_FREE(ctx);
		return NULL;
	}

	ok = directory_create_or_exist_strict(priv_path, sec_initial_uid(),
					      0700);
	if (!ok) {
		DEBUG(10, ("%s: Could not create msg directory: %s\n",
			   __func__, strerror(errno)));
		TALLOC_FREE(ctx);
		return NULL;
	}

	ctx->msg_dgm_ref = messaging_dgm_ref(
		ctx, ctx->event_ctx, &ctx->id.unique_id,
		priv_path, lck_path, messaging_recv_cb, ctx, &ret);

	if (ctx->msg_dgm_ref == NULL) {
		DEBUG(2, ("messaging_dgm_ref failed: %s\n", strerror(ret)));
		TALLOC_FREE(ctx);
		return NULL;
	}

	talloc_set_destructor(ctx, messaging_context_destructor);

	if (lp_clustering()) {
		ret = messaging_ctdbd_init(ctx, ctx, &ctx->remote);

		if (ret != 0) {
			DEBUG(2, ("messaging_ctdbd_init failed: %s\n",
				  strerror(ret)));
			TALLOC_FREE(ctx);
			return NULL;
		}
	}
	ctx->id.vnn = get_my_vnn();

	ctx->names_db = server_id_db_init(
		ctx, ctx->id, lp_lock_directory(), 0,
		TDB_INCOMPATIBLE_HASH|TDB_CLEAR_IF_FIRST);
	if (ctx->names_db == NULL) {
		DEBUG(10, ("%s: server_id_db_init failed\n", __func__));
		TALLOC_FREE(ctx);
		return NULL;
	}

	messaging_register(ctx, NULL, MSG_PING, ping_message);

	/* Register some debugging related messages */

	register_msg_pool_usage(ctx);
	register_dmalloc_msgs(ctx);
	debug_register_msgs(ctx);

	return ctx;
}

struct server_id messaging_server_id(const struct messaging_context *msg_ctx)
{
	return msg_ctx->id;
}

/*
 * re-init after a fork
 */
NTSTATUS messaging_reinit(struct messaging_context *msg_ctx)
{
	int ret;

	TALLOC_FREE(msg_ctx->msg_dgm_ref);

	msg_ctx->id = (struct server_id) {
		.pid = getpid(), .vnn = msg_ctx->id.vnn
	};

	msg_ctx->msg_dgm_ref = messaging_dgm_ref(
		msg_ctx, msg_ctx->event_ctx, &msg_ctx->id.unique_id,
		private_path("msg.sock"), lock_path("msg.lock"),
		messaging_recv_cb, msg_ctx, &ret);

	if (msg_ctx->msg_dgm_ref == NULL) {
		DEBUG(2, ("messaging_dgm_ref failed: %s\n", strerror(ret)));
		return map_nt_error_from_unix(ret);
	}

	TALLOC_FREE(msg_ctx->remote);

	if (lp_clustering()) {
		ret = messaging_ctdbd_init(msg_ctx, msg_ctx,
					   &msg_ctx->remote);

		if (ret != 0) {
			DEBUG(1, ("messaging_ctdbd_init failed: %s\n",
				  strerror(ret)));
			return map_nt_error_from_unix(ret);
		}
	}

	server_id_db_reinit(msg_ctx->names_db, msg_ctx->id);

	return NT_STATUS_OK;
}


/*
 * Register a dispatch function for a particular message type. Allow multiple
 * registrants
*/
NTSTATUS messaging_register(struct messaging_context *msg_ctx,
			    void *private_data,
			    uint32_t msg_type,
			    void (*fn)(struct messaging_context *msg,
				       void *private_data, 
				       uint32_t msg_type, 
				       struct server_id server_id,
				       DATA_BLOB *data))
{
	struct messaging_callback *cb;

	DEBUG(5, ("Registering messaging pointer for type %u - "
		  "private_data=%p\n",
		  (unsigned)msg_type, private_data));

	/*
	 * Only one callback per type
	 */

	for (cb = msg_ctx->callbacks; cb != NULL; cb = cb->next) {
		/* we allow a second registration of the same message
		   type if it has a different private pointer. This is
		   needed in, for example, the internal notify code,
		   which creates a new notify context for each tree
		   connect, and expects to receive messages to each of
		   them. */
		if (cb->msg_type == msg_type && private_data == cb->private_data) {
			DEBUG(5,("Overriding messaging pointer for type %u - private_data=%p\n",
				  (unsigned)msg_type, private_data));
			cb->fn = fn;
			cb->private_data = private_data;
			return NT_STATUS_OK;
		}
	}

	if (!(cb = talloc(msg_ctx, struct messaging_callback))) {
		return NT_STATUS_NO_MEMORY;
	}

	cb->msg_type = msg_type;
	cb->fn = fn;
	cb->private_data = private_data;

	DLIST_ADD(msg_ctx->callbacks, cb);
	return NT_STATUS_OK;
}

/*
  De-register the function for a particular message type.
*/
void messaging_deregister(struct messaging_context *ctx, uint32_t msg_type,
			  void *private_data)
{
	struct messaging_callback *cb, *next;

	for (cb = ctx->callbacks; cb; cb = next) {
		next = cb->next;
		if ((cb->msg_type == msg_type)
		    && (cb->private_data == private_data)) {
			DEBUG(5,("Deregistering messaging pointer for type %u - private_data=%p\n",
				  (unsigned)msg_type, private_data));
			DLIST_REMOVE(ctx->callbacks, cb);
			TALLOC_FREE(cb);
		}
	}
}

/*
  Send a message to a particular server
*/
NTSTATUS messaging_send(struct messaging_context *msg_ctx,
			struct server_id server, uint32_t msg_type,
			const DATA_BLOB *data)
{
	struct iovec iov;

	iov.iov_base = data->data;
	iov.iov_len = data->length;

	return messaging_send_iov(msg_ctx, server, msg_type, &iov, 1, NULL, 0);
}

NTSTATUS messaging_send_buf(struct messaging_context *msg_ctx,
			    struct server_id server, uint32_t msg_type,
			    const uint8_t *buf, size_t len)
{
	DATA_BLOB blob = data_blob_const(buf, len);
	return messaging_send(msg_ctx, server, msg_type, &blob);
}

int messaging_send_iov_from(struct messaging_context *msg_ctx,
			    struct server_id src, struct server_id dst,
			    uint32_t msg_type,
			    const struct iovec *iov, int iovlen,
			    const int *fds, size_t num_fds)
{
	int ret;
	uint8_t hdr[MESSAGE_HDR_LENGTH];
	struct iovec iov2[iovlen+1];

	if (server_id_is_disconnected(&dst)) {
		return EINVAL;
	}

	if (num_fds > INT8_MAX) {
		return EINVAL;
	}

	if (!procid_is_local(&dst)) {
		if (num_fds > 0) {
			return ENOSYS;
		}

		ret = msg_ctx->remote->send_fn(src, dst,
					       msg_type, iov, iovlen,
					       NULL, 0,
					       msg_ctx->remote);
		return ret;
	}

	message_hdr_put(hdr, msg_type, src, dst);
	iov2[0] = (struct iovec){ .iov_base = hdr, .iov_len = sizeof(hdr) };
	memcpy(&iov2[1], iov, iovlen * sizeof(*iov));

	become_root();
	ret = messaging_dgm_send(dst.pid, iov2, iovlen+1, fds, num_fds);
	unbecome_root();

	return ret;
}

NTSTATUS messaging_send_iov(struct messaging_context *msg_ctx,
			    struct server_id dst, uint32_t msg_type,
			    const struct iovec *iov, int iovlen,
			    const int *fds, size_t num_fds)
{
	int ret;

	ret = messaging_send_iov_from(msg_ctx, msg_ctx->id, dst, msg_type,
				      iov, iovlen, fds, num_fds);
	if (ret != 0) {
		return map_nt_error_from_unix(ret);
	}
	return NT_STATUS_OK;
}

static struct messaging_rec *messaging_rec_dup(TALLOC_CTX *mem_ctx,
					       struct messaging_rec *rec)
{
	struct messaging_rec *result;
	size_t fds_size = sizeof(int64_t) * rec->num_fds;

	result = talloc_pooled_object(mem_ctx, struct messaging_rec, 2,
				      rec->buf.length + fds_size);
	if (result == NULL) {
		return NULL;
	}
	*result = *rec;

	/* Doesn't fail, see talloc_pooled_object */

	result->buf.data = talloc_memdup(result, rec->buf.data,
					 rec->buf.length);

	result->fds = NULL;
	if (result->num_fds > 0) {
		result->fds = talloc_memdup(result, rec->fds, fds_size);
	}

	return result;
}

struct messaging_filtered_read_state {
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	void *tevent_handle;

	bool (*filter)(struct messaging_rec *rec, void *private_data);
	void *private_data;

	struct messaging_rec *rec;
};

static void messaging_filtered_read_cleanup(struct tevent_req *req,
					    enum tevent_req_state req_state);

struct tevent_req *messaging_filtered_read_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct messaging_context *msg_ctx,
	bool (*filter)(struct messaging_rec *rec, void *private_data),
	void *private_data)
{
	struct tevent_req *req;
	struct messaging_filtered_read_state *state;
	size_t new_waiters_len;

	req = tevent_req_create(mem_ctx, &state,
				struct messaging_filtered_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->msg_ctx = msg_ctx;
	state->filter = filter;
	state->private_data = private_data;

	/*
	 * We have to defer the callback here, as we might be called from
	 * within a different tevent_context than state->ev
	 */
	tevent_req_defer_callback(req, state->ev);

	state->tevent_handle = messaging_dgm_register_tevent_context(
		state, ev);
	if (tevent_req_nomem(state->tevent_handle, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * We add ourselves to the "new_waiters" array, not the "waiters"
	 * array. If we are called from within messaging_read_done,
	 * messaging_dispatch_rec will be in an active for-loop on
	 * "waiters". We must be careful not to mess with this array, because
	 * it could mean that a single event is being delivered twice.
	 */

	new_waiters_len = talloc_array_length(msg_ctx->new_waiters);

	if (new_waiters_len == msg_ctx->num_new_waiters) {
		struct tevent_req **tmp;

		tmp = talloc_realloc(msg_ctx, msg_ctx->new_waiters,
				     struct tevent_req *, new_waiters_len+1);
		if (tevent_req_nomem(tmp, req)) {
			return tevent_req_post(req, ev);
		}
		msg_ctx->new_waiters = tmp;
	}

	msg_ctx->new_waiters[msg_ctx->num_new_waiters] = req;
	msg_ctx->num_new_waiters += 1;
	tevent_req_set_cleanup_fn(req, messaging_filtered_read_cleanup);

	return req;
}

static void messaging_filtered_read_cleanup(struct tevent_req *req,
					    enum tevent_req_state req_state)
{
	struct messaging_filtered_read_state *state = tevent_req_data(
		req, struct messaging_filtered_read_state);
	struct messaging_context *msg_ctx = state->msg_ctx;
	unsigned i;

	tevent_req_set_cleanup_fn(req, NULL);

	TALLOC_FREE(state->tevent_handle);

	/*
	 * Just set the [new_]waiters entry to NULL, be careful not to mess
	 * with the other "waiters" array contents. We are often called from
	 * within "messaging_dispatch_rec", which loops over
	 * "waiters". Messing with the "waiters" array will mess up that
	 * for-loop.
	 */

	for (i=0; i<msg_ctx->num_waiters; i++) {
		if (msg_ctx->waiters[i] == req) {
			msg_ctx->waiters[i] = NULL;
			return;
		}
	}

	for (i=0; i<msg_ctx->num_new_waiters; i++) {
		if (msg_ctx->new_waiters[i] == req) {
			msg_ctx->new_waiters[i] = NULL;
			return;
		}
	}
}

static void messaging_filtered_read_done(struct tevent_req *req,
					 struct messaging_rec *rec)
{
	struct messaging_filtered_read_state *state = tevent_req_data(
		req, struct messaging_filtered_read_state);

	state->rec = messaging_rec_dup(state, rec);
	if (tevent_req_nomem(state->rec, req)) {
		return;
	}
	tevent_req_done(req);
}

int messaging_filtered_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				 struct messaging_rec **presult)
{
	struct messaging_filtered_read_state *state = tevent_req_data(
		req, struct messaging_filtered_read_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		tevent_req_received(req);
		return err;
	}
	*presult = talloc_move(mem_ctx, &state->rec);
	return 0;
}

struct messaging_read_state {
	uint32_t msg_type;
	struct messaging_rec *rec;
};

static bool messaging_read_filter(struct messaging_rec *rec,
				  void *private_data);
static void messaging_read_done(struct tevent_req *subreq);

struct tevent_req *messaging_read_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct messaging_context *msg,
				       uint32_t msg_type)
{
	struct tevent_req *req, *subreq;
	struct messaging_read_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct messaging_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->msg_type = msg_type;

	subreq = messaging_filtered_read_send(state, ev, msg,
					      messaging_read_filter, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, messaging_read_done, req);
	return req;
}

static bool messaging_read_filter(struct messaging_rec *rec,
				  void *private_data)
{
	struct messaging_read_state *state = talloc_get_type_abort(
		private_data, struct messaging_read_state);

	if (rec->num_fds != 0) {
		return false;
	}

	return rec->msg_type == state->msg_type;
}

static void messaging_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct messaging_read_state *state = tevent_req_data(
		req, struct messaging_read_state);
	int ret;

	ret = messaging_filtered_read_recv(subreq, state, &state->rec);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	tevent_req_done(req);
}

int messaging_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			struct messaging_rec **presult)
{
	struct messaging_read_state *state = tevent_req_data(
		req, struct messaging_read_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	if (presult != NULL) {
		*presult = talloc_move(mem_ctx, &state->rec);
	}
	return 0;
}

struct messaging_handler_state {
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	uint32_t msg_type;
	bool (*handler)(struct messaging_context *msg_ctx,
			struct messaging_rec **rec, void *private_data);
	void *private_data;
};

static void messaging_handler_got_msg(struct tevent_req *subreq);

struct tevent_req *messaging_handler_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct messaging_context *msg_ctx, uint32_t msg_type,
	bool (*handler)(struct messaging_context *msg_ctx,
			struct messaging_rec **rec, void *private_data),
	void *private_data)
{
	struct tevent_req *req, *subreq;
	struct messaging_handler_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct messaging_handler_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->msg_ctx = msg_ctx;
	state->msg_type = msg_type;
	state->handler = handler;
	state->private_data = private_data;

	subreq = messaging_read_send(state, state->ev, state->msg_ctx,
				     state->msg_type);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, messaging_handler_got_msg, req);
	return req;
}

static void messaging_handler_got_msg(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct messaging_handler_state *state = tevent_req_data(
		req, struct messaging_handler_state);
	struct messaging_rec *rec;
	int ret;
	bool ok;

	ret = messaging_read_recv(subreq, state, &rec);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	subreq = messaging_read_send(state, state->ev, state->msg_ctx,
				     state->msg_type);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, messaging_handler_got_msg, req);

	ok = state->handler(state->msg_ctx, &rec, state->private_data);
	TALLOC_FREE(rec);
	if (ok) {
		/*
		 * Next round
		 */
		return;
	}
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

int messaging_handler_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

static bool messaging_append_new_waiters(struct messaging_context *msg_ctx)
{
	if (msg_ctx->num_new_waiters == 0) {
		return true;
	}

	if (talloc_array_length(msg_ctx->waiters) <
	    (msg_ctx->num_waiters + msg_ctx->num_new_waiters)) {
		struct tevent_req **tmp;
		tmp = talloc_realloc(
			msg_ctx, msg_ctx->waiters, struct tevent_req *,
			msg_ctx->num_waiters + msg_ctx->num_new_waiters);
		if (tmp == NULL) {
			DEBUG(1, ("%s: talloc failed\n", __func__));
			return false;
		}
		msg_ctx->waiters = tmp;
	}

	memcpy(&msg_ctx->waiters[msg_ctx->num_waiters], msg_ctx->new_waiters,
	       sizeof(struct tevent_req *) * msg_ctx->num_new_waiters);

	msg_ctx->num_waiters += msg_ctx->num_new_waiters;
	msg_ctx->num_new_waiters = 0;

	return true;
}

/*
  Dispatch one messaging_rec
*/
static void messaging_dispatch_rec(struct messaging_context *msg_ctx,
				   struct messaging_rec *rec)
{
	struct messaging_callback *cb, *next;
	unsigned i;
	size_t j;

	for (cb = msg_ctx->callbacks; cb != NULL; cb = next) {
		next = cb->next;
		if (cb->msg_type != rec->msg_type) {
			continue;
		}

		/*
		 * the old style callbacks don't support fd passing
		 */
		for (j=0; j < rec->num_fds; j++) {
			int fd = rec->fds[j];
			close(fd);
		}
		rec->num_fds = 0;
		rec->fds = NULL;

		cb->fn(msg_ctx, cb->private_data, rec->msg_type,
		       rec->src, &rec->buf);

		/*
		 * we continue looking for matching messages after finding
		 * one. This matters for subsystems like the internal notify
		 * code which register more than one handler for the same
		 * message type
		 */
	}

	if (!messaging_append_new_waiters(msg_ctx)) {
		for (j=0; j < rec->num_fds; j++) {
			int fd = rec->fds[j];
			close(fd);
		}
		rec->num_fds = 0;
		rec->fds = NULL;
		return;
	}

	i = 0;
	while (i < msg_ctx->num_waiters) {
		struct tevent_req *req;
		struct messaging_filtered_read_state *state;

		req = msg_ctx->waiters[i];
		if (req == NULL) {
			/*
			 * This got cleaned up. In the meantime,
			 * move everything down one. We need
			 * to keep the order of waiters, as
			 * other code may depend on this.
			 */
			if (i < msg_ctx->num_waiters - 1) {
				memmove(&msg_ctx->waiters[i],
					&msg_ctx->waiters[i+1],
					sizeof(struct tevent_req *) *
					    (msg_ctx->num_waiters - i - 1));
			}
			msg_ctx->num_waiters -= 1;
			continue;
		}

		state = tevent_req_data(
			req, struct messaging_filtered_read_state);
		if (state->filter(rec, state->private_data)) {
			messaging_filtered_read_done(req, rec);

			/*
			 * Only the first one gets the fd-array
			 */
			rec->num_fds = 0;
			rec->fds = NULL;
		}

		i += 1;
	}

	/*
	 * If the fd-array isn't used, just close it.
	 */
	for (j=0; j < rec->num_fds; j++) {
		int fd = rec->fds[j];
		close(fd);
	}
	rec->num_fds = 0;
	rec->fds = NULL;
}

static int mess_parent_dgm_cleanup(void *private_data);
static void mess_parent_dgm_cleanup_done(struct tevent_req *req);

bool messaging_parent_dgm_cleanup_init(struct messaging_context *msg)
{
	struct tevent_req *req;

	req = background_job_send(
		msg, msg->event_ctx, msg, NULL, 0,
		lp_parm_int(-1, "messaging", "messaging dgm cleanup interval",
			    60*15),
		mess_parent_dgm_cleanup, msg);
	if (req == NULL) {
		return false;
	}
	tevent_req_set_callback(req, mess_parent_dgm_cleanup_done, msg);
	return true;
}

static int mess_parent_dgm_cleanup(void *private_data)
{
	int ret;

	ret = messaging_dgm_wipe();
	DEBUG(10, ("messaging_dgm_wipe returned %s\n",
		   ret ? strerror(ret) : "ok"));
	return lp_parm_int(-1, "messaging", "messaging dgm cleanup interval",
			   60*15);
}

static void mess_parent_dgm_cleanup_done(struct tevent_req *req)
{
	struct messaging_context *msg = tevent_req_callback_data(
		req, struct messaging_context);
	NTSTATUS status;

	status = background_job_recv(req);
	TALLOC_FREE(req);
	DEBUG(1, ("messaging dgm cleanup job ended with %s\n",
		  nt_errstr(status)));

	req = background_job_send(
		msg, msg->event_ctx, msg, NULL, 0,
		lp_parm_int(-1, "messaging", "messaging dgm cleanup interval",
			    60*15),
		mess_parent_dgm_cleanup, msg);
	if (req == NULL) {
		DEBUG(1, ("background_job_send failed\n"));
		return;
	}
	tevent_req_set_callback(req, mess_parent_dgm_cleanup_done, msg);
}

int messaging_cleanup(struct messaging_context *msg_ctx, pid_t pid)
{
	int ret;

	if (pid == 0) {
		ret = messaging_dgm_wipe();
	} else {
		ret = messaging_dgm_cleanup(pid);
	}

	return ret;
}

struct tevent_context *messaging_tevent_context(
	struct messaging_context *msg_ctx)
{
	return msg_ctx->event_ctx;
}

struct server_id_db *messaging_names_db(struct messaging_context *msg_ctx)
{
	return msg_ctx->names_db;
}

/** @} **/
