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
#include "lib/util/server_id.h"
#include "dbwrap/dbwrap.h"
#include "serverid.h"
#include "messages.h"
#include "lib/util/tevent_unix.h"
#include "lib/background.h"
#include "lib/messaging/messages_dgm.h"
#include "lib/util/iov_buf.h"
#include "lib/util/server_id_db.h"
#include "lib/messaging/messages_dgm_ref.h"
#include "lib/messages_ctdb.h"
#include "lib/messages_ctdb_ref.h"
#include "lib/messages_util.h"
#include "cluster_support.h"
#include "ctdbd_conn.h"
#include "ctdb_srvids.h"

#ifdef CLUSTER_SUPPORT
#include "ctdb_protocol.h"
#endif

struct messaging_callback {
	struct messaging_callback *prev, *next;
	uint32_t msg_type;
	void (*fn)(struct messaging_context *msg, void *private_data, 
		   uint32_t msg_type, 
		   struct server_id server_id, DATA_BLOB *data);
	void *private_data;
};

struct messaging_registered_ev {
	struct tevent_context *ev;
	struct tevent_immediate *im;
	size_t refcount;
};

struct messaging_context {
	struct server_id id;
	struct tevent_context *event_ctx;
	struct messaging_callback *callbacks;

	struct messaging_rec *posted_msgs;

	struct messaging_registered_ev *event_contexts;

	struct tevent_req **new_waiters;
	size_t num_new_waiters;

	struct tevent_req **waiters;
	size_t num_waiters;

	struct server_id_db *names_db;

	TALLOC_CTX *per_process_talloc_ctx;
};

static struct messaging_rec *messaging_rec_dup(TALLOC_CTX *mem_ctx,
					       struct messaging_rec *rec);
static bool messaging_dispatch_classic(struct messaging_context *msg_ctx,
				       struct messaging_rec *rec);
static bool messaging_dispatch_waiters(struct messaging_context *msg_ctx,
				       struct tevent_context *ev,
				       struct messaging_rec *rec);
static void messaging_dispatch_rec(struct messaging_context *msg_ctx,
				   struct tevent_context *ev,
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

struct messaging_rec *messaging_rec_create(
	TALLOC_CTX *mem_ctx, struct server_id src, struct server_id dst,
	uint32_t msg_type, const struct iovec *iov, int iovlen,
	const int *fds, size_t num_fds)
{
	ssize_t buflen;
	uint8_t *buf;
	struct messaging_rec *result;

	if (num_fds > INT8_MAX) {
		return NULL;
	}

	buflen = iov_buflen(iov, iovlen);
	if (buflen == -1) {
		return NULL;
	}
	buf = talloc_array(mem_ctx, uint8_t, buflen);
	if (buf == NULL) {
		return NULL;
	}
	iov_buf(iov, iovlen, buf, buflen);

	{
		struct messaging_rec rec;
		int64_t fds64[MAX(1, num_fds)];
		size_t i;

		for (i=0; i<num_fds; i++) {
			fds64[i] = fds[i];
		}

		rec = (struct messaging_rec) {
			.msg_version = MESSAGE_VERSION, .msg_type = msg_type,
			.src = src, .dest = dst,
			.buf.data = buf, .buf.length = buflen,
			.num_fds = num_fds, .fds = fds64,
		};

		result = messaging_rec_dup(mem_ctx, &rec);
	}

	TALLOC_FREE(buf);

	return result;
}

static bool messaging_register_event_context(struct messaging_context *ctx,
					     struct tevent_context *ev)
{
	size_t i, num_event_contexts;
	struct messaging_registered_ev *free_reg = NULL;
	struct messaging_registered_ev *tmp;

	num_event_contexts = talloc_array_length(ctx->event_contexts);

	for (i=0; i<num_event_contexts; i++) {
		struct messaging_registered_ev *reg = &ctx->event_contexts[i];

		if (reg->refcount == 0) {
			if (reg->ev != NULL) {
				abort();
			}
			free_reg = reg;
			/*
			 * We continue here and may find another
			 * free_req, but the important thing is
			 * that we continue to search for an
			 * existing registration in the loop.
			 */
			continue;
		}

		if (reg->ev == ev) {
			reg->refcount += 1;
			return true;
		}
	}

	if (free_reg == NULL) {
		struct tevent_immediate *im = NULL;

		im = tevent_create_immediate(ctx);
		if (im == NULL) {
			return false;
		}

		tmp = talloc_realloc(ctx, ctx->event_contexts,
				     struct messaging_registered_ev,
				     num_event_contexts+1);
		if (tmp == NULL) {
			return false;
		}
		ctx->event_contexts = tmp;

		free_reg = &ctx->event_contexts[num_event_contexts];
		free_reg->im = talloc_move(ctx->event_contexts, &im);
	}

	/*
	 * free_reg->im might be cached
	 */
	free_reg->ev = ev;
	free_reg->refcount = 1;

	return true;
}

static bool messaging_deregister_event_context(struct messaging_context *ctx,
					       struct tevent_context *ev)
{
	size_t i, num_event_contexts;

	num_event_contexts = talloc_array_length(ctx->event_contexts);

	for (i=0; i<num_event_contexts; i++) {
		struct messaging_registered_ev *reg = &ctx->event_contexts[i];

		if (reg->refcount == 0) {
			continue;
		}

		if (reg->ev == ev) {
			reg->refcount -= 1;

			if (reg->refcount == 0) {
				/*
				 * The primary event context
				 * is never unregistered using
				 * messaging_deregister_event_context()
				 * it's only registered using
				 * messaging_register_event_context().
				 */
				SMB_ASSERT(ev != ctx->event_ctx);
				SMB_ASSERT(reg->ev != ctx->event_ctx);

				/*
				 * Not strictly necessary, just
				 * paranoia
				 */
				reg->ev = NULL;

				/*
				 * Do not talloc_free(reg->im),
				 * recycle immediates events.
				 *
				 * We just invalidate it using
				 * the primary event context,
				 * which is never unregistered.
				 */
				tevent_schedule_immediate(reg->im,
							  ctx->event_ctx,
							  NULL, NULL);
			}
			return true;
		}
	}
	return false;
}

static void messaging_post_main_event_context(struct tevent_context *ev,
					      struct tevent_immediate *im,
					      void *private_data)
{
	struct messaging_context *ctx = talloc_get_type_abort(
		private_data, struct messaging_context);

	while (ctx->posted_msgs != NULL) {
		struct messaging_rec *rec = ctx->posted_msgs;
		bool consumed;

		DLIST_REMOVE(ctx->posted_msgs, rec);

		consumed = messaging_dispatch_classic(ctx, rec);
		if (!consumed) {
			consumed = messaging_dispatch_waiters(
				ctx, ctx->event_ctx, rec);
		}

		if (!consumed) {
			uint8_t i;

			for (i=0; i<rec->num_fds; i++) {
				close(rec->fds[i]);
			}
		}

		TALLOC_FREE(rec);
	}
}

static void messaging_post_sub_event_context(struct tevent_context *ev,
					     struct tevent_immediate *im,
					     void *private_data)
{
	struct messaging_context *ctx = talloc_get_type_abort(
		private_data, struct messaging_context);
	struct messaging_rec *rec, *next;

	for (rec = ctx->posted_msgs; rec != NULL; rec = next) {
		bool consumed;

		next = rec->next;

		consumed = messaging_dispatch_waiters(ctx, ev, rec);
		if (consumed) {
			DLIST_REMOVE(ctx->posted_msgs, rec);
			TALLOC_FREE(rec);
		}
	}
}

static bool messaging_alert_event_contexts(struct messaging_context *ctx)
{
	size_t i, num_event_contexts;

	num_event_contexts = talloc_array_length(ctx->event_contexts);

	for (i=0; i<num_event_contexts; i++) {
		struct messaging_registered_ev *reg = &ctx->event_contexts[i];

		if (reg->refcount == 0) {
			continue;
		}

		/*
		 * We depend on schedule_immediate to work
		 * multiple times. Might be a bit inefficient,
		 * but this needs to be proven in tests. The
		 * alternatively would be to track whether the
		 * immediate has already been scheduled. For
		 * now, avoid that complexity here.
		 */

		if (reg->ev == ctx->event_ctx) {
			tevent_schedule_immediate(
				reg->im, reg->ev,
				messaging_post_main_event_context,
				ctx);
		} else {
			tevent_schedule_immediate(
				reg->im, reg->ev,
				messaging_post_sub_event_context,
				ctx);
		}

	}
	return true;
}

static void messaging_recv_cb(struct tevent_context *ev,
			      const uint8_t *msg, size_t msg_len,
			      int *fds, size_t num_fds,
			      void *private_data)
{
	struct messaging_context *msg_ctx = talloc_get_type_abort(
		private_data, struct messaging_context);
	struct server_id_buf idbuf;
	struct messaging_rec rec;
	int64_t fds64[MAX(1, MIN(num_fds, INT8_MAX))];
	size_t i;

	if (msg_len < MESSAGE_HDR_LENGTH) {
		DBG_WARNING("message too short: %zu\n", msg_len);
		goto close_fail;
	}

	if (num_fds > INT8_MAX) {
		DBG_WARNING("too many fds: %zu\n", num_fds);
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

	DBG_DEBUG("Received message 0x%x len %zu (num_fds:%zu) from %s\n",
		  (unsigned)rec.msg_type, rec.buf.length, num_fds,
		  server_id_str_buf(rec.src, &idbuf));

	if (server_id_same_process(&rec.src, &msg_ctx->id)) {
		DBG_DEBUG("Ignoring self-send\n");
		goto close_fail;
	}

	messaging_dispatch_rec(msg_ctx, ev, &rec);
	return;

close_fail:
	for (i=0; i < num_fds; i++) {
		close(fds[i]);
	}
}

static int messaging_context_destructor(struct messaging_context *ctx)
{
	size_t i;

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

	/*
	 * The immediates from messaging_alert_event_contexts
	 * reference "ctx". Don't let them outlive the
	 * messaging_context we're destroying here.
	 */
	TALLOC_FREE(ctx->event_contexts);

	return 0;
}

static const char *private_path(const char *name)
{
	return talloc_asprintf(talloc_tos(), "%s/%s", lp_private_dir(), name);
}

static NTSTATUS messaging_init_internal(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct messaging_context **pmsg_ctx)
{
	TALLOC_CTX *frame;
	struct messaging_context *ctx;
	NTSTATUS status;
	int ret;
	const char *lck_path;
	const char *priv_path;
	void *ref;
	bool ok;

	/*
	 * sec_init() *must* be called before any other
	 * functions that use sec_XXX(). e.g. sec_initial_uid().
	 */

	sec_init();

	lck_path = lock_path(talloc_tos(), "msg.lock");
	if (lck_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ok = directory_create_or_exist_strict(lck_path,
					      sec_initial_uid(),
					      0755);
	if (!ok) {
		DBG_DEBUG("Could not create lock directory: %s\n",
			  strerror(errno));
		return NT_STATUS_ACCESS_DENIED;
	}

	priv_path = private_path("msg.sock");
	if (priv_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ok = directory_create_or_exist_strict(priv_path, sec_initial_uid(),
					      0700);
	if (!ok) {
		DBG_DEBUG("Could not create msg directory: %s\n",
			  strerror(errno));
		return NT_STATUS_ACCESS_DENIED;
	}

	frame = talloc_stackframe();
	if (frame == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ctx = talloc_zero(frame, struct messaging_context);
	if (ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ctx->id = (struct server_id) {
		.pid = getpid(), .vnn = NONCLUSTER_VNN
	};

	ctx->event_ctx = ev;

	ctx->per_process_talloc_ctx = talloc_new(ctx);
	if (ctx->per_process_talloc_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ok = messaging_register_event_context(ctx, ev);
	if (!ok) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ref = messaging_dgm_ref(
		ctx->per_process_talloc_ctx,
		ctx->event_ctx,
		&ctx->id.unique_id,
		priv_path,
		lck_path,
		messaging_recv_cb,
		ctx,
		&ret);
	if (ref == NULL) {
		DEBUG(2, ("messaging_dgm_ref failed: %s\n", strerror(ret)));
		status = map_nt_error_from_unix(ret);
		goto done;
	}
	talloc_set_destructor(ctx, messaging_context_destructor);

#ifdef CLUSTER_SUPPORT
	if (lp_clustering()) {
		ref = messaging_ctdb_ref(
			ctx->per_process_talloc_ctx,
			ctx->event_ctx,
			lp_ctdbd_socket(),
			lp_ctdb_timeout(),
			ctx->id.unique_id,
			messaging_recv_cb,
			ctx,
			&ret);
		if (ref == NULL) {
			DBG_NOTICE("messaging_ctdb_ref failed: %s\n",
				   strerror(ret));
			status = map_nt_error_from_unix(ret);
			goto done;
		}
	}
#endif

	ctx->id.vnn = get_my_vnn();

	ctx->names_db = server_id_db_init(ctx,
					  ctx->id,
					  lp_lock_directory(),
					  0,
					  TDB_INCOMPATIBLE_HASH|TDB_CLEAR_IF_FIRST);
	if (ctx->names_db == NULL) {
		DBG_DEBUG("server_id_db_init failed\n");
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	messaging_register(ctx, NULL, MSG_PING, ping_message);

	/* Register some debugging related messages */

	register_msg_pool_usage(ctx->per_process_talloc_ctx, ctx);
	register_dmalloc_msgs(ctx);
	debug_register_msgs(ctx);

	{
		struct server_id_buf tmp;
		DBG_DEBUG("my id: %s\n", server_id_str_buf(ctx->id, &tmp));
	}

	*pmsg_ctx = talloc_steal(mem_ctx, ctx);

	status = NT_STATUS_OK;
done:
	TALLOC_FREE(frame);

	return status;
}

struct messaging_context *messaging_init(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev)
{
	struct messaging_context *ctx = NULL;
	NTSTATUS status;

	status = messaging_init_internal(mem_ctx,
					 ev,
					 &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

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
	char *lck_path;
	void *ref;

	TALLOC_FREE(msg_ctx->per_process_talloc_ctx);

	msg_ctx->per_process_talloc_ctx = talloc_new(msg_ctx);
	if (msg_ctx->per_process_talloc_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg_ctx->id = (struct server_id) {
		.pid = getpid(), .vnn = msg_ctx->id.vnn
	};

	lck_path = lock_path(talloc_tos(), "msg.lock");
	if (lck_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ref = messaging_dgm_ref(
		msg_ctx->per_process_talloc_ctx,
		msg_ctx->event_ctx,
		&msg_ctx->id.unique_id,
		private_path("msg.sock"),
		lck_path,
		messaging_recv_cb,
		msg_ctx,
		&ret);

	if (ref == NULL) {
		DEBUG(2, ("messaging_dgm_ref failed: %s\n", strerror(ret)));
		return map_nt_error_from_unix(ret);
	}

	if (lp_clustering()) {
		ref = messaging_ctdb_ref(
			msg_ctx->per_process_talloc_ctx,
			msg_ctx->event_ctx,
			lp_ctdbd_socket(),
			lp_ctdb_timeout(),
			msg_ctx->id.unique_id,
			messaging_recv_cb,
			msg_ctx,
			&ret);
		if (ref == NULL) {
			DBG_NOTICE("messaging_ctdb_ref failed: %s\n",
				   strerror(ret));
			return map_nt_error_from_unix(ret);
		}
	}

	server_id_db_reinit(msg_ctx->names_db, msg_ctx->id);
	register_msg_pool_usage(msg_ctx->per_process_talloc_ctx, msg_ctx);

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
	struct iovec iov = {0};

	if (data != NULL) {
		iov.iov_base = data->data;
		iov.iov_len = data->length;
	};

	return messaging_send_iov(msg_ctx, server, msg_type, &iov, 1, NULL, 0);
}

NTSTATUS messaging_send_buf(struct messaging_context *msg_ctx,
			    struct server_id server, uint32_t msg_type,
			    const uint8_t *buf, size_t len)
{
	DATA_BLOB blob = data_blob_const(buf, len);
	return messaging_send(msg_ctx, server, msg_type, &blob);
}

static int messaging_post_self(struct messaging_context *msg_ctx,
			       struct server_id src, struct server_id dst,
			       uint32_t msg_type,
			       const struct iovec *iov, int iovlen,
			       const int *fds, size_t num_fds)
{
	struct messaging_rec *rec;
	bool ok;

	rec = messaging_rec_create(
		msg_ctx, src, dst, msg_type, iov, iovlen, fds, num_fds);
	if (rec == NULL) {
		return ENOMEM;
	}

	ok = messaging_alert_event_contexts(msg_ctx);
	if (!ok) {
		TALLOC_FREE(rec);
		return ENOMEM;
	}

	DLIST_ADD_END(msg_ctx->posted_msgs, rec);

	return 0;
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

	if (server_id_equal(&dst, &msg_ctx->id)) {
		ret = messaging_post_self(msg_ctx, src, dst, msg_type,
					  iov, iovlen, fds, num_fds);
		return ret;
	}

	message_hdr_put(hdr, msg_type, src, dst);
	iov2[0] = (struct iovec){ .iov_base = hdr, .iov_len = sizeof(hdr) };
	memcpy(&iov2[1], iov, iovlen * sizeof(*iov));

	if (dst.vnn != msg_ctx->id.vnn) {
		if (num_fds > 0) {
			return ENOSYS;
		}

		ret = messaging_ctdb_send(dst.vnn, dst.pid, iov2, iovlen+1);
		return ret;
	}

	ret = messaging_dgm_send(dst.pid, iov2, iovlen+1, fds, num_fds);

	if (ret == EACCES) {
		become_root();
		ret = messaging_dgm_send(dst.pid, iov2, iovlen+1,
					 fds, num_fds);
		unbecome_root();
	}

	if (ret == ECONNREFUSED) {
		/*
		 * Linux returns this when a socket exists in the file
		 * system without a listening process. This is not
		 * documented in susv4 or the linux manpages, but it's
		 * easily testable. For the higher levels this is the
		 * same as "destination does not exist"
		 */
		ret = ENOENT;
	}

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

struct send_all_state {
	struct messaging_context *msg_ctx;
	int msg_type;
	const void *buf;
	size_t len;
};

static int send_all_fn(pid_t pid, void *private_data)
{
	struct send_all_state *state = private_data;
	NTSTATUS status;

	if (pid == getpid()) {
		DBG_DEBUG("Skip ourselves in messaging_send_all\n");
		return 0;
	}

	status = messaging_send_buf(state->msg_ctx, pid_to_procid(pid),
				    state->msg_type, state->buf, state->len);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("messaging_send_buf to %ju failed: %s\n",
			    (uintmax_t)pid, nt_errstr(status));
	}

	return 0;
}

void messaging_send_all(struct messaging_context *msg_ctx,
			int msg_type, const void *buf, size_t len)
{
	struct send_all_state state = {
		.msg_ctx = msg_ctx, .msg_type = msg_type,
		.buf = buf, .len = len
	};
	int ret;

#ifdef CLUSTER_SUPPORT
	if (lp_clustering()) {
		struct ctdbd_connection *conn = messaging_ctdb_connection();
		uint8_t msghdr[MESSAGE_HDR_LENGTH];
		struct iovec iov[] = {
			{ .iov_base = msghdr,
			  .iov_len = sizeof(msghdr) },
			{ .iov_base = discard_const_p(void, buf),
			  .iov_len = len }
		};

		message_hdr_put(msghdr, msg_type, messaging_server_id(msg_ctx),
				(struct server_id) {0});

		ret = ctdbd_messaging_send_iov(
			conn, CTDB_BROADCAST_CONNECTED,
			CTDB_SRVID_SAMBA_PROCESS,
			iov, ARRAY_SIZE(iov));
		if (ret != 0) {
			DBG_WARNING("ctdbd_messaging_send_iov failed: %s\n",
				    strerror(ret));
		}

		return;
	}
#endif

	ret = messaging_dgm_forall(send_all_fn, &state);
	if (ret != 0) {
		DBG_WARNING("messaging_dgm_forall failed: %s\n",
			    strerror(ret));
	}
}

static struct messaging_rec *messaging_rec_dup(TALLOC_CTX *mem_ctx,
					       struct messaging_rec *rec)
{
	struct messaging_rec *result;
	size_t fds_size = sizeof(int64_t) * rec->num_fds;
	size_t payload_len;

	payload_len = rec->buf.length + fds_size;
	if (payload_len < rec->buf.length) {
		/* overflow */
		return NULL;
	}

	result = talloc_pooled_object(mem_ctx, struct messaging_rec, 2,
				      payload_len);
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
	struct messaging_dgm_fde *fde;
	struct messaging_ctdb_fde *cluster_fde;

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
	bool ok;

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

	state->fde = messaging_dgm_register_tevent_context(state, ev);
	if (tevent_req_nomem(state->fde, req)) {
		return tevent_req_post(req, ev);
	}

	if (lp_clustering()) {
		state->cluster_fde =
			messaging_ctdb_register_tevent_context(state, ev);
		if (tevent_req_nomem(state->cluster_fde, req)) {
			return tevent_req_post(req, ev);
		}
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

	ok = messaging_register_event_context(msg_ctx, ev);
	if (!ok) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void messaging_filtered_read_cleanup(struct tevent_req *req,
					    enum tevent_req_state req_state)
{
	struct messaging_filtered_read_state *state = tevent_req_data(
		req, struct messaging_filtered_read_state);
	struct messaging_context *msg_ctx = state->msg_ctx;
	size_t i;
	bool ok;

	tevent_req_set_cleanup_fn(req, NULL);

	TALLOC_FREE(state->fde);
	TALLOC_FREE(state->cluster_fde);

	ok = messaging_deregister_event_context(msg_ctx, state->ev);
	if (!ok) {
		abort();
	}

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
	if (presult != NULL) {
		*presult = talloc_move(mem_ctx, &state->rec);
	}
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

static bool messaging_dispatch_classic(struct messaging_context *msg_ctx,
				       struct messaging_rec *rec)
{
	struct messaging_callback *cb, *next;

	for (cb = msg_ctx->callbacks; cb != NULL; cb = next) {
		size_t j;

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

		return true;
	}

	return false;
}

static bool messaging_dispatch_waiters(struct messaging_context *msg_ctx,
				       struct tevent_context *ev,
				       struct messaging_rec *rec)
{
	size_t i;

	if (!messaging_append_new_waiters(msg_ctx)) {
		return false;
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
			ARRAY_DEL_ELEMENT(
				msg_ctx->waiters, i, msg_ctx->num_waiters);
			msg_ctx->num_waiters -= 1;
			continue;
		}

		state = tevent_req_data(
			req, struct messaging_filtered_read_state);
		if ((ev == state->ev) &&
		    state->filter(rec, state->private_data)) {
			messaging_filtered_read_done(req, rec);
			return true;
		}

		i += 1;
	}

	return false;
}

/*
  Dispatch one messaging_rec
*/
static void messaging_dispatch_rec(struct messaging_context *msg_ctx,
				   struct tevent_context *ev,
				   struct messaging_rec *rec)
{
	bool consumed;
	size_t i;

	if (ev == msg_ctx->event_ctx) {
		consumed = messaging_dispatch_classic(msg_ctx, rec);
		if (consumed) {
			return;
		}
	}

	consumed = messaging_dispatch_waiters(msg_ctx, ev, rec);
	if (consumed) {
		return;
	}

	if (ev != msg_ctx->event_ctx) {
		struct iovec iov;
		int fds[MAX(1, rec->num_fds)];
		int ret;

		/*
		 * We've been listening on a nested event
		 * context. Messages need to be handled in the main
		 * event context, so post to ourselves
		 */

		iov.iov_base = rec->buf.data;
		iov.iov_len = rec->buf.length;

		for (i=0; i<rec->num_fds; i++) {
			fds[i] = rec->fds[i];
		}

		ret = messaging_post_self(
			msg_ctx, rec->src, rec->dest, rec->msg_type,
			&iov, 1, fds, rec->num_fds);
		if (ret == 0) {
			return;
		}
	}

	/*
	 * If the fd-array isn't used, just close it.
	 */
	for (i=0; i < rec->num_fds; i++) {
		int fd = rec->fds[i];
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
		DBG_WARNING("background_job_send failed\n");
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
