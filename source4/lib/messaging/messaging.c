/*
   Unix SMB/CIFS implementation.

   Samba internal messaging functions

   Copyright (C) Andrew Tridgell 2004

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
#include "lib/events/events.h"
#include "lib/util/server_id.h"
#include "system/filesys.h"
#include "messaging/messaging.h"
#include "messaging/messaging_internal.h"
#include "../lib/util/dlinklist.h"
#include "lib/socket/socket.h"
#include "librpc/gen_ndr/ndr_irpc.h"
#include "lib/messaging/irpc.h"
#include "../lib/util/unix_privs.h"
#include "librpc/rpc/dcerpc.h"
#include "cluster/cluster.h"
#include "../lib/util/tevent_ntstatus.h"
#include "lib/param/param.h"
#include "lib/util/server_id_db.h"
#include "lib/util/talloc_report_printf.h"
#include "lib/messaging/messages_dgm.h"
#include "lib/messaging/messages_dgm_ref.h"
#include "../source3/lib/messages_util.h"
#include <tdb.h>

/* change the message version with any incompatible changes in the protocol */
#define IMESSAGING_VERSION 1

/*
  a pending irpc call
*/
struct irpc_request {
	struct imessaging_context *msg_ctx;
	int callid;
	struct {
		void (*handler)(struct irpc_request *irpc, struct irpc_message *m);
		void *private_data;
	} incoming;
};

/* we have a linked list of dispatch handlers for each msg_type that
   this messaging server can deal with */
struct dispatch_fn {
	struct dispatch_fn *next, *prev;
	uint32_t msg_type;
	void *private_data;
	msg_callback_t fn;
};

/* an individual message */

static void irpc_handler(struct imessaging_context *,
			 void *,
			 uint32_t,
			 struct server_id,
			 size_t,
			 int *,
			 DATA_BLOB *);


/*
 A useful function for testing the message system.
*/
static void ping_message(struct imessaging_context *msg,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id src,
			 size_t num_fds,
			 int *fds,
			 DATA_BLOB *data)
{
	struct server_id_buf idbuf;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	DEBUG(1,("INFO: Received PING message from server %s [%.*s]\n",
		 server_id_str_buf(src, &idbuf), (int)data->length,
		 data->data?(const char *)data->data:""));
	imessaging_send(msg, src, MSG_PONG, data);
}

static void pool_message(struct imessaging_context *msg,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id src,
			 size_t num_fds,
			 int *fds,
			 DATA_BLOB *data)
{
	FILE *f = NULL;

	if (num_fds != 1) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	f = fdopen(fds[0], "w");
	if (f == NULL) {
		DBG_DEBUG("fopen failed: %s\n", strerror(errno));
		return;
	}

	talloc_full_report_printf(NULL, f);
	fclose(f);
}

static void ringbuf_log_msg(struct imessaging_context *msg,
			    void *private_data,
			    uint32_t msg_type,
			    struct server_id src,
			    size_t num_fds,
			    int *fds,
			    DATA_BLOB *data)
{
	char *log = debug_get_ringbuf();
	size_t logsize = debug_get_ringbuf_size();
	DATA_BLOB blob;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	if (log == NULL) {
		log = discard_const_p(char, "*disabled*\n");
		logsize = strlen(log) + 1;
	}

	blob.data = (uint8_t *)log;
	blob.length = logsize;

	imessaging_send(msg, src, MSG_RINGBUF_LOG, &blob);
}

/****************************************************************************
 Receive a "set debug level" message.
****************************************************************************/

static void debug_imessage(struct imessaging_context *msg_ctx,
			   void *private_data,
			   uint32_t msg_type,
			   struct server_id src,
			   size_t num_fds,
			   int *fds,
			   DATA_BLOB *data)
{
	const char *params_str = (const char *)data->data;
	struct server_id_buf src_buf;
	struct server_id dst = imessaging_get_server_id(msg_ctx);
	struct server_id_buf dst_buf;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	/* Check, it's a proper string! */
	if (params_str[(data->length)-1] != '\0') {
		DBG_ERR("Invalid debug message from pid %s to pid %s\n",
			server_id_str_buf(src, &src_buf),
			server_id_str_buf(dst, &dst_buf));
		return;
	}

	DBG_ERR("INFO: Remote set of debug to `%s' (pid %s from pid %s)\n",
		params_str,
		server_id_str_buf(dst, &dst_buf),
		server_id_str_buf(src, &src_buf));

	debug_parse_levels(params_str);
}

/****************************************************************************
 Return current debug level.
****************************************************************************/

static void debuglevel_imessage(struct imessaging_context *msg_ctx,
				void *private_data,
				uint32_t msg_type,
				struct server_id src,
				size_t num_fds,
				int *fds,
				DATA_BLOB *data)
{
	char *message = debug_list_class_names_and_levels();
	DATA_BLOB blob = data_blob_null;
	struct server_id_buf src_buf;
	struct server_id dst = imessaging_get_server_id(msg_ctx);
	struct server_id_buf dst_buf;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	DBG_DEBUG("Received REQ_DEBUGLEVEL message (pid %s from pid %s)\n",
		  server_id_str_buf(dst, &dst_buf),
		  server_id_str_buf(src, &src_buf));

	if (message == NULL) {
		DBG_ERR("debug_list_class_names_and_levels returned NULL\n");
		return;
	}

	blob = data_blob_string_const_null(message);
	imessaging_send(msg_ctx, src, MSG_DEBUGLEVEL, &blob);

	TALLOC_FREE(message);
}

/*
  return uptime of messaging server via irpc
*/
static NTSTATUS irpc_uptime(struct irpc_message *msg,
			    struct irpc_uptime *r)
{
	struct imessaging_context *ctx = talloc_get_type(msg->private_data, struct imessaging_context);
	*r->out.start_time = timeval_to_nttime(&ctx->start_time);
	return NT_STATUS_OK;
}

static struct dispatch_fn *imessaging_find_dispatch(
	struct imessaging_context *msg, uint32_t msg_type)
{
	/* temporary IDs use an idtree, the rest use a array of pointers */
	if (msg_type >= MSG_TMP_BASE) {
		return (struct dispatch_fn *)idr_find(msg->dispatch_tree,
						      msg_type);
	}
	if (msg_type < msg->num_types) {
		return msg->dispatch[msg_type];
	}
	return NULL;
}

/*
  Register a dispatch function for a particular message type.
*/
NTSTATUS imessaging_register(struct imessaging_context *msg, void *private_data,
			    uint32_t msg_type, msg_callback_t fn)
{
	struct dispatch_fn *d;

	/* possibly expand dispatch array */
	if (msg_type >= msg->num_types) {
		struct dispatch_fn **dp;
		uint32_t i;
		dp = talloc_realloc(msg, msg->dispatch, struct dispatch_fn *, msg_type+1);
		NT_STATUS_HAVE_NO_MEMORY(dp);
		msg->dispatch = dp;
		for (i=msg->num_types;i<=msg_type;i++) {
			msg->dispatch[i] = NULL;
		}
		msg->num_types = msg_type+1;
	}

	d = talloc_zero(msg->dispatch, struct dispatch_fn);
	NT_STATUS_HAVE_NO_MEMORY(d);
	d->msg_type = msg_type;
	d->private_data = private_data;
	d->fn = fn;

	DLIST_ADD(msg->dispatch[msg_type], d);

	return NT_STATUS_OK;
}

/*
  register a temporary message handler. The msg_type is allocated
  above MSG_TMP_BASE
*/
NTSTATUS imessaging_register_tmp(struct imessaging_context *msg, void *private_data,
				msg_callback_t fn, uint32_t *msg_type)
{
	struct dispatch_fn *d;
	int id;

	d = talloc_zero(msg->dispatch, struct dispatch_fn);
	NT_STATUS_HAVE_NO_MEMORY(d);
	d->private_data = private_data;
	d->fn = fn;

	id = idr_get_new_above(msg->dispatch_tree, d, MSG_TMP_BASE, UINT16_MAX);
	if (id == -1) {
		talloc_free(d);
		return NT_STATUS_TOO_MANY_CONTEXT_IDS;
	}

	d->msg_type = (uint32_t)id;
	(*msg_type) = d->msg_type;

	return NT_STATUS_OK;
}

/*
  De-register the function for a particular message type.
*/
void imessaging_deregister(struct imessaging_context *msg, uint32_t msg_type, void *private_data)
{
	struct dispatch_fn *d, *next;

	if (msg_type >= msg->num_types) {
		d = (struct dispatch_fn *)idr_find(msg->dispatch_tree,
						   msg_type);
		if (!d) return;
		idr_remove(msg->dispatch_tree, msg_type);
		talloc_free(d);
		return;
	}

	for (d = msg->dispatch[msg_type]; d; d = next) {
		next = d->next;
		if (d->private_data == private_data) {
			DLIST_REMOVE(msg->dispatch[msg_type], d);
			talloc_free(d);
		}
	}
}

/*
*/
int imessaging_cleanup(struct imessaging_context *msg)
{
	if (!msg) {
		return 0;
	}
	return 0;
}

static void imessaging_dgm_recv(struct tevent_context *ev,
				const uint8_t *buf, size_t buf_len,
				int *fds, size_t num_fds,
				void *private_data);

/* Keep a list of imessaging contexts */
static struct imessaging_context *msg_ctxs;

/*
 * A process has terminated, clean-up any names it has registered.
 */
NTSTATUS imessaging_process_cleanup(
	struct imessaging_context *msg_ctx,
	pid_t pid)
{
	struct irpc_name_records *names = NULL;
	uint32_t i = 0;
	uint32_t j = 0;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	if (mem_ctx == NULL) {
		DBG_ERR("OOM unable to clean up messaging for process (%d)\n",
			pid);
		return NT_STATUS_NO_MEMORY;
	}

	names = irpc_all_servers(msg_ctx, mem_ctx);
	if (names == NULL) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_OK;
	}
	for (i = 0; i < names->num_records; i++) {
		for (j = 0; j < names->names[i]->count; j++) {
			if (names->names[i]->ids[j].pid == pid) {
				int ret = server_id_db_prune_name(
					msg_ctx->names,
					names->names[i]->name,
					names->names[i]->ids[j]);
				if (ret != 0 && ret != ENOENT) {
					TALLOC_FREE(mem_ctx);
					return map_nt_error_from_unix_common(
					    ret);
				}
			}
		}
	}
	TALLOC_FREE(mem_ctx);
	return NT_STATUS_OK;
}

static int imessaging_context_destructor(struct imessaging_context *msg)
{
	DLIST_REMOVE(msg_ctxs, msg);
	TALLOC_FREE(msg->msg_dgm_ref);
	return 0;
}

/*
 * Cleanup messaging dgm contexts on a specific event context.
 *
 * We must make sure to unref all messaging_dgm_ref's *before* the
 * tevent context goes away. Only when the last ref is freed, the
 * refcounted messaging dgm context will be freed.
 */
void imessaging_dgm_unref_ev(struct tevent_context *ev)
{
	struct imessaging_context *msg = NULL;

	for (msg = msg_ctxs; msg != NULL; msg = msg->next) {
		if (msg->ev == ev) {
			TALLOC_FREE(msg->msg_dgm_ref);
		}
	}
}

static NTSTATUS imessaging_reinit(struct imessaging_context *msg)
{
	int ret = -1;

	TALLOC_FREE(msg->msg_dgm_ref);

	msg->server_id.pid = getpid();

	msg->msg_dgm_ref = messaging_dgm_ref(msg,
				msg->ev,
				&msg->server_id.unique_id,
				msg->sock_dir,
				msg->lock_dir,
				imessaging_dgm_recv,
				msg,
				&ret);

	if (msg->msg_dgm_ref == NULL) {
		DEBUG(2, ("messaging_dgm_ref failed: %s\n",
			strerror(ret)));
		return map_nt_error_from_unix_common(ret);
	}

	server_id_db_reinit(msg->names, msg->server_id);
	return NT_STATUS_OK;
}

/*
 * Must be called after a fork.
 */
NTSTATUS imessaging_reinit_all(void)
{
	struct imessaging_context *msg = NULL;

	for (msg = msg_ctxs; msg != NULL; msg = msg->next) {
		NTSTATUS status = imessaging_reinit(msg);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	return NT_STATUS_OK;
}

/*
  create the listening socket and setup the dispatcher
*/
struct imessaging_context *imessaging_init(TALLOC_CTX *mem_ctx,
					   struct loadparm_context *lp_ctx,
					   struct server_id server_id,
					   struct tevent_context *ev)
{
	NTSTATUS status;
	struct imessaging_context *msg;
	bool ok;
	int ret;
	const char *lock_dir = NULL;
	int tdb_flags = TDB_INCOMPATIBLE_HASH | TDB_CLEAR_IF_FIRST;

	if (ev == NULL) {
		return NULL;
	}

	msg = talloc_zero(mem_ctx, struct imessaging_context);
	if (msg == NULL) {
		return NULL;
	}
	msg->ev = ev;

	talloc_set_destructor(msg, imessaging_context_destructor);

	/* create the messaging directory if needed */

	lock_dir = lpcfg_lock_directory(lp_ctx);
	if (lock_dir == NULL) {
		goto fail;
	}

	msg->sock_dir = lpcfg_private_path(msg, lp_ctx, "msg.sock");
	if (msg->sock_dir == NULL) {
		goto fail;
	}
	ok = directory_create_or_exist_strict(msg->sock_dir, geteuid(), 0700);
	if (!ok) {
		goto fail;
	}

	msg->lock_dir = lpcfg_lock_path(msg, lp_ctx, "msg.lock");
	if (msg->lock_dir == NULL) {
		goto fail;
	}
	ok = directory_create_or_exist_strict(msg->lock_dir, geteuid(), 0755);
	if (!ok) {
		goto fail;
	}

	msg->msg_dgm_ref = messaging_dgm_ref(
		msg, ev, &server_id.unique_id, msg->sock_dir, msg->lock_dir,
		imessaging_dgm_recv, msg, &ret);

	if (msg->msg_dgm_ref == NULL) {
		goto fail;
	}

	msg->server_id     = server_id;
	msg->idr           = idr_init(msg);
	if (msg->idr == NULL) {
		goto fail;
	}

	msg->dispatch_tree = idr_init(msg);
	if (msg->dispatch_tree == NULL) {
		goto fail;
	}

	msg->start_time    = timeval_current();

	tdb_flags |= lpcfg_tdb_flags(lp_ctx, 0);

	/*
	 * This context holds a destructor that cleans up any names
	 * registered on this context on talloc_free()
	 */
	msg->names = server_id_db_init(msg, server_id, lock_dir, 0, tdb_flags);
	if (msg->names == NULL) {
		goto fail;
	}

	status = imessaging_register(msg, NULL, MSG_PING, ping_message);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = imessaging_register(msg, NULL, MSG_REQ_POOL_USAGE,
				     pool_message);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = imessaging_register(msg, NULL, MSG_IRPC, irpc_handler);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = imessaging_register(msg, NULL, MSG_REQ_RINGBUF_LOG,
				     ringbuf_log_msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = imessaging_register(msg, NULL, MSG_DEBUG,
				     debug_imessage);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = imessaging_register(msg, NULL, MSG_REQ_DEBUGLEVEL,
				     debuglevel_imessage);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = IRPC_REGISTER(msg, irpc, IRPC_UPTIME, irpc_uptime, msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
#if defined(DEVELOPER) || defined(ENABLE_SELFTEST)
	/*
	 * Register handlers for messages specific to developer and
	 * self test builds
	 */
	status = imessaging_register_extra_handlers(msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
#endif /* defined(DEVELOPER) || defined(ENABLE_SELFTEST) */

	DLIST_ADD(msg_ctxs, msg);

	return msg;
fail:
	talloc_free(msg);
	return NULL;
}

struct imessaging_post_state {
	struct imessaging_context *msg_ctx;
	struct imessaging_post_state **busy_ref;
	size_t buf_len;
	uint8_t buf[];
};

static int imessaging_post_state_destructor(struct imessaging_post_state *state)
{
	if (state->busy_ref != NULL) {
		*state->busy_ref = NULL;
		state->busy_ref = NULL;
	}
	return 0;
}

static void imessaging_post_handler(struct tevent_context *ev,
				    struct tevent_immediate *ti,
				    void *private_data)
{
	struct imessaging_post_state *state = talloc_get_type_abort(
		private_data, struct imessaging_post_state);

	if (state == NULL) {
		return;
	}

	/*
	 * In usecases like using messaging_client_init() with irpc processing
	 * we may free the imessaging_context during the messaging handler.
	 * imessaging_post_state is a child of imessaging_context and
	 * might be implicitly free'ed before the explicit TALLOC_FREE(state).
	 *
	 * The busy_ref pointer makes sure the destructor clears
	 * the local 'state' variable.
	 */

	SMB_ASSERT(state->busy_ref == NULL);
	state->busy_ref = &state;

	imessaging_dgm_recv(ev, state->buf, state->buf_len, NULL, 0,
			    state->msg_ctx);

	state->busy_ref = NULL;
	TALLOC_FREE(state);
}

static int imessaging_post_self(struct imessaging_context *msg,
				const uint8_t *buf, size_t buf_len)
{
	struct tevent_immediate *ti;
	struct imessaging_post_state *state;

	state = talloc_size(
		msg, offsetof(struct imessaging_post_state, buf) + buf_len);
	if (state == NULL) {
		return ENOMEM;
	}
	talloc_set_name_const(state, "struct imessaging_post_state");

	talloc_set_destructor(state, imessaging_post_state_destructor);

	ti = tevent_create_immediate(state);
	if (ti == NULL) {
		TALLOC_FREE(state);
		return ENOMEM;
	}

	state->msg_ctx = msg;
	state->busy_ref = NULL;
	state->buf_len = buf_len;
	memcpy(state->buf, buf, buf_len);

	tevent_schedule_immediate(ti, msg->ev, imessaging_post_handler,
				  state);

	return 0;
}

static void imessaging_dgm_recv(struct tevent_context *ev,
				const uint8_t *buf, size_t buf_len,
				int *fds, size_t num_fds,
				void *private_data)
{
	struct imessaging_context *msg = talloc_get_type_abort(
		private_data, struct imessaging_context);
	uint32_t msg_type;
	struct server_id src, dst;
	struct server_id_buf srcbuf, dstbuf;
	DATA_BLOB data;

	if (buf_len < MESSAGE_HDR_LENGTH) {
		/* Invalid message, ignore */
		return;
	}

	if (ev != msg->ev) {
		int ret;
		ret = imessaging_post_self(msg, buf, buf_len);
		if (ret != 0) {
			DBG_WARNING("imessaging_post_self failed: %s\n",
				    strerror(ret));
		}
		return;
	}

	message_hdr_get(&msg_type, &src, &dst, buf);

	data.data = discard_const_p(uint8_t, buf + MESSAGE_HDR_LENGTH);
	data.length = buf_len - MESSAGE_HDR_LENGTH;

	if ((cluster_id_equal(&dst, &msg->server_id)) ||
	    ((dst.task_id == 0) && (msg->server_id.pid == 0))) {
		struct dispatch_fn *d, *next;

		DEBUG(10, ("%s: dst %s matches my id: %s, type=0x%x\n",
			   __func__,
			   server_id_str_buf(dst, &dstbuf),
			   server_id_str_buf(msg->server_id, &srcbuf),
			   (unsigned)msg_type));

		d = imessaging_find_dispatch(msg, msg_type);

		for (; d; d = next) {
			next = d->next;
			d->fn(msg,
			      d->private_data,
			      d->msg_type,
			      src,
			      num_fds,
			      fds,
			      &data);
		}
	} else {
		DEBUG(10, ("%s: Ignoring type=0x%x dst %s, I am %s, \n",
			   __func__, (unsigned)msg_type,
			   server_id_str_buf(dst, &dstbuf),
			   server_id_str_buf(msg->server_id, &srcbuf)));
	}
}

/*
   A hack, for the short term until we get 'client only' messaging in place
*/
struct imessaging_context *imessaging_client_init(TALLOC_CTX *mem_ctx,
						  struct loadparm_context *lp_ctx,
						struct tevent_context *ev)
{
	struct server_id id;
	ZERO_STRUCT(id);
	id.pid = getpid();
	id.task_id = generate_random();
	id.vnn = NONCLUSTER_VNN;

	/* This is because we are not in the s3 serverid database */
	id.unique_id = SERVERID_UNIQUE_ID_NOT_TO_VERIFY;

	return imessaging_init(mem_ctx, lp_ctx, id, ev);
}
/*
  a list of registered irpc server functions
*/
struct irpc_list {
	struct irpc_list *next, *prev;
	struct GUID uuid;
	const struct ndr_interface_table *table;
	int callnum;
	irpc_function_t fn;
	void *private_data;
};


/*
  register a irpc server function
*/
NTSTATUS irpc_register(struct imessaging_context *msg_ctx,
		       const struct ndr_interface_table *table,
		       int callnum, irpc_function_t fn, void *private_data)
{
	struct irpc_list *irpc;

	/* override an existing handler, if any */
	for (irpc=msg_ctx->irpc; irpc; irpc=irpc->next) {
		if (irpc->table == table && irpc->callnum == callnum) {
			break;
		}
	}
	if (irpc == NULL) {
		irpc = talloc(msg_ctx, struct irpc_list);
		NT_STATUS_HAVE_NO_MEMORY(irpc);
		DLIST_ADD(msg_ctx->irpc, irpc);
	}

	irpc->table   = table;
	irpc->callnum = callnum;
	irpc->fn      = fn;
	irpc->private_data = private_data;
	irpc->uuid = irpc->table->syntax_id.uuid;

	return NT_STATUS_OK;
}


/*
  handle an incoming irpc reply message
*/
static void irpc_handler_reply(struct imessaging_context *msg_ctx, struct irpc_message *m)
{
	struct irpc_request *irpc;

	irpc = (struct irpc_request *)idr_find(msg_ctx->idr, m->header.callid);
	if (irpc == NULL) return;

	irpc->incoming.handler(irpc, m);
}

/*
  send a irpc reply
*/
NTSTATUS irpc_send_reply(struct irpc_message *m, NTSTATUS status)
{
	struct ndr_push *push;
	DATA_BLOB packet;
	enum ndr_err_code ndr_err;

	m->header.status = status;

	/* setup the reply */
	push = ndr_push_init_ctx(m->ndr);
	if (push == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	m->header.flags |= IRPC_FLAG_REPLY;
	m->header.creds.token= NULL;

	/* construct the packet */
	ndr_err = ndr_push_irpc_header(push, NDR_SCALARS|NDR_BUFFERS, &m->header);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		goto failed;
	}

	ndr_err = m->irpc->table->calls[m->irpc->callnum].ndr_push(push, NDR_OUT, m->data);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		goto failed;
	}

	/* send the reply message */
	packet = ndr_push_blob(push);
	status = imessaging_send(m->msg_ctx, m->from, MSG_IRPC, &packet);
	if (!NT_STATUS_IS_OK(status)) goto failed;

failed:
	talloc_free(m);
	return status;
}

/*
  handle an incoming irpc request message
*/
static void irpc_handler_request(struct imessaging_context *msg_ctx,
				 struct irpc_message *m)
{
	struct irpc_list *i;
	void *r;
	enum ndr_err_code ndr_err;

	for (i=msg_ctx->irpc; i; i=i->next) {
		if (GUID_equal(&i->uuid, &m->header.uuid) &&
		    i->table->syntax_id.if_version == m->header.if_version &&
		    i->callnum == m->header.callnum) {
			break;
		}
	}

	if (i == NULL) {
		/* no registered handler for this message */
		talloc_free(m);
		return;
	}

	/* allocate space for the structure */
	r = talloc_zero_size(m->ndr, i->table->calls[m->header.callnum].struct_size);
	if (r == NULL) goto failed;

	m->ndr->flags |= LIBNDR_FLAG_REF_ALLOC;

	/* parse the request data */
	ndr_err = i->table->calls[i->callnum].ndr_pull(m->ndr, NDR_IN, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) goto failed;

	/* make the call */
	m->private_data= i->private_data;
	m->defer_reply = false;
	m->no_reply    = false;
	m->msg_ctx     = msg_ctx;
	m->irpc        = i;
	m->data        = r;

	m->header.status = i->fn(m, r);

	if (m->no_reply) {
		/* the server function won't ever be replying to this request */
		talloc_free(m);
		return;
	}

	if (m->defer_reply) {
		/* the server function has asked to defer the reply to later */
		talloc_steal(msg_ctx, m);
		return;
	}

	irpc_send_reply(m, m->header.status);
	return;

failed:
	talloc_free(m);
}

/*
  handle an incoming irpc message
*/
static void irpc_handler(struct imessaging_context *msg_ctx,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id src,
			 size_t num_fds,
			 int *fds,
			 DATA_BLOB *packet)
{
	struct irpc_message *m;
	enum ndr_err_code ndr_err;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	m = talloc(msg_ctx, struct irpc_message);
	if (m == NULL) goto failed;

	m->from = src;

	m->ndr = ndr_pull_init_blob(packet, m);
	if (m->ndr == NULL) goto failed;

	m->ndr->flags |= LIBNDR_FLAG_REF_ALLOC;

	ndr_err = ndr_pull_irpc_header(m->ndr, NDR_BUFFERS|NDR_SCALARS, &m->header);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) goto failed;

	if (m->header.flags & IRPC_FLAG_REPLY) {
		irpc_handler_reply(msg_ctx, m);
	} else {
		irpc_handler_request(msg_ctx, m);
	}
	return;

failed:
	talloc_free(m);
}


/*
  destroy a irpc request
*/
static int irpc_destructor(struct irpc_request *irpc)
{
	if (irpc->callid != -1) {
		idr_remove(irpc->msg_ctx->idr, irpc->callid);
		irpc->callid = -1;
	}

	return 0;
}

/*
  add a string name that this irpc server can be called on

  It will be removed from the DB either via irpc_remove_name or on
  talloc_free(msg_ctx->names).
*/
NTSTATUS irpc_add_name(struct imessaging_context *msg_ctx, const char *name)
{
	int ret;

	ret = server_id_db_add(msg_ctx->names, name);
	if (ret != 0) {
		return map_nt_error_from_unix_common(ret);
	}
	return NT_STATUS_OK;
}

static int all_servers_func(const char *name, unsigned num_servers,
			    const struct server_id *servers,
			    void *private_data)
{
	struct irpc_name_records *name_records = talloc_get_type(
		private_data, struct irpc_name_records);
	struct irpc_name_record *name_record;
	uint32_t i;

	name_records->names
		= talloc_realloc(name_records, name_records->names,
				 struct irpc_name_record *, name_records->num_records+1);
	if (!name_records->names) {
		return -1;
	}

	name_records->names[name_records->num_records] = name_record
		= talloc(name_records->names,
			 struct irpc_name_record);
	if (!name_record) {
		return -1;
	}

	name_records->num_records++;

	name_record->name = talloc_strdup(name_record, name);
	if (!name_record->name) {
		return -1;
	}

	name_record->count = num_servers;
	name_record->ids = talloc_array(name_record, struct server_id,
					num_servers);
	if (name_record->ids == NULL) {
		return -1;
	}
	for (i=0;i<name_record->count;i++) {
		name_record->ids[i] = servers[i];
	}
	return 0;
}

/*
  return a list of server ids for a server name
*/
struct irpc_name_records *irpc_all_servers(struct imessaging_context *msg_ctx,
					   TALLOC_CTX *mem_ctx)
{
	int ret;
	struct irpc_name_records *name_records = talloc_zero(mem_ctx, struct irpc_name_records);
	if (name_records == NULL) {
		return NULL;
	}

	ret = server_id_db_traverse_read(msg_ctx->names, all_servers_func,
					 name_records);
	if (ret == -1) {
		TALLOC_FREE(name_records);
		return NULL;
	}

	return name_records;
}

/*
  remove a name from a messaging context
*/
void irpc_remove_name(struct imessaging_context *msg_ctx, const char *name)
{
	server_id_db_remove(msg_ctx->names, name);
}

struct server_id imessaging_get_server_id(struct imessaging_context *msg_ctx)
{
	return msg_ctx->server_id;
}

struct irpc_bh_state {
	struct imessaging_context *msg_ctx;
	struct server_id server_id;
	const struct ndr_interface_table *table;
	uint32_t timeout;
	struct security_token *token;
};

static bool irpc_bh_is_connected(struct dcerpc_binding_handle *h)
{
	struct irpc_bh_state *hs = dcerpc_binding_handle_data(h,
				   struct irpc_bh_state);

	if (!hs->msg_ctx) {
		return false;
	}

	return true;
}

static uint32_t irpc_bh_set_timeout(struct dcerpc_binding_handle *h,
				    uint32_t timeout)
{
	struct irpc_bh_state *hs = dcerpc_binding_handle_data(h,
				   struct irpc_bh_state);
	uint32_t old = hs->timeout;

	hs->timeout = timeout;

	return old;
}

struct irpc_bh_raw_call_state {
	struct irpc_request *irpc;
	uint32_t opnum;
	DATA_BLOB in_data;
	DATA_BLOB in_packet;
	DATA_BLOB out_data;
};

static void irpc_bh_raw_call_incoming_handler(struct irpc_request *irpc,
					      struct irpc_message *m);

static struct tevent_req *irpc_bh_raw_call_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h,
						const struct GUID *object,
						uint32_t opnum,
						uint32_t in_flags,
						const uint8_t *in_data,
						size_t in_length)
{
	struct irpc_bh_state *hs =
		dcerpc_binding_handle_data(h,
		struct irpc_bh_state);
	struct tevent_req *req;
	struct irpc_bh_raw_call_state *state;
	bool ok;
	struct irpc_header header;
	struct ndr_push *ndr;
	NTSTATUS status;
	enum ndr_err_code ndr_err;

	req = tevent_req_create(mem_ctx, &state,
				struct irpc_bh_raw_call_state);
	if (req == NULL) {
		return NULL;
	}
	state->opnum = opnum;
	state->in_data.data = discard_const_p(uint8_t, in_data);
	state->in_data.length = in_length;

	ok = irpc_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	state->irpc = talloc_zero(state, struct irpc_request);
	if (tevent_req_nomem(state->irpc, req)) {
		return tevent_req_post(req, ev);
	}

	state->irpc->msg_ctx  = hs->msg_ctx;
	state->irpc->callid   = idr_get_new(hs->msg_ctx->idr,
					    state->irpc, UINT16_MAX);
	if (state->irpc->callid == -1) {
		tevent_req_nterror(req, NT_STATUS_INSUFFICIENT_RESOURCES);
		return tevent_req_post(req, ev);
	}
	state->irpc->incoming.handler = irpc_bh_raw_call_incoming_handler;
	state->irpc->incoming.private_data = req;

	talloc_set_destructor(state->irpc, irpc_destructor);

	/* setup the header */
	header.uuid = hs->table->syntax_id.uuid;

	header.if_version = hs->table->syntax_id.if_version;
	header.callid     = state->irpc->callid;
	header.callnum    = state->opnum;
	header.flags      = 0;
	header.status     = NT_STATUS_OK;
	header.creds.token= hs->token;

	/* construct the irpc packet */
	ndr = ndr_push_init_ctx(state->irpc);
	if (tevent_req_nomem(ndr, req)) {
		return tevent_req_post(req, ev);
	}

	ndr_err = ndr_push_irpc_header(ndr, NDR_SCALARS|NDR_BUFFERS, &header);
	status = ndr_map_error2ntstatus(ndr_err);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	ndr_err = ndr_push_bytes(ndr, in_data, in_length);
	status = ndr_map_error2ntstatus(ndr_err);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	/* and send it */
	state->in_packet = ndr_push_blob(ndr);
	status = imessaging_send(hs->msg_ctx, hs->server_id,
				MSG_IRPC, &state->in_packet);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	if (hs->timeout != IRPC_CALL_TIMEOUT_INF) {
		/* set timeout-callback in case caller wants that */
		ok = tevent_req_set_endtime(req, ev, timeval_current_ofs(hs->timeout, 0));
		if (!ok) {
			return tevent_req_post(req, ev);
		}
	}

	return req;
}

static void irpc_bh_raw_call_incoming_handler(struct irpc_request *irpc,
					      struct irpc_message *m)
{
	struct tevent_req *req =
		talloc_get_type_abort(irpc->incoming.private_data,
		struct tevent_req);
	struct irpc_bh_raw_call_state *state =
		tevent_req_data(req,
		struct irpc_bh_raw_call_state);

	talloc_steal(state, m);

	if (!NT_STATUS_IS_OK(m->header.status)) {
		tevent_req_nterror(req, m->header.status);
		return;
	}

	state->out_data = data_blob_talloc(state,
		m->ndr->data + m->ndr->offset,
		m->ndr->data_size - m->ndr->offset);
	if ((m->ndr->data_size - m->ndr->offset) > 0 && !state->out_data.data) {
		tevent_req_oom(req);
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS irpc_bh_raw_call_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					uint8_t **out_data,
					size_t *out_length,
					uint32_t *out_flags)
{
	struct irpc_bh_raw_call_state *state =
		tevent_req_data(req,
		struct irpc_bh_raw_call_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_data = talloc_move(mem_ctx, &state->out_data.data);
	*out_length = state->out_data.length;
	*out_flags = 0;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct irpc_bh_disconnect_state {
	uint8_t _dummy;
};

static struct tevent_req *irpc_bh_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h)
{
	struct irpc_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct irpc_bh_state);
	struct tevent_req *req;
	struct irpc_bh_disconnect_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct irpc_bh_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	ok = irpc_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	hs->msg_ctx = NULL;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS irpc_bh_disconnect_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static bool irpc_bh_ref_alloc(struct dcerpc_binding_handle *h)
{
	return true;
}

static const struct dcerpc_binding_handle_ops irpc_bh_ops = {
	.name			= "wbint",
	.is_connected		= irpc_bh_is_connected,
	.set_timeout		= irpc_bh_set_timeout,
	.raw_call_send		= irpc_bh_raw_call_send,
	.raw_call_recv		= irpc_bh_raw_call_recv,
	.disconnect_send	= irpc_bh_disconnect_send,
	.disconnect_recv	= irpc_bh_disconnect_recv,

	.ref_alloc		= irpc_bh_ref_alloc,
};

/* initialise a irpc binding handle */
struct dcerpc_binding_handle *irpc_binding_handle(TALLOC_CTX *mem_ctx,
						  struct imessaging_context *msg_ctx,
						  struct server_id server_id,
						  const struct ndr_interface_table *table)
{
	struct dcerpc_binding_handle *h;
	struct irpc_bh_state *hs;

	h = dcerpc_binding_handle_create(mem_ctx,
					 &irpc_bh_ops,
					 NULL,
					 table,
					 &hs,
					 struct irpc_bh_state,
					 __location__);
	if (h == NULL) {
		return NULL;
	}
	hs->msg_ctx = msg_ctx;
	hs->server_id = server_id;
	hs->table = table;
	hs->timeout = IRPC_CALL_TIMEOUT;

	return h;
}

struct dcerpc_binding_handle *irpc_binding_handle_by_name(TALLOC_CTX *mem_ctx,
							  struct imessaging_context *msg_ctx,
							  const char *dest_task,
							  const struct ndr_interface_table *table)
{
	struct dcerpc_binding_handle *h;
	unsigned num_sids;
	struct server_id *sids;
	struct server_id sid;
	NTSTATUS status;

	/* find the server task */

	status = irpc_servers_byname(msg_ctx, mem_ctx, dest_task,
				     &num_sids, &sids);
	if (!NT_STATUS_IS_OK(status)) {
		errno = EADDRNOTAVAIL;
		return NULL;
	}
	sid = sids[0];
	talloc_free(sids);

	h = irpc_binding_handle(mem_ctx, msg_ctx,
				sid, table);
	if (h == NULL) {
		return NULL;
	}

	return h;
}

void irpc_binding_handle_add_security_token(struct dcerpc_binding_handle *h,
					    struct security_token *token)
{
	struct irpc_bh_state *hs =
		dcerpc_binding_handle_data(h,
		struct irpc_bh_state);

	hs->token = token;
}
