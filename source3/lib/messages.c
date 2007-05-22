/* 
   Unix SMB/CIFS implementation.
   Samba internal messaging functions
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) 2001 by Martin Pool
   Copyright (C) 2002 by Jeremy Allison
   Copyright (C) 2007 by Volker Lendecke
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#include "librpc/gen_ndr/messaging.h"
#include "librpc/gen_ndr/ndr_messaging.h"

/* the locking database handle */
static int received_signal;

/* change the message version with any incompatible changes in the protocol */
#define MESSAGE_VERSION 2

struct messaging_callback {
	struct messaging_callback *prev, *next;
	uint32 msg_type;
	void (*fn)(struct messaging_context *msg, void *private_data, 
		   uint32_t msg_type, 
		   struct server_id server_id, DATA_BLOB *data);
	void *private_data;
};

struct messaging_context {
	TDB_CONTEXT *tdb;
	struct server_id id;
	struct event_context *event_ctx;
	struct messaging_callback *callbacks;
};

/****************************************************************************
 Notifications come in as signals.
****************************************************************************/

static void sig_usr1(void)
{
	received_signal = 1;
	sys_select_signal(SIGUSR1);
}

/****************************************************************************
 A useful function for testing the message system.
****************************************************************************/

static void ping_message(struct messaging_context *msg_ctx,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id src,
			 DATA_BLOB *data)
{
	const char *msg = data->data ? (const char *)data->data : "none";

	DEBUG(1,("INFO: Received PING message from PID %s [%s]\n",
		 procid_str_static(&src), msg));
	messaging_send(msg_ctx, src, MSG_PONG, data);
}

/****************************************************************************
 Initialise the messaging functions. 
****************************************************************************/

static BOOL message_init(struct messaging_context *msg_ctx)
{
	sec_init();

	msg_ctx->tdb = tdb_open_log(lock_path("messages.tdb"), 
				    0, TDB_CLEAR_IF_FIRST|TDB_DEFAULT, 
				    O_RDWR|O_CREAT,0600);

	if (!msg_ctx->tdb) {
		DEBUG(0,("ERROR: Failed to initialise messages database\n"));
		return False;
	}

	/* Activate the per-hashchain freelist */
	tdb_set_max_dead(msg_ctx->tdb, 5);

	CatchSignal(SIGUSR1, SIGNAL_CAST sig_usr1);

	messaging_register(msg_ctx, NULL, MSG_PING, ping_message);

	/* Register some debugging related messages */

	register_msg_pool_usage(msg_ctx);
	register_dmalloc_msgs(msg_ctx);
	debug_register_msgs(msg_ctx);

	return True;
}

/*******************************************************************
 Form a static tdb key from a pid.
******************************************************************/

static TDB_DATA message_key_pid(struct server_id pid)
{
	static char key[20];
	TDB_DATA kbuf;

	slprintf(key, sizeof(key)-1, "PID/%s", procid_str_static(&pid));
	
	kbuf.dptr = (uint8 *)key;
	kbuf.dsize = strlen(key)+1;
	return kbuf;
}

/*
  Fetch the messaging array for a process
 */

static NTSTATUS messaging_tdb_fetch(TDB_CONTEXT *msg_tdb,
				    TDB_DATA key,
				    TALLOC_CTX *mem_ctx,
				    struct messaging_array **presult)
{
	struct messaging_array *result;
	TDB_DATA data;
	DATA_BLOB blob;
	NTSTATUS status;

	if (!(result = TALLOC_ZERO_P(mem_ctx, struct messaging_array))) {
		return NT_STATUS_NO_MEMORY;
	}

	data = tdb_fetch(msg_tdb, key);

	if (data.dptr == NULL) {
		*presult = result;
		return NT_STATUS_OK;
	}

	blob = data_blob_const(data.dptr, data.dsize);

	status = ndr_pull_struct_blob(
		&blob, result, result,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_array);

	SAFE_FREE(data.dptr);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(result);
		return status;
	}

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("messaging_tdb_fetch:\n"));
		NDR_PRINT_DEBUG(messaging_array, result);
	}

	*presult = result;
	return NT_STATUS_OK;
}

/*
  Store a messaging array for a pid
*/

static NTSTATUS messaging_tdb_store(TDB_CONTEXT *msg_tdb,
				    TDB_DATA key,
				    struct messaging_array *array)
{
	TDB_DATA data;
	DATA_BLOB blob;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	int ret;

	if (array->num_messages == 0) {
		tdb_delete(msg_tdb, key);
		return NT_STATUS_OK;
	}

	if (!(mem_ctx = talloc_new(array))) {
		return NT_STATUS_NO_MEMORY;
	}

	status = ndr_push_struct_blob(
		&blob, mem_ctx, array,
		(ndr_push_flags_fn_t)ndr_push_messaging_array);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return status;
	}

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("messaging_tdb_store:\n"));
		NDR_PRINT_DEBUG(messaging_array, array);
	}

	data.dptr = blob.data;
	data.dsize = blob.length;

	ret = tdb_store(msg_tdb, key, data, TDB_REPLACE);
	TALLOC_FREE(mem_ctx);

	return (ret == 0) ? NT_STATUS_OK : NT_STATUS_INTERNAL_DB_CORRUPTION;
}

/****************************************************************************
 Notify a process that it has a message. If the process doesn't exist 
 then delete its record in the database.
****************************************************************************/

static NTSTATUS message_notify(struct server_id procid)
{
	pid_t pid = procid.pid;
	int ret;
	uid_t euid = geteuid();

	/*
	 * Doing kill with a non-positive pid causes messages to be
	 * sent to places we don't want.
	 */

	SMB_ASSERT(pid > 0);

	if (euid != 0) {
		/* If we're not root become so to send the message. */
		save_re_uid();
		set_effective_uid(0);
	}

	ret = kill(pid, SIGUSR1);

	if (euid != 0) {
		/* Go back to who we were. */
		int saved_errno = errno;
		restore_re_uid_fromroot();
		errno = saved_errno;
	}

	if (ret == 0) {
		return NT_STATUS_OK;
	}

	/*
	 * Something has gone wrong
	 */

	DEBUG(2,("message to process %d failed - %s\n", (int)pid,
		 strerror(errno)));

	/*
	 * No call to map_nt_error_from_unix -- don't want to link in
	 * errormap.o into lots of utils.
	 */

	if (errno == ESRCH)  return NT_STATUS_INVALID_HANDLE;
	if (errno == EINVAL) return NT_STATUS_INVALID_PARAMETER;
	if (errno == EPERM)  return NT_STATUS_ACCESS_DENIED;
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
 Send a message to a particular pid.
****************************************************************************/

static NTSTATUS messaging_tdb_send(TDB_CONTEXT *msg_tdb,
				   struct server_id pid, int msg_type,
				   const void *buf, size_t len)
{
	struct messaging_array *msg_array;
	struct messaging_rec *rec;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	TDB_DATA key = message_key_pid(pid);

	/* NULL pointer means implicit length zero. */
	if (!buf) {
		SMB_ASSERT(len == 0);
	}

	/*
	 * Doing kill with a non-positive pid causes messages to be
	 * sent to places we don't want.
	 */

	SMB_ASSERT(procid_to_pid(&pid) > 0);

	if (!(mem_ctx = talloc_init("message_send_pid"))) {
		return NT_STATUS_NO_MEMORY;
	}

	if (tdb_chainlock(msg_tdb, key) == -1) {
		return NT_STATUS_LOCK_NOT_GRANTED;
	}

	status = messaging_tdb_fetch(msg_tdb, key, mem_ctx, &msg_array);

	if (!NT_STATUS_IS_OK(status)) {
		tdb_chainunlock(msg_tdb, key);
		TALLOC_FREE(mem_ctx);
		return status;
	}

	if (!(rec = TALLOC_REALLOC_ARRAY(mem_ctx, msg_array->messages,
					 struct messaging_rec,
					 msg_array->num_messages+1))) {
		tdb_chainunlock(msg_tdb, key);
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	rec[msg_array->num_messages].msg_version = MESSAGE_VERSION;
	rec[msg_array->num_messages].msg_type = msg_type;
	rec[msg_array->num_messages].dest = pid;
	rec[msg_array->num_messages].src = procid_self();
	rec[msg_array->num_messages].buf = data_blob_const(buf, len);

	msg_array->messages = rec;
	msg_array->num_messages += 1;

	status = messaging_tdb_store(msg_tdb, key, msg_array);

	tdb_chainunlock(msg_tdb, key);
	TALLOC_FREE(mem_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	status = message_notify(pid);

	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		DEBUG(2, ("pid %s doesn't exist - deleting messages record\n",
			  procid_str_static(&pid)));
		tdb_delete(msg_tdb, message_key_pid(pid));
	}

	return status;
}

/****************************************************************************
 Count the messages pending for a particular pid. Expensive....
****************************************************************************/

unsigned int messages_pending_for_pid(struct messaging_context *msg_ctx,
				      struct server_id pid)
{
	struct messaging_array *msg_array;
	unsigned int result;

	if (!NT_STATUS_IS_OK(messaging_tdb_fetch(msg_ctx->tdb,
						 message_key_pid(pid), NULL,
						 &msg_array))) {
		DEBUG(10, ("messaging_tdb_fetch failed\n"));
		return 0;
	}

	result = msg_array->num_messages;
	TALLOC_FREE(msg_array);
	return result;
}	

/****************************************************************************
 Retrieve all messages for the current process.
****************************************************************************/

static NTSTATUS retrieve_all_messages(TDB_CONTEXT *msg_tdb,
				      TALLOC_CTX *mem_ctx,
				      struct messaging_array **presult)
{
	struct messaging_array *result;
	TDB_DATA key = message_key_pid(procid_self());
	NTSTATUS status;

	if (tdb_chainlock(msg_tdb, key) == -1) {
		return NT_STATUS_LOCK_NOT_GRANTED;
	}

	status = messaging_tdb_fetch(msg_tdb, key, mem_ctx, &result);

	/*
	 * We delete the record here, tdb_set_max_dead keeps it around
	 */
	tdb_delete(msg_tdb, key);
	tdb_chainunlock(msg_tdb, key);

	if (NT_STATUS_IS_OK(status)) {
		*presult = result;
	}

	return status;
}

/*
  Dispatch one messsaging_rec
*/
static void messaging_dispatch_rec(struct messaging_context *msg_ctx,
				   struct messaging_rec *rec)
{
	struct messaging_callback *cb, *next;

	for (cb = msg_ctx->callbacks; cb != NULL; cb = next) {
		next = cb->next;
		if (cb->msg_type == rec->msg_type) {
			cb->fn(msg_ctx, cb->private_data, rec->msg_type,
			       rec->src, &rec->buf);
			return;
		}
	}
	return;
}

/****************************************************************************
 Receive and dispatch any messages pending for this process.
 JRA changed Dec 13 2006. Only one message handler now permitted per type.
 *NOTE*: Dispatch functions must be able to cope with incoming
 messages on an *odd* byte boundary.
****************************************************************************/

void message_dispatch(struct messaging_context *msg_ctx)
{
	struct messaging_array *msg_array = NULL;
	uint32 i;

	if (!received_signal)
		return;

	DEBUG(10, ("message_dispatch: received_signal = %d\n",
		   received_signal));

	received_signal = 0;

	if (!NT_STATUS_IS_OK(retrieve_all_messages(msg_ctx->tdb, NULL,
						   &msg_array))) {
		return;
	}

	for (i=0; i<msg_array->num_messages; i++) {
		messaging_dispatch_rec(msg_ctx, &msg_array->messages[i]);
	}

	TALLOC_FREE(msg_array);
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
	uint32 msg_flag;
	const void *buf;
	size_t len;
	int n_sent;
};

/****************************************************************************
 Send one of the messages for the broadcast.
****************************************************************************/

static int traverse_fn(TDB_CONTEXT *the_tdb,
		       const struct connections_key *ckey,
		       const struct connections_data *crec,
		       void *private_data)
{
	struct msg_all *msg_all = (struct msg_all *)private_data;
	NTSTATUS status;

	if (crec->cnum != -1)
		return 0;

	/* Don't send if the receiver hasn't registered an interest. */

	if(!(crec->bcast_msg_flags & msg_all->msg_flag))
		return 0;

	/* If the msg send fails because the pid was not found (i.e. smbd died), 
	 * the msg has already been deleted from the messages.tdb.*/

	status = messaging_send_buf(msg_all->msg_ctx,
				    crec->pid, msg_all->msg_type,
				    (uint8 *)msg_all->buf, msg_all->len);

	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {

		TDB_DATA key;
		
		/* If the pid was not found delete the entry from
		 * connections.tdb */

		DEBUG(2,("pid %s doesn't exist - deleting connections "
			 "%d [%s]\n", procid_str_static(&crec->pid),
			 crec->cnum, crec->servicename));

		key.dptr = (uint8 *)ckey;
		key.dsize = sizeof(*ckey);

		tdb_delete(the_tdb, key);
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
BOOL message_send_all(struct messaging_context *msg_ctx,
		      int msg_type,
		      const void *buf, size_t len,
		      int *n_sent)
{
	struct msg_all msg_all;

	msg_all.msg_type = msg_type;
	if (msg_type < 1000)
		msg_all.msg_flag = FLAG_MSG_GENERAL;
	else if (msg_type > 1000 && msg_type < 2000)
		msg_all.msg_flag = FLAG_MSG_NMBD;
	else if (msg_type > 2000 && msg_type < 2100)
		msg_all.msg_flag = FLAG_MSG_PRINT_NOTIFY;
	else if (msg_type > 2100 && msg_type < 3000)
		msg_all.msg_flag = FLAG_MSG_PRINT_GENERAL;
	else if (msg_type > 3000 && msg_type < 4000)
		msg_all.msg_flag = FLAG_MSG_SMBD;
	else
		return False;

	msg_all.buf = buf;
	msg_all.len = len;
	msg_all.n_sent = 0;
	msg_all.msg_ctx = msg_ctx;

	connections_forall(traverse_fn, &msg_all);
	if (n_sent)
		*n_sent = msg_all.n_sent;
	return True;
}

/*
 * Block and unblock receiving of messages. Allows removal of race conditions
 * when doing a fork and changing message disposition.
 */

void message_block(void)
{
	BlockSignals(True, SIGUSR1);
}

void message_unblock(void)
{
	BlockSignals(False, SIGUSR1);
}

struct event_context *messaging_event_context(struct messaging_context *msg_ctx)
{
	return msg_ctx->event_ctx;
}

struct messaging_context *messaging_init(TALLOC_CTX *mem_ctx, 
					 struct server_id server_id, 
					 struct event_context *ev)
{
	struct messaging_context *ctx;

	if (!(ctx = TALLOC_ZERO_P(mem_ctx, struct messaging_context))) {
		return NULL;
	}

	ctx->id = server_id;
	ctx->event_ctx = ev;

	if (!message_init(ctx)) {
		DEBUG(0, ("message_init failed: %s\n", strerror(errno)));
		TALLOC_FREE(ctx);
	}

	return ctx;
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

	/*
	 * Only one callback per type
	 */

	for (cb = msg_ctx->callbacks; cb != NULL; cb = cb->next) {
		if (cb->msg_type == msg_type) {
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
			DLIST_REMOVE(ctx->callbacks, cb);
			TALLOC_FREE(cb);
		}
	}
}

/*
  Send a message to a particular server
*/
NTSTATUS messaging_send(struct messaging_context *msg_ctx,
			struct server_id server, 
			uint32_t msg_type, const DATA_BLOB *data)
{
	return messaging_tdb_send(msg_ctx->tdb, server, msg_type,
				  data->data, data->length);
}

NTSTATUS messaging_send_buf(struct messaging_context *msg_ctx,
			    struct server_id server, uint32_t msg_type,
			    const uint8 *buf, size_t len)
{
	DATA_BLOB blob = data_blob_const(buf, len);
	return messaging_send(msg_ctx, server, msg_type, &blob);
}

/** @} **/
