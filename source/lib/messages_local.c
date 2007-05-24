/* 
   Unix SMB/CIFS implementation.
   Samba internal messaging functions
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

static NTSTATUS messaging_tdb_send(struct messaging_context *msg_ctx,
				   struct server_id pid, int msg_type,
				   const DATA_BLOB *data,
				   struct messaging_backend *backend);

/****************************************************************************
 Notifications come in as signals.
****************************************************************************/

static void sig_usr1(void)
{
	received_signal = 1;
	sys_select_signal(SIGUSR1);
}

static int messaging_tdb_destructor(struct messaging_backend *tdb_ctx)
{
	TDB_CONTEXT *tdb = (TDB_CONTEXT *)tdb_ctx->private_data;
	tdb_close(tdb);
	return 0;
}

/****************************************************************************
 Initialise the messaging functions. 
****************************************************************************/

NTSTATUS messaging_tdb_init(struct messaging_context *msg_ctx,
			    TALLOC_CTX *mem_ctx,
			    struct messaging_backend **presult)
{
	struct messaging_backend *result;
	TDB_CONTEXT *tdb;

	if (!(result = TALLOC_P(mem_ctx, struct messaging_backend))) {
		DEBUG(0, ("talloc failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	tdb = tdb_open_log(lock_path("messages.tdb"), 
			   0, TDB_CLEAR_IF_FIRST|TDB_DEFAULT, 
			   O_RDWR|O_CREAT,0600);

	if (!tdb) {
		DEBUG(0,("ERROR: Failed to initialise messages database\n"));
		TALLOC_FREE(result);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	sec_init();

	/* Activate the per-hashchain freelist */
	tdb_set_max_dead(tdb, 5);

	CatchSignal(SIGUSR1, SIGNAL_CAST sig_usr1);

	result->private_data = (void *)tdb;
	result->send_fn = messaging_tdb_send;

	talloc_set_destructor(result, messaging_tdb_destructor);

	*presult = result;
	return NT_STATUS_OK;
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

static NTSTATUS messaging_tdb_send(struct messaging_context *msg_ctx,
				   struct server_id pid, int msg_type,
				   const DATA_BLOB *data,
				   struct messaging_backend *backend)
{
	struct messaging_array *msg_array;
	struct messaging_rec *rec;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	TDB_DATA key = message_key_pid(pid);
	TDB_CONTEXT *tdb = (TDB_CONTEXT *)backend->private_data;

	/* NULL pointer means implicit length zero. */
	if (!data->data) {
		SMB_ASSERT(data->length == 0);
	}

	/*
	 * Doing kill with a non-positive pid causes messages to be
	 * sent to places we don't want.
	 */

	SMB_ASSERT(procid_to_pid(&pid) > 0);

	if (!(mem_ctx = talloc_init("message_send_pid"))) {
		return NT_STATUS_NO_MEMORY;
	}

	if (tdb_chainlock(tdb, key) == -1) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_LOCK_NOT_GRANTED;
	}

	status = messaging_tdb_fetch(tdb, key, mem_ctx, &msg_array);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if ((msg_type & MSG_FLAG_LOWPRIORITY)
	    && (msg_array->num_messages > 1000)) {
		DEBUG(5, ("Dropping message for PID %s\n",
			  procid_str_static(&pid)));
		status = NT_STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	if (!(rec = TALLOC_REALLOC_ARRAY(mem_ctx, msg_array->messages,
					 struct messaging_rec,
					 msg_array->num_messages+1))) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	rec[msg_array->num_messages].msg_version = MESSAGE_VERSION;
	rec[msg_array->num_messages].msg_type = msg_type & MSG_TYPE_MASK;
	rec[msg_array->num_messages].dest = pid;
	rec[msg_array->num_messages].src = procid_self();
	rec[msg_array->num_messages].buf = *data;

	msg_array->messages = rec;
	msg_array->num_messages += 1;

	status = messaging_tdb_store(tdb, key, msg_array);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	
	status = message_notify(pid);

	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		DEBUG(2, ("pid %s doesn't exist - deleting messages record\n",
			  procid_str_static(&pid)));
		tdb_delete(tdb, message_key_pid(pid));
	}

 done:
	tdb_chainunlock(tdb, key);
	TALLOC_FREE(mem_ctx);
	return status;
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

/****************************************************************************
 Receive and dispatch any messages pending for this process.
 JRA changed Dec 13 2006. Only one message handler now permitted per type.
 *NOTE*: Dispatch functions must be able to cope with incoming
 messages on an *odd* byte boundary.
****************************************************************************/

void message_dispatch(struct messaging_context *msg_ctx)
{
	struct messaging_array *msg_array = NULL;
	TDB_CONTEXT *tdb = (TDB_CONTEXT *)(msg_ctx->local->private_data);
	uint32 i;

	if (!received_signal)
		return;

	DEBUG(10, ("message_dispatch: received_signal = %d\n",
		   received_signal));

	received_signal = 0;

	if (!NT_STATUS_IS_OK(retrieve_all_messages(tdb, NULL, &msg_array))) {
		return;
	}

	for (i=0; i<msg_array->num_messages; i++) {
		messaging_dispatch_rec(msg_ctx, &msg_array->messages[i]);
	}

	TALLOC_FREE(msg_array);
}

/** @} **/
