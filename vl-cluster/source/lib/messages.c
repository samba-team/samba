/* 
   Unix SMB/CIFS implementation.
   Samba internal messaging functions
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) 2001 by Martin Pool
   Copyright (C) 2002 by Jeremy Allison
   
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

/* the locking database handle */
static TDB_CONTEXT *tdb;

static char *socket_path;
static int socket_fd;
static struct process_id socket_pid;

/* change the message version with any incompatible changes in the protocol */
#define MESSAGE_VERSION 1

struct message_rec {
	int msg_version;
	int msg_type;
	struct process_id dest;
	struct process_id src;
	size_t len;
};

/* we have a linked list of dispatch handlers */
static struct dispatch_fns {
	struct dispatch_fns *next, *prev;
	int msg_type;
	void (*fn)(int msg_type, struct process_id pid, void *buf, size_t len);
} *dispatch_fns;

/****************************************************************************
 A useful function for testing the message system.
****************************************************************************/

static void ping_message(int msg_type, struct process_id src,
			 void *buf, size_t len)
{
	const char *msg = buf ? buf : "none";
	DEBUG(1,("INFO: Received PING message from PID %s [%s]\n",
		 procid_str_static(&src), msg));
	message_send_pid(src, MSG_PONG, buf, len, True);
}

/****************************************************************************
 Initialise the messaging functions. 
****************************************************************************/

BOOL message_init_socket(void)
{
	socket_pid = procid_self();
	asprintf(&socket_path, "%s/%s", lock_path("messaging"),
		 procid_str_static(&socket_pid));

	DEBUG(10, ("creating socket %s\n", socket_path));

	socket_fd = create_dgram_sock(lock_path("messaging"),
				      procid_str_static(&socket_pid),
				      0700);
	if (socket_fd < 0) {
		DEBUG(0, ("Could not create socket\n"));
		return False;
	}
	return True;
}

BOOL message_init(void)
{
	if (tdb) return True;

	tdb = tdb_open_log(lock_path("messages.tdb"), 
		       0, TDB_CLEAR_IF_FIRST|TDB_DEFAULT, 
		       O_RDWR|O_CREAT,0600);

	if (!tdb) {
		DEBUG(0,("ERROR: Failed to initialise messages database\n"));
		return False;
	}

	if (!message_init_socket()) {
		DEBUG(0, ("Failed to init messaging socket\n"));
		return False;
	}

	message_register(MSG_PING, ping_message);

	/* Register some debugging related messages */

	register_msg_pool_usage();
	register_dmalloc_msgs();

	return True;
}

int message_socket(void)
{
	return socket_fd;
}

/*******************************************************************
 Form a static tdb key from a pid.
******************************************************************/

static TDB_DATA message_key_pid(struct process_id pid)
{
	static char key[50];
	TDB_DATA kbuf;
	char *pidstr = procid_str(NULL, &pid);

	slprintf(key, sizeof(key)-1, "PID/%s", pidstr);
	talloc_free(pidstr);
	
	kbuf.dptr = (char *)key;
	kbuf.dsize = strlen(key)+1;
	return kbuf;
}

static const char *message_path(TALLOC_CTX *mem_ctx,
				const struct process_id *pid)
{
	return talloc_asprintf(mem_ctx, "%s/%s", lock_path("messaging"),
			       procid_str_static(pid));
}

static BOOL message_send_via_socket(struct process_id pid, int msg_type,
				    const void *buf, size_t len)
{
	DATA_BLOB packet;
	struct message_rec *hdr;
	size_t packet_len = sizeof(struct message_rec) + len;
	struct sockaddr_un sunaddr;
	ssize_t sent;

	packet = data_blob_talloc(NULL, NULL, packet_len);
	if (packet.data == NULL) {
		DEBUG(0, ("malloc failed\n"));
		return False;
	}

	hdr = (struct message_rec *)packet.data;
	hdr->msg_version = MESSAGE_VERSION;
	hdr->msg_type = msg_type;
	hdr->len = len;
	hdr->src = procid_self();
	hdr->dest = pid;
	if (len > 0) {
		memcpy(packet.data + sizeof(struct message_rec), buf, len);
	}

	ZERO_STRUCT(sunaddr);
	sunaddr.sun_family = AF_UNIX;
	strncpy(sunaddr.sun_path, message_path(packet.data, &pid),
		sizeof(sunaddr.sun_path)-1);

	sent = sendto(socket_fd, packet.data, packet.length, 0,
		      (struct sockaddr *)&sunaddr, sizeof(sunaddr));
	if (sent != packet.length) {
		DEBUG(3, ("Could not send %d bytes to Unix domain socket %s: "
			  "%s\n", packet.length, sunaddr.sun_path,
			  strerror(errno)));
		talloc_free(packet.data);
		return False;
	}

	talloc_free(packet.data);
	return True;
}

/****************************************************************************
 Notify a process that it has a message. If the process doesn't exist 
 then delete its record in the database.
****************************************************************************/

static BOOL message_notify(struct process_id pid)
{
	return message_send_via_socket(pid, MSG_NOTIFICATION, NULL, 0);
}

/****************************************************************************
 Send a message to a particular pid.
****************************************************************************/

BOOL message_send_pid(struct process_id pid, int msg_type,
		      const void *buf, size_t len,
		      BOOL duplicates_allowed)
{
	TDB_DATA kbuf;
	TDB_DATA dbuf;
	TDB_DATA old_dbuf;
	struct message_rec rec;
	char *ptr;
	struct message_rec prec;

	if (duplicates_allowed && (len < 512)) {
		return message_send_via_socket(pid, msg_type, buf, len);
	}

	rec.msg_version = MESSAGE_VERSION;
	rec.msg_type = msg_type;
	rec.dest = pid;
	rec.src = procid_self();
	rec.len = len;

	kbuf = message_key_pid(pid);

	dbuf.dptr = (void *)SMB_MALLOC(len + sizeof(rec));
	if (!dbuf.dptr)
		return False;

	memcpy(dbuf.dptr, &rec, sizeof(rec));
	if (len > 0)
		memcpy((void *)((char*)dbuf.dptr+sizeof(rec)), buf, len);

	dbuf.dsize = len + sizeof(rec);

	if (duplicates_allowed) {

		/* If duplicates are allowed we can just append the message and return. */

		/* lock the record for the destination */
		if (tdb_chainlock(tdb, kbuf) == -1) {
			DEBUG(0,("message_send_pid_internal: failed to get "
				 "chainlock.\n"));
			return False;
		}
		tdb_append(tdb, kbuf, dbuf);
		tdb_chainunlock(tdb, kbuf);

		SAFE_FREE(dbuf.dptr);
		errno = 0;                    /* paranoia */
		return message_notify(pid);
	}

	/* lock the record for the destination */
	if (tdb_chainlock(tdb, kbuf) == -1) {
		DEBUG(0,("message_send_pid_internal: failed to get "
			 "chainlock.\n"));
		return False;
	}

	old_dbuf = tdb_fetch(tdb, kbuf);

	if (!old_dbuf.dptr) {
		/* its a new record */

		tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
		tdb_chainunlock(tdb, kbuf);

		SAFE_FREE(dbuf.dptr);
		errno = 0;                    /* paranoia */
		return message_notify(pid);
	}

	/* Not a new record. Check for duplicates. */

	for(ptr = (char *)old_dbuf.dptr; ptr < old_dbuf.dptr + old_dbuf.dsize; ) {
		/*
		 * First check if the message header matches, then, if it's a non-zero
		 * sized message, check if the data matches. If so it's a duplicate and
		 * we can discard it. JRA.
		 */

		if (!memcmp(ptr, &rec, sizeof(rec))) {
			if (!len || (len && !memcmp( ptr + sizeof(rec), buf, len))) {
				tdb_chainunlock(tdb, kbuf);
				DEBUG(10,("message_send_pid_internal: discarding duplicate message.\n"));
				SAFE_FREE(dbuf.dptr);
				SAFE_FREE(old_dbuf.dptr);
				return True;
			}
		}
		memcpy(&prec, ptr, sizeof(prec));
		ptr += sizeof(rec) + prec.len;
	}

	/* we're adding to an existing entry */

	tdb_append(tdb, kbuf, dbuf);
	tdb_chainunlock(tdb, kbuf);

	SAFE_FREE(old_dbuf.dptr);
	SAFE_FREE(dbuf.dptr);

	errno = 0;                    /* paranoia */
	return message_notify(pid);
}

/****************************************************************************
 Count the messages pending for a particular pid. Expensive....
****************************************************************************/

unsigned int messages_pending_for_pid(struct process_id pid)
{
	TDB_DATA kbuf;
	TDB_DATA dbuf;
	char *buf;
	unsigned int message_count = 0;

	kbuf = message_key_pid(pid);

	dbuf = tdb_fetch(tdb, kbuf);
	if (dbuf.dptr == NULL || dbuf.dsize == 0) {
		SAFE_FREE(dbuf.dptr);
		return 0;
	}

	for (buf = dbuf.dptr; dbuf.dsize > sizeof(struct message_rec);) {
		struct message_rec rec;
		memcpy(&rec, buf, sizeof(rec));
		buf += (sizeof(rec) + rec.len);
		dbuf.dsize -= (sizeof(rec) + rec.len);
		message_count++;
	}

	SAFE_FREE(dbuf.dptr);
	return message_count;
}

/****************************************************************************
 Retrieve all messages for the current process.
****************************************************************************/

static BOOL retrieve_all_messages(TALLOC_CTX *mem_ctx, char **msgs_buf,
				  size_t *total_len)
{
	TDB_DATA kbuf;
	TDB_DATA dbuf;
	TDB_DATA null_dbuf;

	ZERO_STRUCT(null_dbuf);

	*msgs_buf = NULL;
	*total_len = 0;

	kbuf = message_key_pid(pid_to_procid(sys_getpid()));

	if (tdb_chainlock(tdb, kbuf) == -1)
		return False;

	dbuf = tdb_fetch(tdb, kbuf);
	/*
	 * Replace with an empty record to keep the allocated
	 * space in the tdb.
	 */
	tdb_store(tdb, kbuf, null_dbuf, TDB_REPLACE);
	tdb_chainunlock(tdb, kbuf);

	if (dbuf.dptr == NULL || dbuf.dsize == 0) {
		SAFE_FREE(dbuf.dptr);
		return False;
	}

	*msgs_buf = talloc_memdup(mem_ctx, dbuf.dptr, dbuf.dsize);
	*total_len = dbuf.dsize;
	SAFE_FREE(dbuf.dptr);

	return True;
}

/****************************************************************************
 Parse out the next message for the current process.
****************************************************************************/

static BOOL message_recv(char *msgs_buf, size_t total_len, int *msg_type,
			 struct process_id *src, char **buf, size_t *len)
{
	struct message_rec rec;
	char *ret_buf = *buf;

	*buf = NULL;
	*len = 0;

	if (total_len - (ret_buf - msgs_buf) < sizeof(rec))
		return False;

	memcpy(&rec, ret_buf, sizeof(rec));
	ret_buf += sizeof(rec);

	if (rec.msg_version != MESSAGE_VERSION) {
		DEBUG(0,("message version %d received (expected %d)\n", rec.msg_version, MESSAGE_VERSION));
		return False;
	}

	if (rec.len > 0) {
		if (total_len - (ret_buf - msgs_buf) < rec.len)
			return False;
	}

	*len = rec.len;
	*msg_type = rec.msg_type;
	*src = rec.src;
	*buf = ret_buf;

	return True;
}

static BOOL fetch_socket_message(TALLOC_CTX *mem_ctx,
				 int *msg_type, struct process_id *src,
				 char **buf, size_t *len)
{
	int msglength;
	ssize_t received;
	char *raw_buf;
	struct message_rec *msg;

	if (ioctl(socket_fd, FIONREAD, &msglength) < 0) {
		DEBUG(5, ("Could not get the message length\n"));
		msglength = 65536;
	}

	raw_buf = talloc_size(mem_ctx, msglength);
	if (raw_buf == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return False;
	}

	received = recv(socket_fd, raw_buf, msglength, MSG_DONTWAIT);
	if (received != msglength) {
		DEBUG(0, ("Received different length (%d) than announced "
			  "(%d)\n", received, msglength));
		return False;
	}

	if (received < sizeof(struct message_rec)) {
		DEBUG(5, ("Message too short\n"));
		return False;
	}

	msg = (struct message_rec *)raw_buf;

	if (msg->msg_version != MESSAGE_VERSION) {
		DEBUG(0,("message version %d received (expected %d)\n",
			 msg->msg_version, MESSAGE_VERSION));
		return False;
	}

	if (received != (msg->len + sizeof(struct message_rec))) {
		DEBUG(5, ("Invalid message length received, got %d, "
			  "expected %d\n", received,
			  msg->len + sizeof(struct message_rec)));
		return False;
	}

	if (!procid_is_me(&msg->dest)) {
		DEBUG(5, ("Received message for invalid process: %s\n",
			  procid_str_static(&msg->dest)));
		return False;
	}

	*msg_type = msg->msg_type;
	*src = msg->src;
	*buf = raw_buf + sizeof(struct message_rec);
	*len = msg->len;
	return True;
}

static int dispatch_message(int msg_type, struct process_id src,
			    char *buf, size_t len)
{
	struct dispatch_fns *dfn;
	int n_handled = 0;

	for (dfn = dispatch_fns; dfn; dfn = dfn->next) {
		if (dfn->msg_type != msg_type) {
			continue;
		}
		DEBUG(10,("message_dispatch: processing message of "
			  "type %d.\n", msg_type));
		dfn->fn(msg_type, src, len ? (void *)buf : NULL, len);
		n_handled++;
	}

	if (n_handled == 0) {
		DEBUG(5,("message_dispatch: warning: no handlers registed for "
			 "msg_type %d in pid %u\n", msg_type,
			 (unsigned int)sys_getpid()));
	}

	return n_handled;
}

/****************************************************************************
 Receive and dispatch any messages pending for this process.
 Notice that all dispatch handlers for a particular msg_type get called,
 so you can register multiple handlers for a message.
 *NOTE*: Dispatch functions must be able to cope with incoming
 messages on an *odd* byte boundary.
****************************************************************************/

void message_dispatch(void)
{
	int msg_type;
	struct process_id src;
	char *buf;
	char *msgs_buf;
	size_t len, total_len;
	int n_handled;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("message_dispatch");
	if (mem_ctx == NULL) {
		smb_panic("talloc_init failed\n");
	}

	if (!fetch_socket_message(mem_ctx, &msg_type, &src, &buf, &len)) {
		talloc_free(mem_ctx);
		return;
	}

	if (msg_type != MSG_NOTIFICATION) {
		dispatch_message(msg_type, src, buf, len);
		talloc_free(mem_ctx);
		return;
	}

	if (!retrieve_all_messages(mem_ctx, &msgs_buf, &total_len)) {
		talloc_free(mem_ctx);
		return;
	}

	for (buf = msgs_buf;
	     message_recv(msgs_buf, total_len, &msg_type, &src, &buf, &len);
	     buf += len) {
		n_handled += dispatch_message(msg_type, src, buf, len);
	}
}

/****************************************************************************
 Register a dispatch function for a particular message type.
 *NOTE*: Dispatch functions must be able to cope with incoming
 messages on an *odd* byte boundary.
****************************************************************************/

void message_register(int msg_type, 
		      void (*fn)(int msg_type, struct process_id pid,
				 void *buf, size_t len))
{
	struct dispatch_fns *dfn;

	dfn = SMB_MALLOC_P(struct dispatch_fns);

	if (dfn != NULL) {

		ZERO_STRUCTPN(dfn);

		dfn->msg_type = msg_type;
		dfn->fn = fn;

		DLIST_ADD(dispatch_fns, dfn);
	}
	else {
	
		DEBUG(0,("message_register: Not enough memory. malloc failed!\n"));
	}
}

/****************************************************************************
 De-register the function for a particular message type.
****************************************************************************/

void message_deregister(int msg_type)
{
	struct dispatch_fns *dfn, *next;

	for (dfn = dispatch_fns; dfn; dfn = next) {
		next = dfn->next;
		if (dfn->msg_type == msg_type) {
			DLIST_REMOVE(dispatch_fns, dfn);
			SAFE_FREE(dfn);
		}
	}	
}

struct msg_all {
	int msg_type;
	uint32 msg_flag;
	const void *buf;
	size_t len;
	BOOL duplicates;
	int n_sent;
};

/****************************************************************************
 Send one of the messages for the broadcast.
****************************************************************************/

static int traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA kbuf, TDB_DATA dbuf,
		       void *state)
{
	struct connections_data crec;
	struct msg_all *msg_all = (struct msg_all *)state;

	if (dbuf.dsize != sizeof(crec))
		return 0;

	memcpy(&crec, dbuf.dptr, sizeof(crec));

	if (crec.cnum != -1)
		return 0;

	/* Don't send if the receiver hasn't registered an interest. */

	if(!(crec.bcast_msg_flags & msg_all->msg_flag))
		return 0;

	/* If the msg send fails because the pid was not found (i.e. smbd died), 
	 * the msg has already been deleted from the messages.tdb.*/

	if (!message_send_pid(crec.pid, msg_all->msg_type,
			      msg_all->buf, msg_all->len,
			      msg_all->duplicates)) {
		
		/* If the pid was not found delete the entry from connections.tdb */

		if (errno == ESRCH) {
			DEBUG(2,("pid %s doesn't exist - deleting connections %d [%s]\n",
				 procid_str_static(&crec.pid),
				 crec.cnum, crec.name));
			tdb_delete(the_tdb, kbuf);
		}
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
BOOL message_send_all(TDB_CONTEXT *conn_tdb, int msg_type,
		      const void *buf, size_t len,
		      BOOL duplicates_allowed,
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
	msg_all.duplicates = duplicates_allowed;
	msg_all.n_sent = 0;

	tdb_traverse(conn_tdb, traverse_fn, &msg_all);
	if (n_sent)
		*n_sent = msg_all.n_sent;
	return True;
}
/** @} **/
