/* 
   Unix SMB/CIFS implementation.
   Samba internal messaging functions
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) 2001 by Martin Pool
   
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
   @defgroups messages Internal messaging framework
   @{
   @file messages.c

   This module is used for internal messaging between Samba daemons. 

   The idea is that if a part of Samba wants to do communication with
   another Samba process then it will do a message_register() of a
   dispatch function, and use message_send_pid() to send messages to
   that process.

   The dispatch function is given the pid of the sender, and it can
   use that to reply by message_send_pid().  See ping_message() for a
   simple example.

   This system doesn't have any inherent size limitations but is not
   very efficient for large messages or when messages are sent in very
   quick succession.

*/

#include "includes.h"

/* the locking database handle */
static TDB_CONTEXT *tdb;
static int received_signal;

/* change the message version with any incompatible changes in the protocol */
#define MESSAGE_VERSION 1

struct message_rec {
	int msg_version;
	int msg_type;
	pid_t dest;
	pid_t src;
	size_t len;
};

/* we have a linked list of dispatch handlers */
static struct dispatch_fns {
	struct dispatch_fns *next, *prev;
	int msg_type;
	void (*fn)(int msg_type, pid_t pid, void *buf, size_t len);
} *dispatch_fns;

/****************************************************************************
 Notifications come in as signals.
****************************************************************************/

static void sig_usr1(void)
{
	received_signal = 1;
	sys_select_signal();
}

/****************************************************************************
 A useful function for testing the message system.
****************************************************************************/

void ping_message(int msg_type, pid_t src, void *buf, size_t len)
{
	const char *msg = buf ? buf : "none";
	DEBUG(1,("INFO: Received PING message from PID %u [%s]\n",(unsigned int)src, msg));
	message_send_pid(src, MSG_PONG, buf, len, True);
}

/****************************************************************************
 Return current debug level.
****************************************************************************/

void debuglevel_message(int msg_type, pid_t src, void *buf, size_t len)
{
	DEBUG(1,("INFO: Received REQ_DEBUGLEVEL message from PID %u\n",(unsigned int)src));
	message_send_pid(src, MSG_DEBUGLEVEL, DEBUGLEVEL_CLASS, sizeof(DEBUGLEVEL_CLASS), True);
}

/****************************************************************************
 Initialise the messaging functions. 
****************************************************************************/

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

	CatchSignal(SIGUSR1, SIGNAL_CAST sig_usr1);

	message_register(MSG_PING, ping_message);
	message_register(MSG_REQ_DEBUGLEVEL, debuglevel_message);

	return True;
}

/*******************************************************************
 Form a static tdb key from a pid.
******************************************************************/

static TDB_DATA message_key_pid(pid_t pid)
{
	static char key[20];
	TDB_DATA kbuf;

	slprintf(key, sizeof(key)-1, "PID/%d", (int)pid);
	
	kbuf.dptr = (char *)key;
	kbuf.dsize = strlen(key)+1;
	return kbuf;
}

/****************************************************************************
 Notify a process that it has a message. If the process doesn't exist 
 then delete its record in the database.
****************************************************************************/

static BOOL message_notify(pid_t pid)
{
	if (kill(pid, SIGUSR1) == -1) {
		if (errno == ESRCH) {
			DEBUG(2,("pid %d doesn't exist - deleting messages record\n", (int)pid));
			tdb_delete(tdb, message_key_pid(pid));
		} else {
			DEBUG(2,("message to process %d failed - %s\n", (int)pid, strerror(errno)));
		}
		return False;
	}
	return True;
}

/****************************************************************************
 Send a message to a particular pid.
****************************************************************************/

BOOL message_send_pid(pid_t pid, int msg_type, const void *buf, size_t len,
		      BOOL duplicates_allowed)
{
	TDB_DATA kbuf;
	TDB_DATA dbuf;
	struct message_rec rec;
	void *p;

	rec.msg_version = MESSAGE_VERSION;
	rec.msg_type = msg_type;
	rec.dest = pid;
	rec.src = sys_getpid();
	rec.len = len;

	kbuf = message_key_pid(pid);

	/* lock the record for the destination */
	tdb_chainlock(tdb, kbuf);

	dbuf = tdb_fetch(tdb, kbuf);

	if (!dbuf.dptr) {
		/* its a new record */
		p = (void *)malloc(len + sizeof(rec));
		if (!p) goto failed;

		memcpy(p, &rec, sizeof(rec));
		if (len > 0) memcpy((void *)((char*)p+sizeof(rec)), buf, len);

		dbuf.dptr = p;
		dbuf.dsize = len + sizeof(rec);
		tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
		SAFE_FREE(p);
		goto ok;
	}

	if (!duplicates_allowed) {
		char *ptr;
		struct message_rec prec;
		
		for(ptr = (char *)dbuf.dptr; ptr < dbuf.dptr + dbuf.dsize; ) {
			/*
			 * First check if the message header matches, then, if it's a non-zero
			 * sized message, check if the data matches. If so it's a duplicate and
			 * we can discard it. JRA.
			 */

			if (!memcmp(ptr, &rec, sizeof(rec))) {
				if (!len || (len && !memcmp( ptr + sizeof(rec), buf, len))) {
					DEBUG(10,("message_send_pid: discarding duplicate message.\n"));
					SAFE_FREE(dbuf.dptr);
					tdb_chainunlock(tdb, kbuf);
					return True;
				}
			}
			memcpy(&prec, ptr, sizeof(prec));
			ptr += sizeof(rec) + prec.len;
		}
	}

	/* we're adding to an existing entry */
	p = (void *)malloc(dbuf.dsize + len + sizeof(rec));
	if (!p) goto failed;

	memcpy(p, dbuf.dptr, dbuf.dsize);
	memcpy((void *)((char*)p+dbuf.dsize), &rec, sizeof(rec));
	if (len > 0) memcpy((void *)((char*)p+dbuf.dsize+sizeof(rec)), buf, len);

	SAFE_FREE(dbuf.dptr);
	dbuf.dptr = p;
	dbuf.dsize += len + sizeof(rec);
	tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
	SAFE_FREE(dbuf.dptr);

 ok:
	tdb_chainunlock(tdb, kbuf);
	errno = 0;                    /* paranoia */
	return message_notify(pid);

 failed:
	tdb_chainunlock(tdb, kbuf);
	errno = 0;                    /* paranoia */
	return False;
}

/****************************************************************************
 Retrieve the next message for the current process.
****************************************************************************/

static BOOL message_recv(int *msg_type, pid_t *src, void **buf, size_t *len)
{
	TDB_DATA kbuf;
	TDB_DATA dbuf;
	struct message_rec rec;

	kbuf = message_key_pid(sys_getpid());

	tdb_chainlock(tdb, kbuf);
	
	dbuf = tdb_fetch(tdb, kbuf);
	if (dbuf.dptr == NULL || dbuf.dsize == 0) goto failed;

	memcpy(&rec, dbuf.dptr, sizeof(rec));

	if (rec.msg_version != MESSAGE_VERSION) {
		DEBUG(0,("message version %d received (expected %d)\n", rec.msg_version, MESSAGE_VERSION));
		goto failed;
	}

	if (rec.len > 0) {
		(*buf) = (void *)malloc(rec.len);
		if (!(*buf)) goto failed;

		memcpy(*buf, dbuf.dptr+sizeof(rec), rec.len);
	} else {
		*buf = NULL;
	}

	*len = rec.len;
	*msg_type = rec.msg_type;
	*src = rec.src;

	if (dbuf.dsize - (sizeof(rec)+rec.len) > 0)
		memmove(dbuf.dptr, dbuf.dptr+sizeof(rec)+rec.len, dbuf.dsize - (sizeof(rec)+rec.len));
	dbuf.dsize -= sizeof(rec)+rec.len;

	if (dbuf.dsize == 0)
		tdb_delete(tdb, kbuf);
	else
		tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	SAFE_FREE(dbuf.dptr);
	tdb_chainunlock(tdb, kbuf);
	return True;

 failed:
	tdb_chainunlock(tdb, kbuf);
	return False;
}

/****************************************************************************
 Receive and dispatch any messages pending for this process.
 Notice that all dispatch handlers for a particular msg_type get called,
 so you can register multiple handlers for a message.
****************************************************************************/

void message_dispatch(void)
{
	int msg_type;
	pid_t src;
	void *buf;
	size_t len;
	struct dispatch_fns *dfn;
	int n_handled;

	if (!received_signal) return;

	DEBUG(10,("message_dispatch: received_signal = %d\n", received_signal));

	received_signal = 0;

	while (message_recv(&msg_type, &src, &buf, &len)) {
		DEBUG(10,("message_dispatch: received msg_type=%d src_pid=%u\n",
			  msg_type, (unsigned int) src));
		n_handled = 0;
		for (dfn = dispatch_fns; dfn; dfn = dfn->next) {
			if (dfn->msg_type == msg_type) {
				DEBUG(10,("message_dispatch: processing message of type %d.\n", msg_type));
				dfn->fn(msg_type, src, buf, len);
				n_handled++;
			}
		}
		if (!n_handled) {
			DEBUG(5,("message_dispatch: warning: no handlers registed for "
				 "msg_type %d in pid%u\n",
				 msg_type, (unsigned int)getpid()));
		}
		SAFE_FREE(buf);
	}
}

/****************************************************************************
 Register a dispatch function for a particular message type.
****************************************************************************/

void message_register(int msg_type, 
		      void (*fn)(int msg_type, pid_t pid, void *buf, size_t len))
{
	struct dispatch_fns *dfn;

	dfn = (struct dispatch_fns *)malloc(sizeof(*dfn));

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
	const void *buf;
	size_t len;
	BOOL duplicates;
	int		n_sent;
};

/****************************************************************************
 Send one of the messages for the broadcast.
****************************************************************************/

static int traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA kbuf, TDB_DATA dbuf, void *state)
{
	struct connections_data crec;
	struct msg_all *msg_all = (struct msg_all *)state;

	if (dbuf.dsize != sizeof(crec))
		return 0;

	memcpy(&crec, dbuf.dptr, sizeof(crec));

	if (crec.cnum != -1)
		return 0;

	/* if the msg send fails because the pid was not found (i.e. smbd died), 
	 * the msg has already been deleted from the messages.tdb.*/
	if (!message_send_pid(crec.pid, msg_all->msg_type,
			      msg_all->buf, msg_all->len,
			      msg_all->duplicates)) {
		
		/* if the pid was not found delete the entry from connections.tdb */
		if (errno == ESRCH) {
			DEBUG(2,("pid %u doesn't exist - deleting connections %d [%s]\n",
					(unsigned int)crec.pid, crec.cnum, crec.name));
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
 * @return True for success.
 **/
BOOL message_send_all(TDB_CONTEXT *conn_tdb, int msg_type,
		      const void *buf, size_t len,
		      BOOL duplicates_allowed,
		      int *n_sent)
{
	struct msg_all msg_all;

	msg_all.msg_type = msg_type;
	msg_all.buf = buf;
	msg_all.len = len;
	msg_all.duplicates = duplicates_allowed;
	msg_all.n_sent = 0;

	tdb_traverse(conn_tdb, traverse_fn, &msg_all);
	if (n_sent)
		*n_sent = msg_all.n_sent;
	return True;
}
