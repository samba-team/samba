/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba internal messaging functions
   Copyright (C) Andrew Tridgell 2000
   
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

/* this module is used for internal messaging between Samba daemons. 

   The idea is that if a part of Samba wants to do communication with
   another Samba process then it will do a message_register() of a
   dispatch function, and use message_send_pid() to send messages to
   that process.

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
notifications come in as signals
****************************************************************************/
static void sig_usr1(void)
{
	received_signal = 1;
	sys_select_signal();
}

/****************************************************************************
a useful function for testing the message system
****************************************************************************/
void ping_message(int msg_type, pid_t src, void *buf, size_t len)
{
	message_send_pid(src, MSG_PONG, buf, len);
}

/****************************************************************************
 Initialise the messaging functions. 
****************************************************************************/
BOOL message_init(void)
{
	if (tdb) return True;

	tdb = tdb_open(lock_path("messages.tdb"), 
		       0, TDB_CLEAR_IF_FIRST, 
		       O_RDWR|O_CREAT,0600);

	if (!tdb) {
		DEBUG(0,("ERROR: Failed to initialise messages database\n"));
		return False;
	}

	CatchSignal(SIGUSR1, sig_usr1);

	message_register(MSG_PING, ping_message);

	return True;
}


/*******************************************************************
 form a static tdb key from a pid
******************************************************************/
static TDB_DATA message_key_pid(pid_t pid)
{
	static char key[20];
	TDB_DATA kbuf;

	slprintf(key, sizeof(key), "PID/%d", (int)pid);

	kbuf.dptr = (char *)key;
	kbuf.dsize = sizeof(key);
	return kbuf;
}


/****************************************************************************
notify a process that it has a message. If the process doesn't exist 
then delete its record in the database
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
send a message to a particular pid
****************************************************************************/
BOOL message_send_pid(pid_t pid, int msg_type, void *buf, size_t len)
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
	tdb_lockchain(tdb, kbuf);

	dbuf = tdb_fetch(tdb, kbuf);

	if (!dbuf.dptr) {
		/* its a new record */
		p = (void *)malloc(len + sizeof(rec));
		if (!p) goto failed;

		memcpy(p, &rec, sizeof(rec));
		if (len > 0) memcpy((void *)((unsigned)p+sizeof(rec)), buf, len);

		dbuf.dptr = p;
		dbuf.dsize = len + sizeof(rec);
		tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
		free(p);
		goto ok;
	}

	/* we're adding to an existing entry */
	p = (void *)malloc(dbuf.dsize + len + sizeof(rec));
	if (!p) goto failed;

	memcpy(p, dbuf.dptr, dbuf.dsize);
	memcpy((void *)((unsigned)p+dbuf.dsize), &rec, sizeof(rec));
	if (len > 0) memcpy((void *)((unsigned)p+dbuf.dsize+sizeof(rec)), buf, len);

	free(dbuf.dptr);
	dbuf.dptr = p;
	dbuf.dsize += len + sizeof(rec);
	tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
	free(dbuf.dptr);

 ok:
	tdb_unlockchain(tdb, kbuf);
	return message_notify(pid);

 failed:
	tdb_unlockchain(tdb, kbuf);
	return False;
}



/****************************************************************************
retrieve the next message for the current process
****************************************************************************/
static BOOL message_recv(int *msg_type, pid_t *src, void **buf, size_t *len)
{
	TDB_DATA kbuf;
	TDB_DATA dbuf;
	struct message_rec rec;

	kbuf = message_key_pid(sys_getpid());

	tdb_lockchain(tdb, kbuf);
	
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

	memmove(dbuf.dptr, dbuf.dptr+sizeof(rec)+rec.len, dbuf.dsize - (sizeof(rec)+rec.len));
	dbuf.dsize -= sizeof(rec)+rec.len;
	tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	free(dbuf.dptr);
	tdb_unlockchain(tdb, kbuf);
	return True;

 failed:
	tdb_unlockchain(tdb, kbuf);
	return False;
}


/****************************************************************************
receive and dispatch any messages pending for this process
notice that all dispatch handlers for a particular msg_type get called,
so you can register multiple handlers for a message
****************************************************************************/
void message_dispatch(void)
{
	int msg_type;
	pid_t src;
	void *buf;
	size_t len;
	struct dispatch_fns *dfn;

	if (!received_signal) return;
	received_signal = 0;

	while (message_recv(&msg_type, &src, &buf, &len)) {
		for (dfn = dispatch_fns; dfn; dfn = dfn->next) {
			if (dfn->msg_type == msg_type) {
				dfn->fn(msg_type, src, buf, len);
			}
		}
		if (buf) free(buf);
	}
}


/****************************************************************************
register a dispatch function for a particular message type
****************************************************************************/
void message_register(int msg_type, 
		      void (*fn)(int msg_type, pid_t pid, void *buf, size_t len))
{
	struct dispatch_fns *dfn;

	dfn = (struct dispatch_fns *)malloc(sizeof(*dfn));

	ZERO_STRUCTP(dfn);

	dfn->msg_type = msg_type;
	dfn->fn = fn;

	DLIST_ADD(dispatch_fns, dfn);
}

/****************************************************************************
de-register the function for a particular message type
****************************************************************************/
void message_deregister(int msg_type)
{
	struct dispatch_fns *dfn, *next;

	for (dfn = dispatch_fns; dfn; dfn = next) {
		next = dfn->next;
		if (dfn->msg_type == msg_type) {
			DLIST_REMOVE(dispatch_fns, dfn);
			free(dfn);
		}
	}	
}

static struct {
	int msg_type;
	void *buf;
	size_t len;
} msg_all;

/****************************************************************************
send one of the messages for the broadcast
****************************************************************************/
static int traverse_fn(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf, void *state)
{
	struct connections_data crec;

	memcpy(&crec, dbuf.dptr, sizeof(crec));

	message_send_pid(crec.pid, msg_all.msg_type, msg_all.buf, msg_all.len);
	return 0;
}

/****************************************************************************
this is a useful function for sending messages to all smbd processes.
It isn't very efficient, but should be OK for the sorts of applications that 
use it. When we need efficient broadcast we can add it.
****************************************************************************/
BOOL message_send_all(int msg_type, void *buf, size_t len)
{
	TDB_CONTEXT *tdb;

	tdb = tdb_open(lock_path("connections.tdb"), 0, 0, O_RDONLY, 0);
	if (!tdb) {
		DEBUG(2,("Failed to open connections database in message_send_all\n"));
		return False;
	}

	msg_all.msg_type = msg_type;
	msg_all.buf = buf;
	msg_all.len = len;

	tdb_traverse(tdb, traverse_fn, NULL);
	tdb_close(tdb);
	return True;
}
