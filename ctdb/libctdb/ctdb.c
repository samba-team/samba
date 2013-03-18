/*
   core of libctdb

   Copyright (C) Rusty Russell 2010
   Copyright (C) Ronnie Sahlberg 2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#include <sys/socket.h>
#include <string.h>
#include <ctdb.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include "libctdb_private.h"
#include "io_elem.h"
#include "local_tdb.h"
#include "messages.h"
#include <dlinklist.h>
#include <ctdb_protocol.h>

/* Remove type-safety macros. */
#undef ctdb_attachdb_send
#undef ctdb_readrecordlock_async
#undef ctdb_readonlyrecordlock_async
#undef ctdb_connect

struct ctdb_lock {
	struct ctdb_lock *next, *prev;

	struct ctdb_db *ctdb_db;
	TDB_DATA key;

	/* Is this a request for read-only lock ? */
	bool readonly;

	/* This will always be set by the time user sees this. */
	unsigned long held_magic;
	struct ctdb_ltdb_header *hdr;

	/* For convenience, we stash original callback here. */
	ctdb_rrl_callback_t callback;
};

struct ctdb_db {
	struct ctdb_connection *ctdb;
	bool persistent;
	uint32_t tdb_flags;
	uint32_t id;
	struct tdb_context *tdb;

	ctdb_callback_t callback;
	void *private_data;
};

static void remove_lock(struct ctdb_connection *ctdb, struct ctdb_lock *lock)
{
	DLIST_REMOVE(ctdb->locks, lock);
}

/* FIXME: for thread safety, need tid info too. */
static bool holding_lock(struct ctdb_connection *ctdb)
{
	/* For the moment, you can't ever hold more than 1 lock. */
	return (ctdb->locks != NULL);
}

static void add_lock(struct ctdb_connection *ctdb, struct ctdb_lock *lock)
{
	DLIST_ADD(ctdb->locks, lock);
}

static void cleanup_locks(struct ctdb_connection *ctdb, struct ctdb_db *db)
{
	struct ctdb_lock *i, *next;

	for (i = ctdb->locks; i; i = next) {
		/* Grab next pointer, as release_lock will free i */
		next = i->next;
		if (i->ctdb_db == db) {
			ctdb_release_lock(db, i);
		}
	}
}

/* FIXME: Could be in shared util code with rest of ctdb */
static void close_noerr(int fd)
{
	int olderr = errno;
	close(fd);
	errno = olderr;
}

/* FIXME: Could be in shared util code with rest of ctdb */
static void free_noerr(void *p)
{
	int olderr = errno;
	free(p);
	errno = olderr;
}

/* FIXME: Could be in shared util code with rest of ctdb */
static void set_nonblocking(int fd)
{
	unsigned v;
	v = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, v | O_NONBLOCK);
}

/* FIXME: Could be in shared util code with rest of ctdb */
static void set_close_on_exec(int fd)
{
	unsigned v;
	v = fcntl(fd, F_GETFD, 0);
        fcntl(fd, F_SETFD, v | FD_CLOEXEC);
}

static void set_pnn(struct ctdb_connection *ctdb,
		    struct ctdb_request *req,
		    void *unused)
{
	if (!ctdb_getpnn_recv(ctdb, req, &ctdb->pnn)) {
		DEBUG(ctdb, LOG_CRIT,
		      "ctdb_connect(async): failed to get pnn");
		ctdb->broken = true;
	}
	ctdb_request_free(req);
}

struct ctdb_connection *ctdb_connect(const char *addr,
				     ctdb_log_fn_t log_fn, void *log_priv)
{
	struct ctdb_connection *ctdb;
	struct sockaddr_un sun;

	ctdb = malloc(sizeof(*ctdb));
	if (!ctdb) {
		/* With no format string, we hope it doesn't use ap! */
		va_list ap;
		memset(&ap, 0, sizeof(ap));
		errno = ENOMEM;
		log_fn(log_priv, LOG_ERR, "ctdb_connect: no memory", ap);
		goto fail;
	}
	ctdb->pnn = -1;
	ctdb->outq = NULL;
	ctdb->doneq = NULL;
	ctdb->in = NULL;
	ctdb->inqueue = NULL;
	ctdb->message_handlers = NULL;
	ctdb->next_id = 0;
	ctdb->broken = false;
	ctdb->log = log_fn;
	ctdb->log_priv = log_priv;
	ctdb->locks = NULL;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (!addr)
		addr = CTDB_PATH;
	strncpy(sun.sun_path, addr, sizeof(sun.sun_path)-1);
	ctdb->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctdb->fd < 0)
		goto free_fail;

	if (connect(ctdb->fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		goto close_fail;

	set_nonblocking(ctdb->fd);
	set_close_on_exec(ctdb->fd);

	/* Immediately queue a request to get our pnn. */
	if (!ctdb_getpnn_send(ctdb, CTDB_CURRENT_NODE, set_pnn, NULL))
		goto close_fail;

	return ctdb;

close_fail:
	close_noerr(ctdb->fd);
free_fail:
	free_noerr(ctdb);
fail:
	return NULL;
}

void ctdb_disconnect(struct ctdb_connection *ctdb)
{
	struct ctdb_request *i;

	DEBUG(ctdb, LOG_DEBUG, "ctdb_disconnect");

	while ((i = ctdb->outq) != NULL) {
		DLIST_REMOVE(ctdb->outq, i);
		ctdb_request_free(i);
	}

	while ((i = ctdb->doneq) != NULL) {
		DLIST_REMOVE(ctdb->doneq, i);
		ctdb_request_free(i);
	}

	if (ctdb->in)
		free_io_elem(ctdb->in);

	remove_message_handlers(ctdb);

	close(ctdb->fd);
	/* Just in case they try to reuse */
	ctdb->fd = -1;
	free(ctdb);
}

int ctdb_get_fd(struct ctdb_connection *ctdb)
{
	return ctdb->fd;
}

int ctdb_which_events(struct ctdb_connection *ctdb)
{
	int events = POLLIN;

	if (ctdb->outq)
		events |= POLLOUT;
	return events;
}

struct ctdb_request *new_ctdb_request(struct ctdb_connection *ctdb, size_t len,
				      ctdb_callback_t cb, void *cbdata)
{
	struct ctdb_request *req = malloc(sizeof(*req));
	if (!req)
		return NULL;
	req->io = new_io_elem(len);
	if (!req->io) {
		free(req);
		return NULL;
	}
	req->ctdb = ctdb;
	req->hdr.hdr = io_elem_data(req->io, NULL);
	req->reply = NULL;
	req->callback = cb;
	req->priv_data = cbdata;
	req->extra = NULL;
	req->extra_destructor = NULL;
	return req;
}

void ctdb_request_free(struct ctdb_request *req)
{
	struct ctdb_connection *ctdb = req->ctdb;

	if (req->next || req->prev) {
		DEBUG(ctdb, LOG_ALERT,
		      "ctdb_request_free: request not complete! ctdb_cancel? %p (id %u)",
		      req, req->hdr.hdr ? req->hdr.hdr->reqid : 0);
		ctdb_cancel(ctdb, req);
		return;
	}
	if (req->extra_destructor) {
		req->extra_destructor(ctdb, req);
	}
	if (req->reply) {
		free_io_elem(req->reply);
	}
	free_io_elem(req->io);
	free(req);
}

/* Sanity-checking wrapper for reply. */
static struct ctdb_reply_call *unpack_reply_call(struct ctdb_request *req,
						 uint32_t callid)
{
	size_t len;
	struct ctdb_reply_call *inhdr = io_elem_data(req->reply, &len);

	/* Library user error if this isn't a reply to a call. */
	if (req->hdr.hdr->operation != CTDB_REQ_CALL) {
		errno = EINVAL;
		DEBUG(req->ctdb, LOG_ALERT,
		      "This was not a ctdbd call request: operation %u",
		      req->hdr.hdr->operation);
		return NULL;
	}

	if (req->hdr.call->callid != callid) {
		errno = EINVAL;
		DEBUG(req->ctdb, LOG_ALERT,
		      "This was not a ctdbd %u call request: %u",
		      callid, req->hdr.call->callid);
		return NULL;
	}

	/* ctdbd or our error if this isn't a reply call. */
	if (len < sizeof(*inhdr) || inhdr->hdr.operation != CTDB_REPLY_CALL) {
		errno = EIO;
		DEBUG(req->ctdb, LOG_CRIT,
		      "Invalid ctdbd call reply: len %zu, operation %u",
		      len, inhdr->hdr.operation);
		return NULL;
	}

	return inhdr;
}

/* Sanity-checking wrapper for reply. */
struct ctdb_reply_control *unpack_reply_control(struct ctdb_request *req,
						enum ctdb_controls control)
{
	size_t len;
	struct ctdb_reply_control *inhdr = io_elem_data(req->reply, &len);

	/* Library user error if this isn't a reply to a call. */
	if (len < sizeof(*inhdr)) {
		errno = EINVAL;
		DEBUG(req->ctdb, LOG_ALERT,
		      "Short ctdbd control reply: %zu bytes", len);
		return NULL;
	}
	if (req->hdr.hdr->operation != CTDB_REQ_CONTROL) {
		errno = EINVAL;
		DEBUG(req->ctdb, LOG_ALERT,
		      "This was not a ctdbd control request: operation %u",
		      req->hdr.hdr->operation);
		return NULL;
	}

	/* ... or if it was a different control from what we expected. */
	if (req->hdr.control->opcode != control) {
		errno = EINVAL;
		DEBUG(req->ctdb, LOG_ALERT,
		      "This was not an opcode %u ctdbd control request: %u",
		      control, req->hdr.control->opcode);
		return NULL;
	}

	/* ctdbd or our error if this isn't a reply call. */
	if (inhdr->hdr.operation != CTDB_REPLY_CONTROL) {
		errno = EIO;
		DEBUG(req->ctdb, LOG_CRIT,
		      "Invalid ctdbd control reply: operation %u",
		      inhdr->hdr.operation);
		return NULL;
	}

	return inhdr;
}

static void handle_incoming(struct ctdb_connection *ctdb, struct io_elem *in)
{
	struct ctdb_req_header *hdr;
	size_t len;
	struct ctdb_request *i;

	hdr = io_elem_data(in, &len);
	/* FIXME: use len to check packet! */

	if (hdr->operation == CTDB_REQ_MESSAGE) {
		deliver_message(ctdb, hdr);
		return;
	}

	for (i = ctdb->doneq; i; i = i->next) {
		if (i->hdr.hdr->reqid == hdr->reqid) {
			DLIST_REMOVE(ctdb->doneq, i);
			i->reply = in;
			i->callback(ctdb, i, i->priv_data);
			return;
		}
	}
	DEBUG(ctdb, LOG_WARNING,
	      "Unexpected ctdbd request reply: operation %u reqid %u",
	      hdr->operation, hdr->reqid);
	free_io_elem(in);
}

/* Remove "harmless" errors. */
static ssize_t real_error(ssize_t ret)
{
	if (ret < 0 && (errno == EINTR || errno == EWOULDBLOCK))
		return 0;
	return ret;
}

bool ctdb_service(struct ctdb_connection *ctdb, int revents)
{
	if (ctdb->broken) {
		return false;
	}

	if (holding_lock(ctdb)) {
		DEBUG(ctdb, LOG_ALERT, "Do not block while holding lock!");
	}

	if (revents & POLLOUT) {
		while (ctdb->outq) {
			if (real_error(write_io_elem(ctdb->fd,
						     ctdb->outq->io)) < 0) {
				DEBUG(ctdb, LOG_ERR,
				      "ctdb_service: error writing to ctdbd");
				ctdb->broken = true;
				return false;
			}
			if (io_elem_finished(ctdb->outq->io)) {
				struct ctdb_request *done = ctdb->outq;
				DLIST_REMOVE(ctdb->outq, done);
				/* We add at the head: any dead ones
				 * sit and end. */
				DLIST_ADD(ctdb->doneq, done);
			}
		}
	}

	while (revents & POLLIN) {
		int ret;
		int num_ready = 0;

		if (ioctl(ctdb->fd, FIONREAD, &num_ready) != 0) {
			DEBUG(ctdb, LOG_ERR,
			      "ctdb_service: ioctl(FIONREAD) %d", errno);
			ctdb->broken = true;
			return false;
		}
		if (num_ready == 0) {
			/* the descriptor has been closed or we have all our data */
			break;
		}


		if (!ctdb->in) {
			ctdb->in = new_io_elem(sizeof(struct ctdb_req_header));
			if (!ctdb->in) {
				DEBUG(ctdb, LOG_ERR,
				      "ctdb_service: allocating readbuf");
				ctdb->broken = true;
				return false;
			}
		}

		ret = read_io_elem(ctdb->fd, ctdb->in);
		if (real_error(ret) < 0 || ret == 0) {
			/* They closed fd? */
			if (ret == 0)
				errno = EBADF;
			DEBUG(ctdb, LOG_ERR,
			      "ctdb_service: error reading from ctdbd");
			ctdb->broken = true;
			return false;
		} else if (ret < 0) {
			/* No progress, stop loop. */
			break;
		} else if (io_elem_finished(ctdb->in)) {
			io_elem_queue(ctdb, ctdb->in);
			ctdb->in = NULL;
		}
	}


	while (ctdb->inqueue != NULL) {
		struct io_elem *io = ctdb->inqueue;

		io_elem_dequeue(ctdb, io);
		handle_incoming(ctdb, io);
	}

	return true;
}

/* This is inefficient.  We could pull in idtree.c. */
static bool reqid_used(const struct ctdb_connection *ctdb, uint32_t reqid)
{
	struct ctdb_request *i;

	for (i = ctdb->outq; i; i = i->next) {
		if (i->hdr.hdr->reqid == reqid) {
			return true;
		}
	}
	for (i = ctdb->doneq; i; i = i->next) {
		if (i->hdr.hdr->reqid == reqid) {
			return true;
		}
	}
	return false;
}

uint32_t new_reqid(struct ctdb_connection *ctdb)
{
	while (reqid_used(ctdb, ctdb->next_id)) {
		ctdb->next_id++;
	}
	return ctdb->next_id++;
}

struct ctdb_request *new_ctdb_control_request(struct ctdb_connection *ctdb,
					      uint32_t opcode,
					      uint32_t destnode,
					      const void *extra_data,
					      size_t extra,
					      ctdb_callback_t callback,
					      void *cbdata)
{
	struct ctdb_request *req;
	struct ctdb_req_control *pkt;

	req = new_ctdb_request(
		ctdb, offsetof(struct ctdb_req_control, data) + extra,
		callback, cbdata);
	if (!req)
		return NULL;

	io_elem_init_req_header(req->io,
				CTDB_REQ_CONTROL, destnode, new_reqid(ctdb));

	pkt = req->hdr.control;
	pkt->pad = 0;
	pkt->opcode = opcode;
	pkt->srvid = 0;
	pkt->client_id = 0;
	pkt->flags = 0;
	pkt->datalen = extra;
	memcpy(pkt->data, extra_data, extra);
	DLIST_ADD(ctdb->outq, req);
	return req;
}

void ctdb_cancel_callback(struct ctdb_connection *ctdb,
			  struct ctdb_request *req,
			  void *unused)
{
	ctdb_request_free(req);
}

void ctdb_cancel(struct ctdb_connection *ctdb, struct ctdb_request *req)
{
	if (!req->next && !req->prev) {
		DEBUG(ctdb, LOG_ALERT,
		      "ctdb_cancel: request completed! ctdb_request_free? %p (id %u)",
		      req, req->hdr.hdr ? req->hdr.hdr->reqid : 0);
		ctdb_request_free(req);
		return;
	}

	DEBUG(ctdb, LOG_DEBUG, "ctdb_cancel: %p (id %u)",
	      req, req->hdr.hdr ? req->hdr.hdr->reqid : 0);

	/* FIXME: If it's not sent, we could just free it right now. */
	req->callback = ctdb_cancel_callback;
}

void ctdb_detachdb(struct ctdb_connection *ctdb, struct ctdb_db *db)
{
	cleanup_locks(ctdb, db);
	tdb_close(db->tdb);
	free(db);
}

static void destroy_req_db(struct ctdb_connection *ctdb,
			   struct ctdb_request *req);
static void attachdb_done(struct ctdb_connection *ctdb,
			  struct ctdb_request *req,
			  void *_db);
static void attachdb_getdbpath_done(struct ctdb_connection *ctdb,
				    struct ctdb_request *req,
				    void *_db);

struct ctdb_request *
ctdb_attachdb_send(struct ctdb_connection *ctdb,
		   const char *name, bool persistent, uint32_t tdb_flags,
		   ctdb_callback_t callback, void *private_data)
{
	struct ctdb_request *req;
	struct ctdb_db *db;
	uint32_t opcode;

	/* FIXME: Search if db already open. */
	db = malloc(sizeof(*db));
	if (!db) {
		return NULL;
	}

	if (persistent) {
		opcode = CTDB_CONTROL_DB_ATTACH_PERSISTENT;
	} else {
		opcode = CTDB_CONTROL_DB_ATTACH;
	}

	req = new_ctdb_control_request(ctdb, opcode, CTDB_CURRENT_NODE, name,
				       strlen(name) + 1, attachdb_done, db);
	if (!req) {
		DEBUG(ctdb, LOG_ERR,
		      "ctdb_attachdb_send: failed allocating DB_ATTACH");
		free(db);
		return NULL;
	}

	db->ctdb = ctdb;
	db->tdb_flags = tdb_flags;
	db->persistent = persistent;
	db->callback = callback;
	db->private_data = private_data;

	req->extra_destructor = destroy_req_db;
	/* This is set non-NULL when we succeed, see ctdb_attachdb_recv */
	req->extra = NULL;

	/* Flags get overloaded into srvid. */
	req->hdr.control->srvid = tdb_flags;
	DEBUG(db->ctdb, LOG_DEBUG,
	      "ctdb_attachdb_send: DB_ATTACH request %p", req);
	return req;
}

static void destroy_req_db(struct ctdb_connection *ctdb,
			   struct ctdb_request *req)
{
	/* Incomplete db is in priv_data. */
	free(req->priv_data);
	/* second request is chained off this one. */
	if (req->extra) {
		ctdb_request_free(req->extra);
	}
}

static void attachdb_done(struct ctdb_connection *ctdb,
			  struct ctdb_request *req,
			  void *_db)
{
	struct ctdb_db *db = _db;
	struct ctdb_request *req2;
	struct ctdb_reply_control *reply;
	enum ctdb_controls control = CTDB_CONTROL_DB_ATTACH;

	if (db->persistent) {
		control = CTDB_CONTROL_DB_ATTACH_PERSISTENT;
	}

	reply = unpack_reply_control(req, control);
	if (!reply || reply->status != 0) {
		if (reply) {
			DEBUG(ctdb, LOG_ERR,
			      "ctdb_attachdb_send(async): DB_ATTACH status %i",
			      reply->status);
		}
		/* We failed.  Hand request to user and have them discover it
		 * via ctdb_attachdb_recv. */
		db->callback(ctdb, req, db->private_data);
		return;
	}
	db->id = *(uint32_t *)reply->data;

	/* Now we do another call, to get the dbpath. */
	req2 = new_ctdb_control_request(db->ctdb, CTDB_CONTROL_GETDBPATH,
					CTDB_CURRENT_NODE,
					&db->id, sizeof(db->id),
					attachdb_getdbpath_done, db);
	if (!req2) {
		DEBUG(db->ctdb, LOG_ERR,
		      "ctdb_attachdb_send(async): failed to allocate");
		db->callback(ctdb, req, db->private_data);
		return;
	}
	req->extra = req2;
	req2->extra = req;
	DEBUG(db->ctdb, LOG_DEBUG,
	      "ctdb_attachdb_send(async): created getdbpath request");
}

static void attachdb_getdbpath_done(struct ctdb_connection *ctdb,
				    struct ctdb_request *req,
				    void *_db)
{
	struct ctdb_db *db = _db;

	/* Do callback on original request. */
	db->callback(ctdb, req->extra, db->private_data);
}

struct ctdb_db *ctdb_attachdb_recv(struct ctdb_connection *ctdb,
				   struct ctdb_request *req)
{
	struct ctdb_request *dbpath_req = req->extra;
	struct ctdb_reply_control *reply;
	struct ctdb_db *db = req->priv_data;
	uint32_t tdb_flags = db->tdb_flags;
	struct tdb_logging_context log;

	/* Never sent the dbpath request?  We've failed. */
	if (!dbpath_req) {
		/* FIXME: Save errno? */
		errno = EINVAL;
		return NULL;
	}

	reply = unpack_reply_control(dbpath_req, CTDB_CONTROL_GETDBPATH);
	if (!reply) {
		return NULL;
	}
	if (reply->status != 0) {
		DEBUG(db->ctdb, LOG_ERR,
		      "ctdb_attachdb_recv: reply status %i", reply->status);
		return NULL;
	}

	tdb_flags = db->persistent ? TDB_DEFAULT : TDB_NOSYNC;
	tdb_flags |= TDB_DISALLOW_NESTING;

	log.log_fn = ctdb_tdb_log_bridge;
	log.log_private = ctdb;
	db->tdb = tdb_open_ex((char *)reply->data, 0, tdb_flags, O_RDWR, 0,
			      &log, NULL);
	if (db->tdb == NULL) {
		DEBUG(db->ctdb, LOG_ERR,
		      "ctdb_attachdb_recv: failed to tdb_open %s",
		      (char *)reply->data);
		return NULL;
	}

	/* Finally, separate the db from the request (see destroy_req_db). */
	req->priv_data = NULL;
	DEBUG(db->ctdb, LOG_DEBUG,
	      "ctdb_attachdb_recv: db %p, tdb %s", db, (char *)reply->data);
	return db;
}

static unsigned long lock_magic(struct ctdb_lock *lock)
{
	/* A non-zero magic specific to this structure. */
	return ((unsigned long)lock->key.dptr
		^ (((unsigned long)lock->key.dptr) << 16)
		^ 0xBADC0FFEEBADC0DEULL)
		| 1;
}

/* This is only called on locks before they're held. */
static void free_lock(struct ctdb_lock *lock)
{
	if (lock->held_magic) {
		DEBUG(lock->ctdb_db->ctdb, LOG_ALERT,
		      "free_lock invalid lock %p", lock);
	}
	free(lock->hdr);
	free(lock);
}


void ctdb_release_lock(struct ctdb_db *ctdb_db, struct ctdb_lock *lock)
{
	if (lock->held_magic != lock_magic(lock)) {
		DEBUG(lock->ctdb_db->ctdb, LOG_ALERT,
		      "ctdb_release_lock invalid lock %p", lock);
	} else if (lock->ctdb_db != ctdb_db) {
		errno = EBADF;
		DEBUG(ctdb_db->ctdb, LOG_ALERT,
		      "ctdb_release_lock: wrong ctdb_db.");
	} else {
		tdb_chainunlock(lock->ctdb_db->tdb, lock->key);
		DEBUG(lock->ctdb_db->ctdb, LOG_DEBUG,
		      "ctdb_release_lock %p", lock);
		remove_lock(lock->ctdb_db->ctdb, lock);
	}
	lock->held_magic = 0;
	free_lock(lock);
}


/* We keep the lock if local node is the dmaster. */
static bool try_readrecordlock(struct ctdb_lock *lock, TDB_DATA *data)
{
	struct ctdb_ltdb_header *hdr;

	if (tdb_chainlock(lock->ctdb_db->tdb, lock->key) != 0) {
		DEBUG(lock->ctdb_db->ctdb, LOG_WARNING,
		      "ctdb_readrecordlock_async: failed to chainlock");
		return NULL;
	}

	hdr = ctdb_local_fetch(lock->ctdb_db->tdb, lock->key, data);
	if (hdr && lock->readonly && (hdr->flags & CTDB_REC_RO_HAVE_READONLY) ) {
		DEBUG(lock->ctdb_db->ctdb, LOG_DEBUG,
		      "ctdb_readrecordlock_async: got local lock for ro");
		lock->held_magic = lock_magic(lock);
		lock->hdr = hdr;
		add_lock(lock->ctdb_db->ctdb, lock);
		return true;
	}
	if (hdr && hdr->dmaster == lock->ctdb_db->ctdb->pnn) {
		DEBUG(lock->ctdb_db->ctdb, LOG_DEBUG,
		      "ctdb_readrecordlock_async: got local lock");
		lock->held_magic = lock_magic(lock);
		lock->hdr = hdr;
		add_lock(lock->ctdb_db->ctdb, lock);
		return true;
	}

	/* we dont have the record locally,
	 * drop to writelock to force a migration
	 */
	if (!hdr && lock->readonly) {
		lock->readonly = false;
	}

	tdb_chainunlock(lock->ctdb_db->tdb, lock->key);
	free(hdr);
	return NULL;
}

/* If they shutdown before we hand them the lock, we free it here. */
static void destroy_lock(struct ctdb_connection *ctdb,
			 struct ctdb_request *req)
{
	free_lock(req->extra);
}

static void readrecordlock_retry(struct ctdb_connection *ctdb,
				 struct ctdb_request *req, void *private)
{
	struct ctdb_lock *lock = req->extra;
	struct ctdb_reply_call *reply;
	TDB_DATA data;

	/* OK, we've received reply to fetch migration */
	reply = unpack_reply_call(req, CTDB_FETCH_FUNC);
	if (!reply || reply->status != 0) {
		if (reply) {
			DEBUG(ctdb, LOG_ERR,
			      "ctdb_readrecordlock_async(async):"
			      " FETCH returned %i", reply->status);
		}
		lock->callback(lock->ctdb_db, NULL, tdb_null, private);
		ctdb_request_free(req); /* Also frees lock. */
		return;
	}

	/* Can we get lock now? */
	if (try_readrecordlock(lock, &data)) {
		/* Now it's their responsibility to free lock & request! */
		req->extra_destructor = NULL;
		lock->callback(lock->ctdb_db, lock, data, private);
		ctdb_request_free(req);
		return;
	}

	/* Retransmit the same request again (we lost race). */
	io_elem_reset(req->io);
	DLIST_ADD(ctdb->outq, req);
}

static bool
ctdb_readrecordlock_internal(struct ctdb_db *ctdb_db, TDB_DATA key,
			     bool readonly,
			     ctdb_rrl_callback_t callback, void *cbdata)
{
	struct ctdb_request *req;
	struct ctdb_lock *lock;
	TDB_DATA data;

	if (holding_lock(ctdb_db->ctdb)) {
		DEBUG(ctdb_db->ctdb, LOG_ALERT,
		      "ctdb_readrecordlock_async: already holding lock");
		return false;
	}

	/* Setup lock */
	lock = malloc(sizeof(*lock) + key.dsize);
	if (!lock) {
		DEBUG(ctdb_db->ctdb, LOG_ERR,
		      "ctdb_readrecordlock_async: lock allocation failed");
		return false;
	}
	lock->key.dptr = (void *)(lock + 1);
	memcpy(lock->key.dptr, key.dptr, key.dsize);
	lock->key.dsize = key.dsize;
	lock->ctdb_db = ctdb_db;
	lock->hdr = NULL;
	lock->held_magic = 0;
	lock->readonly = readonly;

	/* Fast path. */
	if (try_readrecordlock(lock, &data)) {
		callback(ctdb_db, lock, data, cbdata);
		return true;
	}

	/* Slow path: create request. */
	req = new_ctdb_request(
		ctdb_db->ctdb,
		offsetof(struct ctdb_req_call, data) + key.dsize,
		readrecordlock_retry, cbdata);
	if (!req) {
		DEBUG(ctdb_db->ctdb, LOG_ERR,
		      "ctdb_readrecordlock_async: allocation failed");
		free_lock(lock);
		return NULL;
	}
	req->extra = lock;
	req->extra_destructor = destroy_lock;
	/* We store the original callback in the lock, and use our own. */
	lock->callback = callback;

	io_elem_init_req_header(req->io, CTDB_REQ_CALL, CTDB_CURRENT_NODE,
				new_reqid(ctdb_db->ctdb));

	if (lock->readonly) {
		req->hdr.call->flags = CTDB_WANT_READONLY;
	} else {
		req->hdr.call->flags = CTDB_IMMEDIATE_MIGRATION;
	}
	req->hdr.call->db_id = ctdb_db->id;
	req->hdr.call->callid = CTDB_FETCH_FUNC;
	req->hdr.call->hopcount = 0;
	req->hdr.call->keylen = key.dsize;
	req->hdr.call->calldatalen = 0;
	memcpy(req->hdr.call->data, key.dptr, key.dsize);
	DLIST_ADD(ctdb_db->ctdb->outq, req);
	return true;
}

bool
ctdb_readrecordlock_async(struct ctdb_db *ctdb_db, TDB_DATA key,
			  ctdb_rrl_callback_t callback, void *cbdata)
{
	return ctdb_readrecordlock_internal(ctdb_db, key,
			false,
			callback, cbdata);
}

bool
ctdb_readonlyrecordlock_async(struct ctdb_db *ctdb_db, TDB_DATA key,
			  ctdb_rrl_callback_t callback, void *cbdata)
{
	return ctdb_readrecordlock_internal(ctdb_db, key,
			true,
			callback, cbdata);
}

bool ctdb_writerecord(struct ctdb_db *ctdb_db,
		      struct ctdb_lock *lock, TDB_DATA data)
{
	if (lock->readonly) {
		errno = EBADF;
		DEBUG(ctdb_db->ctdb, LOG_ALERT,
		      "ctdb_writerecord: Can not write, read-only record.");
		return false;
	}

	if (lock->ctdb_db != ctdb_db) {
		errno = EBADF;
		DEBUG(ctdb_db->ctdb, LOG_ALERT,
		      "ctdb_writerecord: Can not write, wrong ctdb_db.");
		return false;
	}

	if (lock->held_magic != lock_magic(lock)) {
		errno = EBADF;
		DEBUG(ctdb_db->ctdb, LOG_ALERT,
		      "ctdb_writerecord: Can not write. Lock has been released.");
		return false;
	}
		
	if (ctdb_db->persistent) {
		errno = EINVAL;
		DEBUG(ctdb_db->ctdb, LOG_ALERT,
		      "ctdb_writerecord: cannot write to persistent db");
		return false;
	}

	switch (ctdb_local_store(ctdb_db->tdb, lock->key, lock->hdr, data)) {
	case 0:
		DEBUG(ctdb_db->ctdb, LOG_DEBUG,
		      "ctdb_writerecord: optimized away noop write.");
		/* fall thru */
	case 1:
		return true;

	default:
		switch (errno) {
		case ENOMEM:
			DEBUG(ctdb_db->ctdb, LOG_CRIT,
			      "ctdb_writerecord: out of memory.");
			break;
		case EINVAL:
			DEBUG(ctdb_db->ctdb, LOG_ALERT,
			      "ctdb_writerecord: record changed under lock?");
			break;
		default: /* TDB already logged. */
			break;
		}
		return false;
	}
}


struct ctdb_traverse_state {
	struct ctdb_request *handle;
	struct ctdb_db *ctdb_db;
	uint64_t srvid;

	ctdb_traverse_callback_t callback;
	void *cbdata;
};

static void traverse_remhnd_cb(struct ctdb_connection *ctdb,
                        struct ctdb_request *req, void *private_data)
{
	struct ctdb_traverse_state *state = private_data;

	if (!ctdb_remove_message_handler_recv(ctdb, state->handle)) {
		DEBUG(ctdb, LOG_ERR,
				"Failed to remove message handler for"
				" traverse.");
		state->callback(state->ctdb_db->ctdb, state->ctdb_db,
				TRAVERSE_STATUS_ERROR,
				tdb_null, tdb_null,
				state->cbdata);
	}
	ctdb_request_free(state->handle);
	state->handle = NULL;
	free(state);
}
	
static void msg_h(struct ctdb_connection *ctdb, uint64_t srvid,
	   TDB_DATA data, void *private_data)
{
	struct ctdb_traverse_state *state = private_data;
	struct ctdb_db *ctdb_db = state->ctdb_db;
	struct ctdb_rec_data *d = (struct ctdb_rec_data *)data.dptr;
	TDB_DATA key;

	if (data.dsize < sizeof(uint32_t) ||
	    d->length != data.dsize) {
		DEBUG(ctdb, LOG_ERR,
			"Bad data size %u in traverse_handler",
			(unsigned)data.dsize);
		state->callback(state->ctdb_db->ctdb, state->ctdb_db,
				TRAVERSE_STATUS_ERROR,
				tdb_null, tdb_null,
				state->cbdata);
		state->handle = ctdb_remove_message_handler_send(
				state->ctdb_db->ctdb, state->srvid,
				msg_h, state,
				traverse_remhnd_cb, state);
		return;
	}

	key.dsize = d->keylen;
	key.dptr  = &d->data[0];
	data.dsize = d->datalen;
	data.dptr = &d->data[d->keylen];

	if (key.dsize == 0 && data.dsize == 0) {
		state->callback(state->ctdb_db->ctdb, state->ctdb_db,
				TRAVERSE_STATUS_FINISHED,
				tdb_null, tdb_null,
				state->cbdata);
		state->handle = ctdb_remove_message_handler_send(
				state->ctdb_db->ctdb, state->srvid,
				msg_h, state,
				traverse_remhnd_cb, state);
		return;
	}

	if (data.dsize <= sizeof(struct ctdb_ltdb_header)) {
		/* empty records are deleted records in ctdb */
		return;
	}

	data.dsize -= sizeof(struct ctdb_ltdb_header);
	data.dptr  += sizeof(struct ctdb_ltdb_header);

	if (state->callback(ctdb, ctdb_db,
			TRAVERSE_STATUS_RECORD,
			key, data, state->cbdata) != 0) {
		state->handle = ctdb_remove_message_handler_send(
				state->ctdb_db->ctdb, state->srvid,
				msg_h, state,
				traverse_remhnd_cb, state);
		return;
	}
}

static void traverse_start_cb(struct ctdb_connection *ctdb,
                        struct ctdb_request *req, void *private_data)
{
	struct ctdb_traverse_state *state = private_data;

        ctdb_request_free(state->handle);
	state->handle = NULL;
}

static void traverse_msghnd_cb(struct ctdb_connection *ctdb,
                        struct ctdb_request *req, void *private_data)
{
	struct ctdb_traverse_state *state = private_data;
	struct ctdb_db *ctdb_db = state->ctdb_db;
	struct ctdb_traverse_start t;

	if (!ctdb_set_message_handler_recv(ctdb, state->handle)) {
		DEBUG(ctdb, LOG_ERR,
				"Failed to register message handler for"
				" traverse.");
		state->callback(state->ctdb_db->ctdb, state->ctdb_db,
				TRAVERSE_STATUS_ERROR,
				tdb_null, tdb_null,
				state->cbdata);
	        ctdb_request_free(state->handle);
		state->handle = NULL;
		free(state);
		return;
        }
        ctdb_request_free(state->handle);
	state->handle = NULL;

	t.db_id = ctdb_db->id;
	t.srvid = state->srvid;
	t.reqid = 0;

	state->handle = new_ctdb_control_request(ctdb,
				CTDB_CONTROL_TRAVERSE_START,
				CTDB_CURRENT_NODE,
				&t, sizeof(t),
				traverse_start_cb, state);
	if (state->handle == NULL) {
		DEBUG(ctdb, LOG_ERR,
				"ctdb_traverse_async:"
				" failed to send traverse_start control");
		state->callback(state->ctdb_db->ctdb, state->ctdb_db,
				TRAVERSE_STATUS_ERROR,
				tdb_null, tdb_null,
				state->cbdata);
		state->handle = ctdb_remove_message_handler_send(
				state->ctdb_db->ctdb, state->srvid,
				msg_h, state,
				traverse_remhnd_cb, state);
		return;
	}
}

bool ctdb_traverse_async(struct ctdb_db *ctdb_db,
			 ctdb_traverse_callback_t callback, void *cbdata)
{
	struct ctdb_connection *ctdb = ctdb_db->ctdb;
	struct ctdb_traverse_state *state;
	static uint32_t tid = 0;

	state = malloc(sizeof(struct ctdb_traverse_state));
	if (state == NULL) {
		DEBUG(ctdb, LOG_ERR,
				"ctdb_traverse_async: no memory."
				" allocate state failed");
		return false;
	}

	tid++;
	state->srvid = CTDB_SRVID_TRAVERSE_RANGE|tid;

	state->callback = callback;
	state->cbdata   = cbdata;
	state->ctdb_db  = ctdb_db;

	state->handle = ctdb_set_message_handler_send(ctdb_db->ctdb,
				state->srvid,
				msg_h, state,
				traverse_msghnd_cb, state);
	if (state->handle == NULL) {
		DEBUG(ctdb, LOG_ERR,
			"ctdb_traverse_async:"
			" failed ctdb_set_message_handler_send");
		free(state);
		return false;
	}

	return true;
}

int ctdb_num_out_queue(struct ctdb_connection *ctdb)
{
	struct ctdb_request *req;
	int i;

	for (i = 0, req = ctdb->outq; req; req = req->next, i++)
		;

	return i;
}

int ctdb_num_in_flight(struct ctdb_connection *ctdb)
{
	struct ctdb_request *req;
	int i;

	for (i = 0, req = ctdb->doneq; req; req = req->next, i++)
		;

	return i;
}

int ctdb_num_active(struct ctdb_connection *ctdb)
{
	return ctdb_num_out_queue(ctdb)
		 + ctdb_num_in_flight(ctdb);
}

