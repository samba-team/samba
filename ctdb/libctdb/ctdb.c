/*
   core of libctdb

   Copyright (C) Rusty Russell 2010

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
#include <ctdb.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "libctdb_private.h"
#include "io_elem.h"
#include "local_tdb.h"
#include "messages.h"
#include <dlinklist.h>
#include <ctdb_protocol.h>

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

static void set_pnn(int32_t status, uint32_t pnn, void *private_data)
{
	if (status != 0) {
		/* FIXME: Report error. */
		((struct ctdb_connection *)private_data)->broken = true;
	} else {
		((struct ctdb_connection *)private_data)->pnn = pnn;
	}
}

struct ctdb_connection *ctdb_connect(const char *addr)
{
	struct ctdb_connection *ctdb;
	struct sockaddr_un sun;

	ctdb = malloc(sizeof(*ctdb));
	if (!ctdb)
		goto fail;
	ctdb->outq = NULL;
	ctdb->doneq = NULL;
	ctdb->immediateq = NULL;
	ctdb->in = NULL;
	ctdb->message_handlers = NULL;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (!addr)
		addr = CTDB_PATH;
	strncpy(sun.sun_path, addr, sizeof(sun.sun_path));
	ctdb->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctdb->fd < 0)
		goto free_fail;

	set_nonblocking(ctdb->fd);
	set_close_on_exec(ctdb->fd);

	if (connect(ctdb->fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		goto close_fail;

	/* Immediately queue a request to get our pnn. */
	if (!ctdb_getpnn_send(ctdb, CTDB_CURRENT_NODE, set_pnn, ctdb))
		goto close_fail;

	return ctdb;

close_fail:
	close_noerr(ctdb->fd);
free_fail:
	free_noerr(ctdb);
fail:
	return NULL;
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

struct ctdb_request *new_ctdb_request(size_t len)
{
	struct ctdb_request *req = malloc(sizeof(*req));
	if (!req)
		return NULL;
	req->io = new_io_elem(len);
	if (!req->io) {
		free(req);
		return NULL;
	}
	req->hdr.hdr = io_elem_data(req->io, NULL);
	req->cancelled = false;
	return req;
}

static struct ctdb_request *new_immediate_request(void)
{
	struct ctdb_request *req = malloc(sizeof(*req));
	if (!req)
		return NULL;
	req->cancelled = false;
	req->io = NULL;
	req->hdr.hdr = NULL;
	return req;
}

static void free_ctdb_request(struct ctdb_request *req)
{
	/* immediate requests don't have IO */
	if (req->io) {
		free_io_elem(req->io);
	}
	free(req);
}

static void handle_call_reply(struct ctdb_connection *ctdb,
			      struct ctdb_req_header *hdr,
			      struct ctdb_request *i)
{
	struct ctdb_req_call *call = i->hdr.call;
	struct ctdb_reply_call *reply = (struct ctdb_reply_call *)hdr;

	switch (call->callid) {
	case CTDB_NULL_FUNC:
		/* FIXME: We should let it steal the request, rathe than copy */
		i->callback.nullfunc(reply->status, reply, i->priv_data);
		break;
	}
}

static void handle_control_reply(struct ctdb_connection *ctdb,
				 struct ctdb_req_header *hdr,
				 struct ctdb_request *i)
{
	struct ctdb_req_control *control = i->hdr.control;
	struct ctdb_reply_control *reply = (struct ctdb_reply_control *)hdr;

	switch (control->opcode) {
	case CTDB_CONTROL_GET_RECMASTER:
		i->callback.getrecmaster(0, reply->status, i->priv_data);
		break;
	case CTDB_CONTROL_GET_PNN:
		i->callback.getpnn(0, reply->status, i->priv_data);
		break;
	case CTDB_CONTROL_REGISTER_SRVID:
		i->callback.register_srvid(reply->status, i->priv_data);
		break;
	case CTDB_CONTROL_DB_ATTACH_PERSISTENT:
	case CTDB_CONTROL_DB_ATTACH:
		i->callback.attachdb(reply->status, *(uint32_t *)reply->data,
				     i->priv_data);
		break;
	case CTDB_CONTROL_GETDBPATH:
		i->callback.getdbpath(reply->status, (char *)reply->data,
				      i->priv_data);
		break;
	}
}

static void handle_incoming(struct ctdb_connection *ctdb,
			    struct ctdb_req_header *hdr,
			    size_t len /* FIXME: use len to check packet! */)
{
	struct ctdb_request *i;

	if (hdr->operation == CTDB_REQ_MESSAGE) {
		deliver_message(ctdb, hdr);
		return;
	}

	if (hdr->operation != CTDB_REPLY_CALL
	    && hdr->operation != CTDB_REPLY_CONTROL) {
		/* FIXME: report this error. */
		return;
	}

	for (i = ctdb->doneq; i; i = i->next) {
		if (i->hdr.hdr->reqid == hdr->reqid) {
			if (!i->cancelled) {
				if (hdr->operation == CTDB_REPLY_CALL)
					handle_call_reply(ctdb, hdr, i);
				else
					handle_control_reply(ctdb, hdr, i);
			}
			DLIST_REMOVE(ctdb->doneq, i);
			free_ctdb_request(i);
			return;
		}
	}
	/* FIXME: report this error. */
}

/* Remove "harmless" errors. */
static ssize_t real_error(ssize_t ret)
{
	if (ret < 0 && (errno == EINTR || errno == EWOULDBLOCK))
		return 0;
	return ret;
}

int ctdb_service(struct ctdb_connection *ctdb, int revents)
{
	if (ctdb->broken) {
		return -1;
	}

	if (revents & POLLOUT) {
		while (ctdb->outq) {
			if (real_error(write_io_elem(ctdb->fd,
						     ctdb->outq->io)) < 0) {
				ctdb->broken = true;
				return -1;
			}
			if (io_elem_finished(ctdb->outq->io)) {
				struct ctdb_request *done = ctdb->outq;
				DLIST_REMOVE(ctdb->outq, done);
				if (done->cancelled) {
					free_ctdb_request(done);
				} else {
					DLIST_ADD_END(ctdb->doneq, done,
						      struct ctdb_request);
				}
			}
		}
	}

	while (revents & POLLIN) {
		int ret;

		if (!ctdb->in) {
			ctdb->in = new_io_elem(sizeof(struct ctdb_req_header));
			if (!ctdb->in) {
				ctdb->broken = true;
				return -1;
			}
		}

		ret = read_io_elem(ctdb->fd, ctdb->in);
		if (real_error(ret) < 0 || ret == 0) {
			/* They closed fd? */
			if (ret == 0)
				errno = EBADF;
			ctdb->broken = true;
			return -1;
		} else if (ret < 0) {
			/* No progress, stop loop. */
			revents = 0;
		} else if (io_elem_finished(ctdb->in)) {
			struct ctdb_req_header *hdr;
			size_t len;

			hdr = io_elem_data(ctdb->in, &len);
			handle_incoming(ctdb, hdr, len);
			free_io_elem(ctdb->in);
			ctdb->in = NULL;
		}
	}

	while (ctdb->immediateq) {
		struct ctdb_request *imm = ctdb->immediateq;
		/* This has to handle fake->cancelled internally. */
		imm->callback.immediate(imm, imm->priv_data);
		DLIST_REMOVE(ctdb->immediateq, imm);
		free_ctdb_request(imm);
	}

	return 0;
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
					      size_t extra)
{
	struct ctdb_request *req;
	struct ctdb_req_control *pkt;

	req = new_ctdb_request(sizeof(*pkt) + extra);
	if (!req)
		return NULL;

	io_elem_init_req_header(req->io,
				CTDB_REQ_CONTROL, destnode, new_reqid(ctdb));

	pkt = req->hdr.control;
	pkt->opcode = opcode;
	pkt->srvid = 0;
	pkt->client_id = 0;
	pkt->flags = 0;
	pkt->datalen = extra;
	memcpy(pkt->data, extra_data, extra);
	DLIST_ADD_END(ctdb->outq, req, struct ctdb_request);
	return req;
}

int ctdb_cancel(struct ctdb_request *req)
{
	/* FIXME: If it's not sent, we could just free it right now. */
	req->cancelled = true;
	return 0;
}

struct ctdb_db {
	struct ctdb_connection *ctdb;
	bool persistent;
	uint32_t tdb_flags;
	uint32_t id;
	struct tdb_context *tdb;

	ctdb_attachdb_cb callback;
	void *private_data;
};

static void attachdb_getdbpath_done(int status, const char *path,
				    void *_db)
{
	struct ctdb_db *db = _db;
	uint32_t tdb_flags = db->tdb_flags;

	if (status != 0) {
		db->callback(status, NULL, db->private_data);
		free(db);
		return;
	}

	tdb_flags = db->persistent ? TDB_DEFAULT : TDB_NOSYNC;
	tdb_flags |= TDB_DISALLOW_NESTING;

	db->tdb = tdb_open(path, 0, tdb_flags, O_RDWR, 0);
	if (db->tdb == NULL) {
		db->callback(-1, NULL, db->private_data);
		free(db);
		return;
	}

	/* Finally, we tell the client that we opened the db. */
	db->callback(status, db, db->private_data);
}

static void attachdb_done(int status, uint32_t id, struct ctdb_db *db)
{
	struct ctdb_request *req;

	if (status != 0) {
		db->callback(status, NULL, db->private_data);
		free(db);
		return;
	}
	db->id = id;

	/* Now we do another call, to get the dbpath. */
	req = new_ctdb_control_request(db->ctdb, CTDB_CONTROL_GETDBPATH,
				       CTDB_CURRENT_NODE, &id, sizeof(id));
	if (!req) {
		db->callback(-1, NULL, db->private_data);
		free(db);
		return;
	}
	req->callback.getdbpath = attachdb_getdbpath_done;
	req->priv_data = db;
}

struct ctdb_request *
ctdb_attachdb_send(struct ctdb_connection *ctdb,
		   const char *name, int persistent, uint32_t tdb_flags,
		   ctdb_attachdb_cb callback,
		   void *private_data)
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
				       strlen(name) + 1);
	if (!req) {
		free(db);
		return NULL;
	}

	db->ctdb = ctdb;
	db->tdb_flags = tdb_flags;
	db->persistent = persistent;
	db->callback = callback;
	db->private_data = private_data;

	req->callback.attachdb = attachdb_done;
	req->priv_data = db;

	/* Flags get overloaded into srvid. */
	req->hdr.control->srvid = tdb_flags;
	return req;
}

struct ctdb_lock {
	struct ctdb_db *ctdb_db;
	TDB_DATA key;
	struct ctdb_ltdb_header *hdr;
	TDB_DATA data;
	bool held;
	/* For convenience, we stash this here. */
	ctdb_readrecordlock_cb callback;
	void *private_data;
};

void ctdb_release_lock(struct ctdb_lock *lock)
{
	if (lock->held) {
		tdb_chainunlock(lock->ctdb_db->tdb, lock->key);
	}
	free(lock->key.dptr);
	free(lock->hdr); /* Also frees lock->data */
	free(lock);
}

/* We keep the lock if local node is the dmaster. */
static bool try_readrecordlock(struct ctdb_lock *lock)
{
	if (tdb_chainlock(lock->ctdb_db->tdb, lock->key) != 0) {
		return false;
	}

	lock->hdr = ctdb_local_fetch(lock->ctdb_db->tdb,
				     lock->key, &lock->data);
	if (lock->hdr && lock->hdr->dmaster == lock->ctdb_db->ctdb->pnn) {
		lock->held = true;
		return true;
	}

	tdb_chainunlock(lock->ctdb_db->tdb, lock->key);
	free(lock->hdr);
	return false;
}

static void readrecordlock_done(int, struct ctdb_reply_call *, void *);

static struct ctdb_request *new_readrecordlock_request(struct ctdb_lock *lock)
{
	struct ctdb_request *req;
	struct ctdb_req_call *pkt;

	req = new_ctdb_request(sizeof(*pkt) + lock->key.dsize);
	if (!req)
		return NULL;
	req->callback.nullfunc = readrecordlock_done;
	req->priv_data = lock;

	io_elem_init_req_header(req->io, CTDB_REQ_CALL, CTDB_CURRENT_NODE,
				new_reqid(lock->ctdb_db->ctdb));

	pkt = req->hdr.call;
	pkt->flags = CTDB_IMMEDIATE_MIGRATION;
	pkt->db_id = lock->ctdb_db->id;
	pkt->callid = CTDB_NULL_FUNC;
	pkt->hopcount = 0;
	pkt->keylen = lock->key.dsize;
	pkt->calldatalen = 0;
	memcpy(pkt->data, lock->key.dptr, lock->key.dsize);
	DLIST_ADD_END(lock->ctdb_db->ctdb->outq, req, struct ctdb_request);
	return req;
}

/* OK, let's try again... */
static void readrecordlock_done(int status, struct ctdb_reply_call *reply,
				void *_lock)
{
	struct ctdb_lock *lock = _lock;

	if (status != 0) {
		lock->callback(status, NULL, tdb_null, lock->private_data);
		ctdb_release_lock(lock);
		return;
	}

	if (try_readrecordlock(lock)) {
		lock->callback(0, lock, lock->data, lock->private_data);
		return;
	}

	if (!new_readrecordlock_request(lock)) {
		lock->callback(-1, NULL, tdb_null, lock->private_data);
		ctdb_release_lock(lock);
	}
}

static void lock_complete(struct ctdb_request *req, void *_lock)
{
	struct ctdb_lock *lock = _lock;

	if (!req->cancelled) {
		lock->callback(0, lock, lock->data, lock->private_data);
	} else {
		ctdb_release_lock(lock);
	}
}

struct ctdb_request *
ctdb_readrecordlock_send(struct ctdb_db *ctdb_db,
			 TDB_DATA key,
			 ctdb_readrecordlock_cb callback,
			 void *private_data)
{
	struct ctdb_request *req;
	struct ctdb_lock *lock;

	lock = malloc(sizeof(*lock));
	if (!lock)
		return NULL;
	lock->key.dptr = malloc(key.dsize);
	if (!lock->key.dptr) {
		free_noerr(lock);
		return NULL;
	}
	memcpy(lock->key.dptr, key.dptr, key.dsize);
	lock->key.dsize = key.dsize;
	lock->ctdb_db = ctdb_db;
	lock->callback = callback;
	lock->private_data = private_data;
	lock->hdr = NULL;
	lock->held = false;

	if (try_readrecordlock(lock)) {
		/* We pretend to be async, so we just queue this. */
		req = new_immediate_request();
		if (!req) {
			ctdb_release_lock(lock);
			return NULL;
		}
		req->callback.immediate = lock_complete;
		req->priv_data = lock;
		DLIST_ADD_END(lock->ctdb_db->ctdb->immediateq,
			      req, struct ctdb_request);
		return req;
	}

	req = new_readrecordlock_request(lock);
	if (!req) {
		ctdb_release_lock(lock);
		return NULL;
	}
	return req;
}

int ctdb_writerecord(struct ctdb_lock *lock, TDB_DATA data)
{
	if (lock->ctdb_db->persistent) {
		/* FIXME: Report error. */
		return -1;
	}

	return ctdb_local_store(lock->ctdb_db->tdb, lock->key, lock->hdr, data);
}
