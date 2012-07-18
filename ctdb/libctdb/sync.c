/*
   synchronous wrappers for libctdb

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
#include <sys/socket.h>
#include <ctdb.h>
#include <stdbool.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include "libctdb_private.h"

/* Remove type-safety macros. */
#undef ctdb_set_message_handler

/* On failure, frees req and returns NULL. */
static struct ctdb_request *synchronous(struct ctdb_connection *ctdb,
					struct ctdb_request *req,
					bool *done)
{
	struct pollfd fds;

	/* Pass through allocation failures. */
	if (!req)
		return NULL;

	fds.fd = ctdb_get_fd(ctdb);
	while (!*done) {
		fds.events = ctdb_which_events(ctdb);
		if (poll(&fds, 1, -1) < 0) {
			/* Signalled is OK, other error is bad. */
			if (errno == EINTR)
				continue;
			ctdb_cancel(ctdb, req);
			DEBUG(ctdb, LOG_ERR, "ctdb_synchronous: poll failed");
			return NULL;
		}
		if (!ctdb_service(ctdb, fds.revents)) {
			/* It can have failed after it completed request. */
			if (!*done)
				ctdb_cancel(ctdb, req);
			else
				ctdb_request_free(req);
			return NULL;
		}
	}
	return req;
}

static void set(struct ctdb_connection *ctdb,
		struct ctdb_request *req, bool *done)
{
	*done = true;
}

bool ctdb_getrecmaster(struct ctdb_connection *ctdb,
		       uint32_t destnode, uint32_t *recmaster)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	req = synchronous(ctdb,
			  ctdb_getrecmaster_send(ctdb, destnode, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_getrecmaster_recv(ctdb, req, recmaster);
		ctdb_request_free(req);
	}
	return ret;
}

bool ctdb_getrecmode(struct ctdb_connection *ctdb,
		       uint32_t destnode, uint32_t *recmode)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	req = synchronous(ctdb,
			  ctdb_getrecmode_send(ctdb, destnode, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_getrecmode_recv(ctdb, req, recmode);
		ctdb_request_free(req);
	}
	return ret;
}

struct ctdb_db *ctdb_attachdb(struct ctdb_connection *ctdb,
			      const char *name, bool persistent,
			      uint32_t tdb_flags)
{
	struct ctdb_request *req;
	bool done = false;
	struct ctdb_db *ret = NULL;

	req = synchronous(ctdb,
			  ctdb_attachdb_send(ctdb, name, persistent, tdb_flags,
					     set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_attachdb_recv(ctdb, req);
		ctdb_request_free(req);
	}
	return ret;
}

bool ctdb_getpnn(struct ctdb_connection *ctdb,
		 uint32_t destnode, uint32_t *pnn)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	req = synchronous(ctdb,
			  ctdb_getpnn_send(ctdb, destnode, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_getpnn_recv(ctdb, req, pnn);
		ctdb_request_free(req);
	}
	return ret;
}

bool ctdb_getdbstat(struct ctdb_connection *ctdb,
		    uint32_t destnode, uint32_t db_id,
		    struct ctdb_db_statistics **stat)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	req = synchronous(ctdb,
			  ctdb_getdbstat_send(ctdb, destnode, db_id, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_getdbstat_recv(ctdb, req, stat);
		ctdb_request_free(req);
	}
	return ret;
}

bool ctdb_check_message_handlers(struct ctdb_connection *ctdb,
		      uint32_t destnode, uint32_t num,
		      uint64_t *mhs, uint8_t *result)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	req = synchronous(ctdb,
			  ctdb_check_message_handlers_send(ctdb, destnode, num, mhs, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_check_message_handlers_recv(ctdb, req, num, result);
		ctdb_request_free(req);
	}
	return ret;
}

bool ctdb_getnodemap(struct ctdb_connection *ctdb,
		 uint32_t destnode, struct ctdb_node_map **nodemap)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	*nodemap = NULL;

	req = synchronous(ctdb,
			  ctdb_getnodemap_send(ctdb, destnode, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_getnodemap_recv(ctdb, req, nodemap);
		ctdb_request_free(req);
	}
	return ret;
}

bool ctdb_getpublicips(struct ctdb_connection *ctdb,
		       uint32_t destnode, struct ctdb_all_public_ips **ips)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	*ips = NULL;

	req = synchronous(ctdb,
			  ctdb_getpublicips_send(ctdb, destnode, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_getpublicips_recv(ctdb, req, ips);
		ctdb_request_free(req);
	}
	return ret;
}

bool ctdb_set_message_handler(struct ctdb_connection *ctdb, uint64_t srvid,
			      ctdb_message_fn_t handler, void *cbdata)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	req = synchronous(ctdb,
			  ctdb_set_message_handler_send(ctdb, srvid, handler,
							cbdata, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_set_message_handler_recv(ctdb, req);
		ctdb_request_free(req);
	}
	return ret;
}

struct rrl_info {
	bool done;
	struct ctdb_lock *lock;
	TDB_DATA *data;
};

static void rrl_callback(struct ctdb_db *ctdb_db,
			 struct ctdb_lock *lock,
			 TDB_DATA data,
			 struct rrl_info *rrl)
{
	rrl->done = true;
	rrl->lock = lock;
	*rrl->data = data;
}

struct ctdb_lock *ctdb_readrecordlock(struct ctdb_connection *ctdb,
				      struct ctdb_db *ctdb_db, TDB_DATA key,
				      TDB_DATA *data)
{
	struct pollfd fds;
	struct rrl_info rrl;

	rrl.done = false;
	rrl.lock = NULL;
	rrl.data = data;

	/* Immediate failure is easy. */
	if (!ctdb_readrecordlock_async(ctdb_db, key, rrl_callback, &rrl))
		return NULL;

	/* Immediate success is easy. */
	if (!rrl.done) {
		/* Otherwise wait until callback called. */
		fds.fd = ctdb_get_fd(ctdb);
		while (!rrl.done) {
			fds.events = ctdb_which_events(ctdb);
			if (poll(&fds, 1, -1) < 0) {
				/* Signalled is OK, other error is bad. */
				if (errno == EINTR)
					continue;
				DEBUG(ctdb, LOG_ERR,
				      "ctdb_readrecordlock: poll failed");
				return NULL;
			}
			if (!ctdb_service(ctdb, fds.revents)) {
				break;
			}
		}
	}
	return rrl.lock;
}

bool ctdb_getdbseqnum(struct ctdb_connection *ctdb,
		      uint32_t destnode, uint32_t dbid,
		      uint64_t *seqnum)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	req = synchronous(ctdb,
			  ctdb_getdbseqnum_send(ctdb, destnode, dbid, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_getdbseqnum_recv(ctdb, req, seqnum);
		ctdb_request_free(req);
	}
	return ret;
}

bool ctdb_getifaces(struct ctdb_connection *ctdb,
		    uint32_t destnode, struct ctdb_ifaces_list **ifaces)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	*ifaces = NULL;

	req = synchronous(ctdb,
			  ctdb_getifaces_send(ctdb, destnode, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_getifaces_recv(ctdb, req, ifaces);
		ctdb_request_free(req);
	}
	return ret;
}

bool ctdb_getvnnmap(struct ctdb_connection *ctdb,
		    uint32_t destnode, struct ctdb_vnn_map **vnnmap)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	*vnnmap = NULL;

	req = synchronous(ctdb,
			  ctdb_getvnnmap_send(ctdb, destnode, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_getvnnmap_recv(ctdb, req, vnnmap);
		ctdb_request_free(req);
	}
	return ret;
}

bool ctdb_getcapabilities(struct ctdb_connection *ctdb,
			  uint32_t destnode, uint32_t *capabilities)
{
	struct ctdb_request *req;
	bool done = false;
	bool ret = false;

	req = synchronous(ctdb,
			  ctdb_getcapabilities_send(ctdb, destnode, set, &done),
			  &done);
	if (req != NULL) {
		ret = ctdb_getcapabilities_recv(ctdb, req, capabilities);
		ctdb_request_free(req);
	}
	return ret;
}

