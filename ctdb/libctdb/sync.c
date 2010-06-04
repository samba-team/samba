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
#include <ctdb.h>
#include <stdbool.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include "libctdb_private.h"

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
			ctdb_request_free(ctdb, req);
			DEBUG(ctdb, LOG_ERR, "ctdb_synchronous: poll failed");
			return NULL;
		}
		if (ctdb_service(ctdb, fds.revents) < 0) {
			ctdb_request_free(ctdb, req);
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
		ctdb_request_free(ctdb, req);
	}
	return ret;
}

struct ctdb_db *ctdb_attachdb(struct ctdb_connection *ctdb,
			      const char *name, int persistent,
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
		ctdb_request_free(ctdb, req);
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
		ctdb_request_free(ctdb, req);
	}
	return ret;
}
