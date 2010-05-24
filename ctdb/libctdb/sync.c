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

/* On failure, frees req and returns NULL. */
static struct ctdb_request *wait_for(struct ctdb_connection *ctdb,
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
			ctdb_request_free(req);
			return NULL;
		}
		if (ctdb_service(ctdb, fds.revents) < 0) {
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

int ctdb_getrecmaster(struct ctdb_connection *ctdb,
		      uint32_t destnode, uint32_t *recmaster)
{
	struct ctdb_request *req;
	bool done = false;
	int ret = -1;

	req = wait_for(ctdb,
		       ctdb_getrecmaster_send(ctdb, destnode, set, &done),
		       &done);
	if (req != NULL) {
		ret = ctdb_getrecmaster_recv(req, recmaster);
		ctdb_request_free(req);
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

	req = wait_for(ctdb,
		       ctdb_attachdb_send(ctdb, name, persistent, tdb_flags,
					  set, &done),
		       &done);
	if (req != NULL) {
		ret = ctdb_attachdb_recv(req);
		ctdb_request_free(req);
	}
	return ret;
}
