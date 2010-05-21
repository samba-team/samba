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

/* FIXME: Find a way to share more code here. */
struct ctdb_getrecmaster {
	bool done;
	int status;
	uint32_t *recmaster;
};

static bool ctdb_service_flush(struct ctdb_connection *ctdb)
{
	struct pollfd fds;

	fds.fd = ctdb_get_fd(ctdb);
	fds.events = ctdb_which_events(ctdb);
	if (poll(&fds, 1, -1) < 0) {
		/* Signalled is OK, other error is bad. */
		return errno == EINTR;
	}
	return ctdb_service(ctdb, fds.revents) >= 0;
}

static void getrecmaster_done(int status, uint32_t recmaster, void *priv_data)
{
	struct ctdb_getrecmaster *grm = priv_data;
	*grm->recmaster = recmaster;
	grm->status = status;
	grm->done = true;
}

int ctdb_getrecmaster(struct ctdb_connection *ctdb,
		      uint32_t destnode, uint32_t *recmaster)
{
	struct ctdb_request *req;
	struct ctdb_getrecmaster grm;

	grm.done = false;
	grm.recmaster = recmaster;
	req = ctdb_getrecmaster_send(ctdb, destnode, getrecmaster_done, &grm);
	if (!req)
		return -1;

	while (!grm.done) {
		if (!ctdb_service_flush(ctdb)) {
			ctdb_cancel(req);
			return -1;
		}
	}
	return grm.status;
}

struct ctdb_attachdb {
	bool done;
	int status;
	struct ctdb_db *ctdb_db;
};

static void attachdb_sync_done(int status,
			       struct ctdb_db *ctdb_db, void *private_data)
{
	struct ctdb_attachdb *atb = private_data;
	atb->ctdb_db = ctdb_db;
	atb->status = status;
	atb->done = true;
}

struct ctdb_db *ctdb_attachdb(struct ctdb_connection *ctdb,
			      const char *name, int persistent,
			      uint32_t tdb_flags)
{
	struct ctdb_request *req;
	struct ctdb_attachdb atb;

	atb.done = false;
	req = ctdb_attachdb_send(ctdb, name, persistent, tdb_flags,
				 attachdb_sync_done, &atb);
	if (!req)
		return NULL;

	while (!atb.done) {
		if (!ctdb_service_flush(ctdb)) {
			ctdb_cancel(req);
			return NULL;
		}
	}
	if (atb.status != 0)
		return NULL;
	return atb.ctdb_db;
}
