/*
   Misc control routines of libctdb

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
#include <ctdb_protocol.h>
#include "libctdb_private.h"

/* Remove type-safety macros. */
#undef ctdb_getrecmaster_send
#undef ctdb_getpnn_send

int ctdb_getrecmaster_recv(struct ctdb_connection *ctdb,
			   struct ctdb_request *req, uint32_t *recmaster)
{
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(ctdb, req, CTDB_CONTROL_GET_RECMASTER);
	if (!reply) {
		return -1;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getrecmaster_recv: status -1");
		return -1;
	}
	*recmaster = reply->status;
	return 0;
}

struct ctdb_request *ctdb_getrecmaster_send(struct ctdb_connection *ctdb,
					    uint32_t destnode,
					    ctdb_callback_t callback,
					    void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_RECMASTER,
					destnode, NULL, 0,
					callback, private_data);
}

int ctdb_getpnn_recv(struct ctdb_connection *ctdb,
		     struct ctdb_request *req, uint32_t *pnn)
{
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(ctdb, req, CTDB_CONTROL_GET_PNN);
	if (!reply) {
		return -1;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getpnn_recv: status -1");
		return -1;
	}
	*pnn = reply->status;
	return 0;
}

struct ctdb_request *ctdb_getpnn_send(struct ctdb_connection *ctdb,
				      uint32_t destnode,
				      ctdb_callback_t callback,
				      void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_PNN, destnode,
					NULL, 0, callback, private_data);
}
