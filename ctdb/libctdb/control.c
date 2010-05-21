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

struct ctdb_request *ctdb_getrecmaster_send(struct ctdb_connection *ctdb,
				    uint32_t destnode,
				    ctdb_getrecmaster_cb callback,
				    void *private_data)
{
	struct ctdb_request *req;

	req = new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_RECMASTER,
				       destnode, NULL, 0);
	if (!req)
		return NULL;
	req->callback.getrecmaster = callback;
	req->priv_data = private_data;
	return req;
}

struct ctdb_request *
ctdb_getpnn_send(struct ctdb_connection *ctdb,
		 uint32_t destnode,
		 ctdb_getpnn_cb callback,
		 void *private_data)
{
	struct ctdb_request *req;

	req = new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_PNN, destnode,
				       NULL, 0);
	if (!req) {
		return NULL;
	}
	req->callback.getpnn = callback;
	req->priv_data = private_data;
	return req;
}
