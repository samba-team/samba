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
#include <string.h>
#include <ctdb.h>
#include <ctdb_protocol.h>
#include "libctdb_private.h"

/* Remove type-safety macros. */
#undef ctdb_getrecmaster_send
#undef ctdb_getrecmode_send
#undef ctdb_getpnn_send
#undef ctdb_getnodemap_send
#undef ctdb_getpublicips_send

bool ctdb_getrecmaster_recv(struct ctdb_connection *ctdb,
			   struct ctdb_request *req, uint32_t *recmaster)
{
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_GET_RECMASTER);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getrecmaster_recv: status -1");
		return false;
	}
	*recmaster = reply->status;
	return true;
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

bool ctdb_getrecmode_recv(struct ctdb_connection *ctdb,
			  struct ctdb_request *req, uint32_t *recmode)
{
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_GET_RECMODE);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getrecmode_recv: status -1");
		return false;
	}
	*recmode = reply->status;
	return true;
}

struct ctdb_request *ctdb_getrecmode_send(struct ctdb_connection *ctdb,
					    uint32_t destnode,
					    ctdb_callback_t callback,
					    void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_RECMODE,
					destnode, NULL, 0,
					callback, private_data);
}

bool ctdb_getpnn_recv(struct ctdb_connection *ctdb,
		     struct ctdb_request *req, uint32_t *pnn)
{
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_GET_PNN);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getpnn_recv: status -1");
		return false;
	}
	*pnn = reply->status;
	return true;
}

struct ctdb_request *ctdb_getpnn_send(struct ctdb_connection *ctdb,
				      uint32_t destnode,
				      ctdb_callback_t callback,
				      void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_PNN, destnode,
					NULL, 0, callback, private_data);
}

bool ctdb_getnodemap_recv(struct ctdb_connection *ctdb,
		      struct ctdb_request *req, struct ctdb_node_map **nodemap)
{
	struct ctdb_reply_control *reply;

	*nodemap = NULL;
	reply = unpack_reply_control(req, CTDB_CONTROL_GET_NODEMAP);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getnodemap_recv: status -1");
		return false;
	}
	if (reply->datalen == 0) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getnodemap_recv: returned data is 0 bytes");
		return false;
	}

	*nodemap = malloc(reply->datalen);
	if (*nodemap == NULL) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getnodemap_recv: failed to malloc buffer");
		return false;
	}
	memcpy(*nodemap, reply->data, reply->datalen);

	return true;
}
struct ctdb_request *ctdb_getnodemap_send(struct ctdb_connection *ctdb,
					  uint32_t destnode,
					  ctdb_callback_t callback,
					  void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_NODEMAP,
					destnode,
					NULL, 0, callback, private_data);
}

void ctdb_free_nodemap(struct ctdb_node_map *nodemap)
{
	if (nodemap == NULL) {
		return;
	}
	free(nodemap);
}

bool ctdb_getpublicips_recv(struct ctdb_connection *ctdb,
			    struct ctdb_request *req,
			    struct ctdb_all_public_ips **ips)
{
	struct ctdb_reply_control *reply;

	*ips = NULL;
	reply = unpack_reply_control(req, CTDB_CONTROL_GET_PUBLIC_IPS);
	if (!reply) {
		return false;
	}
	if (reply->status == -1) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getpublicips_recv: status -1");
		return false;
	}
	if (reply->datalen == 0) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getpublicips_recv: returned data is 0 bytes");
		return false;
	}

	*ips = malloc(reply->datalen);
	if (*ips == NULL) {
		DEBUG(ctdb, LOG_ERR, "ctdb_getpublicips_recv: failed to malloc buffer");
		return false;
	}
	memcpy(*ips, reply->data, reply->datalen);

	return true;
}
struct ctdb_request *ctdb_getpublicips_send(struct ctdb_connection *ctdb,
					    uint32_t destnode,
					    ctdb_callback_t callback,
					    void *private_data)
{
	return new_ctdb_control_request(ctdb, CTDB_CONTROL_GET_PUBLIC_IPS,
					destnode,
					NULL, 0, callback, private_data);
}

void ctdb_free_publicips(struct ctdb_all_public_ips *ips)
{
	if (ips == NULL) {
		return;
	}
	free(ips);
}
