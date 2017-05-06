/*
   CTDB client code

   Copyright (C) Amitay Isaacs  2015

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

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "common/logging.h"

#include "lib/util/debug.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "client/client_private.h"
#include "client/client.h"
#include "client/client_sync.h"

int ctdb_message_recd_update_ip(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, struct ctdb_public_ip *pubip)
{
	struct ctdb_req_message message;
	int ret;

	message.srvid = CTDB_SRVID_RECD_UPDATE_IP;
	message.data.pubip = pubip;

	ret = ctdb_client_message(mem_ctx, ev, client, destnode, &message);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Message RECD_UPDATE_IP failed to node %u\n",
		       destnode));
	}

	return ret;
}

int ctdb_message_mem_dump(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  int destnode, struct ctdb_srvid_message *msg)
{
	struct ctdb_req_message message;
	int ret;

	message.srvid = CTDB_SRVID_MEM_DUMP;
	message.data.msg = msg;

	ret = ctdb_client_message(mem_ctx, ev, client, destnode, &message);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Message MEM_DUMP failed to node %u\n", destnode));
	}

	return ret;
}

int ctdb_message_reload_nodes(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode)
{
	struct ctdb_req_message message;
	int ret;

	message.srvid = CTDB_SRVID_RELOAD_NODES;

	ret = ctdb_client_message(mem_ctx, ev, client, destnode, &message);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Message RELOAD_NODES failed to node %u\n", destnode));
	}

	return ret;
}

int ctdb_message_takeover_run(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      int destnode, struct ctdb_srvid_message *msg)
{
	struct ctdb_req_message message;
	int ret;

	message.srvid = CTDB_SRVID_TAKEOVER_RUN;
	message.data.msg = msg;

	ret = ctdb_client_message(mem_ctx, ev, client, destnode, &message);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Message TAKEOVER_RUN failed to node %u\n", destnode));
	}

	return ret;
}

int ctdb_message_rebalance_node(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct ctdb_client_context *client,
				int destnode, uint32_t pnn)
{
	struct ctdb_req_message message;
	int ret;

	message.srvid = CTDB_SRVID_REBALANCE_NODE;
	message.data.pnn = pnn;

	ret = ctdb_client_message(mem_ctx, ev, client, destnode, &message);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Message REBALANCE_NODE failed to node %u\n",
		       destnode));
	}

	return ret;
}

int ctdb_message_disable_takeover_runs(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_client_context *client,
				       int destnode,
				       struct ctdb_disable_message *disable)
{
	struct ctdb_req_message message;
	int ret;

	message.srvid = CTDB_SRVID_DISABLE_TAKEOVER_RUNS;
	message.data.disable = disable;

	ret = ctdb_client_message(mem_ctx, ev, client, destnode, &message);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Message DISABLE_TAKEOVER_RUNS failed to node %u\n",
		       destnode));
	}

	return ret;
}

int ctdb_message_disable_recoveries(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    int destnode,
				    struct ctdb_disable_message *disable)
{
	struct ctdb_req_message message;
	int ret;

	message.srvid = CTDB_SRVID_DISABLE_RECOVERIES;
	message.data.disable = disable;

	ret = ctdb_client_message(mem_ctx, ev, client, destnode, &message);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Message DISABLE_RECOVERIES failed to node %u\n",
		       destnode));
	}

	return ret;
}

int ctdb_message_disable_ip_check(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct ctdb_client_context *client,
				  int destnode, uint32_t timeout)
{
	struct ctdb_req_message message;
	int ret;

	message.srvid = CTDB_SRVID_DISABLE_IP_CHECK;
	message.data.timeout = timeout;

	ret = ctdb_client_message(mem_ctx, ev, client, destnode, &message);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Message DISABLE_IP_CHECK failed to node %u\n",
		       destnode));
	}

	return ret;
}
