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

int list_of_nodes(struct ctdb_node_map *nodemap,
		  uint32_t flags_mask, uint32_t exclude_pnn,
		  TALLOC_CTX *mem_ctx, uint32_t **pnn_list)
{
	int num_nodes = 0;
	uint32_t *list;
	unsigned int i;

	/* Allocate the list of same number of nodes */
	list = talloc_array(mem_ctx, uint32_t, nodemap->num);
	if (list == NULL) {
		return -1;
	}

	for (i=0; i<nodemap->num; i++) {
		if (nodemap->node[i].flags & flags_mask) {
			continue;
		}
		if (nodemap->node[i].pnn == exclude_pnn) {
			continue;
		}
		list[num_nodes] = nodemap->node[i].pnn;
		num_nodes++;
	}

	*pnn_list = list;
	return num_nodes;
}

int list_of_active_nodes(struct ctdb_node_map *nodemap, uint32_t exclude_pnn,
			 TALLOC_CTX *mem_ctx, uint32_t **pnn_list)
{
	return list_of_nodes(nodemap, NODE_FLAGS_INACTIVE, exclude_pnn,
			     mem_ctx, pnn_list);
}

int list_of_connected_nodes(struct ctdb_node_map *nodemap,
			    uint32_t exclude_pnn,
			    TALLOC_CTX *mem_ctx, uint32_t **pnn_list)
{
	return list_of_nodes(nodemap, NODE_FLAGS_DISCONNECTED, exclude_pnn,
			     mem_ctx, pnn_list);
}

struct ctdb_server_id ctdb_client_get_server_id(
				struct ctdb_client_context *client,
				uint32_t task_id)
{
	struct ctdb_server_id sid;

	sid.pid = getpid();
	sid.task_id = task_id;
	sid.vnn = ctdb_client_pnn(client);
	sid.unique_id = task_id;
	sid.unique_id = (sid.unique_id << 32) | sid.pid;

	return sid;
}

bool ctdb_server_id_equal(struct ctdb_server_id *sid1,
			  struct ctdb_server_id *sid2)
{
	if (sid1->pid != sid2->pid) {
		return false;
	}
	if (sid1->task_id != sid2->task_id) {
		return false;
	}
	if (sid1->vnn != sid2->vnn) {
		return false;
	}
	if (sid1->unique_id != sid2->unique_id) {
		return false;
	}

	return true;
}

int ctdb_server_id_exists(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			  struct ctdb_client_context *client,
			  struct ctdb_server_id *sid, bool *exists)
{
	int result;
	int ret;

	ret = ctdb_ctrl_process_exists(mem_ctx, ev, client, sid->vnn,
				       tevent_timeval_zero(),
				       sid->pid, &result);
	if (ret != 0) {
		return ret;
	}

	if (result == 1) {
		*exists = true;
	} else {
		*exists = false;
	}

	return 0;
}
