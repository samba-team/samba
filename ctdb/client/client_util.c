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

int list_of_nodes(struct ctdb_node_map *nodemap,
		  uint32_t flags_mask, uint32_t exclude_pnn,
		  TALLOC_CTX *mem_ctx, uint32_t **pnn_list)
{
	int num_nodes = 0;
	uint32_t *list;
	int i;

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

int ctdb_ctrl_modflags(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		       struct ctdb_client_context *client,
		       uint32_t destnode, struct timeval timeout,
		       uint32_t set, uint32_t clear)
{
	struct ctdb_node_map *nodemap;
	struct ctdb_node_flag_change flag_change;
	struct ctdb_req_control request;
	uint32_t *pnn_list;
	int ret, count;

	ret = ctdb_ctrl_get_nodemap(mem_ctx, ev, client, destnode,
				    tevent_timeval_zero(), &nodemap);
	if (ret != 0) {
		return ret;
	}

	flag_change.pnn = destnode;
	flag_change.old_flags = nodemap->node[destnode].flags;
	flag_change.new_flags = flag_change.old_flags | set;
	flag_change.new_flags &= ~clear;

	count = list_of_connected_nodes(nodemap, -1, mem_ctx, &pnn_list);
	if (count == -1) {
		return ENOMEM;
	}

	ctdb_req_control_modify_flags(&request, &flag_change);
	ret = ctdb_client_control_multi(mem_ctx, ev, client, pnn_list, count,
					tevent_timeval_zero(), &request,
					NULL, NULL);
	return ret;
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
	uint8_t *result;
	int ret;

	ret = ctdb_ctrl_check_srvids(mem_ctx, ev, client, sid->vnn,
				     tevent_timeval_zero(),
				     &sid->unique_id, 1, &result);
	if (ret != 0) {
		return ret;
	}

	if (result[0] == 1) {
		*exists = true;
	} else {
		*exists = false;
	}

	return 0;
}
