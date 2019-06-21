/*
   Cluster wide synchronization

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

#ifndef __CLUSTER_WAIT_H__
#define __CLUSTER_WAIT_H__

struct tevent_req *cluster_wait_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct ctdb_client_context *client,
				     uint32_t num_nodes);

bool cluster_wait_recv(struct tevent_req *req, int *perr);

#endif /* __CLUSTER_WAIT_H__ */
