/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2026

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef CLUSTER_LEVEL_DB_H
#define CLUSTER_LEVEL_DB_H

struct ctdbd_connection;
struct ctdb_node_and_flags;
struct messaging_context;

NTSTATUS cluster_level_db_check(struct ctdbd_connection *ctdb_conn);

NTSTATUS cluster_level_db_check_or_update(struct ctdbd_connection *ctdb_conn,
					  struct messaging_context *msg_ctx);

struct cluster_level_db_nodes_foreach_node {
	const struct ctdb_node_and_flags *nf;
	struct timeval update_time;
	struct {
		struct timeval start_time;
		pid_t pid;
	} update_ctdbd;
	const struct cluster_level_ranges *supported_ranges;
};

typedef NTSTATUS (*cluster_level_db_nodes_foreach_cb_t)(
		uint32_t total_nodes_count,
		const struct cluster_level_db_nodes_foreach_node *node,
		void *private_data);

NTSTATUS cluster_level_db_nodes_foreach(struct ctdbd_connection *ctdb_conn,
					cluster_level_db_nodes_foreach_cb_t cb,
					void *private_data);

#endif /* CLUSTER_LEVEL_DB_H */
