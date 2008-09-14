/*
 * Unix SMB/CIFS implementation.
 * Join infiniband wrapper and ctdb.
 *
 * Copyright (C) Sven Oehme <oehmes@de.ibm.com> 2006
 *
 * Major code contributions by Peter Somogyi <psomogyi@gamax.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

struct ctdb_ibw_msg {
	uint8_t *data;
	uint32_t length;
	struct ctdb_ibw_msg *prev;
	struct ctdb_ibw_msg *next;
};

struct ctdb_ibw_node {
	struct ibw_conn *conn;

	struct ctdb_ibw_msg *queue;
	struct ctdb_ibw_msg *queue_last;
	int	qcnt;
};

int ctdb_ibw_get_address(struct ctdb_context *ctdb,
	const char *address, struct in_addr *addr);

int ctdb_ibw_connstate_handler(struct ibw_ctx *ctx, struct ibw_conn *conn);
int ctdb_ibw_receive_handler(struct ibw_conn *conn, void *buf, int n);

int ctdb_ibw_node_connect(struct ctdb_node *node);
void ctdb_ibw_node_connect_event(struct event_context *ev, struct timed_event *te, 
	struct timeval t, void *private_data);

int ctdb_flush_cn_queue(struct ctdb_ibw_node *cn);

int ctdb_ibw_init(struct ctdb_context *ctdb);
