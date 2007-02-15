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
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

int ctdb_ibw_connstate_handler(struct ibw_ctx *ctx, struct ibw_conn *conn);
int ctdb_ibw_receive_handler(struct ibw_conn *conn, void *buf, int n);

int ctdb_ibw_node_connect(struct ibw_ctx *ictx, struct ctdb_node *node);
void ctdb_ibw_node_connect_event(struct event_context *ev, struct timed_event *te, 
	struct timeval t, void *private);

