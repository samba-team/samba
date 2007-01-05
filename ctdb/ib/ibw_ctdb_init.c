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

#include "includes.h"
#include "lib/events/events.h"
#include <system/network.h>
#include <assert.h>
#include "ctdb_private.h"
#include "ibwrapper.h"
#include "ibw_ctdb.h"

/* not nice; temporary workaround for the current implementation... */
static void *last_key = NULL;

static int ctdb_ibw_listen(struct ctdb_context *ctdb, int backlog)
{
	struct ibw_ctx *ictx = talloc_get_type(ctdb->private, struct ibw_ctx);
	struct sockaddr_in my_addr;

	assert(ictx!=NULL);
	memset(&my_addr, 0, sizeof(struct sockaddr_in));
	my_addr.sin_port = htons(ctdb->address.port);
	my_addr.sin_family = PF_INET;
	inet_pton(AF_INET, ctdb->address.address, &my_addr.sin_addr);

	if (ibw_bind(ictx, &my_addr)) {
		DEBUG(0, ("ctdb_ibw_listen: ibw_bind failed\n"));
		return -1;
	}

	if (ibw_listen(ictx, backlog)) {
		DEBUG(0, ("ctdb_ibw_listen: ibw_listen failed\n"));
		return -1;
	}

	return 0;
}

int ctdb_ibw_node_connect(struct ibw_ctx *ictx, struct ctdb_node *node)
{
        struct sockaddr_in sock_out;

	inet_pton(AF_INET, node->address.address, &sock_out.sin_addr);
	sock_out.sin_port = htons(node->address.port);
	sock_out.sin_family = PF_INET;

	if (ibw_connect(ictx, &sock_out, node)) {
		DEBUG(0, ("ctdb_ibw_node_connect: ibw_connect failed\n"));
		return -1;
	}

	/* continues at ibw_ctdb.c/IBWC_CONNECTED in good case */
	return 0;
}

/*
 * Start infiniband
 */
static int ctdb_ibw_start(struct ctdb_context *ctdb)
{
	struct ibw_ctx *ictx = talloc_get_type(ctdb->private, struct ibw_ctx);
	int i;

	/* listen on our own address */
	if (ctdb_ibw_listen(ctdb, 10)) /* TODO: backlog as param */
		return -1;

	/* everything async here */
	for (i=0;i<ctdb->num_nodes;i++) {
		struct ctdb_node *node = ctdb->nodes[i];
		if (!(ctdb->flags & CTDB_FLAG_SELF_CONNECT) &&
			ctdb_same_address(&ctdb->address, &node->address))
			continue;
		ctdb_ibw_node_connect(ictx, node);
	}

	return 0;
}


/*
 * initialise ibw portion of a ctdb node 
 */
static int ctdb_ibw_add_node(struct ctdb_node *node)
{
	/* TODO: clarify whether is this necessary for us ?
	   - why not enough doing such thing internally at connect time ? */
	return 0;
}

/*
 * transport packet allocator - allows transport to control memory for packets
 */
static void *ctdb_ibw_allocate_pkt(struct ctdb_node *node, size_t size)
{
	struct ibw_conn *conn = NULL;
	void *buf = NULL;

	if (ibw_alloc_send_buf(conn, &buf, &last_key, size))
		return NULL;

	return buf;
}

static int ctdb_ibw_queue_pkt(struct ctdb_node *node, uint8_t *data, uint32_t length)
{
	struct ibw_conn *conn = talloc_get_type(node->private, struct ibw_conn);
	int	rc;

	rc = ibw_send(conn, data, last_key, length);
	last_key = NULL;

	return rc;
}

static void ctdb_ibw_dealloc_pkt(struct ctdb_node *node, void *data)
{
	if (last_key) {
		struct ibw_conn *conn = talloc_get_type(node->private, struct ibw_conn);
	
		assert(conn!=NULL);
		ibw_cancel_send_buf(conn, data, last_key);
	} /* else ibw_send is already using it and will free it after completion */
}

static int ctdb_ibw_stop(struct ctdb_context *cctx)
{
	struct ibw_ctx *ictx = talloc_get_type(cctx->private, struct ibw_ctx);

	assert(ictx!=NULL);
	return ibw_stop(ictx);
}

static const struct ctdb_methods ctdb_ibw_methods = {
	.start     = ctdb_ibw_start,
	.add_node  = ctdb_ibw_add_node,
	.queue_pkt = ctdb_ibw_queue_pkt,
	.allocate_pkt = ctdb_ibw_allocate_pkt,

	.dealloc_pkt = ctdb_ibw_dealloc_pkt,
	.stop = ctdb_ibw_stop
};

/*
 * initialise ibw portion of ctdb 
 */
int ctdb_ibw_init(struct ctdb_context *ctdb)
{
	struct ibw_ctx *ictx;

	ictx = ibw_init(
		NULL, //struct ibw_initattr *attr, /* TODO */
		0, //int nattr, /* TODO */
		ctdb,
		ctdb_ibw_connstate_handler,
		ctdb_ibw_receive_handler,
		ctdb->ev);

	if (ictx==NULL) {
		DEBUG(0, ("ctdb_ibw_init: ibw_init failed\n"));
		return -1;
	}

	ctdb->methods = &ctdb_ibw_methods;
	ctdb->private = ictx;
	return 0;
}
