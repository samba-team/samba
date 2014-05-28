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

#include "includes.h"
#include <system/network.h>
#include <assert.h>
#include "ctdb_private.h"
#include "ibwrapper.h"
#include "ibw_ctdb.h"
#include "lib/util/dlinklist.h"

static int ctdb_ibw_listen(struct ctdb_context *ctdb, int backlog)
{
	struct ibw_ctx *ictx = talloc_get_type(ctdb->private_data, struct ibw_ctx);
	struct sockaddr_in my_addr;

	assert(ictx!=NULL);
	memset(&my_addr, 0, sizeof(struct sockaddr_in));
	my_addr.sin_port = htons(ctdb->address.port);
	my_addr.sin_family = PF_INET;
	if (ctdb_ibw_get_address(ctdb, ctdb->address.address, &my_addr.sin_addr))
		return -1;

	if (ibw_bind(ictx, &my_addr)) {
		DEBUG(DEBUG_CRIT, ("ctdb_ibw_listen: ibw_bind failed\n"));
		return -1;
	}

	if (ibw_listen(ictx, backlog)) {
		DEBUG(DEBUG_CRIT, ("ctdb_ibw_listen: ibw_listen failed\n"));
		return -1;
	}

	return 0;
}

/*
 * initialise ibw portion of a ctdb node 
 */
static int ctdb_ibw_add_node(struct ctdb_node *node)
{
	struct ibw_ctx *ictx = talloc_get_type(node->ctdb->private_data, struct ibw_ctx);
	struct ctdb_ibw_node *cn = talloc_zero(node, struct ctdb_ibw_node);

	assert(cn!=NULL);
	cn->conn = ibw_conn_new(ictx, node);
	node->private_data = (void *)cn;

	return (cn->conn!=NULL ? 0 : -1);
}

/*
 * initialise infiniband
 */
static int ctdb_ibw_initialise(struct ctdb_context *ctdb)
{
	int i, ret;

	ret = ctdb_ibw_init(ctdb);
	if (ret != 0) {
		return ret;
	}

	for (i=0; i<ctdb->num_nodes; i++) {
		if (ctdb_ibw_add_node(ctdb->nodes[i]) != 0) {
			DEBUG(DEBUG_CRIT, ("methods->add_node failed at %d\n", i));
			return -1;
		}
	}

	/* listen on our own address */
	if (ctdb_ibw_listen(ctdb, 10)) /* TODO: backlog as param */
		return -1;

	return 0;
}


/*
 * Start infiniband
 */
static int ctdb_ibw_start(struct ctdb_context *ctdb)
{
	int i;

	/* everything async here */
	for (i=0;i<ctdb->num_nodes;i++) {
		struct ctdb_node *node = ctdb->nodes[i];
		if (!ctdb_same_address(&ctdb->address, &node->address)) {
			ctdb_ibw_node_connect(node);
		}
	}

	return 0;
}

static int ctdb_ibw_send_pkt(struct ibw_conn *conn, uint8_t *data, uint32_t length)
{
	void	*buf, *key;

	if (ibw_alloc_send_buf(conn, &buf, &key, length)) {
		DEBUG(DEBUG_ERR, ("queue_pkt/ibw_alloc_send_buf failed\n"));
		return -1;
	}

	memcpy(buf, data, length);
	return ibw_send(conn, buf, key, length);
}

int ctdb_flush_cn_queue(struct ctdb_ibw_node *cn)
{
	struct ctdb_ibw_msg *p;
	int	rc = 0;

	while(cn->queue) {
		p = cn->queue;
		rc = ctdb_ibw_send_pkt(cn->conn, p->data, p->length);
		if (rc)
			return -1; /* will be retried later when conn is up */

		DLIST_REMOVE(cn->queue, p);
		cn->qcnt--;
		talloc_free(p); /* it will talloc_free p->data as well */
	}
	assert(cn->qcnt==0);
	/* cn->queue_last = NULL is not needed - see DLIST_ADD_AFTER */

	return rc;
}

static int ctdb_ibw_queue_pkt(struct ctdb_node *node, uint8_t *data, uint32_t length)
{
	struct ctdb_ibw_node *cn = talloc_get_type(node->private_data, struct ctdb_ibw_node);
	int	rc;

	assert(length>=sizeof(uint32_t));
	assert(cn!=NULL);

	if (cn->conn==NULL) {
		DEBUG(DEBUG_ERR, ("ctdb_ibw_queue_pkt: conn is NULL\n"));
		return -1;
	}

	if (cn->conn->state==IBWC_CONNECTED) {
		rc = ctdb_ibw_send_pkt(cn->conn, data, length);
	} else {
		struct ctdb_ibw_msg *p = talloc_zero(cn, struct ctdb_ibw_msg);
		CTDB_NO_MEMORY(node->ctdb, p);

		p->data = talloc_memdup(p, data, length);
		CTDB_NO_MEMORY(node->ctdb, p->data);

		p->length = length;

		DLIST_ADD_AFTER(cn->queue, p, cn->queue_last);
		cn->queue_last = p;
		cn->qcnt++;

		rc = 0;
	}

	return rc;
}

static void ctdb_ibw_restart(struct ctdb_node *node)
{
	/* TODO: implement this method for IB */
	DEBUG(DEBUG_ALERT,("WARNING: method restart is not yet implemented for IB\n"));
}

/*
 * transport packet allocator - allows transport to control memory for packets
 */
static void *ctdb_ibw_allocate_pkt(TALLOC_CTX *mem_ctx, size_t size)
{
	/* TODO: use ibw_alloc_send_buf instead... */
	return talloc_size(mem_ctx, size);
}

#ifdef __NOTDEF__

static int ctdb_ibw_stop(struct ctdb_context *cctx)
{
	struct ibw_ctx *ictx = talloc_get_type(cctx->private_data, struct ibw_ctx);

	assert(ictx!=NULL);
	return ibw_stop(ictx);
}

#endif /* __NOTDEF__ */

static const struct ctdb_methods ctdb_ibw_methods = {
	.initialise= ctdb_ibw_initialise,
	.start     = ctdb_ibw_start,
	.queue_pkt = ctdb_ibw_queue_pkt,
	.add_node = ctdb_ibw_add_node,
	.allocate_pkt = ctdb_ibw_allocate_pkt,
	.restart      = ctdb_ibw_restart,

//	.stop = ctdb_ibw_stop
};

/*
 * initialise ibw portion of ctdb 
 */
int ctdb_ibw_init(struct ctdb_context *ctdb)
{
	struct ibw_ctx *ictx;

	DEBUG(DEBUG_DEBUG, ("ctdb_ibw_init invoked...\n"));
	ictx = ibw_init(
		NULL, //struct ibw_initattr *attr, /* TODO */
		0, //int nattr, /* TODO */
		ctdb,
		ctdb_ibw_connstate_handler,
		ctdb_ibw_receive_handler,
		ctdb->ev);

	if (ictx==NULL) {
		DEBUG(DEBUG_CRIT, ("ctdb_ibw_init: ibw_init failed\n"));
		return -1;
	}

	ctdb->methods = &ctdb_ibw_methods;
	ctdb->private_data = ictx;
	
	DEBUG(DEBUG_DEBUG, ("ctdb_ibw_init succeeded.\n"));
	return 0;
}
