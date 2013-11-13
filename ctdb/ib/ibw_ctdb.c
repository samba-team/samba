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

int ctdb_ibw_get_address(struct ctdb_context *ctdb,
	const char *address, struct in_addr *addr)
{
	if (inet_pton(AF_INET, address, addr) <= 0) {
		struct hostent *he = gethostbyname(address);
		if (he == NULL || he->h_length > sizeof(*addr)) {
			ctdb_set_error(ctdb, "invalid nework address '%s'\n", 
				       address);
			return -1;
		}
		memcpy(addr, he->h_addr, he->h_length);
	}
	return 0;
}

int ctdb_ibw_node_connect(struct ctdb_node *node)
{
	struct ctdb_ibw_node *cn = talloc_get_type(node->private_data, struct ctdb_ibw_node);
	int	rc;

	assert(cn!=NULL);
	assert(cn->conn!=NULL);
	struct sockaddr_in sock_out;

	memset(&sock_out, 0, sizeof(struct sockaddr_in));
	sock_out.sin_port = htons(node->address.port);
	sock_out.sin_family = PF_INET;
	if (ctdb_ibw_get_address(node->ctdb, node->address.address, &sock_out.sin_addr)) {
		DEBUG(DEBUG_ERR, ("ctdb_ibw_node_connect failed\n"));
		return -1;
	}

	rc = ibw_connect(cn->conn, &sock_out, node);
	if (rc) {
		DEBUG(DEBUG_ERR, ("ctdb_ibw_node_connect/ibw_connect failed - retrying...\n"));
		/* try again once a second */
		event_add_timed(node->ctdb->ev, node, timeval_current_ofs(1, 0), 
			ctdb_ibw_node_connect_event, node);
	}

	/* continues at ibw_ctdb.c/IBWC_CONNECTED in good case */
	return 0;
}

void ctdb_ibw_node_connect_event(struct event_context *ev, struct timed_event *te, 
	struct timeval t, void *private_data)
{
	struct ctdb_node *node = talloc_get_type(private_data, struct ctdb_node);

	ctdb_ibw_node_connect(node);
}

int ctdb_ibw_connstate_handler(struct ibw_ctx *ctx, struct ibw_conn *conn)
{
	if (ctx!=NULL) {
		/* ctx->state changed */
		switch(ctx->state) {
		case IBWS_INIT: /* ctx start - after ibw_init */
			break;
		case IBWS_READY: /* after ibw_bind & ibw_listen */
			break;
		case IBWS_CONNECT_REQUEST: /* after [IBWS_READY + incoming request] */
				/* => [(ibw_accept)IBWS_READY | (ibw_disconnect)STOPPED | ERROR] */
			if (ibw_accept(ctx, conn, NULL)) {
				DEBUG(DEBUG_ERR, ("connstate_handler/ibw_accept failed\n"));
				return -1;
			} /* else continue in IBWC_CONNECTED */
			break;
		case IBWS_STOPPED: /* normal stop <= ibw_disconnect+(IBWS_READY | IBWS_CONNECT_REQUEST) */
			/* TODO: have a CTDB upcall for which CTDB should wait in a (final) loop */
			break;
		case IBWS_ERROR: /* abnormal state; ibw_stop must be called after this */
			break;
		default:
			assert(0);
			break;
		}
	}

	if (conn!=NULL) {
		/* conn->state changed */
		switch(conn->state) {
		case IBWC_INIT: /* conn start - internal state */
			break;
		case IBWC_CONNECTED: { /* after ibw_accept or ibw_connect */
			struct ctdb_node *node = talloc_get_type(conn->conn_userdata, struct ctdb_node);
			if (node!=NULL) { /* after ibw_connect */
				struct ctdb_ibw_node *cn = talloc_get_type(node->private_data, struct ctdb_ibw_node);

				node->ctdb->upcalls->node_connected(node);
				ctdb_flush_cn_queue(cn);
			} else { /* after ibw_accept */
				/* NOP in CTDB case */
			}
		} break;
		case IBWC_DISCONNECTED: { /* after ibw_disconnect */
			struct ctdb_node *node = talloc_get_type(conn->conn_userdata, struct ctdb_node);
			if (node!=NULL)
				node->ctdb->upcalls->node_dead(node);
			talloc_free(conn);
			/* normal + intended disconnect => not reconnecting in this layer */
		} break;
		case IBWC_ERROR: {
			struct ctdb_node *node = talloc_get_type(conn->conn_userdata, struct ctdb_node);
			if (node!=NULL) {
				struct ctdb_ibw_node *cn = talloc_get_type(node->private_data, struct ctdb_ibw_node);
				struct ibw_ctx *ictx = cn->conn->ctx;

				DEBUG(DEBUG_DEBUG, ("IBWC_ERROR, reconnecting...\n"));
				talloc_free(cn->conn); /* internal queue content is destroyed */
				cn->conn = (void *)ibw_conn_new(ictx, node);
				event_add_timed(node->ctdb->ev, node, timeval_current_ofs(1, 0),
					ctdb_ibw_node_connect_event, node);
			}
		} break;
		default:
			assert(0);
			break;
		}
	}

	return 0;
}

int ctdb_ibw_receive_handler(struct ibw_conn *conn, void *buf, int n)
{
	struct ctdb_context *ctdb = talloc_get_type(conn->ctx->ctx_userdata, struct ctdb_context);
	void	*buf2; /* future TODO: a solution for removal of this */

	assert(ctdb!=NULL);
	assert(buf!=NULL);
	assert(conn!=NULL);
	assert(conn->state==IBWC_CONNECTED);

	/* so far "buf" is an ib-registered memory area
	 * and being reused for next receive
	 * noticed that HL requires talloc-ed memory to be stolen */
	buf2 = talloc_zero_size(conn, n);
	CTDB_NO_MEMORY(ctdb, buf2);

	memcpy(buf2, buf, n);

	ctdb->upcalls->recv_pkt(ctdb, (uint8_t *)buf2, (uint32_t)n);

	return 0;
}
