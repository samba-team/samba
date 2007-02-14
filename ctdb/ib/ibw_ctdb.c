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
				DEBUG(0, ("connstate_handler/ibw_accept failed\n"));
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
				node->private = (void *)conn;
				node->ctdb->upcalls->node_connected(node);
			} else { /* after ibw_accept */
				/* NOP in CTDB case */
			}
		} break;
		case IBWC_DISCONNECTED: { /* after ibw_disconnect */
			/* TODO: have a CTDB upcall */
			struct ctdb_node *node = talloc_get_type(conn->conn_userdata, struct ctdb_node);
			if (node!=NULL)
				node->ctdb->upcalls->node_dead(node);
			talloc_free(conn);
		} break;
		case IBWC_ERROR: {
/*			struct ctdb_node *node = talloc_get_type(conn->conn_userdata, struct ctdb_node);
			if (node!=NULL)
				node->ctdb->upcalls->node_dead(node);*/
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

	assert(ctdb!=NULL);
	assert(conn->state==IBWC_CONNECTED);

	/* TODO: shall I short-circuit this in ibwrapper? */
	/* maybe when everything go fine... */

	/* TODO2: !!! here I can provide conn->conn_userdata (with no perf. penalty) -
	 * as struct ctdb_node in case the connection
	 * has been built up by ibw_connect !!! */
	ctdb->upcalls->recv_pkt(ctdb, (uint8_t *)buf, (uint32_t)n);

	return 0;
}
