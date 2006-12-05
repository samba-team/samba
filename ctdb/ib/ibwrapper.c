/*
 * Unix SMB/CIFS implementation.
 * Wrap Infiniband calls.
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

#include "ibwrapper.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <rdma/rdma_cma.h>
#include "lib/events/events.h"

#include "ibwrapper_internal.h"
#include "lib/util/dlinklist.h"

#define IBW_LASTERR_BUFSIZE 512
static char ibw_lasterr[IBW_LASTERR_BUFSIZE];

static ibw_mr *ibw_alloc_mr(ibw_ctx_priv *pctx)
{
}

static int ibw_ctx_priv_destruct(void *ptr)
{
	ibw_ctx *pctx = talloc_get_type(ctx->internal, ibw_ctx_priv);
	assert(pctx!=NULL);

	if (pctx->cm_id) {
		rdma_destroy_id(pctx->cm_id);
		pctx->cm_id = NULL;
	}
	if (pctx->cm_channel) {
		rdma_destroy_event_channel(pctx->cm_channel);
		pctx->cm_channel = NULL;
	}

	/* free memory regions */
}

static int ibw_ctx_destruct(void *ptr)
{
	ibw_ctx *ctx = talloc_get_type(ptr, ibw_ctx);
	assert(ctx!=NULL);

	if (pconn->cm_id) {
		rdma_destroy_id(pconn->cm_id);
		pconn->cm_id = NULL;
	}

	/* free memory regions */

	return 0;
}

static int ibw_conn_priv_destruct(void *ptr)
{
	ibw_conn *pconn = talloc_get_type(ptr, ibw_conn_priv);
	assert(pconn!=NULL);
}

static int ibw_conn_destruct(void *ptr)
{
	ibw_conn *conn = talloc_get_type(ptr, ibw_conn);
	ibw_ctx	*ctx;

	assert(conn!=NULL);
	ctx = ibw_conn->ctx;
	assert(ctx!=NULL);

	DLIST_REMOVE(ctx->conn_list, conn);
	return 0;
}

static ibw_conn *ibw_new_conn(ibw_ctx *ctx)
{
	ibw_conn *conn;
	ibw_conn_priv *pconn;

	conn = talloc_zero(ctx, ibw_conn);
	assert(conn!=NULL);
	talloc_set_destructor(conn, ibw_conn_destruct);

	pconn = talloc_zero(ctx, ibw_conn_priv);
	assert(pconn!=NULL);
	talloc_set_destructor(pconn, ibw_conn_priv_destruct);

	conn->ctx = ctx;

	DLIST_ADD(ctx->conn_list, conn);

	return conn;
}

static void ibw_process_cm_event(struct event_context *ev,
	struct fd_event *fde, uint16_t flags, void *private_data)
{
	int	rc;
	ibw_ctx	*ctx = talloc_get_type(private_data, ibw_ctx);
	ibw_ctx_priv *pctx = talloc_get_type(ctx->internal, ibw_ctx_priv);
	ibw_conn *conn = NULL;
	ibw_conn_priv *pconn = NULL;
	struct rdma_cm_id *id = NULL;
	struct rdma_cm_event *event = NULL;

	assert(ctx!=NULL);

	rc = rdma_get_cm_event(cb->cm_channel, &event);
	if (rc) {
		ctx->state = IBWS_ERROR;
		sprintf(ibw_lasterr, "rdma_get_cm_event error %d\n", rc);
		DEBUG(0, ibw_lasterr);
		return;
	}
	id = event->id;

	/* find whose cm_id do we have */

//	DEBUG(10, "cma_event type %d cma_id %p (%s)\n", event->event, event->id,
//		  (event->id == ctx->cm_id) ? "parent" : "child");

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		assert(pctx->state==IWINT_INIT);
		pctx->state = IWINT_ADDR_RESOLVED;
		rc = rdma_resolve_route(event->id, 2000);
		if (rc) {
			cb->state = ERROR;
			sprintf(ibw_lasterr, "rdma_resolve_route error %d\n", rc);
			DEBUG(0, ibw_lasterr);
		}
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		assert(pctx->state==IWINT_ADDR_RESOLVED);
		pctx->state = IWINT_ROUTE_RESOLVED;
		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ctx->state = IBWS_CONNECT_REQUEST;
		conn = ibw_new_conn(ctx);
		pconn = talloc_get_type(conn, ibw_conn_priv);
		pconn->cm_id = event->id; /* !!! event will be freed but not id */
		DEBUG(10, "conn->cm_id %p\n", pconn->cm_id);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		DEBUG(0, "ESTABLISHED\n");
		ctx->state = IBWS_READY;
		/* TODO */
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		DEBUG(0, "cma event %d, error %d\n", event->event,
		       event->status);
		ctx->state = IBWS_ERROR;
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		DEBUG(0, "%s DISCONNECT EVENT...\n", cb->server ? "server" : "client");
		/* TODO */
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		DEBUG(0, "cma detected device removal!\n");
		break;

	default:
		DEBUG(0, "oof bad type!\n");
		break;
	}

	if ((rc=rdma_ack_cm_event(event))) {
		DEBUG(0, "rdma_ack_cm_event failed with %d\n", rc);
	}
}

static int ibw_process_init_attrs(ibw_initattr *attr, int nattr, ibw_opts *opts)
{
	int	i;
	char *name, *value;
	
	for(i=0; i<nattr; i++) {
		name = attr[i].name;
		value = attr[i].value;

		assert(name!=NULL && value!=NULL);
		if (strcmp(name, "dev_name")==0)
			opts->opts.dev_name = talloc_strdup(ctx, value);
		else if (strcmp(name, "rx_depth")==0)
			opts->rx_depth = atoi(value);
		else if (strcmp(name, "mtu")==0)
			opts->mtu = atoi(value);
		else {
			sprintf(ibw_lasterr, "ibw_init: unknown name %s\n", name);
			return -1;
		}
	}
	return 0;
}

ibw_ctx *ibw_init(ibw_initattr *attr, int nattr,
	void *ctx_userdata,
	ibw_connstate_fn_t ibw_connstate,
	ibw_receive_fn_t ibw_receive,
	event_content *ectx)
{
	ibw_ctx *ctx = talloc_zero(NULL, ibw_ctx);
	ibw_ctx_priv *pctx;
	int	rc;

	/* initialize basic data structures */
	memset(ibw_lasterr, 0, IBW_LASTERR_BUFSIZE);

	assert(ctx!=NULL);
	ibw_lasterr[0] = '\0';
	talloc_set_destructor(ctx, ibw_ctx_destruct);
	ctx->userdata = userdata;

	pctx = talloc_zero(ctx, ibw_ctx_priv);
	talloc_set_destructor(pctx, ibw_ctx_priv_destruct);
	ctx->internal = (void *)pctx;
	assert(pctx!=NULL);

	pctx->connstate_func = ibw_connstate;
	pctx->receive_func = ibw_receive;

	pctx->ectx = ectx;

	/* process attributes */
	if (ibw_process_init_attrs(attr, nattr, pctx->opts))
		goto cleanup;

	/* initialize CM stuff */
	pctx->cm_channel = rdma_create_event_channel();
	if (!pctx->cm_channel) {
		ret = errno;
		sprintf(ibw_lasterr, "rdma_create_event_channel error %d\n", ret);
		goto cleanup;
	}

	pctx->cm_channel_event = event_add_fd(pctx->ectx, pctx,
		pctx->cm_channel->fd, EVENT_FD_READ, ibw_process_cm_event, ctx);

	rc = rdma_create_id(pctx->cm_channel, &pctx->cm_id, cb, RDMA_PS_TCP);
	if (rc) {
		rc = errno;
		sprintf(ibw_lasterr, "rdma_create_id error %d\n", rc);
		goto cleanup;
	}
	DEBUG(10, "created cm_id %p\n", pctx->cm_id);

	/* allocate ib memory regions */

	return ctx;

cleanup:
	if (ctx)
		talloc_free(ctx);

	return NULL;
}

int ibw_stop(ibw_ctx *ctx)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;

}

int ibw_bind(ibw_ctx *ctx, struct sockaddr_in *my_addr)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
	int	rc;

	rc = rdma_bind_addr(cb->cm_id, (struct sockaddr *) &my_addr);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_bind_addr error %d\n", rc);
		return rc;
	}

	return 0;
}

int ibw_listen(ibw_ctx *ctx, int backlog)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
	
	return 0;
}

int ibw_accept(ibw_ctx *ctx, void *conn_userdata)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
	
	return 0;
}

int ibw_connect(ibw_ctx *ctx, struct sockaddr_in *serv_addr, void *conn_userdata)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
		
	return 0;
}

void ibw_disconnect(ibw_conn *conn)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
	
	return 0;
}

int ibw_alloc_send_buf(ibw_conn *conn, void **buf, void **key, int n)
{
	ibw_conn_priv *pconn = (ibw_ctx_priv *)ctx->internal;

	return 0;
}

int ibw_send(ibw_conn *conn, void *buf, void *key, int n)
{
	ibw_conn_priv *pconn = (ibw_ctx_priv *)ctx->internal;
	return 0;
}

const char *ibw_getLastError()
{
	return ibw_lasterr;
}
