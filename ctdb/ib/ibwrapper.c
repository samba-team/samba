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

	/* free memory regions */
	
	/* destroy verbs */
	if (pctx->cq) {
		ibv_destroy_cq(pctx->cq);
		pctx->cq = NULL;
	}

	if (pctx->verbs_channel) {
		ibv_destroy_comp_channel(pctx->verbs_channel);
		pctx->verbs_channel = NULL;
	}

	if (pctx->verbs_channel_event) {
		/* TODO: do we have to do this here? */
		talloc_free(pctx->verbs_channel_event);
		pctx->verbs_channel_event = NULL;
	}

	if (pctx->pd) {
		ibv_dealloc_pd(pctx->pd);
		pctx->pd = NULL;
	}

	/* destroy cm */
	if (pctx->cm_channel) {
		rdma_destroy_event_channel(pctx->cm_channel);
		pctx->cm_channel = NULL;
	}
	if (pctx->cm_channel_event) {
		/* TODO: do we have to do this here? */
		talloc_free(pctx->cm_channel_event);
		pctx->cm_channel_event = NULL;
	}
	if (pctx->cm_id) {
		rdma_destroy_id(pctx->cm_id);
		pctx->cm_id = NULL;
	}
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

static ibw_conn *ibw_conn_new(ibw_ctx *ctx)
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

static int ibw_manage_connect(struct rdma_cm_id *cma_id)
{
	struct rdma_conn_param conn_param;
	int	rc;

	/* TODO: setup verbs... */

	/* cm connect */
	memset(&conn_param, 0, sizeof conn_param);
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 10;

	rc = rdma_connect(cma_id, &conn_param);
	if (rc)
		sprintf(ibw_lasterr, "rdma_connect error %d\n", rc);

	return rc;
}

static void ibw_event_handler_cm(struct event_context *ev,
	struct fd_event *fde, uint16_t flags, void *private_data)
{
	int	rc;
	ibw_ctx	*ctx = talloc_get_type(private_data, ibw_ctx);
	ibw_ctx_priv *pctx = talloc_get_type(ctx->internal, ibw_ctx_priv);
	ibw_conn *conn = NULL;
	ibw_conn_priv *pconn = NULL;
	struct rdma_cm_id *cma_id = NULL;
	struct rdma_cm_event *event = NULL;
	int	error = 0;

	assert(ctx!=NULL);

	rc = rdma_get_cm_event(cb->cm_channel, &event);
	if (rc) {
		ctx->state = IBWS_ERROR;
		sprintf(ibw_lasterr, "rdma_get_cm_event error %d\n", rc);
		DEBUG(0, ibw_lasterr);
		return;
	}
	cma_id = event->id;

	DEBUG(10, "cma_event type %d cma_id %p (%s)\n", event->event, id,
		  (cma_id == ctx->cm_id) ? "parent" : "child");

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		/* continuing from ibw_connect ... */
		assert(pctx->state==IWINT_INIT);
		pctx->state = IWINT_ADDR_RESOLVED;
		rc = rdma_resolve_route(cma_id, 2000);
		if (rc) {
			cb->state = ERROR;
			sprintf(ibw_lasterr, "rdma_resolve_route error %d\n", rc);
			DEBUG(0, ibw_lasterr);
		}
		/* continued at RDMA_CM_EVENT_ROUTE_RESOLVED */
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		/* after RDMA_CM_EVENT_ADDR_RESOLVED: */
		assert(pctx->state==IWINT_ADDR_RESOLVED);
		pctx->state = IWINT_ROUTE_RESOLVED;
		conn = talloc_get_type(cma_id->context, ibw_conn);
		pconn = talloc_get_type(conn->internal, ibw_conn_priv);

		rc = ibw_manage_connect(cma_id);
		if (rc)
			error = 1;

		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ctx->state = IBWS_CONNECT_REQUEST;
		conn = ibw_conn_new(ctx);
		pconn = talloc_get_type(conn->internal, ibw_conn_priv);
		pconn->cm_id = cma_id; /* !!! event will be freed but id not */
		cma_id->context = (void *)conn;
		DEBUG(10, "pconn->cm_id %p\n", pconn->cm_id);

		conn->state = IBWC_INIT;

		pctx->connstate_func(ctx, conn);

		/* continued at ibw_accept when invoked by the func above */
		if (!pconn->is_accepted) {
			talloc_free(conn);
			DEBUG(10, "pconn->cm_id %p wasn't accepted\n", pconn->cm_id);
		}

		/* TODO: clarify whether if it's needed by upper layer: */
		ctx->state = IBWS_READY;
		pctx->connstate_func(ctx, NULL);

		/* NOTE: more requests can arrive until RDMA_CM_EVENT_ESTABLISHED ! */
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		/* expected after ibw_accept and ibw_connect[not directly] */
		DEBUG(0, "ESTABLISHED\n");
		ctx->state = IBWS_READY;
		conn = talloc_get_type(cma_id->context, ibw_conn);
		assert(conn!=NULL); /* important assumption */
		pconn = talloc_get_type(conn->internal, ibw_conn_priv);

		conn->state = IBWC_CONNECTED;

		/* both ctx and conn have changed */
		pctx->connstate_func(ctx, conn);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		DEBUG(0, "cma event %d, error %d\n", event->event, event->status);
		error = 1;
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		if (cma_id!=ctx->cm_id) {
			DEBUG(0, "client DISCONNECT event\n");
			conn = talloc_get_type(cma_id->context, ibw_conn);
			conn->state = IBWC_DISCONNECTED;
			pctx->connstate_func(NULL, conn);

			talloc_free(conn);
		} else {
			DEBUG(0, "server DISCONNECT event\n");
			ctx->state = IBWS_STOPPED; /* ??? TODO: try it... */
			pctx->connstate_func(ctx, NULL);
		}
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		DEBUG(0, "cma detected device removal!\n");
		error = 1;
		break;

	default:
		DEBUG(0, "unknown event %d\n", event->event);
		error = 1;
		break;
	}

	if (error) {
		DEBUG(0, ibw_lasterr);
		if (cma_id!=ctx->cm_id) {
			conn = talloc_get_type(cma_id->context, ibw_conn);
			conn->state = IBWC_ERROR;
			pctx->connstate_func(NULL, conn);
		} else {
			ctx->state = IBWS_ERROR;
			pctx->connstate_func(ctx, NULL);
		}
	}

	if ((rc=rdma_ack_cm_event(event))) {
		sprintf(ibw_lasterr, "rdma_ack_cm_event failed with %d\n");
		DEBUG(0, ibw_lasterr, rc);
	}
}

static void ibw_event_handler_verbs(struct event_context *ev,
	struct fd_event *fde, uint16_t flags, void *private_data)
{
	int	rc;
	ibw_ctx	*ctx = talloc_get_type(private_data, ibw_ctx);
	ibw_ctx_priv *pctx = talloc_get_type(ctx->internal, ibw_ctx_priv);

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

	/* init cm */
	pctx->cm_channel = rdma_create_event_channel();
	if (!pctx->cm_channel) {
		ret = errno;
		sprintf(ibw_lasterr, "rdma_create_event_channel error %d\n", ret);
		goto cleanup;
	}

	pctx->cm_channel_event = event_add_fd(pctx->ectx, pctx,
		pctx->cm_channel->fd, EVENT_FD_READ, ibw_event_handler_cm, ctx);

	rc = rdma_create_id(pctx->cm_channel, &pctx->cm_id, cb, RDMA_PS_TCP);
	if (rc) {
		rc = errno;
		sprintf(ibw_lasterr, "rdma_create_id error %d\n", rc);
		goto cleanup;
	}
	DEBUG(10, "created cm_id %p\n", pctx->cm_id);

	/* init verbs */
	pctx->pd = ibv_alloc_pd(pctx->cmid->verbs);
	if (!pctx->pd) {
		sprintf(ibw_lasterr, "ibv_alloc_pd failed %d\n", errno);
		goto cleanup;
	}
	DEBUG(10, "created pd %p\n", pctx->pd);

	pctx->verbs_channel = ibv_create_comp_channel(cm_id->verbs);
	if (!pctx->verbs_channel) {
		sprintf(stderr, "ibv_create_comp_channel failed %d\n", errno);
		goto cleanup;
	}
	DEBUG_LOG("created channel %p\n", pctx->channel);

	pctx->verbs_channel_event = event_add_fd(pctx->ectx, pctx,
		pctx->verbs_channel->fd, EVENT_FD_READ, ibw_event_handler_verbs, ctx);

	pctx->cq = ibv_create_cq(cm_id->verbs, pctx->opts.rx_depth, ctx,
		ctx->verbs_channel, 0);

	/* allocate ib memory regions */

	return ctx;

cleanup:
	DEBUG(0, ibw_lasterr);
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

	rc = rdma_bind_addr(pctx->cm_id, (struct sockaddr *) my_addr);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_bind_addr error %d\n", rc);
		DEBUG(0, ibw_lasterr);
		return rc;
	}
	DEBUG(10, "rdma_bind_addr successful\n");

	return 0;
}

int ibw_listen(ibw_ctx *ctx, int backlog)
{
	ibw_ctx_priv *pctx = talloc_get_type(ctx->internal, ibw_ctx_priv);
	int	rc;

	DEBUG_LOG("rdma_listen...\n");
	rc = rdma_listen(cb->cm_id, backlog);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_listen failed: %d\n", ret);
		DEBUG(0, ibw_lasterr);
		return rc;
	}	

	return 0;
}

int ibw_accept(ibw_ctx *ctx, ibw_conn *conn, void *conn_userdata)
{
	ibw_ctx_priv *pctx = talloc_get_type(ctx->internal, ibw_ctx_priv);
	ibw_conn_priv *pconn = talloc_get_type(conn->internal, ibw_conn_priv);
	struct rdma_conn_param	conn_param;

	memset(&conn_param, 0, sizeof(struct rdma_conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	rc = rdma_accept(pconn->cm_id, &conn_param);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_accept failed %d\n", rc);
		DEBUG(0, ibw_lasterr);
		return -1;;
	}

	pconn->is_accepted = 1;

	/* continued at RDMA_CM_EVENT_ESTABLISHED */

	return 0;
}

int ibw_connect(ibw_ctx *ctx, struct sockaddr_in *serv_addr, void *conn_userdata)
{
	ibw_ctx_priv *pctx = talloc_get_type(ctx->internal, ibw_ctx_priv);
	ibw_conn *conn = NULL;
	int	rc;

	conn = ibw_conn_new(ctx);
	conn->conn_userdata = conn_userdata;
	pconn = talloc_get_type(conn->internal, ibw_conn_priv);

	rc = rdma_create_id(pctx->cm_channel, &pconn->cm_id, conn, RDMA_PS_TCP);
	if (rc) {
		rc = errno;
		sprintf(ibw_lasterr, "rdma_create_id error %d\n", rc);
		return rc;
	}

	assert(ctx->state==IBWS_READY);

	rc = rdma_resolve_addr(pconn->cm_id, NULL, (struct sockaddr *) &serv_addr, 2000);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_resolve_addr error %d\n", rc);
		DEBUG(0, ibw_lasterr);
		return -1;
	}

	/* continued at RDMA_CM_EVENT_ADDR_RESOLVED */

	return 0;
}

void ibw_disconnect(ibw_conn *conn)
{
	ibw_conn_priv *pconn = talloc_get_type(conn->internal, ibw_conn_priv);
	
	return 0;
}

int ibw_alloc_send_buf(ibw_conn *conn, void **buf, void **key, int n)
{
	ibw_conn_priv *pconn = talloc_get_type(conn->internal, ibw_conn_priv);

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
