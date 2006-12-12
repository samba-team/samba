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

static void ibw_event_handler_verbs(struct event_context *ev,
	struct fd_event *fde, uint16_t flags, void *private_data);

static int ibw_init_memory(ibw_conn *conn)
{
	ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, ibw_ctx_priv);
	ibw_conn_priv *pconn = talloc_get_type(conn->internal, ibw_conn_priv);

	int	i;
	ibw_wr	*p;

	pconn->buf = memalign(pctx->page_size, pctx->max_msg_size);
	if (!pconn->buf) {
		sprintf(ibw_lasterr, "couldn't allocate work buf\n");
		return -1;
	}
	pconn->mr = ibv_reg_mr(pctx->pd, pconn->buf,
		pctx->qsize * pctx->max_msg_size, IBV_ACCESS_LOCAL_WRITE);
	if (!pconn->mr) {
		sprintf(ibw_lasterr, "couldn't allocate mr\n");
		return -1;
	}

	pconn->wr_index = talloc_size(pconn, pctx->qsize * sizeof(ibw_wr *));

	for(i=0; i<pctx->qsize; i++) {
		p = pconn->wr_index[i] = talloc_zero(pconn, ibw_wr);
		p->msg = pconn->buf + (i * pctx->max_msg_size);
		p->wr_id = i;

		DLIST_ADD(pconn->mr_list_avail, p);
	}

	return 0;
}

static int ibw_ctx_priv_destruct(void *ptr)
{
	ibw_ctx *pctx = talloc_get_type(ctx->internal, ibw_ctx_priv);
	assert(pctx!=NULL);

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

	return 0;
}

static int ibw_conn_priv_destruct(void *ptr)
{
	ibw_conn *pconn = talloc_get_type(ptr, ibw_conn_priv);
	assert(pconn!=NULL);

	/* free memory regions */
	if (pconn->mr) {
		ibv_dereg_mr(pconn->mr);
		pconn->mr = NULL;
	}
	if (pconn->buf) {
		free(pconn->buf); /* memalign-ed */
		pconn->buf = NULL;
	}

	/* pconn->wr_index is freed by talloc */
	/* pconn->wr_index[i] are freed by talloc */

	/* destroy verbs */
	if (pconn->cm_id->qp) {
		ibv_destroy_qp(pconn->qp);
		pconn->qp = NULL;
	}
	if (pconn->cq) {
		ibv_destroy_cq(pconn->cq);
		pconn->cq = NULL;
	}
	if (pconn->verbs_channel) {
		ibv_destroy_comp_channel(pconn->verbs_channel);
		pconn->verbs_channel = NULL;
	}
	if (pconn->verbs_channel_event) {
		/* TODO: do we have to do this here? */
		talloc_free(pconn->verbs_channel_event);
		pconn->verbs_channel_event = NULL;
	}
	if (pconn->cm_id) {
		rdma_destroy_id(pctx->cm_id);
		pctx->cm_id = NULL;
	}
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

static int ibw_setup_cq_qp(ibw_conn *conn)
{
	ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, ibw_ctx_priv);
	ibw_conn_priv *pconn = talloc_get_type(conn->internal, ibw_conn_priv);
	struct ibv_qp_init_attr init_attr;
	int rc;

	/* init mr */
	if (ibw_init_memory(conn))
		return -1;

	/* init verbs */
	pconn->verbs_channel = ibv_create_comp_channel(pconn->cm_id->verbs);
	if (!pconn->verbs_channel) {
		sprintf(ibw_lasterr, "ibv_create_comp_channel failed %d\n", errno);
		goto cleanup;
	}
	DEBUG(10, "created channel %p\n", pconn->channel);

	pconn->verbs_channel_event = event_add_fd(pctx->ectx, conn,
		pconn->verbs_channel->fd, EVENT_FD_READ, ibw_event_handler_verbs, conn);

	/* init cq */
	pconn->cq = ibv_create_cq(conn->cm_id->verbs, pctx->qsize,
		conn, pconn->verbs_channel, 0);
	if (cq==NULL) {
		sprintf(ibw_lasterr, "ibv_create_cq failed\n");
		return -1;
	}

	rc = ibv_req_notify_cq(pconn->cq, 0);
	if (rc) {
		sprintf(ibw_lasterr, "ibv_req_notify_cq failed with %d\n", rc);
		return rc;
	}

	/* init qp */
	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.cap.max_send_wr = pctx->opts.max_send_wr;
	init_attr.cap.max_recv_wr = pctx->opts.max_recv_wr;
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.qp_type = IBV_QPT_RC;
	init_attr.send_cq = pconn->cq;
	init_attr.recv_cq = pconn->cq;

	rc = rdma_create_qp(conn->cm_id, pctx->pd, &init_attr);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_create_qp (%d) failed with %d\n", is_server, rc);
		return rc;
	}
	/* elase result is in pconn->cm_id->qp */

	return rc;
}

static int ibw_refill_cq_recv(ibw_conn *conn)
{
	ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, ibw_ctx_priv);
	ibw_conn_priv *pconn = talloc_get_type(conn->internal, ibw_conn_priv);
	int	i, rc;
	struct ibv_sge list = {
		.addr 	= (uintptr_t) NULL,
		.length = pctx->max_msg_size,
		.lkey 	= pconn->mr->lkey
	};
	struct ibv_recv_wr wr = {
		.wr_id 	    = 0,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ibv_recv_wr *bad_wr;
	ibw_wr	*p = pconn->wr_list_avail;

	if (p==NULL) {
		sprintf(ibw_last_err, "out of wr_list_avail");
		DEBUG(0, ibw_last_err);
		return -1;
	}
	DLIST_REMOVE(pconn->wr_list_avail, p);
	DLIST_ADD(pconn->wr_list_used, p);
	list.addr = p->msg;
	wr.wr_id = p->wr_id;

	rc = ibv_post_recv(pconn->qp, &wr, &bad_wr);
	if (rc) {
		sprintf(ibw_lasterr, "ibv_post_recv failed with %d\n", rc);
		DEBUG(0, ibw_last_err);
		return -2;
	}

	return 0;
}

static int ibw_fill_cq(ibw_conn *conn)
{
	ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, ibw_ctx_priv);
	ibw_conn_priv *pconn = talloc_get_type(conn->internal, ibw_conn_priv);
	int	i, rc;
	struct ibv_sge list = {
		.addr 	= (uintptr_t) NULL,
		.length = pctx->max_msg_size,
		.lkey 	= pconn->mr->lkey
	};
	struct ibv_recv_wr wr = {
		.wr_id 	    = 0,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ibv_recv_wr *bad_wr;
	ibw_wr	*p;

	for(i = pctx->opts.max_recv_wr; i!=0; i--) {
		p = pconn->wr_list_avail;
		if (p==NULL) {
			sprintf(ibw_last_err, "out of wr_list_avail");
			DEBUG(0, ibw_last_err);
			return -1;
		}
		DLIST_REMOVE(pconn->wr_list_avail, p);
		DLIST_ADD(pconn->wr_list_used, p);
		list.addr = p->msg;
		wr.wr_id = p->wr_id;

		rc = ibv_post_recv(pconn->qp, &wr, &bad_wr);
		if (rc) {
			sprintf(ibw_lasterr, "ibv_post_recv failed with %d\n", rc);
			DEBUG(0, ibw_last_err);
			return -2;
		}
	}

	return 0;
}

static int ibw_manage_connect(ibw_conn *conn, struct rdma_cm_id *cma_id)
{
	struct rdma_conn_param conn_param;
	int	rc;

	rc = ibw_setup_cq_qp(conn);
	if (rc)
		return -1;

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

	assert(ctx!=NULL);

	rc = rdma_get_cm_event(pctx->cm_channel, &event);
	if (rc) {
		ctx->state = IBWS_ERROR;
		sprintf(ibw_lasterr, "rdma_get_cm_event error %d\n", rc);
		goto error;
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
			ctx->state = ERROR;
			sprintf(ibw_lasterr, "rdma_resolve_route error %d\n", rc);
			goto error;
		}
		/* continued at RDMA_CM_EVENT_ROUTE_RESOLVED */
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		/* after RDMA_CM_EVENT_ADDR_RESOLVED: */
		assert(pctx->state==IWINT_ADDR_RESOLVED);
		pctx->state = IWINT_ROUTE_RESOLVED;
		assert(cma_id->context!=NULL);
		conn = talloc_get_type(cma_id->context, ibw_conn);
		pconn = talloc_get_type(conn->internal, ibw_conn_priv);

		rc = ibw_manage_connect(conn, cma_id);
		if (rc)
			goto error;

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
		} else {
			if (ibw_setup_cq_qp(ctx, conn))
				goto error;
		}

		/* TODO: clarify whether if it's needed by upper layer: */
		ctx->state = IBWS_READY;
		pctx->connstate_func(ctx, NULL);

		/* NOTE: more requests can arrive until RDMA_CM_EVENT_ESTABLISHED ! */
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		/* expected after ibw_accept and ibw_connect[not directly] */
		DEBUG(0, "ESTABLISHED (conn: %u)\n", cma_id->context);
		conn = talloc_get_type(cma_id->context, ibw_conn);
		assert(conn!=NULL); /* important assumption */
		pconn = talloc_get_type(conn->internal, ibw_conn_priv);

		/* client conn is up */
		conn->state = IBWC_CONNECTED;

		/* both ctx and conn have changed */
		pctx->connstate_func(ctx, conn);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		sprintf(ibw_lasterr, "cma event %d, error %d\n", event->event, event->status);
		goto error;

	case RDMA_CM_EVENT_DISCONNECTED:
		if (cma_id!=ctx->cm_id) {
			DEBUG(0, "client DISCONNECT event\n");
			conn = talloc_get_type(cma_id->context, ibw_conn);
			conn->state = IBWC_DISCONNECTED;
			pctx->connstate_func(NULL, conn);

			talloc_free(conn);

			/* if we are the last... */
			if (ctx->conn_list==NULL)
				rdma_disconnect(ctx->cm_id);
		} else {
			DEBUG(0, "server DISCONNECT event\n");
			ctx->state = IBWS_STOPPED; /* ??? TODO: try it... */
			/* talloc_free(ctx) should be called within or after this func */
			pctx->connstate_func(ctx, NULL);
		}
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		sprintf(ibw_lasterr, "cma detected device removal!\n");
		goto error;

	default:
		sprintf(ibw_lasterr, "unknown event %d\n", event->event);
		goto error;
	}

	if ((rc=rdma_ack_cm_event(event))) {
		sprintf(ibw_lasterr, "rdma_ack_cm_event failed with %d\n");
		goto error;
	}

	return;
error:
	DEBUG(0, "cm event handler: %s", ibw_lasterr);
	if (cma_id!=ctx->cm_id) {
		conn = talloc_get_type(cma_id->context, ibw_conn);
		if (conn)
			conn->state = IBWC_ERROR;
		pctx->connstate_func(NULL, conn);
	} else {
		ctx->state = IBWS_ERROR;
		pctx->connstate_func(ctx, NULL);
	}
}

static void ibw_event_handler_verbs(struct event_context *ev,
	struct fd_event *fde, uint16_t flags, void *private_data)
{
	ibw_ctx	*conn = talloc_get_type(private_data, ibw_conn);
	ibw_ctx_priv *pconn = talloc_get_type(conn->internal, ibw_ctx_priv);
	ibw_ctx	*pctx = talloc_get_type(conn->ctx->internal, ibw_ctx_priv);

	struct ibv_wc wc;
	int rc;

	rc = ibv_poll_cq(conn->cq, 1, &wc);
	if (rc!=1) {
		sprintf(ibw_lasterr, "ibv_poll_cq error %d\n", rc);
		goto error;
	}
	if (wc.status) {
		sprintf(ibw_lasterr, "cq completion failed status %d\n",
			wc.status);
		goto error;
	}

	switch(wc.opcode) {
	case IBV_WC_SEND:
		{
			ibw_wr	*p;
	
			DEBUG(10, "send completion\n");
			assert(pconn->qp->qp_num==wc.qp_num);
			assert(wc.wr_id < pctx->qsize);
			p = pconn->wr_index[wc.wr_id];
			DLIST_REMOVE(pconn->wr_list_used, p);
			DLIST_ADD(pconn->wr_list_avail, p);
		}
		break;

	case IBV_WC_RDMA_WRITE:
		DEBUG(10, "rdma write completion\n");
		break;

	case IBV_WC_RDMA_READ:
		DEBUG(10, "rdma read completion\n");
		break;

	case IBV_WC_RECV:
		{
			ibw_wr	*p;
	
			assert(pconn->qp->qp_num==wc.qp_num);
			assert(wc.wr_id < pctx->qsize);
			p = pconn->wr_index[wc.wr_id];
	
			DLIST_REMOVE(pconn->wr_list_used, p);
			DLIST_ADD(pconn->wr_list_avail, p);
	
			DEBUG(10, "recv completion\n");
			assert(wc.byte_len <= pctx->max_msg_size);
	
			pctx->receive_func(conn, p->msg, wc.byte_len);
			if (ibw_refill_cq_recv(conn))
				goto error;
		}
		break;

	default:
		sprintf(ibw_lasterr, "unknown completion %d\n", wc.opcode);
		goto error;
	}

	return;
error:
	DEBUG(0, ibw_lasterr);
	conn->status = IBWC_ERROR;
	pctx->connstate_func(NULL, conn);
}

static int ibw_process_init_attrs(ibw_initattr *attr, int nattr, ibw_opts *opts)
{
	int	i, mtu;
	char *name, *value;

	opts->max_send_wr = 256;
	opts->max_recv_wr = 1024;

	for(i=0; i<nattr; i++) {
		name = attr[i].name;
		value = attr[i].value;

		assert(name!=NULL && value!=NULL);
		if (strcmp(name, "max_send_wr")==0)
			opts->max_send_wr = atoi(value);
		else if (strcmp(name, "max_recv_wr")==0)
			opts->max_recv_wr = atoi(value);
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
	event_content *ectx,
	int max_msg_size)
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
		sprintf(ibw_lasterr, "rdma_create_event_channel error %d\n", errno);
		goto cleanup;
	}

	pctx->cm_channel_event = event_add_fd(pctx->ectx, pctx,
		pctx->cm_channel->fd, EVENT_FD_READ, ibw_event_handler_cm, ctx);

	rc = rdma_create_id(pctx->cm_channel, &pctx->cm_id, ctx, RDMA_PS_TCP);
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

	pctx->pagesize = sysconf(_SC_PAGESIZE);
	pctx->qsize = pctx->opts.max_send_wr + pctx->opts.max_recv_wr;
	pctx->max_msg_size = max_msg_size;

	return ctx;
	/* don't put code here */
cleanup:
	DEBUG(0, ibw_lasterr);

	if (ctx)
		talloc_free(ctx);

	return NULL;
}

int ibw_stop(ibw_ctx *ctx)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
	ibw_conn *p;

	for(p=ctx->conn_list; p!=NULL; p=p->next) {
		if (ctx->state==IBWC_ERROR || ctx->state==IBWC_CONNECTED) {
			if (ibw_disconnect(p))
				return -1;
		}
	}

	return 0;
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
	rc = rdma_listen(pctx->cm_id, backlog);
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

	conn->conn_userdata = conn_userdata;

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
	ibw_ctx *ctx = conn->ctx;
	ibw_ctx_priv *pctx = talloc_get_type(ctx->internal);

	rdma_disconnect(pctx->cm_id);

	/* continued at RDMA_CM_EVENT_DISCONNECTED */

	return 0;
}

int ibw_alloc_send_buf(ibw_conn *conn, void **buf, void **key)
{
	ibw_conn_priv *pconn = talloc_get_type(conn->internal, ibw_conn_priv);
	ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, ibw_ctx_priv);
	ibw_wr *p = pctx->wr_list_avail;

	if (p==NULL) {
		sprintf(ibw_last_err, "insufficient wr chunks\n");
		return -1;
	}

	DLIST_REMOVE(pctx->wr_list_avail, p);
	DLIST_ADD(pctx->wr_list_used, p);

	*buf = (void *)p->msg;
	*key = (void *)p;

	return pctx->buf;
}

int ibw_send(ibw_conn *conn, void *buf, void *key, int n)
{
	ibw_ctx_priv pctx = talloc_get_type(conn->ctx->internal, ibw_ctx_priv);
	ibw_wr *p = talloc_get_type(key, ibw_wr);
	struct ibv_sge list = {
		.addr 	= (uintptr_t) p->msg,
		.length = n,
		.lkey 	= pctx->mr->lkey
	};
	struct ibv_send_wr wr = {
		.wr_id 	    = p->wr_id,
		.sg_list    = &list,
		.num_sge    = 1,
		.opcode     = IBV_WR_SEND,
		.send_flags = IBV_SEND_SIGNALED,
	};
	struct ibv_send_wr *bad_wr;

	assert(p->msg==(char *)buf);
	assert(n<=pctx->max_msg_size);

	return ibv_post_send(conn->qp, &wr, &bad_wr);
}

const char *ibw_getLastError()
{
	return ibw_lasterr;
}
