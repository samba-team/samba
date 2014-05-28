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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <assert.h>
#include <unistd.h>

#include "includes.h"
#include "ibwrapper.h"

#include <infiniband/kern-abi.h>
#include <rdma/rdma_cma_abi.h>
#include <rdma/rdma_cma.h>

#include "ibwrapper_internal.h"
#include "lib/util/dlinklist.h"

#define IBW_LASTERR_BUFSIZE 512
static char ibw_lasterr[IBW_LASTERR_BUFSIZE];

#define IBW_MAX_SEND_WR 256
#define IBW_MAX_RECV_WR 1024
#define IBW_RECV_BUFSIZE 256
#define IBW_RECV_THRESHOLD (1 * 1024 * 1024)

static void ibw_event_handler_verbs(struct event_context *ev,
	struct fd_event *fde, uint16_t flags, void *private_data);
static int ibw_fill_cq(struct ibw_conn *conn);
static int ibw_wc_recv(struct ibw_conn *conn, struct ibv_wc *wc);
static int ibw_wc_send(struct ibw_conn *conn, struct ibv_wc *wc);
static int ibw_send_packet(struct ibw_conn *conn, void *buf, struct ibw_wr *p, uint32_t len);

static void *ibw_alloc_mr(struct ibw_ctx_priv *pctx, struct ibw_conn_priv *pconn,
	uint32_t n, struct ibv_mr **ppmr)
{
	void *buf;

	DEBUG(DEBUG_DEBUG, ("ibw_alloc_mr(cmid=%p, n=%u)\n", pconn->cm_id, n));
	buf = memalign(pctx->pagesize, n);
	if (!buf) {
		sprintf(ibw_lasterr, "couldn't allocate memory\n");
		return NULL;
	}

	*ppmr = ibv_reg_mr(pconn->pd, buf, n, IBV_ACCESS_LOCAL_WRITE);
	if (!*ppmr) {
		sprintf(ibw_lasterr, "couldn't allocate mr\n");
		free(buf);
		return NULL;
	}

	return buf;
}

static void ibw_free_mr(char **ppbuf, struct ibv_mr **ppmr)
{
	DEBUG(DEBUG_DEBUG, ("ibw_free_mr(%p %p)\n", *ppbuf, *ppmr));
	if (*ppmr!=NULL) {
		ibv_dereg_mr(*ppmr);
		*ppmr = NULL;
	}
	if (*ppbuf) {
		free(*ppbuf);
		*ppbuf = NULL;
	}
}

static int ibw_init_memory(struct ibw_conn *conn)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_opts *opts = &pctx->opts;
	int	i;
	struct ibw_wr	*p;

	DEBUG(DEBUG_DEBUG, ("ibw_init_memory(cmid: %p)\n", pconn->cm_id));
	pconn->buf_send = ibw_alloc_mr(pctx, pconn,
		opts->max_send_wr * opts->recv_bufsize, &pconn->mr_send);
	if (!pconn->buf_send) {
		sprintf(ibw_lasterr, "couldn't allocate work send buf\n");
		return -1;
	}

	pconn->buf_recv = ibw_alloc_mr(pctx, pconn,
		opts->max_recv_wr * opts->recv_bufsize, &pconn->mr_recv);
	if (!pconn->buf_recv) {
		sprintf(ibw_lasterr, "couldn't allocate work recv buf\n");
		return -1;
	}

	pconn->wr_index = talloc_size(pconn, opts->max_send_wr * sizeof(struct ibw_wr *));
	assert(pconn->wr_index!=NULL);

	for(i=0; i<opts->max_send_wr; i++) {
		p = pconn->wr_index[i] = talloc_zero(pconn, struct ibw_wr);
		p->buf = pconn->buf_send + (i * opts->recv_bufsize);
		p->wr_id = i;

		DLIST_ADD(pconn->wr_list_avail, p);
	}

	return 0;
}

static int ibw_ctx_priv_destruct(struct ibw_ctx_priv *pctx)
{
	DEBUG(DEBUG_DEBUG, ("ibw_ctx_priv_destruct(%p)\n", pctx));

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

	return 0;
}

static int ibw_ctx_destruct(struct ibw_ctx *ctx)
{
	DEBUG(DEBUG_DEBUG, ("ibw_ctx_destruct(%p)\n", ctx));
	return 0;
}

static int ibw_conn_priv_destruct(struct ibw_conn_priv *pconn)
{
	DEBUG(DEBUG_DEBUG, ("ibw_conn_priv_destruct(%p, cmid: %p)\n",
		pconn, pconn->cm_id));

	/* pconn->wr_index is freed by talloc */
	/* pconn->wr_index[i] are freed by talloc */

	/* destroy verbs */
	if (pconn->cm_id!=NULL && pconn->cm_id->qp!=NULL) {
		rdma_destroy_qp(pconn->cm_id);
		pconn->cm_id->qp = NULL;
	}

	if (pconn->cq!=NULL) {
		ibv_destroy_cq(pconn->cq);
		pconn->cq = NULL;
	}

	if (pconn->verbs_channel!=NULL) {
		ibv_destroy_comp_channel(pconn->verbs_channel);
		pconn->verbs_channel = NULL;
	}

	/* must be freed here because its order is important */
	if (pconn->verbs_channel_event) {
		talloc_free(pconn->verbs_channel_event);
		pconn->verbs_channel_event = NULL;
	}

	/* free memory regions */
	ibw_free_mr(&pconn->buf_send, &pconn->mr_send);
	ibw_free_mr(&pconn->buf_recv, &pconn->mr_recv);

	if (pconn->pd) {
		ibv_dealloc_pd(pconn->pd);
		pconn->pd = NULL;
		DEBUG(DEBUG_DEBUG, ("pconn=%p pd deallocated\n", pconn));
	}

	if (pconn->cm_id) {
		rdma_destroy_id(pconn->cm_id);
		pconn->cm_id = NULL;
		DEBUG(DEBUG_DEBUG, ("pconn=%p cm_id destroyed\n", pconn));
	}

	return 0;
}

static int ibw_wr_destruct(struct ibw_wr *wr)
{
	if (wr->buf_large!=NULL)
		ibw_free_mr(&wr->buf_large, &wr->mr_large);
	return 0;
}

static int ibw_conn_destruct(struct ibw_conn *conn)
{
	DEBUG(DEBUG_DEBUG, ("ibw_conn_destruct(%p)\n", conn));
	
	/* important here: ctx is a talloc _parent_ */
	DLIST_REMOVE(conn->ctx->conn_list, conn);
	return 0;
}

struct ibw_conn *ibw_conn_new(struct ibw_ctx *ctx, TALLOC_CTX *mem_ctx)
{
	struct ibw_conn *conn;
	struct ibw_conn_priv *pconn;

	assert(ctx!=NULL);

	conn = talloc_zero(mem_ctx, struct ibw_conn);
	assert(conn!=NULL);
	talloc_set_destructor(conn, ibw_conn_destruct);

	pconn = talloc_zero(conn, struct ibw_conn_priv);
	assert(pconn!=NULL);
	talloc_set_destructor(pconn, ibw_conn_priv_destruct);

	conn->ctx = ctx;
	conn->internal = (void *)pconn;

	DLIST_ADD(ctx->conn_list, conn);

	return conn;
}

static int ibw_setup_cq_qp(struct ibw_conn *conn)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibv_qp_init_attr init_attr;
	struct ibv_qp_attr attr;
	int rc;

	DEBUG(DEBUG_DEBUG, ("ibw_setup_cq_qp(cmid: %p)\n", pconn->cm_id));

	/* init verbs */
	pconn->verbs_channel = ibv_create_comp_channel(pconn->cm_id->verbs);
	if (!pconn->verbs_channel) {
		sprintf(ibw_lasterr, "ibv_create_comp_channel failed %d\n", errno);
		return -1;
	}
	DEBUG(DEBUG_DEBUG, ("created channel %p\n", pconn->verbs_channel));

	pconn->verbs_channel_event = event_add_fd(pctx->ectx, NULL, /* not pconn or conn */
		pconn->verbs_channel->fd, EVENT_FD_READ, ibw_event_handler_verbs, conn);

	pconn->pd = ibv_alloc_pd(pconn->cm_id->verbs);
	if (!pconn->pd) {
		sprintf(ibw_lasterr, "ibv_alloc_pd failed %d\n", errno);
		return -1;
	}
	DEBUG(DEBUG_DEBUG, ("created pd %p\n", pconn->pd));

	/* init mr */
	if (ibw_init_memory(conn))
		return -1;

	/* init cq */
	pconn->cq = ibv_create_cq(pconn->cm_id->verbs,
		pctx->opts.max_recv_wr + pctx->opts.max_send_wr,
		conn, pconn->verbs_channel, 0);
	if (pconn->cq==NULL) {
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

	rc = rdma_create_qp(pconn->cm_id, pconn->pd, &init_attr);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_create_qp failed with %d\n", rc);
		return rc;
	}
	/* elase result is in pconn->cm_id->qp */

	rc = ibv_query_qp(pconn->cm_id->qp, &attr, IBV_QP_PATH_MTU, &init_attr);
	if (rc) {
		sprintf(ibw_lasterr, "ibv_query_qp failed with %d\n", rc);
		return rc;
	}

	return ibw_fill_cq(conn);
}

static int ibw_refill_cq_recv(struct ibw_conn *conn)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	int	rc;
	struct ibv_sge list = {
		.addr 	= (uintptr_t) NULL, /* filled below */
		.length = pctx->opts.recv_bufsize,
		.lkey 	= pconn->mr_recv->lkey /* always the same */
	};
	struct ibv_recv_wr wr = {
		.wr_id 	    = 0, /* filled below */
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ibv_recv_wr *bad_wr;

	DEBUG(DEBUG_DEBUG, ("ibw_refill_cq_recv(cmid: %p)\n", pconn->cm_id));

	list.addr = (uintptr_t) pconn->buf_recv + pctx->opts.recv_bufsize * pconn->recv_index;
	wr.wr_id = pconn->recv_index;
	pconn->recv_index = (pconn->recv_index + 1) % pctx->opts.max_recv_wr;

	rc = ibv_post_recv(pconn->cm_id->qp, &wr, &bad_wr);
	if (rc) {
		sprintf(ibw_lasterr, "refill/ibv_post_recv failed with %d\n", rc);
		DEBUG(DEBUG_ERR, (ibw_lasterr));
		return -2;
	}

	return 0;
}

static int ibw_fill_cq(struct ibw_conn *conn)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	int	i, rc;
	struct ibv_sge list = {
		.addr 	= (uintptr_t) NULL, /* filled below */
		.length = pctx->opts.recv_bufsize,
		.lkey 	= pconn->mr_recv->lkey /* always the same */
	};
	struct ibv_recv_wr wr = {
		.wr_id 	    = 0, /* filled below */
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ibv_recv_wr *bad_wr;

	DEBUG(DEBUG_DEBUG, ("ibw_fill_cq(cmid: %p)\n", pconn->cm_id));

	for(i = pctx->opts.max_recv_wr; i!=0; i--) {
		list.addr = (uintptr_t) pconn->buf_recv + pctx->opts.recv_bufsize * pconn->recv_index;
		wr.wr_id = pconn->recv_index;
		pconn->recv_index = (pconn->recv_index + 1) % pctx->opts.max_recv_wr;

		rc = ibv_post_recv(pconn->cm_id->qp, &wr, &bad_wr);
		if (rc) {
			sprintf(ibw_lasterr, "fill/ibv_post_recv failed with %d\n", rc);
			DEBUG(DEBUG_ERR, (ibw_lasterr));
			return -2;
		}
	}

	return 0;
}

static int ibw_manage_connect(struct ibw_conn *conn)
{
	struct rdma_conn_param conn_param;
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	int	rc;

	DEBUG(DEBUG_DEBUG, ("ibw_manage_connect(cmid: %p)\n", pconn->cm_id));

	if (ibw_setup_cq_qp(conn))
		return -1;

	/* cm connect */
	memset(&conn_param, 0, sizeof conn_param);
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 10;

	rc = rdma_connect(pconn->cm_id, &conn_param);
	if (rc)
		sprintf(ibw_lasterr, "rdma_connect error %d\n", rc);

	return rc;
}

static void ibw_event_handler_cm(struct event_context *ev,
	struct fd_event *fde, uint16_t flags, void *private_data)
{
	int	rc;
	struct ibw_ctx	*ctx = talloc_get_type(private_data, struct ibw_ctx);
	struct ibw_ctx_priv *pctx = talloc_get_type(ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn *conn = NULL;
	struct ibw_conn_priv *pconn = NULL;
	struct rdma_cm_id *cma_id = NULL;
	struct rdma_cm_event *event = NULL;

	assert(ctx!=NULL);

	rc = rdma_get_cm_event(pctx->cm_channel, &event);
	if (rc) {
		ctx->state = IBWS_ERROR;
		event = NULL;
		sprintf(ibw_lasterr, "rdma_get_cm_event error %d\n", rc);
		goto error;
	}
	cma_id = event->id;

	DEBUG(DEBUG_DEBUG, ("cma_event type %d cma_id %p (%s)\n", event->event, cma_id,
		  (cma_id == pctx->cm_id) ? "parent" : "child"));

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		DEBUG(DEBUG_DEBUG, ("RDMA_CM_EVENT_ADDR_RESOLVED\n"));
		/* continuing from ibw_connect ... */
		rc = rdma_resolve_route(cma_id, 2000);
		if (rc) {
			sprintf(ibw_lasterr, "rdma_resolve_route error %d\n", rc);
			goto error;
		}
		/* continued at RDMA_CM_EVENT_ROUTE_RESOLVED */
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		DEBUG(DEBUG_DEBUG, ("RDMA_CM_EVENT_ROUTE_RESOLVED\n"));
		/* after RDMA_CM_EVENT_ADDR_RESOLVED: */
		assert(cma_id->context!=NULL);
		conn = talloc_get_type(cma_id->context, struct ibw_conn);

		rc = ibw_manage_connect(conn);
		if (rc)
			goto error;

		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		DEBUG(DEBUG_DEBUG, ("RDMA_CM_EVENT_CONNECT_REQUEST\n"));
		ctx->state = IBWS_CONNECT_REQUEST;
		conn = ibw_conn_new(ctx, ctx);
		pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
		pconn->cm_id = cma_id; /* !!! event will be freed but id not */
		cma_id->context = (void *)conn;
		DEBUG(DEBUG_DEBUG, ("pconn->cm_id %p\n", pconn->cm_id));

		if (ibw_setup_cq_qp(conn))
			goto error;

		conn->state = IBWC_INIT;
		pctx->connstate_func(ctx, conn);

		/* continued at ibw_accept when invoked by the func above */
		if (!pconn->is_accepted) {
			rc = rdma_reject(cma_id, NULL, 0);
			if (rc)
				DEBUG(DEBUG_ERR, ("rdma_reject failed with rc=%d\n", rc));
			talloc_free(conn);
			DEBUG(DEBUG_DEBUG, ("pconn->cm_id %p wasn't accepted\n", pconn->cm_id));
		}

		/* TODO: clarify whether if it's needed by upper layer: */
		ctx->state = IBWS_READY;
		pctx->connstate_func(ctx, NULL);

		/* NOTE: more requests can arrive until RDMA_CM_EVENT_ESTABLISHED ! */
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		/* expected after ibw_accept and ibw_connect[not directly] */
		DEBUG(DEBUG_INFO, ("ESTABLISHED (conn: %p)\n", cma_id->context));
		conn = talloc_get_type(cma_id->context, struct ibw_conn);
		assert(conn!=NULL); /* important assumption */

		DEBUG(DEBUG_DEBUG, ("ibw_setup_cq_qp succeeded (cmid=%p)\n", cma_id));

		/* client conn is up */
		conn->state = IBWC_CONNECTED;

		/* both ctx and conn have changed */
		pctx->connstate_func(ctx, conn);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
		sprintf(ibw_lasterr, "RDMA_CM_EVENT_ADDR_ERROR, error %d\n", event->status);
	case RDMA_CM_EVENT_ROUTE_ERROR:
		sprintf(ibw_lasterr, "RDMA_CM_EVENT_ROUTE_ERROR, error %d\n", event->status);
	case RDMA_CM_EVENT_CONNECT_ERROR:
		sprintf(ibw_lasterr, "RDMA_CM_EVENT_CONNECT_ERROR, error %d\n", event->status);
	case RDMA_CM_EVENT_UNREACHABLE:
		sprintf(ibw_lasterr, "RDMA_CM_EVENT_UNREACHABLE, error %d\n", event->status);
		goto error;
	case RDMA_CM_EVENT_REJECTED:
		sprintf(ibw_lasterr, "RDMA_CM_EVENT_REJECTED, error %d\n", event->status);
		DEBUG(DEBUG_INFO, ("cm event handler: %s", ibw_lasterr));
		conn = talloc_get_type(cma_id->context, struct ibw_conn);
		if (conn) {
			/* must be done BEFORE connstate */
			if ((rc=rdma_ack_cm_event(event)))
				DEBUG(DEBUG_ERR, ("reject/rdma_ack_cm_event failed with %d\n", rc));
			event = NULL; /* not to touch cma_id or conn */
			conn->state = IBWC_ERROR;
			/* it should free the conn */
			pctx->connstate_func(NULL, conn);
		}
		break; /* this is not strictly an error */

	case RDMA_CM_EVENT_DISCONNECTED:
		DEBUG(DEBUG_DEBUG, ("RDMA_CM_EVENT_DISCONNECTED\n"));
		if ((rc=rdma_ack_cm_event(event)))
			DEBUG(DEBUG_ERR, ("disc/rdma_ack_cm_event failed with %d\n", rc));
		event = NULL; /* don't ack more */

		if (cma_id!=pctx->cm_id) {
			DEBUG(DEBUG_ERR, ("client DISCONNECT event cm_id=%p\n", cma_id));
			conn = talloc_get_type(cma_id->context, struct ibw_conn);
			conn->state = IBWC_DISCONNECTED;
			pctx->connstate_func(NULL, conn);
		}
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		sprintf(ibw_lasterr, "cma detected device removal!\n");
		goto error;

	default:
		sprintf(ibw_lasterr, "unknown event %d\n", event->event);
		goto error;
	}

	if (event!=NULL && (rc=rdma_ack_cm_event(event))) {
		sprintf(ibw_lasterr, "rdma_ack_cm_event failed with %d\n", rc);
		goto error;
	}

	return;
error:
	DEBUG(DEBUG_ERR, ("cm event handler: %s", ibw_lasterr));

	if (event!=NULL) {
		if (cma_id!=NULL && cma_id!=pctx->cm_id) {
			conn = talloc_get_type(cma_id->context, struct ibw_conn);
			if (conn) {
				conn->state = IBWC_ERROR;
				pctx->connstate_func(NULL, conn);
			}
		} else {
			ctx->state = IBWS_ERROR;
			pctx->connstate_func(ctx, NULL);
		}

		if ((rc=rdma_ack_cm_event(event))!=0) {
			DEBUG(DEBUG_ERR, ("rdma_ack_cm_event failed with %d\n", rc));
		}
	}

	return;
}

static void ibw_event_handler_verbs(struct event_context *ev,
	struct fd_event *fde, uint16_t flags, void *private_data)
{
	struct ibw_conn	*conn = talloc_get_type(private_data, struct ibw_conn);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);

	struct ibv_wc wc;
	int rc;
	struct ibv_cq *ev_cq;
	void          *ev_ctx;

	DEBUG(DEBUG_DEBUG, ("ibw_event_handler_verbs(%u)\n", (uint32_t)flags));

	/* TODO: check whether if it's good to have more channels here... */
	rc = ibv_get_cq_event(pconn->verbs_channel, &ev_cq, &ev_ctx);
	if (rc) {
		sprintf(ibw_lasterr, "Failed to get cq_event with %d\n", rc);
		goto error;
	}
	if (ev_cq != pconn->cq) {
		sprintf(ibw_lasterr, "ev_cq(%p) != pconn->cq(%p)\n", ev_cq, pconn->cq);
		goto error;
	}
	rc = ibv_req_notify_cq(pconn->cq, 0);
	if (rc) {
		sprintf(ibw_lasterr, "Couldn't request CQ notification (%d)\n", rc);
		goto error;
	}

	while((rc=ibv_poll_cq(pconn->cq, 1, &wc))==1) {
		if (wc.status) {
			sprintf(ibw_lasterr, "cq completion failed status=%d, opcode=%d, rc=%d\n",
				wc.status, wc.opcode, rc);
			goto error;
		}

		switch(wc.opcode) {
		case IBV_WC_SEND:
			DEBUG(DEBUG_DEBUG, ("send completion\n"));
			if (ibw_wc_send(conn, &wc))
				goto error;
			break;

		case IBV_WC_RDMA_WRITE:
			DEBUG(DEBUG_DEBUG, ("rdma write completion\n"));
			break;
	
		case IBV_WC_RDMA_READ:
			DEBUG(DEBUG_DEBUG, ("rdma read completion\n"));
			break;

		case IBV_WC_RECV:
			DEBUG(DEBUG_DEBUG, ("recv completion\n"));
			if (ibw_wc_recv(conn, &wc))
				goto error;
			break;

		default:
			sprintf(ibw_lasterr, "unknown completion %d\n", wc.opcode);
			goto error;
		}
	}
	if (rc!=0) {
		sprintf(ibw_lasterr, "ibv_poll_cq error %d\n", rc);
		goto error;
	}

	ibv_ack_cq_events(pconn->cq, 1);

	return;
error:
	ibv_ack_cq_events(pconn->cq, 1);

	DEBUG(DEBUG_ERR, (ibw_lasterr));
	
	if (conn->state!=IBWC_ERROR) {
		conn->state = IBWC_ERROR;
		pctx->connstate_func(NULL, conn);
	}
}

static int ibw_process_queue(struct ibw_conn *conn)
{
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_ctx_priv *pctx;
	struct ibw_wr	*p;
	int	rc;
	uint32_t	msg_size;

	if (pconn->queue==NULL)
		return 0; /* NOP */

	p = pconn->queue;

	/* we must have at least 1 fragment to send */
	assert(p->queued_ref_cnt>0);
	p->queued_ref_cnt--;

	pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	msg_size = (p->queued_ref_cnt) ? pctx->opts.recv_bufsize : p->queued_rlen;

	assert(p->queued_msg!=NULL);
	assert(msg_size!=0);

	DEBUG(DEBUG_DEBUG, ("ibw_process_queue refcnt=%d msgsize=%u\n",
		p->queued_ref_cnt, msg_size));

	rc = ibw_send_packet(conn, p->queued_msg, p, msg_size);

	/* was this the last fragment? */
	if (p->queued_ref_cnt) {
		p->queued_msg += pctx->opts.recv_bufsize;
	} else {
		DLIST_REMOVE2(pconn->queue, p, qprev, qnext);
		p->queued_msg = NULL;
	}

	return rc;
}

static int ibw_wc_send(struct ibw_conn *conn, struct ibv_wc *wc)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_wr	*p;
	int	send_index;

	DEBUG(DEBUG_DEBUG, ("ibw_wc_send(cmid: %p, wr_id: %u, bl: %u)\n",
		pconn->cm_id, (uint32_t)wc->wr_id, (uint32_t)wc->byte_len));

	assert(pconn->cm_id->qp->qp_num==wc->qp_num);
	assert(wc->wr_id >= pctx->opts.max_recv_wr);
	send_index = wc->wr_id - pctx->opts.max_recv_wr;
	pconn->wr_sent--;

	if (send_index < pctx->opts.max_send_wr) {
		DEBUG(DEBUG_DEBUG, ("ibw_wc_send#1 %u\n", (int)wc->wr_id));
		p = pconn->wr_index[send_index];
		if (p->buf_large!=NULL) {
			if (p->ref_cnt) {
				/* awaiting more of it... */
				p->ref_cnt--;
			} else {
				ibw_free_mr(&p->buf_large, &p->mr_large);
				DLIST_REMOVE(pconn->wr_list_used, p);
				DLIST_ADD(pconn->wr_list_avail, p);
			}
		} else { /* nasty - but necessary */
			DLIST_REMOVE(pconn->wr_list_used, p);
			DLIST_ADD(pconn->wr_list_avail, p);
		}
	} else { /* "extra" request - not optimized */
		DEBUG(DEBUG_DEBUG, ("ibw_wc_send#2 %u\n", (int)wc->wr_id));
		for(p=pconn->extra_sent; p!=NULL; p=p->next)
			if ((p->wr_id + pctx->opts.max_recv_wr)==(int)wc->wr_id)
				break;
		if (p==NULL) {
			sprintf(ibw_lasterr, "failed to find wr_id %d\n", (int)wc->wr_id);
				return -1;
		}
		if (p->ref_cnt) {
			p->ref_cnt--;
		} else {
			ibw_free_mr(&p->buf_large, &p->mr_large);
			DLIST_REMOVE(pconn->extra_sent, p);
			DLIST_ADD(pconn->extra_avail, p);
		}
	}

	return ibw_process_queue(conn);
}

static int ibw_append_to_part(struct ibw_conn_priv *pconn,
	struct ibw_part *part, char **pp, uint32_t add_len, int info)
{
	DEBUG(DEBUG_DEBUG, ("ibw_append_to_part: cmid=%p, (bs=%u, len=%u, tr=%u), al=%u, i=%u\n",
		pconn->cm_id, part->bufsize, part->len, part->to_read, add_len, info));

	/* allocate more if necessary - it's an "evergrowing" buffer... */
	if (part->len + add_len > part->bufsize) {
		if (part->buf==NULL) {
			assert(part->len==0);
			part->buf = talloc_size(pconn, add_len);
			if (part->buf==NULL) {
				sprintf(ibw_lasterr, "recv talloc_size error (%u) #%d\n",
					add_len, info);
				return -1;
			}
			part->bufsize = add_len;
		} else {
			part->buf = talloc_realloc_size(pconn,
				part->buf, part->len + add_len);
			if (part->buf==NULL) {
				sprintf(ibw_lasterr, "recv realloc error (%u + %u) #%d\n",
					part->len, add_len, info);
				return -1;
			}
		}
		part->bufsize = part->len + add_len;
	}

	/* consume pp */
	memcpy(part->buf + part->len, *pp, add_len);
	*pp += add_len;
	part->len += add_len;
	part->to_read -= add_len;

	return 0;
}

static int ibw_wc_mem_threshold(struct ibw_conn_priv *pconn,
	struct ibw_part *part, uint32_t threshold)
{
	DEBUG(DEBUG_DEBUG, ("ibw_wc_mem_threshold: cmid=%p, (bs=%u, len=%u, tr=%u), thr=%u\n",
		pconn->cm_id, part->bufsize, part->len, part->to_read, threshold));

	if (part->bufsize > threshold) {
		DEBUG(DEBUG_DEBUG, ("ibw_wc_mem_threshold: cmid=%p, %u > %u\n",
			pconn->cm_id, part->bufsize, threshold));
		talloc_free(part->buf);
		part->buf = talloc_size(pconn, threshold);
		if (part->buf==NULL) {
			sprintf(ibw_lasterr, "talloc_size failed\n");
			return -1;
		}
		part->bufsize = threshold;
	}
	return 0;
}

static int ibw_wc_recv(struct ibw_conn *conn, struct ibv_wc *wc)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_part	*part = &pconn->part;
	char	*p;
	uint32_t	remain = wc->byte_len;

	DEBUG(DEBUG_DEBUG, ("ibw_wc_recv: cmid=%p, wr_id: %u, bl: %u\n",
		pconn->cm_id, (uint32_t)wc->wr_id, remain));

	assert(pconn->cm_id->qp->qp_num==wc->qp_num);
	assert((int)wc->wr_id < pctx->opts.max_recv_wr);
	assert(wc->byte_len <= pctx->opts.recv_bufsize);

	p = pconn->buf_recv + ((int)wc->wr_id * pctx->opts.recv_bufsize);

	while(remain) {
		/* here always true: (part->len!=0 && part->to_read!=0) ||
			(part->len==0 && part->to_read==0) */
		if (part->len) { /* is there a partial msg to be continued? */
			int read_len = (part->to_read<=remain) ? part->to_read : remain;
			if (ibw_append_to_part(pconn, part, &p, read_len, 421))
				goto error;
			remain -= read_len;

			if (part->len<=sizeof(uint32_t) && part->to_read==0) {
				assert(part->len==sizeof(uint32_t));
				/* set it again now... */
				part->to_read = *((uint32_t *)(part->buf)); /* TODO: ntohl */
				if (part->to_read<sizeof(uint32_t)) {
					sprintf(ibw_lasterr, "got msglen=%u #2\n", part->to_read);
					goto error;
				}
				part->to_read -= sizeof(uint32_t); /* it's already read */
			}

			if (part->to_read==0) {
				if (pctx->receive_func(conn, part->buf, part->len) != 0) {
					goto error;
				}
				part->len = 0; /* tells not having partial data (any more) */
				if (ibw_wc_mem_threshold(pconn, part, pctx->opts.recv_threshold))
					goto error;
			}
		} else {
			if (remain>=sizeof(uint32_t)) {
				uint32_t msglen = *(uint32_t *)p; /* TODO: ntohl */
				if (msglen<sizeof(uint32_t)) {
					sprintf(ibw_lasterr, "got msglen=%u\n", msglen);
					goto error;
				}

				/* mostly awaited case: */
				if (msglen<=remain) {
					if (pctx->receive_func(conn, p, msglen) != 0) {
						goto error;
					}
					p += msglen;
					remain -= msglen;
				} else {
					part->to_read = msglen;
					/* part->len is already 0 */
					if (ibw_append_to_part(pconn, part, &p, remain, 422))
						goto error;
					remain = 0; /* to be continued ... */
					/* part->to_read > 0 here */
				}
			} else { /* edge case: */
				part->to_read = sizeof(uint32_t);
				/* part->len is already 0 */
				if (ibw_append_to_part(pconn, part, &p, remain, 423))
					goto error;
				remain = 0;
				/* part->to_read > 0 here */
			}
		}
	} /* <remain> is always decreased at least by 1 */

	if (ibw_refill_cq_recv(conn))
		goto error;

	return 0;

error:
	DEBUG(DEBUG_ERR, ("ibw_wc_recv error: %s", ibw_lasterr));
	return -1;
}

static int ibw_process_init_attrs(struct ibw_initattr *attr, int nattr, struct ibw_opts *opts)
{
	int	i;
	const char *name, *value;

	DEBUG(DEBUG_DEBUG, ("ibw_process_init_attrs: nattr: %d\n", nattr));

	opts->max_send_wr = IBW_MAX_SEND_WR;
	opts->max_recv_wr = IBW_MAX_RECV_WR;
	opts->recv_bufsize = IBW_RECV_BUFSIZE;
	opts->recv_threshold = IBW_RECV_THRESHOLD;

	for(i=0; i<nattr; i++) {
		name = attr[i].name;
		value = attr[i].value;

		assert(name!=NULL && value!=NULL);
		if (strcmp(name, "max_send_wr")==0)
			opts->max_send_wr = atoi(value);
		else if (strcmp(name, "max_recv_wr")==0)
			opts->max_recv_wr = atoi(value);
		else if (strcmp(name, "recv_bufsize")==0)
			opts->recv_bufsize = atoi(value);
		else if (strcmp(name, "recv_threshold")==0)
			opts->recv_threshold = atoi(value);
		else {
			sprintf(ibw_lasterr, "ibw_init: unknown name %s\n", name);
			return -1;
		}
	}
	return 0;
}

struct ibw_ctx *ibw_init(struct ibw_initattr *attr, int nattr,
	void *ctx_userdata,
	ibw_connstate_fn_t ibw_connstate,
	ibw_receive_fn_t ibw_receive,
	struct event_context *ectx)
{
	struct ibw_ctx *ctx = talloc_zero(NULL, struct ibw_ctx);
	struct ibw_ctx_priv *pctx;
	int	rc;

	DEBUG(DEBUG_DEBUG, ("ibw_init(ctx_userdata: %p, ectx: %p)\n", ctx_userdata, ectx));

	/* initialize basic data structures */
	memset(ibw_lasterr, 0, IBW_LASTERR_BUFSIZE);

	assert(ctx!=NULL);
	ibw_lasterr[0] = '\0';
	talloc_set_destructor(ctx, ibw_ctx_destruct);
	ctx->ctx_userdata = ctx_userdata;

	pctx = talloc_zero(ctx, struct ibw_ctx_priv);
	talloc_set_destructor(pctx, ibw_ctx_priv_destruct);
	ctx->internal = (void *)pctx;
	assert(pctx!=NULL);

	pctx->connstate_func = ibw_connstate;
	pctx->receive_func = ibw_receive;

	pctx->ectx = ectx;

	/* process attributes */
	if (ibw_process_init_attrs(attr, nattr, &pctx->opts))
		goto cleanup;

	/* init cm */
	pctx->cm_channel = rdma_create_event_channel();
	if (!pctx->cm_channel) {
		sprintf(ibw_lasterr, "rdma_create_event_channel error %d\n", errno);
		goto cleanup;
	}

	pctx->cm_channel_event = event_add_fd(pctx->ectx, pctx,
		pctx->cm_channel->fd, EVENT_FD_READ, ibw_event_handler_cm, ctx);

#if RDMA_USER_CM_MAX_ABI_VERSION >= 2
	rc = rdma_create_id(pctx->cm_channel, &pctx->cm_id, ctx, RDMA_PS_TCP);
#else
	rc = rdma_create_id(pctx->cm_channel, &pctx->cm_id, ctx);
#endif
	if (rc) {
		rc = errno;
		sprintf(ibw_lasterr, "rdma_create_id error %d\n", rc);
		goto cleanup;
	}
	DEBUG(DEBUG_DEBUG, ("created cm_id %p\n", pctx->cm_id));

	pctx->pagesize = sysconf(_SC_PAGESIZE);

	return ctx;
	/* don't put code here */
cleanup:
	DEBUG(DEBUG_ERR, (ibw_lasterr));

	if (ctx)
		talloc_free(ctx);

	return NULL;
}

int ibw_stop(struct ibw_ctx *ctx)
{
	struct ibw_ctx_priv *pctx = (struct ibw_ctx_priv *)ctx->internal;
	struct ibw_conn *p;

	DEBUG(DEBUG_DEBUG, ("ibw_stop\n"));

	for(p=ctx->conn_list; p!=NULL; p=p->next) {
		if (p->state==IBWC_ERROR || p->state==IBWC_CONNECTED) {
			if (ibw_disconnect(p))
				return -1;
		}
	}

	ctx->state = IBWS_STOPPED;
	pctx->connstate_func(ctx, NULL);

	return 0;
}

int ibw_bind(struct ibw_ctx *ctx, struct sockaddr_in *my_addr)
{
	struct ibw_ctx_priv *pctx = (struct ibw_ctx_priv *)ctx->internal;
	int	rc;

	DEBUG(DEBUG_DEBUG, ("ibw_bind: addr=%s, port=%u\n",
		inet_ntoa(my_addr->sin_addr), ntohs(my_addr->sin_port)));
	rc = rdma_bind_addr(pctx->cm_id, (struct sockaddr *) my_addr);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_bind_addr error %d\n", rc);
		DEBUG(DEBUG_ERR, (ibw_lasterr));
		return rc;
	}
	DEBUG(DEBUG_DEBUG, ("rdma_bind_addr successful\n"));

	return 0;
}

int ibw_listen(struct ibw_ctx *ctx, int backlog)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(ctx->internal, struct ibw_ctx_priv);
	int	rc;

	DEBUG(DEBUG_DEBUG, ("ibw_listen\n"));
	rc = rdma_listen(pctx->cm_id, backlog);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_listen failed: %d\n", rc);
		DEBUG(DEBUG_ERR, (ibw_lasterr));
		return rc;
	}

	return 0;
}

int ibw_accept(struct ibw_ctx *ctx, struct ibw_conn *conn, void *conn_userdata)
{
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct rdma_conn_param	conn_param;
	int	rc;

	DEBUG(DEBUG_DEBUG, ("ibw_accept: cmid=%p\n", pconn->cm_id));
	conn->conn_userdata = conn_userdata;

	memset(&conn_param, 0, sizeof(struct rdma_conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	rc = rdma_accept(pconn->cm_id, &conn_param);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_accept failed %d\n", rc);
		DEBUG(DEBUG_ERR, (ibw_lasterr));
		return -1;;
	}

	pconn->is_accepted = 1;

	/* continued at RDMA_CM_EVENT_ESTABLISHED */

	return 0;
}

int ibw_connect(struct ibw_conn *conn, struct sockaddr_in *serv_addr, void *conn_userdata)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = NULL;
	int	rc;

	assert(conn!=NULL);

	conn->conn_userdata = conn_userdata;
	pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	DEBUG(DEBUG_DEBUG, ("ibw_connect: addr=%s, port=%u\n", inet_ntoa(serv_addr->sin_addr),
		ntohs(serv_addr->sin_port)));

	/* clean previous - probably half - initialization */
	if (ibw_conn_priv_destruct(pconn)) {
		DEBUG(DEBUG_ERR, ("ibw_connect/ibw_pconn_destruct failed for cm_id=%p\n", pconn->cm_id));
		return -1;
	}

	/* init cm */
#if RDMA_USER_CM_MAX_ABI_VERSION >= 2
	rc = rdma_create_id(pctx->cm_channel, &pconn->cm_id, conn, RDMA_PS_TCP);
#else
	rc = rdma_create_id(pctx->cm_channel, &pconn->cm_id, conn);
#endif
	if (rc) {
		rc = errno;
		sprintf(ibw_lasterr, "ibw_connect/rdma_create_id error %d\n", rc);
		talloc_free(conn);
		return -1;
	}
	DEBUG(DEBUG_DEBUG, ("ibw_connect: rdma_create_id succeeded, cm_id=%p\n", pconn->cm_id));

	rc = rdma_resolve_addr(pconn->cm_id, NULL, (struct sockaddr *) serv_addr, 2000);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_resolve_addr error %d\n", rc);
		DEBUG(DEBUG_ERR, (ibw_lasterr));
		talloc_free(conn);
		return -1;
	}

	/* continued at RDMA_CM_EVENT_ADDR_RESOLVED */

	return 0;
}

int ibw_disconnect(struct ibw_conn *conn)
{
	int	rc;
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);

	DEBUG(DEBUG_DEBUG, ("ibw_disconnect: cmid=%p\n", pconn->cm_id));

	assert(pconn!=NULL);

	switch(conn->state) {
	case IBWC_ERROR:
		ibw_conn_priv_destruct(pconn); /* do this here right now */
		break;
	case IBWC_CONNECTED:
		rc = rdma_disconnect(pconn->cm_id);
		if (rc) {
			sprintf(ibw_lasterr, "ibw_disconnect failed with %d\n", rc);
			DEBUG(DEBUG_ERR, (ibw_lasterr));
			return rc;
		}
		break;
	default:
		DEBUG(DEBUG_DEBUG, ("invalid state for disconnect: %d\n", conn->state));
		break;
	}

	return 0;
}

int ibw_alloc_send_buf(struct ibw_conn *conn, void **buf, void **key, uint32_t len)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_wr *p = pconn->wr_list_avail;

	if (p!=NULL) {
		DEBUG(DEBUG_DEBUG, ("ibw_alloc_send_buf#1: cmid=%p, len=%d\n", pconn->cm_id, len));

		DLIST_REMOVE(pconn->wr_list_avail, p);
		DLIST_ADD(pconn->wr_list_used, p);

		if (len <= pctx->opts.recv_bufsize) {
			*buf = (void *)p->buf;
		} else {
			p->buf_large = ibw_alloc_mr(pctx, pconn, len, &p->mr_large);
			if (p->buf_large==NULL) {
				sprintf(ibw_lasterr, "ibw_alloc_mr#1 failed\n");
				goto error;
			}
			*buf = (void *)p->buf_large;
		}
		/* p->wr_id is already filled in ibw_init_memory */
	} else {
		DEBUG(DEBUG_DEBUG, ("ibw_alloc_send_buf#2: cmid=%p, len=%d\n", pconn->cm_id, len));
		/* not optimized */
		p = pconn->extra_avail;
		if (!p) {
			p = pconn->extra_avail = talloc_zero(pconn, struct ibw_wr);
			talloc_set_destructor(p, ibw_wr_destruct);
			if (p==NULL) {
				sprintf(ibw_lasterr, "talloc_zero failed (emax: %u)\n", pconn->extra_max);
				goto error;
			}
			p->wr_id = pctx->opts.max_send_wr + pconn->extra_max;
			pconn->extra_max++;
			switch(pconn->extra_max) {
				case 1: DEBUG(DEBUG_INFO, ("warning: queue performed\n")); break;
				case 10: DEBUG(DEBUG_INFO, ("warning: queue reached 10\n")); break;
				case 100: DEBUG(DEBUG_INFO, ("warning: queue reached 100\n")); break;
				case 1000: DEBUG(DEBUG_INFO, ("warning: queue reached 1000\n")); break;
				default: break;
			}
		}

		p->buf_large = ibw_alloc_mr(pctx, pconn, len, &p->mr_large);
		if (p->buf_large==NULL) {
			sprintf(ibw_lasterr, "ibw_alloc_mr#2 failed\n");
			goto error;
		}
		*buf = (void *)p->buf_large;

		DLIST_REMOVE(pconn->extra_avail, p);
		/* we don't have prepared index for this, so that
		 * we will have to find this by wr_id later on */
		DLIST_ADD(pconn->extra_sent, p);
	}

	*key = (void *)p;

	return 0;
error:
	DEBUG(DEBUG_ERR, ("ibw_alloc_send_buf error: %s", ibw_lasterr));
	return -1;
}


static int ibw_send_packet(struct ibw_conn *conn, void *buf, struct ibw_wr *p, uint32_t len)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	int	rc;

	/* can we send it right now? */
	if (pconn->wr_sent<pctx->opts.max_send_wr) {
		struct ibv_send_wr *bad_wr;
		struct ibv_sge list = {
			.addr 	= (uintptr_t)buf,
			.length = len,
			.lkey 	= pconn->mr_send->lkey
		};
		struct ibv_send_wr wr = {
			.wr_id 	    = p->wr_id + pctx->opts.max_recv_wr,
			.sg_list    = &list,
			.num_sge    = 1,
			.opcode     = IBV_WR_SEND,
			.send_flags = IBV_SEND_SIGNALED,
		};

		if (p->buf_large==NULL) {
			DEBUG(DEBUG_DEBUG, ("ibw_send#normal(cmid: %p, wrid: %u, n: %d)\n",
				pconn->cm_id, (uint32_t)wr.wr_id, len));
		} else {
			DEBUG(DEBUG_DEBUG, ("ibw_send#large(cmid: %p, wrid: %u, n: %d)\n",
				pconn->cm_id, (uint32_t)wr.wr_id, len));
			list.lkey = p->mr_large->lkey;
		}

		rc = ibv_post_send(pconn->cm_id->qp, &wr, &bad_wr);
		if (rc) {
			sprintf(ibw_lasterr, "ibv_post_send error %d (%d)\n",
				rc, pconn->wr_sent);
			goto error;
		}

		pconn->wr_sent++;

		return rc;
	} /* else put the request into our own queue: */

	DEBUG(DEBUG_DEBUG, ("ibw_send#queued(cmid: %p, len: %u)\n", pconn->cm_id, len));

	/* TODO: clarify how to continue when state==IBWC_STOPPED */

	/* to be sent by ibw_wc_send */
	/* regardless "normal" or [a part of] "large" packet */
	if (!p->queued_ref_cnt) {
		DLIST_ADD_END2(pconn->queue, p, struct ibw_wr *,
			qprev, qnext); /* TODO: optimize */
		p->queued_msg = buf;
	}
	p->queued_ref_cnt++;
	p->queued_rlen = len; /* last wins; see ibw_wc_send */

	return 0;
error:
	DEBUG(DEBUG_ERR, (ibw_lasterr));
	return -1;
}

int ibw_send(struct ibw_conn *conn, void *buf, void *key, uint32_t len)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_wr *p = talloc_get_type(key, struct ibw_wr);
	int	rc;

	assert(len>=sizeof(uint32_t));
	assert((*((uint32_t *)buf)==len)); /* TODO: htonl */

	if (len > pctx->opts.recv_bufsize) {
		struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
		int	rlen = len;
		char	*packet = (char *)buf;
		uint32_t	recv_bufsize = pctx->opts.recv_bufsize;

		DEBUG(DEBUG_DEBUG, ("ibw_send#frag(cmid: %p, buf: %p, len: %u)\n",
			pconn->cm_id, buf, len));

		/* single threaded => no race here: */
		assert(p->ref_cnt==0);
		while(rlen > recv_bufsize) {
			rc = ibw_send_packet(conn, packet, p, recv_bufsize);
			if (rc)
				return rc;
			packet += recv_bufsize;
			rlen -= recv_bufsize;
			p->ref_cnt++; /* not good to have it in ibw_send_packet */
		}
		if (rlen) {
			rc = ibw_send_packet(conn, packet, p, rlen);
			p->ref_cnt++; /* not good to have it in ibw_send_packet */
		}
		p->ref_cnt--; /* for the same handling */
	} else {
		assert(p->ref_cnt==0);
		assert(p->queued_ref_cnt==0);

		rc = ibw_send_packet(conn, buf, p, len);
	}
	return rc;
}

int ibw_cancel_send_buf(struct ibw_conn *conn, void *buf, void *key)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_wr *p = talloc_get_type(key, struct ibw_wr);

	assert(p!=NULL);
	assert(buf!=NULL);
	assert(conn!=NULL);

	if (p->buf_large!=NULL)
		ibw_free_mr(&p->buf_large, &p->mr_large);

	/* parallel case */
	if (p->wr_id < pctx->opts.max_send_wr) {
		DEBUG(DEBUG_DEBUG, ("ibw_cancel_send_buf#1 %u", (int)p->wr_id));
		DLIST_REMOVE(pconn->wr_list_used, p);
		DLIST_ADD(pconn->wr_list_avail, p);
	} else { /* "extra" packet */
		DEBUG(DEBUG_DEBUG, ("ibw_cancel_send_buf#2 %u", (int)p->wr_id));
		DLIST_REMOVE(pconn->extra_sent, p);
		DLIST_ADD(pconn->extra_avail, p);
	}

	return 0;
}

const char *ibw_getLastError(void)
{
	return ibw_lasterr;
}
