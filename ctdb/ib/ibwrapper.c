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
#include "lib/events/events.h"
#include "ibwrapper.h"

#include <rdma/rdma_cma.h>

#include "ibwrapper_internal.h"
#include "lib/util/dlinklist.h"

#define IBW_LASTERR_BUFSIZE 512
static char ibw_lasterr[IBW_LASTERR_BUFSIZE];

static void ibw_event_handler_verbs(struct event_context *ev,
	struct fd_event *fde, uint16_t flags, void *private_data);
static int ibw_fill_cq(struct ibw_conn *conn);
static inline int ibw_wc_recv(struct ibw_conn *conn, struct ibv_wc *wc);
static inline int ibw_wc_send(struct ibw_conn *conn, struct ibv_wc *wc);

static void *ibw_alloc_mr(struct ibw_ctx_priv *pctx, struct ibw_conn_priv *pconn,
	uint32_t n, struct ibv_mr **ppmr)
{
	void *buf;

	DEBUG(10, ("ibw_alloc_mr(cmid=%u, n=%u)\n", (uint32_t)pconn->cm_id, n));
	buf = memalign(pctx->pagesize, n);
	if (!buf) {
		sprintf(ibw_lasterr, "couldn't allocate memory\n");
		return NULL;
	}

	*ppmr = ibv_reg_mr(pctx->pd, buf, n, IBV_ACCESS_LOCAL_WRITE);
	if (!*ppmr) {
		sprintf(ibw_lasterr, "couldn't allocate mr\n");
		free(buf);
		return NULL;
	}

	return buf;
}

static void ibw_free_mr(char **ppbuf, struct ibv_mr **ppmr)
{
	DEBUG(10, ("ibw_free_mr(%u %u)\n", (uint32_t)*ppbuf, (uint32_t)*ppmr));
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

	DEBUG(10, ("ibw_init_memory(cmid: %u)\n", (uint32_t)pconn->cm_id));
	pconn->buf_send = ibw_alloc_mr(pctx, pconn,
		opts->max_send_wr * opts->avg_send_size, &pconn->mr_send);
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
		p->msg = pconn->buf_send + (i * opts->avg_send_size);
		p->wr_id = i + opts->max_recv_wr;

		DLIST_ADD(pconn->wr_list_avail, p);
	}

	return 0;
}

static int ibw_ctx_priv_destruct(struct ibw_ctx_priv *pctx)
{
	DEBUG(10, ("ibw_ctx_priv_destruct(%u)\n", (uint32_t)pctx));

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

	return 0;
}

static int ibw_ctx_destruct(struct ibw_ctx *ctx)
{
	DEBUG(10, ("ibw_ctx_destruct(%u)\n", (uint32_t)ctx));
	return 0;
}

static int ibw_conn_priv_destruct(struct ibw_conn_priv *pconn)
{
	DEBUG(10, ("ibw_conn_priv_destruct(%u, cmid: %u)\n",
		(uint32_t)pconn, (uint32_t)pconn->cm_id));

	/* free memory regions */
	ibw_free_mr(&pconn->buf_send, &pconn->mr_send);
	ibw_free_mr(&pconn->buf_recv, &pconn->mr_recv);

	/* pconn->wr_index is freed by talloc */
	/* pconn->wr_index[i] are freed by talloc */

	/* destroy verbs */
	if (pconn->cm_id->qp) {
		ibv_destroy_qp(pconn->cm_id->qp);
		pconn->cm_id->qp = NULL;
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
		rdma_destroy_id(pconn->cm_id);
		pconn->cm_id = NULL;
	}
	return 0;
}

static int ibw_conn_destruct(struct ibw_conn *conn)
{
	DEBUG(10, ("ibw_conn_destruct(%u)\n", (uint32_t)conn));
	
	/* important here: ctx is a talloc _parent_ */
	DLIST_REMOVE(conn->ctx->conn_list, conn);
	return 0;
}

static struct ibw_conn *ibw_conn_new(struct ibw_ctx *ctx)
{
	struct ibw_conn *conn;
	struct ibw_conn_priv *pconn;

	conn = talloc_zero(ctx, struct ibw_conn);
	assert(conn!=NULL);
	talloc_set_destructor(conn, ibw_conn_destruct);

	pconn = talloc_zero(ctx, struct ibw_conn_priv);
	assert(pconn!=NULL);
	talloc_set_destructor(pconn, ibw_conn_priv_destruct);

	conn->ctx = ctx;

	DLIST_ADD(ctx->conn_list, conn);

	return conn;
}

static int ibw_setup_cq_qp(struct ibw_conn *conn)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibv_qp_init_attr init_attr;
	int rc;

	DEBUG(10, ("ibw_setup_cq_qp(cmid: %u)\n", (uint32_t)pconn->cm_id));

	/* init mr */
	if (ibw_init_memory(conn))
		return -1;

	/* init verbs */
	pconn->verbs_channel = ibv_create_comp_channel(pconn->cm_id->verbs);
	if (!pconn->verbs_channel) {
		sprintf(ibw_lasterr, "ibv_create_comp_channel failed %d\n", errno);
		return -1;
	}
	DEBUG(10, ("created channel %p\n", pconn->verbs_channel));

	pconn->verbs_channel_event = event_add_fd(pctx->ectx, conn,
		pconn->verbs_channel->fd, EVENT_FD_READ, ibw_event_handler_verbs, conn);

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

	rc = rdma_create_qp(pconn->cm_id, pctx->pd, &init_attr);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_create_qp failed with %d\n", rc);
		return rc;
	}
	/* elase result is in pconn->cm_id->qp */

	return ibw_fill_cq(conn);
}

static int ibw_refill_cq_recv(struct ibw_conn *conn)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	int	rc;
	struct ibv_sge list = {
		.addr 	= (uintptr_t) NULL,
		.length = pctx->opts.recv_bufsize,
		.lkey 	= pconn->mr_recv->lkey
	};
	struct ibv_recv_wr wr = {
		.wr_id 	    = 0,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ibv_recv_wr *bad_wr;

	DEBUG(10, ("ibw_refill_cq_recv(cmid: %u)\n", (uint32_t)pconn->cm_id));

	list.addr = (uintptr_t) pconn->buf_recv + pctx->opts.recv_bufsize * pconn->recv_index;
	wr.wr_id = pconn->recv_index;
	pconn->recv_index = (pconn->recv_index + 1) % pctx->opts.max_recv_wr;

	rc = ibv_post_recv(pconn->cm_id->qp, &wr, &bad_wr);
	if (rc) {
		sprintf(ibw_lasterr, "ibv_post_recv failed with %d\n", rc);
		DEBUG(0, (ibw_lasterr));
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
		.addr 	= (uintptr_t) NULL,
		.length = pctx->opts.recv_bufsize,
		.lkey 	= pconn->mr_recv->lkey
	};
	struct ibv_recv_wr wr = {
		.wr_id 	    = 0,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ibv_recv_wr *bad_wr;

	DEBUG(10, ("ibw_fill_cq(cmid: %u)\n", (uint32_t)pconn->cm_id));

	for(i = pctx->opts.max_recv_wr; i!=0; i--) {
		list.addr = (uintptr_t) pconn->buf_recv + pctx->opts.recv_bufsize * pconn->recv_index;
		wr.wr_id = pconn->recv_index;
		pconn->recv_index = (pconn->recv_index + 1) % pctx->opts.max_recv_wr;

		rc = ibv_post_recv(pconn->cm_id->qp, &wr, &bad_wr);
		if (rc) {
			sprintf(ibw_lasterr, "ibv_post_recv failed with %d\n", rc);
			DEBUG(0, (ibw_lasterr));
			return -2;
		}
	}

	return 0;
}

static int ibw_manage_connect(struct ibw_conn *conn, struct rdma_cm_id *cma_id)
{
	struct rdma_conn_param conn_param;
	int	rc;

	DEBUG(10, ("ibw_manage_connect(cmid: %u)", (uint32_t)cma_id));
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
		sprintf(ibw_lasterr, "rdma_get_cm_event error %d\n", rc);
		goto error;
	}
	cma_id = event->id;

	DEBUG(10, ("cma_event type %d cma_id %p (%s)\n", event->event, cma_id,
		  (cma_id == pctx->cm_id) ? "parent" : "child"));

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		/* continuing from ibw_connect ... */
		rc = rdma_resolve_route(cma_id, 2000);
		if (rc) {
			sprintf(ibw_lasterr, "rdma_resolve_route error %d\n", rc);
			goto error;
		}
		/* continued at RDMA_CM_EVENT_ROUTE_RESOLVED */
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		/* after RDMA_CM_EVENT_ADDR_RESOLVED: */
		assert(cma_id->context!=NULL);
		conn = talloc_get_type(cma_id->context, struct ibw_conn);

		rc = ibw_manage_connect(conn, cma_id);
		if (rc)
			goto error;

		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ctx->state = IBWS_CONNECT_REQUEST;
		conn = ibw_conn_new(ctx);
		pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
		pconn->cm_id = cma_id; /* !!! event will be freed but id not */
		cma_id->context = (void *)conn;
		DEBUG(10, ("pconn->cm_id %p\n", pconn->cm_id));

		conn->state = IBWC_INIT;
		pctx->connstate_func(ctx, conn);

		/* continued at ibw_accept when invoked by the func above */
		if (!pconn->is_accepted) {
			talloc_free(conn);
			DEBUG(10, ("pconn->cm_id %p wasn't accepted\n", pconn->cm_id));
		} else {
			if (ibw_setup_cq_qp(conn))
				goto error;
		}

		/* TODO: clarify whether if it's needed by upper layer: */
		ctx->state = IBWS_READY;
		pctx->connstate_func(ctx, NULL);

		/* NOTE: more requests can arrive until RDMA_CM_EVENT_ESTABLISHED ! */
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		/* expected after ibw_accept and ibw_connect[not directly] */
		DEBUG(0, ("ESTABLISHED (conn: %u)\n", (unsigned int)cma_id->context));
		conn = talloc_get_type(cma_id->context, struct ibw_conn);
		assert(conn!=NULL); /* important assumption */

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
		if (cma_id!=pctx->cm_id) {
			DEBUG(0, ("client DISCONNECT event\n"));
			conn = talloc_get_type(cma_id->context, struct ibw_conn);
			conn->state = IBWC_DISCONNECTED;
			pctx->connstate_func(NULL, conn);

			talloc_free(conn);

			/* if we are the last... */
			if (ctx->conn_list==NULL)
				rdma_disconnect(pctx->cm_id);
		} else {
			DEBUG(0, ("server DISCONNECT event\n"));
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
		sprintf(ibw_lasterr, "rdma_ack_cm_event failed with %d\n", rc);
		goto error;
	}

	return;
error:
	DEBUG(0, ("cm event handler: %s", ibw_lasterr));
	if (cma_id!=pctx->cm_id) {
		conn = talloc_get_type(cma_id->context, struct ibw_conn);
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
	struct ibw_conn	*conn = talloc_get_type(private_data, struct ibw_conn);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);

	struct ibv_wc wc;
	int rc;
	struct ibv_cq *ev_cq;
	void          *ev_ctx;

	DEBUG(10, ("ibw_event_handler_verbs(%u)\n", (uint32_t)flags));

	/* TODO: check whether if it's good to have more channels here... */
	rc = ibv_get_cq_event(pconn->verbs_channel, &ev_cq, &ev_ctx);
	if (rc) {
		sprintf(ibw_lasterr, "Failed to get cq_event with %d\n", rc);
		goto error;
	}
	if (ev_cq != pconn->cq) {
		sprintf(ibw_lasterr, "ev_cq(%u) != pconn->cq(%u)\n",
			(unsigned int)ev_cq, (unsigned int)pconn->cq);
		goto error;
	}
	rc = ibv_req_notify_cq(pconn->cq, 0);
	if (rc) {
		sprintf(ibw_lasterr, "Couldn't request CQ notification (%d)\n", rc);
		goto error;
	}

	while((rc=ibv_poll_cq(pconn->cq, 1, &wc))==1) {
		if (wc.status) {
			sprintf(ibw_lasterr, "cq completion failed status %d\n",
				wc.status);
			goto error;
		}

		switch(wc.opcode) {
		case IBV_WC_SEND:
			DEBUG(10, ("send completion\n"));
			if (ibw_wc_send(conn, &wc))
				goto error;
			break;

		case IBV_WC_RDMA_WRITE:
			DEBUG(10, ("rdma write completion\n"));
			break;
	
		case IBV_WC_RDMA_READ:
			DEBUG(10, ("rdma read completion\n"));
			break;

		case IBV_WC_RECV:
			DEBUG(10, ("recv completion\n"));
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

	return;
error:
	DEBUG(0, (ibw_lasterr));
	conn->state = IBWC_ERROR;
	pctx->connstate_func(NULL, conn);
}

static inline int ibw_wc_send(struct ibw_conn *conn, struct ibv_wc *wc)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_wr	*p;
	int	send_index;

	DEBUG(10, ("ibw_wc_send(cmid: %u, wr_id: %u, bl: %u)\n",
		(uint32_t)pconn->cm_id, (uint32_t)wc->wr_id, (uint32_t)wc->byte_len));

	assert(pconn->cm_id->qp->qp_num==wc->qp_num);
	assert(wc->wr_id > pctx->opts.max_recv_wr);
	send_index = wc->wr_id - pctx->opts.max_recv_wr;
	pconn->wr_sent--;

	if (send_index < pctx->opts.max_send_wr) {
		DEBUG(10, ("ibw_wc_send#1 %u", (int)wc->wr_id));
		p = pconn->wr_index[send_index];
		if (p->msg_large)
			ibw_free_mr(&p->msg_large, &p->mr_large);
		DLIST_REMOVE(pconn->wr_list_used, p);
		DLIST_ADD(pconn->wr_list_avail, p);
	} else { /* "extra" request - not optimized */
		DEBUG(10, ("ibw_wc_send#2 %u", (int)wc->wr_id));
		for(p=pconn->extra_sent; p!=NULL; p=p->next)
			if (p->wr_id==(int)wc->wr_id)
				break;
		if (p==NULL) {
			sprintf(ibw_lasterr, "failed to find wr_id %d\n", (int)wc->wr_id);
				return -1;
		}
		ibw_free_mr(&p->msg_large, &p->mr_large);
		DLIST_REMOVE(pconn->extra_sent, p);
		DLIST_ADD(pconn->extra_avail, p);
	}

	if (pconn->queue) {
		char	*buf;

		DEBUG(10, ("ibw_wc_send#queue %u", (int)wc->wr_id));
		p = pconn->queue;
		DLIST_REMOVE(pconn->queue, p);

		buf = (p->msg_large!=NULL) ? p->msg_large : p->msg;
		ibw_send(conn, buf, p, ntohl(*(uint32_t *)buf));
	}

	return 0;
}

static inline int ibw_append_to_part(struct ibw_conn_priv *pconn,
	struct ibw_part *part, char **pp, uint32_t add_len, int info)
{
	DEBUG(10, ("ibw_append_to_part: cmid=%u, (bs=%u, len=%u, tr=%u), al=%u, i=%u\n",
		(uint32_t)pconn->cm_id, part->bufsize, part->len, part->to_read, add_len, info));

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

static inline int ibw_wc_mem_threshold(struct ibw_conn_priv *pconn,
	struct ibw_part *part, uint32_t threshold)
{
	DEBUG(10, ("ibw_wc_mem_threshold: cmid=%u, (bs=%u, len=%u, tr=%u), thr=%u\n",
		(uint32_t)pconn->cm_id, part->bufsize, part->len, part->to_read, threshold));

	if (part->bufsize > threshold) {
		DEBUG(3, ("ibw_wc_mem_threshold: cmid=%u, %u > %u\n",
			(uint32_t)pconn->cm_id, part->bufsize, threshold));
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

static inline int ibw_wc_recv(struct ibw_conn *conn, struct ibv_wc *wc)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_part	*part = &pconn->part;
	char	*p;
	uint32_t	remain = wc->byte_len;

	DEBUG(10, ("ibw_wc_recv: cmid=%u, wr_id: %u, bl: %u\n",
		(uint32_t)pconn->cm_id, (uint32_t)wc->wr_id, remain));

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
				part->to_read = ntohl(*((uint32_t *)(part->buf)));
				if (part->to_read<sizeof(uint32_t)) {
					sprintf(ibw_lasterr, "got msglen=%u #2\n", part->to_read);
					goto error;
				}
				part->to_read -= sizeof(uint32_t); /* it's already read */
			}

			if (part->to_read==0) {
				pctx->receive_func(conn, part->buf, part->len);
				part->len = 0; /* tells not having partial data (any more) */
				if (ibw_wc_mem_threshold(pconn, part, pctx->opts.recv_threshold))
					goto error;
			}
		} else {
			if (remain>=sizeof(uint32_t)) {
				uint32_t msglen = ntohl(*(uint32_t *)p);
				if (msglen<sizeof(uint32_t)) {
					sprintf(ibw_lasterr, "got msglen=%u\n", msglen);
					goto error;
				}

				/* mostly awaited case: */
				if (msglen<=remain) {
					pctx->receive_func(conn, p, msglen);
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
	DEBUG(0, ("ibw_wc_recv error: %s", ibw_lasterr));
	return -1;
}

static int ibw_process_init_attrs(struct ibw_initattr *attr, int nattr, struct ibw_opts *opts)
{
	int	i;
	const char *name, *value;

	DEBUG(10, ("ibw_process_init_attrs: nattr: %d\n", nattr));

	opts->max_send_wr = 256;
	opts->max_recv_wr = 1024;
	opts->avg_send_size = 1024;
	opts->recv_bufsize = 256;
	opts->recv_threshold = 1 * 1024 * 1024;

	for(i=0; i<nattr; i++) {
		name = attr[i].name;
		value = attr[i].value;

		assert(name!=NULL && value!=NULL);
		if (strcmp(name, "max_send_wr")==0)
			opts->max_send_wr = atoi(value);
		else if (strcmp(name, "max_recv_wr")==0)
			opts->max_recv_wr = atoi(value);
		else if (strcmp(name, "avg_send_size")==0)
			opts->avg_send_size = atoi(value);
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

	DEBUG(10, ("ibw_init(ctx_userdata: %u, ectx: %u)\n",
		(uint32_t)ctx_userdata, (uint32_t)ectx));

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

	rc = rdma_create_id(pctx->cm_channel, &pctx->cm_id, ctx, RDMA_PS_TCP);
	if (rc) {
		rc = errno;
		sprintf(ibw_lasterr, "rdma_create_id error %d\n", rc);
		goto cleanup;
	}
	DEBUG(10, ("created cm_id %p\n", pctx->cm_id));

	/* init verbs */
	pctx->pd = ibv_alloc_pd(pctx->cm_id->verbs);
	if (!pctx->pd) {
		sprintf(ibw_lasterr, "ibv_alloc_pd failed %d\n", errno);
		goto cleanup;
	}
	DEBUG(10, ("created pd %p\n", pctx->pd));

	pctx->pagesize = sysconf(_SC_PAGESIZE);

	return ctx;
	/* don't put code here */
cleanup:
	DEBUG(0, (ibw_lasterr));

	if (ctx)
		talloc_free(ctx);

	return NULL;
}

int ibw_stop(struct ibw_ctx *ctx)
{
	struct ibw_conn *p;

	DEBUG(10, ("ibw_stop\n"));
	for(p=ctx->conn_list; p!=NULL; p=p->next) {
		if (ctx->state==IBWC_ERROR || ctx->state==IBWC_CONNECTED) {
			if (ibw_disconnect(p))
				return -1;
		}
	}

	return 0;
}

int ibw_bind(struct ibw_ctx *ctx, struct sockaddr_in *my_addr)
{
	struct ibw_ctx_priv *pctx = (struct ibw_ctx_priv *)ctx->internal;
	int	rc;

	DEBUG(10, ("ibw_bind: addr=%s, port=%u\n",
		inet_ntoa(my_addr->sin_addr), my_addr->sin_port));
	rc = rdma_bind_addr(pctx->cm_id, (struct sockaddr *) my_addr);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_bind_addr error %d\n", rc);
		DEBUG(0, (ibw_lasterr));
		return rc;
	}
	DEBUG(10, ("rdma_bind_addr successful\n"));

	return 0;
}

int ibw_listen(struct ibw_ctx *ctx, int backlog)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(ctx->internal, struct ibw_ctx_priv);
	int	rc;

	DEBUG(10, ("ibw_listen\n"));
	rc = rdma_listen(pctx->cm_id, backlog);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_listen failed: %d\n", rc);
		DEBUG(0, (ibw_lasterr));
		return rc;
	}	

	return 0;
}

int ibw_accept(struct ibw_ctx *ctx, struct ibw_conn *conn, void *conn_userdata)
{
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct rdma_conn_param	conn_param;
	int	rc;

	DEBUG(10, ("ibw_accept: cmid=%u\n", (uint32_t)pconn->cm_id));
	conn->conn_userdata = conn_userdata;

	memset(&conn_param, 0, sizeof(struct rdma_conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	rc = rdma_accept(pconn->cm_id, &conn_param);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_accept failed %d\n", rc);
		DEBUG(0, (ibw_lasterr));
		return -1;;
	}

	pconn->is_accepted = 1;

	/* continued at RDMA_CM_EVENT_ESTABLISHED */

	return 0;
}

int ibw_connect(struct ibw_ctx *ctx, struct sockaddr_in *serv_addr, void *conn_userdata)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn *conn = NULL;
	struct ibw_conn_priv *pconn = NULL;
	int	rc;

	DEBUG(10, ("ibw_connect: cmid=%u, addr=%s, port=%u\n", (uint32_t)pconn->cm_id,
		inet_ntoa(serv_addr->sin_addr), serv_addr->sin_port));
	conn = ibw_conn_new(ctx);
	conn->conn_userdata = conn_userdata;
	pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);

	rc = rdma_create_id(pctx->cm_channel, &pconn->cm_id, conn, RDMA_PS_TCP);
	if (rc) {
		rc = errno;
		sprintf(ibw_lasterr, "rdma_create_id error %d\n", rc);
		return rc;
	}

	rc = rdma_resolve_addr(pconn->cm_id, NULL, (struct sockaddr *) &serv_addr, 2000);
	if (rc) {
		sprintf(ibw_lasterr, "rdma_resolve_addr error %d\n", rc);
		DEBUG(0, (ibw_lasterr));
		return -1;
	}

	/* continued at RDMA_CM_EVENT_ADDR_RESOLVED */

	return 0;
}

int ibw_disconnect(struct ibw_conn *conn)
{
	int	rc;
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);

	DEBUG(10, ("ibw_disconnect: cmid=%u\n", (uint32_t)pconn->cm_id));

	rc = rdma_disconnect(pctx->cm_id);
	if (rc) {
		sprintf(ibw_lasterr, "ibw_disconnect failed with %d", rc);
		DEBUG(0, (ibw_lasterr));
		return rc;
	}

	/* continued at RDMA_CM_EVENT_DISCONNECTED */

	return 0;
}

int ibw_alloc_send_buf(struct ibw_conn *conn, void **buf, void **key, uint32_t len)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_wr *p = pconn->wr_list_avail;

	if (p!=NULL) {
		DEBUG(10, ("ibw_alloc_send_buf#1: cmid=%u, len=%d\n", (uint32_t)pconn->cm_id, len));

		DLIST_REMOVE(pconn->wr_list_avail, p);
		DLIST_ADD(pconn->wr_list_used, p);

		if (len + sizeof(uint32_t) <= pctx->opts.avg_send_size) {
			*buf = (void *)(p->msg + sizeof(uint32_t));
		} else {
			p->msg_large = ibw_alloc_mr(pctx, pconn, len + sizeof(uint32_t), &p->mr_large);
			if (!p->msg_large) {
				sprintf(ibw_lasterr, "ibw_alloc_mr#1 failed\n");
				goto error;
			}
			*buf = (void *)(p->msg_large + sizeof(uint32_t));
		}
	} else {
		DEBUG(10, ("ibw_alloc_send_buf#2: cmid=%u, len=%d\n", (uint32_t)pconn->cm_id, len));
		/* not optimized */
		p = pconn->extra_avail;
		if (!p) {
			p = pconn->extra_avail = talloc_zero(pconn, struct ibw_wr);
			if (p==NULL) {
				sprintf(ibw_lasterr, "talloc_zero failed (emax: %u)", pconn->extra_max);
				goto error;
			}
			p->wr_id = pctx->opts.max_send_wr + pconn->extra_max;
			pconn->extra_max++;
			switch(pconn->extra_max) {
				case 1: DEBUG(2, ("warning: queue performed\n")); break;
				case 10: DEBUG(0, ("warning: queue reached 10\n")); break;
				case 100: DEBUG(0, ("warning: queue reached 100\n")); break;
				case 1000: DEBUG(0, ("warning: queue reached 1000\n")); break;
				default: break;
			}
		}
		DLIST_REMOVE(pconn->extra_avail, p);

		p->msg_large = ibw_alloc_mr(pctx, pconn, len + sizeof(uint32_t), &p->mr_large);
		if (!p->msg_large) {
			sprintf(ibw_lasterr, "ibw_alloc_mr#2 failed");
			goto error;
		}
		*buf = (void *)(p->msg_large + sizeof(uint32_t));
	}

	*key = (void *)p;

	return 0;
error:
	DEBUG(0, ("ibw_alloc_send_buf error: %s\n", ibw_lasterr));
	return -1;
}


int ibw_send(struct ibw_conn *conn, void *buf, void *key, uint32_t len)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_wr *p = talloc_get_type(key, struct ibw_wr);
	int	rc;

	*((uint32_t *)buf) = htonl(len);

	/* can we send it right now? */
	if (pconn->wr_sent<=pctx->opts.max_send_wr) {
		struct ibv_sge list = {
			.addr 	= (uintptr_t) NULL,
			.length = len,
			.lkey 	= 0
		};
		struct ibv_send_wr wr = {
			.wr_id 	    = p->wr_id + pctx->opts.max_recv_wr,
			.sg_list    = &list,
			.num_sge    = 1,
			.opcode     = IBV_WR_SEND,
			.send_flags = IBV_SEND_SIGNALED,
		};
		struct ibv_send_wr *bad_wr;

		DEBUG(10, ("ibw_wc_send#1(cmid: %u, wrid: %u, n: %d)\n",
			(uint32_t)pconn->cm_id, (uint32_t)wr.wr_id, len));

		if (p->msg_large==NULL) {
			list.lkey = pconn->mr_send->lkey;
			list.addr = (uintptr_t) p->msg;
		} else {
			assert(p->mr_large!=NULL);
			list.lkey = p->mr_large->lkey;
			list.addr = (uintptr_t) p->msg_large;
		}

		rc = ibv_post_send(pconn->cm_id->qp, &wr, &bad_wr);
		if (rc) {
			sprintf(ibw_lasterr, "ibv_post_send error %d (%d)\n",
				rc, pconn->wr_sent);
			DEBUG(0, (ibw_lasterr));
		} else {
			/* good case */
			if (p->wr_id>=pctx->opts.max_send_wr) {
				/* we don't have prepared index for this, so that
				 * we will have to find this later on */
				DLIST_ADD(pconn->extra_sent, p);
			}
			pconn->wr_sent++;
		}
		return rc;
	} /* else put the request into our own queue: */

	DEBUG(10, ("ibw_wc_send#2(cmid: %u, len: %u)\n", (uint32_t)pconn->cm_id, len));

	/* to be sent by ibw_wc_send */
	DLIST_ADD_END(pconn->queue, p, struct ibw_wr *); /* TODO: optimize */

	return 0;
}

int ibw_cancel_send_buf(struct ibw_conn *conn, void *buf, void *key)
{
	struct ibw_ctx_priv *pctx = talloc_get_type(conn->ctx->internal, struct ibw_ctx_priv);
	struct ibw_conn_priv *pconn = talloc_get_type(conn->internal, struct ibw_conn_priv);
	struct ibw_wr *p = talloc_get_type(key, struct ibw_wr);

	assert(p!=NULL);
	assert(buf!=NULL);
	assert(conn!=NULL);

	if (p->msg_large)
		ibw_free_mr(&p->msg_large, &p->mr_large);

	/* parallel case */
	if (p->wr_id < pctx->opts.max_send_wr) {
		DEBUG(10, ("ibw_cancel_send_buf#1 %u", (int)p->wr_id));
		DLIST_REMOVE(pconn->wr_list_used, p);
		DLIST_ADD(pconn->wr_list_avail, p);
	} else { /* "extra" packet */
		DEBUG(10, ("ibw_cancel_send_buf#2 %u", (int)p->wr_id));
		DLIST_ADD(pconn->extra_avail, p);
	}

	return 0;
}

const char *ibw_getLastError(void)
{
	return ibw_lasterr;
}
