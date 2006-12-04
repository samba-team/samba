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


#define IBW_LASTERR_BUFSIZE 512
static char ibw_lasterr[IBW_LASTERR_BUFSIZE];

static ibw_mr *ibw_alloc_mr(ibw_ctx_priv *pctx)
{
}

static int ibwctx_destruct(void *ptr)
{
	ibw_ctx *pctx = talloc_get_type(ptr, ibw_ctx);
	assert(pctx!=NULL);

	/* free memory regions */

	return 0;
}

int ibw_process_event(ibw_ctx *ctx, int fd_index);

static void ibw_process_cm_event(struct event_context *ev,
	struct fd_event *fde, uint16_t flags, void *private_data)
{
	if (fde->
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
	ibw_receive_fn_t ibw_receive)
{
	ibw_ctx *ctx = talloc_zero(NULL, ibw_ctx);
	ibw_ctx_priv *pctx;
	int	rc;
	ibw_event_ud *event_priv;

	memset(ibw_lasterr, 0, IBW_LASTERR_BUFSIZE);

	assert(ctx!=NULL);
	ibw_lasterr[0] = '\0';
	talloc_set_destructor(ctx, ibwctx_destruct);
	ctx->userdata = userdata;

	pctx = talloc_zero(ctx, ibw_ctx_priv);
	ctx->internal = (void *)pctx;
	assert(pctx!=NULL);

	pctx->connstate_func = ibw_connstate;
	pctx->receive_func = ibw_receive;

	assert((pctx->ectx = event_context_init(ctx))!=NULL);

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

	event_priv = talloc_zero(ctx, ibw_event_ud);
	event_priv->ctx = ctx;
	event_priv->id = IBWET_CM;

	pctx->cm_channel_event = event_add_fd(pctx->ectx, pctx,
		pctx->cm_channel->fd, EVENT_FD_READ, ibw_process_cm_event, event_priv);

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
}

int ibw_listen(ibw_ctx *ctx, int backlog)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
}

int ibw_accept(ibw_ctx *ctx, void *conn_userdata)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
}

int ibw_connect(ibw_ctx *ctx, struct sockaddr_in *serv_addr, void *conn_userdata)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
}

void ibw_disconnect(ibw_conn *conn)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
}

int ibw_process_event(ibw_ctx *ctx, ...)
{
	ibw_ctx_priv *pctx = (ibw_ctx_priv *)ctx->internal;
}

int ibw_alloc_send_buf(ibw_conn *conn, void **buf, void **key, int n)
{
}

int ibw_send(ibw_conn *conn, void *buf, void *key, int n)
{
}

const char *ibw_getLastError()
{
	return ibw_lasterr;
}
