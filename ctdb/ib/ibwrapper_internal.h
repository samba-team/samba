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

typedef struct _ibw_mr {
	struct ibv_mr *mr;
	struct _ibw_mr *next, *prev;
} ibw_mr;

typedef struct _ibw_opts {
	char	*dev_name;
	int	rx_depth;
	int	mtu;
	int	ib_port;
} ibw_opts;

typedef enum {
	IWINT_INIT = 0,
	IWINT_ADDR_RESOLVED,
	IWINT_ROUTE_RESOLVED,
	IWINT_ERROR
} ibw_state_ctx;

typedef struct _ibw_ctx_priv {
	ibw_mr *avail_first;
	ibw_mr *avail_last;
	ibw_mr *used_first;
	ibw_mr *used_last;

	struct event_context *ectx;

	ibw_opts opts;

	struct rdma_cm_id	*cm_id; /* server cm id */

	struct rdma_event_channel *cm_channel;
	struct fd_event *cm_channel_event;

	struct rdma_event_channel *cm_channel;
	struct fd_event *cm_channel_event;
	struct ibv_comp_channel *verbs_channel;
	struct fd_event *verbs_channel_event;

	struct ibv_pd	       *pd;

	ibw_connstate_fn_t connstate_func;
	ibw_receive_fn_t receive_func;
} ibw_ctx_priv;

typedef struct _ibw_conn_priv {
	struct ibv_cq	*cq;
	struct ibv_qp	*qp;

	struct rdma_cm_id *cm_id; /* client's cm id */
	int	is_accepted;
} ibw_conn_priv;

/* 
 * Must be called in all cases after selecting/polling
 * for FDs set via ibw_add_event_fn_t.
 *
 * fd_index: fd identifier passed in ibw_add_event_fn_t
 * with the same fd was set there.
 */
//int ibw_process_event(ibw_ctx *ctx, int fd_index);

