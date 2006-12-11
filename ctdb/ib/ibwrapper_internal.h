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

typedef struct _ibw_opts {
	int	max_send_wr;
	int	max_recv_wr;
	int	max_msg_size;
} ibw_opts;

typedef struct _ibw_wr {
	char	*msg; /* initialized in ibw_init_memory once */
	ibw_conn *conn; /*valid only when in wr_list_used */
	int	wr_id; /* position in wr_index list; also used as wr id */
	struct _ibw_wr *next, *prev; /* in wr_list_avail or wr_list_used */
} ibw_wr;

typedef enum {
	IWINT_INIT = 0,
	IWINT_ADDR_RESOLVED,
	IWINT_ROUTE_RESOLVED,
	IWINT_ERROR
} ibw_state_ctx;

typedef struct _ibw_ctx_priv {
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

	long	pagesize; /* sysconf result for memalign */
} ibw_ctx_priv;

typedef struct _ibw_conn_priv {
	struct rdma_cm_id *cm_id; /* client's cm id */
	int	is_accepted;

	struct ibv_cq	*cq; /* qp is in cm_id */
	struct ibv_mr *mr;
	char *buf; /* fixed size (opts.bufsize) buffer for send/recv */
	ibw_wr *wr_list_avail;
	ibw_wr *wr_list_used;
	ibw_wr **wr_index; /* array[0..(max_send_wr + max_recv_wr)-1] of (ibw_wr *) */
} ibw_conn_priv;

