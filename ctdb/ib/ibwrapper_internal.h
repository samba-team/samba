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

struct ibw_opts {
	int	max_send_wr;
	int	max_recv_wr;
};

struct ibw_wr {
	char	*msg; /* initialized in ibw_init_memory once per connection */
	int	wr_id; /* position in wr_index list; also used as wr id */
	struct _ibw_wr *next, *prev; /* in wr_list_avail or wr_list_used */
};

struct ibw_ctx_priv {
	struct event_context *ectx;

	struct ibw_opts opts;

	struct rdma_cm_id	*cm_id; /* server cm id */

	struct rdma_event_channel *cm_channel;
	struct fd_event *cm_channel_event;

	struct ibv_pd	       *pd;
	enum iwint_state_ctx	state2;

	ibw_connstate_fn_t connstate_func; /* see ibw_init */
	ibw_receive_fn_t receive_func; /* see ibw_init */

	long	pagesize; /* sysconf result for memalign */
	int	qsize; /* opts.max_send_wr + opts.max_recv_wr */
	int	max_msg_size; /* see ibw_init */
};

struct ibw_conn_priv {
	struct ibv_comp_channel *verbs_channel;
	struct fd_event *verbs_channel_event;

	struct rdma_cm_id *cm_id; /* client's cm id */
	int	is_accepted;

	struct ibv_cq	*cq; /* qp is in cm_id */
	struct ibv_mr *mr;
	char *buf; /* fixed size (qsize * opts.max_msg_size) buffer for send/recv */
	struct ibw_wr *wr_list_avail;
	struct ibw_wr *wr_list_used;
	struct ibw_wr **wr_index; /* array[0..(qsize-1)] of (ibw_wr *) */
};

