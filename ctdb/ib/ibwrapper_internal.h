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
	uint32_t	max_send_wr;
	uint32_t	max_recv_wr;
	uint32_t	avg_send_size;
	uint32_t	recv_bufsize;
	uint32_t	recv_threshold;
};

struct ibw_wr {
	char	*msg; /* initialized in ibw_init_memory once per connection */
	int	wr_id; /* position in wr_index list; also used as wr id */

	char	*msg_large; /* allocated specially for "large" message */
	struct ibv_mr *mr_large;

	struct ibw_wr *next, *prev; /* in wr_list_avail or wr_list_used */
};

struct ibw_ctx_priv {
	struct event_context *ectx;

	struct ibw_opts opts;

	struct rdma_cm_id	*cm_id; /* server cm id */

	struct rdma_event_channel *cm_channel;
	struct fd_event *cm_channel_event;

	struct ibv_pd	       *pd;

	ibw_connstate_fn_t connstate_func; /* see ibw_init */
	ibw_receive_fn_t receive_func; /* see ibw_init */

	long	pagesize; /* sysconf result for memalign */
};

struct ibw_part {
	char *buf; /* talloced memory buffer */
	uint32_t bufsize; /* allocated size of buf - always grows */
	uint32_t len; /* message part length */
	uint32_t to_read; /* 4 or *((uint32_t)buf) if len>=sizeof(uint32_t) */
};

struct ibw_conn_priv {
	struct ibv_comp_channel *verbs_channel;
	struct fd_event *verbs_channel_event;

	struct rdma_cm_id *cm_id; /* client's cm id */
	int	is_accepted;

	struct ibv_cq	*cq; /* qp is in cm_id */

	char *buf_send; /* max_send_wr * avg_send_size */
	struct ibv_mr *mr_send;
	struct ibw_wr *wr_list_avail;
	struct ibw_wr *wr_list_used;
	struct ibw_wr **wr_index; /* array[0..(qsize-1)] of (ibw_wr *) */

	/* buf_recv is a ring buffer */
	char *buf_recv; /* max_recv_wr * avg_recv_size */
	struct ibv_mr *mr_recv;
	int recv_index; /* index of the next recv buffer when refilling */
	struct ibw_part part;
};

