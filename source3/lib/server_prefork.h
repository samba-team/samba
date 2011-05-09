/*
   Unix SMB/CIFS implementation.
   Common server globals

   Copyright (C) Simo Sorce <idra@samba.org> 2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "system/network.h"
#include <tevent.h>

enum pf_worker_status {
	PF_WORKER_NONE = 0,
	PF_WORKER_IDLE,
	PF_WORKER_ACCEPTING,
	PF_WORKER_BUSY,
	PF_WORKER_EXITING
};

enum pf_server_cmds {
	PF_SRV_MSG_NONE = 0,
	PF_SRV_MSG_EXIT
};

struct pf_worker_data {
	pid_t pid;
	enum pf_worker_status status;
	time_t started;
	time_t last_used;
	int num_clients;

	enum pf_server_cmds cmds;
	int allowed_clients;
};

typedef int (prefork_main_fn_t)(struct tevent_context *ev,
				struct pf_worker_data *pf,
				int listen_fd,
				int lock_fd,
				void *private_data);

struct prefork_pool;


/* ==== Functions used by controlling process ==== */

bool prefork_create_pool(struct tevent_context *ev_ctx,
			 TALLOC_CTX *mem_ctx, int listen_fd,
			 int min_children, int max_children,
			 prefork_main_fn_t *main_fn, void *private_data,
			 struct prefork_pool **pf_pool);
int prefork_expand_pool(struct prefork_pool *pfp, int new_max);

int prefork_add_children(struct tevent_context *ev_ctx,
			 struct prefork_pool *pfp,
			 int num_children);
int prefork_retire_children(struct prefork_pool *pfp,
			    int num_children, time_t age_limit);
int prefork_count_active_children(struct prefork_pool *pfp, int *total);
bool prefork_mark_pid_dead(struct prefork_pool *pfp, pid_t pid);
void prefork_increase_allowed_clients(struct prefork_pool *pfp, int max);
void prefork_reset_allowed_clients(struct prefork_pool *pfp);

/* ==== Functions used by children ==== */

int prefork_wait_for_client(struct pf_worker_data *pf,
			    int lock_fd, int listen_fd,
			    struct sockaddr *addr,
			    socklen_t *addrlen, int *fd);

struct tevent_req *prefork_listen_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct pf_worker_data *pf,
					int lock_fd, int listen_fd,
					struct sockaddr *addr,
					socklen_t *addrlen);
int prefork_listen_recv(struct tevent_req *req, int *fd);
