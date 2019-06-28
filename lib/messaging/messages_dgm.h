/*
 * Unix SMB/CIFS implementation.
 * messages_dgm.c header
 * Copyright (C) Volker Lendecke 2014
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _MESSAGES_DGM_H_
#define _MESSAGES_DGM_H_

#include "replace.h"
#include "system/filesys.h"
#include <tevent.h>

int messaging_dgm_init(struct tevent_context *ev,
		       uint64_t *unique,
		       const char *socket_dir,
		       const char *lockfile_dir,
		       void (*recv_cb)(struct tevent_context *ev,
				       const uint8_t *msg,
				       size_t msg_len,
				       int *fds,
				       size_t num_fds,
				       void *private_data),
		       void *recv_cb_private_data);
void messaging_dgm_destroy(void);
int messaging_dgm_get_unique(pid_t pid, uint64_t *unique);
int messaging_dgm_send(pid_t pid,
		       const struct iovec *iov, int iovlen,
		       const int *fds, size_t num_fds);
int messaging_dgm_cleanup(pid_t pid);
int messaging_dgm_wipe(void);
int messaging_dgm_forall(int (*fn)(pid_t pid, void *private_data),
			 void *private_data);

struct messaging_dgm_fde;
struct messaging_dgm_fde *messaging_dgm_register_tevent_context(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev);
bool messaging_dgm_fde_active(struct messaging_dgm_fde *fde);

#endif
