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

int messaging_dgm_init(struct tevent_context *ev,
		       struct server_id pid,
		       const char *cache_dir,
		       uid_t dir_owner,
		       void (*recv_cb)(const uint8_t *msg,
				       size_t msg_len,
				       int *fds,
				       size_t num_fds,
				       void *private_data),
		       void *recv_cb_private_data);
void messaging_dgm_destroy(void);
int messaging_dgm_send(pid_t pid,
		       const struct iovec *iov, int iovlen,
		       const int *fds, size_t num_fds);
int messaging_dgm_cleanup(pid_t pid);
int messaging_dgm_wipe(void);
void *messaging_dgm_register_tevent_context(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev);

#endif
