/* 
   Unix SMB/CIFS implementation.
   messages.c header
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) 2001, 2002 by Martin Pool

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

#ifndef _MESSAGES_H_
#define _MESSAGES_H_

/* change the message version with any incompatible changes in the protocol */
#define MESSAGE_VERSION 2

/*
 * Special flags passed to message_send. Allocated from the top, lets see when
 * it collides with the message types in the lower 16 bits :-)
 */

/*
 * Under high load, this message can be dropped. Use for notify-style
 * messages that are not critical for correct operation.
 */
#define MSG_FLAG_LOWPRIORITY		0x80000000


/* Flags to classify messages - used in message_send_all() */
/* Sender will filter by flag. */

#define FLAG_MSG_GENERAL		0x0001
#define FLAG_MSG_SMBD			0x0002
#define FLAG_MSG_NMBD			0x0004
#define FLAG_MSG_WINBIND		0x0008
#define FLAG_MSG_PRINT_GENERAL		0x0010
/* dbwrap messages 4001-4999 */
#define FLAG_MSG_DBWRAP			0x0020

/*
 * ctdb gives us 64-bit server ids for messaging_send. This is done to avoid
 * pid clashes and to be able to register for special messages like "all
 * smbds".
 *
 * Normal individual server id's have the upper 32 bits to 0, I picked "1" for
 * Samba, other subsystems might use something else.
 */

#define MSG_SRVID_SAMBA 0x0000000100000000LL

#include "librpc/gen_ndr/server_id.h"

#define MSG_BROADCAST_PID_STR	"0:0"

struct messaging_context;
struct messaging_rec;

struct messaging_backend {
	int (*send_fn)(struct server_id src,
		       struct server_id pid, int msg_type,
		       const struct iovec *iov, int iovlen,
		       const int *fds, size_t num_fds,
		       struct messaging_backend *backend);
	void *private_data;
};

NTSTATUS messaging_ctdbd_init(struct messaging_context *msg_ctx,
			      TALLOC_CTX *mem_ctx,
			      struct messaging_backend **presult);
struct ctdbd_connection *messaging_ctdbd_connection(void);

bool message_send_all(struct messaging_context *msg_ctx,
		      int msg_type,
		      const void *buf, size_t len,
		      int *n_sent);
struct messaging_context *messaging_init(TALLOC_CTX *mem_ctx, 
					 struct tevent_context *ev);

struct server_id messaging_server_id(const struct messaging_context *msg_ctx);
struct tevent_context *messaging_tevent_context(
	struct messaging_context *msg_ctx);

/*
 * re-init after a fork
 */
NTSTATUS messaging_reinit(struct messaging_context *msg_ctx);

NTSTATUS messaging_register(struct messaging_context *msg_ctx,
			    void *private_data,
			    uint32_t msg_type,
			    void (*fn)(struct messaging_context *msg,
				       void *private_data, 
				       uint32_t msg_type, 
				       struct server_id server_id,
				       DATA_BLOB *data));
void messaging_deregister(struct messaging_context *ctx, uint32_t msg_type,
			  void *private_data);

/**
 * CAVEAT:
 *
 * While the messaging_send*() functions are synchronuous by API,
 * they trigger a tevent-based loop upon sending bigger messages.
 *
 * Hence callers should not use these in purely synchonous code,
 * but run a tevent_loop instead.
 */
NTSTATUS messaging_send(struct messaging_context *msg_ctx,
			struct server_id server, 
			uint32_t msg_type, const DATA_BLOB *data);

NTSTATUS messaging_send_buf(struct messaging_context *msg_ctx,
			    struct server_id server, uint32_t msg_type,
			    const uint8_t *buf, size_t len);
NTSTATUS messaging_send_iov(struct messaging_context *msg_ctx,
			    struct server_id server, uint32_t msg_type,
			    const struct iovec *iov, int iovlen,
			    const int *fds, size_t num_fds);
void messaging_dispatch_rec(struct messaging_context *msg_ctx,
			    struct messaging_rec *rec);

struct tevent_req *messaging_filtered_read_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct messaging_context *msg_ctx,
	bool (*filter)(struct messaging_rec *rec, void *private_data),
	void *private_data);
int messaging_filtered_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				 struct messaging_rec **presult);

struct tevent_req *messaging_read_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct messaging_context *msg,
				       uint32_t msg_type);
int messaging_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			struct messaging_rec **presult);

int messaging_cleanup(struct messaging_context *msg_ctx, pid_t pid);

bool messaging_parent_dgm_cleanup_init(struct messaging_context *msg);

#include "librpc/gen_ndr/ndr_messaging.h"

#endif
