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

#include "librpc/gen_ndr/server_id.h"

struct imessaging_context;

/* general messages */
#define MSG_DEBUG		1
#define MSG_PING		2
#define MSG_PONG		3
#define MSG_BRL_RETRY		4
#define MSG_PVFS_RETRY_OPEN	5
#define MSG_IRPC                6
#define MSG_PVFS_NOTIFY		7
#define MSG_NTVFS_OPLOCK_BREAK	8
#define MSG_DREPL_ALLOCATE_RID	9

/* temporary messaging endpoints are allocated above this line */
#define MSG_TMP_BASE		1000

/* taskid for messaging of parent process */
#define SAMBA_PARENT_TASKID     0

typedef void (*msg_callback_t)(struct imessaging_context *msg, void *private_data,
			       uint32_t msg_type,
			       struct server_id server_id, DATA_BLOB *data);

NTSTATUS imessaging_send(struct imessaging_context *msg, struct server_id server,
			uint32_t msg_type, const DATA_BLOB *data);
NTSTATUS imessaging_register(struct imessaging_context *msg, void *private_data,
			    uint32_t msg_type,
			    msg_callback_t fn);
NTSTATUS imessaging_register_tmp(struct imessaging_context *msg, void *private_data,
				msg_callback_t fn, uint32_t *msg_type);
struct imessaging_context *imessaging_init(TALLOC_CTX *mem_ctx,
					   struct loadparm_context *lp_ctx,
					   struct server_id server_id,
					   struct tevent_context *ev,
					   bool auto_remove);
int imessaging_cleanup(struct imessaging_context *msg);
struct imessaging_context *imessaging_client_init(TALLOC_CTX *mem_ctx,
					   struct loadparm_context *lp_ctx,
					 struct tevent_context *ev);
NTSTATUS imessaging_send_ptr(struct imessaging_context *msg, struct server_id server,
			    uint32_t msg_type, void *ptr);
void imessaging_deregister(struct imessaging_context *msg, uint32_t msg_type, void *private_data);
struct server_id imessaging_get_server_id(struct imessaging_context *msg_ctx);

#endif
