/* 
   Unix SMB/CIFS mplementation.

   helper layer for breaking up streams into discrete requests
   
   Copyright (C) Andrew Tridgell  2005
    
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   
*/

typedef NTSTATUS (*packet_full_request_fn_t)(void *private, 
					     DATA_BLOB blob, size_t *packet_size);
typedef NTSTATUS (*packet_callback_fn_t)(void *private, DATA_BLOB blob);

/* Used to notify that a packet has been sent, and is on the wire */
typedef void (*packet_send_callback_fn_t)(void *private);
typedef void (*packet_error_handler_fn_t)(void *private, NTSTATUS status);



struct packet_context *packet_init(TALLOC_CTX *mem_ctx);
void packet_set_callback(struct packet_context *pc, packet_callback_fn_t callback);
void packet_set_error_handler(struct packet_context *pc, packet_error_handler_fn_t handler);
void packet_set_private(struct packet_context *pc, void *private);
void packet_set_full_request(struct packet_context *pc, packet_full_request_fn_t callback);
void packet_set_socket(struct packet_context *pc, struct socket_context *sock);
void packet_set_event_context(struct packet_context *pc, struct event_context *ev);
void packet_set_fde(struct packet_context *pc, struct fd_event *fde);
void packet_set_serialise(struct packet_context *pc);
void packet_set_initial_read(struct packet_context *pc, uint32_t initial_read);
void packet_set_nofree(struct packet_context *pc);
void packet_recv(struct packet_context *pc);
void packet_recv_disable(struct packet_context *pc);
void packet_recv_enable(struct packet_context *pc);
NTSTATUS packet_send(struct packet_context *pc, DATA_BLOB blob);
NTSTATUS packet_send_callback(struct packet_context *pc, DATA_BLOB blob,
			      packet_send_callback_fn_t send_callback, 
			      void *private);
void packet_queue_run(struct packet_context *pc);

/*
  pre-canned handlers
*/
NTSTATUS packet_full_request_nbt(void *private, DATA_BLOB blob, size_t *size);
NTSTATUS packet_full_request_u32(void *private, DATA_BLOB blob, size_t *size);


