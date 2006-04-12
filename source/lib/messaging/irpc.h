/* 
   Unix SMB/CIFS implementation.

   Samba internal rpc code - header

   Copyright (C) Andrew Tridgell 2005
   
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

#include "librpc/gen_ndr/irpc.h"

/*
  an incoming irpc message
*/
struct irpc_message {
	uint32_t from;
	void *private;
	struct irpc_header header;
	struct ndr_pull *ndr;
	BOOL defer_reply;
	struct messaging_context *msg_ctx;
	struct irpc_list *irpc;
	void *data;
	struct event_context *ev;
};

/* don't allow calls to take too long */
#define IRPC_CALL_TIMEOUT 10


/* the server function type */
typedef NTSTATUS (*irpc_function_t)(struct irpc_message *, void *r);

/* register a server function with the irpc messaging system */
#define IRPC_REGISTER(msg_ctx, pipename, funcname, function, private) \
   irpc_register(msg_ctx, &dcerpc_table_ ## pipename, \
                          DCERPC_ ## funcname, \
			  (irpc_function_t)function, private)

/* make a irpc call */
#define IRPC_CALL(msg_ctx, server_id, pipename, funcname, ptr, ctx) \
   irpc_call(msg_ctx, server_id, &dcerpc_table_ ## pipename, DCERPC_ ## funcname, ptr, ctx)

#define IRPC_CALL_SEND(msg_ctx, server_id, pipename, funcname, ptr, ctx) \
   irpc_call_send(msg_ctx, server_id, &dcerpc_table_ ## pipename, DCERPC_ ## funcname, ptr, ctx)


/*
  a pending irpc call
*/
struct irpc_request {
	struct messaging_context *msg_ctx;
	const struct dcerpc_interface_table *table;
	int callnum;
	int callid;
	void *r;
	NTSTATUS status;
	BOOL done;
	TALLOC_CTX *mem_ctx;
	struct {
		void (*fn)(struct irpc_request *);
		void *private;
	} async;
};

typedef void (*msg_callback_t)(struct messaging_context *msg, void *private, 
			       uint32_t msg_type, uint32_t server_id, DATA_BLOB *data);

struct messaging_context *messaging_init(TALLOC_CTX *mem_ctx, uint32_t server_id, 
					 struct event_context *ev);
NTSTATUS messaging_send(struct messaging_context *msg, uint32_t server, 
			uint32_t msg_type, DATA_BLOB *data);
NTSTATUS messaging_register(struct messaging_context *msg, void *private,
			    uint32_t msg_type, 
			    msg_callback_t fn);
NTSTATUS messaging_register_tmp(struct messaging_context *msg, void *private,
				msg_callback_t fn, uint32_t *msg_type);
struct messaging_context *messaging_init(TALLOC_CTX *mem_ctx, uint32_t server_id, 
					 struct event_context *ev);
struct messaging_context *messaging_client_init(TALLOC_CTX *mem_ctx, 
					 struct event_context *ev);
NTSTATUS messaging_send_ptr(struct messaging_context *msg, uint32_t server, 
			    uint32_t msg_type, void *ptr);
void messaging_deregister(struct messaging_context *msg, uint32_t msg_type, void *private);




NTSTATUS irpc_register(struct messaging_context *msg_ctx, 
		       const struct dcerpc_interface_table *table, 
		       int call, irpc_function_t fn, void *private);
struct irpc_request *irpc_call_send(struct messaging_context *msg_ctx, 
				    uint32_t server_id, 
				    const struct dcerpc_interface_table *table, 
				    int callnum, void *r, TALLOC_CTX *ctx);
NTSTATUS irpc_call_recv(struct irpc_request *irpc);
NTSTATUS irpc_call(struct messaging_context *msg_ctx, 
		   uint32_t server_id, 
		   const struct dcerpc_interface_table *table, 
		   int callnum, void *r, TALLOC_CTX *ctx);

NTSTATUS irpc_add_name(struct messaging_context *msg_ctx, const char *name);
uint32_t *irpc_servers_byname(struct messaging_context *msg_ctx, const char *name);
void irpc_remove_name(struct messaging_context *msg_ctx, const char *name);
NTSTATUS irpc_send_reply(struct irpc_message *m, NTSTATUS status);


