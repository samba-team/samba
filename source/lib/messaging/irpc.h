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

/*
  an incoming irpc message
*/
struct irpc_message {
	uint32_t from;
};

/* don't allow calls to take too long */
#define IRPC_CALL_TIMEOUT 10


/* the server function type */
typedef NTSTATUS (*irpc_function_t)(struct irpc_message *, void *r);

/* register a server function with the irpc messaging system */
#define IRPC_REGISTER(msg_ctx, pipename, funcname, function) \
   irpc_register(msg_ctx, &dcerpc_table_ ## pipename, \
                          DCERPC_ ## funcname, \
			  (irpc_function_t)function)

/* make a irpc call */
#define IRPC_CALL(msg_ctx, server_id, pipename, funcname, ptr) \
   irpc_call(msg_ctx, server_id, &dcerpc_table_ ## pipename, DCERPC_ ## funcname, ptr)


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
	struct {
		void (*fn)(struct irpc_request *);
		void *private;
	} async;
};


struct messaging_context *messaging_init(TALLOC_CTX *mem_ctx, uint32_t server_id, 
					 struct event_context *ev);
NTSTATUS messaging_send(struct messaging_context *msg, uint32_t server, 
			uint32_t msg_type, DATA_BLOB *data);
void messaging_register(struct messaging_context *msg, void *private,
			uint32_t msg_type, 
			void (*fn)(struct messaging_context *, void *, uint32_t, uint32_t, DATA_BLOB *));
struct messaging_context *messaging_init(TALLOC_CTX *mem_ctx, uint32_t server_id, 
					 struct event_context *ev);
NTSTATUS messaging_send_ptr(struct messaging_context *msg, uint32_t server, 
			    uint32_t msg_type, void *ptr);
void messaging_deregister(struct messaging_context *msg, uint32_t msg_type, void *private);




NTSTATUS irpc_register(struct messaging_context *msg_ctx, 
		       const struct dcerpc_interface_table *table, 
		       int call, irpc_function_t fn);
struct irpc_request *irpc_call_send(struct messaging_context *msg_ctx, 
				    uint32_t server_id, 
				    const struct dcerpc_interface_table *table, 
				    int callnum, void *r);
NTSTATUS irpc_call_recv(struct irpc_request *irpc);
NTSTATUS irpc_call(struct messaging_context *msg_ctx, 
		   uint32_t server_id, 
		   const struct dcerpc_interface_table *table, 
		   int callnum, void *r);

