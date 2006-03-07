/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Rafal Szczesniak 2005
   
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
  a composite function for name resolving
*/

#include "includes.h"
#include "lib/events/events.h"
#include "libnet/libnet.h"
#include "libcli/composite/composite.h"
#include "lib/messaging/messaging.h"
#include "lib/messaging/irpc.h"
#include "libcli/resolve/resolve.h"

struct lookup_state {
	struct composite_context *resolve_ctx;
	struct nbt_name hostname;
};


/**
 * Sends asynchronous Lookup request
 *
 * @param io arguments and result of the call
 */

struct composite_context *libnet_Lookup_send(struct libnet_context *ctx,
					     struct libnet_Lookup *io)
{
	struct composite_context *c;
	struct lookup_state *s;
	const char** methods;

	if (!io) return NULL;

	/* allocate context and state structures */
	c = talloc_zero(NULL, struct composite_context);
	if (c == NULL) goto failed;

	s = talloc_zero(c, struct lookup_state);
	if (s == NULL) goto failed;
	
	/* prepare event context */
	c->event_ctx = event_context_find(c);
	if (c->event_ctx == NULL) goto failed;

	/* parameters */
	s->hostname.name   = talloc_strdup(s, io->in.hostname);
	s->hostname.type   = io->in.type;
	s->hostname.scope  = NULL;

	/* name resolution methods */
	if (io->in.methods) {
		methods = io->in.methods;
	} else {
		methods = (const char**)ctx->name_res_methods;
	}

	c->private_data	= s;
	c->state	= COMPOSITE_STATE_IN_PROGRESS;

	/* send resolve request */
	s->resolve_ctx = resolve_name_send(&s->hostname, c->event_ctx, methods);

	return c;

failed:
	talloc_free(c);
	return NULL;
}


/**
 * Waits for and receives results of asynchronous Lookup call
 *
 * @param c composite context returned by asynchronous Lookup call
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_Lookup_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
			    struct libnet_Lookup *io)
{
	NTSTATUS status;
	struct lookup_state *s;
	const char *address;

	s = talloc_get_type(c->private_data, struct lookup_state);

	status = resolve_name_recv(s->resolve_ctx, mem_ctx, &address);
	if (NT_STATUS_IS_OK(status)) {
		io->out.address = str_list_make(mem_ctx, address, NULL);
		NT_STATUS_HAVE_NO_MEMORY(io->out.address);
	}

	return status;
}


/**
 * Synchronous version of Lookup call
 *
 * @param mem_ctx memory context for the call
 * @param io arguments and results of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_Lookup(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
		       struct libnet_Lookup *io)
{
	struct composite_context *c = libnet_Lookup_send(ctx, io);
	return libnet_Lookup_recv(c, mem_ctx, io);
}


/*
 * Shortcut functions to find common types of name
 * (and skip nbt name type argument)
 */


/**
 * Sends asynchronous LookupHost request
 */
struct composite_context* libnet_LookupHost_send(struct libnet_context *ctx,
						 struct libnet_Lookup *io)
{
	io->in.type = NBT_NAME_SERVER;
	return libnet_Lookup_send(ctx, io);
}



/**
 * Synchronous version of LookupHost call
 */
NTSTATUS libnet_LookupHost(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			   struct libnet_Lookup *io)
{
	struct composite_context *c = libnet_LookupHost_send(ctx, io);
	return libnet_Lookup_recv(c, mem_ctx, io);
}


/**
 * Sends asynchronous LookupPdc request
 */
struct composite_context* libnet_LookupDCs_send(struct libnet_context *ctx,
						TALLOC_CTX *mem_ctx,
						struct libnet_LookupDCs *io)
{
	struct messaging_context *msg_ctx = messaging_client_init(mem_ctx, ctx->event_ctx);
	struct composite_context *c;
	c = finddcs_send(mem_ctx,
			 io->in.domain_name, 
			 NBT_NAME_PDC,
			 NULL, ctx->name_res_methods,
			 ctx->event_ctx, msg_ctx);
	return c;
}

/**
 * Waits for and receives results of asynchronous Lookup call
 *
 * @param c composite context returned by asynchronous Lookup call
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_LookupDCs_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
			       struct libnet_LookupDCs *io)
{
	NTSTATUS status;
	status = finddcs_recv(c, mem_ctx, &io->out.num_dcs, &io->out.dcs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return status;
}

/**
 * Synchronous version of LookupPdc
 */
NTSTATUS libnet_LookupDCs(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			  struct libnet_LookupDCs *io)
{
	struct composite_context *c = libnet_LookupDCs_send(ctx, mem_ctx, io);
	return libnet_LookupDCs_recv(c, mem_ctx, io);
}
