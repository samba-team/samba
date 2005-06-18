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
#include "libcli/raw/libcliraw.h"
#include "lib/events/events.h"
#include "libcli/composite/composite.h"
#include "libcli/composite/monitor.h"
#include "libnet/composite.h"
#include "librpc/gen_ndr/ndr_nbt.h"


struct lookup_state {
	struct composite_context *resolve_ctx;
	struct nbt_name hostname;
	char address[16];
};


struct composite_context *libnet_Lookup_send(struct libnet_lookup *io)
{
	struct composite_context *c;
	struct lookup_state *s;

	if (!io) return NULL;

	/* allocate context and state structures */
	c = talloc_zero(NULL, struct composite_context);
	if (c == NULL) goto failed;

	s = talloc_zero(c, struct lookup_state);
	if (s == NULL) goto failed;
	
	/* prepare event context */
	c->event_ctx = event_context_init(c);
	if (c->event_ctx == NULL) goto failed;

	/* parameters */
	s->hostname.name   = talloc_strdup(s, io->in.hostname);
	s->hostname.type   = io->in.type;
	s->hostname.scope  = NULL;

	c->private  = s;
	c->state    = SMBCLI_REQUEST_SEND;

	/* send resolve request */
	s->resolve_ctx = resolve_name_send(&s->hostname, c->event_ctx, io->in.methods);

	return c;

failed:
	talloc_free(c);
	return NULL;
}


NTSTATUS libnet_Lookup_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
			    struct libnet_lookup *io)
{
	NTSTATUS status;
	struct lookup_state *s;

	s = talloc_get_type(c->private, struct lookup_state);

	status = resolve_name_recv(s->resolve_ctx, mem_ctx, io->out.address);
	return status;
}


NTSTATUS libnet_Lookup(TALLOC_CTX *mem_ctx, struct libnet_lookup *io)
{
	struct composite_context *c = libnet_Lookup_send(io);
	return libnet_Lookup_recv(c, mem_ctx, io);
}
