/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Rafal Szczesniak 2007
   
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

/*
  a composite function for manipulating (add/edit/del) groups via samr pipe
*/

#include "includes.h"
#include "libcli/composite/composite.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr_c.h"


struct groupadd_state {
	struct dcerpc_binding_handle *binding_handle;
	struct policy_handle domain_handle;
	struct samr_CreateDomainGroup creategroup;
	struct policy_handle group_handle;
	uint32_t group_rid;
	
	void (*monitor_fn)(struct monitor_msg*);
};


static void continue_groupadd_created(struct tevent_req *subreq);


struct composite_context* libnet_rpc_groupadd_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct dcerpc_binding_handle *b,
						   struct libnet_rpc_groupadd *io,
						   void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct groupadd_state *s;
	struct tevent_req *subreq;

	if (!b || !io) return NULL;

	c = composite_create(mem_ctx, ev);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct groupadd_state);
	if (composite_nomem(s, c)) return c;

	c->private_data = s;

	s->domain_handle = io->in.domain_handle;
	s->binding_handle= b;
	s->monitor_fn    = monitor;

	s->creategroup.in.domain_handle  = &s->domain_handle;

	s->creategroup.in.name           = talloc_zero(c, struct lsa_String);
	if (composite_nomem(s->creategroup.in.name, c)) return c;

	s->creategroup.in.name->string   = talloc_strdup(c, io->in.groupname);
	if (composite_nomem(s->creategroup.in.name->string, c)) return c;
	
	s->creategroup.in.access_mask    = 0;
	
	s->creategroup.out.group_handle  = &s->group_handle;
	s->creategroup.out.rid           = &s->group_rid;
 	
	subreq = dcerpc_samr_CreateDomainGroup_r_send(s, c->event_ctx,
						      s->binding_handle,
						      &s->creategroup);
	if (composite_nomem(subreq, c)) return c;

	tevent_req_set_callback(subreq, continue_groupadd_created, c);
	return c;
}


NTSTATUS libnet_rpc_groupadd_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				  struct libnet_rpc_groupadd *io)
{
	NTSTATUS status;
	struct groupadd_state *s;
	
	status = composite_wait(c);
	if (NT_STATUS_IS_OK(status) && io) {
		s = talloc_get_type(c->private_data, struct groupadd_state);
		io->out.group_handle = s->group_handle;
	}

	talloc_free(c);
	return status;
}


static void continue_groupadd_created(struct tevent_req *subreq)
{
	struct composite_context *c;
	struct groupadd_state *s;

	c = tevent_req_callback_data(subreq, struct composite_context);
	s = talloc_get_type(c->private_data, struct groupadd_state);

	c->status = dcerpc_samr_CreateDomainGroup_r_recv(subreq, s);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(c)) return;

	c->status = s->creategroup.out.result;
	if (!NT_STATUS_IS_OK(c->status)) {
		composite_error(c, c->status);
		return;
	}

	composite_done(c);
}


NTSTATUS libnet_rpc_groupadd(struct tevent_context *ev,
			     struct dcerpc_binding_handle *b,
			     TALLOC_CTX *mem_ctx,
			     struct libnet_rpc_groupadd *io)
{
	struct composite_context *c;

	c = libnet_rpc_groupadd_send(mem_ctx, ev, b, io, NULL);
	return libnet_rpc_groupadd_recv(c, mem_ctx, io);
}
