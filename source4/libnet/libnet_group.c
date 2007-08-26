/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Rafal Szczesniak  2007
   
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


#include "includes.h"
#include "libnet/libnet.h"
#include "libcli/composite/composite.h"
#include "librpc/gen_ndr/lsa.h"


struct group_info_state {
	struct libnet_context *ctx;
	const char *domain_name;
	const char *group_name;
	struct libnet_LookupName lookup;
	struct libnet_DomainOpen domopen;
	struct libnet_rpc_groupinfo info;
	
	/* information about the progress */
	void (*monitor_fn)(struct monitor_msg *);
};


static void continue_domain_open_info(struct composite_context *ctx);
static void continue_name_found(struct composite_context *ctx);
static void continue_group_info(struct composite_context *ctx);


struct composite_context* libnet_GroupInfo_send(struct libnet_context *ctx,
						TALLOC_CTX *mem_ctx,
						struct libnet_GroupInfo *io,
						void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct group_info_state *s;
	BOOL prereq_met = False;
	struct composite_context *lookup_req;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, ctx->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct group_info_state);
	if (composite_nomem(s, c)) return c;

	c->private_data = s;

	s->monitor_fn = monitor;
	s->ctx = ctx;
	
	s->domain_name = talloc_strdup(c, io->in.domain_name);
	s->group_name  = talloc_strdup(c, io->in.group_name);

	/* prerequisite: make sure the domain is opened */
	prereq_met = samr_domain_opened(ctx, s->domain_name, &c, &s->domopen,
					continue_domain_open_info, monitor);
	if (!prereq_met) return c;

	s->lookup.in.name        = s->group_name;
	s->lookup.in.domain_name = s->domain_name;

	lookup_req = libnet_LookupName_send(s->ctx, c, &s->lookup, s->monitor_fn);
	if (composite_nomem(lookup_req, c)) return c;

	composite_continue(c, lookup_req, continue_name_found, c);
	return c;
}


static void continue_domain_open_info(struct composite_context *ctx)
{
	struct composite_context *c;
	struct group_info_state *s;
	struct composite_context *lookup_req;
	
	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct group_info_state);
	
	c->status = libnet_DomainOpen_recv(ctx, s->ctx, c, &s->domopen);
	if (!composite_is_ok(c)) return;

	s->lookup.in.name        = s->group_name;
	s->lookup.in.domain_name = s->domain_name;
	
	lookup_req = libnet_LookupName_send(s->ctx, c, &s->lookup, s->monitor_fn);
	if (composite_nomem(lookup_req, c)) return;
	
	composite_continue(c, lookup_req, continue_name_found, c);
}


static void continue_name_found(struct composite_context *ctx)
{
	struct composite_context *c;
	struct group_info_state *s;
	struct composite_context *info_req;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct group_info_state);
	
	c->status = libnet_LookupName_recv(ctx, c, &s->lookup);
	if (!composite_is_ok(c)) return;

	if (s->lookup.out.sid_type != SID_NAME_DOM_GRP &&
	    s->lookup.out.sid_type != SID_NAME_ALIAS) {
		composite_error(c, NT_STATUS_NO_SUCH_GROUP);
	}

	s->info.in.domain_handle = s->ctx->samr.handle;
	s->info.in.groupname     = s->group_name;
	s->info.in.sid           = s->lookup.out.sidstr;
	s->info.in.level         = GROUPINFOALL;
	
	info_req = libnet_rpc_groupinfo_send(s->ctx->samr.pipe, &s->info, s->monitor_fn);
	if (composite_nomem(info_req, c)) return;

	composite_continue(c, info_req, continue_group_info, c);
}


static void continue_group_info(struct composite_context *ctx)
{
	struct composite_context *c;
	struct group_info_state *s;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct group_info_state);

	c->status = libnet_rpc_groupinfo_recv(ctx, c, &s->info);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


NTSTATUS libnet_GroupInfo_recv(struct composite_context* c, TALLOC_CTX *mem_ctx,
			       struct libnet_GroupInfo *io)
{
	NTSTATUS status;
	struct group_info_state *s;
	
	status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		s = talloc_get_type(c->private_data, struct group_info_state);
		
		io->out.group_sid = talloc_steal(mem_ctx, s->lookup.out.sid);
		io->out.num_members = s->info.out.info.all.num_members;
		io->out.description = talloc_steal(mem_ctx, s->info.out.info.all.description.string);

		io->out.error_string = talloc_strdup(mem_ctx, "Success");
	}

	return status;
}


NTSTATUS libnet_GroupInfo(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			  struct libnet_GroupInfo *io)
{
	struct composite_context *c = libnet_GroupInfo_send(ctx, mem_ctx,
							    io, NULL);
	return libnet_GroupInfo_recv(c, mem_ctx, io);
}
