/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher	2006

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

#include "includes.h"
#include "libnet/libnet.h"
#include "libcli/composite/composite.h"

struct libnet_BecomeDC_state {
	struct libnet_context *libnet;

	struct becomeDC_ldap {
		struct ldb_context *ldb;
		struct ldb_message *rootdse;
	} ldap1;

	struct {
		const char *dns_name;
		const char *netbios_name;
		const char *domain_dn_str;
		const char *config_dn_str;
		const char *schema_dn_str;
	} domain_info;

	struct {
		const char *dns_name;
		const char *netbios_name;
		const char *address;
		const char *server_dn_str;
		const char *ntds_dn_str;
	} source_dsa;

	struct {
		const char *hostname;
	} dest_dsa;
};


static NTSTATUS becomeDC_ldap_connect(struct libnet_BecomeDC_state *s, struct becomeDC_ldap *ldap)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS becomeDC_ldap1_requests(struct libnet_BecomeDC_state *s)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

struct composite_context *libnet_BecomeDC_send(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r)
{
	struct composite_context *c;
	struct libnet_BecomeDC_state *s;

	c = composite_create(mem_ctx, ctx->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct libnet_BecomeDC_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	s->libnet = ctx;

	s->source_dsa.address = talloc_strdup(s, r->in.dest_address);
	if (composite_nomem(s->source_dsa.address, c)) return c;

	c->status = becomeDC_ldap_connect(s, &s->ldap1);
	if (!composite_is_ok(c)) return c;

	c->status = becomeDC_ldap1_requests(s);
	if (!composite_is_ok(c)) return c;

	return c;
}

NTSTATUS libnet_BecomeDC_recv(struct composite_context *c, TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r)
{
	NTSTATUS status;

	status = composite_wait(c);

	ZERO_STRUCT(r->out);

	talloc_free(c);
	return status;
}

NTSTATUS libnet_BecomeDC(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r)
{
	NTSTATUS status;
	struct composite_context *c;
	c = libnet_BecomeDC_send(ctx, mem_ctx, r);
	status = libnet_BecomeDC_recv(c, mem_ctx, r);
	return status;
}
