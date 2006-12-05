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
#include "libcli/cldap/cldap.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/db_wrap.h"
#include "dsdb/samdb/samdb.h"

struct libnet_UnbecomeDC_state {
	struct composite_context *creq;

	struct libnet_context *libnet;

	struct {
		struct cldap_socket *sock;
		struct cldap_netlogon io;
		struct nbt_cldap_netlogon_5 netlogon5;
	} cldap;

	struct {
		struct ldb_context *ldb;
	} ldap;

	struct {
		/* input */
		const char *dns_name;
		const char *netbios_name;

		/* constructed */
		struct GUID guid;
		const char *dn_str;
	} domain;

	struct {
		/* constructed */
		const char *config_dn_str;
	} forest;

	struct {
		/* input */
		const char *address;

		/* constructed */
		const char *dns_name;
		const char *netbios_name;
		const char *site_name;
	} source_dsa;

	struct {
		/* input */
		const char *netbios_name;

		/* constructed */
		const char *dns_name;
		const char *site_name;
		const char *computer_dn_str;
		const char *server_dn_str;
		uint32_t user_account_control;
	} dest_dsa;
};

static void unbecomeDC_connect_ldap(struct libnet_UnbecomeDC_state *s);

static void unbecomeDC_recv_cldap(struct cldap_request *req)
{
	struct libnet_UnbecomeDC_state *s = talloc_get_type(req->async.private,
					    struct libnet_UnbecomeDC_state);
	struct composite_context *c = s->creq;

	c->status = cldap_netlogon_recv(req, s, &s->cldap.io);
	if (!composite_is_ok(c)) return;

	s->cldap.netlogon5 = s->cldap.io.out.netlogon.logon5;

	s->domain.dns_name		= s->cldap.netlogon5.dns_domain;
	s->domain.netbios_name		= s->cldap.netlogon5.domain;
	s->domain.guid			= s->cldap.netlogon5.domain_uuid;

	s->source_dsa.dns_name		= s->cldap.netlogon5.pdc_dns_name;
	s->source_dsa.netbios_name	= s->cldap.netlogon5.pdc_name;
	s->source_dsa.site_name		= s->cldap.netlogon5.server_site;

	s->dest_dsa.site_name		= s->cldap.netlogon5.client_site;

	unbecomeDC_connect_ldap(s);
}

static void unbecomeDC_send_cldap(struct libnet_UnbecomeDC_state *s)
{
	struct composite_context *c = s->creq;
	struct cldap_request *req;

	s->cldap.io.in.dest_address	= s->source_dsa.address;
	s->cldap.io.in.realm		= s->domain.dns_name;
	s->cldap.io.in.host		= s->dest_dsa.netbios_name;
	s->cldap.io.in.user		= NULL;
	s->cldap.io.in.domain_guid	= NULL;
	s->cldap.io.in.domain_sid	= NULL;
	s->cldap.io.in.acct_control	= -1;
	s->cldap.io.in.version		= 6;

	s->cldap.sock = cldap_socket_init(s, s->libnet->event_ctx);
	if (composite_nomem(s->cldap.sock, c)) return;

	req = cldap_netlogon_send(s->cldap.sock, &s->cldap.io);
	if (composite_nomem(req, c)) return;
	req->async.fn		= unbecomeDC_recv_cldap;
	req->async.private	= s;
}

static NTSTATUS unbecomeDC_ldap_connect(struct libnet_UnbecomeDC_state *s)
{
	char *url;

	url = talloc_asprintf(s, "ldap://%s/", s->source_dsa.dns_name);
	NT_STATUS_HAVE_NO_MEMORY(url);

	s->ldap.ldb = ldb_wrap_connect(s, url,
				       NULL,
				       s->libnet->cred,
				       0, NULL);
	talloc_free(url);
	if (s->ldap.ldb == NULL) {
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	return NT_STATUS_OK;
}

static NTSTATUS unbecomeDC_ldap_rootdse(struct libnet_UnbecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	static const char *attrs[] = {
		"defaultNamingContext",
		"configurationNamingContext",
		NULL
	};

	basedn = ldb_dn_new(s, s->ldap.ldb, NULL);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap.ldb, basedn, LDB_SCOPE_BASE, 
			 "(objectClass=*)", attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	talloc_steal(s, r);

	s->domain.dn_str	= ldb_msg_find_attr_as_string(r->msgs[0], "defaultNamingContext", NULL);
	if (!s->domain.dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	talloc_steal(s, s->domain.dn_str);

	s->forest.config_dn_str	= ldb_msg_find_attr_as_string(r->msgs[0], "configurationNamingContext", NULL);
	if (!s->forest.config_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	talloc_steal(s, s->forest.config_dn_str);

	talloc_free(r);
	return NT_STATUS_OK;
}

static void unbecomeDC_connect_ldap(struct libnet_UnbecomeDC_state *s)
{
	struct composite_context *c = s->creq;

	c->status = unbecomeDC_ldap_connect(s);
	if (!composite_is_ok(c)) return;

	c->status = unbecomeDC_ldap_rootdse(s);
	if (!composite_is_ok(c)) return;

	composite_error(c, NT_STATUS_NOT_IMPLEMENTED);
}

struct composite_context *libnet_UnbecomeDC_send(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_UnbecomeDC *r)
{
	struct composite_context *c;
	struct libnet_UnbecomeDC_state *s;
	char *tmp_name;

	c = composite_create(mem_ctx, ctx->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct libnet_UnbecomeDC_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;
	s->creq		= c;
	s->libnet	= ctx;

	/* Domain input */
	s->domain.dns_name	= talloc_strdup(s, r->in.domain_dns_name);
	if (composite_nomem(s->domain.dns_name, c)) return c;
	s->domain.netbios_name	= talloc_strdup(s, r->in.domain_netbios_name);
	if (composite_nomem(s->domain.netbios_name, c)) return c;

	/* Source DSA input */
	s->source_dsa.address	= talloc_strdup(s, r->in.source_dsa_address);
	if (composite_nomem(s->source_dsa.address, c)) return c;

	/* Destination DSA input */
	s->dest_dsa.netbios_name= talloc_strdup(s, r->in.dest_dsa_netbios_name);
	if (composite_nomem(s->dest_dsa.netbios_name, c)) return c;

	/* Destination DSA dns_name construction */
	tmp_name		= strlower_talloc(s, s->dest_dsa.netbios_name);
	if (composite_nomem(tmp_name, c)) return c;
	s->dest_dsa.dns_name	= talloc_asprintf_append(tmp_name, ".%s",
				  			 s->domain.dns_name);
	if (composite_nomem(s->dest_dsa.dns_name, c)) return c;

	unbecomeDC_send_cldap(s);
	return c;
}

NTSTATUS libnet_UnbecomeDC_recv(struct composite_context *c, TALLOC_CTX *mem_ctx, struct libnet_UnbecomeDC *r)
{
	NTSTATUS status;

	status = composite_wait(c);

	ZERO_STRUCT(r->out);

	talloc_free(c);
	return status;
}

NTSTATUS libnet_UnbecomeDC(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_UnbecomeDC *r)
{
	NTSTATUS status;
	struct composite_context *c;
	c = libnet_UnbecomeDC_send(ctx, mem_ctx, r);
	status = libnet_UnbecomeDC_recv(c, mem_ctx, r);
	return status;
}
