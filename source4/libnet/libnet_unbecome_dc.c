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
#include "dsdb/common/flags.h"
#include "librpc/gen_ndr/ndr_drsuapi_c.h"

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
		struct dcerpc_binding *binding;
		struct dcerpc_pipe *pipe;
		struct drsuapi_DsBind bind_r;
		struct GUID bind_guid;
		struct drsuapi_DsBindInfoCtr bind_info_ctr;
		struct drsuapi_DsBindInfo28 local_info28;
		struct drsuapi_DsBindInfo28 remote_info28;
		struct policy_handle bind_handle;
		struct drsuapi_DsRemoveDSServer rm_ds_srv_r;
	} drsuapi;

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

static void unbecomeDC_recv_cldap(struct cldap_request *req);

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

	s->dest_dsa.server_dn_str = talloc_asprintf(s, "CN=%s,CN=Servers,CN=%s,CN=Sites,%s",
						    s->dest_dsa.netbios_name,
						    s->dest_dsa.site_name,
				                    s->forest.config_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(s->dest_dsa.server_dn_str);

	talloc_free(r);
	return NT_STATUS_OK;
}

static NTSTATUS unbecomeDC_ldap_computer_object(struct libnet_UnbecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	char *filter;
	static const char *attrs[] = {
		"distinguishedName",
		"userAccountControl",
		NULL
	};

	basedn = ldb_dn_new(s, s->ldap.ldb, s->domain.dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	filter = talloc_asprintf(basedn, "(&(|(objectClass=user)(objectClass=computer))(sAMAccountName=%s$))",
				 s->dest_dsa.netbios_name);
	NT_STATUS_HAVE_NO_MEMORY(filter);

	ret = ldb_search(s->ldap.ldb, basedn, LDB_SCOPE_SUBTREE, 
			 filter, attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->dest_dsa.computer_dn_str	= samdb_result_string(r->msgs[0], "distinguishedName", NULL);
	if (!s->dest_dsa.computer_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	talloc_steal(s, s->dest_dsa.computer_dn_str);

	s->dest_dsa.user_account_control = samdb_result_uint(r->msgs[0], "userAccountControl", 0);

	talloc_free(r);
	return NT_STATUS_OK;
}

static NTSTATUS unbecomeDC_ldap_modify_computer(struct libnet_UnbecomeDC_state *s)
{
	int ret;
	struct ldb_message *msg;
	uint32_t user_account_control = UF_WORKSTATION_TRUST_ACCOUNT;
	uint32_t i;

	/* as the value is already as we want it to be, we're done */
	if (s->dest_dsa.user_account_control == user_account_control) {
		return NT_STATUS_OK;
	}

	/* make a 'modify' msg, and only for serverReference */
	msg = ldb_msg_new(s);
	NT_STATUS_HAVE_NO_MEMORY(msg);
	msg->dn = ldb_dn_new(msg, s->ldap.ldb, s->dest_dsa.computer_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(msg->dn);

	ret = ldb_msg_add_fmt(msg, "userAccountControl", "%u", user_account_control);
	if (ret != 0) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}

	/* mark all the message elements (should be just one)
	   as LDB_FLAG_MOD_REPLACE */
	for (i=0;i<msg->num_elements;i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	ret = ldb_modify(s->ldap.ldb, msg);
	talloc_free(msg);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	}

	s->dest_dsa.user_account_control = user_account_control;

	return NT_STATUS_OK;
}

static NTSTATUS unbecomeDC_ldap_move_computer(struct libnet_UnbecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	struct ldb_dn *old_dn;
	struct ldb_dn *new_dn;
	static const char *_1_1_attrs[] = {
		"1.1",
		NULL
	};

	basedn = ldb_dn_new_fmt(s, s->ldap.ldb, "<WKGUID=aa312825768811d1aded00c04fd8d5cd,%s>",
				s->domain.dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap.ldb, basedn, LDB_SCOPE_BASE,
			 "(objectClass=*)", _1_1_attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	old_dn = ldb_dn_new(r, s->ldap.ldb, s->dest_dsa.computer_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(old_dn);

	new_dn = r->msgs[0]->dn;

	if (!ldb_dn_add_child_fmt(new_dn, "CN=%s", s->dest_dsa.netbios_name)) {
		talloc_free(r);
		return NT_STATUS_NO_MEMORY;
	}

	if (ldb_dn_compare(old_dn, new_dn) == 0) {
		/* we don't need to rename if the old and new dn match */
		talloc_free(r);
		return NT_STATUS_OK;
	}

	ret = ldb_rename(s->ldap.ldb, old_dn, new_dn);
	if (ret != LDB_SUCCESS) {
		talloc_free(r);
		return NT_STATUS_LDAP(ret);
	}

	s->dest_dsa.computer_dn_str = ldb_dn_alloc_linearized(s, new_dn);
	NT_STATUS_HAVE_NO_MEMORY(s->dest_dsa.computer_dn_str);

	talloc_free(r);

	return NT_STATUS_OK;
}

static void unbecomeDC_drsuapi_connect_send(struct libnet_UnbecomeDC_state *s);

static void unbecomeDC_connect_ldap(struct libnet_UnbecomeDC_state *s)
{
	struct composite_context *c = s->creq;

	c->status = unbecomeDC_ldap_connect(s);
	if (!composite_is_ok(c)) return;

	c->status = unbecomeDC_ldap_rootdse(s);
	if (!composite_is_ok(c)) return;

	c->status = unbecomeDC_ldap_computer_object(s);
	if (!composite_is_ok(c)) return;

	c->status = unbecomeDC_ldap_modify_computer(s);
	if (!composite_is_ok(c)) return;

	c->status = unbecomeDC_ldap_move_computer(s);
	if (!composite_is_ok(c)) return;

	unbecomeDC_drsuapi_connect_send(s);
}

static void unbecomeDC_drsuapi_connect_recv(struct composite_context *creq);

static void unbecomeDC_drsuapi_connect_send(struct libnet_UnbecomeDC_state *s)
{
	struct composite_context *c = s->creq;
	struct composite_context *creq;
	char *binding_str;

	binding_str = talloc_asprintf(s, "ncacn_ip_tcp:%s[seal]", s->source_dsa.dns_name);
	if (composite_nomem(binding_str, c)) return;

	c->status = dcerpc_parse_binding(s, binding_str, &s->drsuapi.binding);
	talloc_free(binding_str);
	if (!composite_is_ok(c)) return;

	creq = dcerpc_pipe_connect_b_send(s, s->drsuapi.binding, &dcerpc_table_drsuapi,
					  s->libnet->cred, s->libnet->event_ctx);
	composite_continue(c, creq, unbecomeDC_drsuapi_connect_recv, s);
}

static void unbecomeDC_drsuapi_bind_send(struct libnet_UnbecomeDC_state *s);

static void unbecomeDC_drsuapi_connect_recv(struct composite_context *req)
{
	struct libnet_UnbecomeDC_state *s = talloc_get_type(req->async.private_data,
					    struct libnet_UnbecomeDC_state);
	struct composite_context *c = s->creq;

	c->status = dcerpc_pipe_connect_b_recv(req, s, &s->drsuapi.pipe);
	if (!composite_is_ok(c)) return;

	unbecomeDC_drsuapi_bind_send(s);
}

static void unbecomeDC_drsuapi_bind_recv(struct rpc_request *req);

static void unbecomeDC_drsuapi_bind_send(struct libnet_UnbecomeDC_state *s)
{
	struct composite_context *c = s->creq;
	struct rpc_request *req;
	struct drsuapi_DsBindInfo28 *bind_info28;

	GUID_from_string(DRSUAPI_DS_BIND_GUID, &s->drsuapi.bind_guid);

	bind_info28				= &s->drsuapi.local_info28;
	bind_info28->supported_extensions	= 0;
	bind_info28->site_guid			= GUID_zero();
	bind_info28->u1				= 508;
	bind_info28->repl_epoch			= 0;

	s->drsuapi.bind_info_ctr.length		= 28;
	s->drsuapi.bind_info_ctr.info.info28	= *bind_info28;

	s->drsuapi.bind_r.in.bind_guid = &s->drsuapi.bind_guid;
	s->drsuapi.bind_r.in.bind_info = &s->drsuapi.bind_info_ctr;
	s->drsuapi.bind_r.out.bind_handle = &s->drsuapi.bind_handle;

	req = dcerpc_drsuapi_DsBind_send(s->drsuapi.pipe, s, &s->drsuapi.bind_r);
	composite_continue_rpc(c, req, unbecomeDC_drsuapi_bind_recv, s);
}

static void unbecomeDC_drsuapi_remove_ds_server_send(struct libnet_UnbecomeDC_state *s);

static void unbecomeDC_drsuapi_bind_recv(struct rpc_request *req)
{
	struct libnet_UnbecomeDC_state *s = talloc_get_type(req->async.private,
					    struct libnet_UnbecomeDC_state);
	struct composite_context *c = s->creq;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	if (!W_ERROR_IS_OK(s->drsuapi.bind_r.out.result)) {
		composite_error(c, werror_to_ntstatus(s->drsuapi.bind_r.out.result));
		return;
	}

	ZERO_STRUCT(s->drsuapi.remote_info28);
	if (s->drsuapi.bind_r.out.bind_info) {
		switch (s->drsuapi.bind_r.out.bind_info->length) {
		case 24: {
			struct drsuapi_DsBindInfo24 *info24;
			info24 = &s->drsuapi.bind_r.out.bind_info->info.info24;
			s->drsuapi.remote_info28.supported_extensions	= info24->supported_extensions;
			s->drsuapi.remote_info28.site_guid		= info24->site_guid;
			s->drsuapi.remote_info28.u1			= info24->u1;
			s->drsuapi.remote_info28.repl_epoch		= 0;
			break;
		}
		case 28:
			s->drsuapi.remote_info28 = s->drsuapi.bind_r.out.bind_info->info.info28;
			break;
		}
	}

	unbecomeDC_drsuapi_remove_ds_server_send(s);
}

static void unbecomeDC_drsuapi_remove_ds_server_recv(struct rpc_request *req);

static void unbecomeDC_drsuapi_remove_ds_server_send(struct libnet_UnbecomeDC_state *s)
{
	struct composite_context *c = s->creq;
	struct rpc_request *req;
	struct drsuapi_DsRemoveDSServer *r = &s->drsuapi.rm_ds_srv_r;

	r->in.bind_handle	= &s->drsuapi.bind_handle;
	r->in.level		= 1;
	r->in.req.req1.server_dn= s->dest_dsa.server_dn_str;
	r->in.req.req1.domain_dn= s->domain.dn_str;
	r->in.req.req1.unknown	= 0x00000001;

	req = dcerpc_drsuapi_DsRemoveDSServer_send(s->drsuapi.pipe, s, r);
	composite_continue_rpc(c, req, unbecomeDC_drsuapi_remove_ds_server_recv, s);
}

static void unbecomeDC_drsuapi_remove_ds_server_recv(struct rpc_request *req)
{
	struct libnet_UnbecomeDC_state *s = talloc_get_type(req->async.private,
					    struct libnet_UnbecomeDC_state);
	struct composite_context *c = s->creq;
	struct drsuapi_DsRemoveDSServer *r = &s->drsuapi.rm_ds_srv_r;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	if (!W_ERROR_IS_OK(r->out.result)) {
		composite_error(c, werror_to_ntstatus(r->out.result));
		return;
	}

	if (r->out.level != 1) {
		composite_error(c, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}
		
	if (!W_ERROR_IS_OK(r->out.res.res1.status)) {
		composite_error(c, werror_to_ntstatus(r->out.res.res1.status));
		return;
	}

	composite_done(c);
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
