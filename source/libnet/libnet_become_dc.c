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

struct libnet_BecomeDC_state {
	struct composite_context *creq;

	struct libnet_context *libnet;

	struct {
		struct cldap_socket *sock;
		struct cldap_netlogon io;
		struct nbt_cldap_netlogon_5 netlogon5;
	} cldap;

	struct becomeDC_ldap {
		struct ldb_context *ldb;
		const struct ldb_message *rootdse;
	} ldap1;

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
		const char *dns_name;
		const char *root_dn_str;
		const char *config_dn_str;
		const char *schema_dn_str;
	} forest;

	struct {
		/* input */
		const char *address;

		/* constructed */
		const char *dns_name;
		const char *netbios_name;
		const char *site_name;
		const char *server_dn_str;
		const char *ntds_dn_str;
	} source_dsa;

	struct {
		/* input */
		const char *netbios_name;

		/* constructed */
		const char *dns_name;
		const char *site_name;
		const char *computer_dn_str;
		const char *server_dn_str;
		const char *ntds_dn_str;
	} dest_dsa;

	struct {
		uint32_t domain_behavior_version;
		uint32_t config_behavior_version;
		uint32_t schema_object_version;
		uint32_t w2k3_update_revision;
	} ads_options;

	struct becomeDC_fsmo {
		const char *dns_name;
		const char *server_dn_str;
		const char *ntds_dn_str;
		struct GUID ntds_guid;
	} infrastructure_fsmo;

	struct becomeDC_fsmo rid_manager_fsmo;
};

static void becomeDC_connect_ldap1(struct libnet_BecomeDC_state *s);

static void becomeDC_recv_cldap(struct cldap_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;

	c->status = cldap_netlogon_recv(req, s, &s->cldap.io);
	if (!composite_is_ok(c)) return;

	s->cldap.netlogon5 = s->cldap.io.out.netlogon.logon5;

	s->domain.dns_name		= s->cldap.netlogon5.dns_domain;
	s->domain.netbios_name		= s->cldap.netlogon5.domain;
	s->domain.guid			= s->cldap.netlogon5.domain_uuid;

	s->forest.dns_name		= s->cldap.netlogon5.forest;

	s->source_dsa.dns_name		= s->cldap.netlogon5.pdc_dns_name;
	s->source_dsa.netbios_name	= s->cldap.netlogon5.pdc_name;
	s->source_dsa.site_name		= s->cldap.netlogon5.server_site;

	s->dest_dsa.site_name		= s->cldap.netlogon5.client_site;

	becomeDC_connect_ldap1(s);
}

static void becomeDC_send_cldap(struct libnet_BecomeDC_state *s)
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
	req->async.fn		= becomeDC_recv_cldap;
	req->async.private	= s;
}

static NTSTATUS becomeDC_ldap_connect(struct libnet_BecomeDC_state *s, struct becomeDC_ldap *ldap)
{
	char *url;

	url = talloc_asprintf(s, "ldap://%s/", s->source_dsa.dns_name);
	NT_STATUS_HAVE_NO_MEMORY(url);

	ldap->ldb = ldb_wrap_connect(s, url,
				     NULL,
				     s->libnet->cred,
				     0, NULL);
	talloc_free(url);
	if (ldap->ldb == NULL) {
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_rootdse(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	static const char *attrs[] = {
		"*",
		NULL
	};

	basedn = ldb_dn_new(s, s->ldap1.ldb, NULL);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_BASE, 
			 "(objectClass=*)", attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	talloc_steal(s, r);

	s->ldap1.rootdse = r->msgs[0];

	s->domain.dn_str	= ldb_msg_find_attr_as_string(s->ldap1.rootdse, "defaultNamingContext", NULL);
	if (!s->domain.dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;

	s->forest.root_dn_str	= ldb_msg_find_attr_as_string(s->ldap1.rootdse, "rootDomainNamingContext", NULL);
	if (!s->forest.root_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	s->forest.config_dn_str	= ldb_msg_find_attr_as_string(s->ldap1.rootdse, "configurationNamingContext", NULL);
	if (!s->forest.config_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	s->forest.schema_dn_str	= ldb_msg_find_attr_as_string(s->ldap1.rootdse, "schemaNamingContext", NULL);
	if (!s->forest.schema_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;

	s->source_dsa.server_dn_str	= ldb_msg_find_attr_as_string(s->ldap1.rootdse, "serverName", NULL);
	if (!s->source_dsa.server_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	s->source_dsa.ntds_dn_str	= ldb_msg_find_attr_as_string(s->ldap1.rootdse, "dsServiceName", NULL);
	if (!s->source_dsa.ntds_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;

	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_config_behavior_version(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	static const char *attrs[] = {
		"msDs-Behavior-Version",
		NULL
	};

	basedn = ldb_dn_new(s, s->ldap1.ldb, s->forest.config_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_ONELEVEL,
			 "(cn=Partitions)", attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->ads_options.config_behavior_version = ldb_msg_find_attr_as_uint(r->msgs[0], "msDs-Behavior-Version", 0);

	talloc_free(r);
	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_domain_behavior_version(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	static const char *attrs[] = {
		"msDs-Behavior-Version",
		NULL
	};

	basedn = ldb_dn_new(s, s->ldap1.ldb, s->domain.dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_BASE,
			 "(objectClass=*)", attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->ads_options.domain_behavior_version = ldb_msg_find_attr_as_uint(r->msgs[0], "msDs-Behavior-Version", 0);

	talloc_free(r);
	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_schema_object_version(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	static const char *attrs[] = {
		"objectVersion",
		NULL
	};

	basedn = ldb_dn_new(s, s->ldap1.ldb, s->forest.schema_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_BASE,
			 "(objectClass=*)", attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->ads_options.schema_object_version = ldb_msg_find_attr_as_uint(r->msgs[0], "objectVersion", 0);

	talloc_free(r);
	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_w2k3_update_revision(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	static const char *attrs[] = {
		"revision",
		NULL
	};

	basedn = ldb_dn_new_fmt(s, s->ldap1.ldb, "CN=Windows2003Update,CN=DomainUpdates,CN=System,%s",
				s->domain.dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_BASE,
			 "(objectClass=*)", attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->ads_options.w2k3_update_revision = ldb_msg_find_attr_as_uint(r->msgs[0], "revision", 0);

	talloc_free(r);
	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_infrastructure_fsmo(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	struct ldb_dn *ntds_dn;
	struct ldb_dn *server_dn;
	static const char *_1_1_attrs[] = {
		"1.1",
		NULL
	};
	static const char *fsmo_attrs[] = {
		"fSMORoleOwner",
		NULL
	};
	static const char *dns_attrs[] = {
		"dnsHostName",
		NULL
	};
	static const char *guid_attrs[] = {
		"objectGUID",
		NULL
	};

	basedn = ldb_dn_new_fmt(s, s->ldap1.ldb, "<WKGUID=2fbac1870ade11d297c400c04fd8d5cd,%s>",
				s->domain.dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_BASE,
			 "(objectClass=*)", _1_1_attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	basedn = talloc_steal(s, r->msgs[0]->dn);
	talloc_free(r);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_BASE,
			 "(objectClass=*)", fsmo_attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->infrastructure_fsmo.ntds_dn_str	= samdb_result_string(r->msgs[0], "fSMORoleOwner", NULL);
	if (!s->infrastructure_fsmo.ntds_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	talloc_steal(s, s->infrastructure_fsmo.ntds_dn_str);

	talloc_free(r);

	ntds_dn = ldb_dn_new(s, s->ldap1.ldb, s->infrastructure_fsmo.ntds_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(ntds_dn);

	server_dn = ldb_dn_get_parent(s, ntds_dn);
	NT_STATUS_HAVE_NO_MEMORY(server_dn);

	s->infrastructure_fsmo.server_dn_str = ldb_dn_alloc_linearized(s, server_dn);
	NT_STATUS_HAVE_NO_MEMORY(s->infrastructure_fsmo.server_dn_str);

	ret = ldb_search(s->ldap1.ldb, server_dn, LDB_SCOPE_BASE,
			 "(objectClass=*)", dns_attrs, &r);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->infrastructure_fsmo.dns_name	= samdb_result_string(r->msgs[0], "dnsHostName", NULL);
	if (!s->infrastructure_fsmo.dns_name) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	talloc_steal(s, s->infrastructure_fsmo.dns_name);

	talloc_free(r);

	ret = ldb_search(s->ldap1.ldb, ntds_dn, LDB_SCOPE_BASE,
			 "(objectClass=*)", guid_attrs, &r);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->infrastructure_fsmo.ntds_guid = samdb_result_guid(r->msgs[0], "objectGUID");

	talloc_free(r);

	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_rid_manager_fsmo(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	const char *reference_dn_str;
	struct ldb_dn *ntds_dn;
	struct ldb_dn *server_dn;
	static const char *rid_attrs[] = {
		"rIDManagerReference",
		NULL
	};
	static const char *fsmo_attrs[] = {
		"fSMORoleOwner",
		NULL
	};
	static const char *dns_attrs[] = {
		"dnsHostName",
		NULL
	};
	static const char *guid_attrs[] = {
		"objectGUID",
		NULL
	};

	basedn = ldb_dn_new(s, s->ldap1.ldb, s->domain.dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_BASE,
			 "(objectClass=*)", rid_attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	reference_dn_str	= samdb_result_string(r->msgs[0], "rIDManagerReference", NULL);
	if (!reference_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;

	basedn = ldb_dn_new(s, s->ldap1.ldb, reference_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	talloc_free(r);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_BASE,
			 "(objectClass=*)", fsmo_attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->rid_manager_fsmo.ntds_dn_str	= samdb_result_string(r->msgs[0], "fSMORoleOwner", NULL);
	if (!s->rid_manager_fsmo.ntds_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	talloc_steal(s, s->rid_manager_fsmo.ntds_dn_str);

	talloc_free(r);

	ntds_dn = ldb_dn_new(s, s->ldap1.ldb, s->rid_manager_fsmo.ntds_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(ntds_dn);

	server_dn = ldb_dn_get_parent(s, ntds_dn);
	NT_STATUS_HAVE_NO_MEMORY(server_dn);

	s->rid_manager_fsmo.server_dn_str = ldb_dn_alloc_linearized(s, server_dn);
	NT_STATUS_HAVE_NO_MEMORY(s->rid_manager_fsmo.server_dn_str);

	ret = ldb_search(s->ldap1.ldb, server_dn, LDB_SCOPE_BASE,
			 "(objectClass=*)", dns_attrs, &r);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->rid_manager_fsmo.dns_name	= samdb_result_string(r->msgs[0], "dnsHostName", NULL);
	if (!s->rid_manager_fsmo.dns_name) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	talloc_steal(s, s->rid_manager_fsmo.dns_name);

	talloc_free(r);

	ret = ldb_search(s->ldap1.ldb, ntds_dn, LDB_SCOPE_BASE,
			 "(objectClass=*)", guid_attrs, &r);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->rid_manager_fsmo.ntds_guid = samdb_result_guid(r->msgs[0], "objectGUID");

	talloc_free(r);

	return NT_STATUS_OK;
}


static void becomeDC_connect_ldap1(struct libnet_BecomeDC_state *s)
{
	struct composite_context *c = s->creq;

	c->status = becomeDC_ldap_connect(s, &s->ldap1);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_rootdse(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_config_behavior_version(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_domain_behavior_version(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_schema_object_version(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_w2k3_update_revision(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_infrastructure_fsmo(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_rid_manager_fsmo(s);
	if (!composite_is_ok(c)) return;

	composite_error(c, NT_STATUS_NOT_IMPLEMENTED);
}

struct composite_context *libnet_BecomeDC_send(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r)
{
	struct composite_context *c;
	struct libnet_BecomeDC_state *s;
	char *tmp_name;

	c = composite_create(mem_ctx, ctx->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct libnet_BecomeDC_state);
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

	becomeDC_send_cldap(s);
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
