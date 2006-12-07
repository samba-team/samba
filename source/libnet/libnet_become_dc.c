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
#include "libcli/security/security.h"

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
	} ldap1, ldap2;

	struct becomeDC_drsuapi {
		struct libnet_BecomeDC_state *s;
		struct dcerpc_binding *binding;
		struct dcerpc_pipe *pipe;
		struct drsuapi_DsBind bind_r;
		struct GUID bind_guid;
		struct drsuapi_DsBindInfoCtr bind_info_ctr;
		struct drsuapi_DsBindInfo28 local_info28;
		struct drsuapi_DsBindInfo28 remote_info28;
		struct policy_handle bind_handle;
	} drsuapi1;

	struct {
		/* input */
		const char *dns_name;
		const char *netbios_name;
		const struct dom_sid *sid;

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
		struct GUID site_guid;
		const char *computer_dn_str;
		const char *server_dn_str;
		const char *ntds_dn_str;
		struct GUID invocation_id;
		uint32_t user_account_control;
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

static NTSTATUS becomeDC_ldap1_site_object(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;

	basedn = ldb_dn_new_fmt(s, s->ldap1.ldb, "CN=%s,CN=Sites,%s",
				s->dest_dsa.site_name,
				s->forest.config_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_BASE, 
			 "(objectClass=*)", NULL, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->dest_dsa.site_guid = samdb_result_guid(r->msgs[0], "objectGUID");

	talloc_free(r);
	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_computer_object(struct libnet_BecomeDC_state *s)
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

	basedn = ldb_dn_new(s, s->ldap1.ldb, s->domain.dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	filter = talloc_asprintf(basedn, "(&(|(objectClass=user)(objectClass=computer))(sAMAccountName=%s$))",
				 s->dest_dsa.netbios_name);
	NT_STATUS_HAVE_NO_MEMORY(filter);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_SUBTREE, 
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

static NTSTATUS becomeDC_ldap1_server_object_1(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	const char *server_reference_dn_str;
	struct ldb_dn *server_reference_dn;
	struct ldb_dn *computer_dn;

	basedn = ldb_dn_new_fmt(s, s->ldap1.ldb, "CN=%s,CN=Servers,CN=%s,CN=Sites,%s",
				s->dest_dsa.netbios_name,
				s->dest_dsa.site_name,
				s->forest.config_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap1.ldb, basedn, LDB_SCOPE_BASE, 
			 "(objectClass=*)", NULL, &r);
	talloc_free(basedn);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* if the object doesn't exist, we'll create it later */
		return NT_STATUS_OK;
	} else if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	server_reference_dn_str = samdb_result_string(r->msgs[0], "serverReference", NULL);
	if (server_reference_dn_str) {
		server_reference_dn	= ldb_dn_new(r, s->ldap1.ldb, server_reference_dn_str);
		NT_STATUS_HAVE_NO_MEMORY(server_reference_dn);

		computer_dn		= ldb_dn_new(r, s->ldap1.ldb, s->dest_dsa.computer_dn_str);
		NT_STATUS_HAVE_NO_MEMORY(computer_dn);

		/*
		 * if the server object belongs to another DC in another domain in the forest,
		 * we should not touch this object!
		 */
		if (ldb_dn_compare(computer_dn, server_reference_dn) != 0) {
			talloc_free(r);
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
	}

	/* if the server object is already for the dest_dsa, then we don't need to create it */
	s->dest_dsa.server_dn_str	= samdb_result_string(r->msgs[0], "distinguishedName", NULL);
	if (!s->dest_dsa.server_dn_str) return NT_STATUS_INVALID_NETWORK_RESPONSE;
	talloc_steal(s, s->dest_dsa.server_dn_str);

	talloc_free(r);
	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_server_object_2(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_result *r;
	struct ldb_dn *basedn;
	const char *server_reference_bl_dn_str;
	static const char *attrs[] = {
		"serverReferenceBL",
		NULL
	};

	/* if the server_dn_str has a valid value, we skip this lookup */
	if (s->dest_dsa.server_dn_str) return NT_STATUS_OK;

	basedn = ldb_dn_new(s, s->ldap1.ldb, s->dest_dsa.computer_dn_str);
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

	server_reference_bl_dn_str = samdb_result_string(r->msgs[0], "serverReferenceBL", NULL);
	if (!server_reference_bl_dn_str) {
		/* if no back link is present, we're done for this function */
		talloc_free(r);
		return NT_STATUS_OK;
	}

	/* if the server object is already for the dest_dsa, then we don't need to create it */
	s->dest_dsa.server_dn_str	= samdb_result_string(r->msgs[0], "serverReferenceBL", NULL);
	if (s->dest_dsa.server_dn_str) {
		/* if a back link is present, we know that the server object is present */
		talloc_steal(s, s->dest_dsa.server_dn_str);
	}

	talloc_free(r);
	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_server_object_add(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_message *msg;
	char *server_dn_str;

	/* if the server_dn_str has a valid value, we skip this lookup */
	if (s->dest_dsa.server_dn_str) return NT_STATUS_OK;

	msg = ldb_msg_new(s);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	msg->dn = ldb_dn_new_fmt(msg, s->ldap1.ldb, "CN=%s,CN=Servers,CN=%s,CN=Sites,%s",
				 s->dest_dsa.netbios_name,
				 s->dest_dsa.site_name,
				 s->forest.config_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(msg->dn);

	ret = ldb_msg_add_string(msg, "objectClass", "server");
	if (ret != 0) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}
	ret = ldb_msg_add_string(msg, "systemFlags", "50000000");
	if (ret != 0) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}
	ret = ldb_msg_add_string(msg, "serverReference", s->dest_dsa.computer_dn_str);
	if (ret != 0) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}

	server_dn_str = ldb_dn_alloc_linearized(s, msg->dn);
	NT_STATUS_HAVE_NO_MEMORY(server_dn_str);

	ret = ldb_add(s->ldap1.ldb, msg);
	talloc_free(msg);
	if (ret != LDB_SUCCESS) {
		talloc_free(server_dn_str);
		return NT_STATUS_LDAP(ret);
	}

	s->dest_dsa.server_dn_str = server_dn_str;

	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap1_server_object_modify(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_message *msg;
	uint32_t i;

	/* make a 'modify' msg, and only for serverReference */
	msg = ldb_msg_new(s);
	NT_STATUS_HAVE_NO_MEMORY(msg);
	msg->dn = ldb_dn_new(msg, s->ldap1.ldb, s->dest_dsa.server_dn_str);
	NT_STATUS_HAVE_NO_MEMORY(msg->dn);

	ret = ldb_msg_add_string(msg, "serverReference", s->dest_dsa.computer_dn_str);
	if (ret != 0) {
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}

	/* mark all the message elements (should be just one)
	   as LDB_FLAG_MOD_ADD */
	for (i=0;i<msg->num_elements;i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_ADD;
	}

	ret = ldb_modify(s->ldap1.ldb, msg);
	if (ret == LDB_SUCCESS) {
		talloc_free(msg);
		return NT_STATUS_OK;
	} else if (ret == LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS) {
		/* retry with LDB_FLAG_MOD_REPLACE */
	} else {
		talloc_free(msg);
		return NT_STATUS_LDAP(ret);
	}

	/* mark all the message elements (should be just one)
	   as LDB_FLAG_MOD_REPLACE */
	for (i=0;i<msg->num_elements;i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	ret = ldb_modify(s->ldap1.ldb, msg);
	talloc_free(msg);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	}

	return NT_STATUS_OK;
}

static void becomeDC_drsuapi_connect_send(struct libnet_BecomeDC_state *s,
					  struct becomeDC_drsuapi *drsuapi,
					  void (*recv_fn)(struct composite_context *req));
static void becomeDC_drsuapi1_connect_recv(struct composite_context *req);
static void becomeDC_connect_ldap2(struct libnet_BecomeDC_state *s);

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

	c->status = becomeDC_ldap1_site_object(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_computer_object(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_server_object_1(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_server_object_2(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_server_object_add(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap1_server_object_modify(s);
	if (!composite_is_ok(c)) return;

	becomeDC_drsuapi_connect_send(s, &s->drsuapi1, becomeDC_drsuapi1_connect_recv);
}

static void becomeDC_drsuapi_connect_send(struct libnet_BecomeDC_state *s,
					  struct becomeDC_drsuapi *drsuapi,
					  void (*recv_fn)(struct composite_context *req))
{
	struct composite_context *c = s->creq;
	struct composite_context *creq;
	char *binding_str;

	drsuapi->s = s;

	binding_str = talloc_asprintf(s, "ncacn_ip_tcp:%s[krb5,seal]", s->source_dsa.dns_name);
	if (composite_nomem(binding_str, c)) return;

	c->status = dcerpc_parse_binding(s, binding_str, &drsuapi->binding);
	talloc_free(binding_str);
	if (!composite_is_ok(c)) return;

	creq = dcerpc_pipe_connect_b_send(s, drsuapi->binding, &dcerpc_table_drsuapi,
					  s->libnet->cred, s->libnet->event_ctx);
	composite_continue(c, creq, recv_fn, s);
}

static void becomeDC_drsuapi_bind_send(struct libnet_BecomeDC_state *s,
				       struct becomeDC_drsuapi *drsuapi,
				       void (*recv_fn)(struct rpc_request *req));
static void becomeDC_drsuapi1_bind_recv(struct rpc_request *req);

static void becomeDC_drsuapi1_connect_recv(struct composite_context *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private_data,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;

	c->status = dcerpc_pipe_connect_b_recv(req, s, &s->drsuapi1.pipe);
	if (!composite_is_ok(c)) return;

	becomeDC_drsuapi_bind_send(s, &s->drsuapi1, becomeDC_drsuapi1_bind_recv);
}

static void becomeDC_drsuapi_bind_send(struct libnet_BecomeDC_state *s,
				       struct becomeDC_drsuapi *drsuapi,
				       void (*recv_fn)(struct rpc_request *req))
{
	struct composite_context *c = s->creq;
	struct rpc_request *req;
	struct drsuapi_DsBindInfo28 *bind_info28;

	GUID_from_string(DRSUAPI_DS_BIND_GUID_W2K3, &drsuapi->bind_guid);

	bind_info28				= &drsuapi->local_info28;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_BASE;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ASYNC_REPLICATION;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_REMOVEAPI;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_MOVEREQ_V2;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHG_COMPRESS;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V1;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_RESTORE_USN_OPTIMIZATION;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY_V2;
	if (s->ads_options.domain_behavior_version == 2) {
		/* TODO: find out how this is really triggered! */
		bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_LINKED_VALUE_REPLICATION;
	}
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V2;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_INSTANCE_TYPE_NOT_REQ_ON_MOD;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_CRYPTO_BIND;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GET_REPL_INFO;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_STRONG_ENCRYPTION;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V01;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_TRANSITIVE_MEMBERSHIP;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADD_SID_HISTORY;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_POST_BETA3;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_00100000;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GET_MEMBERSHIPS2;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V6;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_NONDOMAIN_NCS;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V5;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V6;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V7;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_VERIFY_OBJECT;
#if 0 /* we don't support XPRESS compression yet */
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_XPRESS_COMPRESS;
#endif
	bind_info28->site_guid			= s->dest_dsa.site_guid;
	if (s->ads_options.domain_behavior_version == 2) {
		/* TODO: find out how this is really triggered! */
		bind_info28->u1				= 528;
	} else {
		bind_info28->u1				= 516;
	}
	bind_info28->repl_epoch			= 0;

	drsuapi->bind_info_ctr.length		= 28;
	drsuapi->bind_info_ctr.info.info28	= *bind_info28;

	drsuapi->bind_r.in.bind_guid = &drsuapi->bind_guid;
	drsuapi->bind_r.in.bind_info = &drsuapi->bind_info_ctr;
	drsuapi->bind_r.out.bind_handle = &drsuapi->bind_handle;

	req = dcerpc_drsuapi_DsBind_send(drsuapi->pipe, s, &drsuapi->bind_r);
	composite_continue_rpc(c, req, recv_fn, s);
}

static void becomeDC_drsuapi1_add_entry_send(struct libnet_BecomeDC_state *s);

static void becomeDC_drsuapi1_bind_recv(struct rpc_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	if (!W_ERROR_IS_OK(s->drsuapi1.bind_r.out.result)) {
		composite_error(c, werror_to_ntstatus(s->drsuapi1.bind_r.out.result));
		return;
	}

	ZERO_STRUCT(s->drsuapi1.remote_info28);
	if (s->drsuapi1.bind_r.out.bind_info) {
		switch (s->drsuapi1.bind_r.out.bind_info->length) {
		case 24: {
			struct drsuapi_DsBindInfo24 *info24;
			info24 = &s->drsuapi1.bind_r.out.bind_info->info.info24;
			s->drsuapi1.remote_info28.supported_extensions	= info24->supported_extensions;
			s->drsuapi1.remote_info28.site_guid		= info24->site_guid;
			s->drsuapi1.remote_info28.u1			= info24->u1;
			s->drsuapi1.remote_info28.repl_epoch		= 0;
			break;
		}
		case 28:
			s->drsuapi1.remote_info28 = s->drsuapi1.bind_r.out.bind_info->info.info28;
			break;
		}
	}

	becomeDC_drsuapi1_add_entry_send(s);
}

static void becomeDC_drsuapi1_add_entry_recv(struct rpc_request *req);

static void becomeDC_drsuapi1_add_entry_send(struct libnet_BecomeDC_state *s)
{
	struct composite_context *c = s->creq;
	struct rpc_request *req;
	struct drsuapi_DsAddEntry *r;
	struct drsuapi_DsReplicaObjectIdentifier *identifier;
	uint32_t num_attrs, i = 0;
	struct drsuapi_DsReplicaAttribute *attrs;
	struct dom_sid zero_sid;

	ZERO_STRUCT(zero_sid);

	/* choose a random invocationId */
	s->dest_dsa.invocation_id = GUID_random();

	r = talloc_zero(s, struct drsuapi_DsAddEntry);
	if (composite_nomem(r, c)) return;

	/* setup identifier */
	identifier		= talloc(r, struct drsuapi_DsReplicaObjectIdentifier);
	if (composite_nomem(identifier, c)) return;
	identifier->guid	= GUID_zero();
	identifier->sid		= zero_sid;
	identifier->dn		= talloc_asprintf(identifier, "CN=NTDS Settings,%s",
						  s->dest_dsa.server_dn_str);
	if (composite_nomem(identifier->dn, c)) return;

	/* allocate attribute array */
	num_attrs	= 11;
	attrs		= talloc_array(r, struct drsuapi_DsReplicaAttribute, num_attrs);
	if (composite_nomem(attrs, c)) return;

	/* ntSecurityDescriptor */
	{
		struct drsuapi_DsAttributeValueSecurityDescriptor *vs;
		struct security_descriptor *v;
		struct dom_sid *domain_admins_sid;
		const char *domain_admins_sid_str;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueSecurityDescriptor, 1);
		if (composite_nomem(vs, c)) return;

		domain_admins_sid = dom_sid_add_rid(vs, s->domain.sid, DOMAIN_RID_ADMINS);
		if (composite_nomem(domain_admins_sid, c)) return;

		domain_admins_sid_str = dom_sid_string(domain_admins_sid, domain_admins_sid);
		if (composite_nomem(domain_admins_sid_str, c)) return;

		v = security_descriptor_create(vs,
					       /* owner: domain admins */
					       domain_admins_sid_str,
					       /* owner group: domain admins */
					       domain_admins_sid_str,
					       /* authenticated users */
					       SID_NT_AUTHENTICATED_USERS,
					       SEC_ACE_TYPE_ACCESS_ALLOWED,
					       SEC_STD_READ_CONTROL |
					       SEC_ADS_LIST |
					       SEC_ADS_READ_PROP |
					       SEC_ADS_LIST_OBJECT,
					       0,
					       /* domain admins */
					       domain_admins_sid_str,
					       SEC_ACE_TYPE_ACCESS_ALLOWED,
					       SEC_STD_REQUIRED |
					       SEC_ADS_CREATE_CHILD |
					       SEC_ADS_LIST |
					       SEC_ADS_SELF_WRITE |
					       SEC_ADS_READ_PROP |
					       SEC_ADS_WRITE_PROP |
					       SEC_ADS_DELETE_TREE |
					       SEC_ADS_LIST_OBJECT |
					       SEC_ADS_CONTROL_ACCESS,
					       0,
					       /* system */
					       SID_NT_SYSTEM,
					       SEC_ACE_TYPE_ACCESS_ALLOWED,
					       SEC_STD_REQUIRED |
					       SEC_ADS_CREATE_CHILD |
					       SEC_ADS_DELETE_CHILD |
					       SEC_ADS_LIST |
					       SEC_ADS_SELF_WRITE |
					       SEC_ADS_READ_PROP |
					       SEC_ADS_WRITE_PROP |
					       SEC_ADS_DELETE_TREE |
					       SEC_ADS_LIST_OBJECT |
					       SEC_ADS_CONTROL_ACCESS,
					       0,
					       /* end */
					       NULL);
		if (composite_nomem(v, c)) return;

		vs[0].sd		= v;

		attrs[i].attid						= DRSUAPI_ATTRIBUTE_ntSecurityDescriptor;
		attrs[i].value_ctr.security_descriptor.num_values	= 1;
		attrs[i].value_ctr.security_descriptor.values		= vs;

		i++;
	}

	/* objectClass: nTDSDSA */
	{
		struct drsuapi_DsAttributeValueObjectClassId *vs;
		enum drsuapi_DsObjectClassId *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueObjectClassId, 1);
		if (composite_nomem(vs, c)) return;

		v = talloc_array(vs, enum drsuapi_DsObjectClassId, 1);
		if (composite_nomem(v, c)) return;

		/* value for nTDSDSA */
		v[0]			= 0x0017002F;

		vs[0].objectClassId	= &v[0];

		attrs[i].attid					= DRSUAPI_ATTRIBUTE_objectClass;
		attrs[i].value_ctr.object_class_id.num_values	= 1;
		attrs[i].value_ctr.object_class_id.values	= vs;

		i++;
	}

	/* objectCategory: CN=NTDS-DSA,CN=Schema,... */
	{
		struct drsuapi_DsAttributeValueDNString *vs;
		struct drsuapi_DsReplicaObjectIdentifier3 *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueDNString, 1);
		if (composite_nomem(vs, c)) return;

		v = talloc_array(vs, struct drsuapi_DsReplicaObjectIdentifier3, 1);
		if (composite_nomem(v, c)) return;

		/* value for nTDSDSA */
		v[0].guid		= GUID_zero();
		v[0].sid		= zero_sid;
		v[0].dn			= talloc_asprintf(v, "CN=NTDS-DSA,%s",
							  s->forest.schema_dn_str);
		if (composite_nomem(v->dn, c)) return;

		vs[0].object		= &v[0];

		attrs[i].attid					= DRSUAPI_ATTRIBUTE_objectCategory;
		attrs[i].value_ctr.dn_string.num_values		= 1;
		attrs[i].value_ctr.dn_string.values		= vs;

		i++;
	}

	/* invocationId: random guid */
	{
		struct drsuapi_DsAttributeValueGUID *vs;
		struct GUID *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueGUID, 1);
		if (composite_nomem(vs, c)) return;

		v = talloc_array(vs, struct GUID, 1);
		if (composite_nomem(v, c)) return;

		/* value for nTDSDSA */
		v[0]			= s->dest_dsa.invocation_id;

		vs[0].guid		= &v[0];

		attrs[i].attid					= DRSUAPI_ATTRIBUTE_invocationId;
		attrs[i].value_ctr.guid.num_values		= 1;
		attrs[i].value_ctr.guid.values			= vs;

		i++;
	}

	/* hasMasterNCs: ... */
	{
		struct drsuapi_DsAttributeValueDNString *vs;
		struct drsuapi_DsReplicaObjectIdentifier3 *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueDNString, 3);
		if (composite_nomem(vs, c)) return;

		v = talloc_array(vs, struct drsuapi_DsReplicaObjectIdentifier3, 3);
		if (composite_nomem(v, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= zero_sid;
		v[0].dn			= s->forest.config_dn_str;

		v[1].guid		= GUID_zero();
		v[1].sid		= zero_sid;
		v[1].dn			= s->domain.dn_str;

		v[2].guid		= GUID_zero();
		v[2].sid		= zero_sid;
		v[2].dn			= s->forest.schema_dn_str;

		vs[0].object		= &v[0];
		vs[1].object		= &v[1];
		vs[2].object		= &v[2];

		attrs[i].attid					= DRSUAPI_ATTRIBUTE_hasMasterNCs;
		attrs[i].value_ctr.dn_string.num_values		= 3;
		attrs[i].value_ctr.dn_string.values		= vs;

		i++;
	}

	/* msDS-hasMasterNCs: ... */
	{
		struct drsuapi_DsAttributeValueDNString *vs;
		struct drsuapi_DsReplicaObjectIdentifier3 *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueDNString, 3);
		if (composite_nomem(vs, c)) return;

		v = talloc_array(vs, struct drsuapi_DsReplicaObjectIdentifier3, 3);
		if (composite_nomem(v, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= zero_sid;
		v[0].dn			= s->forest.config_dn_str;

		v[1].guid		= GUID_zero();
		v[1].sid		= zero_sid;
		v[1].dn			= s->domain.dn_str;

		v[2].guid		= GUID_zero();
		v[2].sid		= zero_sid;
		v[2].dn			= s->forest.schema_dn_str;

		vs[0].object		= &v[0];
		vs[1].object		= &v[1];
		vs[2].object		= &v[2];

		attrs[i].attid					= DRSUAPI_ATTRIBUTE_msDS_hasMasterNCs;
		attrs[i].value_ctr.dn_string.num_values		= 3;
		attrs[i].value_ctr.dn_string.values		= vs;

		i++;
	}

	/* dMDLocation: CN=Schema,... */
	{
		struct drsuapi_DsAttributeValueDNString *vs;
		struct drsuapi_DsReplicaObjectIdentifier3 *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueDNString, 1);
		if (composite_nomem(vs, c)) return;

		v = talloc_array(vs, struct drsuapi_DsReplicaObjectIdentifier3, 1);
		if (composite_nomem(v, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= zero_sid;
		v[0].dn			= s->forest.schema_dn_str;

		vs[0].object		= &v[0];

		attrs[i].attid					= DRSUAPI_ATTRIBUTE_dMDLocation;
		attrs[i].value_ctr.dn_string.num_values		= 1;
		attrs[i].value_ctr.dn_string.values		= vs;

		i++;
	}

	/* msDS-HasDomainNCs: <domain_partition> */
	{
		struct drsuapi_DsAttributeValueDNString *vs;
		struct drsuapi_DsReplicaObjectIdentifier3 *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueDNString, 1);
		if (composite_nomem(vs, c)) return;

		v = talloc_array(vs, struct drsuapi_DsReplicaObjectIdentifier3, 1);
		if (composite_nomem(v, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= zero_sid;
		v[0].dn			= s->domain.dn_str;

		vs[0].object		= &v[0];

		attrs[i].attid					= DRSUAPI_ATTRIBUTE_msDS_HasDomainNCs;
		attrs[i].value_ctr.dn_string.num_values		= 1;
		attrs[i].value_ctr.dn_string.values		= vs;

		i++;
	}

	/* msDS-Behavior-Version */
	{
		struct drsuapi_DsAttributeValueUINT32 *vs;
		uint32_t *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueUINT32, 1);
		if (composite_nomem(vs, c)) return;

		v = talloc_array(vs, uint32_t, 1);
		if (composite_nomem(v, c)) return;

		v[0]			= 0x00000002;

		vs[0].value		= &v[0];

		attrs[i].attid					= DRSUAPI_ATTRIBUTE_msDS_Behavior_Version;
		attrs[i].value_ctr.uint32.num_values		= 1;
		attrs[i].value_ctr.uint32.values		= vs;

		i++;
	}

	/* systemFlags */
	{
		struct drsuapi_DsAttributeValueUINT32 *vs;
		uint32_t *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueUINT32, 1);
		if (composite_nomem(vs, c)) return;

		v = talloc_array(vs, uint32_t, 1);
		if (composite_nomem(v, c)) return;

		v[0]			= SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE;

		vs[0].value		= &v[0];

		attrs[i].attid					= DRSUAPI_ATTRIBUTE_systemFlags;
		attrs[i].value_ctr.uint32.num_values		= 1;
		attrs[i].value_ctr.uint32.values		= vs;

		i++;
	}

	/* serverReference: ... */
	{
		struct drsuapi_DsAttributeValueDNString *vs;
		struct drsuapi_DsReplicaObjectIdentifier3 *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValueDNString, 1);
		if (composite_nomem(vs, c)) return;

		v = talloc_array(vs, struct drsuapi_DsReplicaObjectIdentifier3, 1);
		if (composite_nomem(v, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= zero_sid;
		v[0].dn			= s->dest_dsa.computer_dn_str;

		vs[0].object		= &v[0];

		attrs[i].attid					= DRSUAPI_ATTRIBUTE_serverReference;
		attrs[i].value_ctr.dn_string.num_values		= 1;
		attrs[i].value_ctr.dn_string.values		= vs;

		i++;
	}

	/* truncate the attribute list to the attribute count we have filled in */
	num_attrs = i;

	/* setup request structure */
	r->in.bind_handle						= &s->drsuapi1.bind_handle;
	r->in.level							= 2;
	r->in.req.req2.first_object.next_object				= NULL;
	r->in.req.req2.first_object.object.identifier			= identifier;
	r->in.req.req2.first_object.object.unknown1			= 0x00000000;	
	r->in.req.req2.first_object.object.attribute_ctr.num_attributes	= num_attrs;
	r->in.req.req2.first_object.object.attribute_ctr.attributes	= attrs;

	req = dcerpc_drsuapi_DsAddEntry_send(s->drsuapi1.pipe, r, r);
	composite_continue_rpc(c, req, becomeDC_drsuapi1_add_entry_recv, s);
}

static void becomeDC_drsuapi1_add_entry_recv(struct rpc_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;
	struct drsuapi_DsAddEntry *r = talloc_get_type(req->ndr.struct_ptr,
				       struct drsuapi_DsAddEntry);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	if (!W_ERROR_IS_OK(r->out.result)) {
		composite_error(c, werror_to_ntstatus(r->out.result));
		return;
	}

	becomeDC_connect_ldap2(s);
}

static NTSTATUS becomeDC_ldap2_modify_computer(struct libnet_BecomeDC_state *s)
{
	int ret;
	struct ldb_message *msg;
	uint32_t i;
	uint32_t user_account_control = UF_SERVER_TRUST_ACCOUNT |
					UF_TRUSTED_FOR_DELEGATION;

	/* as the value is already as we want it to be, we're done */
	if (s->dest_dsa.user_account_control == user_account_control) {
		return NT_STATUS_OK;
	}

	/* make a 'modify' msg, and only for serverReference */
	msg = ldb_msg_new(s);
	NT_STATUS_HAVE_NO_MEMORY(msg);
	msg->dn = ldb_dn_new(msg, s->ldap2.ldb, s->dest_dsa.computer_dn_str);
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

	ret = ldb_modify(s->ldap2.ldb, msg);
	talloc_free(msg);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	}

	s->dest_dsa.user_account_control = user_account_control;

	return NT_STATUS_OK;
}

static NTSTATUS becomeDC_ldap2_move_computer(struct libnet_BecomeDC_state *s)
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

	basedn = ldb_dn_new_fmt(s, s->ldap2.ldb, "<WKGUID=a361b2ffffd211d1aa4b00c04fd7d83a,%s>",
				s->domain.dn_str);
	NT_STATUS_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->ldap2.ldb, basedn, LDB_SCOPE_BASE,
			 "(objectClass=*)", _1_1_attrs, &r);
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	old_dn = ldb_dn_new(r, s->ldap2.ldb, s->dest_dsa.computer_dn_str);
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

	ret = ldb_rename(s->ldap2.ldb, old_dn, new_dn);
	talloc_free(r);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	}

	return NT_STATUS_OK;
}

static void becomeDC_connect_ldap2(struct libnet_BecomeDC_state *s)
{
	struct composite_context *c = s->creq;

	c->status = becomeDC_ldap_connect(s, &s->ldap2);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap2_modify_computer(s);
	if (!composite_is_ok(c)) return;

	c->status = becomeDC_ldap2_move_computer(s);
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
	s->domain.sid		= dom_sid_dup(s, r->in.domain_sid);
	if (composite_nomem(s->domain.sid, c)) return c;

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
