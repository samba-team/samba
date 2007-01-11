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
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"

struct libnet_BecomeDC_state {
	struct composite_context *creq;

	struct libnet_context *libnet;

	struct dom_sid zero_sid;

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
	} drsuapi1, drsuapi2, drsuapi3;

	struct libnet_BecomeDC_Domain domain;
	struct libnet_BecomeDC_Forest forest;
	struct libnet_BecomeDC_SourceDSA source_dsa;
	struct libnet_BecomeDC_DestDSA dest_dsa;

	struct libnet_BecomeDC_Partition schema_part, config_part, domain_part;

	struct becomeDC_fsmo {
		const char *dns_name;
		const char *server_dn_str;
		const char *ntds_dn_str;
		struct GUID ntds_guid;
	} infrastructure_fsmo;

	struct becomeDC_fsmo rid_manager_fsmo;

	struct libnet_BecomeDC_CheckOptions _co;
	struct libnet_BecomeDC_PrepareDB _pp;
	struct libnet_BecomeDC_StoreChunk _sc;
	struct libnet_BecomeDC_Callbacks callbacks;
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

static NTSTATUS becomeDC_ldap1_crossref_behavior_version(struct libnet_BecomeDC_state *s)
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

	s->forest.crossref_behavior_version = ldb_msg_find_attr_as_uint(r->msgs[0], "msDs-Behavior-Version", 0);

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

	s->domain.behavior_version = ldb_msg_find_attr_as_uint(r->msgs[0], "msDs-Behavior-Version", 0);

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

	s->forest.schema_object_version = ldb_msg_find_attr_as_uint(r->msgs[0], "objectVersion", 0);

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
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* w2k doesn't have this object */
		s->domain.w2k3_update_revision = 0;
		return NT_STATUS_OK;
	} else if (ret != LDB_SUCCESS) {
		return NT_STATUS_LDAP(ret);
	} else if (r->count != 1) {
		talloc_free(r);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	s->domain.w2k3_update_revision = ldb_msg_find_attr_as_uint(r->msgs[0], "revision", 0);

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

static NTSTATUS becomeDC_check_options(struct libnet_BecomeDC_state *s)
{
	if (!s->callbacks.check_options) return NT_STATUS_OK;

	s->_co.domain		= &s->domain;
	s->_co.forest		= &s->forest;
	s->_co.source_dsa	= &s->source_dsa;

	return s->callbacks.check_options(s->callbacks.private_data, &s->_co);
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

	c->status = becomeDC_ldap1_crossref_behavior_version(s);
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

	c->status = becomeDC_check_options(s);
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

	if (!drsuapi->binding) {
		binding_str = talloc_asprintf(s, "ncacn_ip_tcp:%s[krb5,seal]", s->source_dsa.dns_name);
		if (composite_nomem(binding_str, c)) return;

		c->status = dcerpc_parse_binding(s, binding_str, &drsuapi->binding);
		talloc_free(binding_str);
		if (!composite_is_ok(c)) return;
	}

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
	if (s->domain.behavior_version == 2) {
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
	if (s->domain.behavior_version == 2) {
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

static WERROR becomeDC_drsuapi_bind_recv(struct libnet_BecomeDC_state *s,
					 struct becomeDC_drsuapi *drsuapi)
{
	if (!W_ERROR_IS_OK(drsuapi->bind_r.out.result)) {
		return drsuapi->bind_r.out.result;
	}

	ZERO_STRUCT(drsuapi->remote_info28);
	if (drsuapi->bind_r.out.bind_info) {
		switch (drsuapi->bind_r.out.bind_info->length) {
		case 24: {
			struct drsuapi_DsBindInfo24 *info24;
			info24 = &drsuapi->bind_r.out.bind_info->info.info24;
			drsuapi->remote_info28.supported_extensions	= info24->supported_extensions;
			drsuapi->remote_info28.site_guid		= info24->site_guid;
			drsuapi->remote_info28.u1			= info24->u1;
			drsuapi->remote_info28.repl_epoch		= 0;
			break;
		}
		case 28:
			drsuapi->remote_info28 = drsuapi->bind_r.out.bind_info->info.info28;
			break;
		}
	}

	return WERR_OK;
}

static void becomeDC_drsuapi1_add_entry_send(struct libnet_BecomeDC_state *s);

static void becomeDC_drsuapi1_bind_recv(struct rpc_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;
	WERROR status;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	status = becomeDC_drsuapi_bind_recv(s, &s->drsuapi1);
	if (!W_ERROR_IS_OK(status)) {
		composite_error(c, werror_to_ntstatus(status));
		return;
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
	bool w2k3;

	/* choose a random invocationId */
	s->dest_dsa.invocation_id = GUID_random();

	/*
	 * if the schema version indicates w2k3, then
	 * also send some w2k3 specific attributes
	 */
	if (s->forest.schema_object_version >= 30) {
		w2k3 = true;
	} else {
		w2k3 = false;
	}

	r = talloc_zero(s, struct drsuapi_DsAddEntry);
	if (composite_nomem(r, c)) return;

	/* setup identifier */
	identifier		= talloc(r, struct drsuapi_DsReplicaObjectIdentifier);
	if (composite_nomem(identifier, c)) return;
	identifier->guid	= GUID_zero();
	identifier->sid		= s->zero_sid;
	identifier->dn		= talloc_asprintf(identifier, "CN=NTDS Settings,%s",
						  s->dest_dsa.server_dn_str);
	if (composite_nomem(identifier->dn, c)) return;

	/* allocate attribute array */
	num_attrs	= 11;
	attrs		= talloc_array(r, struct drsuapi_DsReplicaAttribute, num_attrs);
	if (composite_nomem(attrs, c)) return;

	/* ntSecurityDescriptor */
	{
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;
		struct security_descriptor *v;
		struct dom_sid *domain_admins_sid;
		const char *domain_admins_sid_str;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 1);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 1);
		if (composite_nomem(vd, c)) return;

		domain_admins_sid = dom_sid_add_rid(vs, s->domain.sid, DOMAIN_RID_ADMINS);
		if (composite_nomem(domain_admins_sid, c)) return;

		domain_admins_sid_str = dom_sid_string(domain_admins_sid, domain_admins_sid);
		if (composite_nomem(domain_admins_sid_str, c)) return;

		v = security_descriptor_create(vd,
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

		c->status = ndr_push_struct_blob(&vd[0], vd, v,(ndr_push_flags_fn_t)ndr_push_security_descriptor);
		if (!composite_is_ok(c)) return;

		vs[0].blob		= &vd[0];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_ntSecurityDescriptor;
		attrs[i].value_ctr.num_values	= 1;
		attrs[i].value_ctr.values	= vs;

		i++;
	}

	/* objectClass: nTDSDSA */
	{
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 1);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 1);
		if (composite_nomem(vd, c)) return;

		vd[0] = data_blob_talloc(vd, NULL, 4);
		if (composite_nomem(vd[0].data, c)) return;

		/* value for nTDSDSA */
		SIVAL(vd[0].data, 0, 0x0017002F);

		vs[0].blob		= &vd[0];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_objectClass;
		attrs[i].value_ctr.num_values	= 1;
		attrs[i].value_ctr.values	= vs;

		i++;
	}

	/* objectCategory: CN=NTDS-DSA,CN=Schema,... */
	{
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;
		struct drsuapi_DsReplicaObjectIdentifier3 v[1];

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 1);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 1);
		if (composite_nomem(vd, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= s->zero_sid;
		v[0].dn			= talloc_asprintf(vd, "CN=NTDS-DSA,%s",
							  s->forest.schema_dn_str);
		if (composite_nomem(v->dn, c)) return;

		c->status = ndr_push_struct_blob(&vd[0], vd, &v[0],
						 (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
		if (!composite_is_ok(c)) return;

		vs[0].blob		= &vd[0];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_objectCategory;
		attrs[i].value_ctr.num_values	= 1;
		attrs[i].value_ctr.values	= vs;

		i++;
	}

	/* invocationId: random guid */
	{
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;
		const struct GUID *v;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 1);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 1);
		if (composite_nomem(vd, c)) return;

		v = &s->dest_dsa.invocation_id;

		c->status = ndr_push_struct_blob(&vd[0], vd, v, (ndr_push_flags_fn_t)ndr_push_GUID);
		if (!composite_is_ok(c)) return;

		vs[0].blob		= &vd[0];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_invocationId;
		attrs[i].value_ctr.num_values	= 1;
		attrs[i].value_ctr.values	= vs;

		i++;
	}

	/* hasMasterNCs: ... */
	{
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;
		struct drsuapi_DsReplicaObjectIdentifier3 v[3];

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 3);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 3);
		if (composite_nomem(vd, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= s->zero_sid;
		v[0].dn			= s->forest.config_dn_str;

		v[1].guid		= GUID_zero();
		v[1].sid		= s->zero_sid;
		v[1].dn			= s->domain.dn_str;

		v[2].guid		= GUID_zero();
		v[2].sid		= s->zero_sid;
		v[2].dn			= s->forest.schema_dn_str;

		c->status = ndr_push_struct_blob(&vd[0], vd, &v[0],
						 (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
		if (!composite_is_ok(c)) return;

		c->status = ndr_push_struct_blob(&vd[1], vd, &v[1],
						 (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
		if (!composite_is_ok(c)) return;

		c->status = ndr_push_struct_blob(&vd[2], vd, &v[2],
						 (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
		if (!composite_is_ok(c)) return;

		vs[0].blob		= &vd[0];
		vs[1].blob		= &vd[1];
		vs[2].blob		= &vd[2];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_hasMasterNCs;
		attrs[i].value_ctr.num_values	= 3;
		attrs[i].value_ctr.values	= vs;

		i++;
	}

	/* msDS-hasMasterNCs: ... */
	if (w2k3) {
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;
		struct drsuapi_DsReplicaObjectIdentifier3 v[3];

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 3);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 3);
		if (composite_nomem(vd, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= s->zero_sid;
		v[0].dn			= s->forest.config_dn_str;

		v[1].guid		= GUID_zero();
		v[1].sid		= s->zero_sid;
		v[1].dn			= s->domain.dn_str;

		v[2].guid		= GUID_zero();
		v[2].sid		= s->zero_sid;
		v[2].dn			= s->forest.schema_dn_str;

		c->status = ndr_push_struct_blob(&vd[0], vd, &v[0],
						 (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
		if (!composite_is_ok(c)) return;

		c->status = ndr_push_struct_blob(&vd[1], vd, &v[1],
						 (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
		if (!composite_is_ok(c)) return;

		c->status = ndr_push_struct_blob(&vd[2], vd, &v[2],
						 (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
		if (!composite_is_ok(c)) return;

		vs[0].blob		= &vd[0];
		vs[1].blob		= &vd[1];
		vs[2].blob		= &vd[2];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_msDS_hasMasterNCs;
		attrs[i].value_ctr.num_values	= 3;
		attrs[i].value_ctr.values	= vs;

		i++;
	}

	/* dMDLocation: CN=Schema,... */
	{
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;
		struct drsuapi_DsReplicaObjectIdentifier3 v[1];

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 1);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 1);
		if (composite_nomem(vd, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= s->zero_sid;
		v[0].dn			= s->forest.schema_dn_str;

		c->status = ndr_push_struct_blob(&vd[0], vd, &v[0],
						 (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
		if (!composite_is_ok(c)) return;

		vs[0].blob		= &vd[0];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_dMDLocation;
		attrs[i].value_ctr.num_values	= 1;
		attrs[i].value_ctr.values	= vs;

		i++;
	}

	/* msDS-HasDomainNCs: <domain_partition> */
	if (w2k3) {
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;
		struct drsuapi_DsReplicaObjectIdentifier3 v[1];

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 1);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 1);
		if (composite_nomem(vd, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= s->zero_sid;
		v[0].dn			= s->domain.dn_str;

		c->status = ndr_push_struct_blob(&vd[0], vd, &v[0],
						 (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
		if (!composite_is_ok(c)) return;

		vs[0].blob		= &vd[0];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_msDS_HasDomainNCs;
		attrs[i].value_ctr.num_values	= 1;
		attrs[i].value_ctr.values	= vs;

		i++;
	}

	/* msDS-Behavior-Version */
	if (w2k3) {
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 1);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 1);
		if (composite_nomem(vd, c)) return;

		vd[0] = data_blob_talloc(vd, NULL, 4);
		if (composite_nomem(vd[0].data, c)) return;

		SIVAL(vd[0].data, 0, DS_BEHAVIOR_WIN2003);

		vs[0].blob		= &vd[0];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_msDS_Behavior_Version;
		attrs[i].value_ctr.num_values	= 1;
		attrs[i].value_ctr.values	= vs;

		i++;
	}

	/* systemFlags */
	{
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 1);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 1);
		if (composite_nomem(vd, c)) return;

		vd[0] = data_blob_talloc(vd, NULL, 4);
		if (composite_nomem(vd[0].data, c)) return;

		SIVAL(vd[0].data, 0, SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE);

		vs[0].blob		= &vd[0];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_systemFlags;
		attrs[i].value_ctr.num_values	= 1;
		attrs[i].value_ctr.values	= vs;

		i++;
	}

	/* serverReference: ... */
	{
		struct drsuapi_DsAttributeValue *vs;
		DATA_BLOB *vd;
		struct drsuapi_DsReplicaObjectIdentifier3 v[1];

		vs = talloc_array(attrs, struct drsuapi_DsAttributeValue, 1);
		if (composite_nomem(vs, c)) return;

		vd = talloc_array(vs, DATA_BLOB, 1);
		if (composite_nomem(vd, c)) return;

		v[0].guid		= GUID_zero();
		v[0].sid		= s->zero_sid;
		v[0].dn			= s->dest_dsa.computer_dn_str;

		c->status = ndr_push_struct_blob(&vd[0], vd, &v[0],
						 (ndr_push_flags_fn_t)ndr_push_drsuapi_DsReplicaObjectIdentifier3);
		if (!composite_is_ok(c)) return;

		vs[0].blob		= &vd[0];

		attrs[i].attid			= DRSUAPI_ATTRIBUTE_serverReference;
		attrs[i].value_ctr.num_values	= 1;
		attrs[i].value_ctr.values	= vs;

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

static void becomeDC_drsuapi2_connect_recv(struct composite_context *req);
static NTSTATUS becomeDC_prepare_db(struct libnet_BecomeDC_state *s);

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

	if (r->out.level == 3) {
		if (r->out.ctr.ctr3.count != 1) {
			WERROR status;

			if (r->out.ctr.ctr3.level != 1) {
				composite_error(c, NT_STATUS_INVALID_NETWORK_RESPONSE);
				return;
			}

			if (!r->out.ctr.ctr3.error) {
				composite_error(c, NT_STATUS_INVALID_NETWORK_RESPONSE);
				return;
			}

			status = r->out.ctr.ctr3.error->info1.status;

			if (!r->out.ctr.ctr3.error->info1.info) {
				composite_error(c, werror_to_ntstatus(status));
				return;
			}

			/* see if we can get a more detailed error */
			switch (r->out.ctr.ctr3.error->info1.level) {
			case 1:
				status = r->out.ctr.ctr3.error->info1.info->error1.status;
				break;
			case 4:
			case 5:
			case 6:
			case 7:
				status = r->out.ctr.ctr3.error->info1.info->errorX.status;
				break;
			}

			composite_error(c, werror_to_ntstatus(status));
			return;
		}

		s->dest_dsa.ntds_guid	= r->out.ctr.ctr3.objects[0].guid;
	} else if (r->out.level == 2) {
		if (r->out.ctr.ctr2.count != 1) {
			composite_error(c, werror_to_ntstatus(r->out.ctr.ctr2.error.status));
			return;
		}

		s->dest_dsa.ntds_guid	= r->out.ctr.ctr2.objects[0].guid;
	} else {
		composite_error(c, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	talloc_free(r);

	s->dest_dsa.ntds_dn_str = talloc_asprintf(s, "CN=NTDS Settings,%s",
						  s->dest_dsa.server_dn_str);
	if (composite_nomem(s->dest_dsa.ntds_dn_str, c)) return;

	c->status = becomeDC_prepare_db(s);
	if (!composite_is_ok(c)) return;

	becomeDC_drsuapi_connect_send(s, &s->drsuapi2, becomeDC_drsuapi2_connect_recv);
}

static NTSTATUS becomeDC_prepare_db(struct libnet_BecomeDC_state *s)
{
	if (!s->callbacks.prepare_db) return NT_STATUS_OK;

	s->_pp.domain		= &s->domain;
	s->_pp.forest		= &s->forest;
	s->_pp.source_dsa	= &s->source_dsa;
	s->_pp.dest_dsa		= &s->dest_dsa;

	return s->callbacks.prepare_db(s->callbacks.private_data, &s->_pp);
}

static void becomeDC_drsuapi2_bind_recv(struct rpc_request *req);

static void becomeDC_drsuapi2_connect_recv(struct composite_context *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private_data,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;

	c->status = dcerpc_pipe_connect_b_recv(req, s, &s->drsuapi2.pipe);
	if (!composite_is_ok(c)) return;

	becomeDC_drsuapi_bind_send(s, &s->drsuapi2, becomeDC_drsuapi2_bind_recv);
}

static void becomeDC_drsuapi3_connect_recv(struct composite_context *req);

static void becomeDC_drsuapi2_bind_recv(struct rpc_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;
	char *binding_str;
	WERROR status;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	status = becomeDC_drsuapi_bind_recv(s, &s->drsuapi2);
	if (!W_ERROR_IS_OK(status)) {
		composite_error(c, werror_to_ntstatus(status));
		return;
	}

	/* this avoids the epmapper lookup on the 2nd connection */
	binding_str = dcerpc_binding_string(s, s->drsuapi2.binding);
	if (composite_nomem(binding_str, c)) return;

	c->status = dcerpc_parse_binding(s, binding_str, &s->drsuapi3.binding);
	talloc_free(binding_str);
	if (!composite_is_ok(c)) return;

	becomeDC_drsuapi_connect_send(s, &s->drsuapi3, becomeDC_drsuapi3_connect_recv);
}

static void becomeDC_drsuapi3_pull_schema_send(struct libnet_BecomeDC_state *s);

static void becomeDC_drsuapi3_connect_recv(struct composite_context *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private_data,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;

	c->status = dcerpc_pipe_connect_b_recv(req, s, &s->drsuapi3.pipe);
	if (!composite_is_ok(c)) return;

	becomeDC_drsuapi3_pull_schema_send(s);
}

static void becomeDC_drsuapi_pull_partition_send(struct libnet_BecomeDC_state *s,
						 struct becomeDC_drsuapi *drsuapi_h,
						 struct becomeDC_drsuapi *drsuapi_p,
						 struct libnet_BecomeDC_Partition *partition,
						 void (*recv_fn)(struct rpc_request *req))
{
	struct composite_context *c = s->creq;
	struct rpc_request *req;
	struct drsuapi_DsGetNCChanges *r;
	int32_t level;

	r = talloc(s, struct drsuapi_DsGetNCChanges);
	if (composite_nomem(r, c)) return;

	r->in.level = &level;
	r->in.bind_handle	= &drsuapi_h->bind_handle;
	if (drsuapi_h->remote_info28.supported_extensions & DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8) {
		level				= 8;
		r->in.req.req8.destination_dsa_guid	= partition->destination_dsa_guid;
		r->in.req.req8.source_dsa_invocation_id	= partition->source_dsa_invocation_id;
		r->in.req.req8.naming_context		= &partition->nc;
		r->in.req.req8.highwatermark		= partition->highwatermark;
		r->in.req.req8.uptodateness_vector	= NULL;
		r->in.req.req8.replica_flags		= partition->replica_flags;
		r->in.req.req8.max_object_count		= 133;
		r->in.req.req8.max_ndr_size		= 1336811;
		r->in.req.req8.unknown4			= 0;
		r->in.req.req8.h1			= 0;
		r->in.req.req8.unique_ptr1		= 0;
		r->in.req.req8.unique_ptr2		= 0;
		r->in.req.req8.mapping_ctr.num_mappings	= 0;
		r->in.req.req8.mapping_ctr.mappings	= NULL;
	} else {
		level				= 5;
		r->in.req.req5.destination_dsa_guid	= partition->destination_dsa_guid;
		r->in.req.req5.source_dsa_invocation_id	= partition->source_dsa_invocation_id;
		r->in.req.req5.naming_context		= &partition->nc;
		r->in.req.req5.highwatermark		= partition->highwatermark;
		r->in.req.req5.uptodateness_vector	= NULL;
		r->in.req.req5.replica_flags		= partition->replica_flags;
		r->in.req.req5.max_object_count		= 133;
		r->in.req.req5.max_ndr_size		= 1336770;
		r->in.req.req5.unknown4			= 0;
		r->in.req.req5.h1			= 0;
	}

	/* 
	 * we should try to use the drsuapi_p->pipe here, as w2k3 does
	 * but it seems that some extra flags in the DCERPC Bind call
	 * are needed for it. Or the same KRB5 TGS is needed on both
	 * connections.
	 */
	req = dcerpc_drsuapi_DsGetNCChanges_send(drsuapi_h->pipe, r, r);
	composite_continue_rpc(c, req, recv_fn, s);
}

static WERROR becomeDC_drsuapi_pull_partition_recv(struct libnet_BecomeDC_state *s,
						   struct libnet_BecomeDC_Partition *partition,
						   struct drsuapi_DsGetNCChanges *r)
{
	uint32_t ctr_level = 0;
	struct drsuapi_DsGetNCChangesCtr1 *ctr1 = NULL;
	struct drsuapi_DsGetNCChangesCtr6 *ctr6 = NULL;
	struct GUID *source_dsa_guid;
	struct GUID *source_dsa_invocation_id;
	struct drsuapi_DsReplicaHighWaterMark *new_highwatermark;
	NTSTATUS nt_status;

	if (!W_ERROR_IS_OK(r->out.result)) {
		return r->out.result;
	}

	if (*r->out.level == 1) {
		ctr_level = 1;
		ctr1 = &r->out.ctr.ctr1;
	} else if (*r->out.level == 2) {
		ctr_level = 1;
		ctr1 = r->out.ctr.ctr2.ctr.mszip1.ctr1;
	} else if (*r->out.level == 6) {
		ctr_level = 6;
		ctr6 = &r->out.ctr.ctr6;
	} else if (*r->out.level == 7 &&
		   r->out.ctr.ctr7.level == 6 &&
		   r->out.ctr.ctr7.type == DRSUAPI_COMPRESSION_TYPE_MSZIP) {
		ctr_level = 6;
		ctr6 = r->out.ctr.ctr7.ctr.mszip6.ctr6;
	} else {
		return WERR_BAD_NET_RESP;
	}

	switch (ctr_level) {
	case 1:
		source_dsa_guid			= &ctr1->source_dsa_guid;
		source_dsa_invocation_id	= &ctr1->source_dsa_invocation_id;
		new_highwatermark		= &ctr1->new_highwatermark;
		break;
	case 6:
		source_dsa_guid			= &ctr6->source_dsa_guid;
		source_dsa_invocation_id	= &ctr6->source_dsa_invocation_id;
		new_highwatermark		= &ctr6->new_highwatermark;
		break;
	}

	partition->highwatermark		= *new_highwatermark;
	partition->source_dsa_guid		= *source_dsa_guid;
	partition->source_dsa_invocation_id	= *source_dsa_invocation_id;

	if (!partition->store_chunk) return WERR_OK;

	s->_sc.domain		= &s->domain;
	s->_sc.forest		= &s->forest;
	s->_sc.source_dsa	= &s->source_dsa;
	s->_sc.dest_dsa		= &s->dest_dsa;
	s->_sc.partition	= partition;
	s->_sc.ctr_level	= ctr_level;
	s->_sc.ctr1		= ctr1;
	s->_sc.ctr6		= ctr6;

	nt_status = partition->store_chunk(s->callbacks.private_data, &s->_sc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return ntstatus_to_werror(nt_status);
	}

	return WERR_OK;
}

static void becomeDC_drsuapi3_pull_schema_recv(struct rpc_request *req);

static void becomeDC_drsuapi3_pull_schema_send(struct libnet_BecomeDC_state *s)
{
	s->schema_part.nc.guid	= GUID_zero();
	s->schema_part.nc.sid	= s->zero_sid;
	s->schema_part.nc.dn	= s->forest.schema_dn_str;

	s->schema_part.destination_dsa_guid	= s->drsuapi2.bind_guid;

	s->schema_part.replica_flags	= DRSUAPI_DS_REPLICA_NEIGHBOUR_WRITEABLE
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_SYNC_ON_STARTUP
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_DO_SCHEDULED_SYNCS
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_FULL_IN_PROGRESS
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_NEVER_SYNCED
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_COMPRESS_CHANGES;

	s->schema_part.store_chunk	= s->callbacks.schema_chunk;

	becomeDC_drsuapi_pull_partition_send(s, &s->drsuapi2, &s->drsuapi3, &s->schema_part,
					     becomeDC_drsuapi3_pull_schema_recv);
}

static void becomeDC_drsuapi3_pull_config_send(struct libnet_BecomeDC_state *s);

static void becomeDC_drsuapi3_pull_schema_recv(struct rpc_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;
	struct drsuapi_DsGetNCChanges *r = talloc_get_type(req->ndr.struct_ptr,
					   struct drsuapi_DsGetNCChanges);
	WERROR status;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	status = becomeDC_drsuapi_pull_partition_recv(s, &s->schema_part, r);
	if (!W_ERROR_IS_OK(status)) {
		composite_error(c, werror_to_ntstatus(status));
		return;
	}

	talloc_free(r);

	if (s->schema_part.highwatermark.tmp_highest_usn > s->schema_part.highwatermark.highest_usn) {
		becomeDC_drsuapi_pull_partition_send(s, &s->drsuapi2, &s->drsuapi3, &s->schema_part,
						     becomeDC_drsuapi3_pull_schema_recv);
		return;
	}

	becomeDC_drsuapi3_pull_config_send(s);
}

static void becomeDC_drsuapi3_pull_config_recv(struct rpc_request *req);

static void becomeDC_drsuapi3_pull_config_send(struct libnet_BecomeDC_state *s)
{
	s->config_part.nc.guid	= GUID_zero();
	s->config_part.nc.sid	= s->zero_sid;
	s->config_part.nc.dn	= s->forest.config_dn_str;

	s->config_part.destination_dsa_guid	= s->drsuapi2.bind_guid;

	s->config_part.replica_flags	= DRSUAPI_DS_REPLICA_NEIGHBOUR_WRITEABLE
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_SYNC_ON_STARTUP
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_DO_SCHEDULED_SYNCS
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_FULL_IN_PROGRESS
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_NEVER_SYNCED
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_COMPRESS_CHANGES;

	s->config_part.store_chunk	= s->callbacks.config_chunk;

	becomeDC_drsuapi_pull_partition_send(s, &s->drsuapi2, &s->drsuapi3, &s->config_part,
					     becomeDC_drsuapi3_pull_config_recv);
}

static void becomeDC_drsuapi3_pull_config_recv(struct rpc_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;
	struct drsuapi_DsGetNCChanges *r = talloc_get_type(req->ndr.struct_ptr,
					   struct drsuapi_DsGetNCChanges);
	WERROR status;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	status = becomeDC_drsuapi_pull_partition_recv(s, &s->config_part, r);
	if (!W_ERROR_IS_OK(status)) {
		composite_error(c, werror_to_ntstatus(status));
		return;
	}

	talloc_free(r);

	if (s->config_part.highwatermark.tmp_highest_usn > s->config_part.highwatermark.highest_usn) {
		becomeDC_drsuapi_pull_partition_send(s, &s->drsuapi2, &s->drsuapi3, &s->config_part,
						     becomeDC_drsuapi3_pull_config_recv);
		return;
	}

	becomeDC_connect_ldap2(s);
}

static void becomeDC_drsuapi3_pull_domain_recv(struct rpc_request *req);

static void becomeDC_drsuapi3_pull_domain_send(struct libnet_BecomeDC_state *s)
{
	s->domain_part.nc.guid	= GUID_zero();
	s->domain_part.nc.sid	= s->zero_sid;
	s->domain_part.nc.dn	= s->domain.dn_str;

	s->domain_part.destination_dsa_guid	= s->drsuapi2.bind_guid;

	s->domain_part.replica_flags	= DRSUAPI_DS_REPLICA_NEIGHBOUR_WRITEABLE
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_SYNC_ON_STARTUP
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_DO_SCHEDULED_SYNCS
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_FULL_IN_PROGRESS
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_NEVER_SYNCED
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_COMPRESS_CHANGES;

	s->domain_part.store_chunk	= s->callbacks.domain_chunk;

	becomeDC_drsuapi_pull_partition_send(s, &s->drsuapi2, &s->drsuapi3, &s->domain_part,
					     becomeDC_drsuapi3_pull_domain_recv);
}

static void becomeDC_drsuapi_update_refs_send(struct libnet_BecomeDC_state *s,
					      struct becomeDC_drsuapi *drsuapi,
					      struct libnet_BecomeDC_Partition *partition,
					      void (*recv_fn)(struct rpc_request *req));
static void becomeDC_drsuapi2_update_refs_schema_recv(struct rpc_request *req);

static void becomeDC_drsuapi3_pull_domain_recv(struct rpc_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;
	struct drsuapi_DsGetNCChanges *r = talloc_get_type(req->ndr.struct_ptr,
					   struct drsuapi_DsGetNCChanges);
	WERROR status;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	status = becomeDC_drsuapi_pull_partition_recv(s, &s->domain_part, r);
	if (!W_ERROR_IS_OK(status)) {
		composite_error(c, werror_to_ntstatus(status));
		return;
	}

	talloc_free(r);

	if (s->domain_part.highwatermark.tmp_highest_usn > s->domain_part.highwatermark.highest_usn) {
		becomeDC_drsuapi_pull_partition_send(s, &s->drsuapi2, &s->drsuapi3, &s->domain_part,
						     becomeDC_drsuapi3_pull_domain_recv);
		return;
	}

	becomeDC_drsuapi_update_refs_send(s, &s->drsuapi2, &s->schema_part,
					  becomeDC_drsuapi2_update_refs_schema_recv);
}

static void becomeDC_drsuapi_update_refs_send(struct libnet_BecomeDC_state *s,
					      struct becomeDC_drsuapi *drsuapi,
					      struct libnet_BecomeDC_Partition *partition,
					      void (*recv_fn)(struct rpc_request *req))
{
	struct composite_context *c = s->creq;
	struct rpc_request *req;
	struct drsuapi_DsReplicaUpdateRefs *r;
	const char *ntds_guid_str;
	const char *ntds_dns_name;

	r = talloc(s, struct drsuapi_DsReplicaUpdateRefs);
	if (composite_nomem(r, c)) return;

	ntds_guid_str = GUID_string(r, &s->dest_dsa.ntds_guid);
	if (composite_nomem(ntds_guid_str, c)) return;

	ntds_dns_name = talloc_asprintf(r, "%s._msdcs.%s",
					ntds_guid_str,
					s->domain.dns_name);
	if (composite_nomem(ntds_dns_name, c)) return;

	r->in.bind_handle		= &drsuapi->bind_handle;
	r->in.level			= 1;
	r->in.req.req1.naming_context	= &partition->nc;
	r->in.req.req1.dest_dsa_dns_name= ntds_dns_name;
	r->in.req.req1.dest_dsa_guid	= s->dest_dsa.ntds_guid;
	r->in.req.req1.options		= DRSUAPI_DS_REPLICA_UPDATE_ADD_REFERENCE
					| DRSUAPI_DS_REPLICA_UPDATE_DELETE_REFERENCE
					| DRSUAPI_DS_REPLICA_UPDATE_0x00000010;

	req = dcerpc_drsuapi_DsReplicaUpdateRefs_send(drsuapi->pipe, r, r);
	composite_continue_rpc(c, req, recv_fn, s);
}

static void becomeDC_drsuapi2_update_refs_config_recv(struct rpc_request *req);

static void becomeDC_drsuapi2_update_refs_schema_recv(struct rpc_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;
	struct drsuapi_DsReplicaUpdateRefs *r = talloc_get_type(req->ndr.struct_ptr,
					   struct drsuapi_DsReplicaUpdateRefs);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	if (!W_ERROR_IS_OK(r->out.result)) {
		composite_error(c, werror_to_ntstatus(r->out.result));
		return;
	}

	talloc_free(r);

	becomeDC_drsuapi_update_refs_send(s, &s->drsuapi2, &s->config_part,
					  becomeDC_drsuapi2_update_refs_config_recv);
}

static void becomeDC_drsuapi2_update_refs_domain_recv(struct rpc_request *req);

static void becomeDC_drsuapi2_update_refs_config_recv(struct rpc_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;
	struct drsuapi_DsReplicaUpdateRefs *r = talloc_get_type(req->ndr.struct_ptr,
					   struct drsuapi_DsReplicaUpdateRefs);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	if (!W_ERROR_IS_OK(r->out.result)) {
		composite_error(c, werror_to_ntstatus(r->out.result));
		return;
	}

	talloc_free(r);

	becomeDC_drsuapi_update_refs_send(s, &s->drsuapi2, &s->domain_part,
					  becomeDC_drsuapi2_update_refs_domain_recv);
}

static void becomeDC_drsuapi2_update_refs_domain_recv(struct rpc_request *req)
{
	struct libnet_BecomeDC_state *s = talloc_get_type(req->async.private,
					  struct libnet_BecomeDC_state);
	struct composite_context *c = s->creq;
	struct drsuapi_DsReplicaUpdateRefs *r = talloc_get_type(req->ndr.struct_ptr,
					   struct drsuapi_DsReplicaUpdateRefs);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	if (!W_ERROR_IS_OK(r->out.result)) {
		composite_error(c, werror_to_ntstatus(r->out.result));
		return;
	}

	talloc_free(r);

	/* TODO: use DDNS updates and register dns names */
	composite_done(c);
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
	if (ret != LDB_SUCCESS) {
		talloc_free(r);
		return NT_STATUS_LDAP(ret);
	}

	s->dest_dsa.computer_dn_str = ldb_dn_alloc_linearized(s, new_dn);
	NT_STATUS_HAVE_NO_MEMORY(s->dest_dsa.computer_dn_str);

	talloc_free(r);

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

	becomeDC_drsuapi3_pull_domain_send(s);
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
	s->dest_dsa.dns_name	= talloc_asprintf(s, "%s.%s",
						  tmp_name,
				  		  s->domain.dns_name);
	talloc_free(tmp_name);
	if (composite_nomem(s->dest_dsa.dns_name, c)) return c;
	/* Callback function pointers */
	s->callbacks = r->in.callbacks;

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
