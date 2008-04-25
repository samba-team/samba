/* 
   Unix SMB/CIFS implementation.

   CLDAP server - netlogon handling

   Copyright (C) Andrew Tridgell	2005
   
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
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "smbd/service_task.h"
#include "cldap_server/cldap_server.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "libcli/ldap/ldap_ndr.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "ldb_wrap.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "param/param.h"

/*
  fill in the cldap netlogon union for a given version
*/
static NTSTATUS cldapd_netlogon_fill(struct cldapd_server *cldapd,
				     TALLOC_CTX *mem_ctx,
				     const char *domain,
				     const char *domain_guid,
				     const char *user,
				     const char *src_address,
				     uint32_t version,
				     struct loadparm_context *lp_ctx,
				     union nbt_cldap_netlogon *netlogon)
{
	const char *ref_attrs[] = {"nETBIOSName", "dnsRoot", "ncName", NULL};
	const char *dom_attrs[] = {"objectGUID", NULL};
	struct ldb_result *ref_res = NULL, *dom_res = NULL;
	int ret;
	const char **services = lp_server_services(lp_ctx);
	uint32_t server_type;
	const char *pdc_name;
	struct GUID domain_uuid;
	const char *realm;
	const char *dns_domain;
	const char *pdc_dns_name;
	const char *flatname;
	const char *server_site;
	const char *client_site;
	const char *pdc_ip;
	struct ldb_dn *partitions_basedn;
	struct interface *ifaces;

	partitions_basedn = samdb_partitions_dn(cldapd->samctx, mem_ctx);

	/* the domain has an optional trailing . */
	if (domain && domain[strlen(domain)-1] == '.') {
		domain = talloc_strndup(mem_ctx, domain, strlen(domain)-1);
	}

	if (domain) {
		struct ldb_dn *dom_dn;
		/* try and find the domain */

		ret = ldb_search_exp_fmt(cldapd->samctx, mem_ctx, &ref_res, 
					 partitions_basedn, LDB_SCOPE_ONELEVEL, 
					 ref_attrs, 
					 "(&(&(objectClass=crossRef)(dnsRoot=%s))(nETBIOSName=*))",
					 domain);
	
		if (ret != LDB_SUCCESS) {
			DEBUG(2,("Unable to find referece to '%s' in sam: %s\n",
				 domain, 
				 ldb_errstring(cldapd->samctx)));
			return NT_STATUS_NO_SUCH_DOMAIN;
		} else if (ref_res->count == 1) {
			talloc_steal(mem_ctx, dom_res);
			dom_dn = ldb_msg_find_attr_as_dn(cldapd->samctx, mem_ctx, ref_res->msgs[0], "ncName");
			if (!dom_dn) {
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
			ret = ldb_search(cldapd->samctx, dom_dn,
					 LDB_SCOPE_BASE, "objectClass=domain", 
					 dom_attrs, &dom_res);
			if (ret != LDB_SUCCESS) {
				DEBUG(2,("Error finding domain '%s'/'%s' in sam: %s\n", domain, ldb_dn_get_linearized(dom_dn), ldb_errstring(cldapd->samctx)));
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
			talloc_steal(mem_ctx, dom_res);
			if (dom_res->count != 1) {
				DEBUG(2,("Error finding domain '%s'/'%s' in sam\n", domain, ldb_dn_get_linearized(dom_dn)));
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
		} else if (ref_res->count > 1) {
			talloc_free(ref_res);
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
	}

	if ((dom_res == NULL || dom_res->count == 0) && domain_guid) {
		ref_res = NULL;

		ret = ldb_search_exp_fmt(cldapd->samctx, mem_ctx, &dom_res,
				 NULL, LDB_SCOPE_SUBTREE, 
				 dom_attrs, 
				 "(&(objectClass=domainDNS)(objectGUID=%s))", 
				 domain_guid);
		
		if (ret != LDB_SUCCESS) {
			DEBUG(2,("Unable to find referece to GUID '%s' in sam: %s\n",
				 domain_guid, 
				 ldb_errstring(cldapd->samctx)));
			return NT_STATUS_NO_SUCH_DOMAIN;
		} else if (dom_res->count == 1) {
			/* try and find the domain */
			ret = ldb_search_exp_fmt(cldapd->samctx, mem_ctx, &ref_res,
						 partitions_basedn, LDB_SCOPE_ONELEVEL, 
						 ref_attrs, 
						 "(&(objectClass=crossRef)(ncName=%s))", 
						 ldb_dn_get_linearized(dom_res->msgs[0]->dn));
			
			if (ret != LDB_SUCCESS) {
				DEBUG(2,("Unable to find referece to '%s' in sam: %s\n",
					 ldb_dn_get_linearized(dom_res->msgs[0]->dn), 
					 ldb_errstring(cldapd->samctx)));
				return NT_STATUS_NO_SUCH_DOMAIN;
				
			} else if (ref_res->count != 1) {
				DEBUG(2,("Unable to find referece to '%s' in sam\n",
					 ldb_dn_get_linearized(dom_res->msgs[0]->dn)));
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
		} else if (dom_res->count > 1) {
			talloc_free(ref_res);
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
	}

	if ((ref_res == NULL || ref_res->count == 0)) {
		DEBUG(2,("Unable to find domain reference with name %s or GUID {%s}\n", domain, domain_guid));
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	if ((dom_res == NULL || dom_res->count == 0)) {
		DEBUG(2,("Unable to find domain with name %s or GUID {%s}\n", domain, domain_guid));
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	server_type      = 
		NBT_SERVER_DS | NBT_SERVER_TIMESERV |
		NBT_SERVER_CLOSEST | NBT_SERVER_WRITABLE | 
		NBT_SERVER_GOOD_TIMESERV;

	if (samdb_is_pdc(cldapd->samctx)) {
		server_type |= NBT_SERVER_PDC;
	}

	if (samdb_is_gc(cldapd->samctx)) {
		server_type |= NBT_SERVER_GC;
	}

	if (str_list_check(services, "ldap")) {
		server_type |= NBT_SERVER_LDAP;
	}

	if (str_list_check(services, "kdc")) {
		server_type |= NBT_SERVER_KDC;
	}

	pdc_name         = talloc_asprintf(mem_ctx, "\\\\%s", lp_netbios_name(lp_ctx));
	domain_uuid      = samdb_result_guid(dom_res->msgs[0], "objectGUID");
	realm            = samdb_result_string(ref_res->msgs[0], "dnsRoot", lp_realm(lp_ctx));
	dns_domain       = samdb_result_string(ref_res->msgs[0], "dnsRoot", lp_realm(lp_ctx));
	pdc_dns_name     = talloc_asprintf(mem_ctx, "%s.%s", 
					   strlower_talloc(mem_ctx, 
							   lp_netbios_name(lp_ctx)), 
					   dns_domain);

	flatname         = samdb_result_string(ref_res->msgs[0], "nETBIOSName", 
					       lp_workgroup(lp_ctx));
	server_site      = "Default-First-Site-Name";
	client_site      = "Default-First-Site-Name";
	load_interfaces(mem_ctx, lp_interfaces(lp_ctx), &ifaces);
	pdc_ip           = iface_best_ip(ifaces, src_address);

	ZERO_STRUCTP(netlogon);

	switch (version & 0xF) {
	case 0:
	case 1:
		netlogon->logon1.type        = (user?19+2:19);
		netlogon->logon1.pdc_name    = pdc_name;
		netlogon->logon1.user_name   = user;
		netlogon->logon1.domain_name = flatname;
		netlogon->logon1.nt_version  = 1;
		netlogon->logon1.lmnt_token  = 0xFFFF;
		netlogon->logon1.lm20_token  = 0xFFFF;
		break;
	case 2:
	case 3:
		netlogon->logon3.type         = (user?19+2:19);
		netlogon->logon3.pdc_name     = pdc_name;
		netlogon->logon3.user_name    = user;
		netlogon->logon3.domain_name  = flatname;
		netlogon->logon3.domain_uuid  = domain_uuid;
		netlogon->logon3.forest       = realm;
		netlogon->logon3.dns_domain   = dns_domain;
		netlogon->logon3.pdc_dns_name = pdc_dns_name;
		netlogon->logon3.pdc_ip       = pdc_ip;
		netlogon->logon3.server_type  = server_type;
		netlogon->logon3.lmnt_token   = 0xFFFF;
		netlogon->logon3.lm20_token   = 0xFFFF;
		break;
	case 4:
	case 5:
	case 6:
	case 7:
		netlogon->logon5.type         = (user?NETLOGON_RESPONSE_FROM_PDC_USER:NETLOGON_RESPONSE_FROM_PDC2);
		netlogon->logon5.server_type  = server_type;
		netlogon->logon5.domain_uuid  = domain_uuid;
		netlogon->logon5.forest       = realm;
		netlogon->logon5.dns_domain   = dns_domain;
		netlogon->logon5.pdc_dns_name = pdc_dns_name;
		netlogon->logon5.domain       = flatname;
		netlogon->logon5.pdc_name     = lp_netbios_name(lp_ctx);
		netlogon->logon5.user_name    = user;
		netlogon->logon5.server_site  = server_site;
		netlogon->logon5.client_site  = client_site;
		netlogon->logon5.lmnt_token   = 0xFFFF;
		netlogon->logon5.lm20_token   = 0xFFFF;
		break;
	default:
		netlogon->logon13.type         = (user?NETLOGON_RESPONSE_FROM_PDC_USER:NETLOGON_RESPONSE_FROM_PDC2);
		netlogon->logon13.server_type  = server_type;
		netlogon->logon13.domain_uuid  = domain_uuid;
		netlogon->logon13.forest       = realm;
		netlogon->logon13.dns_domain   = dns_domain;
		netlogon->logon13.pdc_dns_name = pdc_dns_name;
		netlogon->logon13.domain       = flatname;
		netlogon->logon13.pdc_name     = lp_netbios_name(lp_ctx);
		netlogon->logon13.user_name    = user;
		netlogon->logon13.server_site  = server_site;
		netlogon->logon13.client_site  = client_site;
		netlogon->logon13.unknown      = 10;
		netlogon->logon13.unknown2     = 2;
		netlogon->logon13.pdc_ip       = pdc_ip;
		netlogon->logon13.lmnt_token   = 0xFFFF;
		netlogon->logon13.lm20_token   = 0xFFFF;
		break;
	}

	return NT_STATUS_OK;
}


/*
  handle incoming cldap requests
*/
void cldapd_netlogon_request(struct cldap_socket *cldap, 
			     uint32_t message_id,
			     struct ldb_parse_tree *tree,
			     struct socket_address *src)
{
	struct cldapd_server *cldapd = talloc_get_type(cldap->incoming.private, struct cldapd_server);
	int i;
	const char *domain = NULL;
	const char *host = NULL;
	const char *user = NULL;
	const char *domain_guid = NULL;
	const char *domain_sid = NULL;
	int acct_control = -1;
	int version = -1;
	union nbt_cldap_netlogon netlogon;
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;

	TALLOC_CTX *tmp_ctx = talloc_new(cldap);

	if (tree->operation != LDB_OP_AND) goto failed;

	/* extract the query elements */
	for (i=0;i<tree->u.list.num_elements;i++) {
		struct ldb_parse_tree *t = tree->u.list.elements[i];
		if (t->operation != LDB_OP_EQUALITY) goto failed;
		if (strcasecmp(t->u.equality.attr, "DnsDomain") == 0) {
			domain = talloc_strndup(tmp_ctx, 
						(const char *)t->u.equality.value.data,
						t->u.equality.value.length);
		}
		if (strcasecmp(t->u.equality.attr, "Host") == 0) {
			host = talloc_strndup(tmp_ctx, 
					      (const char *)t->u.equality.value.data,
					      t->u.equality.value.length);
		}
		if (strcasecmp(t->u.equality.attr, "DomainGuid") == 0) {
			NTSTATUS enc_status;
			struct GUID guid;
			enc_status = ldap_decode_ndr_GUID(tmp_ctx, 
							  t->u.equality.value, &guid);
			if (NT_STATUS_IS_OK(enc_status)) {
				domain_guid = GUID_string(tmp_ctx, &guid);
			}
		}
		if (strcasecmp(t->u.equality.attr, "DomainSid") == 0) {
			domain_sid = talloc_strndup(tmp_ctx, 
						    (const char *)t->u.equality.value.data,
						    t->u.equality.value.length);
		}
		if (strcasecmp(t->u.equality.attr, "User") == 0) {
			user = talloc_strndup(tmp_ctx, 
					      (const char *)t->u.equality.value.data,
					      t->u.equality.value.length);
		}
		if (strcasecmp(t->u.equality.attr, "NtVer") == 0 &&
		    t->u.equality.value.length == 4) {
			version = IVAL(t->u.equality.value.data, 0);
		}
		if (strcasecmp(t->u.equality.attr, "AAC") == 0 &&
		    t->u.equality.value.length == 4) {
			acct_control = IVAL(t->u.equality.value.data, 0);
		}
	}

	if (domain_guid == NULL && domain == NULL) {
		domain = lp_realm(cldapd->task->lp_ctx);
	}

	if (version == -1) {
		goto failed;
	}

	DEBUG(5,("cldap netlogon query domain=%s host=%s user=%s version=%d guid=%s\n",
		 domain, host, user, version, domain_guid));

	status = cldapd_netlogon_fill(cldapd, tmp_ctx, domain, domain_guid, 
				      user, src->addr, 
				      version, cldapd->task->lp_ctx, &netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = cldap_netlogon_reply(cldap, message_id, src, version,
				      &netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	talloc_free(tmp_ctx);
	return;
	
failed:
	DEBUG(2,("cldap netlogon query failed domain=%s host=%s version=%d - %s\n",
		 domain, host, version, nt_errstr(status)));
	talloc_free(tmp_ctx);
	cldap_empty_reply(cldap, message_id, src);	
}
