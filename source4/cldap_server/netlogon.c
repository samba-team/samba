/* 
   Unix SMB/CIFS implementation.

   CLDAP server - netlogon handling

   Copyright (C) Andrew Tridgell	2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008
   
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
#include "libcli/security/security.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "ldb_wrap.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "param/param.h"
/*
  fill in the cldap netlogon union for a given version
*/
NTSTATUS fill_netlogon_samlogon_response(struct ldb_context *sam_ctx,
					 TALLOC_CTX *mem_ctx,
					 const char *domain,
					 const char *netbios_domain,
					 struct dom_sid *domain_sid,
					 const char *domain_guid,
					 const char *user,
					 uint32_t acct_control,
					 const char *src_address,
					 uint32_t version,
					 struct loadparm_context *lp_ctx,
					 struct netlogon_samlogon_response *netlogon)
{
	const char *ref_attrs[] = {"nETBIOSName", "dnsRoot", "ncName", NULL};
	const char *dom_attrs[] = {"objectGUID", NULL};
	const char *none_attrs[] = {NULL};
	struct ldb_result *ref_res = NULL, *dom_res = NULL, *user_res = NULL;
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
	bool user_known;
	NTSTATUS status;

	partitions_basedn = samdb_partitions_dn(sam_ctx, mem_ctx);

	/* the domain has an optional trailing . */
	if (domain && domain[strlen(domain)-1] == '.') {
		domain = talloc_strndup(mem_ctx, domain, strlen(domain)-1);
	}

	if (domain) {
		struct ldb_dn *dom_dn;
		/* try and find the domain */

		ret = ldb_search(sam_ctx, mem_ctx, &ref_res,
				 partitions_basedn, LDB_SCOPE_ONELEVEL,
				 ref_attrs,
				 "(&(&(objectClass=crossRef)(dnsRoot=%s))(nETBIOSName=*))",
				 ldb_binary_encode_string(mem_ctx, domain));
	
		if (ret != LDB_SUCCESS) {
			DEBUG(2,("Unable to find referece to '%s' in sam: %s\n",
				 domain, 
				 ldb_errstring(sam_ctx)));
			return NT_STATUS_NO_SUCH_DOMAIN;
		} else if (ref_res->count == 1) {
			dom_dn = ldb_msg_find_attr_as_dn(sam_ctx, mem_ctx, ref_res->msgs[0], "ncName");
			if (!dom_dn) {
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
			ret = ldb_search(sam_ctx, mem_ctx, &dom_res,
					 dom_dn, LDB_SCOPE_BASE, dom_attrs,
					 "objectClass=domain");
			if (ret != LDB_SUCCESS) {
				DEBUG(2,("Error finding domain '%s'/'%s' in sam: %s\n", domain, ldb_dn_get_linearized(dom_dn), ldb_errstring(sam_ctx)));
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
			if (dom_res->count != 1) {
				DEBUG(2,("Error finding domain '%s'/'%s' in sam\n", domain, ldb_dn_get_linearized(dom_dn)));
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
		} else if (ref_res->count > 1) {
			talloc_free(ref_res);
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
	}

	if (netbios_domain) {
		struct ldb_dn *dom_dn;
		/* try and find the domain */

		ret = ldb_search(sam_ctx, mem_ctx, &ref_res,
				 partitions_basedn, LDB_SCOPE_ONELEVEL,
				 ref_attrs,
				 "(&(objectClass=crossRef)(ncName=*)(nETBIOSName=%s))",
				 ldb_binary_encode_string(mem_ctx, netbios_domain));
	
		if (ret != LDB_SUCCESS) {
			DEBUG(2,("Unable to find referece to '%s' in sam: %s\n",
				 netbios_domain, 
				 ldb_errstring(sam_ctx)));
			return NT_STATUS_NO_SUCH_DOMAIN;
		} else if (ref_res->count == 1) {
			dom_dn = ldb_msg_find_attr_as_dn(sam_ctx, mem_ctx, ref_res->msgs[0], "ncName");
			if (!dom_dn) {
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
			ret = ldb_search(sam_ctx, mem_ctx, &dom_res,
					 dom_dn, LDB_SCOPE_BASE, dom_attrs,
					 "objectClass=domain");
			if (ret != LDB_SUCCESS) {
				DEBUG(2,("Error finding domain '%s'/'%s' in sam: %s\n", domain, ldb_dn_get_linearized(dom_dn), ldb_errstring(sam_ctx)));
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
			if (dom_res->count != 1) {
				DEBUG(2,("Error finding domain '%s'/'%s' in sam\n", domain, ldb_dn_get_linearized(dom_dn)));
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
		} else if (ref_res->count > 1) {
			talloc_free(ref_res);
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
	}

	if ((dom_res == NULL || dom_res->count == 0) && (domain_guid || domain_sid)) {
		ref_res = NULL;

		if (domain_guid) {
			struct GUID binary_guid;
			struct ldb_val guid_val;
			enum ndr_err_code ndr_err;

			/* By this means, we ensure we don't have funny stuff in the GUID */

			status = GUID_from_string(domain_guid, &binary_guid);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}

			/* And this gets the result into the binary format we want anyway */
			ndr_err = ndr_push_struct_blob(&guid_val, mem_ctx, NULL, &binary_guid,
						       (ndr_push_flags_fn_t)ndr_push_GUID);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			ret = ldb_search(sam_ctx, mem_ctx, &dom_res,
						 NULL, LDB_SCOPE_SUBTREE, 
						 dom_attrs, 
						 "(&(objectCategory=DomainDNS)(objectGUID=%s))", 
						 ldb_binary_encode(mem_ctx, guid_val));
		} else { /* domain_sid case */
			struct dom_sid *sid;
			struct ldb_val sid_val;
			enum ndr_err_code ndr_err;
			
			/* Rather than go via the string, just push into the NDR form */
			ndr_err = ndr_push_struct_blob(&sid_val, mem_ctx, NULL, &sid,
						       (ndr_push_flags_fn_t)ndr_push_dom_sid);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return NT_STATUS_INVALID_PARAMETER;
			}

			ret = ldb_search(sam_ctx, mem_ctx, &dom_res,
						 NULL, LDB_SCOPE_SUBTREE, 
						 dom_attrs, 
						 "(&(objectCategory=DomainDNS)(objectSID=%s))", 
						 ldb_binary_encode(mem_ctx, sid_val));
		}
		
		if (ret != LDB_SUCCESS) {
			DEBUG(2,("Unable to find referece to GUID '%s' or SID %s in sam: %s\n",
				 domain_guid, dom_sid_string(mem_ctx, domain_sid),
				 ldb_errstring(sam_ctx)));
			return NT_STATUS_NO_SUCH_DOMAIN;
		} else if (dom_res->count == 1) {
			/* try and find the domain */
			ret = ldb_search(sam_ctx, mem_ctx, &ref_res,
						 partitions_basedn, LDB_SCOPE_ONELEVEL, 
						 ref_attrs, 
						 "(&(objectClass=crossRef)(ncName=%s))", 
						 ldb_dn_get_linearized(dom_res->msgs[0]->dn));
			
			if (ret != LDB_SUCCESS) {
				DEBUG(2,("Unable to find referece to '%s' in sam: %s\n",
					 ldb_dn_get_linearized(dom_res->msgs[0]->dn), 
					 ldb_errstring(sam_ctx)));
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

	/* work around different inputs for not-specified users */
	if (!user) {
		user = "";
	}

	/* Enquire about any valid username with just a CLDAP packet -
	 * if kerberos didn't also do this, the security folks would
	 * scream... */
	if (user[0]) {							\
		/* Only allow some bits to be enquired:  [MS-ATDS] 7.3.3.2 */
		if (acct_control == (uint32_t)-1) {
			acct_control = 0;
		}
		acct_control = acct_control & (ACB_TEMPDUP | ACB_NORMAL | ACB_DOMTRUST | ACB_WSTRUST | ACB_SVRTRUST);

		/* We must exclude disabled accounts, but otherwise do the bitwise match the client asked for */
		ret = ldb_search(sam_ctx, mem_ctx, &user_res,
					 dom_res->msgs[0]->dn, LDB_SCOPE_SUBTREE, 
					 none_attrs, 
					 "(&(objectClass=user)(samAccountName=%s)"
					 "(!(userAccountControl:" LDB_OID_COMPARATOR_AND ":=%u))"
					 "(userAccountControl:" LDB_OID_COMPARATOR_OR ":=%u))", 
					 ldb_binary_encode_string(mem_ctx, user),
					 UF_ACCOUNTDISABLE, samdb_acb2uf(acct_control));
		if (ret != LDB_SUCCESS) {
			DEBUG(2,("Unable to find referece to user '%s' with ACB 0x%8x under %s: %s\n",
				 user, acct_control, ldb_dn_get_linearized(dom_res->msgs[0]->dn),
				 ldb_errstring(sam_ctx)));
			return NT_STATUS_NO_SUCH_USER;
		} else if (user_res->count == 1) {
			user_known = true;
		} else {
			user_known = false;
		}

	} else {
		user_known = true;
	}
		
	server_type      = 
		NBT_SERVER_DS | NBT_SERVER_TIMESERV |
		NBT_SERVER_CLOSEST | NBT_SERVER_WRITABLE | 
		NBT_SERVER_GOOD_TIMESERV | DS_DNS_CONTROLLER |
		DS_DNS_DOMAIN;

	if (samdb_is_pdc(sam_ctx)) {
		server_type |= NBT_SERVER_PDC;
	}

	if (samdb_is_gc(sam_ctx)) {
		server_type |= NBT_SERVER_GC;
	}

	if (str_list_check(services, "ldap")) {
		server_type |= NBT_SERVER_LDAP;
	}

	if (str_list_check(services, "kdc")) {
		server_type |= NBT_SERVER_KDC;
	}

	if (ldb_dn_compare(ldb_get_root_basedn(sam_ctx), ldb_get_default_basedn(sam_ctx)) == 0) {
		server_type |= DS_DNS_FOREST;
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
	/* FIXME: Hardcoded site names */
	server_site      = "Default-First-Site-Name";
	client_site      = "Default-First-Site-Name";
	load_interfaces(mem_ctx, lp_interfaces(lp_ctx), &ifaces);
	pdc_ip           = iface_best_ip(ifaces, src_address);

	ZERO_STRUCTP(netlogon);

	/* check if either of these bits is present */
	if (version & (NETLOGON_NT_VERSION_5EX|NETLOGON_NT_VERSION_5EX_WITH_IP)) {
		uint32_t extra_flags = 0;
		netlogon->ntver = NETLOGON_NT_VERSION_5EX;

		/* could check if the user exists */
		if (user_known) {
			netlogon->data.nt5_ex.command      = LOGON_SAM_LOGON_RESPONSE_EX;
		} else {
			netlogon->data.nt5_ex.command      = LOGON_SAM_LOGON_USER_UNKNOWN_EX;
		}
		netlogon->data.nt5_ex.server_type  = server_type;
		netlogon->data.nt5_ex.domain_uuid  = domain_uuid;
		netlogon->data.nt5_ex.forest       = realm;
		netlogon->data.nt5_ex.dns_domain   = dns_domain;
		netlogon->data.nt5_ex.pdc_dns_name = pdc_dns_name;
		netlogon->data.nt5_ex.domain       = flatname;
		netlogon->data.nt5_ex.pdc_name     = lp_netbios_name(lp_ctx);
		netlogon->data.nt5_ex.user_name    = user;
		netlogon->data.nt5_ex.server_site  = server_site;
		netlogon->data.nt5_ex.client_site  = client_site;

		if (version & NETLOGON_NT_VERSION_5EX_WITH_IP) {
			/* Clearly this needs to be fixed up for IPv6 */
			extra_flags = NETLOGON_NT_VERSION_5EX_WITH_IP;
			netlogon->data.nt5_ex.sockaddr.sockaddr_family    = 2;
			netlogon->data.nt5_ex.sockaddr.pdc_ip       = pdc_ip;
			netlogon->data.nt5_ex.sockaddr.remaining = data_blob_talloc_zero(mem_ctx, 8);
		}
		netlogon->data.nt5_ex.nt_version   = NETLOGON_NT_VERSION_1|NETLOGON_NT_VERSION_5EX|extra_flags;
		netlogon->data.nt5_ex.lmnt_token   = 0xFFFF;
		netlogon->data.nt5_ex.lm20_token   = 0xFFFF;

	} else if (version & NETLOGON_NT_VERSION_5) {
		netlogon->ntver = NETLOGON_NT_VERSION_5;

		/* could check if the user exists */
		if (user_known) {
			netlogon->data.nt5.command      = LOGON_SAM_LOGON_RESPONSE;
		} else {
			netlogon->data.nt5.command      = LOGON_SAM_LOGON_USER_UNKNOWN;
		}
		netlogon->data.nt5.pdc_name     = pdc_name;
		netlogon->data.nt5.user_name    = user;
		netlogon->data.nt5.domain_name  = flatname;
		netlogon->data.nt5.domain_uuid  = domain_uuid;
		netlogon->data.nt5.forest       = realm;
		netlogon->data.nt5.dns_domain   = dns_domain;
		netlogon->data.nt5.pdc_dns_name = pdc_dns_name;
		netlogon->data.nt5.pdc_ip       = pdc_ip;
		netlogon->data.nt5.server_type  = server_type;
		netlogon->data.nt5.nt_version   = NETLOGON_NT_VERSION_1|NETLOGON_NT_VERSION_5;
		netlogon->data.nt5.lmnt_token   = 0xFFFF;
		netlogon->data.nt5.lm20_token   = 0xFFFF;

	} else /* (version & NETLOGON_NT_VERSION_1) and all other cases */ {
		netlogon->ntver = NETLOGON_NT_VERSION_1;
		/* could check if the user exists */
		if (user_known) {
			netlogon->data.nt4.command      = LOGON_SAM_LOGON_RESPONSE;
		} else {
			netlogon->data.nt4.command      = LOGON_SAM_LOGON_USER_UNKNOWN;
		}
		netlogon->data.nt4.server      = pdc_name;
		netlogon->data.nt4.user_name   = user;
		netlogon->data.nt4.domain      = flatname;
		netlogon->data.nt4.nt_version  = NETLOGON_NT_VERSION_1;
		netlogon->data.nt4.lmnt_token  = 0xFFFF;
		netlogon->data.nt4.lm20_token  = 0xFFFF;
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
	struct cldapd_server *cldapd = talloc_get_type(cldap->incoming.private_data, struct cldapd_server);
	int i;
	const char *domain = NULL;
	const char *host = NULL;
	const char *user = NULL;
	const char *domain_guid = NULL;
	const char *domain_sid = NULL;
	int acct_control = -1;
	int version = -1;
	struct netlogon_samlogon_response netlogon;
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

	status = fill_netlogon_samlogon_response(cldapd->samctx, tmp_ctx, domain, NULL, NULL, domain_guid,
						 user, acct_control, src->addr, 
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
