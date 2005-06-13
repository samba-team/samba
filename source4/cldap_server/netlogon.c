/* 
   Unix SMB/CIFS implementation.

   CLDAP server - netlogon handling

   Copyright (C) Andrew Tridgell	2005
   
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
#include "libcli/ldap/ldap.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "smbd/service_task.h"
#include "cldap_server/cldap_server.h"

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
				     union nbt_cldap_netlogon *netlogon)
{
	const char *attrs[] = {"realm", "dnsDomain", "objectGUID", "name", NULL};
	struct ldb_message **res;
	int ret;
	const char **services = lp_server_services();
	uint32_t server_type;
	const char *pdc_name;
	struct GUID domain_uuid;
	const char *realm;
	const char *dns_domain;
	const char *pdc_dns_name;
	const char *flatname;
	const char *site_name;
	const char *site_name2;
	const char *pdc_ip;

	if (cldapd->samctx == NULL) {
		cldapd->samctx = samdb_connect(mem_ctx);
		if (cldapd->samctx == NULL) {
			DEBUG(2,("Unable to open sam in cldap netlogon reply\n"));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	/* the domain has an optional trailing . */
	if (domain && domain[strlen(domain)-1] == '.') {
		domain = talloc_strndup(mem_ctx, domain, strlen(domain)-1);
	}

	/* try and find the domain */
	ret = gendb_search(cldapd->samctx, mem_ctx, NULL, &res, attrs, 
			   "(&(objectClass=domainDNS)(|(dnsDomain=%s)(objectGUID=%s)))", 
			   domain?domain:"", 
			   domain_guid?domain_guid:"");
	if (ret != 1) {
		DEBUG(2,("Unable to find domain '%s' in sam\n", domain));
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	server_type      = 
		NBT_SERVER_PDC | NBT_SERVER_GC | 
		NBT_SERVER_DS | NBT_SERVER_TIMESERV |
		NBT_SERVER_CLOSEST | NBT_SERVER_WRITABLE | 
		NBT_SERVER_GOOD_TIMESERV;

	if (str_list_check(services, "ldap")) {
		server_type |= NBT_SERVER_LDAP;
	}

	if (str_list_check(services, "kdc")) {
		server_type |= NBT_SERVER_KDC;
	}

	pdc_name         = talloc_asprintf(mem_ctx, "\\\\%s", lp_netbios_name());
	domain_uuid      = samdb_result_guid(res[0], "objectGUID");
	realm            = samdb_result_string(res[0], "realm", lp_realm());
	dns_domain       = samdb_result_string(res[0], "dnsDomain", lp_realm());
	pdc_dns_name     = talloc_asprintf(mem_ctx, "%s.%s", 
					   strlower_talloc(mem_ctx, lp_netbios_name()), 
					   dns_domain);
	flatname         = samdb_result_string(res[0], "name", lp_workgroup());
	site_name        = "Default-First-Site-Name";
	site_name2       = "";
	pdc_ip           = iface_best_ip(src_address);

	ZERO_STRUCTP(netlogon);

	switch (version & 0xF) {
	case 0:
	case 1:
		netlogon->logon1.pdc_name    = pdc_name;
		netlogon->logon1.user_name   = user;
		netlogon->logon1.domain_name = flatname;
		netlogon->logon1.nt_version  = 1;
		netlogon->logon1.lmnt_token  = 0xFFFF;
		netlogon->logon1.lm20_token  = 0xFFFF;
		break;
	case 2:
	case 3:
		netlogon->logon2.pdc_name     = pdc_name;
		netlogon->logon2.user_name    = user;
		netlogon->logon2.domain_name  = flatname;
		netlogon->logon2.domain_uuid  = domain_uuid;
		netlogon->logon2.forest       = realm;
		netlogon->logon2.dns_domain   = dns_domain;
		netlogon->logon2.pdc_dns_name = pdc_dns_name;
		netlogon->logon2.pdc_ip       = pdc_ip;
		netlogon->logon2.server_type  = server_type;
		netlogon->logon2.nt_version   = 3;
		netlogon->logon2.lmnt_token   = 0xFFFF;
		netlogon->logon2.lm20_token   = 0xFFFF;
		break;
	case 4:
	case 5:
	case 6:
	case 7:
		netlogon->logon3.server_type  = server_type;
		netlogon->logon3.domain_uuid  = domain_uuid;
		netlogon->logon3.forest       = realm;
		netlogon->logon3.dns_domain   = dns_domain;
		netlogon->logon3.pdc_dns_name = pdc_dns_name;
		netlogon->logon3.domain       = flatname;
		netlogon->logon3.pdc_name     = pdc_name;
		netlogon->logon3.user_name    = user;
		netlogon->logon3.site_name    = site_name;
		netlogon->logon3.site_name2   = site_name2;
		netlogon->logon3.nt_version   = 3;
		netlogon->logon3.lmnt_token   = 0xFFFF;
		netlogon->logon3.lm20_token   = 0xFFFF;
		break;
	default:
		netlogon->logon4.server_type  = server_type;
		netlogon->logon4.domain_uuid  = domain_uuid;
		netlogon->logon4.forest       = realm;
		netlogon->logon4.dns_domain   = dns_domain;
		netlogon->logon4.pdc_dns_name = pdc_dns_name;
		netlogon->logon4.domain       = flatname;
		netlogon->logon4.pdc_name     = lp_netbios_name();
		netlogon->logon4.user_name    = user;
		netlogon->logon4.site_name    = site_name;
		netlogon->logon4.site_name2   = site_name2;
		netlogon->logon4.unknown      = 10;
		netlogon->logon4.unknown2     = 2;
		netlogon->logon4.pdc_ip       = pdc_ip;
		netlogon->logon4.nt_version   = 5;
		netlogon->logon4.lmnt_token   = 0xFFFF;
		netlogon->logon4.lm20_token   = 0xFFFF;
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
			     const char *src_address, int src_port)
{
	struct cldapd_server *cldapd = talloc_get_type(cldap->incoming.private, struct cldapd_server);
	int i;
	const char *domain = NULL;
	const char *host = NULL;
	const char *user = "";
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
		if (t->operation != LDB_OP_SIMPLE) goto failed;
		if (strcasecmp(t->u.simple.attr, "DnsDomain") == 0) {
			domain = talloc_strndup(tmp_ctx, 
						t->u.simple.value.data,
						t->u.simple.value.length);
		}
		if (strcasecmp(t->u.simple.attr, "Host") == 0) {
			host = talloc_strndup(tmp_ctx, 
					      t->u.simple.value.data,
					      t->u.simple.value.length);
		}
		if (strcasecmp(t->u.simple.attr, "DomainGuid") == 0) {
			NTSTATUS enc_status;
			struct GUID guid;
			enc_status = ldap_decode_ndr_GUID(tmp_ctx, 
							  t->u.simple.value, &guid);
			if (NT_STATUS_IS_OK(enc_status)) {
				domain_guid = GUID_string(tmp_ctx, &guid);
			}
		}
		if (strcasecmp(t->u.simple.attr, "DomainSid") == 0) {
			domain_sid = talloc_strndup(tmp_ctx, 
						    t->u.simple.value.data,
						    t->u.simple.value.length);
		}
		if (strcasecmp(t->u.simple.attr, "User") == 0) {
			user = talloc_strndup(tmp_ctx, 
					      t->u.simple.value.data,
					      t->u.simple.value.length);
		}
		if (strcasecmp(t->u.simple.attr, "NtVer") == 0 &&
		    t->u.simple.value.length == 4) {
			version = IVAL(t->u.simple.value.data, 0);
		}
		if (strcasecmp(t->u.simple.attr, "AAC") == 0 &&
		    t->u.simple.value.length == 4) {
			acct_control = IVAL(t->u.simple.value.data, 0);
		}
	}

	if (domain_guid == NULL && domain == NULL) {
		domain = lp_realm();
	}

	if (version == -1) {
		goto failed;
	}

	DEBUG(5,("cldap netlogon query domain=%s host=%s user=%s version=%d guid=%s\n",
		 domain, host, user, version, domain_guid));

	status = cldapd_netlogon_fill(cldapd, tmp_ctx, domain, domain_guid, 
				      user, src_address, 
				      version, &netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = cldap_netlogon_reply(cldap, message_id, src_address, src_port, version,
				      &netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	talloc_free(tmp_ctx);
	return;
	
failed:
	DEBUG(0,("cldap netlogon query failed domain=%s host=%s version=%d - %s\n",
		 domain, host, version, nt_errstr(status)));
	talloc_free(tmp_ctx);
	cldap_empty_reply(cldap, message_id, src_address, src_port);	
}
