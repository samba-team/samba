/*
   Unix SMB/CIFS implementation.

   dsgetdcname

   Copyright (C) Gerald Carter 2006
   Copyright (C) Guenther Deschner 2007-2008

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

#define DSGETDCNAME_FMT	"DSGETDCNAME/DOMAIN/%s"
/* 15 minutes */
#define DSGETDCNAME_CACHE_TTL	60*15

struct ip_service_name {
	struct sockaddr_storage ss;
	unsigned port;
	const char *hostname;
};

/****************************************************************
****************************************************************/

void debug_dsdcinfo_flags(int lvl, uint32_t flags)
{
	DEBUG(lvl,("debug_dsdcinfo_flags: 0x%08x\n\t", flags));

	if (flags & DS_FORCE_REDISCOVERY)
		DEBUGADD(lvl,("DS_FORCE_REDISCOVERY "));
	if (flags & 0x000000002)
		DEBUGADD(lvl,("0x00000002 "));
	if (flags & 0x000000004)
		DEBUGADD(lvl,("0x00000004 "));
	if (flags & 0x000000008)
		DEBUGADD(lvl,("0x00000008 "));
	if (flags & DS_DIRECTORY_SERVICE_REQUIRED)
		DEBUGADD(lvl,("DS_DIRECTORY_SERVICE_REQUIRED "));
	if (flags & DS_DIRECTORY_SERVICE_PREFERRED)
		DEBUGADD(lvl,("DS_DIRECTORY_SERVICE_PREFERRED "));
	if (flags & DS_GC_SERVER_REQUIRED)
		DEBUGADD(lvl,("DS_GC_SERVER_REQUIRED "));
	if (flags & DS_PDC_REQUIRED)
		DEBUGADD(lvl,("DS_PDC_REQUIRED "));
	if (flags & DS_BACKGROUND_ONLY)
		DEBUGADD(lvl,("DS_BACKGROUND_ONLY "));
	if (flags & DS_IP_REQUIRED)
		DEBUGADD(lvl,("DS_IP_REQUIRED "));
	if (flags & DS_KDC_REQUIRED)
		DEBUGADD(lvl,("DS_KDC_REQUIRED "));
	if (flags & DS_TIMESERV_REQUIRED)
		DEBUGADD(lvl,("DS_TIMESERV_REQUIRED "));
	if (flags & DS_WRITABLE_REQUIRED)
		DEBUGADD(lvl,("DS_WRITABLE_REQUIRED "));
	if (flags & DS_GOOD_TIMESERV_PREFERRED)
		DEBUGADD(lvl,("DS_GOOD_TIMESERV_PREFERRED "));
	if (flags & DS_AVOID_SELF)
		DEBUGADD(lvl,("DS_AVOID_SELF "));
	if (flags & DS_ONLY_LDAP_NEEDED)
		DEBUGADD(lvl,("DS_ONLY_LDAP_NEEDED "));
	if (flags & DS_IS_FLAT_NAME)
		DEBUGADD(lvl,("DS_IS_FLAT_NAME "));
	if (flags & DS_IS_DNS_NAME)
		DEBUGADD(lvl,("DS_IS_DNS_NAME "));
	if (flags & 0x00040000)
		DEBUGADD(lvl,("0x00040000 "));
	if (flags & 0x00080000)
		DEBUGADD(lvl,("0x00080000 "));
	if (flags & 0x00100000)
		DEBUGADD(lvl,("0x00100000 "));
	if (flags & 0x00200000)
		DEBUGADD(lvl,("0x00200000 "));
	if (flags & 0x00400000)
		DEBUGADD(lvl,("0x00400000 "));
	if (flags & 0x00800000)
		DEBUGADD(lvl,("0x00800000 "));
	if (flags & 0x01000000)
		DEBUGADD(lvl,("0x01000000 "));
	if (flags & 0x02000000)
		DEBUGADD(lvl,("0x02000000 "));
	if (flags & 0x04000000)
		DEBUGADD(lvl,("0x04000000 "));
	if (flags & 0x08000000)
		DEBUGADD(lvl,("0x08000000 "));
	if (flags & 0x10000000)
		DEBUGADD(lvl,("0x10000000 "));
	if (flags & 0x20000000)
		DEBUGADD(lvl,("0x20000000 "));
	if (flags & DS_RETURN_DNS_NAME)
		DEBUGADD(lvl,("DS_RETURN_DNS_NAME "));
	if (flags & DS_RETURN_FLAT_NAME)
		DEBUGADD(lvl,("DS_RETURN_FLAT_NAME "));
	if (flags)
		DEBUGADD(lvl,("\n"));
}

/****************************************************************
****************************************************************/

static char *dsgetdcname_cache_key(TALLOC_CTX *mem_ctx, const char *domain)
{
	if (!mem_ctx || !domain) {
		return NULL;
	}

	return talloc_asprintf_strupper_m(mem_ctx, DSGETDCNAME_FMT, domain);
}

/****************************************************************
****************************************************************/

static NTSTATUS dsgetdcname_cache_delete(TALLOC_CTX *mem_ctx,
					const char *domain_name)
{
	char *key;

	if (!gencache_init()) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	key = dsgetdcname_cache_key(mem_ctx, domain_name);
	if (!key) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!gencache_del(key)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS dsgetdcname_cache_store(TALLOC_CTX *mem_ctx,
					const char *domain_name,
					struct netr_DsRGetDCNameInfo *info)
{
	time_t expire_time;
	char *key;
	bool ret = false;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;

	if (!gencache_init()) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	key = dsgetdcname_cache_key(mem_ctx, domain_name);
	if (!key) {
		return NT_STATUS_NO_MEMORY;
	}

	expire_time = time(NULL) + DSGETDCNAME_CACHE_TTL;

	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, info,
		       (ndr_push_flags_fn_t)ndr_push_netr_DsRGetDCNameInfo);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (gencache_lock_entry(key) != 0) {
		data_blob_free(&blob);
		return NT_STATUS_LOCK_NOT_GRANTED;
	}

	ret = gencache_set_data_blob(key, &blob, expire_time);
	data_blob_free(&blob);

	gencache_unlock_entry(key);

	return ret ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************
****************************************************************/

static NTSTATUS dsgetdcname_cache_refresh(TALLOC_CTX *mem_ctx,
					  const char *domain_name,
					  struct GUID *domain_guid,
					  uint32_t flags,
					  const char *site_name,
					  struct netr_DsRGetDCNameInfo *info)
{
	uint32_t nt_version = NETLOGON_VERSION_1;

	/* check if matching entry is older then 15 minutes, if yes, send
	 * CLDAP/MAILSLOT ping again and store the cached data */

	if (ads_cldap_netlogon(mem_ctx, info->dc_unc,
			       info->domain_name, &nt_version, NULL)) {

		dsgetdcname_cache_delete(mem_ctx, domain_name);

		return dsgetdcname_cache_store(mem_ctx,
					       info->domain_name,
					       info);
	}

	return NT_STATUS_INVALID_NETWORK_RESPONSE;
}

/****************************************************************
****************************************************************/

static uint32_t get_cldap_reply_server_flags(union nbt_cldap_netlogon *r,
					     uint32_t nt_version)
{
	switch (nt_version & 0x000000ff) {
		case 0:
		case 1:
			return 0;
		case 2:
		case 3:
			return r->logon3.server_type;
		case 4:
		case 5:
		case 6:
		case 7:
			return r->logon5.server_type;
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15:
			return r->logon13.server_type;
		default:
			return r->logon29.server_type;
	}
}

/****************************************************************
****************************************************************/

#define RETURN_ON_FALSE(x) if (!x) return false;

static bool check_cldap_reply_required_flags(uint32_t ret_flags,
					     uint32_t req_flags)
{
	if (ret_flags == 0) {
		return true;
	}

	if (req_flags & DS_PDC_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_PDC);

	if (req_flags & DS_GC_SERVER_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_GC);

	if (req_flags & DS_ONLY_LDAP_NEEDED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_LDAP);

	if ((req_flags & DS_DIRECTORY_SERVICE_REQUIRED) ||
	    (req_flags & DS_DIRECTORY_SERVICE_PREFERRED))
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_DS);

	if (req_flags & DS_KDC_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_KDC);

	if (req_flags & DS_TIMESERV_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_TIMESERV);

	if (req_flags & DS_WRITABLE_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_WRITABLE);

	return true;
}

/****************************************************************
****************************************************************/

static NTSTATUS dsgetdcname_cache_fetch(TALLOC_CTX *mem_ctx,
					const char *domain_name,
					struct GUID *domain_guid,
					uint32_t flags,
					const char *site_name,
					struct netr_DsRGetDCNameInfo **info_p,
					bool *expired)
{
	char *key;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	struct netr_DsRGetDCNameInfo *info;

	if (!gencache_init()) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	key = dsgetdcname_cache_key(mem_ctx, domain_name);
	if (!key) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!gencache_get_data_blob(key, &blob, expired)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	info = TALLOC_ZERO_P(mem_ctx, struct netr_DsRGetDCNameInfo);
	if (!info) {
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, info,
		      (ndr_pull_flags_fn_t)ndr_pull_netr_DsRGetDCNameInfo);

	data_blob_free(&blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dsgetdcname_cache_delete(mem_ctx, domain_name);
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(netr_DsRGetDCNameInfo, info);
	}

	/* check flags */
	if (!check_cldap_reply_required_flags(info->dc_flags, flags)) {
		DEBUG(10,("invalid flags\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if ((flags & DS_IP_REQUIRED) &&
	    (info->dc_address_type != DS_ADDRESS_TYPE_INET)) {
	    	return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	*info_p = info;

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS dsgetdcname_cached(TALLOC_CTX *mem_ctx,
				   const char *domain_name,
				   struct GUID *domain_guid,
				   uint32_t flags,
				   const char *site_name,
				   struct netr_DsRGetDCNameInfo **info)
{
	NTSTATUS status;
	bool expired = false;

	status = dsgetdcname_cache_fetch(mem_ctx, domain_name, domain_guid,
					 flags, site_name, info, &expired);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("dsgetdcname_cached: cache fetch failed with: %s\n",
			nt_errstr(status)));
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	if (flags & DS_BACKGROUND_ONLY) {
		return status;
	}

	if (expired) {
		status = dsgetdcname_cache_refresh(mem_ctx, domain_name,
						   domain_guid, flags,
						   site_name, *info);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return status;
}

/****************************************************************
****************************************************************/

static bool check_allowed_required_flags(uint32_t flags)
{
	uint32_t return_type = flags & (DS_RETURN_FLAT_NAME|DS_RETURN_DNS_NAME);
	uint32_t offered_type = flags & (DS_IS_FLAT_NAME|DS_IS_DNS_NAME);
	uint32_t query_type = flags & (DS_BACKGROUND_ONLY|DS_FORCE_REDISCOVERY);

	/* FIXME: check for DSGETDC_VALID_FLAGS and check for excluse bits
	 * (DS_PDC_REQUIRED, DS_KDC_REQUIRED, DS_GC_SERVER_REQUIRED) */

	debug_dsdcinfo_flags(10, flags);

	if (return_type == (DS_RETURN_FLAT_NAME|DS_RETURN_DNS_NAME)) {
		return false;
	}

	if (offered_type == (DS_IS_DNS_NAME|DS_IS_FLAT_NAME)) {
		return false;
	}

	if (query_type == (DS_BACKGROUND_ONLY|DS_FORCE_REDISCOVERY)) {
		return false;
	}

#if 0
	if ((flags & DS_RETURN_DNS_NAME) && (!(flags & DS_IP_REQUIRED))) {
		printf("gd: here5 \n");
		return false;
	}
#endif
	return true;
}

/****************************************************************
****************************************************************/

static NTSTATUS discover_dc_netbios(TALLOC_CTX *mem_ctx,
				    const char *domain_name,
				    uint32_t flags,
				    struct ip_service_name **returned_dclist,
				    int *returned_count)
{
	NTSTATUS status;
	enum nbt_name_type name_type = NBT_NAME_LOGON;
	struct ip_service *iplist;
	int i;
	struct ip_service_name *dclist = NULL;
	int count;

	*returned_dclist = NULL;
	*returned_count = 0;

	if (lp_disable_netbios()) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (flags & DS_PDC_REQUIRED) {
		name_type = NBT_NAME_PDC;
	}

	status = internal_resolve_name(domain_name, name_type, NULL,
				       &iplist, &count,
				       "lmhosts wins bcast");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("discover_dc_netbios: failed to find DC\n"));
		return status;
	}

	dclist = TALLOC_ZERO_ARRAY(mem_ctx, struct ip_service_name, count);
	if (!dclist) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<count; i++) {

		char addr[INET6_ADDRSTRLEN];
		struct ip_service_name *r = &dclist[i];

		print_sockaddr(addr, sizeof(addr),
			       &iplist[i].ss);

		r->ss	= iplist[i].ss;
		r->port = iplist[i].port;
		r->hostname = talloc_strdup(mem_ctx, addr);
		if (!r->hostname) {
			return NT_STATUS_NO_MEMORY;
		}

	}

	*returned_dclist = dclist;
	*returned_count = count;

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS discover_dc_dns(TALLOC_CTX *mem_ctx,
				const char *domain_name,
				struct GUID *domain_guid,
				uint32_t flags,
				const char *site_name,
				struct ip_service_name **returned_dclist,
				int *return_count)
{
	int i, j;
	NTSTATUS status;
	struct dns_rr_srv *dcs = NULL;
	int numdcs = 0;
	int numaddrs = 0;
	struct ip_service_name *dclist = NULL;
	int count = 0;

	if (flags & DS_PDC_REQUIRED) {
		status = ads_dns_query_pdc(mem_ctx, domain_name,
					   &dcs, &numdcs);
	} else if (flags & DS_GC_SERVER_REQUIRED) {
		status = ads_dns_query_gcs(mem_ctx, domain_name, site_name,
					   &dcs, &numdcs);
	} else if (flags & DS_KDC_REQUIRED) {
		status = ads_dns_query_kdcs(mem_ctx, domain_name, site_name,
					    &dcs, &numdcs);
	} else if (flags & DS_DIRECTORY_SERVICE_REQUIRED) {
		status = ads_dns_query_dcs(mem_ctx, domain_name, site_name,
					   &dcs, &numdcs);
	} else if (domain_guid) {
		status = ads_dns_query_dcs_guid(mem_ctx, domain_name,
						domain_guid, &dcs, &numdcs);
	} else {
		status = ads_dns_query_dcs(mem_ctx, domain_name, site_name,
					   &dcs, &numdcs);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (numdcs == 0) {
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	for (i=0;i<numdcs;i++) {
		numaddrs += MAX(dcs[i].num_ips,1);
	}

	dclist = TALLOC_ZERO_ARRAY(mem_ctx,
				   struct ip_service_name,
				   numaddrs);
	if (!dclist) {
		return NT_STATUS_NO_MEMORY;
	}

	/* now unroll the list of IP addresses */

	*return_count = 0;
	i = 0;
	j = 0;

	while ((i < numdcs) && (count < numaddrs)) {

		struct ip_service_name *r = &dclist[count];

		r->port = dcs[count].port;
		r->hostname = dcs[count].hostname;

		if (!(flags & DS_IP_REQUIRED)) {
			count++;
			continue;
		}

		/* If we don't have an IP list for a name, lookup it up */

		if (!dcs[i].ss_s) {
			interpret_string_addr(&r->ss, dcs[i].hostname, 0);
			i++;
			j = 0;
		} else {
			/* use the IP addresses from the SRV sresponse */

			if (j >= dcs[i].num_ips) {
				i++;
				j = 0;
				continue;
			}

			r->ss = dcs[i].ss_s[j];
			j++;
		}

		/* make sure it is a valid IP.  I considered checking the
		 * negative connection cache, but this is the wrong place for
		 * it.  Maybe only as a hac.  After think about it, if all of
		 * the IP addresses retuend from DNS are dead, what hope does a
		 * netbios name lookup have?  The standard reason for falling
		 * back to netbios lookups is that our DNS server doesn't know
		 * anything about the DC's   -- jerry */

		if (!is_zero_addr(&r->ss)) {
			count++;
			continue;
		}
	}

	*returned_dclist = dclist;
	*return_count = count;

	if (count > 0) {
		return NT_STATUS_OK;
	}

	return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
}

/****************************************************************
****************************************************************/

static NTSTATUS make_domain_controller_info(TALLOC_CTX *mem_ctx,
					    const char *dc_unc,
					    const char *dc_address,
					    uint32_t dc_address_type,
					    const struct GUID *domain_guid,
					    const char *domain_name,
					    const char *forest_name,
					    uint32_t flags,
					    const char *dc_site_name,
					    const char *client_site_name,
					    struct netr_DsRGetDCNameInfo **info_out)
{
	struct netr_DsRGetDCNameInfo *info;

	info = TALLOC_ZERO_P(mem_ctx, struct netr_DsRGetDCNameInfo);
	NT_STATUS_HAVE_NO_MEMORY(info);

	if (dc_unc) {
		info->dc_unc = talloc_strdup(mem_ctx, dc_unc);
		NT_STATUS_HAVE_NO_MEMORY(info->dc_unc);
	}

	if (dc_address) {
		info->dc_address = talloc_strdup(mem_ctx, dc_address);
		NT_STATUS_HAVE_NO_MEMORY(info->dc_address);
	}

	info->dc_address_type = dc_address_type;

	if (domain_guid) {
		info->domain_guid = *domain_guid;
	}

	if (domain_name) {
		info->domain_name = talloc_strdup(mem_ctx, domain_name);
		NT_STATUS_HAVE_NO_MEMORY(info->domain_name);
	}

	if (forest_name) {
		info->forest_name = talloc_strdup(mem_ctx, forest_name);
		NT_STATUS_HAVE_NO_MEMORY(info->forest_name);
		flags |= DS_DNS_FOREST;
	}

	info->dc_flags = flags;

	if (dc_site_name) {
		info->dc_site_name = talloc_strdup(mem_ctx, dc_site_name);
		NT_STATUS_HAVE_NO_MEMORY(info->dc_site_name);
	}

	if (client_site_name) {
		info->client_site_name = talloc_strdup(mem_ctx,
						       client_site_name);
		NT_STATUS_HAVE_NO_MEMORY(info->client_site_name);
	}

	*info_out = info;

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS make_dc_info_from_cldap_reply(TALLOC_CTX *mem_ctx,
					      uint32_t flags,
					      struct sockaddr_storage *ss,
					      uint32_t nt_version,
					      union nbt_cldap_netlogon *r,
					      struct netr_DsRGetDCNameInfo **info)
{
	const char *dc_hostname, *dc_domain_name;
	const char *dc_address = NULL;
	const char *dc_forest = NULL;
	uint32_t dc_address_type = 0;
	uint32_t dc_flags = 0;
	struct GUID *dc_domain_guid = NULL;
	const char *dc_server_site = NULL;
	const char *dc_client_site = NULL;

	char addr[INET6_ADDRSTRLEN];

	print_sockaddr(addr, sizeof(addr), ss);

	dc_address = talloc_asprintf(mem_ctx, "\\\\%s", addr);
	NT_STATUS_HAVE_NO_MEMORY(dc_address);
	dc_address_type = DS_ADDRESS_TYPE_INET;

	switch (nt_version & 0x000000ff) {
		case 0:
			return NT_STATUS_INVALID_PARAMETER;
		case 1:
			dc_hostname	= r->logon1.pdc_name;
			dc_domain_name	= r->logon1.domain_name;
			if (flags & DS_PDC_REQUIRED) {
				dc_flags = NBT_SERVER_WRITABLE | NBT_SERVER_PDC;
			}
			break;
		case 2:
		case 3:
			switch (flags & 0xf0000000) {
				case DS_RETURN_FLAT_NAME:
					dc_hostname	= r->logon3.pdc_name;
					dc_domain_name	= r->logon3.domain_name;
					break;
				case DS_RETURN_DNS_NAME:
				default:
					dc_hostname	= r->logon3.pdc_dns_name;
					dc_domain_name	= r->logon3.dns_domain;
					dc_flags |= DS_DNS_DOMAIN | DS_DNS_CONTROLLER;
					break;
			}

			dc_flags	|= r->logon3.server_type;
			dc_forest	= r->logon3.forest;
			dc_domain_guid	= &r->logon3.domain_uuid;

			break;
		case 4:
		case 5:
		case 6:
		case 7:
			switch (flags & 0xf0000000) {
				case DS_RETURN_FLAT_NAME:
					dc_hostname	= r->logon5.pdc_name;
					dc_domain_name	= r->logon5.domain;
					break;
				case DS_RETURN_DNS_NAME:
				default:
					dc_hostname	= r->logon5.pdc_dns_name;
					dc_domain_name	= r->logon5.dns_domain;
					dc_flags |= DS_DNS_DOMAIN | DS_DNS_CONTROLLER;
					break;
			}

			dc_flags	|= r->logon5.server_type;
			dc_forest	= r->logon5.forest;
			dc_domain_guid	= &r->logon5.domain_uuid;
			dc_server_site	= r->logon5.server_site;
			dc_client_site	= r->logon5.client_site;

			break;
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15:
			switch (flags & 0xf0000000) {
				case DS_RETURN_FLAT_NAME:
					dc_hostname	= r->logon13.pdc_name;
					dc_domain_name	= r->logon13.domain;
					break;
				case DS_RETURN_DNS_NAME:
				default:
					dc_hostname	= r->logon13.pdc_dns_name;
					dc_domain_name	= r->logon13.dns_domain;
					dc_flags |= DS_DNS_DOMAIN | DS_DNS_CONTROLLER;
					break;
			}

			dc_flags	|= r->logon13.server_type;
			dc_forest	= r->logon13.forest;
			dc_domain_guid	= &r->logon13.domain_uuid;
			dc_server_site	= r->logon13.server_site;
			dc_client_site	= r->logon13.client_site;

			break;
		default:
			switch (flags & 0xf0000000) {
				case DS_RETURN_FLAT_NAME:
					dc_hostname	= r->logon29.pdc_name;
					dc_domain_name	= r->logon29.domain;
					break;
				case DS_RETURN_DNS_NAME:
				default:
					dc_hostname	= r->logon29.pdc_dns_name;
					dc_domain_name	= r->logon29.dns_domain;
					dc_flags |= DS_DNS_DOMAIN | DS_DNS_CONTROLLER;
					break;
			}

			dc_flags	|= r->logon29.server_type;
			dc_forest	= r->logon29.forest;
			dc_domain_guid	= &r->logon29.domain_uuid;
			dc_server_site	= r->logon29.server_site;
			dc_client_site	= r->logon29.client_site;

			break;
	}

	return make_domain_controller_info(mem_ctx,
					   dc_hostname,
					   dc_address,
					   dc_address_type,
					   dc_domain_guid,
					   dc_domain_name,
					   dc_forest,
					   dc_flags,
					   dc_server_site,
					   dc_client_site,
					   info);
}

/****************************************************************
****************************************************************/

static uint32_t map_ds_flags_to_nt_version(uint32_t flags)
{
	uint32_t nt_version = 0;

	if (flags & DS_PDC_REQUIRED) {
		nt_version |= NETLOGON_VERSION_PDC;
	}

	if (flags & DS_GC_SERVER_REQUIRED) {
		nt_version |= NETLOGON_VERSION_GC;
	}

	if (flags & DS_TRY_NEXTCLOSEST_SITE) {
		nt_version |= NETLOGON_VERSION_WITH_CLOSEST_SITE;
	}

	if (flags & DS_IP_REQUIRED) {
		nt_version |= NETLOGON_VERSION_IP;
	}

	return nt_version;
}

/****************************************************************
****************************************************************/

static NTSTATUS process_dc_dns(TALLOC_CTX *mem_ctx,
			       const char *domain_name,
			       uint32_t flags,
			       struct ip_service_name *dclist,
			       int num_dcs,
			       struct netr_DsRGetDCNameInfo **info)
{
	int i = 0;
	bool valid_dc = false;
	union nbt_cldap_netlogon *r = NULL;
	uint32_t nt_version = NETLOGON_VERSION_5 |
			      NETLOGON_VERSION_5EX;
	uint32_t ret_flags = 0;

	for (i=0; i<num_dcs; i++) {

		DEBUG(10,("LDAP ping to %s\n", dclist[i].hostname));

		if (ads_cldap_netlogon(mem_ctx, dclist[i].hostname,
					domain_name,
					&nt_version,
					&r))
		{
			ret_flags = get_cldap_reply_server_flags(r, nt_version);

			if (check_cldap_reply_required_flags(ret_flags, flags)) {
				valid_dc = true;
				break;
			}
		}

		continue;
	}

	if (!valid_dc) {
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	return make_dc_info_from_cldap_reply(mem_ctx, flags, &dclist[i].ss,
					     nt_version, r, info);
}

/****************************************************************
****************************************************************/

static struct event_context *ev_context(void)
{
	static struct event_context *ctx;

	if (!ctx && !(ctx = event_context_init(NULL))) {
		smb_panic("Could not init event context");
	}
	return ctx;
}

/****************************************************************
****************************************************************/

static struct messaging_context *msg_context(TALLOC_CTX *mem_ctx)
{
	static struct messaging_context *ctx;

	if (!ctx && !(ctx = messaging_init(mem_ctx, server_id_self(),
					   ev_context()))) {
		smb_panic("Could not init messaging context");
	}
	return ctx;
}

/****************************************************************
****************************************************************/

static NTSTATUS process_dc_netbios(TALLOC_CTX *mem_ctx,
				   const char *domain_name,
				   uint32_t flags,
				   struct ip_service_name *dclist,
				   int num_dcs,
				   struct netr_DsRGetDCNameInfo **info)
{
	struct sockaddr_storage ss;
	struct ip_service ip_list;
	enum nbt_name_type name_type = NBT_NAME_LOGON;

	int i;
	const char *dc_hostname, *dc_domain_name;
	const char *dc_address;
	uint32_t dc_address_type;
	uint32_t dc_flags = 0;
	const char *dc_name = NULL;
	const char *dc_forest = NULL;
	const char *dc_server_site = NULL;
	const char *dc_client_site = NULL;
	struct GUID *dc_domain_guid = NULL;
	fstring tmp_dc_name;
	struct messaging_context *msg_ctx = msg_context(mem_ctx);
	struct nbt_ntlogon_packet *reply = NULL;
	uint32_t nt_version = NETLOGON_VERSION_1 |
			      NETLOGON_VERSION_5 |
			      NETLOGON_VERSION_5EX_WITH_IP;

	if (flags & DS_PDC_REQUIRED) {
		name_type = NBT_NAME_PDC;
	}

	nt_version |= map_ds_flags_to_nt_version(flags);

	DEBUG(10,("process_dc_netbios\n"));

	for (i=0; i<num_dcs; i++) {

		ip_list.ss = dclist[i].ss;
		ip_list.port = 0;

		if (!interpret_string_addr(&ss, dclist[i].hostname, AI_NUMERICHOST)) {
			return NT_STATUS_UNSUCCESSFUL;
		}

		if (send_getdc_request(mem_ctx, msg_ctx,
				       &dclist[i].ss, domain_name,
				       NULL, nt_version))
		{
			int k;
			smb_msleep(100);
			for (k=0; k<5; k++) {
				if (receive_getdc_response(mem_ctx,
							   &dclist[i].ss,
							   domain_name,
							   &dc_name,
							   &reply)) {
					namecache_store(dc_name, NBT_NAME_SERVER, 1, &ip_list);
					dc_hostname = dc_name;
					dc_domain_name = talloc_strdup_upper(mem_ctx, domain_name);
					NT_STATUS_HAVE_NO_MEMORY(dc_domain_name);
					goto make_reply;
				}
				smb_msleep(500);
			}
		}

		if (name_status_find(domain_name,
				     name_type,
				     NBT_NAME_SERVER,
				     &dclist[i].ss,
				     tmp_dc_name))
		{
			dc_hostname = tmp_dc_name;
			dc_domain_name = talloc_strdup_upper(mem_ctx, domain_name);
			namecache_store(tmp_dc_name, NBT_NAME_SERVER, 1, &ip_list);
			goto make_reply;
		}
	}

	return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;

 make_reply:

	if (reply && reply->command == NTLOGON_RESPONSE_FROM_PDC2) {

		dc_flags |= reply->req.reply2.server_type;
		dc_forest = reply->req.reply2.forest;
		dc_server_site = reply->req.reply2.server_site;
		dc_client_site = reply->req.reply2.client_site;

		dc_domain_guid = &reply->req.reply2.domain_uuid;

		if (flags & DS_RETURN_DNS_NAME) {
			dc_domain_name = reply->req.reply2.dns_domain;
			dc_hostname = reply->req.reply2.pdc_dns_name;
			dc_flags |= DS_DNS_DOMAIN | DS_DNS_CONTROLLER;
		} else if (flags & DS_RETURN_FLAT_NAME) {
			dc_domain_name = reply->req.reply2.domain;
			dc_hostname = reply->req.reply2.pdc_name;
		}
	}

	if (flags & DS_IP_REQUIRED) {
		char addr[INET6_ADDRSTRLEN];
		print_sockaddr(addr, sizeof(addr), &dclist[i].ss);
		dc_address = talloc_asprintf(mem_ctx, "\\\\%s", addr);
		dc_address_type = DS_ADDRESS_TYPE_INET;
	} else {
		dc_address = talloc_asprintf(mem_ctx, "\\\\%s", dc_hostname);
		dc_address_type = DS_ADDRESS_TYPE_NETBIOS;
	}

	if (flags & DS_PDC_REQUIRED) {
		dc_flags |= NBT_SERVER_PDC | NBT_SERVER_WRITABLE;
	}

	if (dc_forest) {
		dc_flags |= DS_DNS_FOREST;
	}

	return make_domain_controller_info(mem_ctx,
					   dc_hostname,
					   dc_address,
					   dc_address_type,
					   dc_domain_guid,
					   dc_domain_name,
					   dc_forest,
					   dc_flags,
					   dc_server_site,
					   dc_client_site,
					   info);
}

/****************************************************************
****************************************************************/

static NTSTATUS dsgetdcname_rediscover(TALLOC_CTX *mem_ctx,
				       const char *domain_name,
				       struct GUID *domain_guid,
				       uint32_t flags,
				       const char *site_name,
				       struct netr_DsRGetDCNameInfo **info)
{
	NTSTATUS status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	struct ip_service_name *dclist = NULL;
	int num_dcs;

	DEBUG(10,("dsgetdcname_rediscover\n"));

	if (flags & DS_IS_FLAT_NAME) {

		status = discover_dc_netbios(mem_ctx, domain_name, flags,
					     &dclist, &num_dcs);
		NT_STATUS_NOT_OK_RETURN(status);

		return process_dc_netbios(mem_ctx, domain_name, flags,
					  dclist, num_dcs, info);
	}

	if (flags & DS_IS_DNS_NAME) {

		status = discover_dc_dns(mem_ctx, domain_name, domain_guid,
					 flags, site_name, &dclist, &num_dcs);
		NT_STATUS_NOT_OK_RETURN(status);

		return process_dc_dns(mem_ctx, domain_name, flags,
				      dclist, num_dcs, info);
	}

	status = discover_dc_dns(mem_ctx, domain_name, domain_guid, flags,
				 site_name, &dclist, &num_dcs);

	if (NT_STATUS_IS_OK(status) && num_dcs != 0) {

		status = process_dc_dns(mem_ctx, domain_name, flags, dclist,
					num_dcs, info);
		if (NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	status = discover_dc_netbios(mem_ctx, domain_name, flags, &dclist,
				     &num_dcs);
	NT_STATUS_NOT_OK_RETURN(status);

	return process_dc_netbios(mem_ctx, domain_name, flags, dclist,
				  num_dcs, info);
}

/********************************************************************
 dsgetdcname.

 This will be the only public function here.
********************************************************************/

NTSTATUS dsgetdcname(TALLOC_CTX *mem_ctx,
		     const char *domain_name,
		     struct GUID *domain_guid,
		     const char *site_name,
		     uint32_t flags,
		     struct netr_DsRGetDCNameInfo **info)
{
	NTSTATUS status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	struct netr_DsRGetDCNameInfo *myinfo = NULL;

	DEBUG(10,("dsgetdcname: domain_name: %s, "
		  "domain_guid: %s, site_name: %s, flags: 0x%08x\n",
		  domain_name,
		  domain_guid ? GUID_string(mem_ctx, domain_guid) : "(null)",
		  site_name, flags));

	*info = NULL;

	if (!check_allowed_required_flags(flags)) {
		DEBUG(0,("invalid flags specified\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (flags & DS_FORCE_REDISCOVERY) {
		goto rediscover;
	}

	status = dsgetdcname_cached(mem_ctx, domain_name, domain_guid,
				    flags, site_name, &myinfo);
	if (NT_STATUS_IS_OK(status)) {
		*info = myinfo;
		return status;
	}

	if (flags & DS_BACKGROUND_ONLY) {
		return status;
	}

 rediscover:
	status = dsgetdcname_rediscover(mem_ctx, domain_name,
					domain_guid, flags, site_name,
					&myinfo);

 	if (NT_STATUS_IS_OK(status)) {
		dsgetdcname_cache_store(mem_ctx, domain_name, myinfo);
		*info = myinfo;
	}

	return status;
}

/****************************************************************
****************************************************************/

bool pull_mailslot_cldap_reply(TALLOC_CTX *mem_ctx,
			       const DATA_BLOB *blob,
			       union nbt_cldap_netlogon *r,
			       uint32_t *nt_version)
{
	enum ndr_err_code ndr_err;
	uint32_t nt_version_query = ((*nt_version) & 0x000000ff);
	uint16_t command = 0;

	ndr_err = ndr_pull_struct_blob(blob, mem_ctx, &command,
			(ndr_pull_flags_fn_t)ndr_pull_uint16);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	switch (command) {
		case 0x13: /* 19 */
		case 0x15: /* 21 */
		case 0x17: /* 23 */
			 break;
		default:
			DEBUG(1,("got unexpected command: %d (0x%08x)\n",
				command, command));
			return false;
	}

	ndr_err = ndr_pull_union_blob_all(blob, mem_ctx, r, nt_version_query,
		       (ndr_pull_flags_fn_t)ndr_pull_nbt_cldap_netlogon);
	if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		goto done;
	}

	/* when the caller requested just those nt_version bits that the server
	 * was able to reply to, we are fine and all done. otherwise we need to
	 * assume downgraded replies which are painfully parsed here - gd */

	if (nt_version_query & NETLOGON_VERSION_WITH_CLOSEST_SITE) {
		nt_version_query &= ~NETLOGON_VERSION_WITH_CLOSEST_SITE;
	}
	ndr_err = ndr_pull_union_blob_all(blob, mem_ctx, r, nt_version_query,
		       (ndr_pull_flags_fn_t)ndr_pull_nbt_cldap_netlogon);
	if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		goto done;
	}
	if (nt_version_query & NETLOGON_VERSION_5EX_WITH_IP) {
		nt_version_query &= ~NETLOGON_VERSION_5EX_WITH_IP;
	}
	ndr_err = ndr_pull_union_blob_all(blob, mem_ctx, r, nt_version_query,
		       (ndr_pull_flags_fn_t)ndr_pull_nbt_cldap_netlogon);
	if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		goto done;
	}
	if (nt_version_query & NETLOGON_VERSION_5EX) {
		nt_version_query &= ~NETLOGON_VERSION_5EX;
	}
	ndr_err = ndr_pull_union_blob_all(blob, mem_ctx, r, nt_version_query,
		       (ndr_pull_flags_fn_t)ndr_pull_nbt_cldap_netlogon);
	if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		goto done;
	}
	if (nt_version_query & NETLOGON_VERSION_5) {
		nt_version_query &= ~NETLOGON_VERSION_5;
	}
	ndr_err = ndr_pull_union_blob_all(blob, mem_ctx, r, nt_version_query,
		       (ndr_pull_flags_fn_t)ndr_pull_nbt_cldap_netlogon);
	if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		goto done;
	}

	return false;

 done:
	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_UNION_DEBUG(nbt_cldap_netlogon, nt_version_query, r);
	}

	*nt_version = nt_version_query;

	return true;
}
