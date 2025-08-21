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
#include "libsmb/dsgetdcname.h"
#include "libsmb/namequery.h"
#include "libads/sitename_cache.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "libads/cldap.h"
#include "libads/netlogon_ping.h"
#include "lib/addns/dnsquery_srv.h"
#include "libsmb/clidgram.h"
#include "lib/gencache.h"
#include "lib/util/util_net.h"
#include "lib/tsocket/tsocket.h"

/* 15 minutes */
#define DSGETDCNAME_CACHE_TTL	60*15

struct ip_service_name {
	struct samba_sockaddr sa;
	const char *hostname;
};

static NTSTATUS make_dc_info_from_cldap_reply(
	TALLOC_CTX *mem_ctx,
	uint32_t flags,
	const struct samba_sockaddr *sa,
	struct NETLOGON_SAM_LOGON_RESPONSE_EX *r,
	struct netr_DsRGetDCNameInfo **info);

/****************************************************************
****************************************************************/

static void debug_dsdcinfo_flags(int lvl, uint32_t flags)
{
	DEBUG(lvl,("debug_dsdcinfo_flags: 0x%08x\n\t", flags));

	if (flags & DS_FORCE_REDISCOVERY)
		DEBUGADD(lvl,("DS_FORCE_REDISCOVERY "));
	if (flags & 0x00000002)
		DEBUGADD(lvl,("0x00000002 "));
	if (flags & 0x00000004)
		DEBUGADD(lvl,("0x00000004 "));
	if (flags & 0x00000008)
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
	if (flags & DS_TRY_NEXTCLOSEST_SITE)
		DEBUGADD(lvl,("DS_TRY_NEXTCLOSEST_SITE "));
	if (flags & DS_DIRECTORY_SERVICE_6_REQUIRED)
		DEBUGADD(lvl,("DS_DIRECTORY_SERVICE_6_REQUIRED "));
	if (flags & DS_WEB_SERVICE_REQUIRED)
		DEBUGADD(lvl,("DS_WEB_SERVICE_REQUIRED "));
	if (flags & DS_DIRECTORY_SERVICE_8_REQUIRED)
		DEBUGADD(lvl,("DS_DIRECTORY_SERVICE_8_REQUIRED "));
	if (flags & DS_DIRECTORY_SERVICE_9_REQUIRED)
		DEBUGADD(lvl,("DS_DIRECTORY_SERVICE_9_REQUIRED "));
	if (flags & DS_DIRECTORY_SERVICE_10_REQUIRED)
		DEBUGADD(lvl,("DS_DIRECTORY_SERVICE_10_REQUIRED "));
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
	if (!domain) {
		return NULL;
	}

	return talloc_asprintf_strupper_m(mem_ctx, "DSGETDCNAME/DOMAIN/%s",
					  domain);
}

/****************************************************************
****************************************************************/

static NTSTATUS dsgetdcname_cache_delete(TALLOC_CTX *mem_ctx,
					const char *domain_name)
{
	char *key;

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
					DATA_BLOB blob)
{
	time_t expire_time;
	char *key;
	bool ret = false;

	key = dsgetdcname_cache_key(mem_ctx, domain_name);
	if (!key) {
		return NT_STATUS_NO_MEMORY;
	}

	expire_time = time(NULL) + DSGETDCNAME_CACHE_TTL;

	ret = gencache_set_data_blob(key, blob, expire_time);

	return ret ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************
****************************************************************/

static NTSTATUS store_cldap_reply(TALLOC_CTX *mem_ctx,
				  uint32_t flags,
				  struct samba_sockaddr *sa,
				  uint32_t nt_version,
				  struct NETLOGON_SAM_LOGON_RESPONSE_EX *r)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	char addr[INET6_ADDRSTRLEN];

	print_sockaddr(addr, sizeof(addr), &sa->u.ss);

	/* FIXME */
	r->sockaddr_size = 0x10; /* the w32 winsock addr size */
	r->sockaddr.sockaddr_family = 2; /* AF_INET */
	if (is_ipaddress_v4(addr)) {
		r->sockaddr.pdc_ip = talloc_strdup(mem_ctx, addr);
		if (r->sockaddr.pdc_ip == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		/*
		 * ndr_push_NETLOGON_SAM_LOGON_RESPONSE_EX will
		 * fail with an ipv6 address.
		 *
		 * This matches windows behaviour in the CLDAP
		 * response when NETLOGON_NT_VERSION_5EX_WITH_IP
		 * is used.
		 *
		 * Windows returns the ipv4 address of the ipv6
		 * server interface and falls back to 127.0.0.1
		 * if there's no ipv4 address.
		 */
		r->sockaddr.pdc_ip = talloc_strdup(mem_ctx, "127.0.0.1");
		if (r->sockaddr.pdc_ip == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, r,
		       (ndr_push_flags_fn_t)ndr_push_NETLOGON_SAM_LOGON_RESPONSE_EX);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (r->domain_name) {
		status = dsgetdcname_cache_store(mem_ctx, r->domain_name,
						 blob);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		if (r->client_site) {
			sitename_store(r->domain_name, r->client_site);
		}
	}
	if (r->dns_domain) {
		status = dsgetdcname_cache_store(mem_ctx, r->dns_domain, blob);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		if (r->client_site) {
			sitename_store(r->dns_domain, r->client_site);
		}
	}

	status = NT_STATUS_OK;

 done:
	data_blob_free(&blob);

	return status;
}

/****************************************************************
****************************************************************/

static NTSTATUS dsgetdcname_cache_fetch(TALLOC_CTX *mem_ctx,
					const char *domain_name,
					const struct GUID *domain_guid,
					uint32_t flags,
					struct netr_DsRGetDCNameInfo **info_p)
{
	char *key;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	struct netr_DsRGetDCNameInfo *info;
	struct NETLOGON_SAM_LOGON_RESPONSE_EX r;
	NTSTATUS status;

	key = dsgetdcname_cache_key(mem_ctx, domain_name);
	if (!key) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!gencache_get_data_blob(key, NULL, &blob, NULL, NULL)) {
		return NT_STATUS_NOT_FOUND;
	}

	info = talloc_zero(mem_ctx, struct netr_DsRGetDCNameInfo);
	if (!info) {
		data_blob_free(&blob);
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, &r,
		      (ndr_pull_flags_fn_t)ndr_pull_NETLOGON_SAM_LOGON_RESPONSE_EX);

	data_blob_free(&blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dsgetdcname_cache_delete(mem_ctx, domain_name);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = make_dc_info_from_cldap_reply(mem_ctx, flags, NULL,
					       &r, &info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
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
				   struct messaging_context *msg_ctx,
				   const char *domain_name,
				   const struct GUID *domain_guid,
				   uint32_t flags,
				   const char *site_name,
				   struct netr_DsRGetDCNameInfo **info)
{
	NTSTATUS status;

	status = dsgetdcname_cache_fetch(mem_ctx, domain_name, domain_guid,
					 flags, info);
	if (!NT_STATUS_IS_OK(status)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DEBUG(10,("dsgetdcname_cached: cache fetch failed with: %s\n",
			nt_errstr(status)));
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	if (flags & DS_BACKGROUND_ONLY) {
		return status;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		struct netr_DsRGetDCNameInfo *dc_info;

		status = dsgetdcname(mem_ctx, msg_ctx, domain_name,
				     domain_guid, site_name,
				     flags | DS_FORCE_REDISCOVERY,
				     &dc_info);

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		*info = dc_info;
	}

	return status;
}

/****************************************************************
****************************************************************/

static bool check_allowed_required_flags(uint32_t flags,
					 const char *site_name)
{
	uint32_t return_type = flags & (DS_RETURN_FLAT_NAME|DS_RETURN_DNS_NAME);
	uint32_t offered_type = flags & (DS_IS_FLAT_NAME|DS_IS_DNS_NAME);
	uint32_t query_type = flags & (DS_BACKGROUND_ONLY|DS_FORCE_REDISCOVERY);

	/* FIXME: check for DSGETDC_VALID_FLAGS and check for exclusive bits
	 * (DS_PDC_REQUIRED, DS_KDC_REQUIRED, DS_GC_SERVER_REQUIRED) */

	debug_dsdcinfo_flags(10, flags);

	if ((flags & DS_TRY_NEXTCLOSEST_SITE) && site_name) {
		return false;
	}

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
				    size_t *returned_count)
{
	NTSTATUS status;
	enum nbt_name_type name_type = NBT_NAME_LOGON;
	struct samba_sockaddr *salist = NULL;
	size_t i;
	struct ip_service_name *dclist = NULL;
	size_t count = 0;
	static const char *resolve_order[] = { "lmhosts", "wins", "bcast", NULL };

	if (flags & DS_PDC_REQUIRED) {
		name_type = NBT_NAME_PDC;
	}

	status = internal_resolve_name(mem_ctx,
					domain_name,
					name_type,
					NULL,
					&salist,
					&count,
					resolve_order);
	if (!NT_STATUS_IS_OK(status)) {
		NTSTATUS raw_status = status;

		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
			status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_ADDRESS)) {
			status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		}

		DBG_DEBUG("failed to find DC for %s: %s => %s\n",
			  domain_name,
			  nt_errstr(raw_status),
			  nt_errstr(status));
		return status;
	}

	dclist = talloc_zero_array(mem_ctx, struct ip_service_name, count);
	if (!dclist) {
		TALLOC_FREE(salist);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<count; i++) {
		char addr[INET6_ADDRSTRLEN];
		struct ip_service_name *r = &dclist[i];

		print_sockaddr(addr, sizeof(addr),
			       &salist[i].u.ss);

		r->sa = salist[i];
		r->hostname = talloc_strdup(mem_ctx, addr);
		if (!r->hostname) {
			TALLOC_FREE(salist);
			TALLOC_FREE(dclist);
			return NT_STATUS_NO_MEMORY;
		}

	}

	TALLOC_FREE(salist);

	*returned_dclist = dclist;
	*returned_count = count;

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS discover_dc_dns(TALLOC_CTX *mem_ctx,
				const char *domain_name,
				const struct GUID *domain_guid,
				uint32_t flags,
				const char *site_name,
				struct ip_service_name **returned_dclist,
				size_t *return_count)
{
	size_t i;
	NTSTATUS status;
	struct dns_rr_srv *dcs = NULL;
	size_t numdcs = 0;
	struct ip_service_name *dclist = NULL;
	size_t ret_count = 0;
	char *query = NULL;

	if (flags & DS_PDC_REQUIRED) {
		query = ads_dns_query_string_pdc(mem_ctx, domain_name);
	} else if (flags & DS_GC_SERVER_REQUIRED) {
		query = ads_dns_query_string_gcs(mem_ctx, domain_name);
	} else if (flags & DS_KDC_REQUIRED) {
		query = ads_dns_query_string_kdcs(mem_ctx, domain_name);
	} else if (flags & DS_DIRECTORY_SERVICE_REQUIRED) {
		query = ads_dns_query_string_dcs(mem_ctx, domain_name);
	} else if (domain_guid) {
		query = ads_dns_query_string_dcs_guid(
			mem_ctx, domain_guid, domain_name);
	} else {
		query = ads_dns_query_string_dcs(mem_ctx, domain_name);
	}

	if (query == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = ads_dns_query_srv(
		mem_ctx,
		lp_get_async_dns_timeout(),
		site_name,
		query,
		&dcs,
		&numdcs);
	TALLOC_FREE(query);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (numdcs == 0) {
		TALLOC_FREE(dcs);
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	/* Check for integer wrap. */
	if (numdcs + numdcs < numdcs) {
		TALLOC_FREE(dcs);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * We're only returning up to 2 addresses per
	 * DC name, so just allocate size numdcs x 2.
	 */

	dclist = talloc_zero_array(mem_ctx,
				   struct ip_service_name,
				   numdcs * 2);
	if (!dclist) {
		TALLOC_FREE(dcs);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * First, copy the SRV record replies that
	 * have IP addresses returned with them.
	 */
	ret_count = 0;
	for (i = 0; i < numdcs; i++) {
		size_t j;
		bool have_v4_addr = false;
		bool have_v6_addr = false;

		if (dcs[i].num_ips == 0) {
			continue;
		}

		/*
		 * Pick up to 1 address from each address
		 * family (IPv4, IPv6).
		 *
		 * This is different from the previous
		 * code which picked a 'next ip' address
		 * each time, incrementing an index.
		 * Too complex to maintain :-(.
		 */
		for (j = 0; j < dcs[i].num_ips; j++) {
			if ((dcs[i].ss_s[j].ss_family == AF_INET && !have_v4_addr) ||
			    (dcs[i].ss_s[j].ss_family == AF_INET6 && !have_v6_addr)) {
				bool ok;
				dclist[ret_count].hostname =
					talloc_strdup(dclist, dcs[i].hostname);
				ok = sockaddr_storage_to_samba_sockaddr(
					&dclist[ret_count].sa,
					&dcs[i].ss_s[j]);
				if (!ok) {
					TALLOC_FREE(dcs);
					TALLOC_FREE(dclist);
					return NT_STATUS_INVALID_PARAMETER;
				}
				ret_count++;
				if (dcs[i].ss_s[j].ss_family == AF_INET) {
					have_v4_addr = true;
				} else {
					have_v6_addr = true;
				}
				if (have_v4_addr && have_v6_addr) {
					break;
				}
			}
		}
	}

	TALLOC_FREE(dcs);

	if (ret_count == 0) {
		TALLOC_FREE(dclist);
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	*returned_dclist = dclist;
	*return_count = ret_count;
	return NT_STATUS_OK;
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

	info = talloc_zero(mem_ctx, struct netr_DsRGetDCNameInfo);
	NT_STATUS_HAVE_NO_MEMORY(info);

	if (dc_unc) {
		if (!(dc_unc[0] == '\\' && dc_unc[1] == '\\')) {
			info->dc_unc = talloc_asprintf(mem_ctx, "\\\\%s",
						       dc_unc);
		} else {
			info->dc_unc = talloc_strdup(mem_ctx, dc_unc);
		}
		NT_STATUS_HAVE_NO_MEMORY(info->dc_unc);
	}

	if (dc_address) {
		if (!(dc_address[0] == '\\' && dc_address[1] == '\\')) {
			info->dc_address = talloc_asprintf(mem_ctx, "\\\\%s",
							   dc_address);
		} else {
			info->dc_address = talloc_strdup(mem_ctx, dc_address);
		}
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

	if (forest_name && *forest_name) {
		info->forest_name = talloc_strdup(mem_ctx, forest_name);
		NT_STATUS_HAVE_NO_MEMORY(info->forest_name);
		flags |= DS_DNS_FOREST_ROOT;
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

static void map_dc_and_domain_names(uint32_t flags,
				    const char *dc_name,
				    const char *domain_name,
				    const char *dns_dc_name,
				    const char *dns_domain_name,
				    uint32_t *dc_flags,
				    const char **hostname_p,
				    const char **domain_p)
{
	switch (flags & 0xf0000000) {
		case DS_RETURN_FLAT_NAME:
			if (dc_name && domain_name &&
			    *dc_name && *domain_name) {
				*hostname_p = dc_name;
				*domain_p = domain_name;
				break;
			}

			FALL_THROUGH;
		case DS_RETURN_DNS_NAME:
		default:
			if (dns_dc_name && dns_domain_name &&
			    *dns_dc_name && *dns_domain_name) {
				*hostname_p = dns_dc_name;
				*domain_p = dns_domain_name;
				*dc_flags |= DS_DNS_DOMAIN | DS_DNS_CONTROLLER;
				break;
			}
			if (dc_name && domain_name &&
			    *dc_name && *domain_name) {
				*hostname_p = dc_name;
				*domain_p = domain_name;
				break;
			}
	}
}

/****************************************************************
****************************************************************/

static NTSTATUS make_dc_info_from_cldap_reply(
	TALLOC_CTX *mem_ctx,
	uint32_t flags,
	const struct samba_sockaddr *sa,
	struct NETLOGON_SAM_LOGON_RESPONSE_EX *r,
	struct netr_DsRGetDCNameInfo **info)
{
	const char *dc_hostname = NULL;
	const char *dc_domain_name = NULL;
	const char *dc_address = NULL;
	const char *dc_forest = NULL;
	uint32_t dc_address_type = 0;
	uint32_t dc_flags = 0;
	struct GUID *dc_domain_guid = NULL;
	const char *dc_server_site = NULL;
	const char *dc_client_site = NULL;

	char addr[INET6_ADDRSTRLEN];

	if (r->command == LOGON_SAM_LOGON_PAUSE_RESPONSE ||
	    r->command == LOGON_SAM_LOGON_PAUSE_RESPONSE_EX)
	{
		return NT_STATUS_NETLOGON_NOT_STARTED;
	}

	if (sa != NULL) {
		print_sockaddr(addr, sizeof(addr), &sa->u.ss);
		dc_address = addr;
		dc_address_type = DS_ADDRESS_TYPE_INET;
	} else {
		if (r->sockaddr.pdc_ip) {
			dc_address	= r->sockaddr.pdc_ip;
			dc_address_type	= DS_ADDRESS_TYPE_INET;
		} else {
			dc_address      = r->pdc_name;
			dc_address_type = DS_ADDRESS_TYPE_NETBIOS;
		}
	}

	map_dc_and_domain_names(flags,
				r->pdc_name,
				r->domain_name,
				r->pdc_dns_name,
				r->dns_domain,
				&dc_flags,
				&dc_hostname,
				&dc_domain_name);

	dc_flags	|= r->server_type;
	dc_forest	= r->forest;
	dc_domain_guid	= &r->domain_uuid;
	dc_server_site	= r->server_site;
	dc_client_site	= r->client_site;

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
		nt_version |= NETLOGON_NT_VERSION_PDC;
	}

	if (flags & DS_GC_SERVER_REQUIRED) {
		nt_version |= NETLOGON_NT_VERSION_GC;
	}

	if (flags & DS_TRY_NEXTCLOSEST_SITE) {
		nt_version |= NETLOGON_NT_VERSION_WITH_CLOSEST_SITE;
	}

	if (flags & DS_IP_REQUIRED) {
		nt_version |= NETLOGON_NT_VERSION_IP;
	}

	return nt_version;
}

/****************************************************************
****************************************************************/

static NTSTATUS process_dc_dns(TALLOC_CTX *mem_ctx,
			       const char *domain_name,
			       uint32_t flags,
			       struct ip_service_name *dclist,
			       size_t num_dcs,
			       struct netr_DsRGetDCNameInfo **info)
{
	size_t i = 0;
	struct tsocket_address **addrs = NULL;
	struct netlogon_samlogon_response **responses = NULL;
	const uint32_t nt_version = NETLOGON_NT_VERSION_5 |
				    NETLOGON_NT_VERSION_5EX;
	NTSTATUS status;

	addrs = talloc_array(mem_ctx, struct tsocket_address *, num_dcs);
	if (addrs == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<num_dcs; i++) {
		int ret = tsocket_address_bsd_from_samba_sockaddr(
			addrs, &dclist[i].sa, &addrs[i]);
		if (ret != 0) {
			status = map_nt_error_from_unix(errno);
			goto done;
		}
	}

	status = netlogon_pings(
		addrs,				    /* mem_ctx */
		lp_client_netlogon_ping_protocol(), /* proto */
		addrs,				    /* servers */
		num_dcs,			    /* num_servers */
		(struct netlogon_ping_filter){
			.ntversion = nt_version,
			.acct_ctrl = -1,
			.domain = domain_name,
			.required_flags = flags,
		},
		1, /* wanted_servers */
		timeval_current_ofs(MAX(3, lp_ldap_timeout() / 2), 0),
		&responses);

	if (!NT_STATUS_IS_OK(status)) {
		status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		goto done;
	}

	for (i = 0; i < num_dcs; i++) {
		struct netlogon_samlogon_response *r = responses[i];

		if (r == NULL) {
			continue;
		}
		if (r->ntver != NETLOGON_NT_VERSION_5EX) {
			continue;
		}
		status = make_dc_info_from_cldap_reply(
			mem_ctx, flags, &dclist[i].sa, &r->data.nt5_ex, info);
		if (!NT_STATUS_IS_OK(status)) {
			continue;
		}
		status = store_cldap_reply(mem_ctx,
					   flags,
					   &dclist[i].sa,
					   nt_version,
					   &r->data.nt5_ex);
		if (!NT_STATUS_IS_OK(status)) {
			continue;
		}
		goto done;
	}

	status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
done:
	TALLOC_FREE(addrs);
	return status;
}

/****************************************************************
****************************************************************/

/****************************************************************
****************************************************************/

static NTSTATUS process_dc_netbios(TALLOC_CTX *mem_ctx,
				   struct messaging_context *msg_ctx,
				   const char *domain_name,
				   uint32_t flags,
				   struct ip_service_name *dclist,
				   size_t num_dcs,
				   struct netr_DsRGetDCNameInfo **info)
{
	enum nbt_name_type name_type = NBT_NAME_LOGON;
	NTSTATUS status;
	size_t i;
	const char *dc_name = NULL;
	fstring tmp_dc_name;
	struct netlogon_samlogon_response *r = NULL;
	bool store_cache = false;
	uint32_t nt_version = NETLOGON_NT_VERSION_1 |
			      NETLOGON_NT_VERSION_5 |
			      NETLOGON_NT_VERSION_5EX_WITH_IP;
	size_t len = strlen(lp_netbios_name());
	char my_acct_name[len+2];

	if (msg_ctx == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (flags & DS_PDC_REQUIRED) {
		name_type = NBT_NAME_PDC;
	}

	/*
	 * It's 2024 we always want an AD style response!
	 */
	nt_version |= NETLOGON_NT_VERSION_AVOID_NT4EMUL;

	nt_version |= map_ds_flags_to_nt_version(flags);

	snprintf(my_acct_name,
		 sizeof(my_acct_name),
		 "%s$",
		 lp_netbios_name());

	DEBUG(10,("process_dc_netbios\n"));

	for (i=0; i<num_dcs; i++) {
		uint16_t val;

		generate_random_buffer((uint8_t *)&val, 2);

		status = nbt_getdc(msg_ctx, 10, &dclist[i].sa.u.ss, domain_name,
				   NULL, my_acct_name, ACB_WSTRUST, nt_version,
				   mem_ctx, &nt_version, &dc_name, &r);
		if (NT_STATUS_IS_OK(status)) {
			store_cache = true;
			namecache_store(dc_name,
					NBT_NAME_SERVER,
					1,
					&dclist[i].sa);
			goto make_reply;
		}

		if (name_status_find(domain_name,
				     name_type,
				     NBT_NAME_SERVER,
				     &dclist[i].sa.u.ss,
				     tmp_dc_name))
		{
			struct NETLOGON_SAM_LOGON_RESPONSE_NT40 logon1;

			r = talloc_zero(mem_ctx, struct netlogon_samlogon_response);
			NT_STATUS_HAVE_NO_MEMORY(r);

			ZERO_STRUCT(logon1);

			nt_version = NETLOGON_NT_VERSION_1;

			logon1.nt_version = nt_version;
			logon1.pdc_name = tmp_dc_name;
			logon1.domain_name = talloc_strdup_upper(mem_ctx, domain_name);
			NT_STATUS_HAVE_NO_MEMORY(logon1.domain_name);

			r->data.nt4 = logon1;
			r->ntver = nt_version;

			map_netlogon_samlogon_response(r);

			namecache_store(tmp_dc_name,
					NBT_NAME_SERVER,
					1,
					&dclist[i].sa);

			goto make_reply;
		}
	}

	return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;

 make_reply:

	status = make_dc_info_from_cldap_reply(mem_ctx, flags, &dclist[i].sa,
					       &r->data.nt5_ex, info);
	if (NT_STATUS_IS_OK(status) && store_cache) {
		return store_cldap_reply(mem_ctx, flags, &dclist[i].sa,
					 nt_version, &r->data.nt5_ex);
	}

	return status;
}

/****************************************************************
****************************************************************/

static NTSTATUS dsgetdcname_rediscover(TALLOC_CTX *mem_ctx,
				       struct messaging_context *msg_ctx,
				       const char *domain_name,
				       const struct GUID *domain_guid,
				       uint32_t flags,
				       const char *site_name,
				       struct netr_DsRGetDCNameInfo **info)
{
	NTSTATUS status;
	struct ip_service_name *dclist = NULL;
	size_t num_dcs = 0;

	DEBUG(10,("dsgetdcname_rediscover\n"));

	if (flags & DS_IS_FLAT_NAME) {

		if (lp_disable_netbios()) {
			return NT_STATUS_NOT_SUPPORTED;
		}

		status = discover_dc_netbios(mem_ctx, domain_name, flags,
					     &dclist, &num_dcs);
		NT_STATUS_NOT_OK_RETURN(status);

		return process_dc_netbios(mem_ctx, msg_ctx, domain_name, flags,
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

	if (lp_disable_netbios()) {
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	status = discover_dc_netbios(mem_ctx, domain_name, flags, &dclist,
				     &num_dcs);
	NT_STATUS_NOT_OK_RETURN(status);

	return process_dc_netbios(mem_ctx, msg_ctx, domain_name, flags, dclist,
				  num_dcs, info);
}

static bool is_closest_site(struct netr_DsRGetDCNameInfo *info)
{
	if (info->dc_flags & DS_SERVER_CLOSEST) {
		return true;
	}

	if (!info->client_site_name) {
		return true;
	}

	if (!info->dc_site_name) {
		return false;
	}

	if (strcmp(info->client_site_name, info->dc_site_name) == 0) {
		return true;
	}

	return false;
}

/********************************************************************
 Internal dsgetdcname.
********************************************************************/

static NTSTATUS dsgetdcname_internal(TALLOC_CTX *mem_ctx,
		     struct messaging_context *msg_ctx,
		     const char *domain_name,
		     const struct GUID *domain_guid,
		     const char *site_name,
		     uint32_t flags,
		     struct netr_DsRGetDCNameInfo **info)
{
	NTSTATUS status;
	struct netr_DsRGetDCNameInfo *myinfo = NULL;
	bool first = true;
	struct netr_DsRGetDCNameInfo *first_info = NULL;

	DEBUG(10,("dsgetdcname_internal: domain_name: %s, "
		  "domain_guid: %s, site_name: %s, flags: 0x%08x\n",
		  domain_name,
		  domain_guid ? GUID_string(mem_ctx, domain_guid) : "(null)",
		  site_name ? site_name : "(null)", flags));

	*info = NULL;

	if (!check_allowed_required_flags(flags, site_name)) {
		DEBUG(0,("invalid flags specified\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (flags & DS_FORCE_REDISCOVERY) {
		goto rediscover;
	}

	status = dsgetdcname_cached(mem_ctx, msg_ctx, domain_name, domain_guid,
				    flags, site_name, &myinfo);
	if (NT_STATUS_IS_OK(status)) {
		*info = myinfo;
		goto done;
	}

	if (flags & DS_BACKGROUND_ONLY) {
		goto done;
	}

 rediscover:
	status = dsgetdcname_rediscover(mem_ctx, msg_ctx, domain_name,
					domain_guid, flags, site_name,
					&myinfo);

 done:
	if (!NT_STATUS_IS_OK(status)) {
		if (!first) {
			*info = first_info;
			return NT_STATUS_OK;
		}
		return status;
	}

	if (!first) {
		TALLOC_FREE(first_info);
	} else if (!is_closest_site(myinfo)) {
		first = false;
		first_info = myinfo;
		/* TODO: may use the next_closest_site here */
		site_name = myinfo->client_site_name;
		goto rediscover;
	}

	*info = myinfo;
	return NT_STATUS_OK;
}

/********************************************************************
 dsgetdcname.

 This will be the only public function here.
********************************************************************/

NTSTATUS dsgetdcname(TALLOC_CTX *mem_ctx,
		     struct messaging_context *msg_ctx,
		     const char *domain_name,
		     const struct GUID *domain_guid,
		     const char *site_name,
		     uint32_t flags,
		     struct netr_DsRGetDCNameInfo **info)
{
	NTSTATUS status;
	const char *query_site = NULL;
	char *ptr_to_free = NULL;
	bool retry_query_with_null = false;

	if ((site_name == NULL) || (site_name[0] == '\0')) {
		ptr_to_free = sitename_fetch(mem_ctx, domain_name);
		if (ptr_to_free != NULL) {
			retry_query_with_null = true;
		}
		query_site = ptr_to_free;
	} else {
		query_site = site_name;
	}

	status = dsgetdcname_internal(mem_ctx,
				msg_ctx,
				domain_name,
				domain_guid,
				query_site,
				flags,
				info);

	TALLOC_FREE(ptr_to_free);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND)) {
		return status;
	}

	/* Should we try again with site_name == NULL ? */
	if (retry_query_with_null) {
		status = dsgetdcname_internal(mem_ctx,
					msg_ctx,
					domain_name,
					domain_guid,
					NULL,
					flags,
					info);
	}

	return status;
}

NTSTATUS dsgetonedcname(TALLOC_CTX *mem_ctx,
			struct messaging_context *msg_ctx,
			const char *domain_name,
			const char *dcname,
			uint32_t flags,
			struct netr_DsRGetDCNameInfo **info)
{
	NTSTATUS status;
	struct sockaddr_storage *addrs;
	unsigned int num_addrs, i;
	const char *hostname = strip_hostname(dcname);

	status = resolve_name_list(mem_ctx, hostname, 0x20,
				   &addrs, &num_addrs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (i = 0; i < num_addrs; i++) {

		bool ok;
		struct ip_service_name dclist;

		dclist.hostname = hostname;
		ok = sockaddr_storage_to_samba_sockaddr(&dclist.sa, &addrs[i]);
		if (!ok) {
			TALLOC_FREE(addrs);
			return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		}

		status = process_dc_dns(mem_ctx, domain_name, flags,
					&dclist, 1, info);
		if (NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(addrs);
			return NT_STATUS_OK;
		}

		if (lp_disable_netbios()) {
			continue;
		}

		status = process_dc_netbios(mem_ctx, msg_ctx, domain_name, flags,
					    &dclist, 1, info);
		if (NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(addrs);
			return NT_STATUS_OK;
		}
	}

	TALLOC_FREE(addrs);
	return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
}
