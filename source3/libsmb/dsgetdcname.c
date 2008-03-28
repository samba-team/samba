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
	struct cldap_netlogon_reply r;

	/* check if matching entry is older then 15 minutes, if yes, send
	 * CLDAP/MAILSLOT ping again and store the cached data */

	ZERO_STRUCT(r);

	if (ads_cldap_netlogon(info->dc_unc,
			       info->domain_name, &r)) {

		dsgetdcname_cache_delete(mem_ctx, domain_name);

		return dsgetdcname_cache_store(mem_ctx,
					       info->domain_name,
					       info);
	}

	return NT_STATUS_INVALID_NETWORK_RESPONSE;
}

/****************************************************************
****************************************************************/

#define RETURN_ON_FALSE(x) if (!x) return false;

static bool check_cldap_reply_required_flags(uint32_t ret_flags,
					     uint32_t req_flags)
{
	if (req_flags & DS_PDC_REQUIRED)
		RETURN_ON_FALSE(ret_flags & ADS_PDC);

	if (req_flags & DS_GC_SERVER_REQUIRED)
		RETURN_ON_FALSE(ret_flags & ADS_GC);

	if (req_flags & DS_ONLY_LDAP_NEEDED)
		RETURN_ON_FALSE(ret_flags & ADS_LDAP);

	if ((req_flags & DS_DIRECTORY_SERVICE_REQUIRED) ||
	    (req_flags & DS_DIRECTORY_SERVICE_PREFERRED))
		RETURN_ON_FALSE(ret_flags & ADS_DS);

	if (req_flags & DS_KDC_REQUIRED)
		RETURN_ON_FALSE(ret_flags & ADS_KDC);

	if (req_flags & DS_TIMESERV_REQUIRED)
		RETURN_ON_FALSE(ret_flags & ADS_TIMESERV);

	if (req_flags & DS_WRITABLE_REQUIRED)
		RETURN_ON_FALSE(ret_flags & ADS_WRITABLE);

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
				    int *return_count)
{
	if (lp_disable_netbios()) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	/* FIXME: code here */

	return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
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

	if ((!(flags & DS_DIRECTORY_SERVICE_REQUIRED)) &&
	    (!(flags & DS_KDC_REQUIRED)) &&
	    (!(flags & DS_GC_SERVER_REQUIRED)) &&
	    (!(flags & DS_PDC_REQUIRED))) {
	    	DEBUG(1,("discover_dc_dns: invalid flags\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

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
		/* FIXME: ? */
	    	DEBUG(1,("discover_dc_dns: not enough input\n"));
		status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
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

	if ((*returned_dclist = TALLOC_ZERO_ARRAY(mem_ctx,
						  struct ip_service_name,
						  numaddrs)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* now unroll the list of IP addresses */

	*return_count = 0;
	i = 0;
	j = 0;
	while (i < numdcs && (*return_count<numaddrs)) {

		struct ip_service_name *r = &(*returned_dclist)[*return_count];

		r->port = dcs[i].port;
		r->hostname = dcs[i].hostname;

		if (!(flags & DS_IP_REQUIRED)) {
			(*return_count)++;
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
			(*return_count)++;
			continue;
		}
	}

	return (*return_count > 0) ? NT_STATUS_OK :
				     NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
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

static NTSTATUS process_dc_dns(TALLOC_CTX *mem_ctx,
			       const char *domain_name,
			       uint32_t flags,
			       struct ip_service_name **dclist,
			       int num_dcs,
			       struct netr_DsRGetDCNameInfo **info)
{
	int i = 0;
	bool valid_dc = false;
	struct cldap_netlogon_reply r;
	const char *dc_hostname, *dc_domain_name;
	const char *dc_address;
	uint32_t dc_address_type;
	uint32_t dc_flags;
	struct GUID dc_guid;

	for (i=0; i<num_dcs; i++) {

		ZERO_STRUCT(r);

		if ((ads_cldap_netlogon(dclist[i]->hostname,
					domain_name, &r)) &&
		    (check_cldap_reply_required_flags(r.flags, flags))) {
			valid_dc = true;
		    	break;
		}

		continue;
	}

	if (!valid_dc) {
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	dc_flags = r.flags;

	if (flags & DS_RETURN_FLAT_NAME) {
		if (!strlen(r.netbios_hostname) || !strlen(r.netbios_domain)) {
			return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		}
		dc_hostname = r.netbios_hostname;
		dc_domain_name = r.netbios_domain;
	} else if (flags & DS_RETURN_DNS_NAME) {
		if (!strlen(r.hostname) || !strlen(r.domain)) {
			return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		}
		dc_hostname = r.hostname;
		dc_domain_name = r.domain;
		dc_flags |= DS_DNS_DOMAIN | DS_DNS_CONTROLLER;
	} else {
		/* FIXME */
		dc_hostname = r.hostname;
		dc_domain_name = r.domain;
		dc_flags |= DS_DNS_DOMAIN | DS_DNS_CONTROLLER;
	}

	if (flags & DS_IP_REQUIRED) {
		char addr[INET6_ADDRSTRLEN];
		print_sockaddr(addr, sizeof(addr), &dclist[i]->ss);
		dc_address = talloc_asprintf(mem_ctx, "\\\\%s",
						addr);
		dc_address_type = DS_ADDRESS_TYPE_INET;
	} else {
		dc_address = talloc_asprintf(mem_ctx, "\\\\%s",
					     r.netbios_hostname);
		dc_address_type = DS_ADDRESS_TYPE_NETBIOS;
	}
	NT_STATUS_HAVE_NO_MEMORY(dc_address);
	smb_uuid_unpack(r.guid, &dc_guid);

	if (r.forest) {
		dc_flags |= DS_DNS_FOREST;
	}

	return make_domain_controller_info(mem_ctx,
					   dc_hostname,
					   dc_address,
					   dc_address_type,
					   &dc_guid,
					   dc_domain_name,
					   r.forest,
					   dc_flags,
					   r.server_site_name,
					   r.client_site_name,
					   info);

}

/****************************************************************
****************************************************************/

static NTSTATUS process_dc_netbios(TALLOC_CTX *mem_ctx,
				   const char *domain_name,
				   uint32_t flags,
				   struct ip_service_name **dclist,
				   int num_dcs,
				   struct netr_DsRGetDCNameInfo **info)
{
	/* FIXME: code here */

	return NT_STATUS_NOT_SUPPORTED;
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
	struct ip_service_name *dclist;
	int num_dcs;

	DEBUG(10,("dsgetdcname_rediscover\n"));

	if (flags & DS_IS_FLAT_NAME) {

		status = discover_dc_netbios(mem_ctx, domain_name, flags,
					     &dclist, &num_dcs);
		NT_STATUS_NOT_OK_RETURN(status);

		return process_dc_netbios(mem_ctx, domain_name, flags,
					  &dclist, num_dcs, info);
	}

	if (flags & DS_IS_DNS_NAME) {

		status = discover_dc_dns(mem_ctx, domain_name, domain_guid,
					 flags, site_name, &dclist, &num_dcs);
		NT_STATUS_NOT_OK_RETURN(status);

		return process_dc_dns(mem_ctx, domain_name, flags,
				      &dclist, num_dcs, info);
	}

	status = discover_dc_dns(mem_ctx, domain_name, domain_guid, flags,
				 site_name, &dclist, &num_dcs);

	if (NT_STATUS_IS_OK(status) && num_dcs != 0) {

		status = process_dc_dns(mem_ctx, domain_name, flags, &dclist,
					num_dcs, info);
		if (NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	status = discover_dc_netbios(mem_ctx, domain_name, flags, &dclist,
				     &num_dcs);
	NT_STATUS_NOT_OK_RETURN(status);

	return process_dc_netbios(mem_ctx, domain_name, flags, &dclist,
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
