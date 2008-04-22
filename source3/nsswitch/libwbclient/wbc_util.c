/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007-2008


   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Required Headers */

#include "libwbclient.h"



/** @brief Ping winbindd to see if the daemon is running
 *
 * @return #wbcErr
 **/

wbcErr wbcPing(void)
{
	struct winbindd_request request;
	struct winbindd_response response;

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	return wbcRequestResponse(WINBINDD_PING, &request, &response);
}

wbcErr wbcInterfaceDetails(struct wbcInterfaceDetails **_details)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcInterfaceDetails *info;
	struct wbcDomainInfo *domain = NULL;
	struct winbindd_request request;
	struct winbindd_response response;

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	info = talloc(NULL, struct wbcInterfaceDetails);
	BAIL_ON_PTR_ERROR(info, wbc_status);

	/* first the interface version */
	wbc_status = wbcRequestResponse(WINBINDD_INTERFACE_VERSION, NULL, &response);
	BAIL_ON_WBC_ERROR(wbc_status);
	info->interface_version = response.data.interface_version;

	/* then the samba version and the winbind separator */
	wbc_status = wbcRequestResponse(WINBINDD_INFO, NULL, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

	info->winbind_version = talloc_strdup(info,
					      response.data.info.samba_version);
	BAIL_ON_PTR_ERROR(info->winbind_version, wbc_status);
	info->winbind_separator = response.data.info.winbind_separator;

	/* then the local netbios name */
	wbc_status = wbcRequestResponse(WINBINDD_NETBIOS_NAME, NULL, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

	info->netbios_name = talloc_strdup(info,
					   response.data.netbios_name);
	BAIL_ON_PTR_ERROR(info->netbios_name, wbc_status);

	/* then the local workgroup name */
	wbc_status = wbcRequestResponse(WINBINDD_DOMAIN_NAME, NULL, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

	info->netbios_domain = talloc_strdup(info,
					response.data.domain_name);
	BAIL_ON_PTR_ERROR(info->netbios_domain, wbc_status);

	wbc_status = wbcDomainInfo(info->netbios_domain, &domain);
	if (wbc_status == WBC_ERR_DOMAIN_NOT_FOUND) {
		/* maybe it's a standalone server */
		domain = NULL;
		wbc_status = WBC_ERR_SUCCESS;
	} else {
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	if (domain) {
		info->dns_domain = talloc_strdup(info,
						 domain->dns_name);
		wbcFreeMemory(domain);
		BAIL_ON_PTR_ERROR(info->dns_domain, wbc_status);
	} else {
		info->dns_domain = NULL;
	}

	*_details = info;
	info = NULL;

	wbc_status = WBC_ERR_SUCCESS;

done:
	talloc_free(info);
	return wbc_status;
}


/** @brief Lookup the current status of a trusted domain
 *
 * @param domain      Domain to query
 * @param *dinfo       Pointer to returned domain_info struct
 *
 * @return #wbcErr
 *
 **/


wbcErr wbcDomainInfo(const char *domain, struct wbcDomainInfo **dinfo)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct wbcDomainInfo *info = NULL;

	if (!domain || !dinfo) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	strncpy(request.domain_name, domain,
		sizeof(request.domain_name)-1);

	wbc_status = wbcRequestResponse(WINBINDD_DOMAIN_INFO,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	info = talloc(NULL, struct wbcDomainInfo);
	BAIL_ON_PTR_ERROR(info, wbc_status);

	info->short_name = talloc_strdup(info,
					 response.data.domain_info.name);
	BAIL_ON_PTR_ERROR(info->short_name, wbc_status);

	info->dns_name = talloc_strdup(info,
				       response.data.domain_info.alt_name);
	BAIL_ON_PTR_ERROR(info->dns_name, wbc_status);

	wbc_status = wbcStringToSid(response.data.domain_info.sid,
				    &info->sid);
	BAIL_ON_WBC_ERROR(wbc_status);

	if (response.data.domain_info.native_mode)
		info->domain_flags |= WBC_DOMINFO_DOMAIN_NATIVE;
	if (response.data.domain_info.active_directory)
		info->domain_flags |= WBC_DOMINFO_DOMAIN_AD;
	if (response.data.domain_info.primary)
		info->domain_flags |= WBC_DOMINFO_DOMAIN_PRIMARY;

	*dinfo = info;

	wbc_status = WBC_ERR_SUCCESS;

 done:
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		talloc_free(info);
	}

	return wbc_status;
}


/** @brief Resolve a NetbiosName via WINS
 *
 * @param name         Name to resolve
 * @param *ip          Pointer to the ip address string
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcResolveWinsByName(const char *name, char **ip)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *ipaddr;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	strncpy(request.data.winsreq, name,
		sizeof(request.data.winsreq)-1);

	wbc_status = wbcRequestResponse(WINBINDD_WINS_BYNAME,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	/* Display response */

	ipaddr = talloc_strdup(NULL, response.data.winsresp);
	BAIL_ON_PTR_ERROR(ipaddr, wbc_status);

	*ip = ipaddr;
	wbc_status = WBC_ERR_SUCCESS;

 done:
	return wbc_status;
}

/** @brief Resolve an IP address via WINS into a NetbiosName
 *
 * @param ip          The ip address string
 * @param *name       Pointer to the name
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcResolveWinsByIP(const char *ip, char **name)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *name_str;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	strncpy(request.data.winsreq, ip,
		sizeof(request.data.winsreq)-1);

	wbc_status = wbcRequestResponse(WINBINDD_WINS_BYIP,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	/* Display response */

	name_str = talloc_strdup(NULL, response.data.winsresp);
	BAIL_ON_PTR_ERROR(name_str, wbc_status);

	*name = name_str;
	wbc_status = WBC_ERR_SUCCESS;

 done:
	return wbc_status;
}

/**
 */

static wbcErr process_domain_info_string(TALLOC_CTX *ctx, 
					 struct wbcDomainInfo *info,
					 char *info_string)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *r = NULL;
	char *s = NULL;

	if (!info || !info_string) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	r = info_string;

	/* Short Name */
	if ((s = strchr(r, '\\')) == NULL) {
		wbc_status = WBC_ERR_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	*s = '\0';
	s++;

	info->short_name = talloc_strdup(ctx, r);
	BAIL_ON_PTR_ERROR(info->short_name, wbc_status);


	/* DNS Name */
	r = s;
	if ((s = strchr(r, '\\')) == NULL) {
		wbc_status = WBC_ERR_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	*s = '\0';
	s++;

	info->dns_name = talloc_strdup(ctx, r);
	BAIL_ON_PTR_ERROR(info->dns_name, wbc_status);

	/* SID */
	r = s;
	if ((s = strchr(r, '\\')) == NULL) {
		wbc_status = WBC_ERR_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	*s = '\0';
	s++;

	wbc_status = wbcStringToSid(r, &info->sid);
	BAIL_ON_WBC_ERROR(wbc_status);
	
	/* Trust type */
	r = s;
	if ((s = strchr(r, '\\')) == NULL) {
		wbc_status = WBC_ERR_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	*s = '\0';
	s++;

	if (strcmp(r, "None") == 0) {
		info->trust_type = WBC_DOMINFO_TRUSTTYPE_NONE;
	} else if (strcmp(r, "External") == 0) {
		info->trust_type = WBC_DOMINFO_TRUSTTYPE_EXTERNAL;
	} else if (strcmp(r, "Forest") == 0) {
		info->trust_type = WBC_DOMINFO_TRUSTTYPE_FOREST;
	} else if (strcmp(r, "In Forest") == 0) {
		info->trust_type = WBC_DOMINFO_TRUSTTYPE_IN_FOREST;
	} else {
		wbc_status = WBC_ERR_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Transitive */
	r = s;
	if ((s = strchr(r, '\\')) == NULL) {
		wbc_status = WBC_ERR_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	*s = '\0';
	s++;

	if (strcmp(r, "Yes") == 0) {
		info->trust_flags |= WBC_DOMINFO_TRUST_TRANSITIVE;		
	}
	
	/* Incoming */
	r = s;
	if ((s = strchr(r, '\\')) == NULL) {
		wbc_status = WBC_ERR_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	*s = '\0';
	s++;

	if (strcmp(r, "Yes") == 0) {
		info->trust_flags |= WBC_DOMINFO_TRUST_INCOMING;		
	}

	/* Outgoing */
	r = s;
	if ((s = strchr(r, '\\')) == NULL) {
		wbc_status = WBC_ERR_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	*s = '\0';
	s++;

	if (strcmp(r, "Yes") == 0) {
		info->trust_flags |= WBC_DOMINFO_TRUST_OUTGOING;		
	}

	/* Online/Offline status */

	r = s;
	if (r == NULL) {
		wbc_status = WBC_ERR_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	if ( strcmp(r, "Offline") == 0) {
		info->domain_flags |= WBC_DOMINFO_DOMAIN_OFFLINE;
	}

	wbc_status = WBC_ERR_SUCCESS;

 done:
	return wbc_status;
}

/** @brief Enumerate the domain trusts known by Winbind
 *
 * @param **domains     Pointer to the allocated domain list array
 * @param *num_domains  Pointer to number of domains returned
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcListTrusts(struct wbcDomainInfo **domains, size_t *num_domains)
{
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *p = NULL;
	char *q = NULL;
	char *extra_data = NULL;	
	int count = 0;	
	struct wbcDomainInfo *d_list = NULL;
	int i = 0;
	
	*domains = NULL;
	*num_domains = 0;
	
	ZERO_STRUCT(response);

	/* Send request */

	wbc_status = wbcRequestResponse(WINBINDD_LIST_TRUSTDOM,
					NULL,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	/* Decode the response */

	p = (char *)response.extra_data.data;

	if (strlen(p) == 0) {
		/* We should always at least get back our 
		   own SAM domain */
		
		wbc_status = WBC_ERR_DOMAIN_NOT_FOUND;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Count number of domains */

	count = 0;	
	while (p) {
		count++;

		if ((q = strchr(p, '\n')) != NULL)
			q++;
		p = q;		
	}

	d_list = talloc_array(NULL, struct wbcDomainInfo, count);
	BAIL_ON_PTR_ERROR(d_list, wbc_status);

	extra_data = strdup((char*)response.extra_data.data);
	BAIL_ON_PTR_ERROR(extra_data, wbc_status);

	p = extra_data;	

	/* Outer loop processes the list of domain information */

	for (i=0; i<count && p; i++) {
		char *next = strchr(p, '\n');
		
		if (next) {
			*next = '\0';
			next++;
		}

		wbc_status = process_domain_info_string(d_list, &d_list[i], p);
		BAIL_ON_WBC_ERROR(wbc_status);

		p = next;
	}

	*domains = d_list;	
	*num_domains = i;	
	
 done:
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		if (d_list)
			talloc_free(d_list);
		if (extra_data)
			free(extra_data);
	}

	return wbc_status;
}
