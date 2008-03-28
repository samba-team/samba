/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007


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
		info->flags |= WBC_DOMINFO_NATIVE;
	if (response.data.domain_info.active_directory)
		info->flags |= WBC_DOMINFO_AD;
	if (response.data.domain_info.primary)
		info->flags |= WBC_DOMINFO_PRIMARY;

	*dinfo = info;

	wbc_status = WBC_ERR_SUCCESS;

 done:
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		talloc_free(info);
	}

	return wbc_status;
}
