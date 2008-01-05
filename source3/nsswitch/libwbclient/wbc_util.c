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
