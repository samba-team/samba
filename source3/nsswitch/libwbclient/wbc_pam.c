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

/** @brief Authenticate a username/password pair
 *
 * @param username     Name of user to authenticate
 * @param password     Clear text password os user
 *
 * @return #wbcErr
 **/

wbcErr wbcAuthenticateUser(const char *username,
			   const char *password)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct winbindd_request request;
	struct winbindd_response response;

	if (!username) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* dst is already null terminated from the memset above */

	strncpy(request.data.auth.user,	username,
		sizeof(request.data.auth.user)-1);
	strncpy(request.data.auth.pass,	password,
		sizeof(request.data.auth.user)-1);

	wbc_status = wbcRequestResponse(WINBINDD_PAM_AUTH,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

done:
	return wbc_status;
}
