/* 
   Unix SMB/CIFS implementation.

   winbind client code

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Tridgell 2000
   
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

#include "includes.h"
#include "nsswitch/winbind_nss.h"
#include "libwbclient/wbclient.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

NSS_STATUS winbindd_request_response(int req_type,
                                 struct winbindd_request *request,
                                 struct winbindd_response *response);

bool winbind_set_mapping(const struct id_map *map)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	request.data.dual_idmapset.id = map->xid.id;
	request.data.dual_idmapset.type = map->xid.type;
	sid_to_fstring(request.data.dual_idmapset.sid, map->sid);

	result = winbindd_request_response(WINBINDD_SET_MAPPING, &request, &response);

	return (result == NSS_STATUS_SUCCESS);
}

bool winbind_set_uid_hwm(unsigned long id)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	request.data.dual_idmapset.id = id;
	request.data.dual_idmapset.type = ID_TYPE_UID;

	result = winbindd_request_response(WINBINDD_SET_HWM, &request, &response);

	return (result == NSS_STATUS_SUCCESS);
}

bool winbind_set_gid_hwm(unsigned long id)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	request.data.dual_idmapset.id = id;
	request.data.dual_idmapset.type = ID_TYPE_GID;

	result = winbindd_request_response(WINBINDD_SET_HWM, &request, &response);

	return (result == NSS_STATUS_SUCCESS);
}
