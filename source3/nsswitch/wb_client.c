/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   winbind client code

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Tridgell 2000
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#include "includes.h"

/* Call winbindd to convert a name to a sid */

BOOL winbind_lookup_name(char *name, DOM_SID *sid, uint8 *name_type)
{
	struct winbindd_request request;
        struct winbindd_response response;
	enum nss_status result;
	
	if (!sid || !name_type) return False;

        /* Send off request */

        ZERO_STRUCT(request);
        ZERO_STRUCT(response);

        fstrcpy(request.data.name, name);
        if ((result = winbindd_request(WINBINDD_LOOKUPNAME, &request, 
				       &response)) == NSS_STATUS_SUCCESS) {
		string_to_sid(sid, response.data.sid.sid);
		*name_type = response.data.sid.type;
	}

        return result == NSS_STATUS_SUCCESS;
}

/* Call winbindd to convert sid to name */

BOOL winbind_lookup_sid(DOM_SID *sid, fstring dom_name, fstring name, 
			uint8 *name_type)
{
	struct winbindd_request request;
	struct winbindd_response response;
	enum nss_status result;
	DOM_SID tmp_sid;
	uint32 rid;
	fstring sid_str;
	
	if (!name_type) return False;

	/* Check if this is our own sid.  This should perhaps be done by
	   winbind?  For the moment handle it here. */

	if (sid->num_auths == 5) {
		sid_copy(&tmp_sid, sid);
		sid_split_rid(&tmp_sid, &rid);

		if (sid_equal(&global_sam_sid, &tmp_sid)) {

		return map_domain_sid_to_name(&tmp_sid, dom_name) &&
			lookup_local_rid(rid, name, name_type);
		}
	}

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	sid_to_string(sid_str, sid);
	fstrcpy(request.data.sid, sid_str);
	
	/* Make request */

	result = winbindd_request(WINBINDD_LOOKUPSID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		parse_domain_user(response.data.name.name, dom_name, name);
		*name_type = response.data.name.type;
	} else {

		DEBUG(10,("winbind_lookup_sid: winbind lookup for %s failed - trying builtin.\n",
				sid_str));

		sid_copy(&tmp_sid, sid);
		sid_split_rid(&tmp_sid, &rid);
		return map_domain_sid_to_name(&tmp_sid, dom_name) &&
			lookup_known_rid(&tmp_sid, rid, name, name_type);
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert uid to sid */

BOOL winbind_uid_to_sid(uid_t uid, DOM_SID *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	if (!sid) return False;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.data.uid = uid;

	/* Make request */

	result = winbindd_request(WINBINDD_UID_TO_SID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		string_to_sid(sid, response.data.sid.sid);
	} else {
		sid_copy(sid, &global_sid_NULL);
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert uid to sid */

BOOL winbind_gid_to_sid(gid_t gid, DOM_SID *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	if (!sid) return False;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.data.gid = gid;

	/* Make request */

	result = winbindd_request(WINBINDD_GID_TO_SID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		string_to_sid(sid, response.data.sid.sid);
	} else {
		sid_copy(sid, &global_sid_NULL);
	}

	return (result == NSS_STATUS_SUCCESS);
}
