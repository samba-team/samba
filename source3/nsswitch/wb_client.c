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

BOOL winbind_lookup_name(char *name, DOM_SID *sid, enum SID_NAME_USE *name_type)
{
	struct winbindd_request request;
	struct winbindd_response response;
	enum nss_status result;
	
	if (!sid || !name_type)
		return False;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.name, name);
	if ((result = winbindd_request(WINBINDD_LOOKUPNAME, &request, 
				       &response)) == NSS_STATUS_SUCCESS) {
		string_to_sid(sid, response.data.sid.sid);
		*name_type = (enum SID_NAME_USE)response.data.sid.type;
	}

	return result == NSS_STATUS_SUCCESS;
}

/* Call winbindd to convert sid to name */

BOOL winbind_lookup_sid(DOM_SID *sid, fstring dom_name, fstring name, enum SID_NAME_USE *name_type)
{
	struct winbindd_request request;
	struct winbindd_response response;
	enum nss_status result;
	DOM_SID tmp_sid;
	uint32 rid;
	fstring sid_str;
	
	if (!name_type)
		return False;

	/* Check if this is our own sid.  This should perhaps be done by
	   winbind?  For the moment handle it here. */

	if (sid->num_auths == 5) {
		sid_copy(&tmp_sid, sid);
		sid_split_rid(&tmp_sid, &rid);

		if (sid_equal(&global_sam_sid, &tmp_sid)) {

		return map_domain_sid_to_name(&tmp_sid, dom_name) &&
			local_lookup_rid(rid, name, name_type);
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
		*name_type = (enum SID_NAME_USE)response.data.name.type;
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert SID to uid */

static BOOL winbind_sid_to_uid(uid_t *puid, DOM_SID *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;
	fstring sid_str;

	if (!puid)
		return False;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	sid_to_string(sid_str, sid);
	fstrcpy(request.data.sid, sid_str);
	
	/* Make request */

	result = winbindd_request(WINBINDD_SID_TO_UID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		*puid = response.data.uid;
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert uid to sid */

static BOOL winbind_uid_to_sid(DOM_SID *sid, uid_t uid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	if (!sid)
		return False;

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

/* Call winbindd to convert SID to gid */

static BOOL winbind_sid_to_gid(gid_t *pgid, DOM_SID *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;
	fstring sid_str;

	if (!pgid)
		return False;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	sid_to_string(sid_str, sid);
	fstrcpy(request.data.sid, sid_str);
	
	/* Make request */

	result = winbindd_request(WINBINDD_SID_TO_UID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		*pgid = response.data.gid;
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert gid to sid */

static BOOL winbind_gid_to_sid(DOM_SID *sid, gid_t gid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	if (!sid)
		return False;

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



/*****************************************************************
 *THE CANNONICAL* convert name to SID function.
 Tries winbind first - then uses local lookup.
*****************************************************************/  

BOOL lookup_name(char *name, DOM_SID *psid, enum SID_NAME_USE *name_type)
{
	extern pstring global_myname;

	if (!winbind_lookup_name(name, psid, name_type)) {

		DEBUG(10,("lookup_name: winbind lookup for %s failed - trying local\n", name ));

		return local_lookup_name(global_myname, name, psid, name_type);
	}
	return True;
}

/*****************************************************************
 *THE CANNONICAL* convert SID to name function.
 Tries winbind first - then uses local lookup.
*****************************************************************/  

BOOL lookup_sid(DOM_SID *sid, fstring dom_name, fstring name, enum SID_NAME_USE *name_type)
{
	if (!winbind_lookup_sid(sid, dom_name, name, name_type)) {
		fstring sid_str;
		DOM_SID tmp_sid;
		uint32 rid;

		DEBUG(10,("lookup_sid: winbind lookup for SID %s failed - trying local.\n", sid_to_string(sid_str, sid) ));

		sid_copy(&tmp_sid, sid);
		sid_split_rid(&tmp_sid, &rid);
		return map_domain_sid_to_name(&tmp_sid, dom_name) &&
				lookup_known_rid(&tmp_sid, rid, name, name_type);
	}
	return True;
}

/*****************************************************************
 *THE CANNONICAL* convert uid_t to SID function.
 Tries winbind first - then uses local lookup.
 Returns SID pointer.
*****************************************************************/  

DOM_SID *uid_to_sid(DOM_SID *psid, uid_t uid)
{
	if (!winbind_uid_to_sid(psid, uid)) {
		DEBUG(10,("uid_to_sid: winbind lookup for uid %u failed - trying local.\n", (unsigned int)uid ));

		return local_uid_to_sid(psid, uid);
	}

	return psid;
}

/*****************************************************************
 *THE CANNONICAL* convert gid_t to SID function.
 Tries winbind first - then uses local lookup.
 Returns SID pointer.
*****************************************************************/  

DOM_SID *gid_to_sid(DOM_SID *psid, gid_t gid)
{
	if (!winbind_gid_to_sid(psid, gid)) {
		DEBUG(10,("gid_to_sid: winbind lookup for gid %u failed - trying local.\n", (unsigned int)gid ));

		return local_gid_to_sid(psid, gid);
	}

	return psid;
}

/*****************************************************************
 *THE CANNONICAL* convert SID to uid function.
 Tries winbind first - then uses local lookup.
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not.
*****************************************************************/  

BOOL sid_to_uid(DOM_SID *psid, uid_t *puid, enum SID_NAME_USE *sidtype)
{
	fstring dom_name, name, sid_str;
	enum SID_NAME_USE name_type;

	*sidtype = SID_NAME_UNKNOWN;

	/*
	 * First we must look up the name and decide if this is a user sid.
	 */

	if (!winbind_lookup_sid(psid, dom_name, name, &name_type)) {
		fstring sid_str2;

		DEBUG(10,("sid_to_uid: winbind lookup for sid %s failed - trying local.\n",
				sid_to_string(sid_str2, psid) ));

		return local_sid_to_uid(puid, psid, sidtype);
	}

	/*
	 * Ensure this is a user sid.
	 */

	if (name_type != SID_NAME_USER) {
		DEBUG(10,("sid_to_uid: winbind lookup succeeded but SID is not a uid (%u)\n",
				(unsigned int)name_type ));
		return False;
	}

	*sidtype = SID_NAME_USER;

	/*
	 * Get the uid for this SID.
	 */

	if (!winbind_sid_to_uid(puid, psid)) {
		DEBUG(10,("sid_to_uid: winbind lookup for sid %s failed.\n",
				sid_to_string(sid_str, psid) ));
		return False;
	}

	return True;
}

/*****************************************************************
 *THE CANNONICAL* convert SID to gid function.
 Tries winbind first - then uses local lookup.
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not.
*****************************************************************/  

BOOL sid_to_gid(DOM_SID *psid, gid_t *pgid, enum SID_NAME_USE *sidtype)
{
	fstring dom_name, name, sid_str;
	enum SID_NAME_USE name_type;

	*sidtype = SID_NAME_UNKNOWN;

	/*
	 * First we must look up the name and decide if this is a group sid.
	 */

	if (!winbind_lookup_sid(psid, dom_name, name, &name_type)) {
		fstring sid_str2;

		DEBUG(10,("sid_to_gid: winbind lookup for sid %s failed - trying local.\n",
				sid_to_string(sid_str2, psid) ));

		return local_sid_to_gid(pgid, psid, sidtype);
	}

	/*
	 * Ensure this is a group sid.
	 */

	if ((name_type != SID_NAME_DOM_GRP) && (name_type != SID_NAME_ALIAS) && (name_type != SID_NAME_WKN_GRP)) {
		DEBUG(10,("sid_to_gid: winbind lookup succeeded but SID is not a know group (%u)\n",
				(unsigned int)name_type ));

		return local_sid_to_gid(pgid, psid, sidtype);
	}

	*sidtype = name_type;

	/*
	 * Get the gid for this SID.
	 */

	if (!winbind_sid_to_gid(pgid, psid)) {
		DEBUG(10,("sid_to_gid: winbind lookup for sid %s failed.\n",
				sid_to_string(sid_str, psid) ));
		return False;
	}

	return True;
}
