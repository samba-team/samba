/* 
   Unix SMB/CIFS implementation.

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
#include "nsswitch/sys_nss.h"

NSS_STATUS winbindd_request(int req_type,
                                 struct winbindd_request *request,
                                 struct winbindd_response *response);

static BOOL parse_domain_user(const char *domuser, fstring domain, fstring user)
{
        char *p = strchr(domuser,*lp_winbind_separator());

        if (!p)
                return False;

        fstrcpy(user, p+1);
        fstrcpy(domain, domuser);
        domain[PTR_DIFF(p, domuser)] = 0;
        strupper(domain);
        return True;
}

/* Call winbindd to convert a name to a sid */

BOOL winbind_lookup_name(const char *dom_name, const char *name, DOM_SID *sid, 
                         enum SID_NAME_USE *name_type)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	
	if (!sid || !name_type)
		return False;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (dom_name == NULL) {
		if (!parse_domain_user(name, request.data.name.dom_name, request.data.name.name))
			return False;
	} else {
		fstrcpy(request.data.name.dom_name, dom_name);
		fstrcpy(request.data.name.name, name);
	}

	if ((result = winbindd_request(WINBINDD_LOOKUPNAME, &request, 
				       &response)) == NSS_STATUS_SUCCESS) {
		string_to_sid(sid, response.data.sid.sid);
		*name_type = (enum SID_NAME_USE)response.data.sid.type;
	}

	return result == NSS_STATUS_SUCCESS;
}

/* Call winbindd to convert sid to name */

BOOL winbind_lookup_sid(DOM_SID *sid, 
			fstring dom_name, fstring name, 
                        enum SID_NAME_USE *name_type)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	fstring sid_str;
	
	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	sid_to_string(sid_str, sid);
	fstrcpy(request.data.sid, sid_str);
	
	/* Make request */

	result = winbindd_request(WINBINDD_LOOKUPSID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		fstrcpy(dom_name, response.data.name.dom_name);
		fstrcpy(name, response.data.name.name);
		*name_type = (enum SID_NAME_USE)response.data.name.type;

		DEBUG(10, ("winbind_lookup_sid: SUCCESS: SID %s -> %s %s\n", 
                           sid_str, dom_name, name));
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert SID to uid */

BOOL winbind_sid_to_uid(uid_t *puid, DOM_SID *sid)
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

BOOL winbind_uid_to_sid(DOM_SID *sid, uid_t uid)
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

BOOL winbind_sid_to_gid(gid_t *pgid, DOM_SID *sid)
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

	result = winbindd_request(WINBINDD_SID_TO_GID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		*pgid = response.data.gid;
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert gid to sid */

BOOL winbind_gid_to_sid(DOM_SID *sid, gid_t gid)
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

/* Fetch the list of groups a user is a member of from winbindd.  This is
   used by winbind_getgroups. */

static int wb_getgroups(const char *user, gid_t **groups)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	/* Call winbindd */

	fstrcpy(request.data.username, user);

	ZERO_STRUCT(response);

	result = winbindd_request(WINBINDD_GETGROUPS, &request, &response);

	if (result == NSS_STATUS_SUCCESS) {
		
		/* Return group list.  Don't forget to free the group list
		   when finished. */

		*groups = (gid_t *)response.extra_data;
		return response.data.num_entries;
	}

	return -1;
}

/* Call winbindd to initialise group membership.  This is necessary for
   some systems (i.e RH5.2) that do not have an initgroups function as part
   of the nss extension.  In RH5.2 this is implemented using getgrent()
   which can be amazingly inefficient as well as having problems with
   username case. */

int winbind_initgroups(char *user, gid_t gid)
{
	gid_t *tgr, *groups = NULL;
	int result;

	/* Call normal initgroups if we are a local user */

	if (!strchr(user, *lp_winbind_separator())) {
		return initgroups(user, gid);
	}

	result = wb_getgroups(user, &groups);

	DEBUG(10,("winbind_getgroups: %s: result = %s\n", user, 
		  result == -1 ? "FAIL" : "SUCCESS"));

	if (result != -1) {
		int ngroups = result, i;
		BOOL is_member = False;

		/* Check to see if the passed gid is already in the list */

		for (i = 0; i < ngroups; i++) {
			if (groups[i] == gid) {
				is_member = True;
			}
		}

		/* Add group to list if necessary */

		if (!is_member) {
			tgr = (gid_t *)Realloc(groups, sizeof(gid_t) * ngroups + 1);
			
			if (!tgr) {
				errno = ENOMEM;
				result = -1;
				goto done;
			}
			else groups = tgr;

			groups[ngroups] = gid;
			ngroups++;
		}

		/* Set the groups */

		if (sys_setgroups(ngroups, groups) == -1) {
			errno = EPERM;
			result = -1;
			goto done;
		}

	} else {
		
		/* The call failed.  Set errno to something so we don't get
		   a bogus value from the last failed system call. */

		errno = EIO;
	}

	/* Free response data if necessary */

 done:
	SAFE_FREE(groups);

	return result;
}

/* Return a list of groups the user is a member of.  This function is
   useful for large systems where inverting the group database would be too
   time consuming.  If size is zero, list is not modified and the total
   number of groups for the user is returned. */

int winbind_getgroups(const char *user, int size, gid_t *list)
{
	gid_t *groups = NULL;
	int result, i;

	/*
	 * Don't do the lookup if the name has no separator _and_ we are not in
	 * 'winbind use default domain' mode.
	 */

	if (!(strchr(user, *lp_winbind_separator()) || lp_winbind_use_default_domain()))
		return -1;

	/* Fetch list of groups */

	result = wb_getgroups(user, &groups);

	if (size == 0)
		goto done;

	if (result > size) {
		result = -1;
		errno = EINVAL; /* This is what getgroups() does */
		goto done;
	}

	/* Copy list of groups across */

	for (i = 0; i < result; i++) {
		list[i] = groups[i];
	}

 done:
	SAFE_FREE(groups);
	return result;
}

/* Utility function. Convert a uid_t to a name if possible. */

BOOL winbind_uidtoname(fstring name, uid_t uid)
{
	DOM_SID sid;
	fstring dom_name;
	fstring user_name;
	enum SID_NAME_USE name_type;

	if (!winbind_uid_to_sid(&sid, uid))
		return False;
	if (!winbind_lookup_sid(&sid, dom_name, user_name, &name_type))
		return False;

	if (name_type != SID_NAME_USER)
		return False;

	slprintf(name, sizeof(fstring)-1, "%s%s%s", dom_name, 
                 lp_winbind_separator(), user_name);

	return True;
}

/* Utility function. Convert a gid_t to a name if possible. */

BOOL winbind_gidtoname(fstring name, gid_t gid)
{
	DOM_SID sid;
	fstring dom_name;
	fstring group_name;
	enum SID_NAME_USE name_type;

	if (!winbind_gid_to_sid(&sid, gid))
		return False;
	if (!winbind_lookup_sid(&sid, dom_name, group_name, &name_type))
		return False;

	if (name_type != SID_NAME_DOM_GRP)
		return False;

	slprintf(name, sizeof(fstring)-1, "%s%s%s", dom_name, 
                 lp_winbind_separator(), group_name);

	return True;
}

/* Utility function. Convert a name to a uid_t if possible. */

BOOL winbind_nametouid(uid_t *puid, const char *name)
{
	DOM_SID sid;
	enum SID_NAME_USE name_type;

	if (!winbind_lookup_name(NULL, name, &sid, &name_type))
                return False;

	if (name_type != SID_NAME_USER)
		return False;

	return winbind_sid_to_uid(puid, &sid);
}

/* Utility function. Convert a name to a gid_t if possible. */

BOOL winbind_nametogid(gid_t *pgid, const char *gname)
{
	DOM_SID g_sid;
	enum SID_NAME_USE name_type;

	if (!winbind_lookup_name(NULL, gname, &g_sid, &name_type))
                return False;

	if (name_type != SID_NAME_DOM_GRP)
		return False;

	return winbind_sid_to_gid(pgid, &g_sid);
}
