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
#include "nsswitch/nss.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

extern DOM_SID global_sid_NULL;            		/* NULL sid */

NSS_STATUS winbindd_request(int req_type,
                                 struct winbindd_request *request,
                                 struct winbindd_response *response);

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
