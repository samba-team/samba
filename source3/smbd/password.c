/*
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2007.

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
#include "system/passwd.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "auth.h"
#include "../libcli/security/security.h"

/* Fix up prototypes for OSX 10.4, where they're missing */
#ifndef HAVE_SETNETGRENT_PROTOTYPE
extern int setnetgrent(const char* netgroup);
#endif
#ifndef HAVE_GETNETGRENT_PROTOTYPE
extern int getnetgrent(char **host, char **user, char **domain);
#endif
#ifndef HAVE_ENDNETGRENT_PROTOTYPE
extern void endnetgrent(void);
#endif

enum server_allocated_state { SERVER_ALLOCATED_REQUIRED_YES,
				SERVER_ALLOCATED_REQUIRED_NO,
				SERVER_ALLOCATED_REQUIRED_ANY};

static struct user_struct *get_valid_user_struct_internal(
			struct smbd_server_connection *sconn,
			uint64_t vuid,
			enum server_allocated_state server_allocated)
{
	struct user_struct *usp;
	int count=0;

	if (vuid == UID_FIELD_INVALID)
		return NULL;

	usp=sconn->users;
	for (;usp;usp=usp->next,count++) {
		if (vuid == usp->vuid) {
			switch (server_allocated) {
				case SERVER_ALLOCATED_REQUIRED_YES:
					if (usp->session_info == NULL) {
						continue;
					}
					break;
				case SERVER_ALLOCATED_REQUIRED_NO:
					if (usp->session_info != NULL) {
						continue;
					}
				case SERVER_ALLOCATED_REQUIRED_ANY:
					break;
			}
			if (count > 10) {
				DLIST_PROMOTE(sconn->users, usp);
			}
			return usp;
		}
	}

	return NULL;
}

/****************************************************************************
 Check if a uid has been validated, and return an pointer to the user_struct
 if it has. NULL if not. vuid is biased by an offset. This allows us to
 tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/

struct user_struct *get_valid_user_struct(struct smbd_server_connection *sconn,
					  uint64_t vuid)
{
	return get_valid_user_struct_internal(sconn, vuid,
			SERVER_ALLOCATED_REQUIRED_YES);
}

/****************************************************************************
 Invalidate a uid.
****************************************************************************/

void invalidate_vuid(struct smbd_server_connection *sconn, uint64_t vuid)
{
	struct user_struct *vuser = NULL;

	vuser = get_valid_user_struct_internal(sconn, vuid,
			SERVER_ALLOCATED_REQUIRED_ANY);
	if (vuser == NULL) {
		return;
	}

	session_yield(vuser->session);

	DLIST_REMOVE(sconn->users, vuser);
	SMB_ASSERT(sconn->num_users > 0);
	sconn->num_users--;

	/* clear the vuid from the 'cache' on each connection, and
	   from the vuid 'owner' of connections */
	conn_clear_vuid_caches(sconn, vuid);

	TALLOC_FREE(vuser);
}

int register_homes_share(const char *username)
{
	int result;
	struct passwd *pwd;

	result = lp_servicenumber(username);
	if (result != -1) {
		DEBUG(3, ("Using static (or previously created) service for "
			  "user '%s'; path = '%s'\n", username,
			  lp_pathname(talloc_tos(), result)));
		return result;
	}

	pwd = Get_Pwnam_alloc(talloc_tos(), username);

	if ((pwd == NULL) || (pwd->pw_dir[0] == '\0')) {
		DEBUG(3, ("No home directory defined for user '%s'\n",
			  username));
		TALLOC_FREE(pwd);
		return -1;
	}

	DEBUG(3, ("Adding homes service for user '%s' using home directory: "
		  "'%s'\n", username, pwd->pw_dir));

	result = add_home_service(username, username, pwd->pw_dir);

	TALLOC_FREE(pwd);
	return result;
}
