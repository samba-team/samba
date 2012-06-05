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

bool is_partial_auth_vuid(struct smbd_server_connection *sconn, uint64_t vuid)
{
	return (get_partial_auth_user_struct(sconn, vuid) != NULL);
}

/****************************************************************************
 Get the user struct of a partial NTLMSSP login
****************************************************************************/

struct user_struct *get_partial_auth_user_struct(struct smbd_server_connection *sconn,
						 uint64_t vuid)
{
	return get_valid_user_struct_internal(sconn, vuid,
			SERVER_ALLOCATED_REQUIRED_NO);
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

	session_yield(vuser);

	if (vuser->gensec_security) {
		TALLOC_FREE(vuser->gensec_security);
	}

	DLIST_REMOVE(sconn->users, vuser);
	SMB_ASSERT(sconn->num_users > 0);
	sconn->num_users--;

	/* clear the vuid from the 'cache' on each connection, and
	   from the vuid 'owner' of connections */
	conn_clear_vuid_caches(sconn, vuid);

	TALLOC_FREE(vuser);
}

/****************************************************************************
 Invalidate all vuid entries for this process.
****************************************************************************/

void invalidate_all_vuids(struct smbd_server_connection *sconn)
{
	if (sconn->using_smb2) {
		return;
	}

	while (sconn->users != NULL) {
		invalidate_vuid(sconn, sconn->users->vuid);
	}
}

static void increment_next_vuid(uint16_t *vuid)
{
	*vuid += 1;

	/* Check for vuid wrap. */
	if (*vuid == UID_FIELD_INVALID) {
		*vuid = VUID_OFFSET;
	}
}

/****************************************************
 Create a new partial auth user struct.
*****************************************************/

uint64_t register_initial_vuid(struct smbd_server_connection *sconn)
{
	struct user_struct *vuser;

	/* Limit allowed vuids to 16bits - VUID_OFFSET. */
	if (sconn->num_users >= 0xFFFF-VUID_OFFSET) {
		return UID_FIELD_INVALID;
	}

	if((vuser = talloc_zero(NULL, struct user_struct)) == NULL) {
		DEBUG(0,("register_initial_vuid: "
				"Failed to talloc users struct!\n"));
		return UID_FIELD_INVALID;
	}

	/* Allocate a free vuid. Yes this is a linear search... */
	while( get_valid_user_struct_internal(sconn,
			sconn->smb1.sessions.next_vuid,
			SERVER_ALLOCATED_REQUIRED_ANY) != NULL ) {
		increment_next_vuid(&sconn->smb1.sessions.next_vuid);
	}

	DEBUG(10,("register_initial_vuid: allocated vuid = %u\n",
		(unsigned int)sconn->smb1.sessions.next_vuid ));

	vuser->vuid = sconn->smb1.sessions.next_vuid;

	/*
	 * This happens in an unfinished NTLMSSP session setup. We
	 * need to allocate a vuid between the first and second calls
	 * to NTLMSSP.
	 */
	increment_next_vuid(&sconn->smb1.sessions.next_vuid);

	sconn->num_users++;
	DLIST_ADD(sconn->users, vuser);

	return vuser->vuid;
}

int register_homes_share(const char *username)
{
	int result;
	struct passwd *pwd;

	result = lp_servicenumber(username);
	if (result != -1) {
		DEBUG(3, ("Using static (or previously created) service for "
			  "user '%s'; path = '%s'\n", username,
			  lp_pathname(result)));
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

/**
 *  register that a valid login has been performed, establish 'session'.
 *  @param session_info The token returned from the authentication process.
 *   (now 'owned' by register_existing_vuid)
 *
 *  @param session_key The User session key for the login session (now also
 *  'owned' by register_existing_vuid)
 *
 *  @param respose_blob The NT challenge-response, if available.  (May be
 *  freed after this call)
 *
 *  @param smb_name The untranslated name of the user
 *
 *  @return Newly allocated vuid, biased by an offset. (This allows us to
 *   tell random client vuid's (normally zero) from valid vuids.)
 *
 */

uint64_t register_existing_vuid(struct smbd_server_connection *sconn,
				uint64_t vuid,
				struct auth_session_info *session_info,
				DATA_BLOB response_blob)
{
	struct user_struct *vuser;
	bool guest = security_session_user_level(session_info, NULL) < SECURITY_USER;

	vuser = get_partial_auth_user_struct(sconn, vuid);
	if (!vuser) {
		goto fail;
	}

	/* Use this to keep tabs on all our info from the authentication */
	vuser->session_info = talloc_move(vuser, &session_info);

	/* Make clear that we require the optional unix_token and unix_info in the source3 code */
	SMB_ASSERT(vuser->session_info->unix_token);
	SMB_ASSERT(vuser->session_info->unix_info);

	DEBUG(10,("register_existing_vuid: (%u,%u) %s %s %s guest=%d\n",
		  (unsigned int)vuser->session_info->unix_token->uid,
		  (unsigned int)vuser->session_info->unix_token->gid,
		  vuser->session_info->unix_info->unix_name,
		  vuser->session_info->unix_info->sanitized_username,
		  vuser->session_info->info->domain_name,
		  guest));

	DEBUG(3, ("register_existing_vuid: User name: %s\t"
		  "Real name: %s\n", vuser->session_info->unix_info->unix_name,
		  vuser->session_info->info->full_name ?
		  vuser->session_info->info->full_name : ""));

	if (!vuser->session_info->security_token) {
		DEBUG(1, ("register_existing_vuid: session_info does not "
			"contain a user_token - cannot continue\n"));
		goto fail;
	}

	/* Make clear that we require the optional unix_token in the source3 code */
	SMB_ASSERT(vuser->session_info->unix_token);

	DEBUG(3,("register_existing_vuid: UNIX uid %d is UNIX user %s, "
		"and will be vuid %llu\n", (int)vuser->session_info->unix_token->uid,
		 vuser->session_info->unix_info->unix_name,
		 (unsigned long long)vuser->vuid));

	if (!session_claim(sconn, vuser)) {
		DEBUG(1, ("register_existing_vuid: Failed to claim session "
			"for vuid=%llu\n",
			(unsigned long long)vuser->vuid));
		goto fail;
	}

	/* Register a home dir service for this user if
	(a) This is not a guest connection,
	(b) we have a home directory defined
	(c) there s not an existing static share by that name
	If a share exists by this name (autoloaded or not) reuse it . */

	vuser->homes_snum = -1;


	if (!guest) {
		vuser->homes_snum = register_homes_share(
			vuser->session_info->unix_info->unix_name);
	}

	if (srv_is_signing_negotiated(sconn) &&
	    !guest) {
		/* Try and turn on server signing on the first non-guest
		 * sessionsetup. */
		srv_set_signing(sconn,
				vuser->session_info->session_key,
				response_blob);
	}

	/* fill in the current_user_info struct */
	set_current_user_info(
		vuser->session_info->unix_info->sanitized_username,
		vuser->session_info->unix_info->unix_name,
		vuser->session_info->info->domain_name);

	return vuser->vuid;

  fail:

	if (vuser) {
		invalidate_vuid(sconn, vuid);
	}
	return UID_FIELD_INVALID;
}
