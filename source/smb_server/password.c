/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Tridgell 1992-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"


/****************************************************************************
check if a uid has been validated, and return an pointer to the user_struct
if it has. NULL if not. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
struct user_struct *get_valid_user_struct(struct server_context *smb, uint16 vuid)
{
	user_struct *usp;
	int count=0;

	if (vuid == UID_FIELD_INVALID)
		return NULL;

	for (usp=smb->users.validated_users;usp;usp=usp->next,count++) {
		if (vuid == usp->vuid) {
			if (count > 10) {
				DLIST_PROMOTE(smb->users.validated_users, usp);
			}
			return usp;
		}
	}

	return NULL;
}

/****************************************************************************
invalidate a uid
****************************************************************************/
void invalidate_vuid(struct server_context *smb, uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(smb, vuid);

	if (vuser == NULL)
		return;
	
	data_blob_free(&vuser->session_key);

	session_yield(vuser);

	free_server_info(&vuser->server_info);

	DLIST_REMOVE(smb->users.validated_users, vuser);

	/* clear the vuid from the 'cache' on each connection, and
	   from the vuid 'owner' of connections */
	/* REWRITE: conn_clear_vuid_cache(smb, vuid); */

	SAFE_FREE(vuser);
	smb->users.num_validated_vuids--;
}

/****************************************************************************
invalidate all vuid entries for this process
****************************************************************************/
void invalidate_all_vuids(struct server_context *smb)
{
	user_struct *usp, *next=NULL;

	for (usp=smb->users.validated_users;usp;usp=next) {
		next = usp->next;
		
		invalidate_vuid(smb, usp->vuid);
	}
}

/**
 *  register that a valid login has been performed, establish 'session'.
 *  @param server_info The token returned from the authentication process. 
 *   (now 'owned' by register_vuid)
 *
 *  @param session_key The User session key for the login session (now also 'owned' by register_vuid)
 *
 *  @param smb_name The untranslated name of the user
 *
 *  @return Newly allocated vuid, biased by an offset. (This allows us to
 *   tell random client vuid's (normally zero) from valid vuids.)
 *
 */

int register_vuid(struct server_context *smb,
		  struct auth_serversupplied_info *server_info, 
		  DATA_BLOB *session_key,
		  const char *smb_name)
{
	user_struct *vuser = NULL;

	/* Ensure no vuid gets registered in share level security. */
	if(lp_security() == SEC_SHARE)
		return UID_FIELD_INVALID;

	/* Limit allowed vuids to 16bits - VUID_OFFSET. */
	if (smb->users.num_validated_vuids >= 0xFFFF-VUID_OFFSET)
		return UID_FIELD_INVALID;

	if((vuser = (user_struct *)malloc( sizeof(user_struct) )) == NULL) {
		DEBUG(0,("Failed to malloc users struct!\n"));
		return UID_FIELD_INVALID;
	}

	ZERO_STRUCTP(vuser);

	/* Allocate a free vuid. Yes this is a linear search... :-) */
	while (get_valid_user_struct(smb, smb->users.next_vuid) != NULL ) {
		smb->users.next_vuid++;
		/* Check for vuid wrap. */
		if (smb->users.next_vuid == UID_FIELD_INVALID)
			smb->users.next_vuid = VUID_OFFSET;
	}

	DEBUG(10,("register_vuid: allocated vuid = %u\n", 
		  (unsigned int)smb->users.next_vuid));

	vuser->vuid = smb->users.next_vuid;

	vuser->session_key = *session_key;

 	if (!server_info->ptok) {
		DEBUG(1, ("server_info does not contain a user_token - cannot continue\n"));
		free_server_info(&server_info);

		SAFE_FREE(vuser);
		return UID_FIELD_INVALID;
	}

	/* use this to keep tabs on all our info from the authentication */
	vuser->server_info = server_info;

	smb->users.next_vuid++;
	smb->users.num_validated_vuids++;

	DLIST_ADD(smb->users.validated_users, vuser);

	if (!session_claim(smb, vuser)) {
		DEBUG(1,("Failed to claim session for vuid=%d\n", vuser->vuid));
		invalidate_vuid(smb, vuser->vuid);
		return -1;
	}

	return vuser->vuid;
}


/****************************************************************************
add a name to the session users list
****************************************************************************/
void add_session_user(struct server_context *smb, const char *user)
{
	char *suser;
	struct passwd *passwd;

	if (!(passwd = Get_Pwnam(user))) return;

	suser = strdup(passwd->pw_name);
	if (!suser) {
		return;
	}

	if (suser && *suser && !in_list(suser,smb->users.session_users,False)) {
		char *p;
		if (!smb->users.session_users) {
			asprintf(&p, "%s", suser);
		} else {
			asprintf(&p, "%s %s", smb->users.session_users, suser);
		}
		SAFE_FREE(smb->users.session_users);
		smb->users.session_users = p;
	}

	free(suser);
}


/****************************************************************************
check if a username is valid
****************************************************************************/
BOOL user_ok(const char *user,int snum, gid_t *groups, size_t n_groups)
{
	char **valid, **invalid;
	BOOL ret;

	valid = invalid = NULL;
	ret = True;

	if (lp_invalid_users(snum)) {
		str_list_copy(&invalid, lp_invalid_users(snum));
		if (invalid && str_list_substitute(invalid, "%S", lp_servicename(snum))) {
			ret = !user_in_list(user, (const char **)invalid, groups, n_groups);
		}
	}
	if (invalid)
		str_list_free (&invalid);

	if (ret && lp_valid_users(snum)) {
		str_list_copy(&valid, lp_valid_users(snum));
		if (valid && str_list_substitute(valid, "%S", lp_servicename(snum))) {
			ret = user_in_list(user, (const char **)valid, groups, n_groups);
		}
	}
	if (valid)
		str_list_free (&valid);

	if (ret && lp_onlyuser(snum)) {
		char **user_list = str_list_make (lp_username(snum), NULL);
		if (user_list && str_list_substitute(user_list, "%S", lp_servicename(snum))) {
			ret = user_in_list(user, (const char **)user_list, groups, n_groups);
		}
		if (user_list) str_list_free (&user_list);
	}

	return(ret);
}
