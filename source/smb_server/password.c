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
	
	SAFE_FREE(vuser->homedir);
	SAFE_FREE(vuser->unix_homedir);
	SAFE_FREE(vuser->logon_script);
	
	data_blob_free(&vuser->session_key);

	session_yield(vuser);

	free_server_info(&vuser->server_info);

	DLIST_REMOVE(smb->users.validated_users, vuser);

	/* clear the vuid from the 'cache' on each connection, and
	   from the vuid 'owner' of connections */
	/* REWRITE: conn_clear_vuid_cache(smb, vuid); */

	SAFE_FREE(vuser->groups);
	delete_nt_token(&vuser->nt_user_token);
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

	/* the next functions should be done by a SID mapping system (SMS) as
	 * the new real sam db won't have reference to unix uids or gids
	 */
	if (!IS_SAM_UNIX_USER(server_info->sam_account)) {
		DEBUG(0,("Attempted session setup with invalid user.  No uid/gid in SAM_ACCOUNT\n"));
		free(vuser);
		free_server_info(&server_info);
		return UID_FIELD_INVALID;
	}
	
	vuser->uid = pdb_get_uid(server_info->sam_account);
	vuser->gid = pdb_get_gid(server_info->sam_account);
	
	vuser->n_groups = server_info->n_groups;
	if (vuser->n_groups) {
		if (!(vuser->groups = memdup(server_info->groups, sizeof(gid_t) * vuser->n_groups))) {
			DEBUG(0,("register_vuid: failed to memdup vuser->groups\n"));
			free(vuser);
			free_server_info(&server_info);
			return UID_FIELD_INVALID;
		}
	}

	vuser->guest = server_info->guest;
	fstrcpy(vuser->user.unix_name, pdb_get_username(server_info->sam_account)); 

	/* This is a potentially untrusted username */
	alpha_strcpy(vuser->user.smb_name, smb_name, ". _-$", sizeof(vuser->user.smb_name));

	fstrcpy(vuser->user.domain, pdb_get_domain(server_info->sam_account));
	fstrcpy(vuser->user.full_name, pdb_get_fullname(server_info->sam_account));

	{
		/* Keep the homedir handy */
		const char *homedir = pdb_get_homedir(server_info->sam_account);
		const char *unix_homedir = pdb_get_unix_homedir(server_info->sam_account);
		const char *logon_script = pdb_get_logon_script(server_info->sam_account);
		if (homedir) {
			vuser->homedir = smb_xstrdup(homedir);
		}

		if (unix_homedir) {
			vuser->unix_homedir = smb_xstrdup(unix_homedir);
		}

		if (logon_script) {
			vuser->logon_script = smb_xstrdup(logon_script);
		}
	}

	vuser->session_key = *session_key;

	DEBUG(10,("register_vuid: (%u,%u) %s %s %s guest=%d\n", 
		  (unsigned int)vuser->uid, 
		  (unsigned int)vuser->gid,
		  vuser->user.unix_name, vuser->user.smb_name, vuser->user.domain, vuser->guest ));

	DEBUG(3, ("User name: %s\tReal name: %s\n",vuser->user.unix_name,vuser->user.full_name));	

 	if (server_info->ptok) {
		vuser->nt_user_token = dup_nt_token(server_info->ptok);
	} else {
		DEBUG(1, ("server_info does not contain a user_token - cannot continue\n"));
		free_server_info(&server_info);
		SAFE_FREE(vuser->homedir);
		SAFE_FREE(vuser->unix_homedir);
		SAFE_FREE(vuser->logon_script);

		SAFE_FREE(vuser);
		return UID_FIELD_INVALID;
	}

	/* use this to keep tabs on all our info from the authentication */
	vuser->server_info = server_info;

	DEBUG(3,("UNIX uid %d is UNIX user %s, and will be vuid %u\n",(int)vuser->uid,vuser->user.unix_name, vuser->vuid));

	smb->users.next_vuid++;
	smb->users.num_validated_vuids++;

	DLIST_ADD(smb->users.validated_users, vuser);

	if (!session_claim(smb, vuser)) {
		DEBUG(1,("Failed to claim session for vuid=%d\n", vuser->vuid));
		invalidate_vuid(smb, vuser->vuid);
		return -1;
	}

	/* Register a home dir service for this user */
	if ((!vuser->guest) && vuser->unix_homedir && *(vuser->unix_homedir)) {
		DEBUG(3, ("Adding/updating homes service for user '%s' using home direcotry: '%s'\n", 
			  vuser->user.unix_name, vuser->unix_homedir));
		vuser->homes_snum = add_home_service(vuser->user.unix_name, vuser->user.unix_name, vuser->unix_homedir);	  
	} else {
		vuser->homes_snum = -1;
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

/****************************************************************************
validate a group username entry. Return the username or NULL
****************************************************************************/
static const char *validate_group(struct server_context *smb, const char *group, DATA_BLOB password,int snum)
{  
#ifdef HAVE_GETGRENT
	{
		struct group *gptr;
		setgrent();
		while ((gptr = (struct group *)getgrent())) {
			if (strequal(gptr->gr_name,group))
				break;
		}

		/*
		 * As user_ok can recurse doing a getgrent(), we must
		 * copy the member list into a pstring on the stack before
		 * use. Bug pointed out by leon@eatworms.swmed.edu.
		 */

		if (gptr) {
			pstring member_list;
			char *member;
			size_t copied_len = 0;
			int i;

			*member_list = '\0';
			member = member_list;

			for(i = 0; gptr->gr_mem && gptr->gr_mem[i]; i++) {
				size_t member_len = strlen(gptr->gr_mem[i]) + 1;
				if( copied_len + member_len < sizeof(pstring)) { 

					DEBUG(10,("validate_group: = gr_mem = %s\n", gptr->gr_mem[i]));

					safe_strcpy(member, gptr->gr_mem[i], sizeof(pstring) - copied_len - 1);
					copied_len += member_len;
					member += copied_len;
				} else {
					*member = '\0';
				}
			}

			endgrent();

			member = member_list;
			while (*member) {
				const char *name = member;
				if (user_ok(name,snum, NULL, 0) &&
				    password_ok(smb,name,password)) {
					endgrent();
					return(&name[0]);
				}

				DEBUG(10,("validate_group = member = %s\n", member));

				member += strlen(member) + 1;
			}
		} else {
			endgrent();
			return NULL;
		}
	}
#endif
	return(NULL);
}

/****************************************************************************
 Check for authority to login to a service with a given username/password.
 Note this is *NOT* used when logging on using sessionsetup_and_X.
****************************************************************************/

BOOL authorise_login(struct server_context *smb,
		     int snum, const char *user, DATA_BLOB password, 
		     BOOL *guest)
{
	BOOL ok = False;
	
#if DEBUG_PASSWORD
	DEBUG(100,("authorise_login: checking authorisation on user=%s pass=%s\n",
		   user,password.data));
#endif

	*guest = False;
  
	/* there are several possibilities:
		1) login as the given user with given password
		2) login as a previously registered username with the given password
		3) login as a session list username with the given password
		4) login as a previously validated user/password pair
		5) login as the "user =" user with given password
		6) login as the "user =" user with no password (guest connection)
		7) login as guest user with no password

		if the service is guest_only then steps 1 to 5 are skipped
	*/

	/* now check the list of session users */
	if (!ok) {
		char *auser;
		char *user_list = strdup(smb->users.session_users);
		if (!user_list)
			return(False);
		
		for (auser=strtok(user_list,LIST_SEP); !ok && auser;
		     auser = strtok(NULL,LIST_SEP)) {
			const char *user2 = auser;

			if (!user_ok(user2,snum, NULL, 0))
				continue;
			
			if (password_ok(smb, user2,password)) {
				ok = True;
				DEBUG(3,("authorise_login: ACCEPTED: session list username (%s) \
and given password ok\n", user2));
			}
		}
		
		SAFE_FREE(user_list);
	}
	
	/* check the user= fields and the given password */
	if (!ok && lp_username(snum)) {
		const char *auser;
		pstring user_list;
		StrnCpy(user_list,lp_username(snum),sizeof(pstring));
		
		pstring_sub(user_list,"%S",lp_servicename(snum));
		
		for (auser=strtok(user_list,LIST_SEP); auser && !ok;
		     auser = strtok(NULL,LIST_SEP)) {
			if (*auser == '@') {
				auser = validate_group(smb, auser+1,password,snum);
				if (auser) {
					ok = True;
					DEBUG(3,("authorise_login: ACCEPTED: group username \
and given password ok (%s)\n", auser));
				}
			} else {
				const char *user2 = auser;
				if (user_ok(user2,snum, NULL, 0) && password_ok(smb, user2,password)) {
					ok = True;
					DEBUG(3,("authorise_login: ACCEPTED: user list username \
and given password ok (%s)\n", user2));
				}
			}
		}
	}

	/* check for a normal guest connection */
	if (!ok && GUEST_OK(snum)) {
		const char *guestname = lp_guestaccount();
		if (Get_Pwnam(guestname)) {
			ok = True;
			DEBUG(3,("authorise_login: ACCEPTED: guest account and guest ok (%s)\n", guestname));
		} else {
			DEBUG(0,("authorise_login: Invalid guest account %s??\n",guestname));
		}
		*guest = True;
	}

	if (ok && !user_ok(user, snum, NULL, 0)) {
		DEBUG(0,("authorise_login: rejected invalid user %s\n",user));
		ok = False;
	}

	return(ok);
}
