/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
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

/* users from session setup */
static pstring session_users="";

/* this holds info on user ids that are already validated for this VC */
static user_struct *validated_users;
static int next_vuid = VUID_OFFSET;
static int num_validated_vuids;

/****************************************************************************
check if a uid has been validated, and return an pointer to the user_struct
if it has. NULL if not. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
user_struct *get_valid_user_struct(uint16 vuid)
{
	user_struct *usp;
	int count=0;

	if (vuid == UID_FIELD_INVALID)
		return NULL;

	for (usp=validated_users;usp;usp=usp->next,count++) {
		if (vuid == usp->vuid) {
			if (count > 10) {
				DLIST_PROMOTE(validated_users, usp);
			}
			return usp;
		}
	}

	return NULL;
}

/****************************************************************************
invalidate a uid
****************************************************************************/
void invalidate_vuid(uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);

	if (vuser == NULL)
		return;

	SAFE_FREE(vuser->homedir);

	session_yield(vuser);

	DLIST_REMOVE(validated_users, vuser);

	SAFE_FREE(vuser->groups);
	delete_nt_token(&vuser->nt_user_token);
	SAFE_FREE(vuser);
	num_validated_vuids--;
}

/****************************************************************************
invalidate all vuid entries for this process
****************************************************************************/
void invalidate_all_vuids(void)
{
	user_struct *usp, *next=NULL;

	for (usp=validated_users;usp;usp=next) {
		next = usp->next;
		
		invalidate_vuid(usp->vuid);
	}
}

/****************************************************************************
return a validated username
****************************************************************************/
char *validated_username(uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	if (vuser == NULL)
		return 0;
	return(vuser->user.unix_name);
}

/****************************************************************************
return a validated domain
****************************************************************************/
char *validated_domain(uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	if (vuser == NULL)
		return 0;
	return(vuser->user.domain);
}


/****************************************************************************
 Create the SID list for this user.
****************************************************************************/

NT_USER_TOKEN *create_nt_token(uid_t uid, gid_t gid, int ngroups, gid_t *groups, BOOL is_guest, NT_USER_TOKEN *sup_tok)
{
	extern DOM_SID global_sid_World;
	extern DOM_SID global_sid_Network;
	extern DOM_SID global_sid_Builtin_Guests;
	extern DOM_SID global_sid_Authenticated_Users;
	NT_USER_TOKEN *token;
	DOM_SID *psids;
	int i, psid_ndx = 0;
	size_t num_sids = 0;
	fstring sid_str;

	if ((token = (NT_USER_TOKEN *)malloc( sizeof(NT_USER_TOKEN) ) ) == NULL)
		return NULL;

	ZERO_STRUCTP(token);

	/* We always have uid/gid plus World and Network and Authenticated Users or Guest SIDs. */
	num_sids = 5 + ngroups;

	if (sup_tok && sup_tok->num_sids)
		num_sids += sup_tok->num_sids;

	if ((token->user_sids = (DOM_SID *)malloc( num_sids*sizeof(DOM_SID))) == NULL) {
		SAFE_FREE(token);
		return NULL;
	}

	psids = token->user_sids;

	/*
	 * Note - user SID *MUST* be first in token !
	 * se_access_check depends on this.
	 */

	uid_to_sid( &psids[PRIMARY_USER_SID_INDEX], uid);
	psid_ndx++;

	/*
	 * Primary group SID is second in token. Convention.
	 */

	gid_to_sid( &psids[PRIMARY_GROUP_SID_INDEX], gid);
	psid_ndx++;

	/* Now add the group SIDs. */

	for (i = 0; i < ngroups; i++) {
		if (groups[i] != gid) {
			gid_to_sid( &psids[psid_ndx++], groups[i]);
		}
	}

	if (sup_tok) {
		/* Now add the additional SIDs from the supplimentary token. */
		for (i = 0; i < sup_tok->num_sids; i++)
			sid_copy( &psids[psid_ndx++], &sup_tok->user_sids[i] );
	}

	/*
	 * Finally add the "standard" SIDs.
	 * The only difference between guest and "anonymous" (which we
	 * don't really support) is the addition of Authenticated_Users.
	 */

	sid_copy( &psids[psid_ndx++], &global_sid_World);
	sid_copy( &psids[psid_ndx++], &global_sid_Network);

	if (is_guest)
		sid_copy( &psids[psid_ndx++], &global_sid_Builtin_Guests);
	else
		sid_copy( &psids[psid_ndx++], &global_sid_Authenticated_Users);

	token->num_sids = psid_ndx;

	/* Dump list of sids in token */

	for (i = 0; i < token->num_sids; i++) {
		DEBUG(5, ("user token sid %s\n", 
			  sid_to_string(sid_str, &token->user_sids[i])));
	}

	return token;
}

/****************************************************************************
register a uid/name pair as being valid and that a valid password
has been given. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/

int register_vuid(auth_serversupplied_info *server_info, char *smb_name)
{
	user_struct *vuser = NULL;
	uid_t uid;
	gid_t gid;

	/* Ensure no vuid gets registered in share level security. */
	if(lp_security() == SEC_SHARE)
		return UID_FIELD_INVALID;

	/* Limit allowed vuids to 16bits - VUID_OFFSET. */
	if (num_validated_vuids >= 0xFFFF-VUID_OFFSET)
		return UID_FIELD_INVALID;

	if((vuser = (user_struct *)malloc( sizeof(user_struct) )) == NULL) {
		DEBUG(0,("Failed to malloc users struct!\n"));
		return UID_FIELD_INVALID;
	}

	ZERO_STRUCTP(vuser);

	if (!IS_SAM_UNIX_USER(server_info->sam_account)) {
		DEBUG(0,("Attempted session setup with invalid user.  No uid/gid in SAM_ACCOUNT (flags:%x)\n", pdb_get_init_flag(server_info->sam_account)));
		free(vuser);
		return UID_FIELD_INVALID;
	}

	uid = pdb_get_uid(server_info->sam_account);
	gid = pdb_get_gid(server_info->sam_account);

	/* Allocate a free vuid. Yes this is a linear search... :-) */
	while( get_valid_user_struct(next_vuid) != NULL ) {
		next_vuid++;
		/* Check for vuid wrap. */
		if (next_vuid == UID_FIELD_INVALID)
			next_vuid = VUID_OFFSET;
	}

	DEBUG(10,("register_vuid: allocated vuid = %u\n", (unsigned int)next_vuid ));

	vuser->vuid = next_vuid;
	vuser->uid = uid;
	vuser->gid = gid;
	vuser->guest = server_info->guest;
	fstrcpy(vuser->user.unix_name, pdb_get_username(server_info->sam_account));
	fstrcpy(vuser->user.smb_name, smb_name);
	fstrcpy(vuser->user.domain, pdb_get_domain(server_info->sam_account));
	fstrcpy(vuser->user.full_name, pdb_get_fullname(server_info->sam_account));

	{
		/* Keep the homedir handy */
		const char *homedir = pdb_get_homedir(server_info->sam_account);
		if (homedir) {
			vuser->homedir = smb_xstrdup(homedir);
		}
	}

	memcpy(vuser->session_key, server_info->session_key, sizeof(vuser->session_key));

	DEBUG(10,("register_vuid: (%u,%u) %s %s %s guest=%d\n", 
		  (unsigned int)vuser->uid, 
		  (unsigned int)vuser->gid,
		  vuser->user.unix_name, vuser->user.smb_name, vuser->user.domain, vuser->guest ));

	DEBUG(3, ("User name: %s\tReal name: %s\n",vuser->user.unix_name,vuser->user.full_name));	

	vuser->n_groups = 0;
	vuser->groups  = NULL;

	/* Find all the groups this uid is in and store them. 
		Used by change_to_user() */
	initialise_groups(vuser->user.unix_name, vuser->uid, vuser->gid);
	get_current_groups( &vuser->n_groups, &vuser->groups);

	if (server_info->ptok)
		add_supplementary_nt_login_groups(&vuser->n_groups, &vuser->groups, &server_info->ptok);

	/* Create an NT_USER_TOKEN struct for this user. */
	vuser->nt_user_token = create_nt_token(vuser->uid, vuser->gid, vuser->n_groups, vuser->groups, vuser->guest, server_info->ptok);

	DEBUG(3,("uid %d registered to name %s\n",(int)vuser->uid,vuser->user.unix_name));

	next_vuid++;
	num_validated_vuids++;

	DLIST_ADD(validated_users, vuser);

	if (!session_claim(vuser)) {
		DEBUG(1,("Failed to claim session for vuid=%d\n", vuser->vuid));
		invalidate_vuid(vuser->vuid);
		return -1;
	}

	/* Register a home dir service for this user */
	if ((!vuser->guest) && vuser->homedir && *(vuser->homedir)
		&& (lp_servicenumber(vuser->user.unix_name) < 0)) {
		add_home_service(vuser->user.unix_name, vuser->homedir);	  
	}
	
	return vuser->vuid;
}


/****************************************************************************
add a name to the session users list
****************************************************************************/
void add_session_user(char *user)
{
  fstring suser;
  StrnCpy(suser,user,sizeof(suser)-1);

  if (!Get_Pwnam_Modify(suser)) return;

  if (suser && *suser && !in_list(suser,session_users,False))
    {
      if (strlen(suser) + strlen(session_users) + 2 >= sizeof(pstring))
	DEBUG(1,("Too many session users??\n"));
      else
	{
	  pstrcat(session_users," ");
	  pstrcat(session_users,suser);
	}
    }
}


/****************************************************************************
check if a username is valid
****************************************************************************/
BOOL user_ok(char *user,int snum)
{
	char **valid, **invalid;
	BOOL ret;

	valid = invalid = NULL;
	ret = True;

	if (lp_invalid_users(snum)) {
		lp_list_copy(&invalid, lp_invalid_users(snum));
		if (invalid && lp_list_substitute(invalid, "%S", lp_servicename(snum))) {
			ret = !user_in_list(user, invalid);
		}
	}
	if (invalid) lp_list_free (&invalid);

	if (ret && lp_valid_users(snum)) {
		lp_list_copy(&valid, lp_valid_users(snum));
		if (valid && lp_list_substitute(valid, "%S", lp_servicename(snum))) {
			ret = user_in_list(user,valid);
		}
	}
	if (valid) lp_list_free (&valid);

	if (ret && lp_onlyuser(snum)) {
		char **user_list = lp_list_make (lp_username(snum));
		if (user_list && lp_list_substitute(user_list, "%S", lp_servicename(snum))) {
			ret = user_in_list(user, user_list);
		}
		if (user_list) lp_list_free (&user_list);
	}

	return(ret);
}

/****************************************************************************
validate a group username entry. Return the username or NULL
****************************************************************************/
static char *validate_group(char *group, DATA_BLOB password,int snum)
{
#ifdef HAVE_NETGROUP
	{
		char *host, *user, *domain;
		setnetgrent(group);
		while (getnetgrent(&host, &user, &domain)) {
			if (user) {
				if (user_ok(user, snum) && 
				    password_ok(user,password)) {
					endnetgrent();
					return(user);
				}
			}
		}
		endnetgrent();
	}
#endif
  
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
				static fstring name;
				fstrcpy(name,member);
				if (user_ok(name,snum) &&
				    password_ok(name,password)) {
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

BOOL authorise_login(int snum,char *user, DATA_BLOB password, 
		     BOOL *guest,BOOL *force,uint16 vuid)
{
	BOOL ok = False;
	user_struct *vuser = get_valid_user_struct(vuid);

#if DEBUG_PASSWORD
	DEBUG(100,("authorise_login: checking authorisation on user=%s pass=%s vuid=%d\n",
			user,password.data, vuid));
#endif

	*guest = False;
  
	if (GUEST_ONLY(snum))
		*force = True;

	if (!GUEST_ONLY(snum) && (lp_security() > SEC_SHARE)) {

		/*
		 * We should just use the given vuid from a sessionsetup_and_X.
		 */

		if (!vuser) {
			DEBUG(1,("authorise_login: refusing user '%s' with no session setup\n", user));
			return False;
		}

		if ((!vuser->guest && user_ok(vuser->user.unix_name,snum)) || 
		    (vuser->guest && GUEST_OK(snum))) {
			fstrcpy(user,vuser->user.unix_name);
			*guest = vuser->guest;
			DEBUG(3,("authorise_login: ACCEPTED: validated based on vuid as %sguest \
(user=%s)\n", vuser->guest ? "" : "non-", user));
			return True;
		}
	}
 
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

	if (!(GUEST_ONLY(snum) && GUEST_OK(snum))) {
		/* check for a previously registered guest username */
		if (!ok && (vuser != 0) && vuser->guest) {	  
			if (user_ok(vuser->user.unix_name,snum) &&
					password_ok(vuser->user.unix_name, password)) {
				fstrcpy(user, vuser->user.unix_name);
				*guest = False;
				DEBUG(3,("authorise_login: ACCEPTED: given password with registered user %s\n", user));
				ok = True;
			}
		}

		/* now check the list of session users */
		if (!ok) {
			char *auser;
			char *user_list = strdup(session_users);
			if (!user_list)
				return(False);

			for (auser=strtok(user_list,LIST_SEP); !ok && auser;
									auser = strtok(NULL,LIST_SEP)) {
				fstring user2;
				fstrcpy(user2,auser);
				if (!user_ok(user2,snum))
					continue;
		  
				if (password_ok(user2,password)) {
					ok = True;
					fstrcpy(user,user2);
					DEBUG(3,("authorise_login: ACCEPTED: session list username (%s) \
and given password ok\n", user));
				}
			}

			SAFE_FREE(user_list);
		}

		/* check for a previously validated username/password pair */
		if (!ok && (lp_security() > SEC_SHARE) && (vuser != 0) && !vuser->guest &&
							user_ok(vuser->user.unix_name,snum)) {
			fstrcpy(user,vuser->user.unix_name);
			*guest = False;
			DEBUG(3,("authorise_login: ACCEPTED: validated uid (%s) as non-guest\n",
				user));
			ok = True;
		}

		/* check the user= fields and the given password */
		if (!ok && lp_username(snum)) {
			char *auser;
			pstring user_list;
			StrnCpy(user_list,lp_username(snum),sizeof(pstring));

			pstring_sub(user_list,"%S",lp_servicename(snum));
	  
			for (auser=strtok(user_list,LIST_SEP); auser && !ok;
											auser = strtok(NULL,LIST_SEP)) {
				if (*auser == '@') {
					auser = validate_group(auser+1,password,snum);
					if (auser) {
						ok = True;
						fstrcpy(user,auser);
						DEBUG(3,("authorise_login: ACCEPTED: group username \
and given password ok (%s)\n", user));
					}
				} else {
					fstring user2;
					fstrcpy(user2,auser);
					if (user_ok(user2,snum) && password_ok(user2,password)) {
						ok = True;
						fstrcpy(user,user2);
						DEBUG(3,("authorise_login: ACCEPTED: user list username \
and given password ok (%s)\n", user));
					}
				}
			}
		}
	} /* not guest only */

	/* check for a normal guest connection */
	if (!ok && GUEST_OK(snum)) {
		fstring guestname;
		StrnCpy(guestname,lp_guestaccount(),sizeof(guestname)-1);
		if (Get_Pwnam(guestname)) {
			fstrcpy(user,guestname);
			ok = True;
			DEBUG(3,("authorise_login: ACCEPTED: guest account and guest ok (%s)\n",
					user));
		} else {
			DEBUG(0,("authorise_login: Invalid guest account %s??\n",guestname));
		}
		*guest = True;
	}

	if (ok && !user_ok(user,snum)) {
		DEBUG(0,("authorise_login: rejected invalid user %s\n",user));
		ok = False;
	}

	return(ok);
}
