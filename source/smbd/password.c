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

/* users from session setup */
static char *session_userlist = NULL;
/* workgroup from session setup. */
static char *session_workgroup = NULL;

/* this holds info on user ids that are already validated for this VC */
static user_struct *validated_users;
static int next_vuid = VUID_OFFSET;
static int num_validated_vuids;

enum server_allocated_state { SERVER_ALLOCATED_REQUIRED_YES,
				SERVER_ALLOCATED_REQUIRED_NO,
				SERVER_ALLOCATED_REQUIRED_ANY};

static user_struct *get_valid_user_struct_internal(uint16 vuid,
			enum server_allocated_state server_allocated)
{
	user_struct *usp;
	int count=0;

	if (vuid == UID_FIELD_INVALID)
		return NULL;

	for (usp=validated_users;usp;usp=usp->next,count++) {
		if (vuid == usp->vuid) {
			switch (server_allocated) {
				case SERVER_ALLOCATED_REQUIRED_YES:
					if (usp->server_info == NULL) {
						continue;
					}
					break;
				case SERVER_ALLOCATED_REQUIRED_NO:
					if (usp->server_info != NULL) {
						continue;
					}
				case SERVER_ALLOCATED_REQUIRED_ANY:
					break;
			}
			if (count > 10) {
				DLIST_PROMOTE(validated_users, usp);
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

user_struct *get_valid_user_struct(uint16 vuid)
{
	return get_valid_user_struct_internal(vuid,
			SERVER_ALLOCATED_REQUIRED_YES);
}

bool is_partial_auth_vuid(uint16 vuid)
{
	if (vuid == UID_FIELD_INVALID) {
		return False;
	}
	return get_valid_user_struct_internal(vuid,
			SERVER_ALLOCATED_REQUIRED_NO) ? True : False;
}

/****************************************************************************
 Get the user struct of a partial NTLMSSP login
****************************************************************************/

user_struct *get_partial_auth_user_struct(uint16 vuid)
{
	return get_valid_user_struct_internal(vuid,
			SERVER_ALLOCATED_REQUIRED_NO);
}

/****************************************************************************
 Invalidate a uid.
****************************************************************************/

void invalidate_vuid(uint16 vuid)
{
	user_struct *vuser = NULL;

	if (vuid == UID_FIELD_INVALID) {
		return;
	}

	vuser = get_valid_user_struct_internal(vuid,
			SERVER_ALLOCATED_REQUIRED_ANY);
	if (vuser == NULL) {
		return;
	}

	session_yield(vuser);

	data_blob_free(&vuser->session_key);

	if (vuser->auth_ntlmssp_state) {
		auth_ntlmssp_end(&vuser->auth_ntlmssp_state);
	}

	DLIST_REMOVE(validated_users, vuser);

	/* clear the vuid from the 'cache' on each connection, and
	   from the vuid 'owner' of connections */
	conn_clear_vuid_cache(vuid);

	TALLOC_FREE(vuser);
	num_validated_vuids--;
}

/****************************************************************************
 Invalidate all vuid entries for this process.
****************************************************************************/

void invalidate_all_vuids(void)
{
	user_struct *usp, *next=NULL;

	for (usp=validated_users;usp;usp=next) {
		next = usp->next;
		invalidate_vuid(usp->vuid);
	}
}

/****************************************************
 Create a new partial auth user struct.
*****************************************************/

int register_initial_vuid(void)
{
	user_struct *vuser;

	/* Paranoia check. */
	if(lp_security() == SEC_SHARE) {
		smb_panic("register_initial_vuid: "
			"Tried to register uid in security=share");
	}

	/* Limit allowed vuids to 16bits - VUID_OFFSET. */
	if (num_validated_vuids >= 0xFFFF-VUID_OFFSET) {
		return UID_FIELD_INVALID;
	}

	if((vuser = talloc_zero(NULL, user_struct)) == NULL) {
		DEBUG(0,("register_initial_vuid: "
				"Failed to talloc users struct!\n"));
		return UID_FIELD_INVALID;
	}

	/* Allocate a free vuid. Yes this is a linear search... */
	while( get_valid_user_struct_internal(next_vuid,
			SERVER_ALLOCATED_REQUIRED_ANY) != NULL ) {
		next_vuid++;
		/* Check for vuid wrap. */
		if (next_vuid == UID_FIELD_INVALID) {
			next_vuid = VUID_OFFSET;
		}
	}

	DEBUG(10,("register_initial_vuid: allocated vuid = %u\n",
		(unsigned int)next_vuid ));

	vuser->vuid = next_vuid;

	/*
	 * This happens in an unfinished NTLMSSP session setup. We
	 * need to allocate a vuid between the first and second calls
	 * to NTLMSSP.
	 */
	next_vuid++;
	num_validated_vuids++;

	DLIST_ADD(validated_users, vuser);
	return vuser->vuid;
}

/**
 *  register that a valid login has been performed, establish 'session'.
 *  @param server_info The token returned from the authentication process.
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

int register_existing_vuid(uint16 vuid,
			auth_serversupplied_info *server_info,
			DATA_BLOB session_key,
			DATA_BLOB response_blob,
			const char *smb_name)
{
	user_struct *vuser = get_partial_auth_user_struct(vuid);
	if (!vuser) {
		goto fail;
	}

	/* Use this to keep tabs on all our info from the authentication */
	vuser->server_info = server_info;

	/* Ensure that the server_info will disappear with
	 * the vuser it is now attached to */

	talloc_steal(vuser, vuser->server_info);

	/* the next functions should be done by a SID mapping system (SMS) as
	 * the new real sam db won't have reference to unix uids or gids
	 */

	vuser->uid = server_info->uid;
	vuser->gid = server_info->gid;

	vuser->n_groups = server_info->n_groups;
	if (vuser->n_groups) {
		if (!(vuser->groups = (gid_t *)talloc_memdup(vuser,
					server_info->groups,
					sizeof(gid_t)*vuser->n_groups))) {
			DEBUG(0,("register_existing_vuid: "
				"failed to talloc_memdup vuser->groups\n"));
			goto fail;
		}
	}

	vuser->guest = server_info->guest;
	fstrcpy(vuser->user.unix_name, server_info->unix_name);

	/* This is a potentially untrusted username */
	alpha_strcpy(vuser->user.smb_name, smb_name, ". _-$",
		sizeof(vuser->user.smb_name));

	fstrcpy(vuser->user.domain, pdb_get_domain(server_info->sam_account));
	fstrcpy(vuser->user.full_name,
	pdb_get_fullname(server_info->sam_account));

	{
		/* Keep the homedir handy */
		const char *homedir =
			pdb_get_homedir(server_info->sam_account);
		const char *logon_script =
			pdb_get_logon_script(server_info->sam_account);

		if (!IS_SAM_DEFAULT(server_info->sam_account,
					PDB_UNIXHOMEDIR)) {
			const char *unix_homedir =
				pdb_get_unix_homedir(server_info->sam_account);
			if (unix_homedir) {
				vuser->unix_homedir = unix_homedir;
			}
		} else {
			struct passwd *passwd =
				getpwnam_alloc(vuser, vuser->user.unix_name);
			if (passwd) {
				vuser->unix_homedir = passwd->pw_dir;
				/* Ensure that the unix_homedir now
				 * belongs to vuser, so it goes away
				 * with it, not with passwd below: */
				talloc_steal(vuser, vuser->unix_homedir);
				TALLOC_FREE(passwd);
			}
		}

		if (homedir) {
			vuser->homedir = homedir;
		}
		if (logon_script) {
			vuser->logon_script = logon_script;
		}
	}
	vuser->session_key = session_key;

	DEBUG(10,("register_existing_vuid: (%u,%u) %s %s %s guest=%d\n",
			(unsigned int)vuser->uid,
			(unsigned int)vuser->gid,
			vuser->user.unix_name, vuser->user.smb_name,
			vuser->user.domain, vuser->guest ));

	DEBUG(3, ("register_existing_vuid: User name: %s\t"
		"Real name: %s\n", vuser->user.unix_name,
		vuser->user.full_name));

	if (server_info->ptok) {
		vuser->nt_user_token = dup_nt_token(vuser, server_info->ptok);
	} else {
		DEBUG(1, ("register_existing_vuid: server_info does not "
			"contain a user_token - cannot continue\n"));
		goto fail;
	}

	DEBUG(3,("register_existing_vuid: UNIX uid %d is UNIX user %s, "
		"and will be vuid %u\n",
		(int)vuser->uid,vuser->user.unix_name, vuser->vuid));

	next_vuid++;
	num_validated_vuids++;

	if (!session_claim(vuser)) {
		DEBUG(1, ("register_existing_vuid: Failed to claim session "
			"for vuid=%d\n",
			vuser->vuid));
		goto fail;
	}

	/* Register a home dir service for this user if
	(a) This is not a guest connection,
	(b) we have a home directory defined
	(c) there s not an existing static share by that name
	If a share exists by this name (autoloaded or not) reuse it . */

	vuser->homes_snum = -1;
	if ( (!vuser->guest) && vuser->unix_homedir && *(vuser->unix_homedir)) {
		int servicenumber = lp_servicenumber(vuser->user.unix_name);
		if ( servicenumber == -1 ) {
			DEBUG(3, ("Adding homes service for user '%s' using "
				"home directory: '%s'\n",
				vuser->user.unix_name, vuser->unix_homedir));
			vuser->homes_snum =
				add_home_service(vuser->user.unix_name,
						vuser->user.unix_name,
						vuser->unix_homedir);
		} else {
			DEBUG(3, ("Using static (or previously created) "
				"service for user '%s'; path = '%s'\n",
				vuser->user.unix_name,
				lp_pathname(servicenumber) ));
			vuser->homes_snum = servicenumber;
		}
	}

	if (srv_is_signing_negotiated() && !vuser->guest &&
			!srv_signing_started()) {
		/* Try and turn on server signing on the first non-guest
		 * sessionsetup. */
		srv_set_signing(vuser->session_key, response_blob);
	}

	/* fill in the current_user_info struct */
	set_current_user_info( &vuser->user );
	return vuser->vuid;

  fail:

	if (vuser) {
		invalidate_vuid(vuid);
	}
	return UID_FIELD_INVALID;
}

/****************************************************************************
 Add a name to the session users list.
****************************************************************************/

void add_session_user(const char *user)
{
	struct passwd *pw;
	char *tmp;

	pw = Get_Pwnam_alloc(talloc_tos(), user);

	if (pw == NULL) {
		return;
	}

	if (session_userlist == NULL) {
		session_userlist = SMB_STRDUP(pw->pw_name);
		goto done;
	}

	if (in_list(pw->pw_name,session_userlist,False) ) {
		goto done;
	}

	if (strlen(session_userlist) > 128 * 1024) {
		DEBUG(3,("add_session_user: session userlist already "
			 "too large.\n"));
		goto done;
	}

	if (asprintf(&tmp, "%s %s", session_userlist, pw->pw_name) == -1) {
		DEBUG(3, ("asprintf failed\n"));
		goto done;
	}

	SAFE_FREE(session_userlist);
	session_userlist = tmp;
 done:
	TALLOC_FREE(pw);
}

/****************************************************************************
 In security=share mode we need to store the client workgroup, as that's
  what Vista uses for the NTLMv2 calculation.
****************************************************************************/

void add_session_workgroup(const char *workgroup)
{
	if (session_workgroup) {
		SAFE_FREE(session_workgroup);
	}
	session_workgroup = smb_xstrdup(workgroup);
}

/****************************************************************************
 In security=share mode we need to return the client workgroup, as that's
  what Vista uses for the NTLMv2 calculation.
****************************************************************************/

const char *get_session_workgroup(void)
{
	return session_workgroup;
}

/****************************************************************************
 Check if a user is in a netgroup user list. If at first we don't succeed,
 try lower case.
****************************************************************************/

bool user_in_netgroup(const char *user, const char *ngname)
{
#ifdef HAVE_NETGROUP
	static char *mydomain = NULL;
	fstring lowercase_user;

	if (mydomain == NULL)
		yp_get_default_domain(&mydomain);

	if(mydomain == NULL) {
		DEBUG(5,("Unable to get default yp domain, "
			"let's try without specifying it\n"));
	}

	DEBUG(5,("looking for user %s of domain %s in netgroup %s\n",
		user, mydomain?mydomain:"(ANY)", ngname));

	if (innetgr(ngname, NULL, user, mydomain)) {
		DEBUG(5,("user_in_netgroup: Found\n"));
		return (True);
	} else {

		/*
		 * Ok, innetgr is case sensitive. Try once more with lowercase
		 * just in case. Attempt to fix #703. JRA.
		 */

		fstrcpy(lowercase_user, user);
		strlower_m(lowercase_user);

		DEBUG(5,("looking for user %s of domain %s in netgroup %s\n",
			lowercase_user, mydomain?mydomain:"(ANY)", ngname));

		if (innetgr(ngname, NULL, lowercase_user, mydomain)) {
			DEBUG(5,("user_in_netgroup: Found\n"));
			return (True);
		}
	}
#endif /* HAVE_NETGROUP */
	return False;
}

/****************************************************************************
 Check if a user is in a user list - can check combinations of UNIX
 and netgroup lists.
****************************************************************************/

bool user_in_list(const char *user,const char **list)
{
	if (!list || !*list)
		return False;

	DEBUG(10,("user_in_list: checking user %s in list\n", user));

	while (*list) {

		DEBUG(10,("user_in_list: checking user |%s| against |%s|\n",
			  user, *list));

		/*
		 * Check raw username.
		 */
		if (strequal(user, *list))
			return(True);

		/*
		 * Now check to see if any combination
		 * of UNIX and netgroups has been specified.
		 */

		if(**list == '@') {
			/*
			 * Old behaviour. Check netgroup list
			 * followed by UNIX list.
			 */
			if(user_in_netgroup(user, *list +1))
				return True;
			if(user_in_group(user, *list +1))
				return True;
		} else if (**list == '+') {

			if((*(*list +1)) == '&') {
				/*
				 * Search UNIX list followed by netgroup.
				 */
				if(user_in_group(user, *list +2))
					return True;
				if(user_in_netgroup(user, *list +2))
					return True;

			} else {

				/*
				 * Just search UNIX list.
				 */

				if(user_in_group(user, *list +1))
					return True;
			}

		} else if (**list == '&') {

			if(*(*list +1) == '+') {
				/*
				 * Search netgroup list followed by UNIX list.
				 */
				if(user_in_netgroup(user, *list +2))
					return True;
				if(user_in_group(user, *list +2))
					return True;
			} else {
				/*
				 * Just search netgroup list.
				 */
				if(user_in_netgroup(user, *list +1))
					return True;
			}
		}

		list++;
	}
	return(False);
}

/****************************************************************************
 Check if a username is valid.
****************************************************************************/

static bool user_ok(const char *user, int snum)
{
	char **valid, **invalid;
	bool ret;

	valid = invalid = NULL;
	ret = True;

	if (lp_invalid_users(snum)) {
		str_list_copy(talloc_tos(), &invalid, lp_invalid_users(snum));
		if (invalid &&
		    str_list_substitute(invalid, "%S", lp_servicename(snum))) {

			/* This is used in sec=share only, so no current user
			 * around to pass to str_list_sub_basic() */

			if ( invalid && str_list_sub_basic(invalid, "", "") ) {
				ret = !user_in_list(user,
						    (const char **)invalid);
			}
		}
	}
	TALLOC_FREE(invalid);

	if (ret && lp_valid_users(snum)) {
		str_list_copy(talloc_tos(), &valid, lp_valid_users(snum));
		if ( valid &&
		     str_list_substitute(valid, "%S", lp_servicename(snum)) ) {

			/* This is used in sec=share only, so no current user
			 * around to pass to str_list_sub_basic() */

			if ( valid && str_list_sub_basic(valid, "", "") ) {
				ret = user_in_list(user, (const char **)valid);
			}
		}
	}
	TALLOC_FREE(valid);

	if (ret && lp_onlyuser(snum)) {
		char **user_list = str_list_make(
			talloc_tos(), lp_username(snum), NULL);
		if (user_list &&
		    str_list_substitute(user_list, "%S",
					lp_servicename(snum))) {
			ret = user_in_list(user, (const char **)user_list);
		}
		TALLOC_FREE(user_list);
	}

	return(ret);
}

/****************************************************************************
 Validate a group username entry. Return the username or NULL.
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
		 * copy the member list onto the heap before
		 * use. Bug pointed out by leon@eatworms.swmed.edu.
		 */

		if (gptr) {
			char *member_list = NULL;
			size_t list_len = 0;
			char *member;
			int i;

			for(i = 0; gptr->gr_mem && gptr->gr_mem[i]; i++) {
				list_len += strlen(gptr->gr_mem[i])+1;
			}
			list_len++;

			member_list = (char *)SMB_MALLOC(list_len);
			if (!member_list) {
				endgrent();
				return NULL;
			}

			*member_list = '\0';
			member = member_list;

			for(i = 0; gptr->gr_mem && gptr->gr_mem[i]; i++) {
				size_t member_len = strlen(gptr->gr_mem[i])+1;

				DEBUG(10,("validate_group: = gr_mem = "
					  "%s\n", gptr->gr_mem[i]));

				safe_strcpy(member, gptr->gr_mem[i],
					list_len - (member-member_list));
				member += member_len;
			}

			endgrent();

			member = member_list;
			while (*member) {
				if (user_ok(member,snum) &&
				    password_ok(member,password)) {
					char *name = talloc_strdup(talloc_tos(),
								member);
					SAFE_FREE(member_list);
					return name;
				}

				DEBUG(10,("validate_group = member = %s\n",
					  member));

				member += strlen(member) + 1;
			}

			SAFE_FREE(member_list);
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

bool authorise_login(int snum, fstring user, DATA_BLOB password,
		     bool *guest)
{
	bool ok = False;

#ifdef DEBUG_PASSWORD
	DEBUG(100,("authorise_login: checking authorisation on "
		   "user=%s pass=%s\n", user,password.data));
#endif

	*guest = False;

	/* there are several possibilities:
		1) login as the given user with given password
		2) login as a previously registered username with the given
		   password
		3) login as a session list username with the given password
		4) login as a previously validated user/password pair
		5) login as the "user =" user with given password
		6) login as the "user =" user with no password
		   (guest connection)
		7) login as guest user with no password

		if the service is guest_only then steps 1 to 5 are skipped
	*/

	/* now check the list of session users */
	if (!ok) {
		char *auser;
		char *user_list = NULL;
		char *saveptr;

		if ( session_userlist )
			user_list = SMB_STRDUP(session_userlist);
		else
			user_list = SMB_STRDUP("");

		if (!user_list)
			return(False);

		for (auser = strtok_r(user_list, LIST_SEP, &saveptr);
		     !ok && auser;
		     auser = strtok_r(NULL, LIST_SEP, &saveptr)) {
			fstring user2;
			fstrcpy(user2,auser);
			if (!user_ok(user2,snum))
				continue;

			if (password_ok(user2,password)) {
				ok = True;
				fstrcpy(user,user2);
				DEBUG(3,("authorise_login: ACCEPTED: session "
					 "list username (%s) and given "
					 "password ok\n", user));
			}
		}

		SAFE_FREE(user_list);
	}

	/* check the user= fields and the given password */
	if (!ok && lp_username(snum)) {
		TALLOC_CTX *ctx = talloc_tos();
		char *auser;
		char *user_list = talloc_strdup(ctx, lp_username(snum));
		char *saveptr;

		if (!user_list) {
			goto check_guest;
		}

		user_list = talloc_string_sub(ctx,
				user_list,
				"%S",
				lp_servicename(snum));

		if (!user_list) {
			goto check_guest;
		}

		for (auser = strtok_r(user_list, LIST_SEP, &saveptr);
		     auser && !ok;
		     auser = strtok_r(NULL, LIST_SEP, &saveptr)) {
			if (*auser == '@') {
				auser = validate_group(auser+1,password,snum);
				if (auser) {
					ok = True;
					fstrcpy(user,auser);
					DEBUG(3,("authorise_login: ACCEPTED: "
						 "group username and given "
						 "password ok (%s)\n", user));
				}
			} else {
				fstring user2;
				fstrcpy(user2,auser);
				if (user_ok(user2,snum) &&
				    password_ok(user2,password)) {
					ok = True;
					fstrcpy(user,user2);
					DEBUG(3,("authorise_login: ACCEPTED: "
						 "user list username and "
						 "given password ok (%s)\n",
						 user));
				}
			}
		}
	}

  check_guest:

	/* check for a normal guest connection */
	if (!ok && GUEST_OK(snum)) {
		struct passwd *guest_pw;
		fstring guestname;
		fstrcpy(guestname,lp_guestaccount());
		guest_pw = Get_Pwnam_alloc(talloc_tos(), guestname);
		if (guest_pw != NULL) {
			fstrcpy(user,guestname);
			ok = True;
			DEBUG(3,("authorise_login: ACCEPTED: guest account "
				 "and guest ok (%s)\n",	user));
		} else {
			DEBUG(0,("authorise_login: Invalid guest account "
				 "%s??\n",guestname));
		}
		TALLOC_FREE(guest_pw);
		*guest = True;
	}

	if (ok && !user_ok(user, snum)) {
		DEBUG(0,("authorise_login: rejected invalid user %s\n",user));
		ok = False;
	}

	return(ok);
}
