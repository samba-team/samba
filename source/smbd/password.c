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
#include "rpc_client.h"

extern int DEBUGLEVEL;
extern int Protocol;

/* users from session setup */
static pstring session_users = "";

extern pstring scope;
extern pstring global_myname;
extern fstring global_myworkgroup;


/****************************************************************************
add a name to the session users list
****************************************************************************/
void add_session_user(char *user)
{
  fstring suser;
  StrnCpy(suser, user, sizeof(suser) - 1);

  if (!Get_Pwnam(suser, True)) return;

	if (suser && *suser && !in_list(suser, session_users, False))
	{
		if (strlen(suser) + strlen(session_users) + 2 >= sizeof(pstring))
			DEBUG(1, ("Too many session users??\n"));
		else
		{
			pstrcat(session_users, " ");
			pstrcat(session_users, suser);
		}
	}
}

/****************************************************************************
check if a username/password pair is OK either via the system password
database or the encrypted SMB password database
return True if the password is correct, False otherwise
****************************************************************************/
BOOL password_ok(const char *orig_user, const char *domain,
		 const char *smb_apasswd, int smb_apasslen,
		 const char *smb_ntpasswd, int smb_ntpasslen,
		 struct passwd *pwd, NET_USER_INFO_3 * info3)
{
	uchar last_chal[8];
	BOOL cleartext = smb_apasslen != 24 && smb_ntpasslen == 0;
	uchar *chal = NULL;

	if (info3 == NULL)
	{
		DEBUG(0, ("password_ok: no NET_USER_INFO_3 parameter!\n"));
		return False;
	}

	/*
	 * SMB password check
	 */

	if ((smb_apasslen != 0) ||
	    (lp_encrypted_passwords() && smb_apasslen == 0 &&
	     lp_null_passwords()))
	{
		DEBUG(10, ("password_ok: check SMB auth\n"));

		/* check security = user / domain */
		if ((!cleartext) && last_challenge(last_chal))
		{
			chal = last_chal;
		}
		if ((cleartext || chal) &&
		    check_domain_security(orig_user, domain,
					  chal,
					  smb_apasswd, smb_apasslen,
					  smb_ntpasswd, smb_ntpasslen,
					  info3) == 0x0)
		{
			DEBUG(10, ("password_ok: domain auth succeeded\n"));
			return True;
		}
	}

	return False;
}


/****************************************************************************
validate a group username entry. Return the username or NULL
****************************************************************************/
static char *validate_group(char *group, char *password, int pwlen, int snum,
		NET_USER_INFO_3 *info3)
{
#ifdef HAVE_NETGROUP
	char *host, *user, *domain;
#endif
#ifdef HAVE_GETGRENT
	struct group *gptr;
	pstring member_list;
	char *member;
	size_t copied_len = 0;
	int i;
#endif

#ifdef HAVE_NETGROUP

	setnetgrent(group);
	while (getnetgrent(&host, &user, &domain))
	{
		if (user)
		{
			if (user_ok(user, snum) &&
			    password_ok(user, NULL, password, pwlen,
					NULL, 0, NULL, info3))
			{
				endnetgrent();
				return (user);
			}
		}
	}
	endnetgrent();
#endif

#ifdef HAVE_GETGRENT

	setgrent();
	while ((gptr = (struct group *)getgrent()))
	{
		if (strequal(gptr->gr_name, group))
			break;
	}

	/*
	 * As user_ok can recurse doing a getgrent(), we must
	 * copy the member list into a pstring on the stack before
	 * use. Bug pointed out by leon@eatworms.swmed.edu.
	 */

	if (gptr == NULL)
	{
		endgrent();
		return NULL;
	}

	*member_list = '\0';
	member = member_list;

	for (i = 0; gptr->gr_mem && gptr->gr_mem[i]; i++) {
		size_t member_len = strlen(gptr->gr_mem[i]) + 1;
		if (copied_len + member_len < sizeof(pstring)) {

			DEBUG(10, ("validate_group: = gr_mem = %s\n", gptr->gr_mem[i]));

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
		fstrcpy(name, member);
		if (user_ok(name, snum) &&
		    password_ok(name, NULL, password, pwlen,
				NULL, 0, NULL, info3))
		{
			endgrent();
			return (&name[0]);
		}

		DEBUG(10, ("validate_group = member = %s\n", member));

		member += strlen(member) + 1;
	}
#endif
	return (NULL);
}



/****************************************************************************
check for authority to login to a service with a given username/password
****************************************************************************/
BOOL authorise_login(int snum, char *user, char *domain,
		     char *password, int pwlen,
		     BOOL *guest, BOOL *force, const vuser_key * key)
{
	BOOL ok = False;

	DEBUG(0, ("authorise_login: TODO. split function, it's 6 levels!\n"));
	*guest = False;

#if DEBUG_PASSWORD
	DEBUG(100, ("checking authorisation on user=%s pass=%s\n", user, password));
#endif

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

	if (GUEST_ONLY(snum)) *force = True;

	if (!(GUEST_ONLY(snum) && GUEST_OK(snum)))
	{
		user_struct *vuser = get_valid_user_struct(key);

		/* check the given username and password */
		if (!ok && (*user) && user_ok(user, snum)) {
			ok = password_ok(user, domain, password, pwlen,
					 NULL, 0, NULL, &vuser->usr);
			if (ok) DEBUG(3, ("ACCEPTED: given username password ok\n"));
		}

		/* check for a previously registered guest username */
		if (!ok && (vuser != 0) && vuser->guest) {
			if (user_ok(vuser->unix_name, snum) &&
			    password_ok(vuser->unix_name, domain, password, pwlen,
					NULL, 0, NULL, &vuser->usr))
			{
				fstrcpy(user, vuser->unix_name);
				vuser->guest = False;
				DEBUG(3, ("ACCEPTED: given password with registered user %s\n", user));
				ok = True;
			}
		}


		/* now check the list of session users */
		if (!ok)
		{
			char *auser;
			char *user_list = strdup(session_users);
			if (!user_list)
			{
				vuid_free_user_struct(vuser);
				return False;
			}

			for (auser = strtok(user_list, LIST_SEP);
			     !ok && auser;
			     auser = strtok(NULL, LIST_SEP))
			{
				fstring user2;
				fstrcpy(user2, auser);
				if (!user_ok(user2, snum)) continue;

				if (password_ok(user2, domain, password, pwlen,
						NULL, 0, NULL, &vuser->usr))
				{
					ok = True;
					fstrcpy(user, user2);
					DEBUG(3, ("ACCEPTED: session list username and given password ok\n"));
				}
			}
			free(user_list);
		}

		/* check for a previously validated username/password pair */
		if (!ok && (lp_security() > SEC_SHARE)
		    && (vuser != 0) && !vuser->guest
		    && user_ok(vuser->unix_name, snum))
		{
			fstrcpy(user, vuser->unix_name);
			*guest = False;
			DEBUG(3, ("ACCEPTED: validated uid ok as non-guest\n"));
			ok = True;
		}

		/* check for a rhosts entry */
		if (!ok && user_ok(user, snum) && check_hosts_equiv(user)) {
			ok = True;
			DEBUG(3, ("ACCEPTED: hosts equiv or rhosts entry\n"));
		}

		/* check the user= fields and the given password */
		if (!ok && lp_username(snum)) {
			char *auser;
			pstring user_list;
			StrnCpy(user_list, lp_username(snum), sizeof(pstring));

			pstring_sub(user_list, "%S", lp_servicename(snum));

			for (auser = strtok(user_list, LIST_SEP);
			     auser && !ok;
			     auser = strtok(NULL, LIST_SEP))
			{
				if (*auser == '@')
				{
					auser = validate_group(auser + 1,
							       password,
							       pwlen, snum,
							       &vuser->usr);
					if (auser)
					{
						ok = True;
						fstrcpy(user, auser);
						DEBUG(3, ("ACCEPTED: group username and given password ok\n"));
					}
				}
				else
				{
					fstring user2;
					fstrcpy(user2, auser);
					if (user_ok(user2, snum) &&
					    password_ok(user2, domain,
							password, pwlen, NULL,
							0, NULL, &vuser->usr))
					{
						ok = True;
						fstrcpy(user, user2);
						DEBUG(3, ("ACCEPTED: user list username and given password ok\n"));
					}
				}
			}
		}

		if (vuser != NULL)
		{
			tdb_store_vuid(key, vuser);
		}
		vuid_free_user_struct(vuser);

	}			/* not guest only */

	/* check for a normal guest connection */
	if (!ok && GUEST_OK(snum))
	{
		fstring guestname;
		StrnCpy(guestname, lp_guestaccount(snum), sizeof(guestname) - 1);
		if (Get_Pwnam(guestname, True))
		{
			fstrcpy(user, guestname);
			ok = True;
			DEBUG(3, ("ACCEPTED: guest account and guest ok\n"));
		}
		else
			DEBUG(0, ("Invalid guest account %s??\n", guestname));
		*guest = True;
		*force = True;
	}

	if (ok && !user_ok(user, snum))
	{
		DEBUG(0, ("rejected invalid user %s\n", user));
		ok = False;
	}

	return (ok);
}

BOOL check_user_equiv_line(char *buf, const char *user, const char *remote,
			   BOOL *plus_allowed, BOOL *ret)
{
	BOOL is_group = False;
	int plus = 1;
	char *bp = buf;
	char *file_host;
	char *file_user;

	if (strcmp(buf, "NO_PLUS\n") == 0)
	{
		DEBUG(6, ("check_user_equiv NO_PLUS\n"));
		(*plus_allowed) = 0;
		return False;
	}

	if (buf[0] == '+')
	{
		bp++;
		if (*bp == '\n' && (*plus_allowed))
		{
			/* a bare plus means everbody allowed */
			DEBUG(6, ("check_user_equiv everybody allowed\n"));
			*ret = True;
			return True;
		}
	}
	else if (buf[0] == '-')
	{
		bp++;
		plus = 0;
	}
	if (*bp == '@')
	{
		is_group = True;
		bp++;
	}

	file_host = strtok(bp, " \t\n");
	file_user = strtok(NULL, " \t\n");
	DEBUG(7, ("check_user_equiv %s %s\n",
		  file_host ? file_host : "(null)",
		  file_user ? file_user : "(null)"));

	if (file_host && *file_host)
	{
		BOOL host_ok = False;
#if defined(HAVE_NETGROUP) && defined(HAVE_YP_GET_DEFAULT_DOMAIN)
		if (is_group)
		{
			static char *mydomain = NULL;
			if (!mydomain)
				yp_get_default_domain(&mydomain);
			if (mydomain && innetgr(file_host, remote, user,
						mydomain)) host_ok = True;
		}
#else
		if (is_group)
		{
			DEBUG(1, ("Netgroups not configured\n"));
			return False;
		}
#endif
		/* is it this host */
		/* the fact that remote has come from a call of
		 * gethostbyaddr means that it may have the fully
		 * qualified domain name so we could look up the
		 * file version to get it into a canonical form,
		 * but I would rather just type it in full in the
		 * equiv file */
		if (!host_ok && !is_group && strequal(remote, file_host))
		{
			host_ok = True;
		}
		if (!host_ok)
		{
			return False;
		}
		/* is it this user */
		if (file_user == 0 || strequal(user, file_user))
		{
			DEBUG(5, ("check_user_equiv matched %s%s %s\n",
				  (plus ? "+" : "-"), file_host,
				  (file_user ? file_user : "")));
			*ret = (plus ? True : False);
			return True;
		}
	}

	return False;
}

/****************************************************************************
read the a hosts.equiv or .rhosts file and check if it
allows this user from this machine
****************************************************************************/
static BOOL check_user_equiv(char *user, char *remote, char *equiv_file)
{
	pstring buf;
	int plus_allowed = 1;
	FILE *fp = sys_fopen(equiv_file, "r");
	DEBUG(5, ("check_user_equiv %s %s %s\n", user, remote, equiv_file));
	if (!fp)
		return False;
	while (fgets(buf, sizeof(buf), fp))
	{
		trim_string(buf, " ", " ");

		if (buf[0] != '#' && buf[0] != '\n')
		{
			BOOL ret;
			if (check_user_equiv_line(buf, user, remote,
						  &plus_allowed, &ret))
			{
				fclose(fp);
				return ret;
			}
		}
	}
	fclose(fp);
	return False;
}


/****************************************************************************
check for a possible hosts equiv or rhosts entry for the user
****************************************************************************/
BOOL check_hosts_equiv(char *user)
{
	char *fname = NULL;
	pstring rhostsfile;
	const struct passwd *pass = Get_Pwnam(user, True);

	if (!pass)
		return(False);

	fname = lp_hosts_equiv();

	/* note: don't allow hosts.equiv on root */
	if (fname && *fname && (pass->pw_uid != 0)) {
		if (check_user_equiv(user, client_name(), fname))
			return (True);
	}

	if (lp_use_rhosts())
	{
		char *home = get_user_home_dir(user);
		if (home)
		{
			slprintf(rhostsfile, sizeof(rhostsfile) - 1,
				 "%s/.rhosts", home);
			if (check_user_equiv
			    (user, client_name(), rhostsfile))
				return (True);
		}
	}

	return False;
}
