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

extern int DEBUGLEVEL;
extern int Protocol;

/* users from session setup */
static pstring session_users="";

extern pstring scope;
extern pstring global_myname;
extern fstring global_myworkgroup;

/* Data to do lanman1/2 password challenge. */
static unsigned char saved_challenge[8];
static BOOL challenge_sent=False;

/*******************************************************************
Get the next challenge value - no repeats.
********************************************************************/
void generate_next_challenge(char *challenge)
{
#if 0
        /* 
         * Leave this ifdef'd out while we test
         * the new crypto random number generator.
         * JRA.
         */
	unsigned char buf[16];
	static int counter = 0;
	struct timeval tval;
	int v1,v2;

	/* get a sort-of random number */
	GetTimeOfDay(&tval);
	v1 = (counter++) + getpid() + tval.tv_sec;
	v2 = (counter++) * getpid() + tval.tv_usec;
	SIVAL(challenge,0,v1);
	SIVAL(challenge,4,v2);

	/* mash it up with md4 */
	mdfour(buf, (unsigned char *)challenge, 8);
#else
        unsigned char buf[8];

        generate_random_buffer(buf,8,False);
#endif 
	memcpy(saved_challenge, buf, 8);
	memcpy(challenge,buf,8);
	challenge_sent = True;
}

/*******************************************************************
set the last challenge sent, usually from a password server
********************************************************************/
BOOL set_challenge(unsigned char *challenge)
{
  memcpy(saved_challenge,challenge,8);
  challenge_sent = True;
  return(True);
}

/*******************************************************************
get the last challenge sent
********************************************************************/
static BOOL last_challenge(unsigned char *challenge)
{
  if (!challenge_sent) return False;
  memcpy(challenge,saved_challenge,8);
  return(True);
}

/* this holds info on user ids that are already validated for this VC */
static user_struct *validated_users = NULL;
static int num_validated_users = 0;

/****************************************************************************
check if a uid has been validated, and return an pointer to the user_struct
if it has. NULL if not. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
user_struct *get_valid_user_struct(uint16 vuid)
{
  if (vuid == UID_FIELD_INVALID)
    return NULL;
  vuid -= VUID_OFFSET;
  if ((vuid >= (uint16)num_validated_users) || 
     (validated_users[vuid].uid == (uid_t)-1) || (validated_users[vuid].gid == (gid_t)-1))
    return NULL;
  return &validated_users[vuid];
}

/****************************************************************************
invalidate a uid
****************************************************************************/
void invalidate_vuid(uint16 vuid)
{
  user_struct *vuser = get_valid_user_struct(vuid);

  if (vuser == NULL) return;

  vuser->uid = (uid_t)-1;
  vuser->gid = (gid_t)-1;

  vuser->n_sids = 0;

  /* same number of igroups as groups */
  vuser->n_groups = 0;

  if (vuser->groups)
    free((char *)vuser->groups);

  if (vuser->sids)
    free((char *)vuser->sids);

  vuser->sids    = NULL;
  vuser->groups  = NULL;
}


/****************************************************************************
return a validated username
****************************************************************************/
char *validated_username(uint16 vuid)
{
  user_struct *vuser = get_valid_user_struct(vuid);
  if (vuser == NULL)
    return 0;
  return(vuser->name);
}



/****************************************************************************
register a uid/name pair as being valid and that a valid password
has been given. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
uint16 register_vuid(uid_t uid,gid_t gid, char *unix_name, char *requested_name, BOOL guest, uchar user_sess_key[16])
{
  user_struct *vuser;
  struct passwd *pwfile; /* for getting real name from passwd file */

  /* Ensure no vuid gets registered in share level security. */
  if(lp_security() == SEC_SHARE)
    return UID_FIELD_INVALID;

#if 0
  /*
   * After observing MS-Exchange services writing to a Samba share
   * I belive this code is incorrect. Each service does its own
   * sessionsetup_and_X for the same user, and as each service shuts
   * down, it does a user_logoff_and_X. As we are consolidating multiple
   * sessionsetup_and_X's onto the same vuid here, when the first service
   * shuts down, it invalidates all the open files for the other services.
   * Hence I am removing this code and forcing each sessionsetup_and_X
   * to get a new vuid.
   * Jeremy Allison. (jallison@whistle.com).
   */

  int i;
  for(i = 0; i < num_validated_users; i++) {
    vuser = &validated_users[i];
    if ( vuser->uid == uid )
      return (uint16)(i + VUID_OFFSET); /* User already validated */
  }
#endif

  validated_users = (user_struct *)Realloc(validated_users,
			   sizeof(user_struct)*
			   (num_validated_users+1));
  
  if (!validated_users)
    {
      DEBUG(0,("Failed to realloc users struct!\n"));
      num_validated_users = 0;
      return UID_FIELD_INVALID;
    }

  vuser = &validated_users[num_validated_users];
  num_validated_users++;

  vuser->uid = uid;
  vuser->gid = gid;
  vuser->guest = guest;
  fstrcpy(vuser->name,unix_name);
  fstrcpy(vuser->requested_name,requested_name);
  memcpy(vuser->dc.user_sess_key, user_sess_key, sizeof(vuser->dc.user_sess_key));

  vuser->n_sids = 0;
  vuser->sids   = NULL;

  vuser->n_groups = 0;
  vuser->groups  = NULL;

  /* Find all the groups this uid is in and store them. 
     Used by become_user() */
  get_unixgroups(unix_name,uid,gid,
	       &vuser->n_groups,
	       &vuser->groups);

  DEBUG(3,("uid %d registered to name %s\n",(int)uid,unix_name));

  DEBUG(3, ("Clearing default real name\n"));
  fstrcpy(vuser->real_name, "<Full Name>\0");
  if (lp_unix_realname()) {
    if ((pwfile=hashed_getpwnam(vuser->name))!= NULL)
      {
      DEBUG(3, ("User name: %s\tReal name: %s\n",vuser->name,pwfile->pw_gecos));
      fstrcpy(vuser->real_name, pwfile->pw_gecos);
      }
  }

  return (uint16)((num_validated_users - 1) + VUID_OFFSET);
}


/****************************************************************************
add a name to the session users list
****************************************************************************/
void add_session_user(char *user)
{
  fstring suser;
  StrnCpy(suser,user,sizeof(suser)-1);

  if (!Get_Pwnam(suser,True)) return;

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
update the encrypted smbpasswd file from the plaintext username and password
*****************************************************************************/
static BOOL update_smbpassword_file(char *user, char *password)
{
	struct smb_passwd *smbpw;
	BOOL ret;
	
	become_root(0);
	smbpw = getsmbpwnam(user);
	unbecome_root(0);
	
	if(smbpw == NULL) {
		DEBUG(0,("getsmbpwnam returned NULL\n"));
		return False;
	}
 
	/* Here, the flag is one, because we want to ignore the
           XXXXXXX'd out password */
	ret = change_oem_password( smbpw, password, True);
	if (!ret)
	{
		DEBUG(3,("change_oem_password returned False\n"));
	}

	return ret;
}





/****************************************************************************
core of smb password checking routine.
****************************************************************************/
static BOOL smb_pwd_check_ntlmv1(char *password, unsigned char *part_passwd,
				unsigned char *c8,
				uchar sess_key[16])
{
  /* Finish the encryption of part_passwd. */
  unsigned char p24[24];

  if (part_passwd == NULL)
    DEBUG(10,("No password set - allowing access\n"));
  /* No password set - always true ! */
  if (part_passwd == NULL)
    return True;

  SMBOWFencrypt(part_passwd, c8, p24);
	if (sess_key != NULL)
	{
		SMBsesskeygen_ntv1(part_passwd, NULL, sess_key);
	}

#if DEBUG_PASSWORD
	DEBUG(100,("Part password (P16) was |"));
	dump_data(100, part_passwd, 16);
	DEBUG(100,("Password from client was |"));
	dump_data(100, password, 24);
	DEBUG(100,("Given challenge was |"));
	dump_data(100, c8, 8);
	DEBUG(100,("Value from encryption was |"));
	dump_data(100, p24, 24);
#endif
  return (memcmp(p24, password, 24) == 0);
}

/****************************************************************************
core of smb password checking routine.
****************************************************************************/
static BOOL smb_pwd_check_ntlmv2(char *password, size_t pwd_len,
				unsigned char *part_passwd,
				unsigned char const *c8,
				const char *user, const char *domain,
				char *sess_key)
{
	/* Finish the encryption of part_passwd. */
	unsigned char kr[16];
	unsigned char resp[16];

	if (part_passwd == NULL)
	{
		DEBUG(10,("No password set - allowing access\n"));
	}
	/* No password set - always true ! */
	if (part_passwd == NULL)
	{
		return True;
	}

	ntv2_owf_gen(part_passwd, user, domain, kr);
	SMBOWFencrypt_ntv2(kr, c8, 8, password+16, pwd_len-16, resp);
	if (sess_key != NULL)
	{
		SMBsesskeygen_ntv2(kr, resp, sess_key);
	}

#if DEBUG_PASSWORD
	DEBUG(100,("Part password (P16) was |"));
	dump_data(100, part_passwd, 16);
	DEBUG(100,("Password from client was |"));
	dump_data(100, password, pwd_len);
	DEBUG(100,("Given challenge was |"));
	dump_data(100, c8, 8);
	DEBUG(100,("Value from encryption was |"));
	dump_data(100, resp, 16);
#endif

	return (memcmp(resp, password, 16) == 0);
}

/****************************************************************************
 Do a specific test for an smb password being correct, given a smb_password and
 the lanman and NT responses.
****************************************************************************/
BOOL smb_password_ok(struct smb_passwd *smb_pass, uchar chal[8],
				const char *user, const char *domain,
				uchar *lm_pass, size_t lm_pwd_len,
				uchar *nt_pass, size_t nt_pwd_len,
				uchar sess_key[16])
{
	uchar challenge[8];

	if (smb_pass == NULL)
	{
		return False;
	}

	DEBUG(4,("Checking SMB password for user %s\n", 
		 smb_pass->unix_name));

	if (smb_pass->acct_ctrl & ACB_DISABLED)
	{
		DEBUG(3,("account for user %s was disabled.\n", 
			 smb_pass->unix_name));
		return False;
	}

	if (chal == NULL)
	{
		DEBUG(5,("use last SMBnegprot challenge\n"));
		if (!last_challenge(challenge))
		{
			DEBUG(1,("no challenge done - password failed\n"));
			return False;
		}
	}
	else
	{
		DEBUG(5,("challenge received\n"));
		memcpy(challenge, chal, 8);
	}

	if ((Protocol >= PROTOCOL_NT1) && (smb_pass->smb_nt_passwd != NULL))
	{
		/* We have the NT MD4 hash challenge available - see if we can
		   use it (ie. does it exist in the smbpasswd file).
		*/
		if (lp_server_ntlmv2() != False && nt_pwd_len > 24)
		{
			DEBUG(4,("smb_password_ok: Check NTLMv2 password\n"));
			if (smb_pwd_check_ntlmv2(nt_pass, nt_pwd_len,
				       (uchar *)smb_pass->smb_nt_passwd, 
					challenge, user, domain,
			                sess_key))
			{
				return True;
			}
		}
		if (lp_server_ntlmv2() != True && nt_pwd_len == 24)
		{
			DEBUG(4,("smb_password_ok: Check NT MD4 password\n"));
			if (smb_pwd_check_ntlmv1((char *)nt_pass, 
				       (uchar *)smb_pass->smb_nt_passwd, 
				       challenge,
			               sess_key))
			{
				DEBUG(4,("NT MD4 password check succeeded\n"));
				return True;
			}
		}
		DEBUG(4,("NT MD4 password check failed\n"));
	}

	if (lp_server_ntlmv2() == True)
	{
		DEBUG(4,("Not checking LM MD4 password\n"));
		return False;
	}

	/* Try against the lanman password. smb_pass->smb_passwd == NULL means
	   no password, allow access. */

	DEBUG(4,("Checking LM MD4 password\n"));

	if ((smb_pass->smb_passwd == NULL) && 
	   (smb_pass->acct_ctrl & ACB_PWNOTREQ))
	{
		DEBUG(4,("no password required for user %s\n",
			 smb_pass->unix_name));
		return True;
	}

	if ((smb_pass->smb_passwd != NULL) && 
	   smb_pwd_check_ntlmv1((char *)lm_pass, 
			      (uchar *)smb_pass->smb_passwd,
				challenge, NULL))
	{
		DEBUG(4,("LM MD4 password check succeeded\n"));
		return(True);
	}

	DEBUG(4,("LM MD4 password check failed\n"));

	return False;
}


/****************************************************************************
check if a username/password is OK assuming the password is a 24 byte
SMB hash
return True if the password is correct, False otherwise
****************************************************************************/

BOOL pass_check_smb(struct smb_passwd *smb_pass, char *domain, uchar *chal,
		uchar *lm_pwd, size_t lm_pwd_len,
		uchar *nt_pwd, size_t nt_pwd_len,
		struct passwd *pwd, uchar user_sess_key[16])
{
	const struct passwd *pass;
	struct passwd pw;
	char *user = NULL;

	if (smb_pass == NULL)
	{
		DEBUG(3,("Couldn't find user %s in smb_passwd file.\n", user));
		return False;
	}

	user = smb_pass->unix_name;

	if (lm_pwd == NULL || nt_pwd == NULL)
	{
		return False;
	}

	if (pwd != NULL && user == NULL)
	{
		pass = (struct passwd *) pwd;
		user = pass->pw_name;
	}
	else
	{
		pass = Get_Pwnam(user,True);
		if (pass == NULL)
		{
			DEBUG(3,("Couldn't find user %s\n",user));
			return False;
		}
		memcpy(&pw, pass, sizeof(struct passwd));
		pass = &pw;
	}

	/* Quit if the account was disabled. */
	if (smb_pass->acct_ctrl & ACB_DISABLED) {
		DEBUG(3,("account for user %s was disabled.\n", user));
		return False;
        }

	/* Ensure the uid's match */
	if (smb_pass->unix_uid != pass->pw_uid)
	{
		DEBUG(3,("Error : UNIX (%d) and SMB (%d) uids in password files do not match !\n", pass->pw_uid, smb_pass->unix_uid));
		return False;
	}

	if (lm_pwd[0] == '\0' && IS_BITS_SET_ALL(smb_pass->acct_ctrl, ACB_PWNOTREQ) && lp_null_passwords())
	{
		DEBUG(3,("account for user %s has no password and null passwords are allowed.\n", smb_pass->unix_name));
		return(True);
	}

	if (smb_password_ok(smb_pass, chal, user, domain,
	                                    lm_pwd, lm_pwd_len,
		                            nt_pwd, nt_pwd_len,
	                                    user_sess_key))
	{
		if (user_sess_key != NULL)
		{
#ifdef DEBUG_PASSWORD
		DEBUG(100,("user session key: "));
		dump_data(100, user_sess_key, 16);
#endif
		}
		return(True);
	}
	
	DEBUG(3,("Error pass_check_smb failed\n"));
	return False;
}

/****************************************************************************
check if a username/password pair is OK either via the system password
database or the encrypted SMB password database
return True if the password is correct, False otherwise
****************************************************************************/
BOOL password_ok(char *user, char *password, int pwlen, struct passwd *pwd,
		uchar user_sess_key[16])
{
	if (pwlen >= 24 || (lp_encrypted_passwords() && (pwlen == 0) && lp_null_passwords()))
	{
		/* if 24 bytes or longer assume it is an encrypted password */
		uchar challenge[8];

		if (!last_challenge(challenge))
		{
			DEBUG(0,("Error: challenge not done for user=%s\n", user));
			return False;
		}

		return pass_check_smb(getsmbpwnam(user), global_myworkgroup,
		                      challenge, (uchar *)password,
					pwlen, (uchar *)password, pwlen,
					pwd, user_sess_key);
	} 

	return pass_check(user, password, pwlen, pwd, 
			  lp_update_encrypted() ? 
			  update_smbpassword_file : NULL);
}

/****************************************************************************
check if a username is valid
****************************************************************************/
BOOL user_ok(char *user,int snum)
{
	pstring valid, invalid;
	BOOL ret;

	StrnCpy(valid, lp_valid_users(snum), sizeof(pstring));
	StrnCpy(invalid, lp_invalid_users(snum), sizeof(pstring));

	string_sub(valid,"%S",lp_servicename(snum));
	string_sub(invalid,"%S",lp_servicename(snum));
	
	ret = !user_in_list(user,invalid);
	
	if (ret && valid && *valid) {
		ret = user_in_list(user,valid);
	}

	if (ret && lp_onlyuser(snum)) {
		char *user_list = lp_username(snum);
		string_sub(user_list,"%S",lp_servicename(snum));
		ret = user_in_list(user,user_list);
	}

	return(ret);
}




/****************************************************************************
validate a group username entry. Return the username or NULL
****************************************************************************/
static char *validate_group(char *group,char *password,int pwlen,int snum,
				uchar user_sess_key[16])
{
#if defined(HAVE_NETGROUP) && defined(HAVE_GETNETGRENT) && defined(HAVE_SETNETGRENT) && defined(HAVE_ENDNETGRENT)
  {
    char *host, *user, *domain;
    setnetgrent(group);
    while (getnetgrent(&host, &user, &domain)) {
      if (user) {
	if (user_ok(user, snum) && 
	    password_ok(user,password,pwlen,NULL, user_sess_key)) {
	  endnetgrent();
	  return(user);
	}
      }
    }
    endnetgrent();
  }
#endif
  
#ifdef HAVE_GETGRNAM 
  {
    struct group *gptr = (struct group *)getgrnam(group);
    char **member;
    if (gptr)
      {
	member = gptr->gr_mem;
	while (member && *member)
	  {
	    static fstring name;
	    fstrcpy(name,*member);
	    if (user_ok(name,snum) &&
		password_ok(name,password,pwlen,NULL, user_sess_key))
	      return(&name[0]);
	    member++;
	  }
#ifdef GROUP_CHECK_PWENT
	{
	  struct passwd *pwd;
	  static fstring tm;
	  
	  setpwent ();
	  while (pwd = getpwent ()) {
	    if (*(pwd->pw_passwd) && pwd->pw_gid == gptr->gr_gid) {
	      /* This Entry have PASSWORD and same GID then check pwd */
	      if (password_ok(NULL, password, pwlen, pwd, user_sess_key)) {
		fstrcpy(tm, pwd->pw_name);
		endpwent ();
		return tm;
	      }
	    }
	  }
	  endpwent ();
	}
#endif /* GROUP_CHECK_PWENT */
      }
  }      
#endif
  return(NULL);
}



/****************************************************************************
check for authority to login to a service with a given username/password
****************************************************************************/
BOOL authorise_login(int snum,char *user,char *password, int pwlen, 
		     BOOL *guest,BOOL *force,uint16 vuid)
{
  BOOL ok = False;
  
  *guest = False;
  
#if DEBUG_PASSWORD
  DEBUG(100,("checking authorisation on user=%s pass=%s\n",user,password));
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

      user_struct *vuser = get_valid_user_struct(vuid);

      /* check the given username and password */
      if (!ok && (*user) && user_ok(user,snum)) {
	ok = password_ok(user,password, pwlen, NULL, vuser->dc.user_sess_key);
	if (ok) DEBUG(3,("ACCEPTED: given username password ok\n"));
      }

      /* check for a previously registered guest username */
      if (!ok && (vuser != 0) && vuser->guest) {	  
	if (user_ok(vuser->name,snum) &&
	    password_ok(vuser->name, password, pwlen, NULL, vuser->dc.user_sess_key)) {
	  fstrcpy(user, vuser->name);
	  vuser->guest = False;
	  DEBUG(3,("ACCEPTED: given password with registered user %s\n", user));
	  ok = True;
	}
      }


      /* now check the list of session users */
    if (!ok)
    {
      char *auser;
      char *user_list = strdup(session_users);
      if (!user_list) return False;

      for (auser=strtok(user_list,LIST_SEP); 
           !ok && auser; 
           auser = strtok(NULL,LIST_SEP))
      {
        fstring user2;
        fstrcpy(user2,auser);
        if (!user_ok(user2,snum)) continue;
		  
        if (password_ok(user2,password, pwlen, NULL, vuser->dc.user_sess_key)) {
          ok = True;
          fstrcpy(user,user2);
          DEBUG(3,("ACCEPTED: session list username and given password ok\n"));
        }
      }
      free(user_list);
    }

    /* check for a previously validated username/password pair */
    if (!ok && (!lp_revalidate(snum) || lp_security() > SEC_SHARE) &&
        (vuser != 0) && !vuser->guest &&
        user_ok(vuser->name,snum)) {
      fstrcpy(user,vuser->name);
      *guest = False;
      DEBUG(3,("ACCEPTED: validated uid ok as non-guest\n"));
      ok = True;
    }

      /* check for a rhosts entry */
      if (!ok && user_ok(user,snum) && check_hosts_equiv(user)) {
	ok = True;
	DEBUG(3,("ACCEPTED: hosts equiv or rhosts entry\n"));
      }

      /* check the user= fields and the given password */
      if (!ok && lp_username(snum)) {
	char *auser;
	pstring user_list;
	StrnCpy(user_list,lp_username(snum),sizeof(pstring));

	string_sub(user_list,"%S",lp_servicename(snum));
	  
	for (auser=strtok(user_list,LIST_SEP);
	     auser && !ok;
	     auser = strtok(NULL,LIST_SEP))
	  {
	    if (*auser == '@')
	      {
		auser = validate_group(auser+1,password,pwlen,snum, vuser->dc.user_sess_key);
		if (auser)
		  {
		    ok = True;
		    fstrcpy(user,auser);
		    DEBUG(3,("ACCEPTED: group username and given password ok\n"));
		  }
	      }
	    else
	      {
		fstring user2;
		fstrcpy(user2,auser);
		if (user_ok(user2,snum) && 
		    password_ok(user2,password,pwlen,NULL, vuser->dc.user_sess_key))
		  {
		    ok = True;
		    fstrcpy(user,user2);
		    DEBUG(3,("ACCEPTED: user list username and given password ok\n"));
		  }
	      }
	  }
      }      
    } /* not guest only */

  /* check for a normal guest connection */
  if (!ok && GUEST_OK(snum))
    {
      fstring guestname;
      StrnCpy(guestname,lp_guestaccount(snum),sizeof(guestname)-1);
      if (Get_Pwnam(guestname,True))
	{
	  fstrcpy(user,guestname);
	  ok = True;
	  DEBUG(3,("ACCEPTED: guest account and guest ok\n"));
	}
      else
	DEBUG(0,("Invalid guest account %s??\n",guestname));
      *guest = True;
      *force = True;
    }

  if (ok && !user_ok(user,snum))
    {
      DEBUG(0,("rejected invalid user %s\n",user));
      ok = False;
    }

  return(ok);
}


/****************************************************************************
read the a hosts.equiv or .rhosts file and check if it
allows this user from this machine
****************************************************************************/
static BOOL check_user_equiv(char *user, char *remote, char *equiv_file)
{
  pstring buf;
  int plus_allowed = 1;
  char *file_host;
  char *file_user;
  FILE *fp = sys_fopen(equiv_file, "r");
  DEBUG(5, ("check_user_equiv %s %s %s\n", user, remote, equiv_file));
  if (! fp) return False;
  while(fgets(buf, sizeof(buf), fp)) 
  {
    trim_string(buf," "," ");

    if (buf[0] != '#' && buf[0] != '\n') 
    {
      BOOL is_group = False;
      int plus = 1;
      char *bp = buf;
      if (strcmp(buf, "NO_PLUS\n") == 0)
      {
	DEBUG(6, ("check_user_equiv NO_PLUS\n"));
	plus_allowed = 0;
      }
      else {
	if (buf[0] == '+') 
	{
	  bp++;
	  if (*bp == '\n' && plus_allowed) 
	  {
	    /* a bare plus means everbody allowed */
	    DEBUG(6, ("check_user_equiv everybody allowed\n"));
	    fclose(fp);
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
	DEBUG(7, ("check_user_equiv %s %s\n", file_host ? file_host : "(null)", 
                 file_user ? file_user : "(null)" ));
	if (file_host && *file_host) 
	{
	  BOOL host_ok = False;

#if defined(HAVE_NETGROUP) && defined(HAVE_YP_GET_DEFAULT_DOMAIN)
	  if (is_group)
	    {
	      static char *mydomain = NULL;
	      if (!mydomain)
		yp_get_default_domain(&mydomain);
	      if (mydomain && innetgr(file_host,remote,user,mydomain))
		host_ok = True;
	    }
#else
	  if (is_group)
	    {
	      DEBUG(1,("Netgroups not configured\n"));
	      continue;
	    }
#endif

	  /* is it this host */
	  /* the fact that remote has come from a call of gethostbyaddr
	   * means that it may have the fully qualified domain name
	   * so we could look up the file version to get it into
	   * a canonical form, but I would rather just type it
	   * in full in the equiv file
	   */
	  if (!host_ok && !is_group && strequal(remote, file_host))
	    host_ok = True;

	  if (!host_ok)
	    continue;

	  /* is it this user */
	  if (file_user == 0 || strequal(user, file_user)) 
	    {
	      fclose(fp);
	      DEBUG(5, ("check_user_equiv matched %s%s %s\n",
			(plus ? "+" : "-"), file_host,
			(file_user ? file_user : "")));
	      return (plus ? True : False);
	    }
	}
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
  const struct passwd *pass = Get_Pwnam(user,True);

  if (!pass) 
    return False;

  fname = lp_hosts_equiv();

  /* note: don't allow hosts.equiv on root */
  if (fname && *fname && (pass->pw_uid != 0)) {
	  extern int Client;
	  if (check_user_equiv(user,client_name(Client),fname))
		  return(True);
  }
  
  if (lp_use_rhosts())
    {
      char *home = get_home_dir(user);
      if (home) {
	      extern int Client;
	      slprintf(rhostsfile, sizeof(rhostsfile)-1, "%s/.rhosts", home);
	      if (check_user_equiv(user,client_name(Client),rhostsfile))
		      return(True);
      }
    }

  return False;
}


/****************************************************************************
return the client state structure
****************************************************************************/
struct cli_state *server_client(void)
{
	static struct cli_state pw_cli;
	return &pw_cli;
}

/****************************************************************************
support for server level security 
****************************************************************************/
struct cli_state *server_cryptkey(void)
{
	if (cli_connect_serverlist(server_client(), lp_passwordserver()))
	{
		return server_client();
	}
	return NULL;
}

/****************************************************************************
validate a password with the password server
****************************************************************************/
BOOL server_validate(char *user, char *domain, 
		     char *pass, int passlen,
		     char *ntpass, int ntpasslen)
{
  struct cli_state *cli;
  static unsigned char badpass[24];
  static BOOL tested_password_server = False;
  static BOOL bad_password_server = False;

  cli = server_client();

  if (!cli->initialised) {
    DEBUG(1,("password server %s is not connected\n", cli->desthost));
    return False;
  }  

  if(badpass[0] == 0)
    memset(badpass, 0x1f, sizeof(badpass));

  if((passlen == sizeof(badpass)) && !memcmp(badpass, pass, passlen)) {
    /* 
     * Very unlikely, our random bad password is the same as the users
     * password. */
    memset(badpass, badpass[0]+1, sizeof(badpass));
  }

  /*
   * Attempt a session setup with a totally incorrect password.
   * If this succeeds with the guest bit *NOT* set then the password
   * server is broken and is not correctly setting the guest bit. We
   * need to detect this as some versions of NT4.x are broken. JRA.
   */

  if(!tested_password_server) {
    if (cli_session_setup(cli, global_myname,
	                       user, (char *)badpass, sizeof(badpass), 
                              (char *)badpass, sizeof(badpass), domain)) {

      /*
       * We connected to the password server so we
       * can say we've tested it.
       */
      tested_password_server = True;

      if ((SVAL(cli->inbuf,smb_vwv2) & 1) == 0) {
        DEBUG(0,("server_validate: password server %s allows users as non-guest \
with a bad password.\n", cli->desthost));
        DEBUG(0,("server_validate: This is broken (and insecure) behaviour. Please do not \
use this machine as the password server.\n"));
        cli_ulogoff(cli);

        /*
         * Password server has the bug.
         */
        bad_password_server = True;
        return False;
      }
      cli_ulogoff(cli);
    }
  } else {

    /*
     * We have already tested the password server.
     * Fail immediately if it has the bug.
     */

    if(bad_password_server) {
      DEBUG(0,("server_validate: [1] password server %s allows users as non-guest \
with a bad password.\n", cli->desthost));
      DEBUG(0,("server_validate: [1] This is broken (and insecure) behaviour. Please do not \
use this machine as the password server.\n"));
      return False;
    }
  }

  /*
   * Now we know the password server will correctly set the guest bit, or is
   * not guest enabled, we can try with the real password.
   */

  if (!cli_session_setup(cli, global_myname,
	                       user, pass, passlen, ntpass, ntpasslen, domain)) {
    DEBUG(1,("password server %s rejected the password\n", cli->desthost));
    return False;
  }

  /* if logged in as guest then reject */
  if ((SVAL(cli->inbuf,smb_vwv2) & 1) != 0) {
    DEBUG(1,("password server %s gave us guest only\n", cli->desthost));
    cli_ulogoff(cli);
    return False;
  }


  cli_ulogoff(cli);

  return(True);
}

/***********************************************************************
 Do the same as security=server, but using NT Domain calls and a session
 key from the workstation trust account password.
************************************************************************/

BOOL domain_client_validate( char *user, char *domain, char *server_list,
				char *acct_name, uint16 acct_type,
				char *smb_apasswd, int smb_apasslen, 
				char *smb_ntpasswd, int smb_ntpasslen,
				uchar user_sess_key[16])
{
	unsigned char local_challenge[8];
	unsigned char local_lm_response[24];
	unsigned char local_nt_reponse[24];
	unsigned char trust_passwd[16];
	NET_ID_INFO_CTR ctr;
	NET_USER_INFO_3 info3;
	uint32 smb_uid_low;
	fstring trust_acct;
	fstring srv_name;

	fstrcpy(trust_acct, acct_name);
	fstrcat(trust_acct, "$");

	/* 
	* Check that the requested domain is not our own machine name.
	* If it is, we should never check the PDC here, we use our own local
	* password file.
	*/

	if(strequal( domain, global_myname))
	{
		DEBUG(3,("domain_client_validate: Requested domain was for this machine.\n"));
		return False;
	}

	/*
	* Next, check that the passwords given were encrypted.
	*/

	if(((smb_apasslen  != 24) && (smb_apasslen  != 0)) || 
	   ((smb_ntpasslen <= 24) && (smb_ntpasslen != 0)))
	{
		/*
		 * Not encrypted - do so.
		 */

		DEBUG(3,("domain_client_validate: User passwords not in encrypted format.\n"));
		generate_random_buffer( local_challenge, 8, False);
		SMBencrypt( (uchar *)smb_apasswd, local_challenge, local_lm_response);
		SMBNTencrypt((uchar *)smb_ntpasswd, local_challenge, local_nt_reponse);
		smb_apasslen = 24;
		smb_ntpasslen = 24;
		smb_apasswd = (char *)local_lm_response;
		smb_ntpasswd = (char *)local_nt_reponse;
	}
	else
	{
		/*
		 * Encrypted - get the challenge we sent for these
		 * responses.
		 */

		if (!last_challenge(local_challenge))
		{
			DEBUG(0,("domain_client_validate: no challenge done - password failed\n"));
			return False;
		}
	}

	/*
	 * Get the workstation trust account password.
	 */
	if (!trust_get_passwd( trust_passwd, domain, acct_name))
	{
		return False;
	}

	/*
	 * At this point, smb_apasswd points to the lanman response to
	 * the challenge in local_challenge, and smb_ntpasswd points to
	 * the NT response to the challenge in local_challenge. Ship
	 * these over the secure channel to a domain controller and
	 * see if they were valid.
	 */

	/*
	* Ok - we have an anonymous connection to the IPC$ share.
	* Now start the NT Domain stuff :-).
	*/

	if(cli_nt_setup_creds(server_list, global_myname, trust_acct,
	                      trust_passwd, acct_type, srv_name) != 0x0)
	{
		DEBUG(0,("domain_client_validate: unable to setup the PDC credentials to machine \
		%s.\n", srv_name));
		return False;
	}

	/* We really don't care what LUID we give the user. */
	generate_random_buffer( (unsigned char *)&smb_uid_low, 4, False);

	if (!cli_nt_login_network(srv_name, global_myname, 
	                domain, user,
	               smb_uid_low, (char *)local_challenge,
			((smb_apasslen != 0) ? smb_apasswd : NULL),
			((smb_ntpasslen != 0) ? smb_ntpasswd : NULL),
			&ctr, &info3))
	{
		DEBUG(0,("domain_client_validate: unable to validate password for user %s in domain \
		%s to Domain controller %s.\n", user, domain, srv_name));
		return False;
	}

	/*
	 * Here, if we really want it, we have lots of info about the user in info3.
	 * LKCLXXXX - really important to check things like "is this user acct
	 * locked out / disabled" etc!!!!
	 */

	return True;
}
