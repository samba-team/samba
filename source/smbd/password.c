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
	UNISTR2 newpw;
	BOOL ret;
	
	become_root(0);
	smbpw = getsmbpwnam(user);
	unbecome_root(0);

	make_unistr2(&newpw, password, password != NULL ? strlen(password) : 0);

	if(smbpw == NULL)
	{
		DEBUG(0,("getsmbpwnam returned NULL\n"));
		return False;
	}
 
	/* Here, the flag is one, because we want to ignore the
           XXXXXXX'd out password */
	ret = change_oem_password( smbpw, &newpw, True);
	if (!ret)
	{
		DEBUG(3,("change_oem_password returned False\n"));
	}

	return ret;
}





/****************************************************************************
check if a username/password pair is OK either via the system password
database or the encrypted SMB password database
return True if the password is correct, False otherwise
****************************************************************************/
BOOL password_ok(char *orig_user, char *domain,
				char *smb_apasswd, int smb_apasslen,
				char *smb_ntpasswd, int smb_ntpasslen,
				struct passwd *pwd,
				uchar user_sess_key[16])
{
	uchar last_chal[8];

	/*
	 * SMB password check
	 */

	if ((smb_apasslen != 0 && smb_ntpasslen != 0) ||
	    (lp_encrypted_passwords() && smb_apasslen == 0 &&
	     lp_null_passwords()))
	{
		/* check security = server */
		if (check_server_security(orig_user, domain,
					  smb_apasswd, smb_apasslen,
					  smb_ntpasswd, smb_ntpasslen))
		{
			DEBUG(10,("password_ok: server auth succeeded\n"));
			return True;
		}

		/* check security = user / domain */
		if (last_challenge(last_chal) &&
		    check_domain_security(orig_user, domain,
					  last_chal,
					  smb_apasswd, smb_apasslen,
					  smb_ntpasswd, smb_ntpasslen,
					  user_sess_key))
		{
			DEBUG(10,("password_ok: domain auth succeeded\n"));
			return True;
		}
	}

	DEBUG(10,("password_ok: check Unix auth\n"));
	/*
	 * unix password check
	 */
	if (pass_check(orig_user, smb_apasswd, smb_apasslen, pwd, 
			  lp_update_encrypted() ? 
			  update_smbpassword_file : NULL))
	{
		DEBUG(10,("password_ok: Unix auth succeeded\n"));
		return True;
	}
	return False;
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
	    password_ok(user,NULL,password,pwlen,NULL,0,NULL,user_sess_key))
	{
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
	password_ok(name,NULL,password,pwlen,NULL,0,NULL, user_sess_key))
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
	      if (password_ok(NULL, NULL, password, pwlen, NULL, 0, pwd, user_sess_key)) {
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
BOOL authorise_login(int snum,char *user, char *domain,
				char *password, int pwlen, 
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
	ok = password_ok(user,domain, password, pwlen, NULL, 0, NULL, vuser->user_sess_key);
	if (ok) DEBUG(3,("ACCEPTED: given username password ok\n"));
      }

      /* check for a previously registered guest username */
      if (!ok && (vuser != 0) && vuser->guest) {	  
	if (user_ok(vuser->name,snum) &&
	    password_ok(vuser->name, domain, password, pwlen, NULL, 0, NULL, vuser->user_sess_key)) {
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
		  
        if (password_ok(user2, domain, password, pwlen, NULL, 0, NULL,
                        vuser->user_sess_key))
        {
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
		auser = validate_group(auser+1,password,pwlen,snum, vuser->user_sess_key);
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
		    password_ok(user2,domain,password,pwlen,NULL, 0,
		                NULL, vuser->user_sess_key))
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
      char *home = get_unixhome_dir(user);
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
BOOL check_server_security(char *user, char *domain, 
		     char *pass, int passlen,
		     char *ntpass, int ntpasslen)
{
  struct cli_state *cli;
  static unsigned char badpass[24];
  static BOOL tested_password_server = False;
  static BOOL bad_password_server = False;

  if(lp_security() != SEC_SERVER)
    return False;

  DEBUG(10,("check_server_security\n"));

  cli = server_client();

  if (!cli->initialised)
  {
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

