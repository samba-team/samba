/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Main SMB reply routines
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
 Read the a hosts.equiv or .rhosts file and check if it
 allows this user from this machine.
****************************************************************************/

static BOOL check_user_equiv(const char *user, const char *remote, const char *equiv_file)
{
  int plus_allowed = 1;
  char *file_host;
  char *file_user;
  char **lines = file_lines_load(equiv_file, NULL);
  int i;

  DEBUG(5, ("check_user_equiv %s %s %s\n", user, remote, equiv_file));
  if (! lines) return False;
  for (i=0; lines[i]; i++) {
    char *buf = lines[i];
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
	    file_lines_free(lines);
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
	      DEBUG(5, ("check_user_equiv matched %s%s %s\n",
			(plus ? "+" : "-"), file_host,
			(file_user ? file_user : "")));
	      file_lines_free(lines);
	      return (plus ? True : False);
	    }
	}
      }
    }
  }
  file_lines_free(lines);
  return False;
}


/****************************************************************************
check for a possible hosts equiv or rhosts entry for the user
****************************************************************************/

static BOOL check_hosts_equiv(struct passwd *pass)
{
  char *fname = NULL;

  if (!pass) 
    return(False);

  fname = lp_hosts_equiv();

  /* note: don't allow hosts.equiv on root */
  if (fname && *fname && (pass->pw_uid != 0)) {
	  if (check_user_equiv(pass->pw_name,client_name(),fname))
		  return(True);
  }
  
  return(False);
}


/****************************************************************************
 Check for a valid .rhosts/hosts.equiv entry for this user
****************************************************************************/

static NTSTATUS check_hostsequiv_security(void *my_private_data, 
					  const auth_usersupplied_info *user_info, 
					  const auth_authsupplied_info *auth_info,
					  auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	struct passwd *pass = Get_Pwnam(user_info->internal_username.str);
	
	if (pass) {
		if (check_hosts_equiv(pass)) {
			nt_status = NT_STATUS_OK;
			make_server_info_pw(server_info, pass);
		}
	} else {
		nt_status = NT_STATUS_NO_SUCH_USER;
	}

	return nt_status;
}


/****************************************************************************
 Check for a valid .rhosts/hosts.equiv entry for this user
****************************************************************************/

static NTSTATUS check_rhosts_security(void *my_private_data, 
				      const auth_usersupplied_info *user_info, 
				      const auth_authsupplied_info *auth_info,
				      auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	struct passwd *pass = Get_Pwnam(user_info->internal_username.str);
	pstring rhostsfile;
	
	if (pass) {
		char *home = pass->pw_dir;
		if (home) {
			slprintf(rhostsfile, sizeof(rhostsfile)-1, "%s/.rhosts", home);
			become_root();
			if (check_user_equiv(pass->pw_name,client_name(),rhostsfile)) {
				nt_status = NT_STATUS_OK;
				make_server_info_pw(server_info, pass);
			}
			unbecome_root();
		} 
	} else {
		nt_status = NT_STATUS_NO_SUCH_USER;
	}

	return nt_status;
}

BOOL auth_init_hostsequiv(auth_methods **auth_method) 
{

	if (!make_auth_methods(auth_method)) {
		return False;
	}
	(*auth_method)->auth = check_hostsequiv_security;
	return True;
}

BOOL auth_init_rhosts(auth_methods **auth_method) 
{

	if (!make_auth_methods(auth_method)) {
		return False;
	}
	(*auth_method)->auth = check_rhosts_security;
	return True;
}
