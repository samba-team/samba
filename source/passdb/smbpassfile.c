/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

extern int DEBUGLEVEL;

BOOL global_machine_password_needs_changing = False;
static int mach_passwd_lock_depth = 0;
static FILE *mach_passwd_fp = NULL;

/************************************************************************
 Routine to get the name for a trust account file.
************************************************************************/

static void get_trust_account_file_name( const char *domain, const char *name,
				char *mac_file)
{
  unsigned int mac_file_len;
  char *p;
  fstring dom_name;
  fstring trust_name;

  pstrcpy(mac_file, lp_smb_passwd_file());
  p = strrchr(mac_file, '/');
  if(p != NULL)
    *++p = '\0';

  mac_file_len = strlen(mac_file);

  if ((int)(sizeof(pstring) - mac_file_len - strlen(domain) - strlen(name) - 6) < 0)
  {
    DEBUG(0,("get_trust_account_file_name: path %s too long to add trust details.\n",
              mac_file));
    return;
  }

	fstrcpy(dom_name, domain);
	strupper(dom_name);
	fstrcpy(trust_name, name);
	strupper(trust_name);

  pstrcat(mac_file, dom_name);
  pstrcat(mac_file, ".");
  pstrcat(mac_file, trust_name);
  pstrcat(mac_file, ".mac");

  DEBUG(5,("trust_account_file_name: %s\n", mac_file));
}
 
/************************************************************************
 Routine to lock the trust account password file for a domain.
************************************************************************/

BOOL trust_password_lock( const char *domain, const char *name, BOOL update)
{
  pstring mac_file;

  if(mach_passwd_lock_depth == 0) {

    get_trust_account_file_name( domain, name, mac_file);

    if((mach_passwd_fp = sys_fopen(mac_file, "r+b")) == NULL) {
      if(errno == ENOENT && update) {
        mach_passwd_fp = sys_fopen(mac_file, "w+b");
      }

      if(mach_passwd_fp == NULL) {
        DEBUG(0,("trust_password_lock: cannot open file %s - Error was %s.\n",
              mac_file, strerror(errno) ));
        return False;
      }
    }

    chmod(mac_file, 0600);

    if(!file_lock(fileno(mach_passwd_fp), (update ? F_WRLCK : F_RDLCK), 
                                      60, &mach_passwd_lock_depth))
    {
      DEBUG(0,("trust_password_lock: cannot lock file %s\n", mac_file));
      fclose(mach_passwd_fp);
      return False;
    }

  }

  return True;
}

/************************************************************************
 Routine to unlock the trust account password file for a domain.
************************************************************************/

BOOL trust_password_unlock(void)
{
  BOOL ret = file_unlock(fileno(mach_passwd_fp), &mach_passwd_lock_depth);
  if(mach_passwd_lock_depth == 0)
    fclose(mach_passwd_fp);
  return ret;
}

/************************************************************************
 Routine to delete the trust account password file for a domain.
************************************************************************/

BOOL trust_password_delete( char *domain, char *name )
{
  pstring mac_file;

  get_trust_account_file_name( domain, name, mac_file);
  return (unlink( mac_file ) == 0);
}

/************************************************************************
 Routine to get the trust account password for a domain.
 The user of this function must have locked the trust password file.
************************************************************************/

BOOL get_trust_account_password( uchar *ret_pwd, time_t *pass_last_set_time)
{
  char linebuf[256];

  linebuf[0] = '\0';

  *pass_last_set_time = (time_t)0;
  memset(ret_pwd, '\0', 16);

  if(sys_fseek( mach_passwd_fp, (SMB_OFF_T)0, SEEK_SET) == -1) {
    DEBUG(0,("get_trust_account_password: Failed to seek to start of file. Error was %s.\n",
              strerror(errno) ));
    return False;
  } 

  fgets(linebuf, sizeof(linebuf), mach_passwd_fp);
  if(ferror(mach_passwd_fp)) {
    DEBUG(0,("get_trust_account_password: Failed to read password. Error was %s.\n",
              strerror(errno) ));
    return False;
  }

  if(linebuf[strlen(linebuf)-1] == '\n')
    linebuf[strlen(linebuf)-1] = '\0';

  /*
   * The length of the line read
   * must be 45 bytes ( <---XXXX 32 bytes-->:TLC-12345678
   */

  if(strlen(linebuf) != 45) {
    DEBUG(0,("get_trust_account_password: Malformed trust password file (wrong length \
- was %d, should be 45).\n", strlen(linebuf)));
#ifdef DEBUG_PASSWORD
    DEBUG(100,("get_trust_account_password: line = |%s|\n", linebuf));
#endif
    return False;
  }

  /*
   * Get the hex password.
   */

  if (!pwdb_gethexpwd((char *)linebuf, (char *)ret_pwd, NULL) ||
       linebuf[32] != ':')
         {
    DEBUG(0,("get_trust_account_password: Malformed trust password file (incorrect format).\n"));
#ifdef DEBUG_PASSWORD
    DEBUG(100,("get_trust_account_password: line = |%s|\n", linebuf));
#endif
    return False;
  }

#ifdef DEBUG_PASSWORD
      DEBUG(100,("get_trust_account_password:"));
      dump_data(100, ret_pwd, 16);
#endif
  /*
   * Get the last changed time.
   */

  (*pass_last_set_time) = pwdb_get_time_last_changed(&linebuf[33]);

  if ((*pass_last_set_time) == -1)
  {
      DEBUG(0,("get_trust_account_password: Malformed trust password file (no timestamp).\n"));
#ifdef DEBUG_PASSWORD
      DEBUG(100,("get_trust_account_password: line = |%s|\n", linebuf));
#endif
      return False;
  }

  return True;
}

/************************************************************************
 Routine to get the trust account password for a domain.
 The user of this function must have locked the trust password file.
************************************************************************/

BOOL set_trust_account_password( uchar *md4_new_pwd)
{
  char linebuf[64];

  if(sys_fseek( mach_passwd_fp, (SMB_OFF_T)0, SEEK_SET) == -1) {
    DEBUG(0,("set_trust_account_password: Failed to seek to start of file. Error was %s.\n",
              strerror(errno) ));
    return False;
  } 

  pwdb_sethexpwd((char *)linebuf, (uchar*)md4_new_pwd, 0);
  pwdb_set_time_last_changed(&linebuf[32], 32, (unsigned)time(NULL));
  linebuf[45] = '\n';

  if(fwrite( linebuf, 1, 46, mach_passwd_fp)!= 46) {
    DEBUG(0,("set_trust_account_password: Failed to write file. Warning - the trust \
account is now invalid. Please recreate. Error was %s.\n", strerror(errno) ));
    return False;
  }

  fflush(mach_passwd_fp);
  return True;
}

BOOL trust_get_passwd( uchar trust_passwd[16],
				const char *domain, const char *myname)
{
  time_t lct;

  /*
   * Get the trust account password.
   */
  if(!trust_password_lock( domain, myname, False)) {
    DEBUG(0,("trust_get_passwd: unable to open the trust account password file for \
trust %s in domain %s.\n", myname, domain ));
    return False;
  }

  if(get_trust_account_password( trust_passwd, &lct) == False) {
    DEBUG(0,("trust_get_passwd: unable to read the trust account password for \
trust %s in domain %s.\n", myname, domain ));
    trust_password_unlock();
    return False;
  }

  trust_password_unlock();

  /* 
   * Here we check the last change time to see if the trust
   * password needs changing. JRA. 
   */

  if(time(NULL) > lct + lp_machine_password_timeout())
  {
    global_machine_password_needs_changing = True;
  }
  return True;
}

/*********************************************************
record Trust Account password.
**********************************************************/
BOOL create_trust_account_file(char *domain, char *name, uchar pass[16])
{
	/*
	 * Create the machine account password file.
	 */

	if (!trust_password_lock( domain, name, True))
	{
		DEBUG(0,("unable to open the trust account password file for \
account %s in domain %s.\n", name, domain)); 
		return False;
	}

	/*
	 * Write the old machine account password.
	 */
	
	if (!set_trust_account_password( pass))
	{              
		DEBUG(0,("unable to write the trust account password for \
%s in domain %s.\n", name, domain));
		trust_password_unlock();
		return False;
	}
	
	trust_password_unlock();
	
	return True;
}
