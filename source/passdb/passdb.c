/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   
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
#include "nterr.h"

extern int DEBUGLEVEL;

/*
 * This is set on startup - it defines the SID for this
 * machine.
 */
DOM_SID global_machine_sid;

/**********************************************************
 **********************************************************

 low-level redirection routines:

	startsampwent()
	endsampwent()
	getsampwent()
	getsam21pwent()
	getsampwpos()
	setsampwpos()

	add_sampwd_entry()
	mod_sampwd_entry()
	add_sam21pwd_entry()
	mod_sam21pwd_entry()

 **********************************************************
 **********************************************************/

/***************************************************************
 Start to enumerate the sam passwd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/
void *startsampwent(BOOL update)
{
#ifdef USE_NISPLUS_DB
  return startnisppwent(update);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
  return startldappwent(update);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
  return startsmbpwent(update);
#endif /* USE_SMBPASS_DB */
}

/***************************************************************
 End enumeration of the sam passwd list.
****************************************************************/
void endsampwent(void *vp)
{
#ifdef USE_NISPLUS_DB
  endnisppwent(vp);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
  endldappwent(vp);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
  endsmbpwent(vp);
#endif /* USE_SMBPASS_DB */
}

/*************************************************************************
 Routine to return the next entry in the sam passwd list.
 *************************************************************************/
struct smb_passwd *getsampwent(void *vp)
{
#ifdef USE_NISPLUS_DB
  return getnisppwent(vp);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
  return getldappwent(vp);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
  return getsmbpwent(vp);
#endif /* USE_SMBPASS_DB */
}

/*************************************************************************
 Routine to return the next entry in the sam passwd list.
 *************************************************************************/
struct sam_disp_info *getsamdispent(void *vp)
{
	struct sam_passwd *pwd = NULL;
	static struct sam_disp_info disp_info;

#ifdef USE_NISPLUS_DB
	pwd = getnisp21pwent(vp);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
	pwd = getldap21pwent(vp);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
	pwd = getsmb21pwent(vp);
#endif /* USE_SMBPASS_DB */

	if (pwd == NULL) return NULL;

	disp_info.smb_name  = pwd->smb_name;
	disp_info.full_name = pwd->full_name;
	disp_info.user_rid  = pwd->user_rid;

	return &disp_info;
}

/*************************************************************************
 Routine to return the next entry in the sam passwd list.
 *************************************************************************/
struct sam_passwd *getsam21pwent(void *vp)
{
#ifdef USE_NISPLUS_DB
  return getnisp21pwent(vp);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
  return getldap21pwent(vp);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
  return getsmb21pwent(vp);
#endif /* USE_SMBPASS_DB */
}

/*************************************************************************
 Return the current position in the sam passwd list as an unsigned long.
 This must be treated as an opaque token.
 *************************************************************************/
unsigned long getsampwpos(void *vp)
{
#ifdef USE_NISPLUS_DB
  return getnisppwpos(vp);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
  return getldappwpos(vp);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
  return getsmbpwpos(vp);
#endif /* USE_SMBPASS_DB */
}

/*************************************************************************
 Set the current position in the sam passwd list from unsigned long.
 This must be treated as an opaque token.
 *************************************************************************/
BOOL setsampwpos(void *vp, unsigned long tok)
{
#ifdef USE_NISPLUS_DB
  return setnisppwpos(vp, tok);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
  return setldappwpos(vp, tok);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
  return setsmbpwpos(vp, tok);
#endif /* USE_SMBPASS_DB */
}

/************************************************************************
 Routine to add an entry to the sam passwd file.
*************************************************************************/
BOOL add_sampwd_entry(struct smb_passwd *newpwd)
{
#ifdef USE_NISPLUS_DB
  return add_nisppwd_entry(newpwd);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
  return add_ldappwd_entry(newpwd);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
  return add_smbpwd_entry(newpwd);
#endif /* USE_SMBPASS_DB */
}

/************************************************************************
 Routine to add an entry to the sam passwd file.
*************************************************************************/
BOOL add_sam21pwd_entry(struct sam_passwd *newpwd)
{
#ifdef USE_NISPLUS_DB
  return add_nisp21pwd_entry(newpwd);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
  return add_ldap21pwd_entry(newpwd);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
  return add_smb21pwd_entry(newpwd);
#endif /* USE_SMBPASS_DB */
}

/************************************************************************
 Routine to search the sam passwd file for an entry matching the username.
 and then modify its password entry. We can't use the startsampwent()/
 getsampwent()/endsampwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
 override = False, normal
 override = True, override XXXXXXXX'd out password or NO PASS
************************************************************************/
BOOL mod_sampwd_entry(struct smb_passwd* pwd, BOOL override)
{
#ifdef USE_NISPLUS_DB
  return mod_nisppwd_entry(pwd, override);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
  return mod_ldappwd_entry(pwd, override);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
  return mod_smbpwd_entry(pwd, override);
#endif /* USE_SMBPASS_DB */
}

/************************************************************************
 Routine to search the sam passwd file for an entry matching the username.
 and then modify its password entry. We can't use the startsampwent()/
 getsampwent()/endsampwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
 override = False, normal
 override = True, override XXXXXXXX'd out password or NO PASS
************************************************************************/
BOOL mod_sam21pwd_entry(struct sam_passwd* pwd, BOOL override)
{
#ifdef USE_NISPLUS_DB
  return mod_nisp21pwd_entry(pwd, override);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
  return mod_ldap21pwd_entry(pwd, override);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
  return mod_smb21pwd_entry(pwd, override);
#endif /* USE_SMBPASS_DB */
}

/**********************************************************
 **********************************************************

 high-level database routines:
 	getsampwnam()
 	getsampwuid()
 	getsam21pwnam()
 	getsam21pwuid()

 **********************************************************
 **********************************************************/

/************************************************************************
 Routine to search sam passwd by name.  use this if your database
 does not have search facilities.
*************************************************************************/
static struct smb_passwd *_getsampwnam(char *name)
{
	struct smb_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("getsampwnam: search by name: %s\n", name));

	/* Open the sam password file - not for update. */
	fp = startsampwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("getsampwnam: unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsampwent(fp)) != NULL && !strequal(pwd->smb_name, name));

	if (pwd != NULL)
	{
		DEBUG(10, ("getsampwnam: found by name: %s\n", name));
	}

	endsampwent(fp);
	return pwd;
}

/************************************************************************
 Routine to search sam passwd by name.
*************************************************************************/
struct smb_passwd *getsampwnam(char *name)
{
#ifdef USE_NISPLUS_DB
	return _getsampwnam(name);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
	return _getsampwnam(name);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
	return _getsampwnam(name);
#endif /* USE_SMBPASS_DB */
}

/************************************************************************
 Routine to search sam passwd by name.  use this if your database
 does not have search facilities.
*************************************************************************/
static struct sam_passwd *_getsam21pwnam(char *name)
{
	struct sam_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("_getsam21pwnam: search by name: %s\n", name));

	/* Open the sam password file - not for update. */
	fp = startsampwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("_getsam21pwnam: unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsam21pwent(fp)) != NULL && !strequal(pwd->smb_name, name));

	if (pwd != NULL)
	{
		DEBUG(10, ("_getsam21pwnam: found by name: %s\n", name));
	}

	endsampwent(fp);
	return pwd;
}

/************************************************************************
 Routine to search sam passwd by name.
*************************************************************************/
struct sam_passwd *getsam21pwnam(char *name)
{
#ifdef USE_NISPLUS_DB
	return _getsam21pwnam(name);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
	return _getsam21pwnam(name);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
	return _getsam21pwnam(name);
#endif /* USE_SMBPASS_DB */
}

/************************************************************************
 Routine to search sam passwd by uid.  use this if your database
 does not have search facilities.
*************************************************************************/
static struct smb_passwd *_getsampwuid(uid_t smb_userid)
{
	struct smb_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("getsampwuid: search by smb_userid: %x\n", smb_userid));

	/* Open the sam password file - not for update. */
	fp = startsampwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("getsampwuid: unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsampwent(fp)) != NULL && pwd->smb_userid != smb_userid);

	if (pwd != NULL)
	{
		DEBUG(10, ("getsampwuid: found by smb_userid: %x\n", smb_userid));
	}

	endsmbpwent(fp);
	return pwd;
}

/************************************************************************
 Routine to search sam passwd by uid.
*************************************************************************/
struct smb_passwd *getsampwuid(uid_t smb_userid)
{
#ifdef USE_NISPLUS_DB
	return _getsampwuid(smb_userid);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
	return _getsampwuid(smb_userid);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
	return _getsampwuid(smb_userid);
#endif /* USE_SMBPASS_DB */
}


/************************************************************************
 Routine to search sam passwd by rid.  use this if your database
 does not have search facilities.
*************************************************************************/
static struct sam_passwd *_getsam21pwrid(uint32 rid)
{
	struct sam_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("_getsam21pwrid: search by rid: %x\n", rid));

	/* Open the sam password file - not for update. */
	fp = startsampwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("_getsam21pwrid: unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsam21pwent(fp)) != NULL && pwd->user_rid != rid);

	if (pwd != NULL)
	{
		DEBUG(10, ("_getsam21pwrid: found by smb_userid: %x\n", rid));
	}

	endsmbpwent(fp);
	return pwd;
}

/************************************************************************
 Routine to search sam passwd by rid.  
*************************************************************************/
struct sam_passwd *getsam21pwrid(uint32 rid)
{
#ifdef USE_NISPLUS_DB
	return _getsam21pwrid(rid);
#endif /* USE_NISPLUS_DB */

#ifdef USE_LDAP_DB
	return _getsam21pwrid(rid);
#endif /* USE_LDAP_DB */

#ifdef USE_SMBPASS_DB
	return _getsam21pwrid(rid);
#endif /* USE_SMBPASS_DB */
}


/**********************************************************
 **********************************************************

 utility routines which are likely to be useful to all password
 databases

 **********************************************************
 **********************************************************/

/*************************************************************
 initialises a struct smb_passwd.
 **************************************************************/
void pdb_init_sam(struct smb_passwd *user)
{
	if (user == NULL) return;

	bzero(user, sizeof(*user));
	user->pass_last_set_time    = (time_t)-1;
}

/*************************************************************
 initialises a struct sam_passwd.
 **************************************************************/
void pdb_init_sam(struct sam_passwd *user)
{
	if (user == NULL) return;

	bzero(user, sizeof(*user));
	user->logon_time            = (time_t)-1;
	user->logoff_time           = (time_t)-1;
	user->kickoff_time          = (time_t)-1;
	user->pass_last_set_time    = (time_t)-1;
	user->pass_can_change_time  = (time_t)-1;
	user->pass_must_change_time = (time_t)-1;
}

/*************************************************************
 converts a sam_passwd structure to a smb_passwd structure.
 **************************************************************/
struct smb_passwd *pdb_sam_to_smb(struct sam_passwd *user)
{
	static struct smb_passwd pw_buf;

	if (user == NULL) return NULL;

	pdb_init_sam(&pw_buf);

	pw_buf.smb_userid         = user->smb_userid;
	pw_buf.smb_name           = user->smb_name;
	pw_buf.smb_passwd         = user->smb_passwd;
	pw_buf.smb_nt_passwd      = user->smb_nt_passwd;
	pw_buf.acct_ctrl          = user->acct_ctrl;
	pw_buf.pass_last_set_time = user->pass_last_set_time;

	return &pw_buf;
}

/*************************************************************
 converts a smb_passwd structure to a sam_passwd structure.
 **************************************************************/
struct sam_passwd *pdb_smb_to_sam(struct smb_passwd *user)
{
	static struct sam_passwd pw_buf;

	if (user == NULL) return NULL;

	pdb_init_smb(&pw_buf);

	pw_buf.smb_userid         = user->smb_userid;
	pw_buf.smb_name           = user->smb_name;
	pw_buf.smb_passwd         = user->smb_passwd;
	pw_buf.smb_nt_passwd      = user->smb_nt_passwd;
	pw_buf.acct_ctrl          = user->acct_ctrl;
	pw_buf.pass_last_set_time = user->pass_last_set_time;

	return &pw_buf;
}

/*******************************************************************
 gets password-database-format time from a string.
 ********************************************************************/
static time_t get_time_from_string(char *p)
{
	int i;

	for (i = 0; i < 8; i++)
	{
		if (p[i] == '\0' || !isxdigit(p[i]))
		break;
	}
	if (i == 8)
	{
		/*
		 * p points at 8 characters of hex digits - 
		 * read into a time_t as the seconds since
		 * 1970 that the password was last changed.
		 */
		return (time_t)strtol((char *)p, NULL, 16);
	}
	return (time_t)-1;
}

/*******************************************************************
 gets password last set time
 ********************************************************************/
time_t pdb_get_last_set_time(char *p)
{
	if (*p && StrnCaseCmp((char *)p, "LCT-", 4))
	{
		return get_time_from_string(p + 4);
	}
	return (time_t)-1;
}


/*******************************************************************
 sets password-database-format time in a string.
 ********************************************************************/
static void set_time_in_string(char *p, int max_len, char *type, time_t t)
{
	slprintf(p, max_len, ":%s-%08X:", type, (uint32)t);
}

/*******************************************************************
 sets password last set time
 ********************************************************************/
void pdb_set_last_set_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "LCT", t);
}
/**********************************************************
 Encode the account control bits into a string.
 **********************************************************/
char *pdb_encode_acct_ctrl(uint16 acct_ctrl)
{
  static fstring acct_str;
  char *p = acct_str;
 
  *p++ = '[';

  if (acct_ctrl & ACB_HOMDIRREQ) *p++ = 'H';
  if (acct_ctrl & ACB_TEMPDUP  ) *p++ = 'T'; 
  if (acct_ctrl & ACB_NORMAL   ) *p++ = 'U';
  if (acct_ctrl & ACB_MNS      ) *p++ = 'M';
  if (acct_ctrl & ACB_WSTRUST  ) *p++ = 'W';
  if (acct_ctrl & ACB_SVRTRUST ) *p++ = 'S';
  if (acct_ctrl & ACB_AUTOLOCK ) *p++ = 'L';
  if (acct_ctrl & ACB_PWNOEXP  ) *p++ = 'X';
  if (acct_ctrl & ACB_DOMTRUST ) *p++ = 'I';
      
  *p++ = ']';
  *p = '\0';
  return acct_str;
}     

/**********************************************************
 Decode the account control bits from a string.

 this function breaks coding standards minimum line width of 80 chars.
 reason: vertical line-up code clarity - all case statements fit into
 15 lines, which is more important.
 **********************************************************/
uint16 pdb_decode_acct_ctrl(char *p)
{
	uint16 acct_ctrl = 0;
	BOOL finished = False;

	/*
	 * Check if the account type bits have been encoded after the
	 * NT password (in the form [NDHTUWSLXI]).
	 */

	if (*p != '[') return 0;

	for (p++; *p && !finished; p++)
	{
		switch (*p)
		{
#if 0
			/*
			 * Hmmm. Don't allow these to be set/read independently
			 * of the actual password fields. We don't want a mismatch.
			 * JRA.
			 */
			case 'N': { acct_ctrl |= ACB_PWNOTREQ ; break; /* 'N'o password. */ }
			case 'D': { acct_ctrl |= ACB_DISABLED ; break; /* 'D'isabled. */ }
#endif 
			case 'H': { acct_ctrl |= ACB_HOMDIRREQ; break; /* 'H'omedir required. */ }
			case 'T': { acct_ctrl |= ACB_TEMPDUP  ; break; /* 'T'emp account. */ } 
			case 'U': { acct_ctrl |= ACB_NORMAL   ; break; /* 'U'ser account (normal). */ } 
			case 'M': { acct_ctrl |= ACB_MNS      ; break; /* 'M'NS logon user account. What is this ? */ } 
			case 'W': { acct_ctrl |= ACB_WSTRUST  ; break; /* 'W'orkstation account. */ } 
			case 'S': { acct_ctrl |= ACB_SVRTRUST ; break; /* 'S'erver account. */ } 
			case 'L': { acct_ctrl |= ACB_AUTOLOCK ; break; /* 'L'ocked account. */ } 
			case 'X': { acct_ctrl |= ACB_PWNOEXP  ; break; /* No 'X'piry on password */ } 
			case 'I': { acct_ctrl |= ACB_DOMTRUST ; break; /* 'I'nterdomain trust account. */ }

			case ':':
			case '\n':
			case '\0': 
			case ']':
			default:  { finished = True; }
		}
	}

	return acct_ctrl;
}

/*************************************************************
 Routine to get the next 32 hex characters and turn them
 into a 16 byte array.
**************************************************************/
int pdb_gethexpwd(char *p, char *pwd)
{
  int i;
  unsigned char   lonybble, hinybble;
  char           *hexchars = "0123456789ABCDEF";
  char           *p1, *p2;

  for (i = 0; i < 32; i += 2) {
    hinybble = toupper(p[i]);
    lonybble = toupper(p[i + 1]);
 
    p1 = strchr(hexchars, hinybble);
    p2 = strchr(hexchars, lonybble);
    if (!p1 || !p2)
      return (False);
    hinybble = PTR_DIFF(p1, hexchars);
    lonybble = PTR_DIFF(p2, hexchars);
 
    pwd[i / 2] = (hinybble << 4) | lonybble;
  }
  return (True);
}

/*******************************************************************
 Group and User RID username mapping function
 ********************************************************************/
BOOL pdb_name_to_rid(char *user_name, uint32 *u_rid, uint32 *g_rid)
{
    struct passwd *pw = Get_Pwnam(user_name, False);

	if (u_rid == NULL || g_rid == NULL || user_name == NULL)
	{
		return False;
	}

    if (!pw)
	{
      DEBUG(1,("Username %s is invalid on this system\n", user_name));
      return False;
    }

	if (user_in_list(user_name, lp_domain_guest_users()))
	{
		*u_rid = DOMAIN_USER_RID_GUEST;
	}
	else if (user_in_list(user_name, lp_domain_admin_users()))
	{
		*u_rid = DOMAIN_USER_RID_ADMIN;
	}
	else
	{
		/* turn the unix UID into a Domain RID.  this is what the posix
		   sub-system does (adds 1000 to the uid) */
		*u_rid = pdb_uid_to_user_rid(pw->pw_uid);
	}

	/* absolutely no idea what to do about the unix GID to Domain RID mapping */
	*g_rid = pdb_gid_to_group_rid(pw->pw_gid);

	return True;
}

/****************************************************************************
 Read the machine SID from a file.
****************************************************************************/
static BOOL read_sid_from_file(int fd, char *sid_file)
{   
  fstring fline;
    
  if(read(fd, &fline, sizeof(fline) -1 ) < 0) {
    DEBUG(0,("read_sid_from_file: unable to read file %s. Error was %s\n",
           sid_file, strerror(errno) ));
    return False;
  }

  /*
   * Convert to the machine SID.
   */

  fline[sizeof(fline)-1] = '\0';
  if(!string_to_sid( &global_machine_sid, fline)) {
    DEBUG(0,("read_sid_from_file: unable to generate machine SID.\n"));
    return False;
  }

  return True;
}

/****************************************************************************
 Generate the global machine sid. Look for the MACHINE.SID file first, if
 not found then look in smb.conf and use it to create the MACHINE.SID file.
****************************************************************************/
BOOL pdb_generate_machine_sid(void)
{
  int fd;
  char *p;
  pstring sid_file;
  fstring sid_string;
  struct stat st;
  uchar raw_sid_data[12];

  pstrcpy(sid_file, lp_smb_passwd_file());
  p = strrchr(sid_file, '/');
  if(p != NULL)
    *++p = '\0';
    
  pstrcat(sid_file, "MACHINE.SID");
    
  if((fd = open( sid_file, O_RDWR | O_CREAT, 0644)) < 0 ) {
    DEBUG(0,("generate_machine_sid: unable to open or create file %s. Error was %s\n",
             sid_file, strerror(errno) ));
    return False;
  } 
  
  /*
   * Check if the file contains data.
   */
    
  if(fstat( fd, &st) < 0) {
    DEBUG(0,("generate_machine_sid: unable to stat file %s. Error was %s\n",
             sid_file, strerror(errno) ));
    close(fd);
    return False;
  } 
  
  if(st.st_size > 0) {
    /*
     * We have a valid SID - read it.
     */
    if(!read_sid_from_file( fd, sid_file)) {
      DEBUG(0,("generate_machine_sid: unable to read file %s. Error was %s\n",
             sid_file, strerror(errno) ));
      close(fd);
      return False;
    }
    close(fd);
    return True;
  } 
  
  /*
   * The file contains no data - we may need to generate our
   * own sid. Try the lp_domain_sid() first.
   */
    
  if(*lp_domain_sid())
    fstrcpy( sid_string, lp_domain_sid());
  else {
    /*
     * Generate the new sid data & turn it into a string.
     */
    int i;
    generate_random_buffer( raw_sid_data, 12, True);
    
    fstrcpy( sid_string, "S-1-5-21");
    for( i = 0; i < 3; i++) {
      fstring tmp_string;
      slprintf( tmp_string, sizeof(tmp_string) - 1, "-%u", IVAL(raw_sid_data, i*4));
      fstrcat( sid_string, tmp_string);
    }
  } 
  
  fstrcat(sid_string, "\n");
    
  /*
   * Ensure our new SID is valid.
   */
    
  if(!string_to_sid( &global_machine_sid, sid_string)) {
    DEBUG(0,("generate_machine_sid: unable to generate machine SID.\n"));
    return False;
  } 
  
  /*
   * Do an exclusive blocking lock on the file.
   */
    
  if(!do_file_lock( fd, 60, F_WRLCK)) {
    DEBUG(0,("generate_machine_sid: unable to lock file %s. Error was %s\n",
             sid_file, strerror(errno) ));
    close(fd);
    return False;
  } 
  
  /*
   * At this point we have a blocking lock on the SID
   * file - check if in the meantime someone else wrote
   * SID data into the file. If so - they were here first,
   * use their data.
   */
    
  if(fstat( fd, &st) < 0) {
    DEBUG(0,("generate_machine_sid: unable to stat file %s. Error was %s\n",
             sid_file, strerror(errno) ));
    close(fd);
    return False;
  } 
  
  if(st.st_size > 0) {
    /*
     * Unlock as soon as possible to reduce
     * contention on the exclusive lock.
     */ 
    do_file_lock( fd, 60, F_UNLCK);
    
    /*
     * We have a valid SID - read it.
     */
    
    if(!read_sid_from_file( fd, sid_file)) {
      DEBUG(0,("generate_machine_sid: unable to read file %s. Error was %s\n",
             sid_file, strerror(errno) ));
      close(fd);
      return False;
    }
    close(fd);
    return True;
  } 
    
  /*
   * The file is still empty and we have an exlusive lock on it.
   * Write out out SID data into the file.
   */
    
  if(fchmod(fd, 0644) < 0) {
    DEBUG(0,("generate_machine_sid: unable to set correct permissions on file %s. \
Error was %s\n", sid_file, strerror(errno) ));
    close(fd);
    return False;
  } 
  
  if(write( fd, sid_string, strlen(sid_string)) != strlen(sid_string)) {
    DEBUG(0,("generate_machine_sid: unable to write file %s. Error was %s\n",
          sid_file, strerror(errno) ));
    close(fd);
    return False;
  } 
  
  /*
   * Unlock & exit.
   */
    
  do_file_lock( fd, 60, F_UNLCK);
  close(fd);
  return True;
}   

/*******************************************************************
 converts NT User RID to a UNIX uid.
 ********************************************************************/
uid_t pdb_user_rid_to_uid(uint32 u_rid)
{
	return (uid_t)(u_rid - 1000);
}

/*******************************************************************
 converts NT Group RID to a UNIX uid.
 ********************************************************************/
uid_t pdb_group_rid_to_uid(uint32 u_gid)
{
	return (uid_t)(u_gid - 1000);
}

/*******************************************************************
 converts UNIX uid to an NT User RID.
 ********************************************************************/
uint32 pdb_uid_to_user_rid(uint32 uid)
{
	return (uint32)(uid + 1000);
}

/*******************************************************************
 converts NT Group RID to a UNIX uid.
 ********************************************************************/
uint32 pdb_gid_to_group_rid(uint32 gid)
{
	return (uint32)(gid + 1000);
}

