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
#ifdef USE_LDAP
  return startldappwent(update);
#else
  return startsmbpwent(update);
#endif /* USE_LDAP */
}

/***************************************************************
 End enumeration of the sam passwd list.
****************************************************************/
void endsampwent(void *vp)
{
#ifdef USE_LDAP
  endldappwent(vp);
#else
  endsmbpwent(vp);
#endif /* USE_LDAP */
}

/*************************************************************************
 Routine to return the next entry in the sam passwd list.
 *************************************************************************/
struct smb_passwd *getsampwent(void *vp)
{
#ifdef USE_LDAP
  return getldappwent(vp);
#else
  return getsmbpwent(vp);
#endif /* USE_LDAP */
}

/*************************************************************************
 Routine to return the next entry in the sam passwd list.
 *************************************************************************/
struct sam_passwd *getsam21pwent(void *vp)
{
#ifdef USE_LDAP
  return getldap21pwent(vp);
#else
  return getsmb21pwent(vp);
#endif /* USE_LDAP */
}

/*************************************************************************
 Return the current position in the sam passwd list as an unsigned long.
 This must be treated as an opaque token.
 *************************************************************************/
unsigned long getsampwpos(void *vp)
{
#ifdef USE_LDAP
  return getldappwpos(vp);
#else
  return getsmbpwpos(vp);
#endif /* USE_LDAP */
}

/*************************************************************************
 Set the current position in the sam passwd list from unsigned long.
 This must be treated as an opaque token.
 *************************************************************************/
BOOL setsampwpos(void *vp, unsigned long tok)
{
#ifdef USE_LDAP
  return setldappwpos(vp, tok);
#else
  return setsmbpwpos(vp, tok);
#endif /* USE_LDAP */
}

/************************************************************************
 Routine to add an entry to the sam passwd file.
*************************************************************************/
BOOL add_sampwd_entry(struct smb_passwd *newpwd)
{
#ifdef USE_LDAP
  return add_ldappwd_entry(newpwd);
#else
  return add_smbpwd_entry(newpwd);
#endif /* USE_LDAP */
}

/************************************************************************
 Routine to add an entry to the sam passwd file.
*************************************************************************/
BOOL add_sam21pwd_entry(struct sam_passwd *newpwd)
{
#if 0
#ifdef USE_LDAP
  return add_ldap21pwd_entry(newpwd);
#else
  return add_smb21pwd_entry(newpwd);
#endif /* USE_LDAP */
#else
	DEBUG(0,("add_sam21pwd_entry() - under development\n"));
	return False;
#endif
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
#ifdef USE_LDAP
  return mod_ldappwd_entry(pwd, override);
#else
  return mod_smbpwd_entry(pwd, override);
#endif /* USE_LDAP */
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
#if 0
#ifdef USE_LDAP
  return mod_ldap21pwd_entry(pwd, override);
#else
  return mod_smb21pwd_entry(pwd, override);
#endif /* USE_LDAP */
#else
	DEBUG(0,("mod_sam21pwd_entry() - under development\n"));
	return False;
#endif
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
 Routine to search sam passwd by name.
*************************************************************************/
struct smb_passwd *getsampwnam(char *name)
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
struct sam_passwd *getsam21pwnam(char *name)
{
	struct sam_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("getsam21pwnam: search by name: %s\n", name));

	/* Open the sam password file - not for update. */
	fp = startsampwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("getsam21pwnam: unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsam21pwent(fp)) != NULL && !strequal(pwd->smb_name, name));

	if (pwd != NULL)
	{
		DEBUG(10, ("getsam21pwnam: found by name: %s\n", name));
	}

	endsampwent(fp);
	return pwd;
}

/************************************************************************
 Routine to search sam passwd by uid.
*************************************************************************/
struct smb_passwd *getsampwuid(uid_t smb_userid)
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
 Routine to search sam passwd by rid.
*************************************************************************/
struct sam_passwd *getsam21pwrid(uint32 rid)
{
	struct sam_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("getsam21pwrid: search by rid: %x\n", rid));

	/* Open the sam password file - not for update. */
	fp = startsampwent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("getsam21pwrid: unable to open sam password database.\n"));
		return NULL;
	}

	while ((pwd = getsam21pwent(fp)) != NULL && pwd->user_rid != rid);

	if (pwd != NULL)
	{
		DEBUG(10, ("getsam21pwrid: found by smb_userid: %x\n", rid));
	}

	endsmbpwent(fp);
	return pwd;
}


/**********************************************************
 **********************************************************

 utility routines which are likely to be useful to all password
 databases

 **********************************************************
 **********************************************************/

/**********************************************************
 Encode the account control bits into a string.
 **********************************************************/
char *encode_acct_ctrl(uint16 acct_ctrl)
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
uint16 decode_acct_ctrl(char *p)
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
int gethexpwd(char *p, char *pwd)
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
BOOL name_to_rid(char *user_name, uint32 *u_rid, uint32 *g_rid)
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
		*u_rid = uid_to_user_rid(pw->pw_uid);
	}

	/* absolutely no idea what to do about the unix GID to Domain RID mapping */
	*g_rid = gid_to_group_rid(pw->pw_gid);

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

BOOL generate_machine_sid(void)
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
 XXXX THIS FUNCTION SHOULD NOT BE HERE: IT SHOULD BE A STATIC FUNCTION
 INSIDE smbpass.c

 converts NT User RID to a UNIX uid.
 ********************************************************************/
uid_t user_rid_to_uid(uint32 u_rid)
{
	return (uid_t)(u_rid - 1000);
}

/*******************************************************************
 XXXX THIS FUNCTION SHOULD NOT BE HERE: IT SHOULD BE A STATIC FUNCTION
 INSIDE smbpass.c

 converts NT Group RID to a UNIX uid.
 ********************************************************************/
uid_t group_rid_to_uid(uint32 u_gid)
{
	return (uid_t)(u_gid - 1000);
}

/*******************************************************************
 XXXX THIS FUNCTION SHOULD NOT BE HERE: IT SHOULD BE A STATIC FUNCTION
 INSIDE smbpass.c

 converts UNIX uid to an NT User RID.
 ********************************************************************/
uint32 uid_to_user_rid(uint32 uid)
{
	return (uint32)(uid + 1000);
}

/*******************************************************************
 XXXX THIS FUNCTION SHOULD NOT BE HERE: IT SHOULD BE A STATIC FUNCTION
 INSIDE smbpass.c

 converts NT Group RID to a UNIX uid.
 ********************************************************************/
uint32 gid_to_group_rid(uint32 gid)
{
	return (uint32)(gid + 1000);
}

