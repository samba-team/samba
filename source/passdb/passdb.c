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

extern int DEBUGLEVEL;

/************************************************************************
 Routine to search sam passwd by name.
*************************************************************************/

struct smb_passwd *getsampwnam(char *name)
{
#ifdef USE_LDAP
  return getldappwnam(name);
#else
  return getsmbpwnam(name);
#endif /* USE_LDAP */
}

/************************************************************************
 Routine to search sam passwd by uid.
*************************************************************************/

struct smb_passwd *getsampwuid(unsigned int uid)
{
#ifdef USE_LDAP
  return getldappwuid(uid);
#else
  return getsmbpwuid(uid);
#endif /* USE_LDAP */
}

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

