/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   LDAP passgrp database for SAMBA
   Copyright (C) Matthew Chapman 1998
   
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

#ifdef WITH_LDAP

#include <lber.h>
#include <ldap.h>

extern int DEBUGLEVEL;

/* Internal state */
extern LDAP *ldap_struct;
extern LDAPMessage *ldap_results;
extern LDAPMessage *ldap_entry;


/***************************************************************
  Enumerate RIDs of groups which user is a member of, of type
  given by attribute.
 ****************************************************************/

static void ldappassgrp_member(char *attribute, uint32 **rids, int *numrids)
{
	char **values;
	uint32 *ridlist;
	int i;

	if((values = ldap_get_values(ldap_struct, ldap_entry, attribute))) {
		*numrids = i = ldap_count_values(values);
		*rids = ridlist = malloc(i * sizeof(uint32));
		do {
			ridlist[--i] = atoi(values[i]);
		} while(i > 0);
		ldap_value_free(values);
	} else {
		*numrids = 0;
		*rids = NULL;
	}
}


/***************************************************************
  Begin/end smbgrp enumeration.
 ****************************************************************/

static void *ldappassgrp_enumfirst(BOOL update)
{
	if (!ldap_connect())
		return NULL;

	ldap_search_for("&(objectclass=sambaAccount)(|(group=*)(alias=*))");

	return ldap_struct;
}

static void ldappassgrp_enumclose(void *vp)
{
	ldap_disconnect();
}


/*************************************************************************
  Save/restore the current position in a query
 *************************************************************************/

static SMB_BIG_UINT ldappassgrp_getdbpos(void *vp)
{
	return (SMB_BIG_UINT)((ulong)ldap_entry);
}

static BOOL ldappassgrp_setdbpos(void *vp, SMB_BIG_UINT tok)
{
	ldap_entry = (LDAPMessage *)((ulong)tok);
	return (True);
}


/*************************************************************************
  Return limited smb_passwd information, and group membership.
 *************************************************************************/

static struct smb_passwd *ldappassgrp_getpwbynam(const char *name,
	       uint32 **grp_rids, int *num_grps,
	       uint32 **als_rids, int *num_alss)
{
	struct smb_passwd *ret;

	if(!ldap_connect())
		return NULL;

	ldap_search_by_ntname(name);
	ldappassgrp_member("group", grp_rids, num_grps);
	ldappassgrp_member("alias", als_rids, num_alss);
	ret = ldap_getpw();

	ldap_disconnect();
	return ret;
}

static struct smb_passwd *ldappassgrp_getpwbyuid(uid_t userid,
	       uint32 **grp_rids, int *num_grps,
	       uint32 **als_rids, int *num_alss)
{
	struct smb_passwd *ret;

	if(!ldap_connect())
		return NULL;

	ldap_search_by_uid(userid);
	ldappassgrp_member("group", grp_rids, num_grps);
	ldappassgrp_member("alias", als_rids, num_alss);
	ret = ldap_getpw();

	ldap_disconnect();
	return ret;
}

static struct smb_passwd *ldappassgrp_getpwbyrid(uint32 user_rid,
	       uint32 **grp_rids, int *num_grps,
	       uint32 **als_rids, int *num_alss)
{
	struct smb_passwd *ret;

	if(!ldap_connect())
		return NULL;

	ldap_search_by_rid(user_rid);
	ldappassgrp_member("group", grp_rids, num_grps);
	ldappassgrp_member("alias", als_rids, num_alss);
	ret = ldap_getpw();

	ldap_disconnect();
	return ret;
}

static struct smb_passwd *ldappassgrp_getcurrentpw(void *vp,
	       uint32 **grp_rids, int *num_grps,
	       uint32 **als_rids, int *num_alss)
{
	ldappassgrp_member("group", grp_rids, num_grps);
	ldappassgrp_member("alias", als_rids, num_alss);
	return ldap_getpw();
}



static struct passgrp_ops ldappassgrp_ops =
{
	ldappassgrp_enumfirst,
	ldappassgrp_enumclose,
	ldappassgrp_getdbpos,
	ldappassgrp_setdbpos,

	ldappassgrp_getpwbynam,
	ldappassgrp_getpwbyuid,
	ldappassgrp_getpwbyrid,
	ldappassgrp_getcurrentpw,
};

struct passgrp_ops *ldap_initialise_password_grp(void)
{
	return &ldappassgrp_ops;
}

#else
 void passgrpldap_dummy_function(void);
 void passgrpldap_dummy_function(void) { } /* stop some compilers complaining */
#endif

