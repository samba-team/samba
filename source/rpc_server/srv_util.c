/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*  this module apparently provides an implementation of DCE/RPC over a
 *  named pipe (IPC$ connection using SMBtrans).  details of DCE/RPC
 *  documentation are available (in on-line form) from the X-Open group.
 *
 *  this module should provide a level of abstraction between SMB
 *  and DCE/RPC, while minimising the amount of mallocs, unnecessary
 *  data copies, and network traffic.
 *
 *  in this version, which takes a "let's learn what's going on and
 *  get something running" approach, there is additional network
 *  traffic generated, but the code should be easier to understand...
 *
 *  ... if you read the docs.  or stare at packets for weeks on end.
 *
 */

#include "includes.h"

/*
 * A list of the rids of well known BUILTIN and Domain users
 * and groups.
 */

rid_name builtin_alias_rids[] =
{  
    { BUILTIN_ALIAS_RID_ADMINS       , "Administrators" },
    { BUILTIN_ALIAS_RID_USERS        , "Users" },
    { BUILTIN_ALIAS_RID_GUESTS       , "Guests" },
    { BUILTIN_ALIAS_RID_POWER_USERS  , "Power Users" },
   
    { BUILTIN_ALIAS_RID_ACCOUNT_OPS  , "Account Operators" },
    { BUILTIN_ALIAS_RID_SYSTEM_OPS   , "System Operators" },
    { BUILTIN_ALIAS_RID_PRINT_OPS    , "Print Operators" },
    { BUILTIN_ALIAS_RID_BACKUP_OPS   , "Backup Operators" },
    { BUILTIN_ALIAS_RID_REPLICATOR   , "Replicator" },
    { 0                             , NULL }
};

/* array lookup of well-known Domain RID users. */
rid_name domain_user_rids[] =
{  
    { DOMAIN_USER_RID_ADMIN         , "Administrator" },
    { DOMAIN_USER_RID_GUEST         , "Guest" },
    { 0                             , NULL }
};

/* array lookup of well-known Domain RID groups. */
rid_name domain_group_rids[] =
{  
    { DOMAIN_GROUP_RID_ADMINS       , "Domain Admins" },
    { DOMAIN_GROUP_RID_USERS        , "Domain Users" },
    { DOMAIN_GROUP_RID_GUESTS       , "Domain Guests" },
    { 0                             , NULL }
};

#define LSA_MAX_GROUPS 96

int make_dom_gids(TALLOC_CTX *ctx, char *gids_str, DOM_GID **ppgids)
{
  const char *ptr;
  pstring s2;
  int count;
  DOM_GID *gids;

  *ppgids = NULL;

  DEBUG(4,("make_dom_gids: %s\n", gids_str));

  if (gids_str == NULL || *gids_str == 0)
    return 0;

  for (count = 0, ptr = gids_str; 
       next_token(&ptr, s2, NULL, sizeof(s2)); 
       count++)
    ;

  gids = (DOM_GID *)talloc(ctx, sizeof(DOM_GID) * count );
  if(!gids)
  {
    DEBUG(0,("make_dom_gids: talloc fail !\n"));
    return 0;
  }

  for (count = 0, ptr = gids_str; 
       next_token(&ptr, s2, NULL, sizeof(s2)) && 
	       count < LSA_MAX_GROUPS; 
       count++) 
  {
    /* the entries are of the form GID/ATTR, ATTR being optional.*/
    const char *attr = NULL;
    char *pattr = NULL;
    uint32 rid = 0;
    int i;

    pattr = strchr(s2,'/');
    if (pattr)
      *pattr++ = 0;

    attr = pattr;
    if (!attr || !*attr)
      attr = "7"; /* default value for attribute is 7 */

    /* look up the RID string and see if we can turn it into a rid number */
    for (i = 0; builtin_alias_rids[i].name != NULL; i++)
    {
      if (strequal(builtin_alias_rids[i].name, s2))
      {
        rid = builtin_alias_rids[i].rid;
        break;
      }
    }

    if (rid == 0)
      rid = atoi(s2);

    if (rid == 0)
    {
      DEBUG(1,("make_dom_gids: unknown well-known alias RID %s/%s\n", s2, attr));
      count--;
    }
    else
    {
      gids[count].g_rid = rid;
      gids[count].attr  = atoi(attr);

      DEBUG(5,("group id: %d attr: %d\n", gids[count].g_rid, gids[count].attr));
    }
  }

  *ppgids = gids;
  return count;
}


/*******************************************************************
 gets a domain user's groups
 ********************************************************************/
void get_domain_user_groups(char *domain_groups, char *user)
{
	pstring tmp;

	if (domain_groups == NULL || user == NULL) return;

#if 0	/* removed by --jerry */ 
	/* any additional groups this user is in.  e.g power users */
	pstrcpy(domain_groups, lp_domain_groups());
#else
	*domain_groups = '\0';
#endif

	/* can only be a user or a guest.  cannot be guest _and_ admin */
	if (user_in_list(user, lp_domain_guest_group()))
	{
		slprintf(tmp, sizeof(tmp) - 1, " %ld/7 ", DOMAIN_GROUP_RID_GUESTS);
		pstrcat(domain_groups, tmp);

		DEBUG(3,("domain guest group access %s granted\n", tmp));
	}
	else
	{
		slprintf(tmp, sizeof(tmp) -1, " %ld/7 ", DOMAIN_GROUP_RID_USERS);
		pstrcat(domain_groups, tmp);

		DEBUG(3,("domain group access %s granted\n", tmp));

		if (user_in_list(user, lp_domain_admin_group()))
		{
			slprintf(tmp, sizeof(tmp) - 1, " %ld/7 ", DOMAIN_GROUP_RID_ADMINS);
			pstrcat(domain_groups, tmp);

			DEBUG(3,("domain admin group access %s granted\n", tmp));
		}
	}
}

/*******************************************************************
 Look up a local (domain) rid and return a name and type.
 ********************************************************************/
NTSTATUS local_lookup_group_name(uint32 rid, char *group_name, uint32 *type)
{
	int i = 0; 
	(*type) = SID_NAME_DOM_GRP;

	DEBUG(5,("lookup_group_name: rid: %d", rid));

	while (domain_group_rids[i].rid != rid && domain_group_rids[i].rid != 0)
	{
		i++;
	}

	if (domain_group_rids[i].rid != 0)
	{
		fstrcpy(group_name, domain_group_rids[i].name);
		DEBUG(5,(" = %s\n", group_name));
		return NT_STATUS_OK;
	}

	DEBUG(5,(" none mapped\n"));
	return NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 Look up a local alias rid and return a name and type.
 ********************************************************************/
NTSTATUS local_lookup_alias_name(uint32 rid, char *alias_name, uint32 *type)
{
	int i = 0; 
	(*type) = SID_NAME_WKN_GRP;

	DEBUG(5,("lookup_alias_name: rid: %d", rid));

	while (builtin_alias_rids[i].rid != rid && builtin_alias_rids[i].rid != 0)
	{
		i++;
	}

	if (builtin_alias_rids[i].rid != 0)
	{
		fstrcpy(alias_name, builtin_alias_rids[i].name);
		DEBUG(5,(" = %s\n", alias_name));
		return NT_STATUS_OK;
	}

	DEBUG(5,(" none mapped\n"));
	return NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 Look up a local user rid and return a name and type.
 ********************************************************************/
NTSTATUS local_lookup_user_name(uint32 rid, char *user_name, uint32 *type)
{
	SAM_ACCOUNT *sampwd=NULL;
	int i = 0;
	BOOL ret;
	
	(*type) = SID_NAME_USER;

	DEBUG(5,("lookup_user_name: rid: %d", rid));

	/* look up the well-known domain user rids first */
	while (domain_user_rids[i].rid != rid && domain_user_rids[i].rid != 0)
	{
		i++;
	}

	if (domain_user_rids[i].rid != 0) {
		fstrcpy(user_name, domain_user_rids[i].name);
		DEBUG(5,(" = %s\n", user_name));
		return NT_STATUS_OK;
	}

	pdb_init_sam(&sampwd);

	/* ok, it's a user.  find the user account */
	become_root();
	ret = pdb_getsampwrid(sampwd, rid);
	unbecome_root();

	if (ret == True) {
		fstrcpy(user_name, pdb_get_username(sampwd) );
		DEBUG(5,(" = %s\n", user_name));
		pdb_free_sam(sampwd);
		return NT_STATUS_OK;
	}

	DEBUG(5,(" none mapped\n"));
	pdb_free_sam(sampwd);
	return NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 Look up a local (domain) group name and return a rid
 ********************************************************************/
NTSTATUS local_lookup_group_rid(char *group_name, uint32 *rid)
{
	const char *grp_name;
	int i = -1; /* start do loop at -1 */

	do /* find, if it exists, a group rid for the group name*/
	{
		i++;
		(*rid) = domain_group_rids[i].rid;
		grp_name = domain_group_rids[i].name;

	} while (grp_name != NULL && !strequal(grp_name, group_name));

	return (grp_name != NULL) ? NT_STATUS_OK : NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 Look up a local (BUILTIN) alias name and return a rid
 ********************************************************************/
NTSTATUS local_lookup_alias_rid(char *alias_name, uint32 *rid)
{
	const char *als_name;
	int i = -1; /* start do loop at -1 */

	do /* find, if it exists, a alias rid for the alias name*/
	{
		i++;
		(*rid) = builtin_alias_rids[i].rid;
		als_name = builtin_alias_rids[i].name;

	} while (als_name != NULL && !strequal(als_name, alias_name));

	return (als_name != NULL) ? NT_STATUS_OK : NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 Look up a local user name and return a rid
 ********************************************************************/
NTSTATUS local_lookup_user_rid(char *user_name, uint32 *rid)
{
	SAM_ACCOUNT *sampass=NULL;
	BOOL ret;

	(*rid) = 0;

	pdb_init_sam(&sampass);

	/* find the user account */
	become_root();
	ret = pdb_getsampwnam(sampass, user_name);
	unbecome_root();

	if (ret == True) {
		(*rid) = pdb_get_user_rid(sampass);
		pdb_free_sam(sampass);
		return NT_STATUS_OK;
	}

	pdb_free_sam(sampass);
	return NT_STATUS_NONE_MAPPED;
}
