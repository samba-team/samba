/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Pasesword and authentication handling
   Copyright (C) Jeremy Allison 1996-1998
   Copyright (C) Luke Kenneth Caseson Leighton 1996-1998
      
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
   Foundation, Inc., 675 Mases Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;

/*
 * NOTE. All these functions are abstracted into a structure
 * that points to the correct function for the selected database. JRA.
 */

static struct aliasdb_ops *aldb_ops = NULL;

/***************************************************************
 Initialise the alias db operations.
***************************************************************/

BOOL initialise_alias_db(void)
{
  if (aldb_ops)
  {
    return True;
  }

#ifdef WITH_NISPLUS
  aldb_ops =  nisplus_initialise_alias_db();
#elif defined(WITH_LDAP)
  aldb_ops = ldap_initialise_alias_db();
#elif defined(USE_SMBUNIX_DB)
  aldb_ops = unix_initialise_alias_db();
#endif 

  return (aldb_ops != NULL);
}

/*
 * Functions that return/manipulate a LOCAL_GRP.
 */

/************************************************************************
 Utility function to search alias database by gid: the LOCAL_GRP
 structure does not have a gid member, so we have to convert here
 from gid to alias rid.
*************************************************************************/
LOCAL_GRP *iterate_getaliasgid(gid_t gid, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	DOM_NAME_MAP gmep;
	uint32 rid;
	if (!lookupsmbgrpgid(gid, &gmep))
	{
		DEBUG(0,("iterate_getaliasgid: gid %d does not map to one of our Domain's Aliases\n", gid));
		return NULL;
	}

	if (gmep.type != SID_NAME_ALIAS )
	{
		DEBUG(0,("iterate_getaliasgid: gid %d does not map to one of our Domain's Aliases\n", gid));
		return NULL;
	}

	sid_split_rid(&gmep.sid, &rid);
	if (!sid_equal(&gmep.sid, &global_sam_sid))
	{
		DEBUG(0,("iterate_getaliasgid: gid %d does not map into our Domain SID\n", gid));
		return NULL;
	}

	return iterate_getaliasrid(rid, mem, num_mem);
}

/************************************************************************
 Utility function to search alias database by rid.  use this if your database
 does not have search facilities.
*************************************************************************/
LOCAL_GRP *iterate_getaliasrid(uint32 rid, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	LOCAL_GRP *als = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by rid: 0x%x\n", rid));

	/* Open the alias database file - not for update. */
	fp = startaliasent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open alias database.\n"));
		return NULL;
	}

	while ((als = getaliasent(fp, mem, num_mem)) != NULL && als->rid != rid)
	{
		DEBUG(10,("iterate: %s 0x%x", als->name, als->rid));
	}

	if (als != NULL)
	{
		DEBUG(10, ("found alias %s by rid: 0x%x\n", als->name, rid));
	}

	endaliasent(fp);
	return als;
}

/************************************************************************
 Utility function to search alias database by name.  use this if your database
 does not have search facilities.
*************************************************************************/
LOCAL_GRP *iterate_getaliasntnam(const char *name, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	LOCAL_GRP *als = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by name: %s\n", name));

	/* Open the alias database file - not for update. */
	fp = startaliasent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open alias database.\n"));
		return NULL;
	}

	while ((als = getaliasent(fp, mem, num_mem)) != NULL && !strequal(als->name, name))
	{
	}

	if (als != NULL)
	{
		DEBUG(10, ("found by name: %s\n", name));
	}

	endaliasent(fp);
	return als;
}

/*************************************************************************
 Routine to return the next entry in the smbdomainalias list.
 *************************************************************************/
BOOL add_domain_alias(LOCAL_GRP **alss, int *num_alss, LOCAL_GRP *als)
{
	if (alss == NULL || num_alss == NULL || als == NULL)
	{
		return False;
	}

	(*alss) = Realloc((*alss), ((*num_alss)+1) * sizeof(LOCAL_GRP));
	if ((*alss) == NULL)
	{
		return False;
	}

	DEBUG(10,("adding alias %s(%s)\n", als->name, als->comment));

	fstrcpy((*alss)[(*num_alss)].name   , als->name);
	fstrcpy((*alss)[(*num_alss)].comment, als->comment);
	(*alss)[(*num_alss)].rid = als->rid;

	(*num_alss)++;

	return True;
}

/*************************************************************************
 checks to see if a user is a member of a domain alias
 *************************************************************************/
static BOOL user_is_member(const char *user_name, LOCAL_GRP_MEMBER *mem, int num_mem)
{
	int i;
	pstring name;
	slprintf(name, sizeof(name)-1, "%s\\%s", global_sam_name, user_name);

	for (i = 0; i < num_mem; i++)
	{
		DEBUG(10,("searching against user %s...\n", mem[i].name));
		if (strequal(mem[i].name, name))
		{
			DEBUG(10,("searching for user %s: found\n", name));
			return True;
		}
	}
	DEBUG(10,("searching for user %s: not found\n", name));
	return False;
}

/*************************************************************************
 gets an array of aliases that a user is in.  use this if your database
 does not have search facilities
 *************************************************************************/
BOOL iterate_getuseraliasntnam(const char *user_name, LOCAL_GRP **alss, int *num_alss)
{
	LOCAL_GRP *als = NULL;
	LOCAL_GRP_MEMBER *mem = NULL;
	int num_mem = 0;
	void *fp = NULL;

	DEBUG(10, ("search for useralias by name: %s\n", user_name));

	if (user_name == NULL || alss == NULL || num_alss == NULL)
	{
		return False;
	}

	(*alss) = NULL;
	(*num_alss) = 0;

	/* Open the alias database file - not for update. */
	fp = startaliasent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open alias database.\n"));
		return False;
	}

	/* iterate through all aliases.  search members for required user */
	while ((als = getaliasent(fp, &mem, &num_mem)) != NULL)
	{
		DEBUG(5,("alias name %s members: %d\n", als->name, num_mem));
		if (num_mem != 0 && mem != NULL)
		{
			BOOL ret = True;
			if (user_is_member(user_name, mem, num_mem))
			{
				ret = add_domain_alias(alss, num_alss, als);
			}

			free(mem);
			mem = NULL;
			num_mem = 0;

			if (!ret)
			{
				(*num_alss) = 0;
				break;
			}
		}
	}

	if ((*num_alss) != 0)
	{
		DEBUG(10, ("found %d user aliases:\n", (*num_alss)));
	}

	endaliasent(fp);
	return True;
}

/*************************************************************************
 gets an array of aliases that a user is in.  use this if your database
 does not have search facilities
 *************************************************************************/
BOOL enumdomaliases(LOCAL_GRP **alss, int *num_alss)
{
	LOCAL_GRP *als = NULL;
	void *fp = NULL;

	DEBUG(10, ("enum user aliases\n"));

	if (alss == NULL || num_alss == NULL)
	{
		return False;
	}

	(*alss) = NULL;
	(*num_alss) = 0;

	/* Open the alias database file - not for update. */
	fp = startaliasent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open alias database.\n"));
		return False;
	}

	/* iterate through all aliases. */
	while ((als = getaliasent(fp, NULL, NULL)) != NULL)
	{
		if (!add_domain_alias(alss, num_alss, als))
		{
			DEBUG(0,("unable to add alias while enumerating\n"));
			return False;
		}
	}

	if ((*num_alss) != 0)
	{
		DEBUG(10, ("found %d user aliases:\n", (*num_alss)));
	}

	endaliasent(fp);
	return True;
}

/***************************************************************
 Start to enumerate the alias database list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

void *startaliasent(BOOL update)
{
  return aldb_ops->startaliasent(update);
}

/***************************************************************
 End enumeration of the alias database list.
****************************************************************/

void endaliasent(void *vp)
{
  aldb_ops->endaliasent(vp);
}

/*************************************************************************
 Routine to return the next entry in the alias database list.
 *************************************************************************/

LOCAL_GRP *getaliasent(void *vp, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	return aldb_ops->getaliasent(vp, mem, num_mem);
}

/************************************************************************
 Routine to add an entry to the alias database file.
 on entry, the entry is added by name.
 on exit, the RID is expected to have been set.
*************************************************************************/
BOOL add_alias_entry(LOCAL_GRP *newgrp)
{
	BOOL ret;
	if (newgrp->rid != 0xffffffff)
{
		DEBUG(0,("add_alias_entry - RID must be 0xffffffff, \
database instance is responsible for allocating the RID, not you.\n"));
		return False;
	}
 	ret = aldb_ops->add_alias_entry(newgrp);
	if (newgrp->rid == 0xffffffff)
	{
		DEBUG(0,("add_alias_entry - RID has not been set by database\n"));
		return False;
	}
	return ret;
}

/************************************************************************
 Routine to search the alias database file for an entry matching the aliasname.
 and then replace the entry.
************************************************************************/

BOOL mod_alias_entry(LOCAL_GRP* als)
{
 	return aldb_ops->mod_alias_entry(als);
}

/************************************************************************
 Routine to delete alias database entry matching by rid.
************************************************************************/
BOOL del_alias_entry(uint32 rid)
{
 	return aldb_ops->del_alias_entry(rid);
}

/************************************************************************
 Routine to add a member to an entry in the alias database file.
*************************************************************************/
BOOL add_alias_member(uint32 rid, const DOM_SID *member_sid)
{
 	return aldb_ops->add_alias_member(rid, member_sid);
}

/************************************************************************
 Routine to delete a member from an entry in the alias database file.
*************************************************************************/
BOOL del_alias_member(uint32 rid, const DOM_SID *member_sid)
{
 	return aldb_ops->del_alias_member(rid, member_sid);
}
/************************************************************************
 Routine to search alias database by name.
*************************************************************************/

LOCAL_GRP *getaliasntnam(const char *name, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	return aldb_ops->getaliasntnam(name, mem, num_mem);
}

/************************************************************************
 Routine to search alias database by alias rid.
*************************************************************************/

LOCAL_GRP *getaliasrid(uint32 alias_rid, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	return aldb_ops->getaliasrid(alias_rid, mem, num_mem);
}

/************************************************************************
 Routine to search alias database by gid.
*************************************************************************/

LOCAL_GRP *getaliasgid(gid_t gid, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	return aldb_ops->getaliasgid(gid, mem, num_mem);
}

/*************************************************************************
 gets an array of aliases that a user is in.
 *************************************************************************/
BOOL getuseraliasntnam(const char *user_name, LOCAL_GRP **als, int *num_alss)
{
	return aldb_ops->getuseraliasntnam(user_name, als, num_alss);
}

/*************************************************************
 initialises a LOCAL_GRP.
 **************************************************************/
void aldb_init_als(LOCAL_GRP *als)
{
	if (als == NULL) return;
	ZERO_STRUCTP(als);
}

/*************************************************************
 turns an alias entry into a string.
 **************************************************************/
BOOL make_alias_line(char *p, int max_len,
				LOCAL_GRP *als,
				LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	int i;
	int len;
	len = slprintf(p, max_len-1, "%s:%s:%d:", als->name, als->comment, als->rid);

	if (len == -1)
	{
		DEBUG(0,("make_alias_line: cannot create entry\n"));
		return False;
	}

	p += len;
	max_len -= len;

	if (mem == NULL || num_mem == NULL)
	{
		return True;
	}

	for (i = 0; i < (*num_mem); i++)
	{
		len = strlen((*mem)[i].name);
		p = safe_strcpy(p, (*mem)[i].name, max_len); 

		if (p == NULL)
		{
			DEBUG(0, ("make_alias_line: out of space for aliases!\n"));
			return False;
		}

		max_len -= len;

		if (i != (*num_mem)-1)
		{
			*p = ',';
			p++;
			max_len--;
		}
	}

	return True;
}
