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

static struct aliasdb_ops *bidb_ops = NULL;

/***************************************************************
 Initialise the builtin db operations.
***************************************************************/

BOOL initialise_builtin_db(void)
{
  if (bidb_ops)
  {
    return True;
  }

#ifdef WITH_NISPLUS
  bidb_ops =  nisplus_initialise_builtin_db();
#elif defined(WITH_LDAP)
  bidb_ops = ldap_initialise_builtin_db();
#elif defined(USE_SMBUNIX_DB)
  bidb_ops = unix_initialise_builtin_db();
#endif 

  return (bidb_ops != NULL);
}

/*
 * Functions that return/manipulate a LOCAL_GRP.
 */

/************************************************************************
 Utility function to search builtin database by gid: the LOCAL_GRP
 structure does not have a gid member, so we have to convert here
 from gid to builtin rid.
*************************************************************************/
LOCAL_GRP *iterate_getbuiltingid(gid_t gid, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	DOM_NAME_MAP gmep;
	uint32 rid;
	if (!lookupsmbgrpgid(gid, &gmep))
	{
		DEBUG(0,("iterate_getbuiltingid: gid %d does not map to one of our Domain's Aliases\n", gid));
		return NULL;
	}

	if (gmep.type != SID_NAME_ALIAS )
	{
		DEBUG(0,("iterate_getbuiltingid: gid %d does not map to one of our Domain's Aliases\n", gid));
		return NULL;
	}

	sid_split_rid(&gmep.sid, &rid);
	if (!sid_equal(&gmep.sid, &global_sam_sid))
	{
		DEBUG(0,("iterate_getbuiltingid: gid %d does not map into our Domain SID\n", gid));
		return NULL;
	}

	return iterate_getbuiltinrid(rid, mem, num_mem);
}

/************************************************************************
 Utility function to search builtin database by rid.  use this if your database
 does not have search facilities.
*************************************************************************/
LOCAL_GRP *iterate_getbuiltinrid(uint32 rid, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	LOCAL_GRP *blt = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by rid: 0x%x\n", rid));

	/* Open the builtin database file - not for update. */
	fp = startbuiltinent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open builtin database.\n"));
		return NULL;
	}

	while ((blt = getbuiltinent(fp, mem, num_mem)) != NULL && blt->rid != rid)
	{
		DEBUG(10,("iterate: %s 0x%x", blt->name, blt->rid));
	}

	if (blt != NULL)
	{
		DEBUG(10, ("found builtin %s by rid: 0x%x\n", blt->name, rid));
	}

	endbuiltinent(fp);
	return blt;
}

/************************************************************************
 Utility function to search builtin database by name.  use this if your database
 does not have search facilities.
*************************************************************************/
LOCAL_GRP *iterate_getbuiltinntnam(const char *name, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	LOCAL_GRP *blt = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by name: %s\n", name));

	/* Open the builtin database file - not for update. */
	fp = startbuiltinent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open builtin database.\n"));
		return NULL;
	}

	while ((blt = getbuiltinent(fp, mem, num_mem)) != NULL && !strequal(blt->name, name))
	{
	}

	if (blt != NULL)
	{
		DEBUG(10, ("found by name: %s\n", name));
	}

	endbuiltinent(fp);
	return blt;
}

/*************************************************************************
 Routine to return the next entry in the smbdomainbuiltin list.
 *************************************************************************/
BOOL add_domain_builtin(LOCAL_GRP **blts, int *num_blts, LOCAL_GRP *blt)
{
	if (blts == NULL || num_blts == NULL || blt == NULL)
	{
		return False;
	}

	(*blts) = Realloc((*blts), ((*num_blts)+1) * sizeof(LOCAL_GRP));
	if ((*blts) == NULL)
	{
		return False;
	}

	DEBUG(10,("adding builtin %s(%s)\n", blt->name, blt->comment));

	fstrcpy((*blts)[(*num_blts)].name   , blt->name);
	fstrcpy((*blts)[(*num_blts)].comment, blt->comment);
	(*blts)[(*num_blts)].rid = blt->rid;

	(*num_blts)++;

	return True;
}

/*************************************************************************
 checks to see if a user is a member of a domain builtin
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
 gets an array of builtin aliases that a user is in.  use this if your database
 does not have search facilities
 *************************************************************************/
BOOL iterate_getuserbuiltinntnam(const char *user_name, LOCAL_GRP **blts, int *num_blts)
{
	LOCAL_GRP *blt = NULL;
	LOCAL_GRP_MEMBER *mem = NULL;
	int num_mem = 0;
	void *fp = NULL;

	DEBUG(10, ("search for userbuiltin by name: %s\n", user_name));

	if (user_name == NULL || blts == NULL || num_blts == NULL)
	{
		return False;
	}

	(*blts) = NULL;
	(*num_blts) = 0;

	/* Open the builtin database file - not for update. */
	fp = startbuiltinent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open builtin database.\n"));
		return False;
	}

	/* iterate through all builtin aliases.  search members for required user */
	while ((blt = getbuiltinent(fp, &mem, &num_mem)) != NULL)
	{
		DEBUG(5,("builtin name %s members: %d\n", blt->name, num_mem));
		if (num_mem != 0 && mem != NULL)
		{
			BOOL ret = True;
			if (user_is_member(user_name, mem, num_mem))
			{
				ret = add_domain_builtin(blts, num_blts, blt);
			}

			free(mem);
			mem = NULL;
			num_mem = 0;

			if (!ret)
			{
				(*num_blts) = 0;
				break;
			}
		}
	}

	if ((*num_blts) != 0)
	{
		DEBUG(10, ("found %d user builtin aliases:\n", (*num_blts)));
	}

	endbuiltinent(fp);
	return True;
}

/*************************************************************************
 gets an array of builtin aliases that a user is in.  use this if your database
 does not have search facilities
 *************************************************************************/
BOOL enumdombuiltins(LOCAL_GRP **blts, int *num_blts)
{
	LOCAL_GRP *blt = NULL;
	void *fp = NULL;

	DEBUG(10, ("enum user builtin aliases\n"));

	if (blts == NULL || num_blts == NULL)
	{
		return False;
	}

	(*blts) = NULL;
	(*num_blts) = 0;

	/* Open the builtin database file - not for update. */
	fp = startbuiltinent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open builtin database.\n"));
		return False;
	}

	/* iterate through all builtin aliases. */
	while ((blt = getbuiltinent(fp, NULL, NULL)) != NULL)
	{
		if (!add_domain_builtin(blts, num_blts, blt))
		{
			DEBUG(0,("unable to add builtin while enumerating\n"));
			return False;
		}
	}

	if ((*num_blts) != 0)
	{
		DEBUG(10, ("found %d user builtin aliases:\n", (*num_blts)));
	}

	endbuiltinent(fp);
	return True;
}

/***************************************************************
 Start to enumerate the builtin database list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

void *startbuiltinent(BOOL update)
{
  return bidb_ops->startaliasent(update);
}

/***************************************************************
 End enumeration of the builtin database list.
****************************************************************/

void endbuiltinent(void *vp)
{
  bidb_ops->endaliasent(vp);
}

/*************************************************************************
 Routine to return the next entry in the builtin database list.
 *************************************************************************/

LOCAL_GRP *getbuiltinent(void *vp, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	return bidb_ops->getaliasent(vp, mem, num_mem);
}

/************************************************************************
 Routine to add an entry to the builtin database file.
*************************************************************************/

BOOL add_builtin_entry(LOCAL_GRP *newblt)
{
 	return bidb_ops->add_alias_entry(newblt);
}

/************************************************************************
 Routine to search the builtin database file for an entry matching the builtinname.
 and then replace the entry.
************************************************************************/

BOOL mod_builtin_entry(LOCAL_GRP* blt)
{
 	return bidb_ops->mod_alias_entry(blt);
}

/************************************************************************
 Routine to add a member to an entry in the builtin database file.
*************************************************************************/
BOOL add_builtin_member(uint32 rid, const DOM_SID *member_sid)
{
 	return bidb_ops->add_alias_member(rid, member_sid);
}

/************************************************************************
 Routine to delete a member from an entry in the builtindatabase file.
*************************************************************************/
BOOL del_builtin_member(uint32 rid, const DOM_SID *member_sid)
{
 	return bidb_ops->del_alias_member(rid, member_sid);
}

/************************************************************************
 Routine to search builtin database by name.
*************************************************************************/

LOCAL_GRP *getbuiltinntnam(const char *name, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	return bidb_ops->getaliasntnam(name, mem, num_mem);
}

/************************************************************************
 Routine to search builtin database by builtin rid.
*************************************************************************/

LOCAL_GRP *getbuiltinrid(uint32 builtin_rid, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	return bidb_ops->getaliasrid(builtin_rid, mem, num_mem);
}

/************************************************************************
 Routine to search builtin database by gid.
*************************************************************************/

LOCAL_GRP *getbuiltingid(gid_t gid, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	return bidb_ops->getaliasgid(gid, mem, num_mem);
}

/*************************************************************************
 gets an array of builtin aliases that a user is in.
 *************************************************************************/
BOOL getuserbuiltinntnam(const char *user_name, LOCAL_GRP **blt, int *num_blts)
{
	return bidb_ops->getuseraliasntnam(user_name, blt, num_blts);
}

/*************************************************************
 initialises a LOCAL_GRP.
 **************************************************************/
void bidb_init_blt(LOCAL_GRP *blt)
{
	if (blt == NULL) return;
	ZERO_STRUCTP(blt);
}

/*************************************************************
 turns an builtin entry into a string.
 **************************************************************/
BOOL make_builtin_line(char *p, int max_len,
				LOCAL_GRP *blt,
				LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	int i;
	int len;
	len = slprintf(p, max_len-1, "%s:%s:%d:", blt->name, blt->comment, blt->rid);

	if (len == -1)
	{
		DEBUG(0,("make_builtin_line: cannot create entry\n"));
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
			DEBUG(0, ("make_builtin_line: out of space for builtin aliases!\n"));
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
