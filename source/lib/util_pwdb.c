/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Jeremy Allison 1996-1998
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
extern DOM_SID global_sam_sid;
extern fstring global_sam_name;

extern DOM_SID global_member_sid;
extern fstring global_myworkgroup;

extern DOM_SID global_sid_S_1_5_20;

extern pstring global_myname;

typedef struct
{
	uint32 rid;
	char *defaultname;
	char *name;
} rid_name;

/*
 * A list of the rids of well known BUILTIN and Domain users
 * and groups.
 */

static rid_name builtin_alias_rids[] =
{  
    { BUILTIN_ALIAS_RID_ADMINS       , "Administrators"    , NULL },
    { BUILTIN_ALIAS_RID_USERS        , "Users"             , NULL },
    { BUILTIN_ALIAS_RID_GUESTS       , "Guests"            , NULL },
    { BUILTIN_ALIAS_RID_POWER_USERS  , "Power Users"       , NULL },
   
    { BUILTIN_ALIAS_RID_ACCOUNT_OPS  , "Account Operators" , NULL },
    { BUILTIN_ALIAS_RID_SYSTEM_OPS   , "System Operators"  , NULL },
    { BUILTIN_ALIAS_RID_PRINT_OPS    , "Print Operators"   , NULL },
    { BUILTIN_ALIAS_RID_BACKUP_OPS   , "Backup Operators"  , NULL },
    { BUILTIN_ALIAS_RID_REPLICATOR   , "Replicator"        , NULL },
    { 0                              , NULL                , NULL}
};

/* array lookup of well-known Domain RID users. */
static rid_name domain_user_rids[] =
{  
    { DOMAIN_USER_RID_ADMIN         , "Administrator" , NULL },
    { DOMAIN_USER_RID_GUEST         , "Guest"         , NULL },
    { 0                             , NULL            , NULL}
};

/* array lookup of well-known Domain RID groups. */
static rid_name domain_group_rids[] =
{  
    { DOMAIN_GROUP_RID_ADMINS       , "Domain Admins" , NULL },
    { DOMAIN_GROUP_RID_USERS        , "Domain Users"  , NULL },
    { DOMAIN_GROUP_RID_GUESTS       , "Domain Guests" , NULL },
    { 0                             , NULL            , NULL}
};

/*******************************************************************
  make an entry in wk name map
  the name is strdup()ed!
 *******************************************************************/
static BOOL make_alias_entry(rid_name *map, char *defaultname, char *name)
{
	if(isdigit(*defaultname))
	{
		long rid = -1;
		char *s;

		if(*defaultname == '0')
		{
			if(defaultname[1] == 'x')
			{
				s = "%lx";
				defaultname += 2;
			}
			else
			{
				s = "%lo";
			}
		}
		else
		{
			s = "%ld";
		}

		sscanf(defaultname, s, &rid);

		for( ; map->rid; map++)
		{
			if(map->rid == rid) {
				map->name = strdup(name);
				DEBUG(5, ("make_alias_entry: mapping %s (rid 0x%x) to %s\n",
				      map->defaultname, map->rid, map->name));
				return True;
			}
		}
		return False;
	}

	for( ; map->rid; map++)
	{
		if(!StrCaseCmp(map->name, defaultname)) {
			map->name = strdup(name);
			DEBUG(5, ("make_alias_entry: mapping %s (rid 0x%x) to %s\n",
			      map->defaultname, map->rid, map->name));
			return True;
		}
	}
	return False;
}

/*******************************************************************
  reset wk map to default values
 *******************************************************************/
static void reset_wk_map(rid_name *map)
{
	for( ; map->rid; map++)
	{
		if(map->name != NULL && map->name != map->defaultname)
			free(map->name);
		map->name = map->defaultname;
	}
}

/*******************************************************************
  reset all wk maps
 *******************************************************************/
static void reset_wk_maps(void)
{
	DEBUG(4, ("reset_wk_maps: Initializing maps\n"));
	reset_wk_map(builtin_alias_rids);
	reset_wk_map(domain_user_rids);
	reset_wk_map(domain_group_rids);
}

/*******************************************************************
  Load builtin alias map
 *******************************************************************/
static BOOL load_wk_rid_map(void)
{
	static int map_initialized = 0;
	static time_t builtin_rid_file_last_modified = (time_t)0;
	char *builtin_rid_file = lp_builtinrid_file();

	FILE *fp;
	char *s;
	pstring buf;

	if (!map_initialized)
	{
		reset_wk_maps();
		map_initialized = 1;
	}

	if (!*builtin_rid_file)
	{
		return False;
	}

	fp = open_file_if_modified(builtin_rid_file, "r", &builtin_rid_file_last_modified);
	if(!fp)
	{
		DEBUG(0,("load_wk_rid_map: can't open name map %s. Error was %s\n",
			  builtin_rid_file, strerror(errno)));
		 return False;
	}

	reset_wk_maps();
	DEBUG(4,("load_wk_rid_map: Scanning builtin rid map %s\n",builtin_rid_file));

	while ((s = fgets_slash(buf, sizeof(buf), fp)) != NULL)
	{
		pstring defaultname;
		pstring name;

		DEBUG(10,("Read line |%s|\n", s));

		if (!*s || strchr("#;",*s))
			continue;

		if (!next_token(&s,name, "\t\n\r=", sizeof(defaultname)))
			continue;

		if (!next_token(&s,defaultname, "\t\n\r=", sizeof(name)))
			continue;

		trim_string(defaultname, " ", " ");
		trim_string(name, " ", " ");

		if (!*defaultname || !*name)
			continue;

		if(make_alias_entry(builtin_alias_rids, defaultname, name))
			continue;
		if(make_alias_entry(domain_user_rids, defaultname, name))
			continue;
		if(make_alias_entry(domain_group_rids, defaultname, name))
			continue;

		DEBUG(0,("load_wk_rid_map: Unknown alias %s in map %s\n",
		         defaultname, builtin_rid_file));
	}

	fclose(fp);
	return True;
}

/*******************************************************************
 lookup_wk_group_name
 ********************************************************************/
uint32 lookup_wk_group_name(const char *group_name, const char *domain,
				DOM_SID *sid, uint8 *type)
{
	char *grp_name;
	int i = -1; /* start do loop at -1 */
	uint32 rid;

	if (strequal(domain, global_sam_name))
	{
		sid_copy(sid, &global_sam_sid);
	}
	else if (strequal(domain, "BUILTIN"))
	{
		sid_copy(sid, &global_sid_S_1_5_20);
	}
	else
	{
		return 0xC0000000 | NT_STATUS_NONE_MAPPED;
	}

	load_wk_rid_map();

	do /* find, if it exists, a group rid for the group name */
	{
		i++;
		rid      = domain_group_rids[i].rid;
		grp_name = domain_group_rids[i].name;

		if (strequal(grp_name, group_name))
		{
			sid_append_rid(sid, rid);
			(*type) = SID_NAME_DOM_GRP;

			return 0x0;
		}
			
	} while (grp_name != NULL);

	return 0xC0000000 | NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_wk_user_name
 ********************************************************************/
uint32 lookup_wk_user_name(const char *user_name, const char *domain,
				DOM_SID *sid, uint8 *type)
{
	char *usr_name;
	int i = -1; /* start do loop at -1 */

	if (strequal(domain, global_sam_name))
	{
		sid_copy(sid, &global_sam_sid);
	}
	else if (strequal(domain, "BUILTIN"))
	{
		sid_copy(sid, &global_sid_S_1_5_20);
	}
	else
	{
		return 0xC0000000 | NT_STATUS_NONE_MAPPED;
	}

	load_wk_rid_map();

	do /* find, if it exists, a alias rid for the alias name */
	{
		i++;
		usr_name = domain_user_rids[i].name;

	} while (usr_name != NULL && !strequal(usr_name, user_name));

	if (usr_name != NULL)
	{
		sid_append_rid(sid, domain_user_rids[i].rid);
		(*type) = SID_NAME_USER;
		return 0;
	}

	return 0xC0000000 | NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_builtin_alias_name
 ********************************************************************/
uint32 lookup_builtin_alias_name(const char *alias_name, const char *domain,
				DOM_SID *sid, uint8 *type)
{
	char *als_name;
	int i = 0;
	uint32 rid;

	if (strequal(domain, "BUILTIN"))
	{
		if (sid != NULL)
		{
			sid_copy(sid, &global_sid_S_1_5_20);
		}
	}
	else
	{
		return 0xC0000000 | NT_STATUS_NONE_MAPPED;
	}

	load_wk_rid_map();

	do /* find, if it exists, a alias rid for the alias name*/
	{
		rid      = builtin_alias_rids[i].rid;
		als_name = builtin_alias_rids[i].name;

		if (strequal(als_name, alias_name))
		{
			if (sid != NULL)
			{
				sid_append_rid(sid, rid);
			}

			if (type != NULL)
			{
				(*type) = SID_NAME_ALIAS;
			}

			return 0x0;
		}
			
		i++;

	} while (als_name != NULL);

	return 0xC0000000 | NT_STATUS_NONE_MAPPED;
}

/*************************************************************
 the following functions lookup wk rid's.
 these may be unnecessary...
**************************************************************/
static char *lookup_wk_rid(uint32 rid, rid_name *table)
{
	load_wk_rid_map();
	for( ; table->rid ; table++)
	{
		if(table->rid == rid)
		{
			return table->name;
		}
	}
	return NULL;
}

char *lookup_wk_alias_rid(uint32 rid)
{
	return lookup_wk_rid(rid, builtin_alias_rids);
}

char *lookup_wk_user_rid(uint32 rid)
{
	return lookup_wk_rid(rid, domain_user_rids);
}

char *lookup_wk_group_rid(uint32 rid)
{
	return lookup_wk_rid(rid, domain_group_rids);
}
