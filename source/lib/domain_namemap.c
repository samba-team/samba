/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Groupname handling
   Copyright (C) Jeremy Allison 1998.
   
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

/* 
 * UNIX gid and Local or Domain SID resolution.  This module resolves
 * only those entries in the map files, it is *NOT* responsible for
 * resolving UNIX groups not listed: that is an entirely different
 * matter, altogether...
 */

/*
 *
 *

 format of the file is:

 unixname	NT Group name
 unixname	Domain Admins (well-known Domain Group)
 unixname	DOMAIN_NAME\NT Group name
 unixname	OTHER_DOMAIN_NAME\NT Group name
 unixname	DOMAIN_NAME\Domain Admins (well-known Domain Group)
 ....

 if the DOMAIN_NAME\ component is left off, then your own domain is assumed.

 *
 *
 */


#include "includes.h"

extern fstring global_myworkgroup;
extern DOM_SID global_member_sid;
extern fstring global_sam_name;
extern DOM_SID global_sam_sid;
extern DOM_SID global_sid_S_1_5_20;

/*******************************************************************
 converts UNIX uid to an NT User RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uid_t pwdb_user_rid_to_uid(uint32 user_rid)
{
	return ((user_rid & (~RID_TYPE_USER))- 1000)/RID_MULTIPLIER;
}

/*******************************************************************
 converts NT Group RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 pwdb_group_rid_to_gid(uint32 group_rid)
{
	return ((group_rid & (~RID_TYPE_GROUP))- 1000)/RID_MULTIPLIER;
}

/*******************************************************************
 converts NT Alias RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 pwdb_alias_rid_to_gid(uint32 alias_rid)
{
	return ((alias_rid & (~RID_TYPE_ALIAS))- 1000)/RID_MULTIPLIER;
}

/*******************************************************************
 converts NT Group RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 pwdb_gid_to_group_rid(uint32 gid)
{
	uint32 grp_rid = ((((gid)*RID_MULTIPLIER) + 1000) | RID_TYPE_GROUP);
	return grp_rid;
}

/******************************************************************
 converts UNIX gid to an NT Alias RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 pwdb_gid_to_alias_rid(uint32 gid)
{
	uint32 alias_rid = ((((gid)*RID_MULTIPLIER) + 1000) | RID_TYPE_ALIAS);
	return alias_rid;
}

/*******************************************************************
 converts UNIX uid to an NT User RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 pwdb_uid_to_user_rid(uint32 uid)
{
	uint32 user_rid = ((((uid)*RID_MULTIPLIER) + 1000) | RID_TYPE_USER);
	return user_rid;
}

/******************************************************************
 converts SID + SID_NAME_USE type to a UNIX id.  the Domain SID is,
 and can only be, our own SID.
 ********************************************************************/
static BOOL pwdb_sam_sid_to_unixid(DOM_SID *sid, uint8 type, uint32 *id)
{
	DOM_SID tmp_sid;
	uint32 rid;

	sid_copy(&tmp_sid, sid);
	sid_split_rid(&tmp_sid, &rid);
	if (!sid_equal(&global_sam_sid, &tmp_sid))
	{
		return False;
	}

	switch (type)
	{
		case SID_NAME_USER:
		{
			*id = pwdb_user_rid_to_uid(rid);
			return True;
		}
		case SID_NAME_ALIAS:
		{
			*id = pwdb_alias_rid_to_gid(rid);
			return True;
		}
		case SID_NAME_DOM_GRP:
		case SID_NAME_WKN_GRP:
		{
			*id = pwdb_group_rid_to_gid(rid);
			return True;
		}
	}
	return False;
}

/******************************************************************
 converts UNIX gid + SID_NAME_USE type to a SID.  the Domain SID is,
 and can only be, our own SID.
 ********************************************************************/
static BOOL pwdb_unixid_to_sam_sid(uint32 id, uint8 type, DOM_SID *sid)
{
	sid_copy(sid, &global_sam_sid);
	switch (type)
	{
		case SID_NAME_USER:
		{
			sid_append_rid(sid, pwdb_uid_to_user_rid(id));
			return True;
		}
		case SID_NAME_ALIAS:
		{
			sid_append_rid(sid, pwdb_gid_to_alias_rid(id));
			return True;
		}
		case SID_NAME_DOM_GRP:
		case SID_NAME_WKN_GRP:
		{
			sid_append_rid(sid, pwdb_gid_to_group_rid(id));
			return True;
		}
	}
	return False;
}

/*******************************************************************
 Decides if a RID is a well known RID.
 ********************************************************************/
static BOOL pwdb_rid_is_well_known(uint32 rid)
{
	return (rid < 1000);
}

/*******************************************************************
 determines a rid's type.  NOTE: THIS IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 pwdb_rid_type(uint32 rid)
{
	/* lkcl i understand that NT attaches an enumeration to a RID
	 * such that it can be identified as either a user, group etc
	 * type: SID_ENUM_TYPE.
	 */
	if (pwdb_rid_is_well_known(rid))
	{
		/*
		 * The only well known user RIDs are DOMAIN_USER_RID_ADMIN
		 * and DOMAIN_USER_RID_GUEST.
		 */
		if (rid == DOMAIN_USER_RID_ADMIN || rid == DOMAIN_USER_RID_GUEST)
		{
			return RID_TYPE_USER;
		}
		if (DOMAIN_GROUP_RID_ADMINS <= rid && rid <= DOMAIN_GROUP_RID_GUESTS)
		{
			return RID_TYPE_GROUP;
		}
		if (BUILTIN_ALIAS_RID_ADMINS <= rid && rid <= BUILTIN_ALIAS_RID_REPLICATOR)
		{
			return RID_TYPE_ALIAS;
		}
	}
	return (rid & RID_TYPE_MASK);
}

/*******************************************************************
 checks whether rid is a user rid.  NOTE: THIS IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
BOOL pwdb_rid_is_user(uint32 rid)
{
	return pwdb_rid_type(rid) == RID_TYPE_USER;
}

/**************************************************************************
 Groupname map functionality. The code loads a groupname map file and
 (currently) loads it into a linked list. This is slow and memory
 hungry, but can be changed into a more efficient storage format
 if the demands on it become excessive.
***************************************************************************/

typedef struct name_map
{
	ubi_slNode next;
	DOM_NAME_MAP grp;

} name_map_entry;

static ubi_slList groupname_map_list;
static ubi_slList aliasname_map_list;
static ubi_slList ntusrname_map_list;

static void delete_name_entry(name_map_entry *gmep)
{
	SAFE_FREE(gmep->grp.nt_name);
	SAFE_FREE(gmep->grp.nt_domain);
	SAFE_FREE(gmep->grp.unix_name);
	SAFE_FREE(gmep);
}

/**************************************************************************
 Delete all the entries in the name map list.
***************************************************************************/

static void delete_map_list(ubi_slList *map_list)
{
	name_map_entry *gmep;

	while ((gmep = (name_map_entry *)ubi_slRemHead(map_list )) != NULL)
	{
		delete_name_entry(gmep);
	}
}


/**************************************************************************
 makes a group sid out of a domain sid and a _unix_ gid.
***************************************************************************/
static BOOL make_mydomain_sid(DOM_NAME_MAP *grp, DOM_MAP_TYPE type)
{
	int ret = False;
	fstring sid_str;

	if (!map_domain_name_to_sid(&grp->sid, &(grp->nt_domain)))
	{
		DEBUG(0,("make_mydomain_sid: unknown domain %s\n",
			  grp->nt_domain));
		return False;
	}

	if (sid_equal(&grp->sid, &global_sid_S_1_5_20))
	{
		/*
		 * only builtin aliases are recognised in S-1-5-20
		 */
		DEBUG(10,("make_mydomain_sid: group %s in builtin domain\n",
		           grp->nt_name));

		if (lookup_builtin_alias_name(grp->nt_name, "BUILTIN", &grp->sid, &grp->type) != 0x0)
		{
			DEBUG(0,("unix group %s mapped to an unrecognised BUILTIN domain name %s\n",
			          grp->unix_name, grp->nt_name));
			return False;
		}
		ret = True;
	}
	else if (lookup_wk_user_name(grp->nt_name, grp->nt_domain, &grp->sid, &grp->type) == 0x0)
	{
		if (type != DOM_MAP_USER)
		{
			DEBUG(0,("well-known NT user %s\\%s listed in wrong map file\n",
			          grp->nt_domain, grp->nt_name));
			return False;
		}
		ret = True;
	}
	else if (lookup_wk_group_name(grp->nt_name, grp->nt_domain, &grp->sid, &grp->type) == 0x0)
	{
		if (type != DOM_MAP_DOMAIN)
		{
			DEBUG(0,("well-known NT group %s\\%s listed in wrong map file\n",
			          grp->nt_domain, grp->nt_name));
			return False;
		}
		ret = True;
	}
	else
	{
		switch (type)
		{
			case DOM_MAP_USER:
			{
				grp->type = SID_NAME_USER;
				break;
			}
			case DOM_MAP_DOMAIN:
			{
				grp->type = SID_NAME_DOM_GRP;
				break;
			}
			case DOM_MAP_LOCAL:
			{
				grp->type = SID_NAME_ALIAS;
				break;
			}
		}

		ret = pwdb_unixid_to_sam_sid(grp->unix_id, grp->type, &grp->sid);
	}

	sid_to_string(sid_str, &grp->sid);
	DEBUG(10,("nt name %s\\%s gid %d mapped to %s\n",
	           grp->nt_domain, grp->nt_name, grp->unix_id, sid_str));
	return ret;
}

/**************************************************************************
 makes a group sid out of an nt domain, nt group name or a unix group name.
***************************************************************************/
static BOOL unix_name_to_nt_name_info(DOM_NAME_MAP *map, DOM_MAP_TYPE type)
{
	/*
	 * Attempt to get the unix gid_t for this name.
	 */

	DEBUG(5,("unix_name_to_nt_name_info: unix_name:%s\n", map->unix_name));

	if (type == DOM_MAP_USER)
	{
		const struct passwd *pwptr = Get_Pwnam(map->unix_name, False);
		if (pwptr == NULL)
		{
			DEBUG(0,("unix_name_to_nt_name_info: Get_Pwnam for user %s\
failed. Error was %s.\n", map->unix_name, strerror(errno) ));
			return False;
		}

		map->unix_id = (uint32)pwptr->pw_uid;
	}
	else
	{
		struct group *gptr = getgrnam(map->unix_name);
		if (gptr == NULL)
		{
			DEBUG(0,("unix_name_to_nt_name_info: getgrnam for group %s\
failed. Error was %s.\n", map->unix_name, strerror(errno) ));
			return False;
		}

		map->unix_id = (uint32)gptr->gr_gid;
	}

	DEBUG(5,("unix_name_to_nt_name_info: unix gid:%d\n", map->unix_id));

	/*
	 * Now map the name to an NT SID+RID.
	 */

	if (map->nt_domain != NULL && !strequal(map->nt_domain, global_sam_name))
	{
		/* Must add client-call lookup code here, to 
		 * resolve remote domain's sid and the group's rid,
		 * in that domain.
		 *
		 * NOTE: it is _incorrect_ to put code here that assumes
		 * we are responsible for lookups for foriegn domains' RIDs.
		 *
		 * for foriegn domains for which we are *NOT* the PDC, all
		 * we can be responsible for is the unix gid_t to which
		 * the foriegn SID+rid maps to, on this _local_ machine.  
		 * we *CANNOT* make any short-cuts or assumptions about
		 * RIDs in a foriegn domain.
		 */

		if (!map_domain_name_to_sid(&map->sid, &(map->nt_domain)))
		{
			DEBUG(0,("unix_name_to_nt_name_info: no known sid for %s\n",
				  map->nt_domain));
			return False;
		}
	}

	return make_mydomain_sid(map, type);
}

static BOOL make_name_entry(name_map_entry **new_ep,
		char *nt_domain, char *nt_group, char *unix_group,
		DOM_MAP_TYPE type)
{
	/*
	 * Create the list entry and add it onto the list.
	 */

	DEBUG(5,("make_name_entry:%s,%s,%s\n", nt_domain, nt_group, unix_group));

	(*new_ep) = (name_map_entry *)malloc(sizeof(name_map_entry));
	if ((*new_ep) == NULL)
	{
		DEBUG(0,("make_name_entry: malloc fail for name_map_entry.\n"));
		return False;
	} 

	ZERO_STRUCTP(*new_ep);

	(*new_ep)->grp.nt_name   = strdup(nt_group  );
	(*new_ep)->grp.nt_domain = strdup(nt_domain );
	(*new_ep)->grp.unix_name = strdup(unix_group);

	if ((*new_ep)->grp.nt_name   == NULL ||
	    (*new_ep)->grp.unix_name == NULL)
	{
		DEBUG(0,("make_name_entry: malloc fail for names in name_map_entry.\n"));
		delete_name_entry((*new_ep));
		return False;
	}

	/*
	 * look up the group names, make the Group-SID and unix gid
	 */
 
	if (!unix_name_to_nt_name_info(&(*new_ep)->grp, type))
	{
		delete_name_entry((*new_ep));
		return False;
	}

	return True;
}

/**************************************************************************
 Load a name map file. Sets last accessed timestamp.
***************************************************************************/
static ubi_slList *load_name_map(DOM_MAP_TYPE type)
{
	static time_t groupmap_file_last_modified = (time_t)0;
	static time_t aliasmap_file_last_modified = (time_t)0;
	static time_t ntusrmap_file_last_modified  = (time_t)0;
	static BOOL initialised_group = False;
	static BOOL initialised_alias = False;
	static BOOL initialised_ntusr  = False;
	char *groupname_map_file = lp_groupname_map();
	char *aliasname_map_file = lp_aliasname_map();
	char *ntusrname_map_file = lp_ntusrname_map();

	FILE *fp;
	char *s;
	pstring buf;
	name_map_entry *new_ep;

	time_t *file_last_modified = NULL;
	int    *initialised = NULL;
	char   *map_file = NULL;
	ubi_slList *map_list = NULL;

	switch (type)
	{
		case DOM_MAP_DOMAIN:
		{
			file_last_modified = &groupmap_file_last_modified;
			initialised        = &initialised_group;
			map_file           = groupname_map_file;
			map_list           = &groupname_map_list;

			break;
		}
		case DOM_MAP_LOCAL:
		{
			file_last_modified = &aliasmap_file_last_modified;
			initialised        = &initialised_alias;
			map_file           = aliasname_map_file;
			map_list           = &aliasname_map_list;

			break;
		}
		case DOM_MAP_USER:
		{
			file_last_modified = &ntusrmap_file_last_modified;
			initialised        = &initialised_ntusr;
			map_file           = ntusrname_map_file;
			map_list           = &ntusrname_map_list;

			break;
		}
	}

	if (!(*initialised))
	{
		DEBUG(10,("initialising map %s\n", map_file));
		ubi_slInitList(map_list);
		(*initialised) = True;
	}

	if (!*map_file)
	{
		return map_list;
	}

	/*
	 * Load the file.
	 */

	fp = open_file_if_modified(map_file, "r", file_last_modified);
	if (!fp)
	{
		return map_list;
	}

	/*
	 * Throw away any previous list.
	 */
	delete_map_list(map_list);

	DEBUG(4,("load_name_map: Scanning name map %s\n",map_file));

	while ((s = fgets_slash(buf, sizeof(buf), fp)) != NULL)
	{
		pstring unixname;
		pstring nt_name;
		fstring nt_domain;
		fstring ntname;
		char *p;

		DEBUG(10,("Read line |%s|\n", s));

		memset(nt_name, 0, sizeof(nt_name));

		if (!*s || strchr("#;",*s))
			continue;

		if (!next_token(&s,unixname, "\t\n\r=", sizeof(unixname)))
			continue;

		if (!next_token(&s,nt_name, "\t\n\r=", sizeof(nt_name)))
			continue;

		trim_string(unixname, " ", " ");
		trim_string(nt_name, " ", " ");

		if (!*nt_name)
			continue;

		if (!*unixname)
			continue;

		p = strchr(nt_name, '\\');

		if (p == NULL)
		{
			memset(nt_domain, 0, sizeof(nt_domain));
			fstrcpy(ntname, nt_name);
		}
		else
		{
			*p = 0;
			p++;
			fstrcpy(nt_domain, nt_name);
			fstrcpy(ntname , p);
		}

		if (make_name_entry(&new_ep, nt_domain, ntname, unixname, type))
		{
			ubi_slAddTail(map_list, (ubi_slNode *)new_ep);
			DEBUG(5,("unixname = %s, ntname = %s\\%s type = %d\n",
				  new_ep->grp.unix_name,
			          new_ep->grp.nt_domain,
			          new_ep->grp.nt_name,
			          new_ep->grp.type));
		}
	}

	DEBUG(10,("load_name_map: Added %ld entries to name map.\n",
	           ubi_slCount(map_list)));

	fclose(fp);

	return map_list;
}

static void copy_grp_map_entry(DOM_NAME_MAP *grp, const DOM_NAME_MAP *from)
{
	sid_copy(&grp->sid, &from->sid);
	grp->unix_id   = from->unix_id;
	grp->nt_name   = from->nt_name;
	grp->nt_domain = from->nt_domain;
	grp->unix_name = from->unix_name;
	grp->type      = from->type;
}

#if 0
/***********************************************************
 Lookup unix name.
************************************************************/
static BOOL map_unixname(DOM_MAP_TYPE type,
		char *unixname, DOM_NAME_MAP *grp_info)
{
	name_map_entry *gmep;
	ubi_slList *map_list;

	/*
	 * Initialise and load if not already loaded.
	 */
	map_list = load_name_map(type);

	for (gmep = (name_map_entry *)ubi_slFirst(map_list);
	     gmep != NULL;
	     gmep = (name_map_entry *)ubi_slNext(gmep ))
	{
		if (strequal(gmep->grp.unix_name, unixname))
		{
			copy_grp_map_entry(grp_info, &gmep->grp);
			DEBUG(7,("map_unixname: Mapping unix name %s to nt group %s.\n",
			       gmep->grp.unix_name, gmep->grp.nt_name ));
			return True;
		}
	}

	return False;
}

#endif

/***********************************************************
 Lookup nt name.
************************************************************/
static BOOL map_ntname(DOM_MAP_TYPE type, char *ntname, char *ntdomain,
				DOM_NAME_MAP *grp_info)
{
	name_map_entry *gmep;
	ubi_slList *map_list;

	/*
	 * Initialise and load if not already loaded.
	 */
	map_list = load_name_map(type);

	for (gmep = (name_map_entry *)ubi_slFirst(map_list);
	     gmep != NULL;
	     gmep = (name_map_entry *)ubi_slNext(gmep ))
	{
		if (strequal(gmep->grp.nt_name  , ntname) &&
		    strequal(gmep->grp.nt_domain, ntdomain))
		{
			copy_grp_map_entry(grp_info, &gmep->grp);
			DEBUG(7,("map_ntname: Mapping unix name %s to nt name %s.\n",
			       gmep->grp.unix_name, gmep->grp.nt_name ));
			return True;
		}
	}

	return False;
}


/***********************************************************
 Lookup by SID
************************************************************/
static BOOL map_sid(DOM_MAP_TYPE type,
		DOM_SID *psid, DOM_NAME_MAP *grp_info)
{
	name_map_entry *gmep;
	ubi_slList *map_list;

	/*
	 * Initialise and load if not already loaded.
	 */
	map_list = load_name_map(type);

	for (gmep = (name_map_entry *)ubi_slFirst(map_list);
	     gmep != NULL;
	     gmep = (name_map_entry *)ubi_slNext(gmep ))
	{
		if (sid_equal(&gmep->grp.sid, psid))
		{
			copy_grp_map_entry(grp_info, &gmep->grp);
			DEBUG(7,("map_sid: Mapping unix name %s to nt name %s.\n",
			       gmep->grp.unix_name, gmep->grp.nt_name ));
			return True;
		}
	}

	return False;
}

/***********************************************************
 Lookup by gid_t.
************************************************************/
static BOOL map_unixid(DOM_MAP_TYPE type, uint32 unix_id, DOM_NAME_MAP *grp_info)
{
	name_map_entry *gmep;
	ubi_slList *map_list;

	/*
	 * Initialise and load if not already loaded.
	 */
	map_list = load_name_map(type);

	for (gmep = (name_map_entry *)ubi_slFirst(map_list);
	     gmep != NULL;
	     gmep = (name_map_entry *)ubi_slNext(gmep ))
	{
		fstring sid_str;
		sid_to_string(sid_str, &gmep->grp.sid);
		DEBUG(10,("map_unixid: enum entry unix group %s %d nt %s %s\n",
			       gmep->grp.unix_name, gmep->grp.unix_id, gmep->grp.nt_name, sid_str));
		if (gmep->grp.unix_id == unix_id)
		{
			copy_grp_map_entry(grp_info, &gmep->grp);
			DEBUG(7,("map_unixid: Mapping unix name %s to nt name %s type %d\n",
			       gmep->grp.unix_name, gmep->grp.nt_name, gmep->grp.type));
			return True;
		}
	}

	return False;
}

/***********************************************************
 *
 * Call four functions to resolve unix group ids and either
 * local group SIDs or domain group SIDs listed in the local group
 * or domain group map files.
 *
 * Note that it is *NOT* the responsibility of these functions to
 * resolve entries that are not in the map files.
 *
 * Any SID can be in the map files (i.e from any Domain).
 *
 ***********************************************************/

#if 0

/***********************************************************
 Lookup a UNIX Group entry by name.
************************************************************/
BOOL map_unix_group_name(char *group_name, DOM_NAME_MAP *grp_info)
{
	return map_unixname(DOM_MAP_DOMAIN, group_name, grp_info);
}

/***********************************************************
 Lookup a UNIX Alias entry by name.
************************************************************/
BOOL map_unix_alias_name(char *alias_name, DOM_NAME_MAP *grp_info)
{
	return map_unixname(DOM_MAP_LOCAL, alias_name, grp_info);
}

/***********************************************************
 Lookup an Alias name entry 
************************************************************/
BOOL map_nt_alias_name(char *ntalias_name, char *nt_domain, DOM_NAME_MAP *grp_info)
{
	return map_ntname(DOM_MAP_LOCAL, ntalias_name, nt_domain, grp_info);
}

/***********************************************************
 Lookup a Group entry
************************************************************/
BOOL map_nt_group_name(char *ntgroup_name, char *nt_domain, DOM_NAME_MAP *grp_info)
{
	return map_ntname(DOM_MAP_DOMAIN, ntgroup_name, nt_domain, grp_info);
}

#endif

/***********************************************************
 Lookup a Username entry by name.
************************************************************/
static BOOL map_nt_username(char *nt_name, char *nt_domain, DOM_NAME_MAP *grp_info)
{
	return map_ntname(DOM_MAP_USER, nt_name, nt_domain, grp_info);
}

/***********************************************************
 Lookup a Username entry by SID.
************************************************************/
static BOOL map_username_sid(DOM_SID *sid, DOM_NAME_MAP *grp_info)
{
	return map_sid(DOM_MAP_USER, sid, grp_info);
}

/***********************************************************
 Lookup a Username SID entry by uid.
************************************************************/
static BOOL map_username_uid(uid_t gid, DOM_NAME_MAP *grp_info)
{
	return map_unixid(DOM_MAP_USER, (uint32)gid, grp_info);
}

/***********************************************************
 Lookup an Alias SID entry by name.
************************************************************/
BOOL map_alias_sid(DOM_SID *psid, DOM_NAME_MAP *grp_info)
{
	return map_sid(DOM_MAP_LOCAL, psid, grp_info);
}

/***********************************************************
 Lookup a Group entry by sid.
************************************************************/
BOOL map_group_sid(DOM_SID *psid, DOM_NAME_MAP *grp_info)
{
	return map_sid(DOM_MAP_DOMAIN, psid, grp_info);
}

/***********************************************************
 Lookup an Alias SID entry by gid_t.
************************************************************/
static BOOL map_alias_gid(gid_t gid, DOM_NAME_MAP *grp_info)
{
	return map_unixid(DOM_MAP_LOCAL, (uint32)gid, grp_info);
}

/***********************************************************
 Lookup a Group SID entry by gid_t.
************************************************************/
static BOOL map_group_gid( gid_t gid, DOM_NAME_MAP *grp_info)
{
	return map_unixid(DOM_MAP_DOMAIN, (uint32)gid, grp_info);
}


/************************************************************************
 Routine to look up User details by UNIX name
*************************************************************************/
BOOL lookupsmbpwnam(const char *unix_usr_name, DOM_NAME_MAP *grp)
{
	uid_t uid;
	DEBUG(10,("lookupsmbpwnam: unix user name %s\n", unix_usr_name));
	if (nametouid(unix_usr_name, &uid))
	{
		return lookupsmbpwuid(uid, grp);
	}
	else
	{
		return False;
	}
}

/************************************************************************
 Routine to look up a remote nt name
*************************************************************************/
static BOOL lookup_remote_ntname(const char *ntname, DOM_SID *sid, uint8 *type)
{
	struct cli_state cli;
	POLICY_HND lsa_pol;
	fstring srv_name;
	extern struct ntuser_creds *usr_creds;
	struct ntuser_creds usr;

	BOOL res3 = True;
	BOOL res4 = True;
	uint32 num_sids;
	DOM_SID *sids;
	uint8 *types;
	char *names[1];

	usr_creds = &usr;

	ZERO_STRUCT(usr);
	pwd_set_nullpwd(&usr.pwd);

	DEBUG(5,("lookup_remote_ntname: %s\n", ntname));

	if (!cli_connect_serverlist(&cli, lp_passwordserver()))
	{
		return False;
	}

	names[0] = ntname;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, cli.desthost);
	strupper(srv_name);

	/* lookup domain controller; receive a policy handle */
	res3 = res3 ? lsa_open_policy( srv_name,
				&lsa_pol, True) : False;

	/* send lsa lookup sids call */
	res4 = res3 ? lsa_lookup_names( &lsa_pol,
				       1, names, 
				       &sids, &types, &num_sids) : False;

	res3 = res3 ? lsa_close(&lsa_pol) : False;

	if (res4 && res3 && sids != NULL && types != NULL)
	{
		sid_copy(sid, &sids[0]);
		*type = types[0];
	}
	else
	{
		res3 = False;
	}
	SAFE_FREE(types);
	SAFE_FREE(sids);
	
	return res3 && res4;
}

/************************************************************************
 Routine to look up a remote nt name
*************************************************************************/
static BOOL get_sid_and_type(const char *fullntname, uint8 expected_type,
				DOM_NAME_MAP *gmep)
{
	/*
	 * check with the PDC to see if it owns the name.  if so,
	 * the SID is resolved with the PDC database.
	 */

	if (lp_server_role() == ROLE_DOMAIN_MEMBER)
	{
		if (lookup_remote_ntname(fullntname, &gmep->sid, &gmep->type))
		{
			if (sid_front_equal(&gmep->sid, &global_member_sid) &&
			    strequal(gmep->nt_domain, global_myworkgroup) &&
			    gmep->type == expected_type)
			{
				return True;
			}
			return False;
		}
	}

	/*
	 * ... otherwise, it's one of ours.  map the sid ourselves,
	 * which can only happen in our own SAM database.
	 */

	if (!strequal(gmep->nt_domain, global_sam_name))
	{
		return False;
	}
	if (!pwdb_unixid_to_sam_sid(gmep->unix_id, gmep->type, &gmep->sid))
	{
		return False;
	}

	return True;
}

/*
 * used by lookup functions below
 */

static fstring nt_name;
static fstring unix_name;
static fstring nt_domain;

/*************************************************************************
 looks up a uid, returns User Information.  
*************************************************************************/
BOOL lookupsmbpwuid(uid_t uid, DOM_NAME_MAP *gmep)
{
	DEBUG(10,("lookupsmbpwuid: unix uid %d\n", uid));
	if (map_username_uid(uid, gmep))
	{
		return True;
	}
#if 0
	if (lp_server_role() != ROLE_DOMAIN_NONE)
#endif
	{
		gmep->nt_name   = nt_name;
		gmep->unix_name = unix_name;
		gmep->nt_domain = nt_domain;

		gmep->unix_id = (uint32)uid;

		/*
		 * ok, assume it's one of ours.  then double-check it
		 * if we are a member of a domain
		 */

		gmep->type = SID_NAME_USER;
		fstrcpy(gmep->nt_name, uidtoname(uid));
		fstrcpy(gmep->unix_name, gmep->nt_name);

		/*
		 * here we should do a LsaLookupNames() call
		 * to check the status of the name with the PDC.
		 * if the PDC know nothing of the name, it's ours.
		 */

		if (lp_server_role() == ROLE_DOMAIN_MEMBER)
		{
#if 0
			lsa_lookup_names(global_myworkgroup, gmep->nt_name, &gmep->sid...);
#endif
		}

		/*
		 * ok, it's one of ours.
		 */

		gmep->nt_domain = global_sam_name;
		pwdb_unixid_to_sam_sid(gmep->unix_id, gmep->type, &gmep->sid);

		return True;
	}

	/* oops. */

	return False;
}

/*************************************************************************
 looks up by NT name, returns User Information.  
*************************************************************************/
BOOL lookupsmbpwntnam(const char *fullntname, DOM_NAME_MAP *gmep)
{
	DEBUG(10,("lookupsmbpwntnam: nt user name %s\n", fullntname));

	if (!split_domain_name(fullntname, nt_domain, nt_name))
	{
		return False;
	}

	if (map_nt_username(nt_name, nt_domain, gmep))
	{
		return True;
	}
	if (lp_server_role() != ROLE_DOMAIN_NONE)
	{
		uid_t uid;
		gmep->nt_name   = nt_name;
		gmep->unix_name = unix_name;
		gmep->nt_domain = nt_domain;

		/*
		 * ok, it's one of ours.  we therefore "create" an nt user named
		 * after the unix user.  this is the point where "appliance mode"
		 * should get its teeth in, as unix users won't really exist,
		 * they will only be numbers...
		 */

		gmep->type = SID_NAME_USER;
		fstrcpy(gmep->unix_name, gmep->nt_name);
		if (!nametouid(gmep->unix_name, &uid))
		{
			return False;
		}
		gmep->unix_id = (uint32)uid;

		return get_sid_and_type(fullntname, gmep->type, gmep);
	}

	/* oops. */

	return False;
}

/*************************************************************************
 looks up by RID, returns User Information.  
*************************************************************************/
BOOL lookupsmbpwsid(DOM_SID *sid, DOM_NAME_MAP *gmep)
{
	fstring sid_str;
	sid_to_string(sid_str, sid);
	DEBUG(10,("lookupsmbpwsid: nt sid %s\n", sid_str));

	if (map_username_sid(sid, gmep))
	{
		return True;
	}
	if (lp_server_role() != ROLE_DOMAIN_NONE)
	{
		gmep->nt_name   = nt_name;
		gmep->unix_name = unix_name;
		gmep->nt_domain = nt_domain;

		/*
		 * here we should do a LsaLookupNames() call
		 * to check the status of the name with the PDC.
		 * if the PDC know nothing of the name, it's ours.
		 */

		if (lp_server_role() == ROLE_DOMAIN_MEMBER)
		{
#if 0
			if (lookup_remote_sid(global_myworkgroup, gmep->sid, gmep->nt_name, gmep->nt_domain...);
#endif
		}

		/*
		 * ok, it's one of ours.  we therefore "create" an nt user named
		 * after the unix user.  this is the point where "appliance mode"
		 * should get its teeth in, as unix users won't really exist,
		 * they will only be numbers...
		 */

		gmep->type = SID_NAME_USER;
		sid_copy(&gmep->sid, sid);
		if (!pwdb_sam_sid_to_unixid(&gmep->sid, gmep->type, &gmep->unix_id))
		{
			return False;
		}
		fstrcpy(gmep->nt_name, uidtoname((uid_t)gmep->unix_id));
		fstrcpy(gmep->unix_name, gmep->nt_name);
		gmep->nt_domain = global_sam_name;

		return True;
	}

	/* oops. */

	return False;
}

/************************************************************************
 Routine to look up group / alias / well-known group RID by UNIX name
*************************************************************************/
BOOL lookupsmbgrpnam(const char *unix_grp_name, DOM_NAME_MAP *grp)
{
	gid_t gid;
	DEBUG(10,("lookupsmbgrpnam: unix user group %s\n", unix_grp_name));
	if (nametogid(unix_grp_name, &gid))
	{
		return lookupsmbgrpgid(gid, grp);
	}
	else
	{
		return False;
	}
}

/*************************************************************************
 looks up a SID, returns name map entry
*************************************************************************/
BOOL lookupsmbgrpsid(DOM_SID *sid, DOM_NAME_MAP *gmep)
{
	fstring sid_str;
	sid_to_string(sid_str, sid);
	DEBUG(10,("lookupsmbgrpsid: nt sid %s\n", sid_str));

	if (map_alias_sid(sid, gmep))
	{
		return True;
	}
	if (map_group_sid(sid, gmep))
	{
		return True;
	}
	if (lp_server_role() != ROLE_DOMAIN_NONE)
	{
		gmep->nt_name   = nt_name;
		gmep->unix_name = unix_name;
		gmep->nt_domain = nt_domain;

		/*
		 * here we should do a LsaLookupNames() call
		 * to check the status of the name with the PDC.
		 * if the PDC know nothing of the name, it's ours.
		 */

		if (lp_server_role() == ROLE_DOMAIN_MEMBER)
		{
#if 0
			lsa_lookup_sids(global_myworkgroup, gmep->sid, gmep->nt_name, gmep->nt_domain...);
#endif
		}

		/*
		 * ok, it's one of ours.  we therefore "create" an nt group or
		 * alias name named after the unix group.  this is the point
		 * where "appliance mode" should get its teeth in, as unix
		 * groups won't really exist, they will only be numbers...
		 */

		/* name is not explicitly mapped
		 * with map files or the PDC
		 * so we are responsible for it...
		 */

		if (lp_server_role() == ROLE_DOMAIN_MEMBER)
		{
		 	/* ... as a LOCAL group. */
			gmep->type = SID_NAME_ALIAS;
		}
		else
		{
		 	/* ... as a DOMAIN group. */
			gmep->type = SID_NAME_DOM_GRP;
		}

		sid_copy(&gmep->sid, sid);
		if (!pwdb_sam_sid_to_unixid(&gmep->sid, gmep->type, &gmep->unix_id))
		{
			return False;
		}
		fstrcpy(gmep->nt_name, gidtoname((gid_t)gmep->unix_id));
		fstrcpy(gmep->unix_name, gmep->nt_name);
		gmep->nt_domain = global_sam_name;

		return True;
	}

	/* oops */
	return False;
}

/*************************************************************************
 looks up a gid, returns RID and type local, domain or well-known domain group
*************************************************************************/
BOOL lookupsmbgrpgid(gid_t gid, DOM_NAME_MAP *gmep)
{
	DEBUG(10,("lookupsmbgrpgid: unix gid %d\n", (int)gid));
	if (map_alias_gid(gid, gmep))
	{
		return True;
	}
	if (map_group_gid(gid, gmep))
	{
		return True;
	}
	if (lp_server_role() != ROLE_DOMAIN_NONE)
	{
		gmep->nt_name   = nt_name;
		gmep->unix_name = unix_name;
		gmep->nt_domain = nt_domain;

		gmep->unix_id = (uint32)gid;

		/*
		 * here we should do a LsaLookupNames() call
		 * to check the status of the name with the PDC.
		 * if the PDC know nothing of the name, it's ours.
		 */

		if (lp_server_role() == ROLE_DOMAIN_MEMBER)
		{
#if 0
			if (lsa_lookup_names(global_myworkgroup, gmep->nt_name, &gmep->sid...);
			{
				return True;
			}
#endif
		}

		/*
		 * ok, it's one of ours.  we therefore "create" an nt group or
		 * alias name named after the unix group.  this is the point
		 * where "appliance mode" should get its teeth in, as unix
		 * groups won't really exist, they will only be numbers...
		 */

		/* name is not explicitly mapped
		 * with map files or the PDC
		 * so we are responsible for it...
		 */

		if (lp_server_role() == ROLE_DOMAIN_MEMBER)
		{
		 	/* ... as a LOCAL group. */
			gmep->type = SID_NAME_ALIAS;
		}
		else
		{
		 	/* ... as a DOMAIN group. */
			gmep->type = SID_NAME_DOM_GRP;
		}
		fstrcpy(gmep->nt_name, gidtoname(gid));
		fstrcpy(gmep->unix_name, gmep->nt_name);

		return get_sid_and_type(gmep->nt_name, gmep->type, gmep);
	}

	/* oops */
	return False;
}

