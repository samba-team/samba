/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Groupname handling
   Copyright (C) Jeremy Allison               1998-2000.
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000.
   
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
#include "rpc_client.h"
#include "sids.h"

extern int DEBUGLEVEL;

extern fstring global_myworkgroup;

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

}
name_map_entry;

static ubi_slList groupname_map_list;
static ubi_slList aliasname_map_list;
static ubi_slList ntusrname_map_list;

static void delete_name_entry(name_map_entry * gmep)
{
	if (gmep->grp.nt_name)
	{
		free(gmep->grp.nt_name);
	}
	if (gmep->grp.nt_domain)
	{
		free(gmep->grp.nt_domain);
	}
	if (gmep->grp.unix_name)
	{
		free(gmep->grp.unix_name);
	}
	free((char *)gmep);
}

/**************************************************************************
 Delete all the entries in the name map list.
***************************************************************************/

static void delete_map_list(ubi_slList * map_list)
{
	name_map_entry *gmep;

	while ((gmep = (name_map_entry *) ubi_slRemHead(map_list)) != NULL)
	{
		delete_name_entry(gmep);
	}
}

static void map_posix_to_nt_type( DOM_NAME_MAP * gmep, int type)
{
	if (type == SURS_POSIX_UID)
	{
		gmep->type = SID_NAME_USER;
	}
	else
	{
		if (lp_server_role() == ROLE_DOMAIN_MEMBER ||
		    lp_server_role() == ROLE_STANDALONE)
		{
			/* ... as a LOCAL group. */
			gmep->type = SID_NAME_ALIAS;
		}
		else
		{
			/* ... as a DOMAIN group. */
			gmep->type = SID_NAME_DOM_GRP;
		}
	}
}

/************************************************************************
 Routine to look up a remote nt name
*************************************************************************/
static BOOL get_sid( DOM_NAME_MAP * gmep, int type)
{
	SURS_POSIX_ID id;

	id.id = gmep->unix_id;
	id.type = type;
	if (!surs_unixid_to_sam_sid(&id, &gmep->sid, False))
	{
		return False;
	}

	map_posix_to_nt_type(gmep, type);

	return True;
}

/************************************************************************
 
*************************************************************************/
static BOOL get_uid( DOM_NAME_MAP * gmep, int type)
{
	SURS_POSIX_ID id;

	id.type = type;
	if (!surs_sam_sid_to_unixid(&gmep->sid, &id, False))
	{
		return False;
	}

	if (id.type != type)
	{
		return False;
	}

	gmep->unix_id = id.id;

	map_posix_to_nt_type(gmep, type);

	return True;
}

/**************************************************************************
 makes a group sid out of an nt domain, nt group name or a unix group name.
***************************************************************************/
static BOOL unix_name_to_nt_name_info(DOM_NAME_MAP * map, DOM_MAP_TYPE type)
{
	DOM_SID dom_sid;
	uint32 rid;
	int surs_type;

	/*
	 * Attempt to get the unix gid_t for this name.
	 */

	DEBUG(5,
	      ("unix_name_to_nt_name_info: unix_name:%s\n", map->unix_name));

	if (type == DOM_MAP_USER)
	{
		const struct passwd *pwptr = Get_Pwnam(map->unix_name, False);
		surs_type = SURS_POSIX_UID;
		if (pwptr == NULL)
		{
			DEBUG(0,
			      ("unix_name_to_nt_name_info: Get_Pwnam for user %s\
failed. Error was %s.\n",
			       map->unix_name, strerror(errno)));
			return False;
		}

		map->unix_id = (uint32)pwptr->pw_uid;
	}
	else
	{
		struct group *gptr = getgrnam(map->unix_name);
		surs_type = SURS_POSIX_GID;
		if (gptr == NULL)
		{
			DEBUG(0,
			      ("unix_name_to_nt_name_info: getgrnam for group %s\
failed. Error was %s.\n",
			       map->unix_name, strerror(errno)));
			return False;
		}

		map->unix_id = (uint32)gptr->gr_gid;
	}

	DEBUG(5, ("unix_name_to_nt_name_info: unix gid:%d\n", map->unix_id));

	/*
	 * Now map the name to an NT SID+RID.
	 */

	if (!get_sid(map, surs_type))
	{
		DEBUG(0, ("get_sid: unknown unix id %x\n", map->unix_id));
		return False;
	}

	sid_copy(&dom_sid, &map->sid);
	sid_split_rid(&dom_sid, &rid);

	if (!map_domain_sid_to_name(&dom_sid, map->nt_domain))
	{
		fstring sid_str;
		sid_to_string(sid_str, &dom_sid);
		DEBUG(1, ("map_domain_sid_to_name: unknown SID %s\n",
			  sid_str));
		return False;
	}

	{
		fstring sid_str;
		sid_to_string(sid_str, &map->sid);
		DEBUG(10, ("nt name %s\\%s gid %d mapped to %s\n",
			   map->nt_domain, map->nt_name, map->unix_id,
			   sid_str));
	}
	return True;
}

static BOOL make_name_entry(name_map_entry ** new_ep,
			    char *nt_domain, char *nt_group, char *unix_group,
			    DOM_MAP_TYPE type)
{
	/*
	 * Create the list entry and add it onto the list.
	 */

	DEBUG(5,
	      ("make_name_entry:%s,%s,%s\n", nt_domain, nt_group,
	       unix_group));

	(*new_ep) = (name_map_entry *) malloc(sizeof(name_map_entry));
	if ((*new_ep) == NULL)
	{
		DEBUG(0,
		      ("make_name_entry: malloc fail for name_map_entry.\n"));
		return False;
	}

	ZERO_STRUCTP(*new_ep);

	(*new_ep)->grp.nt_name = strdup(nt_group);
	(*new_ep)->grp.nt_domain = strdup(nt_domain);
	(*new_ep)->grp.unix_name = strdup(unix_group);

	if ((*new_ep)->grp.nt_name == NULL ||
	    (*new_ep)->grp.unix_name == NULL)
	{
		DEBUG(0,
		      ("make_name_entry: malloc fail for names in name_map_entry.\n"));
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
	static time_t groupmap_file_last_modified = (time_t) 0;
	static time_t aliasmap_file_last_modified = (time_t) 0;
	static time_t ntusrmap_file_last_modified = (time_t) 0;
	static BOOL initialised_group = False;
	static BOOL initialised_alias = False;
	static BOOL initialised_ntusr = False;
	char *groupname_map_file = lp_groupname_map();
	char *aliasname_map_file = lp_aliasname_map();
	char *ntusrname_map_file = lp_ntusrname_map();

	FILE *fp;
	char *s;
	pstring buf;
	name_map_entry *new_ep;

	time_t *file_last_modified = NULL;
	int *initialised = NULL;
	char *map_file = NULL;
	ubi_slList *map_list = NULL;

	switch (type)
	{
		case DOM_MAP_DOMAIN:
		{
			file_last_modified = &groupmap_file_last_modified;
			initialised = &initialised_group;
			map_file = groupname_map_file;
			map_list = &groupname_map_list;

			break;
		}
		case DOM_MAP_LOCAL:
		{
			file_last_modified = &aliasmap_file_last_modified;
			initialised = &initialised_alias;
			map_file = aliasname_map_file;
			map_list = &aliasname_map_list;

			break;
		}
		case DOM_MAP_USER:
		{
			file_last_modified = &ntusrmap_file_last_modified;
			initialised = &initialised_ntusr;
			map_file = ntusrname_map_file;
			map_list = &ntusrname_map_list;

			break;
		}
	}

	if (!(*initialised))
	{
		DEBUG(10, ("initialising map %s\n", map_file));
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

	DEBUG(4, ("load_name_map: Scanning name map %s\n", map_file));

	while ((s = fgets_slash(buf, sizeof(buf), fp)) != NULL)
	{
		pstring unixname;
		pstring nt_name;
		fstring nt_domain;
		fstring ntname;
		char *p;

		DEBUG(10, ("Read line |%s|\n", s));

		memset(nt_name, 0, sizeof(nt_name));

		if (!*s || strchr("#;", *s))
			continue;

		if (!next_token(&s, unixname, "\t\n\r=", sizeof(unixname)))
			continue;

		if (!next_token(&s, nt_name, "\t\n\r=", sizeof(nt_name)))
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
			fstrcpy(ntname, p);
		}

		if (make_name_entry
		    (&new_ep, nt_domain, ntname, unixname, type))
		{
			ubi_slAddTail(map_list, (ubi_slNode *) new_ep);
			DEBUG(5,
			      ("unixname = %s, ntname = %s\\%s type = %d\n",
			       new_ep->grp.unix_name, new_ep->grp.nt_domain,
			       new_ep->grp.nt_name, new_ep->grp.type));
		}
	}

	DEBUG(10, ("load_name_map: Added %ld entries to name map.\n",
		   ubi_slCount(map_list)));

	fclose(fp);

	return map_list;
}

static void copy_grp_map_entry(DOM_NAME_MAP * grp, const DOM_NAME_MAP * from)
{
	sid_copy(&grp->sid, &from->sid);
	grp->unix_id = from->unix_id;
	grp->nt_name = from->nt_name;
	grp->nt_domain = from->nt_domain;
	grp->unix_name = from->unix_name;
	grp->type = from->type;
}

#if 0
/***********************************************************
 Lookup unix name.
************************************************************/
static BOOL map_unixname(DOM_MAP_TYPE type,
			 char *unixname, DOM_NAME_MAP * grp_info)
{
	name_map_entry *gmep;
	ubi_slList *map_list;

	/*
	 * Initialise and load if not already loaded.
	 */
	map_list = load_name_map(type);

	for (gmep = (name_map_entry *) ubi_slFirst(map_list);
	     gmep != NULL; gmep = (name_map_entry *) ubi_slNext(gmep))
	{
		if (strequal(gmep->grp.unix_name, unixname))
		{
			copy_grp_map_entry(grp_info, &gmep->grp);
			DEBUG(7,
			      ("map_unixname: Mapping unix name %s to nt group %s.\n",
			       gmep->grp.unix_name, gmep->grp.nt_name));
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
		       DOM_NAME_MAP * grp_info)
{
	name_map_entry *gmep;
	ubi_slList *map_list;

	/*
	 * Initialise and load if not already loaded.
	 */
	map_list = load_name_map(type);

	for (gmep = (name_map_entry *) ubi_slFirst(map_list);
	     gmep != NULL; gmep = (name_map_entry *) ubi_slNext(gmep))
	{
		if (strequal(gmep->grp.nt_name, ntname) &&
		    strequal(gmep->grp.nt_domain, ntdomain))
		{
			copy_grp_map_entry(grp_info, &gmep->grp);
			DEBUG(7,
			      ("map_ntname: Mapping unix name %s to nt name %s.\n",
			       gmep->grp.unix_name, gmep->grp.nt_name));
			return True;
		}
	}

	return False;
}


/***********************************************************
 Lookup by SID
************************************************************/
static BOOL map_sid(DOM_MAP_TYPE type, DOM_SID *psid, DOM_NAME_MAP * grp_info)
{
	name_map_entry *gmep;
	ubi_slList *map_list;

	/*
	 * Initialise and load if not already loaded.
	 */
	map_list = load_name_map(type);

	for (gmep = (name_map_entry *) ubi_slFirst(map_list);
	     gmep != NULL; gmep = (name_map_entry *) ubi_slNext(gmep))
	{
		if (sid_equal(&gmep->grp.sid, psid))
		{
			copy_grp_map_entry(grp_info, &gmep->grp);
			DEBUG(7,
			      ("map_sid: Mapping unix name %s to nt name %s.\n",
			       gmep->grp.unix_name, gmep->grp.nt_name));
			return True;
		}
	}

	return False;
}

/***********************************************************
 Lookup by gid_t.
************************************************************/
static BOOL map_unixid(DOM_MAP_TYPE type, uint32 unix_id,
		       DOM_NAME_MAP * grp_info)
{
	name_map_entry *gmep;
	ubi_slList *map_list;

	/*
	 * Initialise and load if not already loaded.
	 */
	map_list = load_name_map(type);

	for (gmep = (name_map_entry *) ubi_slFirst(map_list);
	     gmep != NULL; gmep = (name_map_entry *) ubi_slNext(gmep))
	{
		fstring sid_str;
		sid_to_string(sid_str, &gmep->grp.sid);
		DEBUG(10,
		      ("map_unixid: enum entry unix group %s %d nt %s %s\n",
		       gmep->grp.unix_name, gmep->grp.unix_id,
		       gmep->grp.nt_name, sid_str));
		if (gmep->grp.unix_id == unix_id)
		{
			copy_grp_map_entry(grp_info, &gmep->grp);
			DEBUG(7,
			      ("map_unixid: Mapping unix name %s to nt name %s type %d\n",
			       gmep->grp.unix_name, gmep->grp.nt_name,
			       gmep->grp.type));
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
BOOL map_unix_group_name(char *group_name, DOM_NAME_MAP * grp_info)
{
	return map_unixname(DOM_MAP_DOMAIN, group_name, grp_info);
}

/***********************************************************
 Lookup a UNIX Alias entry by name.
************************************************************/
BOOL map_unix_alias_name(char *alias_name, DOM_NAME_MAP * grp_info)
{
	return map_unixname(DOM_MAP_LOCAL, alias_name, grp_info);
}

/***********************************************************
 Lookup an Alias name entry 
************************************************************/
BOOL map_nt_alias_name(char *ntalias_name, char *nt_domain,
		       DOM_NAME_MAP * grp_info)
{
	return map_ntname(DOM_MAP_LOCAL, ntalias_name, nt_domain, grp_info);
}

/***********************************************************
 Lookup a Group entry
************************************************************/
BOOL map_nt_group_name(char *ntgroup_name, char *nt_domain,
		       DOM_NAME_MAP * grp_info)
{
	return map_ntname(DOM_MAP_DOMAIN, ntgroup_name, nt_domain, grp_info);
}

#endif

/***********************************************************
 Lookup a Username entry by name.
************************************************************/
static BOOL map_nt_username(char *nt_name, char *nt_domain,
			    DOM_NAME_MAP * grp_info)
{
	return map_ntname(DOM_MAP_USER, nt_name, nt_domain, grp_info);
}

/***********************************************************
 Lookup a Username entry by SID.
************************************************************/
static BOOL map_username_sid(DOM_SID *sid, DOM_NAME_MAP * grp_info)
{
	return map_sid(DOM_MAP_USER, sid, grp_info);
}

/***********************************************************
 Lookup a Username SID entry by uid.
************************************************************/
static BOOL map_username_uid(uid_t gid, DOM_NAME_MAP * grp_info)
{
	return map_unixid(DOM_MAP_USER, (uint32)gid, grp_info);
}

/***********************************************************
 Lookup an Alias SID entry by name.
************************************************************/
BOOL map_alias_sid(DOM_SID *psid, DOM_NAME_MAP * grp_info)
{
	return map_sid(DOM_MAP_LOCAL, psid, grp_info);
}

/***********************************************************
 Lookup a Group entry by sid.
************************************************************/
BOOL map_group_sid(DOM_SID *psid, DOM_NAME_MAP * grp_info)
{
	return map_sid(DOM_MAP_DOMAIN, psid, grp_info);
}

/***********************************************************
 Lookup an Alias SID entry by gid_t.
************************************************************/
static BOOL map_alias_gid(gid_t gid, DOM_NAME_MAP * grp_info)
{
	return map_unixid(DOM_MAP_LOCAL, (uint32)gid, grp_info);
}

/***********************************************************
 Lookup a Group SID entry by gid_t.
************************************************************/
static BOOL map_group_gid(gid_t gid, DOM_NAME_MAP * grp_info)
{
	return map_unixid(DOM_MAP_DOMAIN, (uint32)gid, grp_info);
}


/************************************************************************
 Routine to look up User details by UNIX name
*************************************************************************/
BOOL lookupsmbpwnam(const char *unix_usr_name, DOM_NAME_MAP * grp)
{
	uid_t uid;
	DEBUG(10, ("lookupsmbpwnam: unix user name %s\n", unix_usr_name));
	if (nametouid(unix_usr_name, &uid))
	{
		return lookupsmbpwuid(uid, grp);
	}
	else
	{
		return False;
	}
}

/*************************************************************************
 looks up a uid, returns User Information.  
*************************************************************************/
BOOL lookupsmbpwuid(uid_t uid, DOM_NAME_MAP * gmep)
{
	static fstring nt_name;
	static fstring unix_name;
	static fstring nt_domain;

	DEBUG(10, ("lookupsmbpwuid: unix uid %d\n", uid));
	if (map_username_uid(uid, gmep))
	{
		return True;
	}

	gmep->nt_name = nt_name;
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

	gmep->nt_domain = global_sam_name;

	return get_sid(gmep, SURS_POSIX_UID);
}

/*************************************************************************
 looks up by NT name, returns User Information.  
*************************************************************************/
BOOL lookupsmbpwntnam(const char *fullntname, DOM_NAME_MAP * gmep)
{
	static fstring nt_name;
	static fstring unix_name;
	static fstring nt_domain;

	uid_t uid;

	DEBUG(10, ("lookupsmbpwntnam: nt user name %s\n", fullntname));

	if (!split_domain_name(fullntname, nt_domain, nt_name))
	{
		return False;
	}

	if (map_nt_username(nt_name, nt_domain, gmep))
	{
		return True;
	}
	gmep->nt_name = nt_name;
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

	return get_sid(gmep, SURS_POSIX_UID);
}

/*************************************************************************
 looks up by RID, returns User Information.  
*************************************************************************/
BOOL lookupsmbpwsid(DOM_SID *sid, DOM_NAME_MAP * gmep)
{
	static fstring nt_name;
	static fstring unix_name;
	static fstring nt_domain;

	fstring sid_str;
	sid_to_string(sid_str, sid);
	DEBUG(10, ("lookupsmbpwsid: nt sid %s\n", sid_str));

	if (map_username_sid(sid, gmep))
	{
		return True;
	}
	gmep->nt_name = nt_name;
	gmep->unix_name = unix_name;
	gmep->nt_domain = nt_domain;

	/*
	 * "create" an nt user named
	 * after the unix user.  this is the point where "appliance mode"
	 * should get its teeth in, as unix users won't really exist,
	 * they will only be numbers...
	 */

	sid_copy(&gmep->sid, sid);
	if (!get_uid(gmep, SURS_POSIX_UID))
	{
		return False;
	}

	fstrcpy(gmep->nt_name, uidtoname((uid_t) gmep->unix_id));
	fstrcpy(gmep->unix_name, gmep->nt_name);
	gmep->nt_domain = global_sam_name;

	return True;
}

/************************************************************************
 Routine to look up group / alias / well-known group RID by UNIX name
*************************************************************************/
BOOL lookupsmbgrpnam(const char *unix_grp_name, DOM_NAME_MAP * grp)
{
	gid_t gid;
	DEBUG(10, ("lookupsmbgrpnam: unix user group %s\n", unix_grp_name));
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
BOOL lookupsmbgrpsid(DOM_SID *sid, DOM_NAME_MAP * gmep)
{
	static fstring nt_name;
	static fstring unix_name;
	static fstring nt_domain;

	fstring sid_str;
	sid_to_string(sid_str, sid);
	DEBUG(10, ("lookupsmbgrpsid: nt sid %s\n", sid_str));
	if (map_alias_sid(sid, gmep))
	{
		return True;
	}
	if (map_group_sid(sid, gmep))
	{
		return True;
	}
	gmep->nt_name = nt_name;
	gmep->unix_name = unix_name;
	gmep->nt_domain = nt_domain;

	/*
	 * "create" an nt group or
	 * alias name named after the unix group.  this is the point
	 * where "appliance mode" should get its teeth in, as unix
	 * groups won't really exist, they will only be numbers...
	 */

	sid_copy(&gmep->sid, sid);
	if (!get_uid(gmep, SURS_POSIX_GID))
	{
		return False;
	}

	fstrcpy(gmep->nt_name, gidtoname((gid_t) gmep->unix_id));
	fstrcpy(gmep->unix_name, gmep->nt_name);
	gmep->nt_domain = global_sam_name;
	return True;
}

/*************************************************************************
 looks up a gid, returns RID and type local, domain or well-known domain group
*************************************************************************/
BOOL lookupsmbgrpgid(gid_t gid, DOM_NAME_MAP * gmep)
{
	static fstring nt_name;
	static fstring unix_name;
	static fstring nt_domain;

	DEBUG(10, ("lookupsmbgrpgid: unix gid %d\n", (int)gid));
	if (map_alias_gid(gid, gmep))
	{
		return True;
	}
	if (map_group_gid(gid, gmep))
	{
		return True;
	}
	gmep->nt_name = nt_name;
	gmep->unix_name = unix_name;
	gmep->nt_domain = nt_domain;
	gmep->unix_id = (uint32)gid;

	/*
	 * "create" an nt group or
	 * alias name named after the unix group.  this is the point
	 * where "appliance mode" should get its teeth in, as unix
	 * groups won't really exist, they will only be numbers...
	 */

	/* name is not explicitly mapped
	 * with map files or the PDC
	 * so we are responsible for it...
	 */

	fstrcpy(gmep->nt_domain, global_sam_name);
	fstrcpy(gmep->nt_name, gidtoname(gid));
	fstrcpy(gmep->unix_name, gmep->nt_name);
	return get_sid(gmep, SURS_POSIX_GID);
}


/****************************************************************************
  does _both_ nt->unix and unix->unix username remappings.
****************************************************************************/
const struct passwd *map_nt_and_unix_username(const char *domain,
					      const char *ntuser,
					      char *unix_user, char *nt_user)
{
	DOM_NAME_MAP gmep;
	fstring nt_username;
	if (nt_user == NULL)
	{
		nt_user = nt_username;
	}

	memset(nt_user, 0, sizeof(nt_user));
	if (domain != NULL)
	{
		slprintf(nt_user, sizeof(fstring), "%s\\%s", domain, ntuser);
	}
	else
	{
		fstrcpy(nt_user, ntuser);
	}

	/*
	 * Pass the user through the NT -> unix user mapping
	 * function.
	 */

	if (lookupsmbpwntnam(nt_user, &gmep))
	{
		fstrcpy(unix_user, gmep.unix_name);
	}
	else
	{
		return NULL;
	}

	/*
	 * Pass the user through the unix -> unix user mapping
	 * function.
	 */

	(void)map_username(unix_user);
	/*
	 * Do any UNIX username case mangling.
	 */
	return Get_Pwnam(unix_user, True);
}
