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
extern int DEBUGLEVEL;

/* we can map either local aliases or domain groups */
typedef enum 
{
	GROUP_LOCAL,
	GROUP_DOMAIN

} GROUP_TYPE;

/**************************************************************************
 Groupname map functionality. The code loads a groupname map file and
 (currently) loads it into a linked list. This is slow and memory
 hungry, but can be changed into a more efficient storage format
 if the demands on it become excessive.
***************************************************************************/

typedef struct group_name_info
{
   char *nt_name;
   char *nt_domain;
   char *unix_name;

   DOM_SID sid;
   gid_t  unix_gid;

} GROUP_NAME_INFO;

typedef struct name_map
{
	ubi_slNode next;
	GROUP_NAME_INFO grp;

} name_map_entry;

static ubi_slList groupname_map_list;
static ubi_slList aliasname_map_list;

static void delete_name_entry(name_map_entry *gmep)
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
	free((char*)gmep);
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
static BOOL make_mydomain_sid(GROUP_NAME_INFO *grp, GROUP_TYPE type)
{
	uint32 tmp_rid;
	uint8  tmp_type;

	DEBUG(10,("make_mydomain_sid\n"));

	if (!map_domain_name_to_sid(&grp->sid, &(grp->nt_domain)))
	{
		DEBUG(0,("make_mydomain_sid: unknown domain %s\n",
			  grp->nt_domain));
		return False;
	}
	else if (lookup_wk_group_rid(grp->nt_name, &tmp_rid, &tmp_type))
	{
		return sid_append_rid(&grp->sid, tmp_rid);
	}
	else
	{
		if (type == GROUP_DOMAIN)
		{
			tmp_rid = pwdb_gid_to_group_rid(grp->unix_gid);
		}
		else
		{
			tmp_rid = pwdb_gid_to_alias_rid(grp->unix_gid);
		}
		return sid_append_rid(&(grp->sid), tmp_rid);
	}
}

/**************************************************************************
 makes a group sid out of an nt domain, nt group name or a unix group name.
***************************************************************************/
static BOOL unix_name_to_group_info(GROUP_NAME_INFO *grp, GROUP_TYPE type)
{
	extern fstring global_sam_name;
	struct group *gptr = NULL;

	/*
	 * Attempt to get the unix gid_t for this name.
	 */

	DEBUG(5,("unix_name_to_group_info: unix_name:%s\n", grp->unix_name));

	gptr = (struct group *)getgrnam(grp->unix_name);
	if (gptr == NULL)
	{
		DEBUG(0,("unix_name_to_group_info: getgrnam for group %s\
failed. Error was %s.\n", grp->unix_name, strerror(errno) ));
		return False;
	}

	grp->unix_gid = (gid_t)gptr->gr_gid;

	DEBUG(5,("unix_name_to_group_info: unix gid:%d\n", grp->unix_gid));

	/*
	 * Now map the name to an NT SID+RID.
	 */

	if (grp->nt_domain != NULL && !strequal(grp->nt_domain, global_sam_name))
	{
		/* Must add client-call lookup code here, to 
		 * resolve remote domain's sid and the group's rid,
		 * in that domain.
		 *
		 * NOTE: it is _incorrect_ to put code here that assumes
		 * that we can call pwdb_gid_to_group_rid() or _alias_rid():
		 * it is a totally different domain for which we are *NOT*
		 * responsible.
		 * for foriegn domains for which we are *NOT* the PDC, all
		 * we can be responsible for is the unix * gid_t to which
		 * the foriegn SID+rid maps to, on this _local_ machine.  
		 */

		if (!map_domain_name_to_sid(&grp->sid, &(grp->nt_domain)))
		{
			DEBUG(0,("unix_name_to_group_info: no known sid for %s\n",
				  grp->nt_domain));
			return False;
		}

		DEBUG(0,("unix_name_to_group_info: cannot resolve domain %s\n",
			  grp->nt_domain));

		return False;
	}
	else
	{
		return make_mydomain_sid(grp, type);
	}
}

static BOOL make_name_entry(name_map_entry **new_ep,
		char *nt_domain, char *nt_group, char *unix_group,
		GROUP_TYPE type)
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
 
	if (!unix_name_to_group_info(&(*new_ep)->grp, type))
	{
		delete_name_entry((*new_ep));
		return False;
	}

	return True;
}

/**************************************************************************
 Load a name map file. Sets last accessed timestamp.
***************************************************************************/
static void load_name_map(GROUP_TYPE type)
{
	static time_t groupmap_file_last_modified = (time_t)0;
	static time_t aliasmap_file_last_modified = (time_t)0;
	static BOOL initialised_group = False;
	static BOOL initialised_alias = False;
	char *groupname_map_file = lp_groupname_map();
	char *aliasname_map_file = lp_aliasname_map();

	SMB_STRUCT_STAT st;
	FILE *fp;
	char *s;
	pstring buf;
	name_map_entry *new_ep;

	time_t *file_last_modified;
	int    *initialised;
	char   *map_file;
	ubi_slList *map_list;

	if (type == GROUP_DOMAIN)
	{
		file_last_modified = &groupmap_file_last_modified;
		initialised        = &initialised_group;
		map_file           = groupname_map_file;
		map_list           = &groupname_map_list;
	}
	else
	{
		file_last_modified = &aliasmap_file_last_modified;
		initialised        = &initialised_alias;
		map_file           = aliasname_map_file;
		map_list           = &aliasname_map_list;
	}

	DEBUG(10,("load_name_map : %s\n", map_file));

	if (!(*initialised))
	{
		ubi_slInitList(map_list);
		(*initialised) = True;
	}

	if (!*map_file)
	{
		return;
	}

	if (sys_stat(map_file, &st) != 0)
	{
		DEBUG(0, ("load_name_map: Unable to stat file %s. Error was %s\n",
		           map_file, strerror(errno) ));
		return;
	}

	/*
	 * Check if file has changed.
	 */
	if (st.st_mtime <= (*file_last_modified))
	{
		return;
	}

	(*file_last_modified) = st.st_mtime;

	/*
	 * Load the file.
	 */

	fp = sys_fopen(map_file,"r");
	if (!fp)
	{
		DEBUG(0,("load_name_map: can't open name map %s. Error was %s\n",
		          map_file, strerror(errno)));
		return;
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
		fstring nt_group;
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

		DEBUG(5,("unixname = %s, ntname = %s.\n",
		          unixname, nt_name));

		p = strchr(nt_name, '\\');

		if (p == NULL)
		{
			memset(nt_domain, 0, sizeof(nt_domain));
			fstrcpy(nt_group, nt_name);
		}
		else
		{
			*p = 0;
			p++;
			fstrcpy(nt_domain, nt_name);
			fstrcpy(nt_group , p);
		}

		if (make_name_entry(&new_ep, nt_domain, nt_name, unixname, type))
		{
			ubi_slAddHead(map_list, (ubi_slNode *)new_ep);
		}
	}

	DEBUG(10,("load_name_map: Added %ld entries to name map.\n",
	ubi_slCount(map_list)));

	fclose(fp);
}

/***********************************************************
 Lookup a gid_t by SID
************************************************************/
static BOOL map_sid_to_gid(GROUP_TYPE type, ubi_slList *map_list,
		DOM_SID *psid, gid_t *gid)
{
	name_map_entry *gmep;

	/*
	 * Initialize and load if not already loaded.
	 */
	load_name_map(type);

	for (gmep = (name_map_entry *)ubi_slFirst(map_list);
	     gmep != NULL;
	     gmep = (name_map_entry *)ubi_slNext(gmep ))
	{
		if (sid_equal(&gmep->grp.sid, psid))
		{
			*gid = gmep->grp.unix_gid;
			DEBUG(7,("map_sid_to_gid: Mapping unix group %s to nt group %s.\n",
			       gmep->grp.unix_name, gmep->grp.nt_name ));
			return True;
		}
	}

	return False;
}

/***********************************************************
 Lookup a SID entry by nt name.
************************************************************/
static BOOL map_sid_to_ntname(GROUP_TYPE type, ubi_slList *map_list,
		DOM_SID *psid, char *ntname, char *ntdomain)
{
	name_map_entry *gmep;

	/*
	 * Initialize and load if not already loaded.
	 */
	load_name_map(type);

	for (gmep = (name_map_entry *)ubi_slFirst(&map_list);
	     gmep != NULL;
	     gmep = (name_map_entry *)ubi_slNext(gmep ))
	{
		if (sid_equal(&gmep->grp.sid, psid))
		{
			if (ntname != NULL)
			{
				fstrcpy(ntname, gmep->grp.nt_name);
			}
			if (ntdomain != NULL)
			{
				fstrcpy(ntname, gmep->grp.nt_domain);
			}
			DEBUG(7,("map_sid_to_ntname: Mapping unix group %s to nt group \\%s\\%s\n",
			       gmep->grp.unix_name,
			       gmep->grp.nt_domain, gmep->grp.nt_name ));
			return True;
		}
	}

	return False;
}

/***********************************************************
 Lookup a SID entry by nt name.
************************************************************/
static BOOL map_ntname_to_sid(GROUP_TYPE type, ubi_slList *map_list,
		char * ntname, DOM_SID *psid)
{
	name_map_entry *gmep;

	/*
	 * Initialize and load if not already loaded.
	 */
	load_name_map(type);

	for (gmep = (name_map_entry *)ubi_slFirst(&map_list);
	     gmep != NULL;
	     gmep = (name_map_entry *)ubi_slNext(gmep ))
	{
		if (strequal(gmep->grp.nt_name, ntname))
		{
			*psid = gmep->grp.sid;
			DEBUG(7,("map_ntname_to_sid: Mapping unix group %s to nt group %s.\n",
			       gmep->grp.unix_name, gmep->grp.nt_name ));
			return True;
		}
	}

	return False;
}

/***********************************************************
 Lookup a SID entry by gid_t.
************************************************************/
static BOOL map_gid_to_sid(GROUP_TYPE type, ubi_slList *map_list,
		gid_t gid, DOM_SID *psid)
{
	name_map_entry *gmep;

	/*
	 * Initialize and load if not already loaded.
	 */
	load_name_map(type);

	for (gmep = (name_map_entry *)ubi_slFirst(&map_list);
	     gmep != NULL;
	     gmep = (name_map_entry *)ubi_slNext(gmep ))
	{
		if (gmep->grp.unix_gid == gid)
		{
			*psid = gmep->grp.sid;
			DEBUG(7,("map_gid_to_sid: Mapping unix group %s to nt group %s.\n",
			       gmep->grp.unix_name, gmep->grp.nt_name ));
			return True;
		}
	}

	return False;
}

/*
 * Call these four functions to resolve unix group ids and either
 * local group SIDs or domain group SIDs listed in the local group
 * or domain group map files.
 *
 * Note that it is *NOT* the responsibility of these functions to
 * resolve entries that are not in the map files.
 *
 * Any SID can be in the map files (i.e from any Domain).
 */

/***********************************************************
 Lookup a Group entry by sid.
************************************************************/
BOOL map_group_sid_to_name(DOM_SID *psid, char *group_name, char *nt_domain)
{
	return map_sid_to_ntname(GROUP_DOMAIN, &groupname_map_list, psid, group_name, nt_domain);
}

/***********************************************************
 Lookup an Alias SID entry by name.
************************************************************/
BOOL map_alias_sid_to_name(DOM_SID *psid, char *alias_name, char *nt_domain)
{
	return map_sid_to_ntname(GROUP_LOCAL, &aliasname_map_list, psid, alias_name, nt_domain);
}

/***********************************************************
 Lookup a Group SID entry by name.
************************************************************/
BOOL map_group_name_to_sid(char *group_name, DOM_SID *psid)
{
	return map_ntname_to_sid(GROUP_DOMAIN, &groupname_map_list, group_name, psid);
}

/***********************************************************
 Lookup an Alias SID entry by name.
************************************************************/
BOOL map_alias_name_to_sid(char *alias_name, DOM_SID *psid)
{
	return map_ntname_to_sid(GROUP_LOCAL, &aliasname_map_list, alias_name, psid);
}

/***********************************************************
 Lookup an Alias SID entry by gid_t.
************************************************************/
BOOL map_gid_to_alias_sid(gid_t gid, DOM_SID *psid)
{
	return map_gid_to_sid(GROUP_LOCAL, &aliasname_map_list, gid, psid);
}

/***********************************************************
 Lookup a Group SID entry by gid_t.
************************************************************/
BOOL map_gid_to_group_sid( gid_t gid, DOM_SID *psid)
{
	return map_gid_to_sid(GROUP_DOMAIN, &groupname_map_list, gid, psid);
}

/***********************************************************
 Lookup a Group gid_t by SID
************************************************************/
BOOL map_group_sid_to_gid( DOM_SID *psid, gid_t *gid)
{
	return map_sid_to_gid(GROUP_DOMAIN, &groupname_map_list, psid, gid);
}

/***********************************************************
 Lookup an Alias gid_t by SID
************************************************************/
BOOL map_alias_sid_to_gid( DOM_SID *psid, gid_t *gid)
{
	return map_sid_to_gid(GROUP_LOCAL, &aliasname_map_list, psid, gid);
}

