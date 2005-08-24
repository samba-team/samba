/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2001.
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

#include "includes.h"
#include "system/iconv.h"
#include "lib/samba3/samba3.h"
#include "lib/tdb/include/tdbutil.h"
#include "system/filesys.h"

#define DATABASE_VERSION_V1 1 /* native byte format. */
#define DATABASE_VERSION_V2 2 /* le format. */

#define GROUP_PREFIX "UNIXGROUP/"

/* Alias memberships are stored reverse, as memberships. The performance
 * critical operation is to determine the aliases a SID is member of, not
 * listing alias members. So we store a list of alias SIDs a SID is member of
 * hanging of the member as key.
 */
#define MEMBEROF_PREFIX "MEMBEROF/"

#define ENUM_ONLY_MAPPED True
#define ENUM_ALL_MAPPED False


/****************************************************************************
dump the mapping group mapping to a text file
****************************************************************************/
static const char *decode_sid_name_use(enum SID_NAME_USE name_use)
{	
	switch(name_use) {
		case SID_NAME_USER:
			return "User";
		case SID_NAME_DOM_GRP:
			return "Domain group";
		case SID_NAME_DOMAIN:
			return "Domain";
		case SID_NAME_ALIAS:
			return "Local group";
		case SID_NAME_WKN_GRP:
			return "Builtin group";
		case SID_NAME_DELETED:
			return "Deleted";
		case SID_NAME_INVALID:
			return "Invalid";
		case SID_NAME_UNKNOWN:
		default:
			return "Unknown type";
	}
}

/****************************************************************************
 Open the group mapping tdb.
****************************************************************************/
static TDB_CONTEXT *tdbgroup_open(const char *file)
{
	int32_t vers_id;
	
	TDB_CONTEXT *tdb = tdb_open(file, 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open group mapping database\n"));
		return NULL;
	}

	/* Cope with byte-reversed older versions of the db. */
	vers_id = tdb_fetch_int32(tdb, "INFO/version");
	if ((vers_id == DATABASE_VERSION_V1) || (IREV(vers_id) == DATABASE_VERSION_V1)) {
		/* Written on a bigendian machine with old fetch_int code. Save as le. */
		vers_id = DATABASE_VERSION_V2;
	}

	if (vers_id != DATABASE_VERSION_V2) {
		return NULL;
	}

	return tdb;
}

/****************************************************************************
 Return the sid and the type of the unix group.
****************************************************************************/

static BOOL get_group_map_from_sid(TDB_CONTEXT *tdb, struct dom_sid sid, struct samba3_groupmapping *map)
{
	TDB_DATA kbuf, dbuf;
	const char *key;
	int ret = 0;
	
	/* the key is the SID, retrieving is direct */

	kbuf.dptr = talloc_asprintf(tdb, "%s%s", GROUP_PREFIX, dom_sid_string(tdb, &sid));
	kbuf.dsize = strlen(key)+1;
		
	dbuf = tdb_fetch(tdb, kbuf);
	if (!dbuf.dptr)
		return False;

	ret = tdb_unpack(tdb, dbuf.dptr, dbuf.dsize, "ddff",
		&map->gid, &map->sid_name_use, &map->nt_name, &map->comment);

	SAFE_FREE(dbuf.dptr);
	
	if ( ret == -1 ) {
		DEBUG(3,("get_group_map_from_sid: tdb_unpack failure\n"));
		return False;
	}

	map->sid = dom_sid_dup(tdb, &sid);
	
	return True;
}

/****************************************************************************
 Return the sid and the type of the unix group.
****************************************************************************/

static BOOL get_group_map_from_gid(TDB_CONTEXT *tdb, gid_t gid, struct samba3_groupmapping *map)
{
	TDB_DATA kbuf, dbuf, newkey;
	int ret;

	/* we need to enumerate the TDB to find the GID */

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		if (strncmp(kbuf.dptr, GROUP_PREFIX, strlen(GROUP_PREFIX)) != 0) continue;
		
		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr)
			continue;


		map->sid = dom_sid_parse_talloc(tdb, kbuf.dptr+strlen(GROUP_PREFIX));
		
		ret = tdb_unpack(tdb, dbuf.dptr, dbuf.dsize, "ddff",
				 &map->gid, &map->sid_name_use, &map->nt_name, &map->comment);

		SAFE_FREE(dbuf.dptr);

		if ( ret == -1 ) {
			DEBUG(3,("get_group_map_from_gid: tdb_unpack failure\n"));
			return False;
		}
	
		if (gid==map->gid) {
			SAFE_FREE(kbuf.dptr);
			return True;
		}
	}

	return False;
}

/****************************************************************************
 Return the sid and the type of the unix group.
****************************************************************************/

static BOOL get_group_map_from_ntname(TDB_CONTEXT *tdb, const char *name, struct samba3_groupmapping *map)
{
	TDB_DATA kbuf, dbuf, newkey;
	int ret;

	/* we need to enumerate the TDB to find the name */

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		if (strncmp(kbuf.dptr, GROUP_PREFIX, strlen(GROUP_PREFIX)) != 0) continue;
		
		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr)
			continue;

		map->sid = dom_sid_parse_talloc(tdb, kbuf.dptr+strlen(GROUP_PREFIX));
		
		ret = tdb_unpack(tdb, dbuf.dptr, dbuf.dsize, "ddff",
				 &map->gid, &map->sid_name_use, &map->nt_name, &map->comment);

		SAFE_FREE(dbuf.dptr);
		
		if ( ret == -1 ) {
			DEBUG(3,("get_group_map_from_ntname: tdb_unpack failure\n"));
			return False;
		}

		if (StrCaseCmp(name, map->nt_name)==0) {
			SAFE_FREE(kbuf.dptr);
			return True;
		}
	}

	return False;
}

/****************************************************************************
 Enumerate the group mapping.
****************************************************************************/

static BOOL enum_group_mapping(TDB_CONTEXT *tdb, enum SID_NAME_USE sid_name_use, struct samba3_groupmapping **rmap,
			int *num_entries, BOOL unix_only)
{
	TDB_DATA kbuf, dbuf, newkey;
	struct samba3_groupmapping map;
	struct samba3_groupmapping *mapt;
	int ret;
	int entries=0;

	*num_entries=0;
	*rmap=NULL;

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		if (strncmp(kbuf.dptr, GROUP_PREFIX, strlen(GROUP_PREFIX)) != 0)
			continue;

		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr)
			continue;

		map.sid = dom_sid_parse_talloc(tdb, kbuf.dptr+strlen(GROUP_PREFIX));
				
		ret = tdb_unpack(tdb, dbuf.dptr, dbuf.dsize, "ddff",
				 &map.gid, &map.sid_name_use, &map.nt_name, &map.comment);

		SAFE_FREE(dbuf.dptr);

		if ( ret == -1 ) {
			DEBUG(3,("enum_group_mapping: tdb_unpack failure\n"));
			continue;
		}
	
		/* list only the type or everything if UNKNOWN */
		if (sid_name_use!=SID_NAME_UNKNOWN  && sid_name_use!=map.sid_name_use) {
			DEBUG(11,("enum_group_mapping: group %s is not of the requested type\n", map.nt_name));
			continue;
		}

		if (unix_only==ENUM_ONLY_MAPPED && map.gid==-1) {
			DEBUG(11,("enum_group_mapping: group %s is non mapped\n", map.nt_name));
			continue;
		}

		DEBUG(11,("enum_group_mapping: returning group %s of type %s\n", map.nt_name ,decode_sid_name_use(map.sid_name_use)));

		mapt = talloc_realloc(tdb, *rmap, struct samba3_groupmapping, entries+1);
		if (!mapt) {
			DEBUG(0,("enum_group_mapping: Unable to enlarge group map!\n"));
			SAFE_FREE(*rmap);
			return False;
		}
		else
			(*rmap) = mapt;

		mapt[entries].gid = map.gid;
		mapt[entries].sid = dom_sid_dup(tdb, map.sid);
		mapt[entries].sid_name_use = map.sid_name_use;
		mapt[entries].nt_name = map.nt_name;
		mapt[entries].comment = map.comment;

		entries++;

	}

	*num_entries=entries;

	return True;
}

/* This operation happens on session setup, so it should better be fast. We
 * store a list of aliases a SID is member of hanging off MEMBEROF/SID. */

static NTSTATUS one_alias_membership(TDB_CONTEXT *tdb, 
		const struct dom_sid *member, struct dom_sid **sids, int *num)
{
	TDB_DATA kbuf, dbuf;
	const char *p;

	char * key = talloc_asprintf(tdb, "%s%s", MEMBEROF_PREFIX, dom_sid_string(tdb, member));

	kbuf.dsize = strlen(key)+1;
	kbuf.dptr = key;

	dbuf = tdb_fetch(tdb, kbuf);

	if (dbuf.dptr == NULL) {
		return NT_STATUS_OK;
	}

	p = dbuf.dptr;

	while (next_token(&p, string_sid, " ", sizeof(string_sid))) {

		struct dom_sid alias;

		if (!string_to_sid(&alias, string_sid))
			continue;

		add_sid_to_array_unique(NULL, &alias, sids, num);

		if (sids == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	SAFE_FREE(dbuf.dptr);
	return NT_STATUS_OK;
}

static NTSTATUS alias_memberships(TDB_CONTEXT *tdb, const struct dom_sid *members, int num_members,
				  struct dom_sid **sids, int *num)
{
	int i;

	*num = 0;
	*sids = NULL;

	for (i=0; i<num_members; i++) {
		NTSTATUS status = one_alias_membership(tdb, &members[i], sids, num);
		if (!NT_STATUS_IS_OK(status))
			return status;
	}
	return NT_STATUS_OK;
}

struct aliasmem_closure {
	const struct dom_sid *alias;
	struct dom_sid **sids;
	int *num;
};

static int collect_aliasmem(TDB_CONTEXT *tdb_ctx, TDB_DATA key, TDB_DATA data,
			    void *state)
{
	struct aliasmem_closure *closure = (struct aliasmem_closure *)state;
	const char *p;
	fstring alias_string;

	if (strncmp(key.dptr, MEMBEROF_PREFIX,
		    strlen(MEMBEROF_PREFIX)) != 0)
		return 0;

	p = data.dptr;

	while (next_token(&p, alias_string, " ", sizeof(alias_string))) {

		struct dom_sid alias, member;
		const char *member_string;
		

		if (!string_to_sid(&alias, alias_string))
			continue;

		if (sid_compare(closure->alias, &alias) != 0)
			continue;

		/* Ok, we found the alias we're looking for in the membership
		 * list currently scanned. The key represents the alias
		 * member. Add that. */

		member_string = strchr(key.dptr, '/');

		/* Above we tested for MEMBEROF_PREFIX which includes the
		 * slash. */

		SMB_ASSERT(member_string != NULL);
		member_string += 1;

		if (!string_to_sid(&member, member_string))
			continue;
		
		add_sid_to_array(NULL, &member, closure->sids, closure->num);
	}

	return 0;
}

static NTSTATUS enum_aliasmem(TDB_CONTEXT *tdb, const struct dom_sid *alias, struct dom_sid **sids, int *num)
{
	struct samba3_groupmapping map;
	struct aliasmem_closure closure;

	if (!get_group_map_from_sid(*alias, &map))
		return NT_STATUS_NO_SUCH_ALIAS;

	if ( (map.sid_name_use != SID_NAME_ALIAS) &&
	     (map.sid_name_use != SID_NAME_WKN_GRP) )
		return NT_STATUS_NO_SUCH_ALIAS;

	*sids = NULL;
	*num = 0;

	closure.alias = alias;
	closure.sids = sids;
	closure.num = num;

	tdb_traverse(tdb, collect_aliasmem, &closure);
	return NT_STATUS_OK;
}

/*
 *
 * High level functions
 * better to use them than the lower ones.
 *
 * we are checking if the group is in the mapping file
 * and if the group is an existing unix group
 *
 */

/* get a domain group from it's SID */

/* get a local (alias) group from it's SID */

static BOOL get_local_group_from_sid(TDB_CONTEXT *tdb, struct dom_sid *sid, struct samba3_groupmapping *map)
{
	BOOL ret;
	
	/* The group is in the mapping table */
	ret = pdb_getgrsid(map, *sid);
	
	if ( !ret )
		return False;
		
	if ( ( (map->sid_name_use != SID_NAME_ALIAS) &&
	       (map->sid_name_use != SID_NAME_WKN_GRP) )
		|| (map->gid == -1)
		|| (getgrgid(map->gid) == NULL) ) 
	{
		return False;
	} 		
			
#if 1 	/* JERRY */
	/* local groups only exist in the group mapping DB so this 
	   is not necessary */
	   
	else {
		/* the group isn't in the mapping table.
		 * make one based on the unix information */
		uint32_t alias_rid;
		struct group *grp;

		sid_peek_rid(sid, &alias_rid);
		map->gid=pdb_group_rid_to_gid(alias_rid);
		
		grp = getgrgid(map->gid);
		if ( !grp ) {
			DEBUG(3,("get_local_group_from_sid: No unix group for [%ul]\n", map->gid));
			return False;
		}

		map->sid_name_use=SID_NAME_ALIAS;

		fstrcpy(map->nt_name, grp->gr_name);
		fstrcpy(map->comment, "Local Unix Group");

		sid_copy(&map->sid, sid);
	}
#endif

	return True;
}
