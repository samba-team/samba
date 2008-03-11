/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2006,
 *  Copyright (C) Jean François Micouleau      1998-2001.
 *  Copyright (C) Volker Lendecke              2006.
 *  Copyright (C) Gerald Carter                2006.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "groupdb/mapping.h"

static TDB_CONTEXT *tdb; /* used for driver files */

static bool enum_group_mapping(const DOM_SID *domsid, enum lsa_SidType sid_name_use, GROUP_MAP **pp_rmap,
			       size_t *p_num_entries, bool unix_only);
static bool group_map_remove(const DOM_SID *sid);
	
/****************************************************************************
 Open the group mapping tdb.
****************************************************************************/
static bool init_group_mapping(void)
{
	const char *vstring = "INFO/version";
	int32 vers_id;
	GROUP_MAP *map_table = NULL;
	size_t num_entries = 0;
	
	if (tdb)
		return True;
		
	tdb = tdb_open_log(state_path("group_mapping.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open group mapping database\n"));
		return False;
	}

	/* handle a Samba upgrade */
	tdb_lock_bystring(tdb, vstring);

	/* Cope with byte-reversed older versions of the db. */
	vers_id = tdb_fetch_int32(tdb, vstring);
	if ((vers_id == DATABASE_VERSION_V1) || (IREV(vers_id) == DATABASE_VERSION_V1)) {
		/* Written on a bigendian machine with old fetch_int code. Save as le. */
		tdb_store_int32(tdb, vstring, DATABASE_VERSION_V2);
		vers_id = DATABASE_VERSION_V2;
	}

	/* if its an unknown version we remove everthing in the db */
	
	if (vers_id != DATABASE_VERSION_V2) {
		tdb_traverse(tdb, tdb_traverse_delete_fn, NULL);
		tdb_store_int32(tdb, vstring, DATABASE_VERSION_V2);
	}

	tdb_unlock_bystring(tdb, vstring);

	/* cleanup any map entries with a gid == -1 */
	
	if ( enum_group_mapping( NULL, SID_NAME_UNKNOWN, &map_table, &num_entries, False ) ) {
		int i;
		
		for ( i=0; i<num_entries; i++ ) {
			if ( map_table[i].gid == -1 ) {
				group_map_remove( &map_table[i].sid );
			}
		}
		
		SAFE_FREE( map_table );
	}


	return True;
}

/****************************************************************************
****************************************************************************/
static bool add_mapping_entry(GROUP_MAP *map, int flag)
{
	TDB_DATA dbuf;
	char *key, *buf, *sid_string;
	int len;
	bool ret;

	sid_string = sid_string_talloc(talloc_tos(), &map->sid);
	if (sid_string == NULL) {
		return NULL;
	}

	len = tdb_pack(NULL, sizeof(buf), "ddff",
		map->gid, map->sid_name_use, map->nt_name, map->comment);
	if (len) {
		buf = TALLOC_ARRAY(sid_string, char, len);
		if (!buf) {
			TALLOC_FREE(sid_string);
			return false;
		}
		len = tdb_pack((uint8 *)buf, len, "ddff", map->gid,
				map->sid_name_use, map->nt_name, map->comment);
	}

	key = talloc_asprintf(sid_string, "%s%s", GROUP_PREFIX, sid_string);
	if (key == NULL) {
		TALLOC_FREE(sid_string);
		return false;
	}

	dbuf.dsize = len;
	dbuf.dptr = (uint8 *)buf;

	ret = (tdb_store_bystring(tdb, key, dbuf, flag) == 0);

	TALLOC_FREE(sid_string);
	return ret;
}


/****************************************************************************
 Return the sid and the type of the unix group.
****************************************************************************/

static bool get_group_map_from_sid(DOM_SID sid, GROUP_MAP *map)
{
	TDB_DATA dbuf;
	char *key = NULL;
	fstring string_sid;
	int ret = 0;

	/* the key is the SID, retrieving is direct */

	sid_to_fstring(string_sid, &sid);
	if (asprintf(&key, "%s%s", GROUP_PREFIX, string_sid) < 0) {
		return false;
	}

	dbuf = tdb_fetch_bystring(tdb, key);
	if (!dbuf.dptr) {
		SAFE_FREE(key);
		return false;
	}

	SAFE_FREE(key);

	ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddff",
			&map->gid, &map->sid_name_use,
			&map->nt_name, &map->comment);

	SAFE_FREE(dbuf.dptr);

	if ( ret == -1 ) {
		DEBUG(3,("get_group_map_from_sid: tdb_unpack failure\n"));
		return False;
	}

	sid_copy(&map->sid, &sid);

	return True;
}

/****************************************************************************
 Return the sid and the type of the unix group.
****************************************************************************/

static bool get_group_map_from_gid(gid_t gid, GROUP_MAP *map)
{
	TDB_DATA kbuf, dbuf, newkey;
	fstring string_sid;
	int ret;

	/* we need to enumerate the TDB to find the GID */

	for (kbuf = tdb_firstkey(tdb);
	     kbuf.dptr;
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		if (strncmp((const char *)kbuf.dptr, GROUP_PREFIX, strlen(GROUP_PREFIX)) != 0) continue;

		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr)
			continue;

		fstrcpy(string_sid, (const char *)kbuf.dptr+strlen(GROUP_PREFIX));

		string_to_sid(&map->sid, string_sid);

		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddff",
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

static bool get_group_map_from_ntname(const char *name, GROUP_MAP *map)
{
	TDB_DATA kbuf, dbuf, newkey;
	fstring string_sid;
	int ret;

	/* we need to enumerate the TDB to find the name */

	for (kbuf = tdb_firstkey(tdb);
	     kbuf.dptr;
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		if (strncmp((const char *)kbuf.dptr, GROUP_PREFIX, strlen(GROUP_PREFIX)) != 0) continue;

		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr)
			continue;

		fstrcpy(string_sid, (const char *)kbuf.dptr+strlen(GROUP_PREFIX));

		string_to_sid(&map->sid, string_sid);

		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddff",
				 &map->gid, &map->sid_name_use, &map->nt_name, &map->comment);

		SAFE_FREE(dbuf.dptr);

		if ( ret == -1 ) {
			DEBUG(3,("get_group_map_from_ntname: tdb_unpack failure\n"));
			return False;
		}

		if ( strequal(name, map->nt_name) ) {
			SAFE_FREE(kbuf.dptr);
			return True;
		}
	}

	return False;
}

/****************************************************************************
 Remove a group mapping entry.
****************************************************************************/

static bool group_map_remove(const DOM_SID *sid)
{
	TDB_DATA dbuf;
	char *key = NULL;
	fstring string_sid;
	bool ret;

	/* the key is the SID, retrieving is direct */

	sid_to_fstring(string_sid, sid);
	if (asprintf(&key, "%s%s", GROUP_PREFIX, string_sid) < 0) {
		return false;
	}

	dbuf = tdb_fetch_bystring(tdb, key);
	if (!dbuf.dptr) {
		SAFE_FREE(key);
		return false;
	}

	SAFE_FREE(dbuf.dptr);

	ret = (tdb_delete_bystring(tdb, key) == TDB_SUCCESS);
	SAFE_FREE(key);
	return ret;
}

/****************************************************************************
 Enumerate the group mapping.
****************************************************************************/

static bool enum_group_mapping(const DOM_SID *domsid, enum lsa_SidType sid_name_use, GROUP_MAP **pp_rmap,
			size_t *p_num_entries, bool unix_only)
{
	TDB_DATA kbuf, dbuf, newkey;
	fstring string_sid;
	GROUP_MAP map;
	GROUP_MAP *mapt;
	int ret;
	size_t entries=0;
	DOM_SID grpsid;
	uint32 rid;

	*p_num_entries=0;
	*pp_rmap=NULL;

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		if (strncmp((const char *)kbuf.dptr, GROUP_PREFIX, strlen(GROUP_PREFIX)) != 0)
			continue;

		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr)
			continue;

		fstrcpy(string_sid, (const char *)kbuf.dptr+strlen(GROUP_PREFIX));
				
		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddff",
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

		string_to_sid(&grpsid, string_sid);
		sid_copy( &map.sid, &grpsid );
		
		sid_split_rid( &grpsid, &rid );

		/* Only check the domain if we were given one */

		if ( domsid && !sid_equal( domsid, &grpsid ) ) {
			DEBUG(11,("enum_group_mapping: group %s is not in "
				  "domain %s\n", string_sid,
				  sid_string_dbg(domsid)));
			continue;
		}

		DEBUG(11,("enum_group_mapping: returning group %s of "
			  "type %s\n", map.nt_name,
			  sid_type_lookup(map.sid_name_use)));

		(*pp_rmap) = SMB_REALLOC_ARRAY((*pp_rmap), GROUP_MAP, entries+1);
		if (!(*pp_rmap)) {
			DEBUG(0,("enum_group_mapping: Unable to enlarge group map!\n"));
			return False;
		}

		mapt = (*pp_rmap);

		mapt[entries].gid = map.gid;
		sid_copy( &mapt[entries].sid, &map.sid);
		mapt[entries].sid_name_use = map.sid_name_use;
		fstrcpy(mapt[entries].nt_name, map.nt_name);
		fstrcpy(mapt[entries].comment, map.comment);

		entries++;

	}

	*p_num_entries=entries;

	return True;
}

/* This operation happens on session setup, so it should better be fast. We
 * store a list of aliases a SID is member of hanging off MEMBEROF/SID. */

static NTSTATUS one_alias_membership(const DOM_SID *member,
			       DOM_SID **sids, size_t *num)
{
	fstring tmp;
	fstring key;
	char *string_sid;
	TDB_DATA dbuf;
	const char *p;
	NTSTATUS status = NT_STATUS_OK;
	TALLOC_CTX *frame;

	slprintf(key, sizeof(key), "%s%s", MEMBEROF_PREFIX,
		 sid_to_fstring(tmp, member));

	dbuf = tdb_fetch_bystring(tdb, key);

	if (dbuf.dptr == NULL) {
		return NT_STATUS_OK;
	}

	p = (const char *)dbuf.dptr;
	frame = talloc_stackframe();
	while (next_token_talloc(frame, &p, &string_sid, " ")) {
		DOM_SID alias;

		if (!string_to_sid(&alias, string_sid))
			continue;

		status= add_sid_to_array_unique(NULL, &alias, sids, num);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

done:
	TALLOC_FREE(frame);
	SAFE_FREE(dbuf.dptr);
	return status;
}

static NTSTATUS alias_memberships(const DOM_SID *members, size_t num_members,
				  DOM_SID **sids, size_t *num)
{
	size_t i;

	*num = 0;
	*sids = NULL;

	for (i=0; i<num_members; i++) {
		NTSTATUS status = one_alias_membership(&members[i], sids, num);
		if (!NT_STATUS_IS_OK(status))
			return status;
	}
	return NT_STATUS_OK;
}

static bool is_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	DOM_SID *sids;
	size_t i, num;

	/* This feels the wrong way round, but the on-disk data structure
	 * dictates it this way. */
	if (!NT_STATUS_IS_OK(alias_memberships(member, 1, &sids, &num)))
		return False;

	for (i=0; i<num; i++) {
		if (sid_compare(alias, &sids[i]) == 0) {
			TALLOC_FREE(sids);
			return True;
		}
	}
	TALLOC_FREE(sids);
	return False;
}


static NTSTATUS add_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	GROUP_MAP map;
	TDB_DATA dbuf;
	char *key = NULL;
	fstring string_sid;
	char *new_memberstring;
	int result;

	if (!get_group_map_from_sid(*alias, &map))
		return NT_STATUS_NO_SUCH_ALIAS;

	if ( (map.sid_name_use != SID_NAME_ALIAS) &&
	     (map.sid_name_use != SID_NAME_WKN_GRP) )
		return NT_STATUS_NO_SUCH_ALIAS;

	if (is_aliasmem(alias, member))
		return NT_STATUS_MEMBER_IN_ALIAS;

	sid_to_fstring(string_sid, member);
	if (asprintf(&key, "%s%s", MEMBEROF_PREFIX, string_sid) < 0) {
		return NT_STATUS_NO_MEMORY;
	}

	dbuf = tdb_fetch_bystring(tdb, key);

	sid_to_fstring(string_sid, alias);

	if (dbuf.dptr != NULL) {
		asprintf(&new_memberstring, "%s %s", (char *)(dbuf.dptr),
			 string_sid);
	} else {
		new_memberstring = SMB_STRDUP(string_sid);
	}

	if (new_memberstring == NULL) {
		SAFE_FREE(key);
		return NT_STATUS_NO_MEMORY;
	}

	SAFE_FREE(dbuf.dptr);
	dbuf = string_term_tdb_data(new_memberstring);

	result = tdb_store_bystring(tdb, key, dbuf, 0);

	SAFE_FREE(new_memberstring);
	SAFE_FREE(key);

	return (result == 0 ? NT_STATUS_OK : NT_STATUS_ACCESS_DENIED);
}

struct aliasmem_closure {
	const DOM_SID *alias;
	DOM_SID **sids;
	size_t *num;
};

static int collect_aliasmem(TDB_CONTEXT *tdb_ctx, TDB_DATA key, TDB_DATA data,
			    void *state)
{
	struct aliasmem_closure *closure = (struct aliasmem_closure *)state;
	const char *p;
	char *alias_string;
	TALLOC_CTX *frame;

	if (strncmp((const char *)key.dptr, MEMBEROF_PREFIX,
		    strlen(MEMBEROF_PREFIX)) != 0)
		return 0;

	p = (const char *)data.dptr;

	frame = talloc_stackframe();
	while (next_token_talloc(frame, &p, &alias_string, " ")) {
		DOM_SID alias, member;
		const char *member_string;

		if (!string_to_sid(&alias, alias_string))
			continue;

		if (sid_compare(closure->alias, &alias) != 0)
			continue;

		/* Ok, we found the alias we're looking for in the membership
		 * list currently scanned. The key represents the alias
		 * member. Add that. */

		member_string = strchr((const char *)key.dptr, '/');

		/* Above we tested for MEMBEROF_PREFIX which includes the
		 * slash. */

		SMB_ASSERT(member_string != NULL);
		member_string += 1;

		if (!string_to_sid(&member, member_string))
			continue;

		if (!NT_STATUS_IS_OK(add_sid_to_array(NULL, &member,
						      closure->sids,
						      closure->num)))
		{
			/* talloc fail. */
			break;
		}
	}

	TALLOC_FREE(frame);
	return 0;
}

static NTSTATUS enum_aliasmem(const DOM_SID *alias, DOM_SID **sids, size_t *num)
{
	GROUP_MAP map;
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

static NTSTATUS del_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	NTSTATUS result;
	DOM_SID *sids;
	size_t i, num;
	bool found = False;
	char *member_string;
	TDB_DATA dbuf;
	char *key = NULL;
	fstring sid_string;

	result = alias_memberships(member, 1, &sids, &num);

	if (!NT_STATUS_IS_OK(result))
		return result;

	for (i=0; i<num; i++) {
		if (sid_compare(&sids[i], alias) == 0) {
			found = True;
			break;
		}
	}

	if (!found) {
		TALLOC_FREE(sids);
		return NT_STATUS_MEMBER_NOT_IN_ALIAS;
	}

	if (i < num)
		sids[i] = sids[num-1];

	num -= 1;

	sid_to_fstring(sid_string, member);
	if (asprintf(&key, "%s%s", MEMBEROF_PREFIX, sid_string) < 0) {
		TALLOC_FREE(sids);
		return NT_STATUS_NO_MEMORY;
	}

	if (num == 0) {
		NTSTATUS ret = (tdb_delete_bystring(tdb, key) == 0 ?
			NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL);
		TALLOC_FREE(sids);
		SAFE_FREE(key);
		return ret;
	}

	member_string = SMB_STRDUP("");

	if (member_string == NULL) {
		TALLOC_FREE(sids);
		SAFE_FREE(key);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<num; i++) {
		char *s = member_string;

		sid_to_fstring(sid_string, &sids[i]);
		asprintf(&member_string, "%s %s", s, sid_string);

		SAFE_FREE(s);
		if (member_string == NULL) {
			TALLOC_FREE(sids);
			SAFE_FREE(key);
			return NT_STATUS_NO_MEMORY;
		}
	}

	dbuf = string_term_tdb_data(member_string);

	result = tdb_store_bystring(tdb, key, dbuf, 0) == 0 ?
		NT_STATUS_OK : NT_STATUS_ACCESS_DENIED;

	TALLOC_FREE(sids);
	SAFE_FREE(member_string);
	SAFE_FREE(key);

	return result;
}


static const struct mapping_backend tdb_backend = {
	.add_mapping_entry         = add_mapping_entry,
	.get_group_map_from_sid    = get_group_map_from_sid,
	.get_group_map_from_gid    = get_group_map_from_gid,
	.get_group_map_from_ntname = get_group_map_from_ntname,
	.group_map_remove          = group_map_remove,
	.enum_group_mapping        = enum_group_mapping,
	.one_alias_membership      = one_alias_membership,
	.add_aliasmem              = add_aliasmem,
	.del_aliasmem              = del_aliasmem,
	.enum_aliasmem             = enum_aliasmem	
};

/*
  initialise the tdb mapping backend
 */
const struct mapping_backend *groupdb_tdb_init(void)
{
	if (!init_group_mapping()) {
		DEBUG(0,("Failed to initialise tdb mapping backend\n"));
		return NULL;
	}

	return &tdb_backend;
}
