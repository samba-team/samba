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

static TDB_CONTEXT *tdb; /* used for driver files */

#define DATABASE_VERSION_V1 1 /* native byte format. */
#define DATABASE_VERSION_V2 2 /* le format. */

#define GROUP_PREFIX "UNIXGROUP/"

/* Alias memberships are stored reverse, as memberships. The performance
 * critical operation is to determine the aliases a SID is member of, not
 * listing alias members. So we store a list of alias SIDs a SID is member of
 * hanging of the member as key.
 */
#define MEMBEROF_PREFIX "MEMBEROF/"

PRIVS privs[] = {
	{SE_PRIV_NONE,           "no_privs",                  "No privilege"                    }, /* this one MUST be first */
	{SE_PRIV_ADD_MACHINES,   "SeMachineAccountPrivilege", "Add workstations to the domain"  },
	{SE_PRIV_SEC_PRIV,       "SeSecurityPrivilege",       "Manage the audit logs"           },
	{SE_PRIV_TAKE_OWNER,     "SeTakeOwnershipPrivilege",  "Take ownership of file"          },
	{SE_PRIV_ADD_USERS,      "SaAddUsers",                "Add users to the domain - Samba" },
	{SE_PRIV_PRINT_OPERATOR, "SaPrintOp",                 "Add or remove printers - Samba"  },
	{SE_PRIV_ALL,            "SaAllPrivs",                "all privileges"                  }
};


/****************************************************************************
dump the mapping group mapping to a text file
****************************************************************************/
char *decode_sid_name_use(fstring group, enum SID_NAME_USE name_use)
{	
	static fstring group_type;

	switch(name_use) {
		case SID_NAME_USER:
			fstrcpy(group_type,"User");
			break;
		case SID_NAME_DOM_GRP:
			fstrcpy(group_type,"Domain group");
			break;
		case SID_NAME_DOMAIN:
			fstrcpy(group_type,"Domain");
			break;
		case SID_NAME_ALIAS:
			fstrcpy(group_type,"Local group");
			break;
		case SID_NAME_WKN_GRP:
			fstrcpy(group_type,"Builtin group");
			break;
		case SID_NAME_DELETED:
			fstrcpy(group_type,"Deleted");
			break;
		case SID_NAME_INVALID:
			fstrcpy(group_type,"Invalid");
			break;
		case SID_NAME_UNKNOWN:
		default:
			fstrcpy(group_type,"Unknown type");
			break;
	}
	
	fstrcpy(group, group_type);
	return group_type;
}

/****************************************************************************
initialise first time the mapping list - called from init_group_mapping()
****************************************************************************/
static BOOL default_group_mapping(void)
{
	DOM_SID sid_admins;
	DOM_SID sid_users;
	DOM_SID sid_guests;
	fstring str_admins;
	fstring str_users;
	fstring str_guests;

	/* Add the Wellknown groups */

	add_initial_entry(-1, "S-1-5-32-544", SID_NAME_WKN_GRP, "Administrators", "");
	add_initial_entry(-1, "S-1-5-32-545", SID_NAME_WKN_GRP, "Users", "");
	add_initial_entry(-1, "S-1-5-32-546", SID_NAME_WKN_GRP, "Guests", "");
	add_initial_entry(-1, "S-1-5-32-547", SID_NAME_WKN_GRP, "Power Users", "");
	add_initial_entry(-1, "S-1-5-32-548", SID_NAME_WKN_GRP, "Account Operators", "");
	add_initial_entry(-1, "S-1-5-32-549", SID_NAME_WKN_GRP, "System Operators", "");
	add_initial_entry(-1, "S-1-5-32-550", SID_NAME_WKN_GRP, "Print Operators", "");
	add_initial_entry(-1, "S-1-5-32-551", SID_NAME_WKN_GRP, "Backup Operators", "");
	add_initial_entry(-1, "S-1-5-32-552", SID_NAME_WKN_GRP, "Replicators", "");

	/* Add the defaults domain groups */

	sid_copy(&sid_admins, get_global_sam_sid());
	sid_append_rid(&sid_admins, DOMAIN_GROUP_RID_ADMINS);
	sid_to_string(str_admins, &sid_admins);
	add_initial_entry(-1, str_admins, SID_NAME_DOM_GRP, "Domain Admins", "");

	sid_copy(&sid_users,  get_global_sam_sid());
	sid_append_rid(&sid_users,  DOMAIN_GROUP_RID_USERS);
	sid_to_string(str_users, &sid_users);
	add_initial_entry(-1, str_users,  SID_NAME_DOM_GRP, "Domain Users",  "");

	sid_copy(&sid_guests, get_global_sam_sid());
	sid_append_rid(&sid_guests, DOMAIN_GROUP_RID_GUESTS);
	sid_to_string(str_guests, &sid_guests);
	add_initial_entry(-1, str_guests, SID_NAME_DOM_GRP, "Domain Guests", "");

	return True;
}

/****************************************************************************
 Open the group mapping tdb.
****************************************************************************/

static BOOL init_group_mapping(void)
{
	static pid_t local_pid;
	const char *vstring = "INFO/version";
	int32 vers_id;
	
	if (tdb && local_pid == sys_getpid())
		return True;
	tdb = tdb_open_log(lock_path("group_mapping.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open group mapping database\n"));
		return False;
	}

	local_pid = sys_getpid();

	/* handle a Samba upgrade */
	tdb_lock_bystring(tdb, vstring, 0);

	/* Cope with byte-reversed older versions of the db. */
	vers_id = tdb_fetch_int32(tdb, vstring);
	if ((vers_id == DATABASE_VERSION_V1) || (IREV(vers_id) == DATABASE_VERSION_V1)) {
		/* Written on a bigendian machine with old fetch_int code. Save as le. */
		tdb_store_int32(tdb, vstring, DATABASE_VERSION_V2);
		vers_id = DATABASE_VERSION_V2;
	}

	if (vers_id != DATABASE_VERSION_V2) {
		tdb_traverse(tdb, tdb_traverse_delete_fn, NULL);
		tdb_store_int32(tdb, vstring, DATABASE_VERSION_V2);
	}

	tdb_unlock_bystring(tdb, vstring);

	/* write a list of default groups */
	if(!default_group_mapping())
		return False;

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL add_mapping_entry(GROUP_MAP *map, int flag)
{
	TDB_DATA kbuf, dbuf;
	pstring key, buf;
	fstring string_sid="";
	int len;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}
	
	sid_to_string(string_sid, &map->sid);

	len = tdb_pack(buf, sizeof(buf), "ddff",
			map->gid, map->sid_name_use, map->nt_name, map->comment);

	if (len > sizeof(buf))
		return False;

	slprintf(key, sizeof(key), "%s%s", GROUP_PREFIX, string_sid);

	kbuf.dsize = strlen(key)+1;
	kbuf.dptr = key;
	dbuf.dsize = len;
	dbuf.dptr = buf;
	if (tdb_store(tdb, kbuf, dbuf, flag) != 0) return False;

	return True;
}

/****************************************************************************
initialise first time the mapping list
****************************************************************************/
BOOL add_initial_entry(gid_t gid, const char *sid, enum SID_NAME_USE sid_name_use, const char *nt_name, const char *comment)
{
	GROUP_MAP map;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}
	
	map.gid=gid;
	if (!string_to_sid(&map.sid, sid)) {
		DEBUG(0, ("string_to_sid failed: %s", sid));
		return False;
	}
	
	map.sid_name_use=sid_name_use;
	fstrcpy(map.nt_name, nt_name);
	fstrcpy(map.comment, comment);

	return pdb_add_group_mapping_entry(&map);
}

/****************************************************************************
 Return the sid and the type of the unix group.
****************************************************************************/

static BOOL get_group_map_from_sid(DOM_SID sid, GROUP_MAP *map)
{
	TDB_DATA kbuf, dbuf;
	pstring key;
	fstring string_sid;
	int ret = 0;
	
	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

	/* the key is the SID, retrieving is direct */

	sid_to_string(string_sid, &sid);
	slprintf(key, sizeof(key), "%s%s", GROUP_PREFIX, string_sid);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
		
	dbuf = tdb_fetch(tdb, kbuf);
	if (!dbuf.dptr)
		return False;

	ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddff",
				&map->gid, &map->sid_name_use, &map->nt_name, &map->comment);

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

static BOOL get_group_map_from_gid(gid_t gid, GROUP_MAP *map)
{
	TDB_DATA kbuf, dbuf, newkey;
	fstring string_sid;
	int ret;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

	/* we need to enumerate the TDB to find the GID */

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		if (strncmp(kbuf.dptr, GROUP_PREFIX, strlen(GROUP_PREFIX)) != 0) continue;
		
		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr)
			continue;

		fstrcpy(string_sid, kbuf.dptr+strlen(GROUP_PREFIX));

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

static BOOL get_group_map_from_ntname(const char *name, GROUP_MAP *map)
{
	TDB_DATA kbuf, dbuf, newkey;
	fstring string_sid;
	int ret;

	if(!init_group_mapping()) {
		DEBUG(0,("get_group_map_from_ntname:failed to initialize group mapping\n"));
		return(False);
	}

	/* we need to enumerate the TDB to find the name */

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {

		if (strncmp(kbuf.dptr, GROUP_PREFIX, strlen(GROUP_PREFIX)) != 0) continue;
		
		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr)
			continue;

		fstrcpy(string_sid, kbuf.dptr+strlen(GROUP_PREFIX));

		string_to_sid(&map->sid, string_sid);
		
		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddff",
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
 Remove a group mapping entry.
****************************************************************************/

static BOOL group_map_remove(DOM_SID sid)
{
	TDB_DATA kbuf, dbuf;
	pstring key;
	fstring string_sid;
	
	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

	/* the key is the SID, retrieving is direct */

	sid_to_string(string_sid, &sid);
	slprintf(key, sizeof(key), "%s%s", GROUP_PREFIX, string_sid);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
		
	dbuf = tdb_fetch(tdb, kbuf);
	if (!dbuf.dptr)
		return False;
	
	SAFE_FREE(dbuf.dptr);

	if(tdb_delete(tdb, kbuf) != TDB_SUCCESS)
		return False;

	return True;
}

/****************************************************************************
 Enumerate the group mapping.
****************************************************************************/

static BOOL enum_group_mapping(enum SID_NAME_USE sid_name_use, GROUP_MAP **rmap,
			int *num_entries, BOOL unix_only)
{
	TDB_DATA kbuf, dbuf, newkey;
	fstring string_sid;
	fstring group_type;
	GROUP_MAP map;
	GROUP_MAP *mapt;
	int ret;
	int entries=0;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

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

		fstrcpy(string_sid, kbuf.dptr+strlen(GROUP_PREFIX));
				
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

		string_to_sid(&map.sid, string_sid);
		
		decode_sid_name_use(group_type, map.sid_name_use);
		DEBUG(11,("enum_group_mapping: returning group %s of type %s\n", map.nt_name ,group_type));

		mapt=(GROUP_MAP *)Realloc((*rmap), (entries+1)*sizeof(GROUP_MAP));
		if (!mapt) {
			DEBUG(0,("enum_group_mapping: Unable to enlarge group map!\n"));
			SAFE_FREE(*rmap);
			return False;
		}
		else
			(*rmap) = mapt;

		mapt[entries].gid = map.gid;
		sid_copy( &mapt[entries].sid, &map.sid);
		mapt[entries].sid_name_use = map.sid_name_use;
		fstrcpy(mapt[entries].nt_name, map.nt_name);
		fstrcpy(mapt[entries].comment, map.comment);

		entries++;

	}

	*num_entries=entries;

	return True;
}

/* This operation happens on session setup, so it should better be fast. We
 * store a list of aliases a SID is member of hanging off MEMBEROF/SID. */

static NTSTATUS alias_memberships(const DOM_SID *sid, DOM_SID **sids, int *num)
{
	fstring key, string_sid;
	TDB_DATA kbuf, dbuf;
	const char *p;

	*num = 0;
	*sids = NULL;

	if (!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	sid_to_string(string_sid, sid);
	slprintf(key, sizeof(key), "%s%s", MEMBEROF_PREFIX, string_sid);

	kbuf.dsize = strlen(key)+1;
	kbuf.dptr = key;

	dbuf = tdb_fetch(tdb, kbuf);

	if (dbuf.dptr == NULL) {
		return NT_STATUS_OK;
	}

	p = dbuf.dptr;

	while (next_token(&p, string_sid, " ", sizeof(string_sid))) {

		DOM_SID alias;

		if (!string_to_sid(&alias, string_sid))
			continue;

		add_sid_to_array(&alias, sids, num);

		if (sids == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	SAFE_FREE(dbuf.dptr);
	return NT_STATUS_OK;
}

static BOOL is_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	DOM_SID *sids;
	int i, num;

	/* This feels the wrong way round, but the on-disk data structure
	 * dictates it this way. */
	if (!NT_STATUS_IS_OK(alias_memberships(member, &sids, &num)))
		return False;

	for (i=0; i<num; i++) {
		if (sid_compare(alias, &sids[i]) == 0) {
			SAFE_FREE(sids);
			return True;
		}
	}
	SAFE_FREE(sids);
	return False;
}

static NTSTATUS add_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	GROUP_MAP map;
	TDB_DATA kbuf, dbuf;
	pstring key;
	fstring string_sid;
	char *new_memberstring;
	int result;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!get_group_map_from_sid(*alias, &map))
		return NT_STATUS_NO_SUCH_ALIAS;

	if ( (map.sid_name_use != SID_NAME_ALIAS) &&
	     (map.sid_name_use != SID_NAME_WKN_GRP) )
		return NT_STATUS_NO_SUCH_ALIAS;

	if (is_aliasmem(alias, member))
		return NT_STATUS_MEMBER_IN_ALIAS;

	sid_to_string(string_sid, member);
	slprintf(key, sizeof(key), "%s%s", MEMBEROF_PREFIX, string_sid);

	kbuf.dsize = strlen(key)+1;
	kbuf.dptr = key;

	dbuf = tdb_fetch(tdb, kbuf);

	sid_to_string(string_sid, alias);

	if (dbuf.dptr != NULL) {
		asprintf(&new_memberstring, "%s %s", (char *)(dbuf.dptr),
			 string_sid);
	} else {
		new_memberstring = strdup(string_sid);
	}

	if (new_memberstring == NULL)
		return NT_STATUS_NO_MEMORY;

	SAFE_FREE(dbuf.dptr);
	dbuf.dsize = strlen(new_memberstring)+1;
	dbuf.dptr = new_memberstring;

	result = tdb_store(tdb, kbuf, dbuf, 0);

	SAFE_FREE(new_memberstring);

	return (result == 0 ? NT_STATUS_OK : NT_STATUS_ACCESS_DENIED);
}

struct aliasmem_closure {
	const DOM_SID *alias;
	DOM_SID **sids;
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

		DOM_SID alias, member;
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
		
		add_sid_to_array(&member, closure->sids, closure->num);
	}

	return 0;
}

static NTSTATUS enum_aliasmem(const DOM_SID *alias, DOM_SID **sids, int *num)
{
	GROUP_MAP map;
	struct aliasmem_closure closure;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

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
	int i, num;
	BOOL found = False;
	char *member_string;
	TDB_DATA kbuf, dbuf;
	pstring key;
	fstring sid_string;

	result = alias_memberships(member, &sids, &num);

	if (!NT_STATUS_IS_OK(result))
		return result;

	for (i=0; i<num; i++) {
		if (sid_compare(&sids[i], alias) == 0) {
			found = True;
			break;
		}
	}

	if (!found) {
		SAFE_FREE(sids);
		return NT_STATUS_MEMBER_NOT_IN_ALIAS;
	}

	if (i < num)
		sids[i] = sids[num-1];

	num -= 1;

	sid_to_string(sid_string, member);
	slprintf(key, sizeof(key), "%s%s", MEMBEROF_PREFIX, sid_string);

	kbuf.dsize = strlen(key)+1;
	kbuf.dptr = key;

	if (num == 0)
		return tdb_delete(tdb, kbuf) == 0 ?
			NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;

	member_string = strdup("");

	if (member_string == NULL) {
		SAFE_FREE(sids);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<num; i++) {
		char *s = member_string;

		sid_to_string(sid_string, &sids[i]);
		asprintf(&member_string, "%s %s", s, sid_string);

		SAFE_FREE(s);
		if (member_string == NULL) {
			SAFE_FREE(sids);
			return NT_STATUS_NO_MEMORY;
		}
	}

	dbuf.dsize = strlen(member_string)+1;
	dbuf.dptr = member_string;

	result = tdb_store(tdb, kbuf, dbuf, 0) == 0 ?
		NT_STATUS_OK : NT_STATUS_ACCESS_DENIED;

	SAFE_FREE(sids);
	SAFE_FREE(member_string);

	return result;
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

BOOL get_domain_group_from_sid(DOM_SID sid, GROUP_MAP *map)
{
	struct group *grp;
	BOOL ret;
	
	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

	DEBUG(10, ("get_domain_group_from_sid\n"));

	/* if the group is NOT in the database, it CAN NOT be a domain group */
	
	become_root();
	ret = pdb_getgrsid(map, sid);
	unbecome_root();
	
	if ( !ret ) 
		return False;

	DEBUG(10, ("get_domain_group_from_sid: SID found in the TDB\n"));

	/* if it's not a domain group, continue */
	if (map->sid_name_use!=SID_NAME_DOM_GRP) {
		return False;
	}

	DEBUG(10, ("get_domain_group_from_sid: SID is a domain group\n"));
 	
	if (map->gid==-1) {
		return False;
	}

	DEBUG(10, ("get_domain_group_from_sid: SID is mapped to gid:%lu\n",(unsigned long)map->gid));
	
	grp = getgrgid(map->gid);
	if ( !grp ) {
		DEBUG(10, ("get_domain_group_from_sid: gid DOESN'T exist in UNIX security\n"));
		return False;
	}

	DEBUG(10, ("get_domain_group_from_sid: gid exists in UNIX security\n"));

	return True;
}


/* get a local (alias) group from it's SID */

BOOL get_local_group_from_sid(DOM_SID *sid, GROUP_MAP *map)
{
	BOOL ret;
	
	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

	/* The group is in the mapping table */
	become_root();
	ret = pdb_getgrsid(map, *sid);
	unbecome_root();
	
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
		uint32 alias_rid;
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

/* get a builtin group from it's SID */

BOOL get_builtin_group_from_sid(DOM_SID *sid, GROUP_MAP *map)
{
	struct group *grp;
	BOOL ret;
	

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

	become_root();
	ret = pdb_getgrsid(map, *sid);
	unbecome_root();
	
	if ( !ret )
		return False;

	if (map->sid_name_use!=SID_NAME_WKN_GRP) {
		return False;
	}

	if (map->gid==-1) {
		return False;
	}

	if ( (grp=getgrgid(map->gid)) == NULL) {
		return False;
	}

	return True;
}



/****************************************************************************
Returns a GROUP_MAP struct based on the gid.
****************************************************************************/
BOOL get_group_from_gid(gid_t gid, GROUP_MAP *map)
{
	struct group *grp;
	BOOL ret;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

	if ( (grp=getgrgid(gid)) == NULL)
		return False;

	/*
	 * make a group map from scratch if doesn't exist.
	 */
	
	become_root();
	ret = pdb_getgrgid(map, gid);
	unbecome_root();
	
	if ( !ret ) {
		map->gid=gid;
		map->sid_name_use=SID_NAME_ALIAS;

		/* interim solution until we have a last RID allocated */

		sid_copy(&map->sid, get_global_sam_sid());
		sid_append_rid(&map->sid, pdb_gid_to_group_rid(gid));

		fstrcpy(map->nt_name, grp->gr_name);
		fstrcpy(map->comment, "Local Unix Group");
	}
	
	return True;
}




/****************************************************************************
 Get the member users of a group and
 all the users who have that group as primary.
            
 give back an array of SIDS
 return the grand number of users


 TODO: sort the list and remove duplicate. JFM.

****************************************************************************/
        
BOOL get_sid_list_of_group(gid_t gid, DOM_SID **sids, int *num_sids)
{
	struct group *grp;
	int i=0;
	char *gr;
	DOM_SID *s;

	struct sys_pwent *userlist;
	struct sys_pwent *user;
 
	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

	*num_sids = 0;
	*sids=NULL;
	
	if ( (grp=getgrgid(gid)) == NULL)
		return False;

	gr = grp->gr_mem[0];
	DEBUG(10, ("getting members\n"));
        
	while (gr && (*gr != (char)'\0')) {
		SAM_ACCOUNT *group_member_acct = NULL;
		BOOL found_user;
		s = Realloc((*sids), sizeof(**sids)*(*num_sids+1));
		if (!s) {
			DEBUG(0,("get_uid_list_of_group: unable to enlarge SID list!\n"));
			return False;
		}
		else (*sids) = s;

		if (!NT_STATUS_IS_OK(pdb_init_sam(&group_member_acct))) {
			continue;
		}

		become_root();
		found_user = pdb_getsampwnam(group_member_acct, gr);
		unbecome_root();
	
		if (found_user) {
			sid_copy(&(*sids)[*num_sids], pdb_get_user_sid(group_member_acct));
			(*num_sids)++;
		}
	
		pdb_free_sam(&group_member_acct);

		gr = grp->gr_mem[++i];
	}
	DEBUG(10, ("got [%d] members\n", *num_sids));

	winbind_off();

	user = userlist = getpwent_list();

	while (user != NULL) {

		SAM_ACCOUNT *group_member_acct = NULL;
		BOOL found_user;

		if (user->pw_gid != gid) {
			user = user->next;
			continue;
		}

		s = Realloc((*sids), sizeof(**sids)*(*num_sids+1));
		if (!s) {
			DEBUG(0,("get_sid_list_of_group: unable to enlarge "
				 "SID list!\n"));
			pwent_free(userlist);
			winbind_on();
			return False;
		}
		else (*sids) = s;
			
		if (!NT_STATUS_IS_OK(pdb_init_sam(&group_member_acct))) {
			continue;
		}
			
		become_root();
		found_user = pdb_getsampwnam(group_member_acct, user->pw_name);
		unbecome_root();
			
		if (found_user) {
			sid_copy(&(*sids)[*num_sids],
				 pdb_get_user_sid(group_member_acct));
			(*num_sids)++;
		} else {
			DEBUG(4,("get_sid_list_of_group: User %s [uid == %lu] "
				 "has no samba account\n",
				 user->pw_name, (unsigned long)user->pw_uid));
			if (algorithmic_uid_to_sid(&(*sids)[*num_sids],
						   user->pw_uid))
				(*num_sids)++;
		}
		pdb_free_sam(&group_member_acct);

		user = user->next;
	}
	pwent_free(userlist);
	DEBUG(10, ("got primary groups, members: [%d]\n", *num_sids));

	winbind_on();
        return True;
}

/****************************************************************************
 Create a UNIX group on demand.
****************************************************************************/

int smb_create_group(char *unix_group, gid_t *new_gid)
{
	pstring add_script;
	int 	ret = -1;
	int 	fd = 0;
	
	*new_gid = 0;

	/* defer to scripts */
	
	if ( *lp_addgroup_script() ) {
		pstrcpy(add_script, lp_addgroup_script());
		pstring_sub(add_script, "%g", unix_group);
		ret = smbrun(add_script, (new_gid!=NULL) ? &fd : NULL);
		DEBUG(3,("smb_create_group: Running the command `%s' gave %d\n",add_script,ret));
		if (ret != 0)
			return ret;
			
		if (fd != 0) {
			fstring output;

			*new_gid = 0;
			if (read(fd, output, sizeof(output)) > 0) {
				*new_gid = (gid_t)strtoul(output, NULL, 10);
			}
			
			close(fd);
		}

	} else if ( winbind_create_group( unix_group, NULL ) ) {

		DEBUG(3,("smb_create_group: winbindd created the group (%s)\n",
			unix_group));
		ret = 0;
	}
	
	if (*new_gid == 0) {
		struct group *grp = getgrnam(unix_group);

		if (grp != NULL)
			*new_gid = grp->gr_gid;
	}
			
	return ret;	
}

/****************************************************************************
 Delete a UNIX group on demand.
****************************************************************************/

int smb_delete_group(char *unix_group)
{
	pstring del_script;
	int ret;

	/* defer to scripts */
	
	if ( *lp_delgroup_script() ) {
		pstrcpy(del_script, lp_delgroup_script());
		pstring_sub(del_script, "%g", unix_group);
		ret = smbrun(del_script,NULL);
		DEBUG(3,("smb_delete_group: Running the command `%s' gave %d\n",del_script,ret));
		return ret;
	}

	if ( winbind_delete_group( unix_group ) ) {
		DEBUG(3,("smb_delete_group: winbindd deleted the group (%s)\n",
			unix_group));
		return 0;
	}
		
	return -1;
}

/****************************************************************************
 Set a user's primary UNIX group.
****************************************************************************/
int smb_set_primary_group(const char *unix_group, const char* unix_user)
{
	pstring add_script;
	int ret;

	/* defer to scripts */
	
	if ( *lp_setprimarygroup_script() ) {
		pstrcpy(add_script, lp_setprimarygroup_script());
		all_string_sub(add_script, "%g", unix_group, sizeof(add_script));
		all_string_sub(add_script, "%u", unix_user, sizeof(add_script));
		ret = smbrun(add_script,NULL);
		DEBUG(3,("smb_set_primary_group: "
			 "Running the command `%s' gave %d\n",add_script,ret));
		return ret;
	}

	/* Try winbindd */
	
	if ( winbind_set_user_primary_group( unix_user, unix_group ) ) {
		DEBUG(3,("smb_delete_group: winbindd set the group (%s) as the primary group for user (%s)\n",
			unix_group, unix_user));
		return 0;
	}		
	
	return -1;
}

/****************************************************************************
 Add a user to a UNIX group.
****************************************************************************/

int smb_add_user_group(char *unix_group, char *unix_user)
{
	pstring add_script;
	int ret;

	/* defer to scripts */
	
	if ( *lp_addusertogroup_script() ) {
		pstrcpy(add_script, lp_addusertogroup_script());
		pstring_sub(add_script, "%g", unix_group);
		pstring_sub(add_script, "%u", unix_user);
		ret = smbrun(add_script,NULL);
		DEBUG(3,("smb_add_user_group: Running the command `%s' gave %d\n",add_script,ret));
		return ret;
	}
	
	/* Try winbindd */

	if ( winbind_add_user_to_group( unix_user, unix_group ) ) {
		DEBUG(3,("smb_delete_group: winbindd added user (%s) to the group (%s)\n",
			unix_user, unix_group));
		return -1;
	}	
	
	return -1;
}

/****************************************************************************
 Delete a user from a UNIX group
****************************************************************************/

int smb_delete_user_group(const char *unix_group, const char *unix_user)
{
	pstring del_script;
	int ret;

	/* defer to scripts */
	
	if ( *lp_deluserfromgroup_script() ) {
		pstrcpy(del_script, lp_deluserfromgroup_script());
		pstring_sub(del_script, "%g", unix_group);
		pstring_sub(del_script, "%u", unix_user);
		ret = smbrun(del_script,NULL);
		DEBUG(3,("smb_delete_user_group: Running the command `%s' gave %d\n",del_script,ret));
		return ret;
	}
	
	/* Try winbindd */

	if ( winbind_remove_user_from_group( unix_user, unix_group ) ) {
		DEBUG(3,("smb_delete_group: winbindd removed user (%s) from the group (%s)\n",
			unix_user, unix_group));
		return 0;
	}
	
	return -1;
}


NTSTATUS pdb_default_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 DOM_SID sid)
{
	return get_group_map_from_sid(sid, map) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_default_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid)
{
	return get_group_map_from_gid(gid, map) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_default_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 const char *name)
{
	return get_group_map_from_ntname(name, map) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_default_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map)
{
	return add_mapping_entry(map, TDB_INSERT) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_default_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map)
{
	return add_mapping_entry(map, TDB_REPLACE) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_default_delete_group_mapping_entry(struct pdb_methods *methods,
						   DOM_SID sid)
{
	return group_map_remove(sid) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_default_enum_group_mapping(struct pdb_methods *methods,
					   enum SID_NAME_USE sid_name_use,
					   GROUP_MAP **rmap, int *num_entries,
					   BOOL unix_only)
{
	return enum_group_mapping(sid_name_use, rmap, num_entries, unix_only) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_default_find_alias(struct pdb_methods *methods,
				const char *name, DOM_SID *sid)
{
	GROUP_MAP map;

	if (!pdb_getgrnam(&map, name))
		return NT_STATUS_NO_SUCH_ALIAS;

	if ((map.sid_name_use != SID_NAME_WKN_GRP) &&
	    (map.sid_name_use != SID_NAME_ALIAS))
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	sid_copy(sid, &map.sid);
	return NT_STATUS_OK;
}

NTSTATUS pdb_default_create_alias(struct pdb_methods *methods,
				  const char *name, uint32 *rid)
{
	DOM_SID sid;
	enum SID_NAME_USE type;
	uint32 new_rid;
	gid_t gid;

	GROUP_MAP map;

	if (lookup_name(get_global_sam_name(), name, &sid, &type))
		return NT_STATUS_ALIAS_EXISTS;

	if (!winbind_allocate_rid(&new_rid))
		return NT_STATUS_ACCESS_DENIED;

	sid_copy(&sid, get_global_sam_sid());
	sid_append_rid(&sid, new_rid);

	/* Here we allocate the gid */
	if (!winbind_sid_to_gid(&gid, &sid)) {
		DEBUG(0, ("Could not get gid for new RID\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	map.gid = gid;
	sid_copy(&map.sid, &sid);
	map.sid_name_use = SID_NAME_ALIAS;
	fstrcpy(map.nt_name, name);
	fstrcpy(map.comment, "");

	if (!pdb_add_group_mapping_entry(&map)) {
		DEBUG(0, ("Could not add group mapping entry for alias %s\n",
			  name));
		return NT_STATUS_ACCESS_DENIED;
	}

	*rid = new_rid;

	return NT_STATUS_OK;
}

NTSTATUS pdb_default_delete_alias(struct pdb_methods *methods,
				  const DOM_SID *sid)
{
	return pdb_delete_group_mapping_entry(*sid) ?
		NT_STATUS_OK : NT_STATUS_ACCESS_DENIED;
}

NTSTATUS pdb_default_enum_aliases(struct pdb_methods *methods,
				  const DOM_SID *sid,
				  uint32 start_idx, uint32 max_entries,
				  uint32 *num_aliases,
				  struct acct_info **info)
{
	extern DOM_SID global_sid_Builtin;

	GROUP_MAP *map;
	int i, num_maps;
	enum SID_NAME_USE type = SID_NAME_UNKNOWN;

	if (sid_compare(sid, get_global_sam_sid()) == 0)
		type = SID_NAME_ALIAS;

	if (sid_compare(sid, &global_sid_Builtin) == 0)
		type = SID_NAME_WKN_GRP;

	if (!pdb_enum_group_mapping(type, &map, &num_maps, False) ||
	    (num_maps == 0)) {
		*num_aliases = 0;
		*info = NULL;
		goto done;
	}

	if (start_idx > num_maps) {
		*num_aliases = 0;
		*info = NULL;
		goto done;
	}

	*num_aliases = num_maps - start_idx;

	if (*num_aliases > max_entries)
		*num_aliases = max_entries;

	*info = malloc(sizeof(struct acct_info) * (*num_aliases));

	for (i=0; i<*num_aliases; i++) {
		fstrcpy((*info)[i].acct_name, map[i+start_idx].nt_name);
		fstrcpy((*info)[i].acct_desc, map[i+start_idx].comment);
		sid_peek_rid(&map[i].sid, &(*info)[i+start_idx].rid);
	}

 done:
	SAFE_FREE(map);
	return NT_STATUS_OK;
}

NTSTATUS pdb_default_get_aliasinfo(struct pdb_methods *methods,
				   const DOM_SID *sid,
				   struct acct_info *info)
{
	GROUP_MAP map;

	if (!pdb_getgrsid(&map, *sid))
		return NT_STATUS_NO_SUCH_ALIAS;

	fstrcpy(info->acct_name, map.nt_name);
	fstrcpy(info->acct_desc, map.comment);
	sid_peek_rid(&map.sid, &info->rid);
	return NT_STATUS_OK;
}

NTSTATUS pdb_default_set_aliasinfo(struct pdb_methods *methods,
				   const DOM_SID *sid,
				   struct acct_info *info)
{
	GROUP_MAP map;

	if (!pdb_getgrsid(&map, *sid))
		return NT_STATUS_NO_SUCH_ALIAS;

	fstrcpy(map.comment, info->acct_desc);

	if (!pdb_update_group_mapping_entry(&map))
		return NT_STATUS_ACCESS_DENIED;

	return NT_STATUS_OK;
}

NTSTATUS pdb_default_add_aliasmem(struct pdb_methods *methods,
				  const DOM_SID *alias, const DOM_SID *member)
{
	return add_aliasmem(alias, member);
}

NTSTATUS pdb_default_del_aliasmem(struct pdb_methods *methods,
				  const DOM_SID *alias, const DOM_SID *member)
{
	return del_aliasmem(alias, member);
}

NTSTATUS pdb_default_enum_aliasmem(struct pdb_methods *methods,
				   const DOM_SID *alias, DOM_SID **members,
				   int *num_members)
{
	return enum_aliasmem(alias, members, num_members);
}

NTSTATUS pdb_default_alias_memberships(struct pdb_methods *methods,
				       const DOM_SID *sid,
				       DOM_SID **aliases, int *num)
{
	return alias_memberships(sid, aliases, num);
}

/**********************************************************************
 no ops for passdb backends that don't implement group mapping
 *********************************************************************/

NTSTATUS pdb_nop_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 DOM_SID sid)
{
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_nop_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid)
{
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_nop_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 const char *name)
{
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_nop_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map)
{
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_nop_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map)
{
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_nop_delete_group_mapping_entry(struct pdb_methods *methods,
						   DOM_SID sid)
{
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_nop_enum_group_mapping(struct pdb_methods *methods,
					   enum SID_NAME_USE sid_name_use,
					   GROUP_MAP **rmap, int *num_entries,
					   BOOL unix_only)
{
	return NT_STATUS_UNSUCCESSFUL;
}

