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

PRIVS privs[] = {
	{SE_PRIV_NONE,           "no_privs",                  "No privilege"                    }, /* this one MUST be first */
	{SE_PRIV_ADD_MACHINES,   "SeMachineAccountPrivilege", "Add workstations to the domain"  },
	{SE_PRIV_SEC_PRIV,       "SeSecurityPrivilege",       "Manage the audit logs"           },
	{SE_PRIV_TAKE_OWNER,     "SeTakeOwnershipPrivilege",  "Take ownership of file"          },
	{SE_PRIV_ADD_USERS,      "SaAddUsers",                "Add users to the domain - Samba" },
	{SE_PRIV_PRINT_OPERATOR, "SaPrintOp",                 "Add or remove printers - Samba"  },
	{SE_PRIV_ALL,            "SaAllPrivs",                "all privileges"                  }
};
/*
PRIVS privs[] = {
	{  2, "SeCreateTokenPrivilege" },
	{  3, "SeAssignPrimaryTokenPrivilege" },
	{  4, "SeLockMemoryPrivilege" },
	{  5, "SeIncreaseQuotaPrivilege" },
	{  6, "SeMachineAccountPrivilege" },
	{  7, "SeTcbPrivilege" },
	{  8, "SeSecurityPrivilege" },
	{  9, "SeTakeOwnershipPrivilege" },
	{ 10, "SeLoadDriverPrivilege" },
	{ 11, "SeSystemProfilePrivilege" },
	{ 12, "SeSystemtimePrivilege" },
	{ 13, "SeProfileSingleProcessPrivilege" },
	{ 14, "SeIncreaseBasePriorityPrivilege" },
	{ 15, "SeCreatePagefilePrivilege" },
	{ 16, "SeCreatePermanentPrivilege" },
	{ 17, "SeBackupPrivilege" },
	{ 18, "SeRestorePrivilege" },
	{ 19, "SeShutdownPrivilege" },
	{ 20, "SeDebugPrivilege" },
	{ 21, "SeAuditPrivilege" },
	{ 22, "SeSystemEnvironmentPrivilege" },
	{ 23, "SeChangeNotifyPrivilege" },
	{ 24, "SeRemoteShutdownPrivilege" },
	{ 25, "SeUndockPrivilege" },
	{ 26, "SeSyncAgentPrivilege" },
	{ 27, "SeEnableDelegationPrivilege" },
};
*/

	/*
	 * Those are not really privileges like the other ones.
	 * They are handled in a special case and called
	 * system privileges.
	 *
	 * SeNetworkLogonRight
	 * SeUnsolicitedInputPrivilege
	 * SeBatchLogonRight
	 * SeServiceLogonRight
	 * SeInteractiveLogonRight
	 * SeDenyInteractiveLogonRight
	 * SeDenyNetworkLogonRight
	 * SeDenyBatchLogonRight
	 * SeDenyBatchLogonRight
	 */

#if 0
/****************************************************************************
check if the user has the required privilege.
****************************************************************************/
static BOOL se_priv_access_check(NT_USER_TOKEN *token, uint32 privilege)
{
	/* no token, no privilege */
	if (token==NULL)
		return False;
	
	if ((token->privilege & privilege)==privilege)
		return True;
	
	return False;
}
#endif

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
	LUID_ATTR set;

	PRIVILEGE_SET privilege_none;
	PRIVILEGE_SET privilege_all;
	PRIVILEGE_SET privilege_print_op;

	init_privilege(&privilege_none);
	init_privilege(&privilege_all);
	init_privilege(&privilege_print_op);

	set.attr=0;
	set.luid.high=0;
	set.luid.low=SE_PRIV_PRINT_OPERATOR;
	add_privilege(&privilege_print_op, set);

	add_all_privilege(&privilege_all);

	/* Add the Wellknown groups */

	add_initial_entry(-1, "S-1-5-32-544", SID_NAME_ALIAS, "Administrators", "", privilege_all, PR_ACCESS_FROM_NETWORK|PR_LOG_ON_LOCALLY);
	add_initial_entry(-1, "S-1-5-32-545", SID_NAME_ALIAS, "Users", "", privilege_none, PR_ACCESS_FROM_NETWORK|PR_LOG_ON_LOCALLY);
	add_initial_entry(-1, "S-1-5-32-546", SID_NAME_ALIAS, "Guests", "", privilege_none, PR_ACCESS_FROM_NETWORK);
	add_initial_entry(-1, "S-1-5-32-547", SID_NAME_ALIAS, "Power Users", "", privilege_none, PR_ACCESS_FROM_NETWORK|PR_LOG_ON_LOCALLY);

	add_initial_entry(-1, "S-1-5-32-548", SID_NAME_ALIAS, "Account Operators", "", privilege_none, PR_ACCESS_FROM_NETWORK|PR_LOG_ON_LOCALLY);
	add_initial_entry(-1, "S-1-5-32-549", SID_NAME_ALIAS, "System Operators", "", privilege_none, PR_ACCESS_FROM_NETWORK|PR_LOG_ON_LOCALLY);
	add_initial_entry(-1, "S-1-5-32-550", SID_NAME_ALIAS, "Print Operators", "", privilege_print_op, PR_ACCESS_FROM_NETWORK|PR_LOG_ON_LOCALLY);
	add_initial_entry(-1, "S-1-5-32-551", SID_NAME_ALIAS, "Backup Operators", "", privilege_none, PR_ACCESS_FROM_NETWORK|PR_LOG_ON_LOCALLY);

	add_initial_entry(-1, "S-1-5-32-552", SID_NAME_ALIAS, "Replicators", "", privilege_none, PR_ACCESS_FROM_NETWORK);

	/* Add the defaults domain groups */

	sid_copy(&sid_admins, get_global_sam_sid());
	sid_append_rid(&sid_admins, DOMAIN_GROUP_RID_ADMINS);
	sid_to_string(str_admins, &sid_admins);
	add_initial_entry(-1, str_admins, SID_NAME_DOM_GRP, "Domain Admins", "", privilege_all, PR_ACCESS_FROM_NETWORK|PR_LOG_ON_LOCALLY);

	sid_copy(&sid_users,  get_global_sam_sid());
	sid_append_rid(&sid_users,  DOMAIN_GROUP_RID_USERS);
	sid_to_string(str_users, &sid_users);
	add_initial_entry(-1, str_users,  SID_NAME_DOM_GRP, "Domain Users",  "", privilege_none, PR_ACCESS_FROM_NETWORK|PR_LOG_ON_LOCALLY);

	sid_copy(&sid_guests, get_global_sam_sid());
	sid_append_rid(&sid_guests, DOMAIN_GROUP_RID_GUESTS);
	sid_to_string(str_guests, &sid_guests);
	add_initial_entry(-1, str_guests, SID_NAME_DOM_GRP, "Domain Guests", "", privilege_none, PR_ACCESS_FROM_NETWORK);

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
BOOL add_mapping_entry(GROUP_MAP *map, int flag)
{
	TDB_DATA kbuf, dbuf;
	pstring key, buf;
	fstring string_sid="";
	int len;
	int i;
	PRIVILEGE_SET *set;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
		return(False);
	}
	
	sid_to_string(string_sid, &map->sid);

	len = tdb_pack(buf, sizeof(buf), "ddffd",
			map->gid, map->sid_name_use, map->nt_name, map->comment, map->systemaccount);

	/* write the privilege list in the TDB database */

	set=&map->priv_set;
	len += tdb_pack(buf+len, sizeof(buf)-len, "d", set->count);
	for (i=0; i<set->count; i++)
		len += tdb_pack(buf+len, sizeof(buf)-len, "ddd", 
				set->set[i].luid.low, set->set[i].luid.high, set->set[i].attr);

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
BOOL add_initial_entry(gid_t gid, const char *sid, enum SID_NAME_USE sid_name_use,
		       const char *nt_name, const char *comment, PRIVILEGE_SET priv_set, uint32 systemaccount)
{
	GROUP_MAP map;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
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
	map.systemaccount=systemaccount;

	map.priv_set.count=priv_set.count;
	map.priv_set.set=priv_set.set;

	pdb_add_group_mapping_entry(&map);

	return True;
}

/****************************************************************************
initialise a privilege list
****************************************************************************/
void init_privilege(PRIVILEGE_SET *priv_set)
{
	priv_set->count=0;
	priv_set->control=0;
	priv_set->set=NULL;
}

/****************************************************************************
free a privilege list
****************************************************************************/
BOOL free_privilege(PRIVILEGE_SET *priv_set)
{
	if (priv_set->count==0) {
		DEBUG(100,("free_privilege: count=0, nothing to clear ?\n"));
		return False;
	}

	if (priv_set->set==NULL) {
		DEBUG(0,("free_privilege: list ptr is NULL, very strange !\n"));
		return False;
	}

	safe_free(priv_set->set);
	priv_set->count=0;
	priv_set->control=0;
	priv_set->set=NULL;

	return True;
}

/****************************************************************************
add a privilege to a privilege array
****************************************************************************/
BOOL add_privilege(PRIVILEGE_SET *priv_set, LUID_ATTR set)
{
	LUID_ATTR *new_set;

	/* check if the privilege is not already in the list */
	if (check_priv_in_privilege(priv_set, set))
		return False;

	/* we can allocate memory to add the new privilege */

	new_set=(LUID_ATTR *)Realloc(priv_set->set, (priv_set->count+1)*(sizeof(LUID_ATTR)));
	if (new_set==NULL) {
		DEBUG(0,("add_privilege: could not Realloc memory to add a new privilege\n"));
		return False;
	}

	new_set[priv_set->count].luid.high=set.luid.high;
	new_set[priv_set->count].luid.low=set.luid.low;
	new_set[priv_set->count].attr=set.attr;
	
	priv_set->count++;
	priv_set->set=new_set;
	
	return True;	
}

/****************************************************************************
add all the privileges to a privilege array
****************************************************************************/
BOOL add_all_privilege(PRIVILEGE_SET *priv_set)
{
	LUID_ATTR set;

	set.attr=0;
	set.luid.high=0;
	
	set.luid.low=SE_PRIV_ADD_USERS;
	add_privilege(priv_set, set);

	set.luid.low=SE_PRIV_ADD_MACHINES;
	add_privilege(priv_set, set);

	set.luid.low=SE_PRIV_PRINT_OPERATOR;
	add_privilege(priv_set, set);
	
	return True;
}

/****************************************************************************
check if the privilege list is empty
****************************************************************************/
BOOL check_empty_privilege(PRIVILEGE_SET *priv_set)
{
	return (priv_set->count == 0);
}

/****************************************************************************
check if the privilege is in the privilege list
****************************************************************************/
BOOL check_priv_in_privilege(PRIVILEGE_SET *priv_set, LUID_ATTR set)
{
	int i;

	/* if the list is empty, obviously we can't have it */
	if (check_empty_privilege(priv_set))
		return False;

	for (i=0; i<priv_set->count; i++) {
		LUID_ATTR *cur_set;

		cur_set=&priv_set->set[i];
		/* check only the low and high part. Checking the attr field has no meaning */
		if( (cur_set->luid.low==set.luid.low) && (cur_set->luid.high==set.luid.high) )
			return True;
	}

	return False;
}

/****************************************************************************
remove a privilege from a privilege array
****************************************************************************/
BOOL remove_privilege(PRIVILEGE_SET *priv_set, LUID_ATTR set)
{
	LUID_ATTR *new_set;
	LUID_ATTR *old_set;
	int i,j;

	/* check if the privilege is in the list */
	if (!check_priv_in_privilege(priv_set, set))
		return False;

	/* special case if it's the only privilege in the list */
	if (priv_set->count==1) {
		free_privilege(priv_set);
		init_privilege(priv_set);	
	
		return True;
	}

	/* 
	 * the privilege is there, create a new list,
	 * and copy the other privileges
	 */

	old_set=priv_set->set;

	new_set=(LUID_ATTR *)malloc((priv_set->count-1)*(sizeof(LUID_ATTR)));
	if (new_set==NULL) {
		DEBUG(0,("remove_privilege: could not malloc memory for new privilege list\n"));
		return False;
	}

	for (i=0, j=0; i<priv_set->count; i++) {
		if ((old_set[i].luid.low==set.luid.low) && 
		    (old_set[i].luid.high==set.luid.high)) {
		    	continue;
		}
		
		new_set[j].luid.low=old_set[i].luid.low;
		new_set[j].luid.high=old_set[i].luid.high;
		new_set[j].attr=old_set[i].attr;

		j++;
	}
	
	if (j!=priv_set->count-1) {
		DEBUG(0,("remove_privilege: mismatch ! difference is not -1\n"));
		DEBUGADD(0,("old count:%d, new count:%d\n", priv_set->count, j));
		safe_free(new_set);
		return False;
	}
		
	/* ok everything is fine */
	
	priv_set->count--;
	priv_set->set=new_set;
	
	safe_free(old_set);
	
	return True;	
}

/****************************************************************************
 Return the sid and the type of the unix group.
****************************************************************************/

BOOL get_group_map_from_sid(DOM_SID sid, GROUP_MAP *map, BOOL with_priv)
{
	TDB_DATA kbuf, dbuf;
	pstring key;
	fstring string_sid;
	int ret;
	int i;
	PRIVILEGE_SET *set;
	
	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
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

	ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddffd",
				&map->gid, &map->sid_name_use, &map->nt_name, &map->comment, &map->systemaccount);

	set=&map->priv_set;
	init_privilege(set);
	ret += tdb_unpack(dbuf.dptr+ret, dbuf.dsize-ret, "d", &set->count);

	DEBUG(10,("get_group_map_from_sid: %d privileges\n", map->priv_set.count));

	set->set = NULL;
	if (set->count) {
		set->set=(LUID_ATTR *)smb_xmalloc(set->count*sizeof(LUID_ATTR));
	}

	for (i=0; i<set->count; i++)
		ret += tdb_unpack(dbuf.dptr+ret, dbuf.dsize-ret, "ddd", 
				&(set->set[i].luid.low), &(set->set[i].luid.high), &(set->set[i].attr));

	SAFE_FREE(dbuf.dptr);
	if (ret != dbuf.dsize) {
		DEBUG(0,("get_group_map_from_sid: group mapping TDB corrupted ?\n"));
		free_privilege(set);
		return False;
	}

	/* we don't want the privileges */
	if (with_priv==MAPPING_WITHOUT_PRIV)
		free_privilege(set);

	sid_copy(&map->sid, &sid);
	
	return True;
}

/****************************************************************************
 Return the sid and the type of the unix group.
****************************************************************************/

BOOL get_group_map_from_gid(gid_t gid, GROUP_MAP *map, BOOL with_priv)
{
	TDB_DATA kbuf, dbuf, newkey;
	fstring string_sid;
	int ret;
	int i;
	PRIVILEGE_SET *set;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
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
		
		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddffd",
				 &map->gid, &map->sid_name_use, &map->nt_name, &map->comment, &map->systemaccount);

		set=&map->priv_set;
		ret += tdb_unpack(dbuf.dptr+ret, dbuf.dsize-ret, "d", &set->count);
		set->set = NULL;
		if (set->count) {
			set->set=(LUID_ATTR *)smb_xmalloc(set->count*sizeof(LUID_ATTR));
		}

		for (i=0; i<set->count; i++)
			ret += tdb_unpack(dbuf.dptr+ret, dbuf.dsize-ret, "ddd", 
					&(set->set[i].luid.low), &(set->set[i].luid.high), &(set->set[i].attr));

		SAFE_FREE(dbuf.dptr);
		if (ret != dbuf.dsize){
			free_privilege(set);
			continue;
		}

		if (gid==map->gid) {
			if (!with_priv)
				free_privilege(&map->priv_set);
			return True;
		}
		
		free_privilege(set);
	}

	return False;
}

/****************************************************************************
 Return the sid and the type of the unix group.
****************************************************************************/

BOOL get_group_map_from_ntname(char *name, GROUP_MAP *map, BOOL with_priv)
{
	TDB_DATA kbuf, dbuf, newkey;
	fstring string_sid;
	int ret;
	int i;
	PRIVILEGE_SET *set;

	if(!init_group_mapping()) {
		DEBUG(0,("get_group_map_from_ntname:failed to initialize group mapping"));
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
		
		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddffd",
				 &map->gid, &map->sid_name_use, &map->nt_name, &map->comment, &map->systemaccount);

		set=&map->priv_set;
		ret += tdb_unpack(dbuf.dptr+ret, dbuf.dsize-ret, "d", &set->count);
	
		set->set=(LUID_ATTR *)malloc(set->count*sizeof(LUID_ATTR));
		if (set->set==NULL) {
			DEBUG(0,("get_group_map_from_ntname: could not allocate memory for privileges\n"));
			return False;
		}

		for (i=0; i<set->count; i++)
			ret += tdb_unpack(dbuf.dptr+ret, dbuf.dsize-ret, "ddd", 
					&(set->set[i].luid.low), &(set->set[i].luid.high), &(set->set[i].attr));

		SAFE_FREE(dbuf.dptr);
		if (ret != dbuf.dsize) {
			free_privilege(set);
			continue;
		}

		if (StrCaseCmp(name, map->nt_name)==0) {
			if (!with_priv)
				free_privilege(&map->priv_set);
			return True;
		}

		free_privilege(set);
	}

	return False;
}

/****************************************************************************
 Remove a group mapping entry.
****************************************************************************/

BOOL group_map_remove(DOM_SID sid)
{
	TDB_DATA kbuf, dbuf;
	pstring key;
	fstring string_sid;
	
	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
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

BOOL enum_group_mapping(enum SID_NAME_USE sid_name_use, GROUP_MAP **rmap,
			int *num_entries, BOOL unix_only, BOOL with_priv)
{
	TDB_DATA kbuf, dbuf, newkey;
	fstring string_sid;
	fstring group_type;
	GROUP_MAP map;
	GROUP_MAP *mapt;
	int ret;
	int entries=0;
	int i;
	PRIVILEGE_SET *set;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
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
				
		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddffd",
				 &map.gid, &map.sid_name_use, &map.nt_name, &map.comment, &map.systemaccount);

		set=&map.priv_set;
		init_privilege(set);
		
		ret += tdb_unpack(dbuf.dptr+ret, dbuf.dsize-ret, "d", &set->count);
	
		if (set->count!=0) {
			set->set=(LUID_ATTR *)malloc(set->count*sizeof(LUID_ATTR));
			if (set->set==NULL) {
				DEBUG(0,("enum_group_mapping: could not allocate memory for privileges\n"));
				return False;
			}
		}

		for (i=0; i<set->count; i++)
			ret += tdb_unpack(dbuf.dptr+ret, dbuf.dsize-ret, "ddd", 
					&(set->set[i].luid.low), &(set->set[i].luid.high), &(set->set[i].attr));

		SAFE_FREE(dbuf.dptr);
		if (ret != dbuf.dsize) {
			DEBUG(11,("enum_group_mapping: error in memory size\n"));
			free_privilege(set);
			continue;
		}

		/* list only the type or everything if UNKNOWN */
		if (sid_name_use!=SID_NAME_UNKNOWN  && sid_name_use!=map.sid_name_use) {
			DEBUG(11,("enum_group_mapping: group %s is not of the requested type\n", map.nt_name));
			free_privilege(set);
			continue;
		}
		
		if (unix_only==ENUM_ONLY_MAPPED && map.gid==-1) {
			DEBUG(11,("enum_group_mapping: group %s is non mapped\n", map.nt_name));
			free_privilege(set);
			continue;
		}

		string_to_sid(&map.sid, string_sid);
		
		decode_sid_name_use(group_type, map.sid_name_use);
		DEBUG(11,("enum_group_mapping: returning group %s of type %s\n", map.nt_name ,group_type));

		mapt=(GROUP_MAP *)Realloc((*rmap), (entries+1)*sizeof(GROUP_MAP));
		if (!mapt) {
			DEBUG(0,("enum_group_mapping: Unable to enlarge group map!\n"));
			SAFE_FREE(*rmap);
			free_privilege(set);
			return False;
		}
		else
			(*rmap) = mapt;

		mapt[entries].gid = map.gid;
		sid_copy( &mapt[entries].sid, &map.sid);
		mapt[entries].sid_name_use = map.sid_name_use;
		fstrcpy(mapt[entries].nt_name, map.nt_name);
		fstrcpy(mapt[entries].comment, map.comment);
		mapt[entries].systemaccount=map.systemaccount;
		mapt[entries].priv_set.count=set->count;
		mapt[entries].priv_set.control=set->control;
		mapt[entries].priv_set.set=set->set;
		if (!with_priv)
			free_privilege(&(mapt[entries].priv_set));

		entries++;
	}

	*num_entries=entries;
	return True;
}


/****************************************************************************
convert a privilege string to a privilege array
****************************************************************************/
void convert_priv_from_text(PRIVILEGE_SET *se_priv, char *privilege)
{
	pstring tok;
	const char *p = privilege;
	int i;
	LUID_ATTR set;

	/* By default no privilege */
	init_privilege(se_priv);
	
	if (privilege==NULL)
		return;

	while(next_token(&p, tok, " ", sizeof(tok)) ) {
		for (i=0; i<=PRIV_ALL_INDEX; i++) {
			if (StrCaseCmp(privs[i].priv, tok)==0) {
				set.attr=0;
				set.luid.high=0;
				set.luid.low=privs[i].se_priv;
				add_privilege(se_priv, set);
			}
		}		
	}
}

/****************************************************************************
convert a privilege array to a privilege string
****************************************************************************/
void convert_priv_to_text(PRIVILEGE_SET *se_priv, char *privilege)
{
	int i,j;

	if (privilege==NULL)
		return;

	ZERO_STRUCTP(privilege);

	if (check_empty_privilege(se_priv)) {
		fstrcat(privilege, "No privilege");
		return;
	}

	for(i=0; i<se_priv->count; i++) {
		j=1;
		while (privs[j].se_priv!=se_priv->set[i].luid.low && j<=PRIV_ALL_INDEX) {
			j++;
		}

		fstrcat(privilege, privs[j].priv);
		fstrcat(privilege, " ");
	}
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

BOOL get_domain_group_from_sid(DOM_SID sid, GROUP_MAP *map, BOOL with_priv)
{
	struct group *grp;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
		return(False);
	}

	DEBUG(10, ("get_domain_group_from_sid\n"));

	/* if the group is NOT in the database, it CAN NOT be a domain group */
	if(!pdb_getgrsid(map, sid, with_priv))
		return False;

	DEBUG(10, ("get_domain_group_from_sid: SID found in the TDB\n"));

	/* if it's not a domain group, continue */
	if (map->sid_name_use!=SID_NAME_DOM_GRP) {
		if (with_priv)
			free_privilege(&map->priv_set);
		return False;
	}

	DEBUG(10, ("get_domain_group_from_sid: SID is a domain group\n"));
 	
	if (map->gid==-1) {
		if (with_priv)
			free_privilege(&map->priv_set);
		return False;
	}

	DEBUG(10, ("get_domain_group_from_sid: SID is mapped to gid:%d\n",map->gid));

	if ( (grp=getgrgid(map->gid)) == NULL) {
		DEBUG(10, ("get_domain_group_from_sid: gid DOESN'T exist in UNIX security\n"));
		if (with_priv)
			free_privilege(&map->priv_set);
		return False;
	}

	DEBUG(10, ("get_domain_group_from_sid: gid exists in UNIX security\n"));

	return True;
}


/* get a local (alias) group from it's SID */

BOOL get_local_group_from_sid(DOM_SID sid, GROUP_MAP *map, BOOL with_priv)
{
	struct group *grp;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
		return(False);
	}

	/* The group is in the mapping table */
	if(pdb_getgrsid(map, sid, with_priv)) {
		if (map->sid_name_use!=SID_NAME_ALIAS) {
			if (with_priv)
				free_privilege(&map->priv_set);
			return False;
 		}
		
		if (map->gid==-1) {
			if (with_priv)
				free_privilege(&map->priv_set);
			return False;
		}

		if ( (grp=getgrgid(map->gid)) == NULL) {
			if (with_priv)
				free_privilege(&map->priv_set);
			return False;
		}
	} else {
		/* the group isn't in the mapping table.
		 * make one based on the unix information */
		uint32 alias_rid;

		sid_peek_rid(&sid, &alias_rid);
		map->gid=pdb_group_rid_to_gid(alias_rid);

		if ((grp=getgrgid(map->gid)) == NULL)
			return False;

		map->sid_name_use=SID_NAME_ALIAS;
		map->systemaccount=PR_ACCESS_FROM_NETWORK;

		fstrcpy(map->nt_name, grp->gr_name);
		fstrcpy(map->comment, "Local Unix Group");

		init_privilege(&map->priv_set);

		sid_copy(&map->sid, &sid);
	}

	return True;
}

/* get a builtin group from it's SID */

BOOL get_builtin_group_from_sid(DOM_SID sid, GROUP_MAP *map, BOOL with_priv)
{
	struct group *grp;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
		return(False);
	}

	if(!pdb_getgrsid(map, sid, with_priv))
		return False;

	if (map->sid_name_use!=SID_NAME_WKN_GRP) {
		if (with_priv)
			free_privilege(&map->priv_set);
		return False;
	}

	if (map->gid==-1) {
		if (with_priv)
			free_privilege(&map->priv_set);
		return False;
	}

	if ( (grp=getgrgid(map->gid)) == NULL) {
		if (with_priv)
			free_privilege(&map->priv_set);
		return False;
	}

	return True;
}



/****************************************************************************
Returns a GROUP_MAP struct based on the gid.
****************************************************************************/
BOOL get_group_from_gid(gid_t gid, GROUP_MAP *map, BOOL with_priv)
{
	struct group *grp;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
		return(False);
	}

	if ( (grp=getgrgid(gid)) == NULL)
		return False;

	/*
	 * make a group map from scratch if doesn't exist.
	 */
	if (!pdb_getgrgid(map, gid, with_priv)) {
		map->gid=gid;
		map->sid_name_use=SID_NAME_ALIAS;
		map->systemaccount=PR_ACCESS_FROM_NETWORK;
		init_privilege(&map->priv_set);

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
            
 give back an array of uid
 return the grand number of users


 TODO: sort the list and remove duplicate. JFM.

****************************************************************************/
        
BOOL get_uid_list_of_group(gid_t gid, uid_t **uid, int *num_uids)
{
	struct group *grp;
	struct passwd *pwd;
	int i=0;
	char *gr;
	uid_t *u;
 
	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping"));
		return(False);
	}

	*num_uids = 0;
	*uid=NULL;
	
	if ( (grp=getgrgid(gid)) == NULL)
		return False;

	gr = grp->gr_mem[0];
	DEBUG(10, ("getting members\n"));
        
	while (gr && (*gr != (char)'\0')) {
		u = Realloc((*uid), sizeof(uid_t)*(*num_uids+1));
		if (!u) {
			DEBUG(0,("get_uid_list_of_group: unable to enlarge uid list!\n"));
			return False;
		}
		else (*uid) = u;

		if( (pwd=getpwnam_alloc(gr)) !=NULL) {
			(*uid)[*num_uids]=pwd->pw_uid;
			(*num_uids)++;
		}
		passwd_free(&pwd);
		gr = grp->gr_mem[++i];
	}
	DEBUG(10, ("got [%d] members\n", *num_uids));

	setpwent();
	while ((pwd=getpwent()) != NULL) {
		if (pwd->pw_gid==gid) {
			u = Realloc((*uid), sizeof(uid_t)*(*num_uids+1));
			if (!u) {
				DEBUG(0,("get_uid_list_of_group: unable to enlarge uid list!\n"));
				return False;
			}
			else (*uid) = u;
			(*uid)[*num_uids]=pwd->pw_uid;

			(*num_uids)++;
		}
	}
	endpwent();
	DEBUG(10, ("got primary groups, members: [%d]\n", *num_uids));

        return True;
}

/****************************************************************************
 Create a UNIX group on demand.
****************************************************************************/

int smb_create_group(char *unix_group, gid_t *new_gid)
{
	pstring add_script;
	int ret;
	int fd = 0;

	pstrcpy(add_script, lp_addgroup_script());
	if (! *add_script) return -1;
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

		if (*new_gid == 0) {
			/* The output was garbage. We assume nobody
                           will create group 0 via smbd. Now we try to
                           get the group via getgrnam. */

			struct group *grp = getgrnam(unix_group);
			if (grp != NULL)
				*new_gid = grp->gr_gid;
			else
				return 1;
		}
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

	pstrcpy(del_script, lp_delgroup_script());
	if (! *del_script) return -1;
	pstring_sub(del_script, "%g", unix_group);
	ret = smbrun(del_script,NULL);
	DEBUG(3,("smb_delete_group: Running the command `%s' gave %d\n",del_script,ret));
	return ret;
}

/****************************************************************************
 Set a user's primary UNIX group.
****************************************************************************/
int smb_set_primary_group(const char *unix_group, const char* unix_user)
{
	pstring add_script;
	int ret;

	pstrcpy(add_script, lp_setprimarygroup_script());
	if (! *add_script) return -1;
	all_string_sub(add_script, "%g", unix_group, sizeof(add_script));
	all_string_sub(add_script, "%u", unix_user, sizeof(add_script));
	ret = smbrun(add_script,NULL);
	DEBUG(3,("smb_set_primary_group: "
		 "Running the command `%s' gave %d\n",add_script,ret));
	return ret;
}

/****************************************************************************
 Add a user to a UNIX group.
****************************************************************************/

int smb_add_user_group(char *unix_group, char *unix_user)
{
	pstring add_script;
	int ret;

	pstrcpy(add_script, lp_addusertogroup_script());
	if (! *add_script) return -1;
	pstring_sub(add_script, "%g", unix_group);
	pstring_sub(add_script, "%u", unix_user);
	ret = smbrun(add_script,NULL);
	DEBUG(3,("smb_add_user_group: Running the command `%s' gave %d\n",add_script,ret));
	return ret;
}

/****************************************************************************
 Delete a user from a UNIX group
****************************************************************************/

int smb_delete_user_group(const char *unix_group, const char *unix_user)
{
	pstring del_script;
	int ret;

	pstrcpy(del_script, lp_deluserfromgroup_script());
	if (! *del_script) return -1;
	pstring_sub(del_script, "%g", unix_group);
	pstring_sub(del_script, "%u", unix_user);
	ret = smbrun(del_script,NULL);
	DEBUG(3,("smb_delete_user_group: Running the command `%s' gave %d\n",del_script,ret));
	return ret;
}
