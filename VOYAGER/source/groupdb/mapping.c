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

#define NAME_PREFIX "NAMEMAP/"
#define COMMENT_PREFIX "COMMENT/"
#define ALIAS_PREFIX "ALIAS/"

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

static BOOL add_initial_alias(const char *sid_str, const char *name)
{
	DOM_SID sid;
	TDB_DATA kbuf, dbuf;
	pstring key;

	/* Just a consistency check that we actually got a SID */

	if (!string_to_sid(&sid, sid_str))
		return False;

	slprintf(key, sizeof(key), "%s%s", ALIAS_PREFIX,
		 sid_string_static(&sid));

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = name;
	dbuf.dsize = strlen(name)+1;

	return (tdb_store(tdb, kbuf, dbuf, 0) == 0);
}

/****************************************************************************
initialise first time the mapping list - called from init_group_mapping()
****************************************************************************/
static BOOL default_group_mapping(void)
{
#if 0
	DOM_SID sid_admins;
	DOM_SID sid_users;
	DOM_SID sid_guests;
	fstring str_admins;
	fstring str_users;
	fstring str_guests;
#endif

	/* Add the Wellknown groups */

	add_initial_alias("S-1-5-32-544", "Administrators");
	add_initial_alias("S-1-5-32-545", "Users");
	add_initial_alias("S-1-5-32-546", "Guests");
	add_initial_alias("S-1-5-32-547", "Power Users");
	add_initial_alias("S-1-5-32-548", "Account Operators");
	add_initial_alias("S-1-5-32-549", "System Operators");
	add_initial_alias("S-1-5-32-550", "Print Operators");
	add_initial_alias("S-1-5-32-551", "Backup Operators");
	add_initial_alias("S-1-5-32-552", "Replicators");

	/* Add the defaults domain groups */

#if 0
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

#endif

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

/* This operation happens on session setup, so it should better be fast. We
 * store a list of aliases a SID is member of hanging off MEMBEROF/SID. */

static NTSTATUS alias_memberships(const DOM_SID *sid, DOM_SID **sids, int *num)
{
	fstring key, string_sid;
	TDB_DATA kbuf, dbuf;
	const char *p;

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

		if (*sids == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	SAFE_FREE(dbuf.dptr);
	return NT_STATUS_OK;
}

static BOOL is_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	DOM_SID *sids;
	int i, num;

	sids = NULL;
	num = 0;

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

static BOOL is_alias(const DOM_SID *sid)
{
	char *name;
	if (pdb_get_aliasname(NULL, sid, &name)) {
		SAFE_FREE(name);
		return True;
	}
	return False;
}

static NTSTATUS add_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	TDB_DATA kbuf, dbuf;
	pstring key;
	fstring string_sid;
	char *new_memberstring;
	int result;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!is_alias(alias))
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
	struct aliasmem_closure closure;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!is_alias(alias))
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

	sids = NULL;
	num = 0;

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

	if (num == 0) {
		SAFE_FREE(sids);
		return tdb_delete(tdb, kbuf) == 0 ?
			NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
	}

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

/****************************************************************************
 Create a UNIX user on demand.
****************************************************************************/

int smb_create_user(const char *domain, const char *unix_username, const char *homedir)
{
	pstring add_script;
	int ret;

	pstrcpy(add_script, lp_adduser_script());
	if (! *add_script)
		return -1;
	all_string_sub(add_script, "%u", unix_username, sizeof(pstring));
	if (domain)
		all_string_sub(add_script, "%D", domain, sizeof(pstring));
	if (homedir)
		all_string_sub(add_script, "%H", homedir, sizeof(pstring));
	ret = smbrun(add_script,NULL);
	DEBUG(3,("smb_create_user: Running the command `%s' gave %d\n",add_script,ret));
	return ret;
}

int smb_create_account(const char *add_script, const char *unix_username)
{
	pstring script;
	int ret;

	if (! *add_script)
		return -1;

	pstrcpy(script, add_script);
	all_string_sub(script, "%u", unix_username, sizeof(pstring));
	ret = smbrun(script,NULL);
	DEBUG(3,("smb_create_account: Running the command `%s' gave %d\n",
		 script,ret));
	return ret;
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

static BOOL aliaskey_to_sid(const char *key, DOM_SID *sid)
{
	char *p;

	if (strncmp(key, ALIAS_PREFIX, strlen(ALIAS_PREFIX)) != 0)
		return False;

	p = strchr(key, '/');

	if (p == NULL) {
		DEBUG(0, ("Weird -- strncmp found a / but strchr did not?\n"));
		return False;
	}

	p += 1;

	if (!string_to_sid(sid, p)) {
		DEBUG(3, ("Could not convert %s to SID -- tdb broken?\n", p));
		return False;
	}
	return True;

}

struct find_alias_closure {
	char *name;
	DOM_SID *sid;
	BOOL found;
};

static int find_this_alias(TDB_CONTEXT *tdb_ctx, TDB_DATA key, TDB_DATA data,
			   void *state)
{
	struct find_alias_closure *closure =
		(struct find_alias_closure *)state;
	char *name_lc;

	if (strncmp(key.dptr, ALIAS_PREFIX, strlen(ALIAS_PREFIX)) != 0)
		return 0;

	name_lc = strdup(data.dptr);
	strlower_m(name_lc);

	if (strcmp(name_lc, closure->name) != 0)
		return 0;

	SAFE_FREE(name_lc);

	if (aliaskey_to_sid(key.dptr, closure->sid)) {
		closure->found = True;
		return -1;
	}

	return 0;
}

NTSTATUS pdb_default_find_alias(struct pdb_methods *methods,
				const char *name, DOM_SID *sid)
{
	struct find_alias_closure closure;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	closure.name = strdup(name);
	strlower_m(closure.name);
	closure.sid = sid;
	closure.found = False;
	
	tdb_traverse(tdb, find_this_alias, &closure);

	SAFE_FREE(closure.name);

	return closure.found ? NT_STATUS_OK : NT_STATUS_NO_SUCH_ALIAS;
}

BOOL new_alias(const char *name, const DOM_SID *sid)
{
	return add_initial_alias(sid_string_static(sid), name);
}

NTSTATUS pdb_default_create_alias(struct pdb_methods *methods,
				  const char *name, uint32 *rid)
{
	DOM_SID sid;
	enum SID_NAME_USE type;
	uint32 new_rid;
	gid_t gid;

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

	sid_copy(&sid, get_global_sam_sid());
	sid_append_rid(&sid, new_rid);

	if (!add_initial_alias(sid_string_static(&sid), name)) {
		DEBUG(0, ("Could not add initial alias entry\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	*rid = new_rid;

	return NT_STATUS_OK;
}

NTSTATUS pdb_default_delete_alias(struct pdb_methods *methods,
				  const DOM_SID *sid)
{
	TDB_DATA kbuf;
	pstring key;

	slprintf(key, sizeof(key), "%s%s", ALIAS_PREFIX,
		 sid_string_static(sid));

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	return (tdb_delete(tdb, kbuf) == 0) ?
		NT_STATUS_OK : NT_STATUS_ACCESS_DENIED;
}

struct aliases_closure {
	const DOM_SID *sid;
	DOM_SID **sids;
	int *num_sids;
};

static int collect_alias(TDB_CONTEXT *tdb_ctx, TDB_DATA key, TDB_DATA data,
			 void *state)
{
	struct aliases_closure *closure = (struct aliases_closure *)state;
	fstring prefix;
	DOM_SID sid;

	slprintf(prefix, sizeof(prefix), "%s%s-", ALIAS_PREFIX,
		 sid_string_static(closure->sid));

	if (strncmp(key.dptr, prefix, strlen(prefix)) != 0)
		return 0;

	if (!aliaskey_to_sid(key.dptr, &sid))
		return 0;

	add_sid_to_array(&sid, closure->sids, closure->num_sids);
	return 0;
}

static char *maybe_talloc_strdup(TALLOC_CTX *mem_ctx, const char *p)
{
	return (mem_ctx != NULL) ? talloc_strdup(mem_ctx, p) : strdup(p);
}

static void enum_all_aliases(const DOM_SID *sid, DOM_SID **sids, int *num_sids)
{
	struct aliases_closure closure;

	closure.sid = sid;
	closure.sids = sids;
	closure.num_sids = num_sids;
	tdb_traverse(tdb, collect_alias, &closure);
}

NTSTATUS pdb_default_enum_aliases(struct pdb_methods *methods,
				  const DOM_SID *sid,
				  uint32 start_idx, uint32 max_entries,
				  uint32 *num_aliases,
				  struct acct_info **info)
{
	int i;
	DOM_SID *sids = NULL;
	int num_sids = 0;

	become_root();
	if(!init_group_mapping()) {
		unbecome_root();
		DEBUG(0,("failed to initialize group mapping\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	enum_all_aliases(sid, &sids, &num_sids);
	unbecome_root();

	if (start_idx > num_sids) {
		*num_aliases = 0;
		*info = NULL;
		goto done;
	}

	*num_aliases = num_sids - start_idx;

	if (*num_aliases > max_entries)
		*num_aliases = max_entries;

	if (*num_aliases == 0)
		goto done;

	*info = malloc(sizeof(struct acct_info) * (*num_aliases));

	for (i=0; i<*num_aliases; i++) {
		const DOM_SID *alias_sid = &(sids[i+start_idx]);
		char *str;

		if (pdb_get_aliasname(NULL, alias_sid, &str)) {
			fstrcpy((*info)[i].acct_name, str);
			SAFE_FREE(str);
		} else {
			DEBUG(1, ("Can't find alias %s just listed\n",
				  sid_string_static(alias_sid)));
			fstrcpy((*info)[i].acct_name, "***REMOVED***");
		}

		pdb_get_group_comment(NULL, (*info)[i].acct_name, &str);
		fstrcpy((*info)[i].acct_desc, str);
		SAFE_FREE(str);

		sid_peek_rid(alias_sid, &(*info)[i].rid);
	}

 done:
	SAFE_FREE(sids);
	return NT_STATUS_OK;
}

NTSTATUS pdb_default_get_aliasname(struct pdb_methods *methods,
				   TALLOC_CTX *mem_ctx, const DOM_SID *sid,
				   char **alias_name)
{
	TDB_DATA kbuf, dbuf;
	pstring key;
	fstring string_sid;
	
	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* the key is the SID, retrieving is direct */

	sid_to_string(string_sid, sid);
	slprintf(key, sizeof(key), "%s%s", ALIAS_PREFIX, string_sid);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
		
	dbuf = tdb_fetch(tdb, kbuf);
	if (!dbuf.dptr)
		return NT_STATUS_NO_SUCH_ALIAS;

	*alias_name = maybe_talloc_strdup(mem_ctx, dbuf.dptr);

	SAFE_FREE(dbuf.dptr);

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

/****************************************************************************
 These need to be redirected through pdb_interface.c
****************************************************************************/

void pdb_get_group_comment(TALLOC_CTX *mem_ctx, const char *unix_name,
			   char **comment)
{
	TDB_DATA kbuf, dbuf;
	pstring key;

	become_root();
	if(!init_group_mapping()) {
		unbecome_root();
		*comment = maybe_talloc_strdup(mem_ctx, "");
		DEBUG(0,("failed to initialize group mapping\n"));
		return;
	}

	slprintf(key, sizeof(key), "%s%s", COMMENT_PREFIX, unix_name);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	dbuf = tdb_fetch(tdb, kbuf);

	unbecome_root();

	*comment = maybe_talloc_strdup(mem_ctx,
				       (dbuf.dptr != NULL) ? dbuf.dptr : "");
	SAFE_FREE(dbuf.dptr);

	return;
}

BOOL pdb_set_group_comment(const char *unix_name, const char *comment)
{
	TDB_DATA kbuf, dbuf;
	pstring key;

	if(!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return False;
	}

	slprintf(key, sizeof(key), "%s%s", COMMENT_PREFIX, unix_name);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = comment;
	dbuf.dsize = strlen(comment)+1;

	return (tdb_store(tdb, kbuf, dbuf, 0) == 0);
}

/* NT to Unix name table.
 *
 * The idea is the following: The table is keyed on the lower-case
 * unix-charset of the nt-name to be able to search case-insensitively. The
 * values contain the correct-case ntname, the unix name and a BOOL is_user.
 *
 * nt_to_unix_name simply looks into the table.
 *
 * unix_to_nt_name never fails and auto-generates the appropriate entry. The
 * unified namespace problem is solved the following way: If we have to create
 * an entry, look whether an entry for the opposite side already exists. If
 * so, then append ".user" or ".group". If that happens to also exist try
 * random stuff.
 */

BOOL nt_to_unix_name(TALLOC_CTX *mem_ctx, const char *nt_name,
		     char **unix_name, BOOL *is_user)
{
	TDB_DATA kbuf, dbuf;
	char *lcname;
	char *key;
	int ret;
	fstring tmp_ntname;
	fstring tmp_unixname;

	if (!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

	lcname = strdup(nt_name);
	strlower_m(lcname);

	asprintf(&key, "%s%s", NAME_PREFIX, lcname);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	dbuf = tdb_fetch(tdb, kbuf);

	if (!dbuf.dptr)
		return False;

	ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ffd", tmp_ntname,
			 tmp_unixname, is_user);

	SAFE_FREE(lcname);
	SAFE_FREE(key);
	SAFE_FREE(dbuf.dptr);

	if (ret > 0) {
		*unix_name = maybe_talloc_strdup(mem_ctx, tmp_unixname);
		return True;
	}

	return False;
}

struct find_unixname_closure {
	TALLOC_CTX *mem_ctx;
	BOOL want_user;
	const char *unixname;
	char **ntname;
	BOOL found;
};

static BOOL find_name_entry(TDB_CONTEXT *ctx, TDB_DATA key, TDB_DATA dbuf,
			    void *data)
{
	struct find_unixname_closure *closure =
		(struct find_unixname_closure *)data;

	fstring ntname;
	fstring unixname;
	BOOL is_user;
	int ret;

	if (strncmp(key.dptr, NAME_PREFIX, strlen(NAME_PREFIX)) != 0)
		return False;

	ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ffd", ntname, unixname,
			 &is_user);

	if (ret == -1)
		return False;

	if ((closure->want_user != is_user) ||
	    (strcmp(closure->unixname, unixname) != 0))
		return False;

	*(closure->ntname) = maybe_talloc_strdup(closure->mem_ctx, ntname);

	closure->found = True;
	return True;
}

static BOOL set_name_mapping(const char *unixname, const char *ntname,
			     BOOL is_user, int tdb_flag)
{
	TDB_DATA kbuf, dbuf;
	char *lcname;
	char *key;
	pstring buf;
	int len;
	BOOL res;

	len = tdb_pack(buf, sizeof(buf), "ffd", ntname, unixname, is_user);

	if (len > sizeof(buf))
		return False;

	dbuf.dptr = buf;
	dbuf.dsize = len;

	lcname = strdup(ntname);
	strlower_m(lcname);

	asprintf(&key, "%s%s", NAME_PREFIX, lcname);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	res = (tdb_store(tdb, kbuf, dbuf, tdb_flag) == 0);

	SAFE_FREE(lcname);
	SAFE_FREE(key);
	return res;
}

BOOL create_name_mapping(const char *unixname, const char *ntname,
			 BOOL is_user)
{
	return set_name_mapping(unixname, ntname, is_user, TDB_INSERT);
}

/* This deletes all mappings, use with care! It's mainly for vampire */

BOOL delete_name_mappings(void)
{
	fstring pattern;
	TDB_LIST_NODE *nodes, *node;
	BOOL ok = True;

	if (!init_group_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return False;
	}

	fstr_sprintf(pattern, "%s*", NAME_PREFIX);

	nodes = tdb_search_keys(tdb, pattern);

	for (node = nodes; node != NULL; node = node->next) {
		if (tdb_delete(tdb, node->node_key) != 0)
			ok = False;
	}

	tdb_search_list_free(nodes);
	return ok;
}

static void generate_name_mapping(TALLOC_CTX *mem_ctx,
				  const char *unixname, char **ntname,
				  BOOL is_user)
{
	fstring generated_name;
	int attempts;

	if (set_name_mapping(unixname, unixname, is_user, TDB_INSERT)) {
		*ntname = maybe_talloc_strdup(mem_ctx, unixname);
		return;
	}

	slprintf(generated_name, sizeof(generated_name), "%s.%s",
		 unixname, is_user ? "user" : "group");

	if (set_name_mapping(unixname, generated_name, is_user, TDB_INSERT)) {
		*ntname = maybe_talloc_strdup(mem_ctx, generated_name);
		return;
	}

	/* Ok... Now try random stuff appended */

	for (attempts = 0; attempts < 5; attempts++) {
		slprintf(generated_name, sizeof(generated_name), "%s.%s",
			 unixname, generate_random_str(4));
		if (set_name_mapping(unixname, generated_name, is_user,
				     TDB_INSERT)) {
			*ntname = maybe_talloc_strdup(mem_ctx, generated_name);
			return;
		}
	}

	/* Weird... Completely random now */

	for (attempts = 0; attempts < 5; attempts++) {
		slprintf(generated_name, sizeof(generated_name), "%s",
			 generate_random_str(8));
		if (set_name_mapping(unixname, generated_name, is_user,
				     TDB_INSERT)) {
			*ntname = strdup(generated_name);
			return;
		}
	}

	smb_panic("Could not generate a NT name\n");
}

static void unix_name_to_nt_name(TALLOC_CTX *mem_ctx,
				 const char *unixname, char **ntname,
				 BOOL want_user)
{
	struct find_unixname_closure closure;
	closure.mem_ctx = mem_ctx;
	closure.want_user = want_user;
	closure.unixname = unixname;
	closure.ntname = ntname;
	closure.found = False;

	become_root();
	if (!init_group_mapping()) {
		unbecome_root();
		DEBUG(0,("failed to initialize group mapping\n"));
		return;
	}

	tdb_traverse(tdb, find_name_entry, &closure);

	if (closure.found) {
		unbecome_root();
		return;
	}

	generate_name_mapping(mem_ctx, unixname, ntname, want_user);
	unbecome_root();
}

void unix_username_to_ntname(TALLOC_CTX *mem_ctx,
			     const char *unixname, char **ntname)
{
	unix_name_to_nt_name(mem_ctx, unixname, ntname, True);
}

void unix_groupname_to_ntname(TALLOC_CTX *mem_ctx,
			      const char *unixname, char **ntname)
{
	unix_name_to_nt_name(mem_ctx, unixname, ntname, False);
}
