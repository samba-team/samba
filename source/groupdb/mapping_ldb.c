/* 
 *  Unix SMB/CIFS implementation.
 *
 *  group mapping code on top of ldb
 *
 *  Copyright (C) Andrew Tridgell              2006
 *
 * based on tdb group mapping code from groupdb/mapping.c
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
#include "groupdb/mapping.h"
#include "lib/ldb/include/includes.h"
#include "lib/ldb/include/ldb_errors.h"

static struct ldb_context *ldb;

static BOOL mapping_upgrade(const char *tdb_path);

/*
  connect to the group mapping ldb
*/
 BOOL init_group_mapping(void)
{
	BOOL existed;
	const char *init_ldif[] = 
		{ "dn: @ATTRIBUTES\n" \
		  "ntName: CASE_INSENSITIVE\n" \
		  "\n",
		  "dn: @INDEXLIST\n" \
		  "@IDXATTR: gidNumber\n" \
		  "@IDXATTR: ntName\n" \
		  "@IDXATTR: member\n" };
	const char *db_path, *tdb_path;
	int ret;
	int flags = 0;

	if (ldb != NULL) {
		return True;
	}

	/* this is needed as Samba3 doesn't have this globally yet */
	ldb_global_init();

	db_path = lock_path("group_mapping.ldb");

	ldb = ldb_init(NULL);
	if (ldb == NULL) goto failed;

	existed = file_exist(db_path, NULL);

	if (lp_parm_bool(-1, "groupmap", "nosync", False)) {
		flags |= LDB_FLG_NOSYNC;
	}

	ret = ldb_connect(ldb, db_path, flags, NULL);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}
	
	if (!existed) {
		/* initialise the ldb with an index */
		struct ldb_ldif *ldif;
		int i;
		for (i=0;i<ARRAY_SIZE(init_ldif);i++) {
			ldif = ldb_ldif_read_string(ldb, &init_ldif[i]);
			if (ldif == NULL) goto failed;
			ret = ldb_add(ldb, ldif->msg);
			talloc_free(ldif);
			if (ret == -1) goto failed;
		}
	}

	/* possibly upgrade */
	tdb_path = lock_path("group_mapping.tdb");
	if (file_exist(tdb_path, NULL) && !mapping_upgrade(tdb_path)) {
		unlink(lock_path("group_mapping.ldb"));
		goto failed;
	}

	return True;

failed:
	DEBUG(0,("Failed to open group mapping ldb '%s' - '%s'\n",
		 db_path, ldb?ldb_errstring(ldb):strerror(errno)));
	talloc_free(ldb);
	ldb = NULL;
	return False;
}


/*
  form the DN for a mapping entry from a SID
 */
static struct ldb_dn *mapping_dn(TALLOC_CTX *mem_ctx, const DOM_SID *sid)
{
	fstring string_sid;
	uint32_t rid;
	DOM_SID domsid;

	sid_copy(&domsid, sid);
	if (!sid_split_rid(&domsid, &rid)) {
		return NULL;
	}
      	if (!sid_to_string(string_sid, &domsid)) {
		return NULL;
	}
	/* we split by domain and rid so we can do a subtree search
	   when we only want one domain */
	return ldb_dn_string_compose(mem_ctx, NULL, "rid=%u,domain=%s", 
				     rid, string_sid);
}

/*
  add a group mapping entry
 */
 BOOL add_mapping_entry(GROUP_MAP *map, int flag)
{
	struct ldb_message *msg;	
	int ret, i;
	fstring string_sid;

	if (!init_group_mapping()) {
		return False;
	}
	
	msg = ldb_msg_new(ldb);
	if (msg == NULL) {
		return False;
	}

	msg->dn = mapping_dn(msg, &map->sid);
	if (msg->dn == NULL) {
		goto failed;
	}

	if (ldb_msg_add_string(msg, "objectClass", "groupMap") != LDB_SUCCESS ||
	    ldb_msg_add_string(msg, "sid", 
			       sid_to_string(string_sid, &map->sid)) != LDB_SUCCESS ||
	    ldb_msg_add_fmt(msg, "gidNumber", "%u", (unsigned)map->gid) != LDB_SUCCESS ||
	    ldb_msg_add_fmt(msg, "sidNameUse", "%u", (unsigned)map->sid_name_use) != LDB_SUCCESS ||
	    ldb_msg_add_string(msg, "comment", map->comment) != LDB_SUCCESS ||
	    ldb_msg_add_string(msg, "ntName", map->nt_name) != LDB_SUCCESS) {
		goto failed;
	}

	ret = ldb_add(ldb, msg);

	/* if it exists we update it. This is a hangover from the semantics the
	   tdb backend had */
	if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
		for (i=0;i<msg->num_elements;i++) {
			msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
		}
		ret = ldb_modify(ldb, msg);
	}

	talloc_free(msg);

	return ret == LDB_SUCCESS;

failed:
	talloc_free(msg);
	return False;
}

/*
  unpack a ldb message into a GROUP_MAP structure
*/
static BOOL msg_to_group_map(struct ldb_message *msg, GROUP_MAP *map)
{
	const char *sidstr;

	map->gid          = ldb_msg_find_attr_as_int(msg, "gidNumber", -1);
	map->sid_name_use = ldb_msg_find_attr_as_int(msg, "sidNameUse", -1);
	fstrcpy(map->nt_name, ldb_msg_find_attr_as_string(msg, "ntName", NULL));
	fstrcpy(map->comment, ldb_msg_find_attr_as_string(msg, "comment", NULL));
	sidstr = ldb_msg_find_attr_as_string(msg, "sid", NULL);

	if (!string_to_sid(&map->sid, sidstr) ||
	    map->gid == (gid_t)-1 ||
	    map->sid_name_use == (enum lsa_SidType)-1) {
		DEBUG(0,("Unable to unpack group mapping\n"));
		return False;
	}

	return True;
}

/*
 return a group map entry for a given sid
*/
 BOOL get_group_map_from_sid(DOM_SID sid, GROUP_MAP *map)
{
	int ret;
	struct ldb_dn *dn;
	struct ldb_result *res=NULL;
	
	if (!init_group_mapping()) {
		return False;
	}

	dn = mapping_dn(ldb, &sid);
	if (dn == NULL) goto failed;

	ret = ldb_search(ldb, dn, LDB_SCOPE_BASE, NULL, NULL, &res);
	talloc_steal(dn, res);
	if (ret != LDB_SUCCESS || res->count != 1) {
		goto failed;
	}

	if (!msg_to_group_map(res->msgs[0], map)) goto failed;

	talloc_free(dn);
	return True;

failed:
	talloc_free(dn);
	return False;
}

/*
 return a group map entry for a given gid
*/
 BOOL get_group_map_from_gid(gid_t gid, GROUP_MAP *map)
{
	int ret;
	char *expr;
	struct ldb_result *res=NULL;

	if (!init_group_mapping()) {
		return False;
	}

	expr = talloc_asprintf(ldb, "(&(gidNumber=%u)(objectClass=groupMap))", 
			       (unsigned)gid);
	if (expr == NULL) goto failed;

	ret = ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, expr, NULL, &res);
	talloc_steal(expr, res);
	if (ret != LDB_SUCCESS || res->count != 1) goto failed;
	
	if (!msg_to_group_map(res->msgs[0], map)) goto failed;

	talloc_free(expr);
	return True;

failed:
	talloc_free(expr);
	return False;
}

/*
  Return the sid and the type of the unix group.
*/
 BOOL get_group_map_from_ntname(const char *name, GROUP_MAP *map)
{
	int ret;
	char *expr;
	struct ldb_result *res=NULL;

	if (!init_group_mapping()) {
		return False;
	}

	expr = talloc_asprintf(ldb, "(&(ntName=%s)(objectClass=groupMap))", name);
	if (expr == NULL) goto failed;

	ret = ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, expr, NULL, &res);
	talloc_steal(expr, res);
	if (ret != LDB_SUCCESS || res->count != 1) goto failed;
	
	if (!msg_to_group_map(res->msgs[0], map)) goto failed;

	talloc_free(expr);
	return True;

failed:
	talloc_free(expr);
	return False;
}

/*
 Remove a group mapping entry.
*/
 BOOL group_map_remove(const DOM_SID *sid)
{
	struct ldb_dn *dn;
	int ret;
	
	if (!init_group_mapping()) {
		return False;
	}

	dn = mapping_dn(ldb, sid);
	if (dn == NULL) {
		return False;
	}
	ret = ldb_delete(ldb, dn);
	talloc_free(dn);

	return ret == LDB_SUCCESS;
}


/*
  Enumerate the group mappings for a domain
*/
 BOOL enum_group_mapping(const DOM_SID *domsid, enum lsa_SidType sid_name_use, 
			 GROUP_MAP **pp_rmap,
			 size_t *p_num_entries, BOOL unix_only)
{
	int i, ret;
	char *expr;
	fstring name;
	struct ldb_result *res;
	struct ldb_dn *basedn=NULL;
	TALLOC_CTX *tmp_ctx;

	if (!init_group_mapping()) {
		return False;
	}

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) goto failed;

	if (sid_name_use == SID_NAME_UNKNOWN) {
		expr = talloc_asprintf(tmp_ctx, "(&(objectClass=groupMap))");
	} else {
		expr = talloc_asprintf(tmp_ctx, "(&(sidNameUse=%u)(objectClass=groupMap))",
				       sid_name_use);
	}
	if (expr == NULL) goto failed;

	/* we do a subtree search on the domain */
	if (domsid != NULL) {
		sid_to_string(name, domsid);
		basedn = ldb_dn_string_compose(tmp_ctx, NULL, "domain=%s", name);
		if (basedn == NULL) goto failed;
	}

	ret = ldb_search(ldb, basedn, LDB_SCOPE_SUBTREE, expr, NULL, &res);
	if (ret != LDB_SUCCESS) goto failed;

	(*pp_rmap) = NULL;
	*p_num_entries = 0;

	for (i=0;i<res->count;i++) {
		(*pp_rmap) = SMB_REALLOC_ARRAY((*pp_rmap), GROUP_MAP, 
					       (*p_num_entries)+1);
		if (!(*pp_rmap)) goto failed;

		if (!msg_to_group_map(res->msgs[i], &(*pp_rmap)[*p_num_entries])) {
			goto failed;
		}

		(*p_num_entries)++;
	}

	talloc_free(tmp_ctx);
	return True;

failed:
	talloc_free(tmp_ctx);
	return False;	
}

/* 
   This operation happens on session setup, so it should better be fast. We
   store a list of aliases a SID is member of hanging off MEMBEROF/SID. 
*/
 NTSTATUS one_alias_membership(const DOM_SID *member,
			       DOM_SID **sids, size_t *num)
{
	const char *attrs[] = {
		"sid",
		NULL
	};
	DOM_SID alias;
	char *expr;
	int ret, i;
	struct ldb_result *res=NULL;
	fstring string_sid;
	NTSTATUS status = NT_STATUS_INTERNAL_DB_CORRUPTION;

	if (!init_group_mapping()) {
		return NT_STATUS_ACCESS_DENIED;
	}

      	if (!sid_to_string(string_sid, member)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	expr = talloc_asprintf(ldb, "(&(member=%s)(objectClass=groupMap))", 
			       string_sid);
	if (expr == NULL) goto failed;

	ret = ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, expr, attrs, &res);
	talloc_steal(expr, res);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	for (i=0;i<res->count;i++) {
		struct ldb_message_element *el;
		el = ldb_msg_find_element(res->msgs[i], "sid");
		if (el == NULL || el->num_values != 1) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			goto failed;
		}
		string_to_sid(&alias, (char *)el->values[0].data);
		if (!add_sid_to_array_unique(NULL, &alias, sids, num)) {
			status = NT_STATUS_NO_MEMORY;
			goto failed;
		}
	}

	talloc_free(expr);
	return NT_STATUS_OK;

failed:
	talloc_free(expr);
	return status;
}

/*
  add/remove a member field
*/
static NTSTATUS modify_aliasmem(const DOM_SID *alias, const DOM_SID *member,
				int operation)
{
	fstring string_sid;
	int ret;
	struct ldb_message msg;
	struct ldb_message_element el;
	struct ldb_val val;
	TALLOC_CTX *tmp_ctx;
	GROUP_MAP map;

	if (!init_group_mapping()) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!get_group_map_from_sid(*alias, &map)) {
		sid_to_string(string_sid, alias);
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	if ((map.sid_name_use != SID_NAME_ALIAS) &&
	    (map.sid_name_use != SID_NAME_WKN_GRP)) {
		DEBUG(0,("sid_name_use=%d\n", map.sid_name_use));
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg.dn = mapping_dn(tmp_ctx, alias);
	if (msg.dn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	msg.num_elements = 1;
	msg.elements = &el;
	el.flags = operation;
	el.name = talloc_strdup(tmp_ctx, "member");
	el.num_values = 1;
	el.values = &val;
	sid_to_string(string_sid, member);
	val.data = (uint8_t *)string_sid;
	val.length = strlen(string_sid);

	ret = ldb_modify(ldb, &msg);
	talloc_free(tmp_ctx);

	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	if (operation == LDB_FLAG_MOD_ADD &&
	    ret == LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS) {
		return NT_STATUS_MEMBER_IN_ALIAS;
	}

	return (ret == LDB_SUCCESS ? NT_STATUS_OK : NT_STATUS_ACCESS_DENIED);
}

 NTSTATUS add_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	return modify_aliasmem(alias, member, LDB_FLAG_MOD_ADD);
}

 NTSTATUS del_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	return modify_aliasmem(alias, member, LDB_FLAG_MOD_DELETE);
}


/*
  enumerate sids that have the given alias set in member
*/
 NTSTATUS enum_aliasmem(const DOM_SID *alias, DOM_SID **sids, size_t *num)
{
	const char *attrs[] = {
		"member",
		NULL
	};
	int ret, i;
	struct ldb_result *res=NULL;
	struct ldb_dn *dn;
	struct ldb_message_element *el;
	
	if (!init_group_mapping()) {
		return NT_STATUS_ACCESS_DENIED;
	}

	*sids = NULL;
	*num = 0;

	dn = mapping_dn(ldb, alias);
	if (dn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_search(ldb, dn, LDB_SCOPE_BASE, NULL, attrs, &res);
	talloc_steal(dn, res);
	if (ret == LDB_SUCCESS && res->count == 0) {
		talloc_free(dn);
		return NT_STATUS_OK;
	}
	if (ret != LDB_SUCCESS) {
		talloc_free(dn);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	el = ldb_msg_find_element(res->msgs[0], "member");
	if (el == NULL) {
		talloc_free(dn);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	
	for (i=0;i<el->num_values;i++) {
		DOM_SID sid;
		string_to_sid(&sid, (const char *)el->values[i].data);
		if (!add_sid_to_array_unique(NULL, &sid, sids, num)) {
			talloc_free(dn);
			return NT_STATUS_NO_MEMORY;
		}
	}
	talloc_free(dn);

	return NT_STATUS_OK;
}

/*
  upgrade one group mapping record from the old tdb format
*/
static int upgrade_map_record(TDB_CONTEXT *tdb_ctx, TDB_DATA key, 
			      TDB_DATA data, void *state)
{
	int ret;
	GROUP_MAP map;

	if (strncmp(key.dptr, GROUP_PREFIX, 
		    MIN(key.dsize, strlen(GROUP_PREFIX))) != 0) {
		return 0;
	}

	if (!string_to_sid(&map.sid, strlen(GROUP_PREFIX) + (const char *)key.dptr)) {
		DEBUG(0,("Bad sid key '%s' during upgrade\n", (const char *)key.dptr));
		*(int *)state = -1;
		return -1;
	}

	ret = tdb_unpack(data.dptr, data.dsize, "ddff",
			 &map.gid, &map.sid_name_use, &map.nt_name, &map.comment);
	if (ret == -1) {
		DEBUG(0,("Failed to unpack group map record during upgrade\n"));
		*(int *)state = -1;
		return -1;
	}

	if (!add_mapping_entry(&map, 0)) {
		DEBUG(0,("Failed to add mapping entry during upgrade\n"));
		*(int *)state = -1;
		return -1;
	}

	return 0;
}

/*
  upgrade one alias record from the old tdb format
*/
static int upgrade_alias_record(TDB_CONTEXT *tdb_ctx, TDB_DATA key, 
				TDB_DATA data, void *state)
{
	const char *p = data.dptr;
	fstring string_sid;
	DOM_SID member;

	if (strncmp(key.dptr, MEMBEROF_PREFIX, 
		    MIN(key.dsize, strlen(MEMBEROF_PREFIX))) != 0) {
		return 0;
	}

	if (!string_to_sid(&member, strlen(MEMBEROF_PREFIX) + (const char *)key.dptr)) {
		DEBUG(0,("Bad alias key %s during upgrade\n",
			 (const char *)key.dptr));
		*(int *)state = -1;
	}

	while (next_token(&p, string_sid, " ", sizeof(string_sid))) {
		DOM_SID alias;
		NTSTATUS status;
		string_to_sid(&alias, string_sid);
		status = add_aliasmem(&alias, &member);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_ALIAS)) {
			DEBUG(0,("Ignoring orphaned alias record '%s'\n", 
				 string_sid));
		} else if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Failed to add alias member during upgrade - %s\n",
				 nt_errstr(status)));
			*(int *)state = -1;
			return -1;
		}
	}

	return 0;
}

/*
  upgrade from a old style tdb
*/
static BOOL mapping_upgrade(const char *tdb_path)
{
	static TDB_CONTEXT *tdb;
	int ret, status=0;
	pstring old_path;
	pstring new_path;

	tdb = tdb_open_log(tdb_path, 0, TDB_DEFAULT, O_RDWR, 0600);
	if (tdb == NULL) goto failed;

	/* we have to do the map records first, as alias records may
	   reference them */
	ret = tdb_traverse(tdb, upgrade_map_record, &status);
	if (ret == -1 || status == -1) goto failed;

	ret = tdb_traverse(tdb, upgrade_alias_record, &status);
	if (ret == -1 || status == -1) goto failed;

	if (tdb) {
		tdb_close(tdb);
		tdb = NULL;
	}

	pstrcpy(old_path, tdb_path);
	pstrcpy(new_path, lock_path("group_mapping.tdb.upgraded"));

	if (rename(old_path, new_path) != 0) {
		DEBUG(0,("Failed to rename old group mapping database\n"));
		goto failed;
	}
	return True;

failed:
	DEBUG(0,("Failed to upgrade group mapping database\n"));
	if (tdb) tdb_close(tdb);
	return False;
}
