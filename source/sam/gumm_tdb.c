/*
 * Unix SMB/CIFS implementation. 
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Simo Sorce 2000-2002
 * Copyright (C) Gerald Carter 2000
 * Copyright (C) Jeremy Allison 2001
 * Copyright (C) Andrew Bartlett 2002
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "gums.h"
#include "tdbsam2.h"
#include "tdbsam2_parse_info.h"

static int tdbgumm_debug_level = DBGC_ALL;
#undef DBGC_CLASS
#define DBGC_CLASS tdbgumm_debug_level

#define TDBSAM_VERSION		"20021215"
#define TDB_FILE_NAME		"tdbsam2.tdb"
#define DOMAINPREFIX		"DOMAIN_"
#define OBJECTPREFIX		"OBJECT_"
#define SIDPREFIX		"SID_"
#define PRIVILEGEPREFIX		"PRIV_"

#define TDB_FORMAT_STRING	"ddB"

union tdbsam2_data {
	struct tdbsam2_domain_data *domain;
	struct tdbsam2_user_data *user;
	struct tdbsam2_group_data *group;
};

struct tdbsam2_object {
	uint32 type;
	union tdbsam2_data data;
};

static TDB_CONTEXT *tdbsam2_db;

#define TALLOC_CHECK(ptr, err, label) do { if ((ptr) == NULL) { DEBUG(0, ("%s: Out of memory!\n", __FUNCTION__)); err = NT_STATUS_NO_MEMORY; goto label; } } while(0)
#define SET_OR_FAIL(func, label) do { if (NT_STATUS_IS_ERR(func)) { DEBUG(0, ("%s: Setting gums object data failed!\n", __FUNCTION__)); goto label; } } while(0)

static NTSTATUS init_tdbsam2_object_from_buffer(struct tdbsam2_object *object, TALLOC_CTX *mem_ctx, char *buffer, int size) {

	return NT_STATUS_OK;
}

static NTSTATUS tdbsam2_opentdb(void) {

	return NT_STATUS_OK;
}

static NTSTATUS tdbsam2_get_object_by_name(struct tdbsam2_object *obj, TALLOC_CTX *mem_ctx, const char* name) {

	NTSTATUS ret;
	TDB_DATA data, key;
	fstring keystr;
	fstring objname;

	if (!obj || !mem_ctx || !name)
		return NT_STATUS_INVALID_PARAMETER;

	if (tdbsam2_db == NULL) {
		if (NT_STATUS_IS_ERR(ret = tdbsam2_opentdb())) {
			goto done;
		}
	}

	unix_strlower(name, -1, objname, sizeof(objname));

	slprintf(keystr, sizeof(keystr)-1, "%s%s", OBJECTPREFIX, objname);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(tdbsam2_db, key);
	if (!data.dptr) {
		DEBUG(5, ("get_domain_sid: Error fetching database, domain entry not found!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (NT_STATUS_IS_ERR(init_tdbsam2_object_from_buffer(obj, mem_ctx, data.dptr, data.dsize))) {
		SAFE_FREE(data.dptr);
		DEBUG(0, ("get_domain_sid: Error fetching database, malformed entry!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	SAFE_FREE(data.dptr);

	ret = NT_STATUS_OK;

done:
	return ret;
}


static NTSTATUS tdbsam2_store(struct tdbsam2_object *object) {

	NTSTATUS ret;

	return NT_STATUS_OK;
}

static NTSTATUS tdbsam2_get_next_sid(TALLOC_CTX *mem_ctx, DOM_SID *sid) {

	NTSTATUS ret;

	return NT_STATUS_OK;
}

static NTSTATUS tdbsam2_user_data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_user_data *userdata, uint32 type) {

	NTSTATUS ret;

	if (!object || !userdata) {
		DEBUG(0, ("tdbsam2_user_data_to_gums_object: no NULL pointers are accepted here!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* userdata->xcounter */
	/* userdata->sec_desc */

	SET_OR_FAIL(gums_set_object_sid(*object, userdata->user_sid), error);
	SET_OR_FAIL(gums_set_object_name(*object, userdata->name), error);

	SET_OR_FAIL(gums_set_user_pri_group(*object, userdata->group_sid), error);

	if (userdata->description)
		SET_OR_FAIL(gums_set_object_description(*object, userdata->description), error);

	if (userdata->full_name)
		SET_OR_FAIL(gums_set_user_fullname(*object, userdata->full_name), error);
	
	if (userdata->home_dir)
		SET_OR_FAIL(gums_set_user_homedir(*object, userdata->home_dir), error);

	if (userdata->dir_drive)
		SET_OR_FAIL(gums_set_user_dir_drive(*object, userdata->dir_drive), error);

	if (userdata->logon_script)
		SET_OR_FAIL(gums_set_user_logon_script(*object, userdata->logon_script), error);
	
	if (userdata->profile_path) 
		SET_OR_FAIL(gums_set_user_profile_path(*object, userdata->profile_path), error);

	if (userdata->workstations)
		SET_OR_FAIL(gums_set_user_workstations(*object, userdata->workstations), error);

	if (userdata->unknown_str)
		SET_OR_FAIL(gums_set_user_unknown_str(*object, userdata->unknown_str), error);

	if (userdata->munged_dial)
		SET_OR_FAIL(gums_set_user_munged_dial(*object, userdata->munged_dial), error);

	SET_OR_FAIL(gums_set_user_logon_divs(*object, userdata->logon_divs), error);
	SET_OR_FAIL(gums_set_user_hours_len(*object, userdata->hours_len), error);

	if (userdata->hours)
		SET_OR_FAIL(gums_set_user_hours(*object, userdata->hours), error);

	SET_OR_FAIL(gums_set_user_unknown_3(*object, userdata->unknown_3), error);
	SET_OR_FAIL(gums_set_user_unknown_5(*object, userdata->unknown_5), error);
	SET_OR_FAIL(gums_set_user_unknown_6(*object, userdata->unknown_6), error);

	SET_OR_FAIL(gums_set_user_logon_time(*object, userdata->logon_time), error);
	SET_OR_FAIL(gums_set_user_logoff_time(*object, userdata->logoff_time), error);
	SET_OR_FAIL(gums_set_user_kickoff_time(*object, userdata->kickoff_time), error);
	SET_OR_FAIL(gums_set_user_pass_last_set_time(*object, userdata->pass_last_set_time), error);
	SET_OR_FAIL(gums_set_user_pass_can_change_time(*object, userdata->pass_can_change_time), error);
	SET_OR_FAIL(gums_set_user_pass_must_change_time(*object, userdata->pass_must_change_time), error);

	ret = NT_STATUS_OK;
	return ret;
	
error:
	talloc_destroy((*object)->mem_ctx);
	*object = NULL;
	return ret;
}

static NTSTATUS tdbsam2_group_data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_group_data *groupdata, uint32 type) {

	NTSTATUS ret;

	if (!object || !groupdata) {
		DEBUG(0, ("tdbsam2_group_data_to_gums_object: no NULL pointers are accepted here!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* groupdata->xcounter */
	/* groupdata->sec_desc */

	SET_OR_FAIL(gums_set_object_sid(*object, groupdata->group_sid), error);
	SET_OR_FAIL(gums_set_object_name(*object, groupdata->name), error);

	if (groupdata->description)
		SET_OR_FAIL(gums_set_object_description(*object, groupdata->description), error);

	if (groupdata->count)
		SET_OR_FAIL(gums_set_group_members(*object, groupdata->count, groupdata->members), error);

	ret = NT_STATUS_OK;
	return ret;
	
error:
	talloc_destroy((*object)->mem_ctx);
	*object = NULL;
	return ret;
}

static NTSTATUS tdbsam2_domain_data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_domain_data *domdata, uint32 type) {

	NTSTATUS ret;

	if (!object || !domdata) {
		DEBUG(0, ("tdbsam2_domain_data_to_gums_object: no NULL pointers are accepted here!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* domdata->xcounter */
	/* domdata->sec_desc */

	SET_OR_FAIL(gums_set_object_sid(*object, domdata->dom_sid), error);
	SET_OR_FAIL(gums_set_object_name(*object, domdata->name), error);

	if (domdata->description)
		SET_OR_FAIL(gums_set_object_description(*object, domdata->description), error);

	ret = NT_STATUS_OK;
	return ret;
	
error:
	talloc_destroy((*object)->mem_ctx);
	*object = NULL;
	return ret;
}

static NTSTATUS tdbsam2_data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_object *data) {

	NTSTATUS ret;

	if (!object || !data) {
		DEBUG(0, ("tdbsam2_user_data_to_gums_object: no NULL structure pointers are accepted here!\n"));
		ret = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	ret = gums_create_object(object, data->type);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(5, ("tdbsam2_user_data_to_gums_object: error creating gums object!\n"));
		goto done;
	}

	switch (data->type) {
		case GUMS_OBJ_DOMAIN:
			ret = tdbsam2_domain_data_to_gums_object(object, data->data.domain, data->type);
			break;

		case GUMS_OBJ_NORMAL_USER:
			ret = tdbsam2_user_data_to_gums_object(object, data->data.user, data->type);
			break;

		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			ret = tdbsam2_group_data_to_gums_object(object, data->data.group, data->type);
			break;

		default:
			ret = NT_STATUS_UNSUCCESSFUL;
	}

done:
	return ret;
}





/* GUMM object functions */

static NTSTATUS get_domain_sid(DOM_SID *sid, const char* name) {

	NTSTATUS ret;
	struct tdbsam2_object obj;
	TALLOC_CTX *mem_ctx;
	TDB_DATA data, key;
	fstring keystr;
	fstring domname;

	if (!sid || !name)
		return NT_STATUS_INVALID_PARAMETER;

	mem_ctx = talloc_init("get_domain_sid");
	if (!mem_ctx) {
		DEBUG(0, ("tdbsam2_new_object: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (tdbsam2_db == NULL) {
		if (NT_STATUS_IS_ERR(ret = tdbsam2_opentdb())) {
			goto done;
		}
	}

	unix_strlower(name, -1, domname, sizeof(domname));

	slprintf(keystr, sizeof(keystr)-1, "%s%s", DOMAINPREFIX, domname);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(tdbsam2_db, key);
	if (!data.dptr) {
		DEBUG(5, ("get_domain_sid: Error fetching database, domain entry not found!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (NT_STATUS_IS_ERR(init_tdbsam2_object_from_buffer(&obj, mem_ctx, data.dptr, data.dsize))) {
		SAFE_FREE(data.dptr);
		DEBUG(0, ("get_domain_sid: Error fetching database, malformed entry!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	SAFE_FREE(data.dptr);

	if (obj.type != GUMS_OBJ_DOMAIN) {
		DEBUG(5, ("get_domain_sid: Requested object is not a domain!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	sid_copy(sid, obj.data.domain->dom_sid);

	ret = NT_STATUS_OK;

done:
	if (mem_ctx) talloc_destroy(mem_ctx);
	return ret;
}

	NTSTATUS (*set_domain_sid) (const DOM_SID *sid, const char *name);

	NTSTATUS (*get_sequence_number) (void);


static NTSTATUS tdbsam2_new_object(DOM_SID **sid, const char *name, const int obj_type) {

	NTSTATUS ret;
	struct tdbsam2_object obj;
	TALLOC_CTX *mem_ctx;

	if (!sid || !name) {
		DEBUG(0, ("tdbsam2_new_object: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	mem_ctx = talloc_init("tdbsam2_new_object");
	if (!mem_ctx) {
		DEBUG(0, ("tdbsam2_new_object: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	switch (obj_type) {
		case GUMS_OBJ_NORMAL_USER:
			obj.data.user = (struct tdbsam2_user_data *)talloc_zero(mem_ctx, sizeof(struct tdbsam2_user_data));
			TALLOC_CHECK(obj.data.user, ret, done);

			/*obj.data.user->sec_desc*/

			tdbsam2_get_next_sid(mem_ctx, obj.data.user->user_sid);
			TALLOC_CHECK(obj.data.user->user_sid, ret, done);

			obj.data.user->name = talloc_strdup(mem_ctx, name);
			TALLOC_CHECK(obj.data.user, ret, done);

			break;

		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			obj.data.group = (struct tdbsam2_group_data *)talloc_zero(mem_ctx, sizeof(struct tdbsam2_group_data));
			TALLOC_CHECK(obj.data.group, ret, done);

			/*obj.data.user->sec_desc*/

			tdbsam2_get_next_sid(mem_ctx, obj.data.group->group_sid);
			TALLOC_CHECK(obj.data.group->group_sid, ret, done);

			obj.data.group->name = talloc_strdup(mem_ctx, name);
			TALLOC_CHECK(obj.data.group, ret, done);

			break;

		case GUMS_OBJ_DOMAIN:
			/* TODO: SHOULD WE ALLOW TO CREATE NEW DOMAINS ? */

		default:
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
	}

	ret = tdbsam2_store(&obj);

done:
	talloc_destroy(mem_ctx);
	return ret;
}

static NTSTATUS tdbsam2_delete_object(const DOM_SID *sid) {

	NTSTATUS ret;
	struct tdbsam2_object obj;
	TALLOC_CTX *mem_ctx;
	TDB_DATA data, key;
	fstring keystr;
	fstring sidstr;
	char *obj_name = NULL;
	int obj_type, obj_version, len;

	if (!sid) {
		DEBUG(0, ("tdbsam2_new_object: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	mem_ctx = talloc_init("tdbsam2_delete_object");
	if (!mem_ctx) {
		DEBUG(0, ("tdbsam2_new_object: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (tdbsam2_db == NULL) {
		if (NT_STATUS_IS_ERR(ret = tdbsam2_opentdb())) {
			goto done;
		}
	}

	sid_to_string(sidstr, sid);

	slprintf(keystr, sizeof(keystr)-1, "%s%s", SIDPREFIX, sidstr);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(tdbsam2_db, key);
	if (!data.dptr) {
		DEBUG(5, ("get_domain_sid: Error fetching database, SID entry not found!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	len = tdb_unpack(data.dptr, data.dsize, TDB_FORMAT_STRING,
		&obj_version,
		&obj_type,
		&obj_name);

	if (len == -1) {
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (tdb_delete(tdbsam2_db, key) != TDB_SUCCESS) {
		DEBUG(5, ("tdbsam2_object_delete: Error deleting object!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}	

	switch (obj_type) {
		case GUMS_OBJ_NORMAL_USER:
		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			
			slprintf(keystr, sizeof(keystr)-1, "%s%s", OBJECTPREFIX, obj_name);
			key.dptr = keystr;
			key.dsize = strlen(keystr) + 1;

			if (tdb_delete(tdbsam2_db, key) != TDB_SUCCESS) {
				DEBUG(5, ("tdbsam2_object_delete: Error deleting object!\n"));
				DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam2_db)));
				DEBUGADD(5, (" Key: %s\n", keystr));
				ret = NT_STATUS_UNSUCCESSFUL;
				goto done;
			}
			break;

		case GUMS_OBJ_DOMAIN:
			/* TODO: SHOULD WE ALLOW TO DELETE DOMAINS ? */

		default:
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
	}

done:
	SAFE_FREE(obj_name);
	talloc_destroy(mem_ctx);
	return ret;
}

	NTSTATUS (*get_object_from_sid) (GUMS_OBJECT **object, const DOM_SID *sid, const int obj_type);
	NTSTATUS (*get_sid_from_name) (GUMS_OBJECT **object, const char *name);
	/* This function is used to get the list of all objects changed since b_time, it is
	   used to support PDC<->BDC synchronization */
	NTSTATUS (*get_updated_objects) (GUMS_OBJECT **objects, const NTTIME base_time);

	NTSTATUS (*enumerate_objects_start) (void *handle, const DOM_SID *sid, const int obj_type);
	NTSTATUS (*enumerate_objects_get_next) (GUMS_OBJECT **object, void *handle);
	NTSTATUS (*enumerate_objects_stop) (void *handle);

	/* This function MUST be used ONLY by PDC<->BDC replication code or recovery tools.
	   Never use this function to update an object in the database, use set_object_values() */
	NTSTATUS (*set_object) (const GUMS_OBJECT *object);

	/* set object values function */
	NTSTATUS (*set_object_values) (DOM_SID *sid, uint32 count, GUMS_DATA_SET *data_set);

	/* Group related functions */
	NTSTATUS (*add_memberss_to_group) (const DOM_SID *group, const DOM_SID **members);
	NTSTATUS (*delete_members_from_group) (const DOM_SID *group, const DOM_SID **members);
	NTSTATUS (*enumerate_group_members) (DOM_SID **members, const DOM_SID *sid, const int type);

	NTSTATUS (*get_sid_groups) (DOM_SID **groups, const DOM_SID *sid);

	NTSTATUS (*lock_sid) (const DOM_SID *sid);
	NTSTATUS (*unlock_sid) (const DOM_SID *sid);

	/* privileges related functions */

	NTSTATUS (*add_members_to_privilege) (const LUID_ATTR *priv, const DOM_SID **members);
	NTSTATUS (*delete_members_from_privilege) (const LUID_ATTR *priv, const DOM_SID **members);
	NTSTATUS (*enumerate_privilege_members) (DOM_SID **members, const LUID_ATTR *priv);
	NTSTATUS (*get_sid_privileges) (DOM_SID **privs, const DOM_SID *sid);
	/* warning!: set_privilege will overwrite a prior existing privilege if such exist */
	NTSTATUS (*set_privilege) (GUMS_PRIVILEGE *priv);


int gumm_init(GUMS_FUNCTIONS **storage) {

	return 0;
}
