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
#include "tdbsam2.h"
#include "tdbsam2_parse_info.h"

static int tdbgumm_debug_level = DBGC_ALL;
#undef DBGC_CLASS
#define DBGC_CLASS tdbgumm_debug_level

#define TDBSAM_VERSION		20021215
#define TDB_FILE_NAME		"tdbsam2.tdb"
#define NAMEPREFIX		"NAME_"
#define SIDPREFIX		"SID_"
#define PRIVILEGEPREFIX		"PRIV_"

#define TDB_FORMAT_STRING	"ddB"

#define TALLOC_CHECK(ptr, err, label) do { if ((ptr) == NULL) { DEBUG(0, ("%s: Out of memory!\n", FUNCTION_MACRO)); err = NT_STATUS_NO_MEMORY; goto label; } } while(0)
#define SET_OR_FAIL(func, label) do { if (NT_STATUS_IS_ERR(func)) { DEBUG(0, ("%s: Setting gums object data failed!\n", FUNCTION_MACRO)); goto label; } } while(0)

struct tdbsam2_enum_objs {
	uint32 type;
	fstring dom_sid;
	TDB_CONTEXT *db;
	TDB_DATA key;
	struct tdbsam2_enum_objs *next;
};

union tdbsam2_data {
	struct tdbsam2_domain_data *domain;
	struct tdbsam2_user_data *user;
	struct tdbsam2_group_data *group;
};

struct tdbsam2_object {
	uint32 type;
	uint32 version;
	union tdbsam2_data data;
};

static TDB_CONTEXT *tdbsam2_db;

struct tdbsam2_enum_objs **teo_handlers;

static NTSTATUS init_tdbsam2_object_from_buffer(struct tdbsam2_object *object, TALLOC_CTX *mem_ctx, char *buffer, int size)
{

	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	int iret;
	char *obj_data;
	int data_size = 0;
	int len;
	
	len = tdb_unpack (buffer, size, TDB_FORMAT_STRING,
			  &(object->version),
			  &(object->type),
			  &data_size, &obj_data);

	if (len == -1)
		goto done;

	/* version is checked inside this function so that backward compatibility code can be
	   called eventually.
	   this way we can easily handle database format upgrades */
	if (object->version != TDBSAM_VERSION) {
		DEBUG(3,("init_tdbsam2_object_from_buffer: Error, db object has wrong tdbsam version!\n"));
		goto done;
	}

	/* be sure the string is terminated before trying to parse it */
	if (obj_data[data_size - 1] != '\0')
		obj_data[data_size - 1] = '\0';

	switch (object->type) {
		case GUMS_OBJ_DOMAIN:
			object->data.domain = (struct tdbsam2_domain_data *)talloc(mem_ctx, sizeof(struct tdbsam2_domain_data));
			TALLOC_CHECK(object->data.domain, ret, done);
			memset(object->data.domain, 0, sizeof(struct tdbsam2_domain_data));

			iret = gen_parse(mem_ctx, pinfo_tdbsam2_domain_data, (char *)(object->data.domain), obj_data);
			break;
		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			object->data.group = (struct tdbsam2_group_data *)talloc(mem_ctx, sizeof(struct tdbsam2_group_data));
			TALLOC_CHECK(object->data.group, ret, done);
			memset(object->data.group, 0, sizeof(struct tdbsam2_group_data));

			iret = gen_parse(mem_ctx, pinfo_tdbsam2_group_data, (char *)(object->data.group), obj_data);
			break;
		case GUMS_OBJ_NORMAL_USER:
			object->data.user = (struct tdbsam2_user_data *)talloc(mem_ctx, sizeof(struct tdbsam2_user_data));
			TALLOC_CHECK(object->data.user, ret, done);
			memset(object->data.user, 0, sizeof(struct tdbsam2_user_data));

			iret = gen_parse(mem_ctx, pinfo_tdbsam2_user_data, (char *)(object->data.user), obj_data);
			break;
		default:
			DEBUG(3,("init_tdbsam2_object_from_buffer: Error, wrong object type number!\n"));
			goto done;
	}

	if (iret != 0) {
		DEBUG(0,("init_tdbsam2_object_from_buffer: Fatal Error! Unable to parse object!\n"));
		DEBUG(0,("init_tdbsam2_object_from_buffer: DB Corrupted ?"));
		goto done;
	}

	ret = NT_STATUS_OK;
done:
	SAFE_FREE(obj_data);
	return ret;
}

static NTSTATUS init_buffer_from_tdbsam2_object(char **buffer, size_t *len, TALLOC_CTX *mem_ctx, struct tdbsam2_object *object)
{

	NTSTATUS ret;
	char *buf1 = NULL;
	size_t buflen;

	if (!buffer)
		return NT_STATUS_INVALID_PARAMETER;

	switch (object->type) {
		case GUMS_OBJ_DOMAIN:
			buf1 = gen_dump(mem_ctx, pinfo_tdbsam2_domain_data, (char *)(object->data.domain), 0);
			break;
		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			buf1 = gen_dump(mem_ctx, pinfo_tdbsam2_group_data, (char *)(object->data.group), 0);
			break;
		case GUMS_OBJ_NORMAL_USER:
			buf1 = gen_dump(mem_ctx, pinfo_tdbsam2_user_data, (char *)(object->data.user), 0);
			break;
		default:
			DEBUG(3,("init_buffer_from_tdbsam2_object: Error, wrong object type number!\n"));
			return NT_STATUS_UNSUCCESSFUL;	
	}
	
	if (buf1 == NULL) {
		DEBUG(0, ("init_buffer_from_tdbsam2_object: Fatal Error! Unable to dump object!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	buflen = tdb_pack(NULL, 0,  TDB_FORMAT_STRING,
			TDBSAM_VERSION,
			object->type,
			strlen(buf1) + 1, buf1);

	*buffer = talloc(mem_ctx, buflen);
	TALLOC_CHECK(*buffer, ret, done);

	*len = tdb_pack(*buffer, buflen, TDB_FORMAT_STRING,
			TDBSAM_VERSION,
			object->type,
			strlen(buf1) + 1, buf1);

	if (*len != buflen) {
		DEBUG(0, ("init_tdb_data_from_tdbsam2_object: somthing odd is going on here: bufflen (%d) != len (%d) in tdb_pack operations!\n", 
			  buflen, *len));
		*buffer = NULL;
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ret = NT_STATUS_OK;
done:
	return ret;
}

static NTSTATUS opentdb(void)
{
	if (!tdbsam2_db) {
		pstring tdbfile;
		get_private_directory(tdbfile);
		pstrcat(tdbfile, "/");
		pstrcat(tdbfile, TDB_FILE_NAME);

		tdbsam2_db = tdb_open_log(tdbfile, 0, TDB_DEFAULT, O_RDWR | O_CREAT, 0600);
  		if (!tdbsam2_db)
		{
			DEBUG(0, ("opentdb: Unable to open database (%s)!\n", tdbfile));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS get_object_by_sid(TALLOC_CTX *mem_ctx, struct tdbsam2_object *obj, const DOM_SID *sid)
{
	NTSTATUS ret;
	TDB_DATA data, key;
	fstring keystr;

	if (!obj || !mem_ctx || !sid)
		return NT_STATUS_INVALID_PARAMETER;

	if (NT_STATUS_IS_ERR(ret = opentdb())) {
		return ret;
	}

	slprintf(keystr, sizeof(keystr)-1, "%s%s", SIDPREFIX, sid_string_static(sid));
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(tdbsam2_db, key);
	if (!data.dptr) {
		DEBUG(5, ("get_object_by_sid: Error fetching database, domain entry not found!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (NT_STATUS_IS_ERR(init_tdbsam2_object_from_buffer(obj, mem_ctx, data.dptr, data.dsize))) {
		SAFE_FREE(data.dptr);
		DEBUG(0, ("get_object_by_sid: Error fetching database, malformed entry!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	SAFE_FREE(data.dptr);

	return NT_STATUS_OK;
	
}

static NTSTATUS get_object_by_name(TALLOC_CTX *mem_ctx, struct tdbsam2_object *obj, const char* name)
{

	NTSTATUS ret;
	TDB_DATA data, key;
	fstring keystr;
	fstring objname;
	DOM_SID sid;
	char *obj_sidstr;
	int obj_version, obj_type, obj_sidstr_len, len;

	if (!obj || !mem_ctx || !name)
		return NT_STATUS_INVALID_PARAMETER;

	if (NT_STATUS_IS_ERR(ret = opentdb())) {
		return ret;
	}

	fstrcpy(objname, name);
	strlower(objname);

	slprintf(keystr, sizeof(keystr)-1, "%s%s", NAMEPREFIX, objname);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(tdbsam2_db, key);
	if (!data.dptr) {
		DEBUG(5, ("get_object_by_name: Error fetching database, domain entry not found!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		return NT_STATUS_UNSUCCESSFUL;
	}

	len = tdb_unpack(data.dptr, data.dsize, TDB_FORMAT_STRING,
		&obj_version,
		&obj_type,
		&obj_sidstr_len, &obj_sidstr);

	SAFE_FREE(data.dptr);

	if (len == -1 || obj_version != TDBSAM_VERSION || obj_sidstr_len <= 0) {
		DEBUG(5, ("get_object_by_name: Error unpacking database object!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!string_to_sid(&sid, obj_sidstr)) {
		DEBUG(5, ("get_object_by_name: Error invalid sid string found in database object!\n"));
		SAFE_FREE(obj_sidstr);
		return NT_STATUS_UNSUCCESSFUL;
	}
	SAFE_FREE(obj_sidstr);
	
	return get_object_by_sid(mem_ctx, obj, &sid);
}

static NTSTATUS store_object(TALLOC_CTX *mem_ctx, struct tdbsam2_object *object, BOOL new_obj)
{

	NTSTATUS ret;
	TDB_DATA data, key, key2;
	fstring keystr;
	fstring namestr;
	int flag, r;

	if (NT_STATUS_IS_ERR(ret = opentdb())) {
		return ret;
	}

	if (new_obj) {
		flag = TDB_INSERT;
	} else {
		flag = TDB_MODIFY;
	}

	ret = init_buffer_from_tdbsam2_object(&(data.dptr), &(data.dsize), mem_ctx, object);
	if (NT_STATUS_IS_ERR(ret))
		return ret;

	switch (object->type) {
		case GUMS_OBJ_DOMAIN:
			slprintf(keystr, sizeof(keystr) - 1, "%s%s", SIDPREFIX, sid_string_static(object->data.domain->dom_sid));
			slprintf(namestr, sizeof(namestr) - 1, "%s%s", NAMEPREFIX, object->data.domain->name);
			break;
		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			slprintf(keystr, sizeof(keystr) - 1, "%s%s", SIDPREFIX, sid_string_static(object->data.group->group_sid));
			slprintf(namestr, sizeof(namestr) - 1, "%s%s", NAMEPREFIX, object->data.group->name);
			break;
		case GUMS_OBJ_NORMAL_USER:
			slprintf(keystr, sizeof(keystr) - 1, "%s%s", SIDPREFIX, sid_string_static(object->data.user->user_sid));
			slprintf(namestr, sizeof(namestr) - 1, "%s%s", NAMEPREFIX, object->data.user->name);
			break;
		default:
			return NT_STATUS_UNSUCCESSFUL;	
	}

	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	if ((r = tdb_store(tdbsam2_db, key, data, flag)) != TDB_SUCCESS) {
		DEBUG(0, ("store_object: Unable to modify SAM!\n"));
		DEBUGADD(0, (" Error: %s", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(0, (" occured while storing the main record (%s)\n", keystr));
		if (r == TDB_ERR_EXISTS) return NT_STATUS_UNSUCCESSFUL;
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	key2.dptr = namestr;
	key2.dsize = strlen(namestr) + 1;

	if ((r = tdb_store(tdbsam2_db, key2, key, flag)) != TDB_SUCCESS) {
		DEBUG(0, ("store_object: Unable to modify SAM!\n"));
		DEBUGADD(0, (" Error: %s", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(0, (" occured while storing the main record (%s)\n", keystr));
		if (r == TDB_ERR_EXISTS) return NT_STATUS_UNSUCCESSFUL;
		return NT_STATUS_INTERNAL_DB_ERROR;
	}
/* TODO: update the general database counter */
/* TODO: update this entry counter too */

	return NT_STATUS_OK;
}

static NTSTATUS get_next_sid(TALLOC_CTX *mem_ctx, DOM_SID **sid)
{
	NTSTATUS ret;
	struct tdbsam2_object obj;
	DOM_SID *dom_sid = get_global_sam_sid();
	uint32 new_rid;

/* TODO: LOCK DOMAIN OBJECT */
	ret = get_object_by_sid(mem_ctx, &obj, dom_sid);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(0, ("get_next_sid: unable to get root Domain object!\n"));
		ret = NT_STATUS_INTERNAL_DB_ERROR;
		goto error;
	}

	new_rid = obj.data.domain->next_rid;
	
	/* Increment the RID Counter */
	obj.data.domain->next_rid++;
	
	/* Store back Domain object */
	ret = store_object(mem_ctx, &obj, False);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(0, ("get_next_sid: unable to update root Domain object!\n"));
		ret = NT_STATUS_INTERNAL_DB_ERROR;
		goto error;
	}
/* TODO: UNLOCK DOMAIN OBJECT */

	*sid = sid_dup_talloc(mem_ctx, dom_sid);
	TALLOC_CHECK(*sid, ret, error);
	
	if (!sid_append_rid(*sid, new_rid)) {
		DEBUG(0, ("get_next_sid: unable to build new SID !?!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto error;
	}

	return NT_STATUS_OK;

error:
	return ret;
}

static NTSTATUS user_data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_user_data *userdata)
{
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
	SET_OR_FAIL(gums_set_user_bad_password_count(*object, userdata->bad_password_count), error);
	SET_OR_FAIL(gums_set_user_unknown_6(*object, userdata->unknown_6), error);

	SET_OR_FAIL(gums_set_user_logon_time(*object, *(userdata->logon_time)), error);
	SET_OR_FAIL(gums_set_user_logoff_time(*object, *(userdata->logoff_time)), error);
	SET_OR_FAIL(gums_set_user_kickoff_time(*object, *(userdata->kickoff_time)), error);
	SET_OR_FAIL(gums_set_user_pass_last_set_time(*object, *(userdata->pass_last_set_time)), error);
	SET_OR_FAIL(gums_set_user_pass_can_change_time(*object, *(userdata->pass_can_change_time)), error);
	SET_OR_FAIL(gums_set_user_pass_must_change_time(*object, *(userdata->pass_must_change_time)), error);

	ret = NT_STATUS_OK;
	return ret;
	
error:
	talloc_destroy((*object)->mem_ctx);
	*object = NULL;
	return ret;
}

static NTSTATUS group_data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_group_data *groupdata)
{
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

static NTSTATUS domain_data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_domain_data *domdata)
{

	NTSTATUS ret;

	if (!object || !*object || !domdata) {
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

static NTSTATUS data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_object *data)
{

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
			ret = domain_data_to_gums_object(object, data->data.domain);
			break;

		case GUMS_OBJ_NORMAL_USER:
			ret = user_data_to_gums_object(object, data->data.user);
			break;

		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			ret = group_data_to_gums_object(object, data->data.group);
			break;

		default:
			ret = NT_STATUS_UNSUCCESSFUL;
	}

done:
	return ret;
}


/* GUMM object functions */

static NTSTATUS tdbsam2_get_domain_sid(DOM_SID *sid, const char* name)
{

	NTSTATUS ret;
	struct tdbsam2_object obj;
	TALLOC_CTX *mem_ctx;
	fstring domname;

	if (!sid || !name)
		return NT_STATUS_INVALID_PARAMETER;

	mem_ctx = talloc_init("tdbsam2_get_domain_sid");
	if (!mem_ctx) {
		DEBUG(0, ("tdbsam2_new_object: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (NT_STATUS_IS_ERR(ret = opentdb())) {
		goto done;
	}

	fstrcpy(domname, name);
	strlower(domname);

	ret = get_object_by_name(mem_ctx, &obj, domname);

	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(0, ("tdbsam2_get_domain_sid: Error fetching database!\n"));
		goto done;
	}

	if (obj.type != GUMS_OBJ_DOMAIN) {
		DEBUG(5, ("tdbsam2_get_domain_sid: Requested object is not a domain!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	sid_copy(sid, obj.data.domain->dom_sid);

	ret = NT_STATUS_OK;

done:
	talloc_destroy(mem_ctx);
	return ret;
}

static NTSTATUS tdbsam2_set_domain_sid (const DOM_SID *sid, const char *name)
{

	NTSTATUS ret;
	struct tdbsam2_object obj;
	TALLOC_CTX *mem_ctx;
	fstring domname;

	if (!sid || !name)
		return NT_STATUS_INVALID_PARAMETER;

	mem_ctx = talloc_init("tdbsam2_set_domain_sid");
	if (!mem_ctx) {
		DEBUG(0, ("tdbsam2_new_object: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (tdbsam2_db == NULL) {
		if (NT_STATUS_IS_ERR(ret = opentdb())) {
			goto done;
		}
	}

	fstrcpy(domname, name);
	strlower(domname);

/* TODO: we need to lock this entry until updated! */

	ret = get_object_by_name(mem_ctx, &obj, domname);

	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(0, ("tdbsam2_get_domain_sid: Error fetching database!\n"));
		goto done;
	}

	if (obj.type != GUMS_OBJ_DOMAIN) {
		DEBUG(5, ("tdbsam2_get_domain_sid: Requested object is not a domain!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	sid_copy(obj.data.domain->dom_sid, sid);

	ret = store_object(mem_ctx, &obj, False);

done:
/* TODO: unlock here */
	if (mem_ctx) talloc_destroy(mem_ctx);
	return ret;
}

/* TODO */
	NTSTATUS (*get_sequence_number) (void);


extern DOM_SID global_sid_NULL;

static NTSTATUS tdbsam2_new_object(DOM_SID *sid, const char *name, const int obj_type)
{

	NTSTATUS ret;
	struct tdbsam2_object obj;
	TALLOC_CTX *mem_ctx;
	NTTIME zero_time = {0,0};
	const char *defpw = "NOPASSWORDXXXXXX";
	uint8 defhours[21] = {255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255};

	if (!sid || !name) {
		DEBUG(0, ("tdbsam2_new_object: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	mem_ctx = talloc_init("tdbsam2_new_object");
	if (!mem_ctx) {
		DEBUG(0, ("tdbsam2_new_object: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	obj.type = obj_type;
	obj.version = TDBSAM_VERSION;

	switch (obj_type) {
		case GUMS_OBJ_NORMAL_USER:
			obj.data.user = (struct tdbsam2_user_data *)talloc_zero(mem_ctx, sizeof(struct tdbsam2_user_data));
			TALLOC_CHECK(obj.data.user, ret, done);

			get_next_sid(mem_ctx, &(obj.data.user->user_sid));
			TALLOC_CHECK(obj.data.user->user_sid, ret, done);
			sid_copy(sid, obj.data.user->user_sid);

			obj.data.user->name = talloc_strdup(mem_ctx, name);
			TALLOC_CHECK(obj.data.user, ret, done);

			obj.data.user->xcounter = 1;
			/*obj.data.user->sec_desc*/
			obj.data.user->description = "";
			obj.data.user->group_sid = &global_sid_NULL;
			obj.data.user->logon_time = &zero_time;
			obj.data.user->logoff_time = &zero_time;
			obj.data.user->kickoff_time = &zero_time;
			obj.data.user->pass_last_set_time = &zero_time;
			obj.data.user->pass_can_change_time = &zero_time;
			obj.data.user->pass_must_change_time = &zero_time;

			obj.data.user->full_name = "";		
			obj.data.user->home_dir = "";		
			obj.data.user->dir_drive = "";		
			obj.data.user->logon_script = "";		
			obj.data.user->profile_path = "";		
			obj.data.user->workstations = "";		
			obj.data.user->unknown_str = "";		
			obj.data.user->munged_dial = "";		

			obj.data.user->lm_pw_ptr = defpw;
			obj.data.user->nt_pw_ptr = defpw;

			obj.data.user->logon_divs = 168;
			obj.data.user->hours_len = 21;
			obj.data.user->hours = &defhours;

			obj.data.user->unknown_3 = 0x00ffffff;
			obj.data.user->bad_password_count = 0x00020000;
			obj.data.user->unknown_6 = 0x000004ec;
			break;

		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			obj.data.group = (struct tdbsam2_group_data *)talloc_zero(mem_ctx, sizeof(struct tdbsam2_group_data));
			TALLOC_CHECK(obj.data.group, ret, done);

			get_next_sid(mem_ctx, &(obj.data.group->group_sid));
			TALLOC_CHECK(obj.data.group->group_sid, ret, done);
			sid_copy(sid, obj.data.group->group_sid);

			obj.data.group->name = talloc_strdup(mem_ctx, name);
			TALLOC_CHECK(obj.data.group, ret, done);

			obj.data.group->xcounter = 1;
			/*obj.data.group->sec_desc*/
			obj.data.group->description = "";

			break;

		case GUMS_OBJ_DOMAIN:

			/* FIXME: should we check against global_sam_sid to make it impossible
				  to store more than one domain ? */ 

			obj.data.domain = (struct tdbsam2_domain_data *)talloc_zero(mem_ctx, sizeof(struct tdbsam2_domain_data));
			TALLOC_CHECK(obj.data.domain, ret, done);

			obj.data.domain->dom_sid = sid_dup_talloc(mem_ctx, get_global_sam_sid());
			TALLOC_CHECK(obj.data.domain->dom_sid, ret, done);
			sid_copy(sid, obj.data.domain->dom_sid);

			obj.data.domain->name = talloc_strdup(mem_ctx, name);
			TALLOC_CHECK(obj.data.domain, ret, done);

			obj.data.domain->xcounter = 1;
			/*obj.data.domain->sec_desc*/
			obj.data.domain->next_rid = 0x3e9;
			obj.data.domain->description = "";

			ret = NT_STATUS_OK;
			break;	

		default:
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
	}

	ret = store_object(mem_ctx, &obj, True);

done:
	talloc_destroy(mem_ctx);
	return ret;
}

static NTSTATUS tdbsam2_delete_object(const DOM_SID *sid)
{
	NTSTATUS ret;
	struct tdbsam2_object obj;
	TALLOC_CTX *mem_ctx;
	TDB_DATA data, key;
	fstring keystr;

	if (!sid) {
		DEBUG(0, ("tdbsam2_delete_object: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	mem_ctx = talloc_init("tdbsam2_delete_object");
	if (!mem_ctx) {
		DEBUG(0, ("tdbsam2_delete_object: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (tdbsam2_db == NULL) {
		if (NT_STATUS_IS_ERR(ret = opentdb())) {
			goto done;
		}
	}

	slprintf(keystr, sizeof(keystr)-1, "%s%s", SIDPREFIX, sid_string_static(sid));
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(tdbsam2_db, key);
	if (!data.dptr) {
		DEBUG(5, ("tdbsam2_delete_object: Error fetching database, SID entry not found!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (tdb_delete(tdbsam2_db, key) != TDB_SUCCESS) {
		DEBUG(5, ("tdbsam2_delete_object: Error deleting object!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}	

	if (NT_STATUS_IS_ERR(init_tdbsam2_object_from_buffer(&obj, mem_ctx, data.dptr, data.dsize))) {
		SAFE_FREE(data.dptr);
		DEBUG(0, ("tdbsam2_delete_object: Error fetching database, malformed entry!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	switch (obj.type) {
		case GUMS_OBJ_DOMAIN:
			/* TODO: SHOULD WE ALLOW TO DELETE DOMAINS ? */
			slprintf(keystr, sizeof(keystr) - 1, "%s%s", NAMEPREFIX, obj.data.domain->name);
			break;
		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			slprintf(keystr, sizeof(keystr) - 1, "%s%s", NAMEPREFIX, obj.data.group->name);
			break;
		case GUMS_OBJ_NORMAL_USER:
			slprintf(keystr, sizeof(keystr) - 1, "%s%s", NAMEPREFIX, obj.data.user->name);
			break;
		default:
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
	}

	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	if (tdb_delete(tdbsam2_db, key) != TDB_SUCCESS) {
		DEBUG(5, ("tdbsam2_delete_object: Error deleting object!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdbsam2_db)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

/* TODO: update the general database counter */

done:
	SAFE_FREE(data.dptr);
	talloc_destroy(mem_ctx);
	return ret;
}

static NTSTATUS tdbsam2_get_object_from_sid(GUMS_OBJECT **object, const DOM_SID *sid, const int obj_type)
{
	NTSTATUS ret;
	struct tdbsam2_object obj;
	TALLOC_CTX *mem_ctx;

	if (!object || !sid) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	mem_ctx = talloc_init("tdbsam2_get_object_from_sid");
	if (!mem_ctx) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ret = get_object_by_sid(mem_ctx, &obj, sid);
	if (NT_STATUS_IS_ERR(ret) || (obj_type && obj.type != obj_type)) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: error fetching object or wrong object type!\n"));
		goto done;
	}

	ret = data_to_gums_object(object, &obj);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: error setting object data!\n"));
		goto done;
	}
	
done:
	talloc_destroy(mem_ctx);
	return ret;
}

static NTSTATUS tdbsam2_get_object_from_name(GUMS_OBJECT **object, const char *name, const int obj_type)
{
	NTSTATUS ret;
	struct tdbsam2_object obj;
	TALLOC_CTX *mem_ctx;

	if (!object || !name) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	mem_ctx = talloc_init("tdbsam2_get_object_from_sid");
	if (!mem_ctx) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ret = get_object_by_name(mem_ctx, &obj, name);
	if (NT_STATUS_IS_ERR(ret) || (obj_type && obj.type != obj_type)) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: error fetching object or wrong object type!\n"));
		goto done;
	}

	ret = data_to_gums_object(object, &obj);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: error setting object data!\n"));
		goto done;
	}
	
done:
	talloc_destroy(mem_ctx);
	return ret;
}

	/* This function is used to get the list of all objects changed since base_time, it is
	   used to support PDC<->BDC synchronization */
	NTSTATUS (*get_updated_objects) (GUMS_OBJECT **objects, const NTTIME base_time);

static NTSTATUS tdbsam2_enumerate_objects_start(void *handle, const DOM_SID *sid, const int obj_type)
{
	struct tdbsam2_enum_objs *teo, *t;
	pstring tdbfile;

	teo = (struct tdbsam2_enum_objs *)calloc(1, sizeof(struct tdbsam2_enum_objs));
	if (!teo) {
		DEBUG(0, ("tdbsam2_enumerate_objects_start: Out of Memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	teo->type = obj_type;
	if (sid) {
		sid_to_string(teo->dom_sid, sid);
	}

	get_private_directory(tdbfile);
	pstrcat(tdbfile, "/");
	pstrcat(tdbfile, TDB_FILE_NAME);

	teo->db = tdb_open_log(tdbfile, 0, TDB_DEFAULT, O_RDONLY, 0600);
  	if (!teo->db)
	{
		DEBUG(0, ("tdbsam2_enumerate_objects_start: Unable to open database (%s)!\n", tdbfile));
		SAFE_FREE(teo);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!teo_handlers) {
		*teo_handlers = teo;
	} else {
		t = *teo_handlers;
		while (t->next) {
			t = t->next;
		}
		t->next = teo;
	}

	handle = teo;

	teo->key = tdb_firstkey(teo->db);

	return NT_STATUS_OK;	
}

static NTSTATUS tdbsam2_enumerate_objects_get_next(GUMS_OBJECT **object, void *handle)
{
	NTSTATUS ret;
	TALLOC_CTX *mem_ctx;
	TDB_DATA data;
	struct tdbsam2_enum_objs *teo;
	struct tdbsam2_object obj;
	const char *prefix = SIDPREFIX;
	const int preflen = strlen(prefix);

	if (!object || !handle) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	teo = (struct tdbsam2_enum_objs *)handle;

	mem_ctx = talloc_init("tdbsam2_enumerate_objects_get_next");
	if (!mem_ctx) {
		DEBUG(0, ("tdbsam2_enumerate_objects_get_next: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	while ((teo->key.dsize != 0)) {
		int len, version, type, size;
		char *ptr;

		if (strncmp(teo->key.dptr, prefix, preflen)) {
			teo->key = tdb_nextkey(teo->db, teo->key);
			continue;
		}

		if (teo->dom_sid) {
			if (strncmp(&(teo->key.dptr[preflen]), teo->dom_sid, strlen(teo->dom_sid))) {
				teo->key = tdb_nextkey(teo->db, teo->key);
				continue;
			}
		}

		data = tdb_fetch(teo->db, teo->key);
		if (!data.dptr) {
			DEBUG(5, ("tdbsam2_enumerate_objects_get_next: Error fetching database, SID entry not found!\n"));
			DEBUGADD(5, (" Error: %s\n", tdb_errorstr(teo->db)));
			DEBUGADD(5, (" Key: %s\n", teo->key.dptr));
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}

		len = tdb_unpack (data.dptr, data.dsize, TDB_FORMAT_STRING,
			  &version,
			  &type,
			  &size, &ptr);

		if (len == -1) {
			DEBUG(5, ("tdbsam2_enumerate_objects_get_next: Error unable to unpack data!\n"));
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
		SAFE_FREE(ptr);

		if (teo->type && type != teo->type) {
			SAFE_FREE(data.dptr);
			data.dsize = 0;
			teo->key = tdb_nextkey(teo->db, teo->key);
			continue;
		}
		
		break;
	}

	if (data.dsize != 0) {
		if (NT_STATUS_IS_ERR(init_tdbsam2_object_from_buffer(&obj, mem_ctx, data.dptr, data.dsize))) {
			SAFE_FREE(data.dptr);
			DEBUG(0, ("tdbsam2_enumerate_objects_get_next: Error fetching database, malformed entry!\n"));
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
		SAFE_FREE(data.dptr);
	}

	ret = data_to_gums_object(object, &obj);

done:
	talloc_destroy(mem_ctx);
	return ret;
}

static NTSTATUS tdbsam2_enumerate_objects_stop(void *handle)
{
	struct tdbsam2_enum_objs *teo, *t, *p;

	teo = (struct tdbsam2_enum_objs *)handle;

	if (*teo_handlers == teo) {
		*teo_handlers = teo->next;
	} else {
		t = *teo_handlers;
		while (t != teo) {
			p = t;
			t = t->next;
			if (t == NULL) {
				DEBUG(0, ("tdbsam2_enumerate_objects_stop: Error, handle not found!\n"));
				return NT_STATUS_UNSUCCESSFUL;
			}
		}
		p = t->next;
	}

	tdb_close(teo->db);
	SAFE_FREE(teo);

	return NT_STATUS_OK;
}

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


int gumm_init(GUMS_FUNCTIONS **storage)
{
	tdbsam2_db = NULL;
	teo_handlers = 0;

	return 0;
}

#if 0
int main(int argc, char *argv[])
{
	NTSTATUS ret;
	DOM_SID dsid;

	if (argc < 2) {
		printf ("not enough arguments!\n");
		exit(0);
	}

	if (!lp_load(dyn_CONFIGFILE,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", dyn_CONFIGFILE);
		exit(1);
	}

	ret = tdbsam2_new_object(&dsid, "_domain_", GUMS_OBJ_DOMAIN);
	if (NT_STATUS_IS_OK(ret)) {
		printf ("_domain_ created, sid=%s\n", sid_string_static(&dsid));
	} else {
		printf ("_domain_ creation error n. 0x%08x\n", ret.v);
	}
	ret = tdbsam2_new_object(&dsid, argv[1], GUMS_OBJ_NORMAL_USER);
	if (NT_STATUS_IS_OK(ret)) {
		printf ("%s user created, sid=%s\n", argv[1], sid_string_static(&dsid));
	} else {
		printf ("%s user creation error n. 0x%08x\n", argv[1], ret.v);
	}
	
	exit(0);
}
#endif
