/*
 * Unix SMB/CIFS implementation. 
 * tdbsam2 - sam backend
 * Copyright (C) Simo Sorce 2002-2003
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

#if 0
static int gums_tdbsam2_debug_class = DBGC_ALL;
#endif
/*
#undef DBGC_CLASS
#define DBGC_CLASS gums_tdbsam2_debug_class
*/

#define TDBSAM_VERSION		20021215
#define TDB_FILE_NAME		"tdbsam2.tdb"
#define NAMEPREFIX		"NAME_"
#define SIDPREFIX		"SID_"
#define PRIVILEGEPREFIX		"PRIV_"

#define TDB_FORMAT_STRING	"ddB"

#define TALLOC_CHECK(ptr, err, label) do { if ((ptr) == NULL) { DEBUG(0, ("%s: Out of memory!\n", FUNCTION_MACRO)); err = NT_STATUS_NO_MEMORY; goto label; } } while(0)
#define SET_OR_FAIL(func, label) do { if (!NT_STATUS_IS_OK(func)) { DEBUG(0, ("%s: Setting gums object data failed!\n", FUNCTION_MACRO)); goto label; } } while(0)



struct tdbsam2_enum_objs {
	uint32 type;
	DOM_SID *dom_sid;
	TDB_CONTEXT *db;
	TDB_DATA key;
	struct tdbsam2_enum_objs *next;
};

union tdbsam2_data {
	struct tdbsam2_domain_data *domain;
	struct tdbsam2_user_data *user;
	struct tdbsam2_group_data *group;
	struct tdbsam2_priv_data *priv;
};

struct tdbsam2_object {
	uint32 type;
	uint32 version;
	union tdbsam2_data data;
};

struct tdbsam2_private_data {

	const char *storage;
	struct tdbsam2_enum_objs *teo_handlers;
};

static struct tdbsam2_private_data *ts2_privs;


static NTSTATUS init_object_from_buffer(GUMS_OBJECT **go, char *buffer, int size)
{

	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx;
	int iret;
	char *obj_data = NULL;
	int data_size = 0;
	int version, type;
	int len;

	mem_ctx = talloc_init("init_object_from_buffer");
	if (!mem_ctx) {
		DEBUG(0, ("init_object_from_buffer: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	len = tdb_unpack (buffer, size, TDB_FORMAT_STRING,
			  &version,
			  &type,
			  &data_size, &obj_data);

	if (len == -1 || data_size <= 0)
		goto done;

	/* version is checked inside this function so that backward compatibility code can be
	   called eventually.
	   this way we can easily handle database format upgrades */
	if (version != TDBSAM_VERSION) {
		DEBUG(3,("init_tdbsam2_object_from_buffer: Error, db object has wrong tdbsam version!\n"));
		goto done;
	}

	/* be sure the string is terminated before trying to parse it */
	if (obj_data[data_size - 1] != '\0')
		obj_data[data_size - 1] = '\0';

	*go = (GUMS_OBJECT *)talloc_zero(mem_ctx, sizeof(GUMS_OBJECT));
	TALLOC_CHECK(*go, ret, done);

	switch (type) {

		case GUMS_OBJ_DOMAIN:
			iret = gen_parse(mem_ctx, pinfo_tdbsam2_domain_data, (char *)(*go), obj_data);
			break;

		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			iret = gen_parse(mem_ctx, pinfo_tdbsam2_group_data, (char *)(*go), obj_data);
			break;

		case GUMS_OBJ_NORMAL_USER:
			iret = gen_parse(mem_ctx, pinfo_tdbsam2_user_data, (char *)(*go), obj_data);
			break;

		case GUMS_OBJ_PRIVILEGE:
			iret = gen_parse(mem_ctx, pinfo_tdbsam2_priv_data, (char *)(*go), obj_data);
			break;

		default:
			DEBUG(3,("init_object_from_buffer: Error, wrong object type number!\n"));
			goto done;
	}

	if (iret != 0) {
		DEBUG(0, ("init_object_from_buffer: Fatal Error! Unable to parse object!\n"));
		DEBUG(0, ("init_object_from_buffer: DB Corrupt ?"));
		goto done;
	}

	(*go)->mem_ctx = mem_ctx;

	ret = NT_STATUS_OK;
done:
	SAFE_FREE(obj_data);
	return ret;
}

static NTSTATUS init_buffer_from_object(char **buffer, size_t *len, TALLOC_CTX *mem_ctx, GUMS_OBJECT *object)
{

	NTSTATUS ret;
	char *genbuf = NULL;
	size_t buflen;

	if (!buffer)
		return NT_STATUS_INVALID_PARAMETER;

	switch (gums_get_object_type(object)) {

		case GUMS_OBJ_DOMAIN:
			genbuf = gen_dump(mem_ctx, pinfo_tdbsam2_domain_data, (char *)object, 0);
			break;

		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			genbuf = gen_dump(mem_ctx, pinfo_tdbsam2_group_data, (char *)object, 0);
			break;

		case GUMS_OBJ_NORMAL_USER:
			genbuf = gen_dump(mem_ctx, pinfo_tdbsam2_user_data, (char *)object, 0);
			break;

		case GUMS_OBJ_PRIVILEGE:
			genbuf = gen_dump(mem_ctx, pinfo_tdbsam2_priv_data, (char *)object, 0);
			break;

		default:
			DEBUG(3,("init_buffer_from_object: Error, wrong object type number!\n"));
			return NT_STATUS_UNSUCCESSFUL;	
	}
	
	if (genbuf == NULL) {
		DEBUG(0, ("init_buffer_from_object: Fatal Error! Unable to dump object!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	buflen = tdb_pack(NULL, 0,  TDB_FORMAT_STRING,
			TDBSAM_VERSION,
			object->type,
			strlen(genbuf) + 1, genbuf);

	*buffer = talloc(mem_ctx, buflen);
	TALLOC_CHECK(*buffer, ret, done);

	*len = tdb_pack(*buffer, buflen, TDB_FORMAT_STRING,
			TDBSAM_VERSION,
			object->type,
			strlen(genbuf) + 1, genbuf);

	if (*len != buflen) {
		DEBUG(0, ("init_buffer_from_object: something odd is going on here: bufflen (%d) != len (%d) in tdb_pack operations!\n", 
			  buflen, *len));
		*buffer = NULL;
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ret = NT_STATUS_OK;
done:
	return ret;
}

static NTSTATUS opentdb(TDB_CONTEXT **tdb, BOOL readonly)
{
	if (!tdb)
		return NT_STATUS_INVALID_PARAMETER;

	*tdb = tdb_open_log(ts2_privs->storage, 0, TDB_DEFAULT, readonly?(O_RDONLY):(O_RDWR | O_CREAT), 0600);
  	if (!(*tdb))
	{
		DEBUG(0, ("opentdb: Unable to open database (%s)!\n", ts2_privs->storage));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

static NTSTATUS get_object_by_sid(TDB_CONTEXT *tdb, GUMS_OBJECT **obj, const DOM_SID *sid)
{
	NTSTATUS ret;
	TDB_DATA data, key;
	fstring keystr;

	if (!obj || !sid)
		return NT_STATUS_INVALID_PARAMETER;

	slprintf(keystr, sizeof(keystr)-1, "%s%s", SIDPREFIX, sid_string_static(sid));
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(tdb, key);
	if (!data.dptr) {
		DEBUG(5, ("get_object_by_sid: Entry not found!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdb)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_NOT_FOUND;
		goto done;
	}

	if (!NT_STATUS_IS_OK(init_object_from_buffer(obj, data.dptr, data.dsize))) {
		DEBUG(0, ("get_object_by_sid: Error fetching database, malformed entry!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ret = NT_STATUS_OK;

done:
	SAFE_FREE(data.dptr);
	return ret;
}

static NTSTATUS get_object_by_name(TDB_CONTEXT *tdb, GUMS_OBJECT **obj, const char* name)
{

	NTSTATUS ret = NT_STATUS_OK;
	TDB_DATA data, key;
	fstring keystr;
	fstring objname;
	DOM_SID sid;
	fstring sidstr;
	int sidstr_len;

	if (!obj || !name)
		return NT_STATUS_INVALID_PARAMETER;

	/* Data is stored in all lower-case */
	fstrcpy(objname, name);
	strlower_m(objname);

	slprintf(keystr, sizeof(keystr)-1, "%s%s", NAMEPREFIX, objname);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(tdb, key);
	if (!data.dptr) {
		DEBUG(5, ("get_object_by_name: Entry not found!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdb)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_NOT_FOUND;
		goto done;
	}

	fstrcpy(sidstr, data.dptr);
	sidstr_len = data.dsize;

	SAFE_FREE(data.dptr);

	if (sidstr_len <= 0) {
		DEBUG(5, ("get_object_by_name: Error unpacking database object!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!string_to_sid(&sid, sidstr)) {
		DEBUG(5, ("get_object_by_name: Error invalid sid string found in database object!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

done:
	if (NT_STATUS_IS_OK(ret))
		return get_object_by_sid(tdb, obj, &sid);
	return ret;
}

/* store a tdbsam2_object
 * flag: TDB_REPLACE or TDB_MODIFY or TDB_INSERT
 */

static NTSTATUS store_object(TDB_CONTEXT *tdb, const GUMS_OBJECT *object, int flag)
{

	NTSTATUS ret = NT_STATUS_OK;
	TDB_DATA data, data2, key, key2;
	TALLOC_CTX *mem_ctx;
	fstring keystr;
	fstring sidstr;
	fstring namestr;
	fstring objname;
	int r;

	/* TODO: on object renaming/replacing this function should
	 * check name->sid record and delete the old one
	 */

	mem_ctx = talloc_init("store_object");
	if (!mem_ctx) {
		DEBUG(0, ("store_object: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (!NT_STATUS_IS_OK(ret = init_buffer_from_object(&(data.dptr), &(data.dsize), mem_ctx, object)))
		goto done;

	switch (object->type) {

		case GUMS_OBJ_DOMAIN:
		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
		case GUMS_OBJ_NORMAL_USER:

			fstrcpy(sidstr, sid_string_static(gums_get_object_sid(object)));
			slprintf(keystr, sizeof(keystr) - 1, "%s%s", SIDPREFIX, sidstr);
			break;

		default:
			ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
	}

	/* Data is stored in all lower-case */
	fstrcpy(objname, gums_get_object_name(object));
	strlower_m(objname);

	slprintf(namestr, sizeof(namestr) - 1, "%s%s", NAMEPREFIX, objname);

	if (object->type != GUMS_OBJ_PRIVILEGE) {
		key.dptr = keystr;
		key.dsize = strlen(keystr) + 1;

		if ((r = tdb_store(tdb, key, data, flag)) != TDB_SUCCESS) {
			DEBUG(0, ("store_object: Unable to modify TDBSAM!\n"));
			DEBUGADD(0, (" Error: %s", tdb_errorstr(tdb)));
			DEBUGADD(0, (" occured while storing sid record (%s)\n", keystr));
			if (r == TDB_ERR_EXISTS)
				ret = NT_STATUS_UNSUCCESSFUL;
			else
				ret = NT_STATUS_INTERNAL_DB_ERROR;
			goto done;
		}

		data2.dptr = sidstr;
		data2.dsize = strlen(sidstr) + 1;
		key2.dptr = namestr;
		key2.dsize = strlen(namestr) + 1;

		if ((r = tdb_store(tdb, key2, data2, flag)) != TDB_SUCCESS) {
			DEBUG(0, ("store_object: Unable to modify TDBSAM!\n"));
			DEBUGADD(0, (" Error: %s", tdb_errorstr(tdb)));
			DEBUGADD(0, (" occured while storing name record (%s)\n", keystr));
			DEBUGADD(0, (" attempting rollback operation.\n"));
			if ((tdb_delete(tdb, key)) != TDB_SUCCESS) {
				DEBUG(0, ("store_object: Unable to rollback! Check database consitency!\n"));
			}
			if (r == TDB_ERR_EXISTS)
				ret = NT_STATUS_UNSUCCESSFUL;
			else
				ret = NT_STATUS_INTERNAL_DB_ERROR;
			goto done;
		}
	} else {
		key.dptr = namestr;
		key.dsize = strlen(keystr) + 1;

		if ((r = tdb_store(tdb, key, data, flag)) != TDB_SUCCESS) {
			DEBUG(0, ("store_object: Unable to modify TDBSAM!\n"));
			DEBUGADD(0, (" Error: %s", tdb_errorstr(tdb)));
			DEBUGADD(0, (" occured while storing sid record (%s)\n", keystr));
			if (r == TDB_ERR_EXISTS)
				ret = NT_STATUS_UNSUCCESSFUL;
			else
				ret = NT_STATUS_INTERNAL_DB_ERROR;
			goto done;
		}
	}

/* TODO: update the general database counter */
/* TODO: update this entry counter too */

done:
	talloc_destroy(mem_ctx);
	return ret;
}

#if 0
static NTSTATUS user_data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_user_data *userdata)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	DATA_BLOB pwd;

	if (!object || !userdata) {
		DEBUG(0, ("tdbsam2_user_data_to_gums_object: no NULL pointers are accepted here!\n"));
		return ret;
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

	if (userdata->hours)
		SET_OR_FAIL(gums_set_user_hours(*object, userdata->hours_len, userdata->hours), error);

	SET_OR_FAIL(gums_set_user_unknown_3(*object, userdata->unknown_3), error);
	SET_OR_FAIL(gums_set_user_unknown_5(*object, userdata->unknown_5), error);
	SET_OR_FAIL(gums_set_user_unknown_6(*object, userdata->unknown_6), error);

	SET_OR_FAIL(gums_set_user_logon_time(*object, *(userdata->logon_time)), error);
	SET_OR_FAIL(gums_set_user_logoff_time(*object, *(userdata->logoff_time)), error);
	SET_OR_FAIL(gums_set_user_kickoff_time(*object, *(userdata->kickoff_time)), error);
	SET_OR_FAIL(gums_set_user_pass_last_set_time(*object, *(userdata->pass_last_set_time)), error);
	SET_OR_FAIL(gums_set_user_pass_can_change_time(*object, *(userdata->pass_can_change_time)), error);
	SET_OR_FAIL(gums_set_user_pass_must_change_time(*object, *(userdata->pass_must_change_time)), error);

	pwd = data_blob(userdata->nt_pw_ptr, NT_HASH_LEN);
	ret = gums_set_user_nt_pwd(*object, pwd);
	data_blob_clear_free(&pwd);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(5, ("user_data_to_gums_object: failed to set nt password!\n"));
		goto error;
	}
	pwd = data_blob(userdata->lm_pw_ptr, LM_HASH_LEN);
	ret = gums_set_user_lm_pwd(*object, pwd);
	data_blob_clear_free(&pwd);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(5, ("user_data_to_gums_object: failed to set lanman password!\n"));
		goto error;
	}

	ret = NT_STATUS_OK;
	return ret;
	
error:
	talloc_destroy((*object)->mem_ctx);
	*object = NULL;
	return ret;
}

static NTSTATUS group_data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_group_data *groupdata)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!object || !groupdata) {
		DEBUG(0, ("tdbsam2_group_data_to_gums_object: no NULL pointers are accepted here!\n"));
		return ret;
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

	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!object || !*object || !domdata) {
		DEBUG(0, ("tdbsam2_domain_data_to_gums_object: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
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

static NTSTATUS priv_data_to_gums_object(GUMS_OBJECT **object, struct tdbsam2_priv_data *privdata)
{

	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!object || !*object || !privdata) {
		DEBUG(0, ("tdbsam2_priv_data_to_gums_object: no NULL pointers are accepted here!\n"));
		return ret;
	}

	/* domdata->xcounter */
	/* domdata->sec_desc */

	SET_OR_FAIL(gums_set_priv_luid_attr(*object, privdata->privilege), error);
	SET_OR_FAIL(gums_set_object_name(*object, privdata->name), error);

	if (privdata->description)
		SET_OR_FAIL(gums_set_object_description(*object, privdata->description), error);

	if (privdata->count)
		SET_OR_FAIL(gums_set_priv_members(*object, privdata->count, privdata->members), error);

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
	if (!NT_STATUS_IS_OK(ret)) {
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

		case GUMS_OBJ_PRIVILEGE:
			ret = priv_data_to_gums_object(object, data->data.priv);
			break;

		default:
			ret = NT_STATUS_UNSUCCESSFUL;
	}

done:
	return ret;
}
#endif

/* GUMM object functions */

static NTSTATUS tdbsam2_get_domain_sid(DOM_SID *sid, const char* name)
{

	NTSTATUS ret;
	TDB_CONTEXT *tdb;
	GUMS_OBJECT *go;
	fstring domname;

	if (!sid || !name)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = opentdb(&tdb, True))) {
		return ret;
	}

	/* Data is stored in all lower-case */
	fstrcpy(domname, name);
	strlower_m(domname);

	if (!NT_STATUS_IS_OK(ret = get_object_by_name(tdb, &go, domname))) {
		go = NULL;
		DEBUG(0, ("tdbsam2_get_domain_sid: Error fetching database!\n"));
		goto done;
	}

	if (gums_get_object_type(go) != GUMS_OBJ_DOMAIN) {
		DEBUG(5, ("tdbsam2_get_domain_sid: Requested object is not a domain!\n"));
		ret = NT_STATUS_OBJECT_TYPE_MISMATCH;
		goto done;
	}

	sid_copy(sid, gums_get_object_sid(go));

	ret = NT_STATUS_OK;

done:
	if (go)
		gums_destroy_object(&go);
	tdb_close(tdb);
	return ret;
}

static NTSTATUS get_next_sid(TDB_CONTEXT *tdb, DOM_SID *sid)
{
	NTSTATUS ret;
	GUMS_OBJECT *go;
	DOM_SID dom_sid;
	TDB_DATA dom_sid_key;
	fstring dom_sid_str;
	uint32 new_rid;

	/* Find the domain SID */
       	if (!NT_STATUS_IS_OK(tdbsam2_get_domain_sid(&dom_sid, global_myname()))) {
		DEBUG(0, ("get_next_sid: cannot found the domain sid!!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Lock the domain record */
	sid_to_string(dom_sid_str, &dom_sid);
	dom_sid_key.dptr = dom_sid_str;
	dom_sid_key.dsize = strlen(dom_sid_key.dptr) + 1;
	
	if(tdb_chainlock(tdb, dom_sid_key) != 0) {
		DEBUG(0, ("get_next_sid: unable to lock domain record!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Get the domain object */
	ret = get_object_by_sid(tdb, &go, &dom_sid);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0, ("get_next_sid: unable to get root Domain object!\n"));
		ret = NT_STATUS_INTERNAL_DB_ERROR;
		goto done;
	}

	new_rid = gums_get_domain_next_rid(go);
	
	/* Increment the RID Counter */
	gums_set_domain_next_rid(go, new_rid+1);
	
	/* Store back Domain object */
	ret = store_object(tdb, go, TDB_MODIFY);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0, ("get_next_sid: unable to update root Domain object!\n"));
		ret = NT_STATUS_INTERNAL_DB_ERROR;
		goto done;
	}

	/* Build the Domain SID to return */
	sid_copy(sid, &dom_sid);
	
	if (!sid_append_rid(sid, new_rid)) {
		DEBUG(0, ("get_next_sid: unable to build new SID !?!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ret = NT_STATUS_OK;

done:
	/* Unlock the Domain object */
	tdb_chainunlock(tdb, dom_sid_key);

	return ret;
}

/* TODO */
	NTSTATUS (*get_sequence_number) (void);


extern DOM_SID global_sid_NULL;

static NTSTATUS tdbsam2_new_object(DOM_SID *sid, const char *name, const int obj_type)
{

	NTSTATUS ret = NT_STATUS_OK;
	TDB_CONTEXT *tdb;
	GUMS_OBJECT *go;
	NTTIME null_time;
	DATA_BLOB pw;
	const char *defpw = "NOPASSWORDXXXXXX";
	uint8 defhours[21] = {255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255};

	if (!name) {
		DEBUG(0, ("tdbsam2_new_object: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(ret = opentdb(&tdb, False))) {
		return ret;
	}

	if (!NT_STATUS_IS_OK(ret = gums_create_object(&go, obj_type))) {
		go = NULL;
		goto done;
	}

	if (obj_type != GUMS_OBJ_PRIVILEGE) {
		if (!sid) {
			ret = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}

		if (obj_type == GUMS_OBJ_DOMAIN) {
			sid_copy(sid, get_global_sam_sid());
		} else {
			if (!NT_STATUS_IS_OK(ret = get_next_sid(tdb, sid)))
				goto done;
		}

		gums_set_object_sid(go, sid);
	}

	gums_set_object_name(go, name);
	gums_set_object_seq_num(go, 1);

	/*obj.data.domain->sec_desc*/

	switch (obj_type) {
		case GUMS_OBJ_NORMAL_USER:

			init_nt_time(&null_time);

			gums_set_user_logon_time(go, null_time);
			gums_set_user_logoff_time(go, null_time);
			gums_set_user_kickoff_time(go, null_time);
			gums_set_user_pass_last_set_time(go, null_time);
			gums_set_user_pass_can_change_time(go, null_time);
			gums_set_user_pass_must_change_time(go, null_time);

			pw = data_blob(defpw, NT_HASH_LEN);
			gums_set_user_nt_pwd(go, pw);
			gums_set_user_lm_pwd(go, pw);
			data_blob_free(&pw);

			gums_set_user_logon_divs(go, 168);
			gums_set_user_hours(go, 21, defhours);

			gums_set_user_unknown_3(go, 0x00ffffff);
			gums_set_user_bad_password_count(go, 0);
			gums_set_user_logon_count(go, 0);
			gums_set_user_unknown_6(go, 0x000004ec);
			break;

		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:

			break;

		case GUMS_OBJ_DOMAIN:

			gums_set_domain_next_rid(go, 0x3e9);

			break;	

		case GUMS_OBJ_PRIVILEGE:

			break;

		default:
			ret = NT_STATUS_OBJECT_TYPE_MISMATCH;
			goto done;
	}

	ret = store_object(tdb, go, TDB_INSERT);

done:
	if (go)
		gums_destroy_object(&go);
	tdb_close(tdb);
	return ret;
}

static NTSTATUS tdbsam2_delete_object(const DOM_SID *sid)
{
	/* TODO: need to address privilege deletion */
	NTSTATUS ret = NT_STATUS_OK;
	TDB_CONTEXT *tdb;
	GUMS_OBJECT *go;
	TDB_DATA data, key;
	fstring keystr;

	if (!sid) {
		DEBUG(0, ("tdbsam2_delete_object: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(ret = opentdb(&tdb, False))) {
		return ret;
	}

	slprintf(keystr, sizeof(keystr)-1, "%s%s", SIDPREFIX, sid_string_static(sid));
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(tdb, key);
	if (!data.dptr) {
		DEBUG(5, ("tdbsam2_delete_object: Error fetching database, SID entry not found!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdb)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (tdb_delete(tdb, key) != TDB_SUCCESS) {
		DEBUG(5, ("tdbsam2_delete_object: Error deleting object!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdb)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}	

	if (!NT_STATUS_IS_OK(init_object_from_buffer(&go, data.dptr, data.dsize))) {
		DEBUG(0, ("tdbsam2_delete_object: Error fetching database, malformed entry!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	switch (go->type) {
		case GUMS_OBJ_DOMAIN:
			/* FIXME: SHOULD WE ALLOW TO DELETE DOMAINS ? */
		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
		case GUMS_OBJ_NORMAL_USER:
			slprintf(keystr, sizeof(keystr) - 1, "%s%s", NAMEPREFIX, gums_get_object_name(go));
			break;
		default:
			ret = NT_STATUS_OBJECT_TYPE_MISMATCH;
			goto done;
	}

	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	if (tdb_delete(tdb, key) != TDB_SUCCESS) {
		DEBUG(5, ("tdbsam2_delete_object: Error deleting object!\n"));
		DEBUGADD(5, (" Error: %s\n", tdb_errorstr(tdb)));
		DEBUGADD(5, (" Key: %s\n", keystr));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

/* TODO: update the general database counter */

done:
	gums_destroy_object(&go);
	SAFE_FREE(data.dptr);
	return ret;
}

static NTSTATUS tdbsam2_get_object_from_sid(GUMS_OBJECT **object, const DOM_SID *sid, const int obj_type)
{
	NTSTATUS ret;
	TDB_CONTEXT *tdb;

	if (!object || !sid) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(ret = opentdb(&tdb, True))) {
		return ret;
	}

	ret = get_object_by_sid(tdb, object, sid);
	if (!NT_STATUS_IS_OK(ret) || (obj_type && gums_get_object_type(*object) != obj_type)) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: %s\n", nt_errstr(ret)));
		goto error;
	}

	tdb_close(tdb);
	return NT_STATUS_OK;	

error:
	gums_destroy_object(object);
	tdb_close(tdb);
	return ret;
}

static NTSTATUS tdbsam2_get_object_from_name(GUMS_OBJECT **object, const char *name, const int obj_type)
{
	NTSTATUS ret;
	TDB_CONTEXT *tdb;

	if (!object || !name) {
		DEBUG(0, ("tdbsam2_get_object_from_name: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(ret = opentdb(&tdb, True))) {
		return ret;
	}

	*object = NULL;
	ret = get_object_by_name(tdb, object, name);
	if (!NT_STATUS_IS_OK(ret) || (obj_type && gums_get_object_type(*object) != obj_type)) {
		DEBUG(0, ("tdbsam2_get_object_from_name: %s\n", nt_errstr(ret)));
		goto error;
	}

	tdb_close(tdb);
	return NT_STATUS_OK;

error:
	gums_destroy_object(object);
	tdb_close(tdb);
	return ret;
}

	/* This function is used to get the list of all objects changed since base_time, it is
	   used to support PDC<->BDC synchronization */
	NTSTATUS (*get_updated_objects) (GUMS_OBJECT **objects, const NTTIME base_time);

static NTSTATUS tdbsam2_enumerate_objects_start(void **handle, const DOM_SID *sid, const int obj_type)
{
	struct tdbsam2_enum_objs *teo, *t;

	teo = (struct tdbsam2_enum_objs *)malloc(sizeof(struct tdbsam2_enum_objs));
	if (!teo) {
		DEBUG(0, ("tdbsam2_enumerate_objects_start: Out of Memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	memset(teo, 0, sizeof(struct tdbsam2_enum_objs));

	teo->type = obj_type;
	if (sid) {
		teo->dom_sid = (DOM_SID *)malloc(sizeof(DOM_SID));
		if (!teo->dom_sid) {
			DEBUG(0, ("tdbsam2_enumerate_objects_start: Out of Memory!\n"));
			return NT_STATUS_NO_MEMORY;
		}
		sid_copy(teo->dom_sid, sid);
	}

  	if (!NT_STATUS_IS_OK(opentdb(&(teo->db), True)))
	{
		DEBUG(0, ("tdbsam2_enumerate_objects_start: Unable to open database (%s)!\n", ts2_privs->storage));
		SAFE_FREE(teo);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!ts2_privs->teo_handlers) {
		ts2_privs->teo_handlers = teo;
	} else {
		t = ts2_privs->teo_handlers;
		while (t->next) {
			t = t->next;
		}
		t->next = teo;
	}

	*handle = teo;

	teo->key = tdb_firstkey(teo->db);

	return NT_STATUS_OK;	
}

static NTSTATUS tdbsam2_enumerate_objects_get_next(GUMS_OBJECT **object, void *handle)
{
	NTSTATUS ret;
	TDB_DATA data;
	struct tdbsam2_enum_objs *teo;
	const char *prefix = SIDPREFIX;
	const int preflen = strlen(prefix);
	fstring dom_sid_str;
	int dom_sid_str_len = 0;

	if (!object || !handle) {
		DEBUG(0, ("tdbsam2_get_object_from_sid: no NULL pointers are accepted here!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	teo = (struct tdbsam2_enum_objs *)handle;

	if (teo->dom_sid) {
		sid_to_string(dom_sid_str, teo->dom_sid);
		dom_sid_str_len = strlen(dom_sid_str);
	}	

	while ((teo->key.dptr != NULL)) {
		int len, version, type, size;
		char *ptr;

		if (strncmp(teo->key.dptr, prefix, preflen)) {
			teo->key = tdb_nextkey(teo->db, teo->key);
			continue;
		}

		if (dom_sid_str_len != 0) {
			if (strncmp(&(teo->key.dptr[preflen]), dom_sid_str, dom_sid_str_len)) {
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

	if (teo->key.dptr == NULL) { /* no more objs */
		ret = NT_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	if (!NT_STATUS_IS_OK(ret = init_object_from_buffer(object, data.dptr, data.dsize))) {
		SAFE_FREE(data.dptr);
		DEBUG(0, ("tdbsam2_enumerate_objects_get_next: Error fetching database, malformed entry!\n"));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	SAFE_FREE(data.dptr);

	/* prepare next run */
	teo->key = tdb_nextkey(teo->db, teo->key);

done:
	return ret;
}

static NTSTATUS tdbsam2_enumerate_objects_stop(void *handle)
{
	struct tdbsam2_enum_objs *teo, *t, *p;

	teo = (struct tdbsam2_enum_objs *)handle;

	if (ts2_privs->teo_handlers == teo) {
		ts2_privs->teo_handlers = teo->next;
	} else {
		t = ts2_privs->teo_handlers;
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
	SAFE_FREE(teo->dom_sid);
	SAFE_FREE(teo);

	return NT_STATUS_OK;
}

static NTSTATUS tdbsam2_set_object(const GUMS_OBJECT *go)
{
	NTSTATUS ret;
	TDB_CONTEXT *tdb;

	if (!go)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = opentdb(&tdb, False))) {
		return ret;
	}

	ret = store_object(tdb, go, TDB_REPLACE);

	tdb_close(tdb);
	return ret;
}

#if 0
	/* set object values function */
static NTSTATUS (*set_object_values) (DOM_SID *sid, uint32 count, GUMS_DATA_SET *data_set);

	/* Group related functions */
static NTSTATUS (*add_memberss_to_group) (const DOM_SID *group, const DOM_SID **members);
	NTSTATUS (*delete_members_from_group) (const DOM_SID *group, const DOM_SID **members);
static NTSTATUS (*enumerate_group_members) (DOM_SID **members, const DOM_SID *sid, const int type);

static NTSTATUS (*get_sid_groups) (DOM_SID **groups, const DOM_SID *sid);

static NTSTATUS (*lock_sid) (const DOM_SID *sid);
static NTSTATUS (*unlock_sid) (const DOM_SID *sid);

	/* privileges related functions */

static NTSTATUS (*add_members_to_privilege) (const LUID_ATTR *priv, const DOM_SID **members);
static NTSTATUS (*delete_members_from_privilege) (const LUID_ATTR *priv, const DOM_SID **members);
static NTSTATUS (*enumerate_privilege_members) (DOM_SID **members, const LUID_ATTR *priv);
static NTSTATUS (*get_sid_privileges) (DOM_SID **privs, const DOM_SID *sid);
	/* warning!: set_privilege will overwrite a prior existing privilege if such exist */
static NTSTATUS (*set_privilege) (GUMS_PRIVILEGE *priv);
#endif

static void free_tdbsam2_private_data(void **vp) 
{
	struct tdbsam2_private_data **tdb_privs = (struct tdbsam2_private_data **)vp;
	while (ts2_privs->teo_handlers)
		tdbsam2_enumerate_objects_stop(ts2_privs->teo_handlers);
	*tdb_privs = NULL;
	/* No need to free any further, as it is talloc()ed */
}

static NTSTATUS init_tdbsam2(GUMS_FUNCTIONS *fns, const char *storage)
{
	NTSTATUS ret;
	TDB_CONTEXT *tdb;
	DOM_SID dom_sid;

	fns->name = talloc_strdup(fns->mem_ctx, "tdbsam2");

	fns->get_domain_sid = tdbsam2_get_domain_sid;
	/* fns->get_sequence_number = tdbsam2_get_sequence_number; */
	fns->new_object = tdbsam2_new_object;
	fns->delete_object = tdbsam2_delete_object;
	fns->get_object_from_sid = tdbsam2_get_object_from_sid;
	fns->get_object_from_name = tdbsam2_get_object_from_name;
	/* fns->get_updated_objects = tdbsam2_get_updated_objects; */
	fns->enumerate_objects_start = tdbsam2_enumerate_objects_start;
	fns->enumerate_objects_get_next = tdbsam2_enumerate_objects_get_next;
	fns->enumerate_objects_stop = tdbsam2_enumerate_objects_stop;
	fns->set_object = tdbsam2_set_object;
	/* fns->set_object_values = tdbsam2_set_object_values;
	fns->add_members_to_group = tdbsam2_add_members_to_group;
	fns->delete_members_from_group = tdbsam2_delete_members_from_group;
	fns->enumerate_group_members = tdbsam2_enumerate_group_members;
	fns->get_sid_groups = tdbsam2_get_sid_groups;
	fns->lock_sid = tdbsam2_lock_sid;
	fns->unlock_sid = tdbsam2_unlock_sid;
	fns->add_members_to_privilege = tdbsam2_add_members_to_privilege;
	fns->delete_members_from_privilege = tdbsam2_delete_members_from_privilege;
	fns->enumerate_privilege_members = tdbsam2_enumerate_privilege_members;
	fns->get_sid_privileges = tdbsam2_get_sid_privileges;
	fns->set_privilege = tdbsam2_set_privilege; */

	ts2_privs = talloc_zero(fns->mem_ctx, sizeof(struct tdbsam2_private_data));
	if (!ts2_privs) {
		DEBUG(0, ("talloc() failed for tdbsam2 private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (storage) {
		ts2_privs->storage = talloc_strdup(fns->mem_ctx, storage);
	} else {
		pstring tdbfile;
		get_private_directory(tdbfile);
		pstrcat(tdbfile, "/");
		pstrcat(tdbfile, TDB_FILE_NAME);
		ts2_privs->storage = talloc_strdup(fns->mem_ctx, tdbfile);
	}

	/* check tdb exist (or create it) */

		/* Find the domain SID */
       	if (!NT_STATUS_IS_OK(tdbsam2_get_domain_sid(&dom_sid, global_myname()))) {
		/* db file does not exist or it is not inited */
			/* make the tdb file */
		if (!NT_STATUS_IS_OK(ret = opentdb(&tdb, False))) {
			return ret;
		}
		tdb_close(tdb);

		if (!NT_STATUS_IS_OK(tdbsam2_get_domain_sid(&dom_sid, "BUILTIN"))) {
			gums_init_builtin_domain();
		}

		gums_init_domain(get_global_sam_sid(), global_myname());
	}

	fns->private_data = &ts2_privs;
	fns->free_private_data = free_tdbsam2_private_data;

	return NT_STATUS_OK;
}

NTSTATUS gums_tdbsam2_init(void)
{
	/*
	if ((gums_tdbsam2_debug_class = debug_add_class("gums_tdbsam2")) == -1) {
		DEBUG(0, ("gums_tdbsam2: unable to register my own debug class! going on ...\n"));
		gums_tdbsam2_debug_class = DBGC_ALL;
	} 
	*/
	return gums_register_module(GUMS_INTERFACE_VERSION, "tdbsam2", init_tdbsam2);
}
