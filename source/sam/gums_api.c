/* 
   Unix SMB/CIFS implementation.
   GUMS structures
   Copyright (C) Simo Sorce 2002
   
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

#include "includes.h"

extern GUMS_FUNCTIONS *gums_storage;

/* Functions to get info from a GUMS object */

NTSTATUS gums_get_object_type(uint32 *type, const GUMS_OBJECT *obj)
{
	*type = obj->type;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_object_seq_num(uint32 *version, const GUMS_OBJECT *obj)
{
	*version = obj->version;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_sec_desc(SEC_DESC **sec_desc, const GUMS_OBJECT *obj)
{
	*sec_desc = obj->sec_desc;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_object_sid(DOM_SID **sid, const GUMS_OBJECT *obj)
{
	*sid = obj->sid;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_object_name(char **name, const GUMS_OBJECT *obj)
{
	*name = obj->name;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_object_description(char **description, const GUMS_OBJECT *obj)
{
	*description = obj->description;
	return NT_STATUS_OK;
}

/* User specific functions */

NTSTATUS gums_get_object_privileges(PRIVILEGE_SET **priv_set, const GUMS_OBJECT *obj)
{
	if (!priv_set)
		return NT_STATUS_INVALID_PARAMETER;

	*priv_set = obj->priv_set;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_pri_group(DOM_SID **sid, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!sid)
		return NT_STATUS_INVALID_PARAMETER;

	*sid = ((GUMS_USER *)(obj->data))->group_sid;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_nt_pwd(DATA_BLOB **nt_pwd, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!nt_pwd)
		return NT_STATUS_INVALID_PARAMETER;

	*nt_pwd = ((GUMS_USER *)(obj->data))->nt_pw;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_lm_pwd(DATA_BLOB **lm_pwd, const GUMS_OBJECT *obj)
{ 
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!lm_pwd)
		return NT_STATUS_INVALID_PARAMETER;

	*lm_pwd = ((GUMS_USER *)(obj->data))->lm_pw;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_fullname(char **fullname, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!fullname)
		return NT_STATUS_INVALID_PARAMETER;

	*fullname = ((GUMS_USER *)(obj->data))->full_name;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_homedir(char **homedir, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!homedir)
		return NT_STATUS_INVALID_PARAMETER;

	*homedir = ((GUMS_USER *)(obj->data))->home_dir;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_dir_drive(char **dirdrive, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!dirdrive)
		return NT_STATUS_INVALID_PARAMETER;

	*dirdrive = ((GUMS_USER *)(obj->data))->dir_drive;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_logon_script(char **logon_script, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!logon_script)
		return NT_STATUS_INVALID_PARAMETER;

	*logon_script = ((GUMS_USER *)(obj->data))->logon_script;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_profile_path(char **profile_path, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!profile_path)
		return NT_STATUS_INVALID_PARAMETER;

	*profile_path = ((GUMS_USER *)(obj->data))->profile_path;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_workstations(char **workstations, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!workstations)
		return NT_STATUS_INVALID_PARAMETER;

	*workstations = ((GUMS_USER *)(obj->data))->workstations;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_unknown_str(char **unknown_str, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!unknown_str)
		return NT_STATUS_INVALID_PARAMETER;

	*unknown_str = ((GUMS_USER *)(obj->data))->unknown_str;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_munged_dial(char **munged_dial, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!munged_dial)
		return NT_STATUS_INVALID_PARAMETER;

	*munged_dial = ((GUMS_USER *)(obj->data))->munged_dial;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_logon_time(NTTIME **logon_time, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!logon_time)
		return NT_STATUS_INVALID_PARAMETER;

	*logon_time = ((GUMS_USER *)(obj->data))->logon_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_logoff_time(NTTIME **logoff_time, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!logoff_time)
		return NT_STATUS_INVALID_PARAMETER;

	*logoff_time = ((GUMS_USER *)(obj->data))->logoff_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_kickoff_time(NTTIME **kickoff_time, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!kickoff_time)
		return NT_STATUS_INVALID_PARAMETER;

	*kickoff_time = ((GUMS_USER *)(obj->data))->kickoff_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_pass_last_set_time(NTTIME **pass_last_set_time, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!pass_last_set_time)
		return NT_STATUS_INVALID_PARAMETER;

	*pass_last_set_time = ((GUMS_USER *)(obj->data))->pass_last_set_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_pass_can_change_time(NTTIME **pass_can_change_time, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!pass_can_change_time)
		return NT_STATUS_INVALID_PARAMETER;

	*pass_can_change_time = ((GUMS_USER *)(obj->data))->pass_can_change_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_pass_must_change_time(NTTIME **pass_must_change_time, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!pass_must_change_time)
		return NT_STATUS_INVALID_PARAMETER;

	*pass_must_change_time = ((GUMS_USER *)(obj->data))->pass_must_change_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_logon_divs(uint16 *logon_divs, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!logon_divs)
		return NT_STATUS_INVALID_PARAMETER;

	*logon_divs = ((GUMS_USER *)(obj->data))->logon_divs;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_hours_len(uint32 *hours_len, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!hours_len)
		return NT_STATUS_INVALID_PARAMETER;

	*hours_len = ((GUMS_USER *)(obj->data))->hours_len;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_hours(uint8 **hours, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!hours)
		return NT_STATUS_INVALID_PARAMETER;

	*hours = ((GUMS_USER *)(obj->data))->hours;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_unknown_3(uint32 *unknown3, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!unknown3)
		return NT_STATUS_INVALID_PARAMETER;

	*unknown3 = ((GUMS_USER *)(obj->data))->unknown_3;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_unknown_5(uint32 *unknown5, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!unknown5)
		return NT_STATUS_INVALID_PARAMETER;

	*unknown5 = ((GUMS_USER *)(obj->data))->unknown_5;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_unknown_6(uint32 *unknown6, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!unknown6)
		return NT_STATUS_INVALID_PARAMETER;

	*unknown6 = ((GUMS_USER *)(obj->data))->unknown_6;
	return NT_STATUS_OK;
}

/* Group specific functions */

NTSTATUS gums_get_group_members(uint32 *count, DOM_SID **members, const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_GROUP &&
		obj->type != GUMS_OBJ_ALIAS)
			return NT_STATUS_OBJECT_TYPE_MISMATCH;
	if (!members)
		return NT_STATUS_INVALID_PARAMETER;

	*count = ((GUMS_GROUP *)(obj->data))->count;
	*members = ((GUMS_GROUP *)(obj->data))->members;
	return NT_STATUS_OK;
}

/* set functions */

NTSTATUS gums_create_data_set(GUMS_COMMIT_SET **com_set, TALLOC_CTX *ctx, DOM_SID *sid, uint32 type)
{
	TALLOC_CTX *mem_ctx;
	GUMS_COMMIT_SET *set;

	mem_ctx = talloc_init_named("commit_set");
	if (mem_ctx == NULL)
		return NT_STATUS_NO_MEMORY;
	set = (GUMS_COMMIT_SET *)talloc(mem_ctx, sizeof(GUMS_COMMIT_SET));
	if (set == NULL) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	set->mem_ctx = mem_ctx;
	set->type = type;
	sid_copy(&(set->sid), sid);
	set->count = 0;
	set->data = NULL;
	*com_set = set;

	return NT_STATUS_OK;
}

NTSTATUS gums_set_sec_desc(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, SEC_DESC *sec_desc)
{
	GUMS_DATA_SET *data_set;
	SEC_DESC *new_sec_desc;

	if (!mem_ctx || !com_set || !sec_desc)
		return NT_STATUS_INVALID_PARAMETER;

	com_set->count = com_set->count + 1;
	if (com_set->count == 1) { /* first data set */
		data_set = (GUMS_DATA_SET *)talloc(mem_ctx, sizeof(GUMS_DATA_SET));
	} else {
		data_set = (GUMS_DATA_SET *)talloc_realloc(mem_ctx, com_set->data, sizeof(GUMS_DATA_SET) * com_set->count);
	}
	if (data_set == NULL)
		return NT_STATUS_NO_MEMORY;

	com_set->data = data_set;
	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_SET_SEC_DESC;
	new_sec_desc = dup_sec_desc(mem_ctx, sec_desc);
	if (new_sec_desc == NULL)
		return NT_STATUS_NO_MEMORY;

	(SEC_DESC *)(data_set->data) = new_sec_desc;

	return NT_STATUS_OK;
}

NTSTATUS gums_add_privilege(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, LUID_ATTR priv)
{
	GUMS_DATA_SET *data_set;
	LUID_ATTR *new_priv;

	if (!mem_ctx || !com_set)
		return NT_STATUS_INVALID_PARAMETER;

	com_set->count = com_set->count + 1;
	if (com_set->count == 1) { /* first data set */
		data_set = (GUMS_DATA_SET *)talloc(mem_ctx, sizeof(GUMS_DATA_SET));
	} else {
		data_set = (GUMS_DATA_SET *)talloc_realloc(mem_ctx, com_set->data, sizeof(GUMS_DATA_SET) * com_set->count);
	}
	if (data_set == NULL)
		return NT_STATUS_NO_MEMORY;

	com_set->data = data_set;
	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_ADD_PRIVILEGE;
	if (NT_STATUS_IS_ERR(dupalloc_luid_attr(mem_ctx, &new_priv, priv)))
		return NT_STATUS_NO_MEMORY;

	(SEC_DESC *)(data_set->data) = new_priv;

	return NT_STATUS_OK;	
}

NTSTATUS gums_del_privilege(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, LUID_ATTR priv)
{
	GUMS_DATA_SET *data_set;
	LUID_ATTR *new_priv;

	if (!mem_ctx || !com_set)
		return NT_STATUS_INVALID_PARAMETER;

	com_set->count = com_set->count + 1;
	if (com_set->count == 1) { /* first data set */
		data_set = (GUMS_DATA_SET *)talloc(mem_ctx, sizeof(GUMS_DATA_SET));
	} else {
		data_set = (GUMS_DATA_SET *)talloc_realloc(mem_ctx, com_set->data, sizeof(GUMS_DATA_SET) * com_set->count);
	}
	if (data_set == NULL)
		return NT_STATUS_NO_MEMORY;

	com_set->data = data_set;
	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_DEL_PRIVILEGE;
	if (NT_STATUS_IS_ERR(dupalloc_luid_attr(mem_ctx, &new_priv, priv)))
		return NT_STATUS_NO_MEMORY;

	(SEC_DESC *)(data_set->data) = new_priv;

	return NT_STATUS_OK;	
}

NTSTATUS gums_set_privilege_set(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, PRIVILEGE_SET *priv_set)
{
	GUMS_DATA_SET *data_set;
	PRIVILEGE_SET *new_priv_set;

	if (!mem_ctx || !com_set || !priv_set)
		return NT_STATUS_INVALID_PARAMETER;

	com_set->count = com_set->count + 1;
	if (com_set->count == 1) { /* first data set */
		data_set = (GUMS_DATA_SET *)talloc(mem_ctx, sizeof(GUMS_DATA_SET));
	} else {
		data_set = (GUMS_DATA_SET *)talloc_realloc(mem_ctx, com_set->data, sizeof(GUMS_DATA_SET) * com_set->count);
	}
	if (data_set == NULL)
		return NT_STATUS_NO_MEMORY;

	com_set->data = data_set;
	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_SET_SEC_DESC;
	if (NT_STATUS_IS_ERR(dup_priv_set(&new_priv_set, mem_ctx, priv_set)))
		return NT_STATUS_NO_MEMORY;

	(SEC_DESC *)(data_set->data) = new_priv_set;

	return NT_STATUS_OK;
}

NTSTATUS gums_set_string(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, uint32 type, char *str)
{
	GUMS_DATA_SET *data_set;
	char *new_str;

	if (!mem_ctx || !com_set || !str || type < GUMS_SET_NAME || type > GUMS_SET_MUNGED_DIAL)
		return NT_STATUS_INVALID_PARAMETER;

	com_set->count = com_set->count + 1;
	if (com_set->count == 1) { /* first data set */
		data_set = (GUMS_DATA_SET *)talloc(mem_ctx, sizeof(GUMS_DATA_SET));
	} else {
		data_set = (GUMS_DATA_SET *)talloc_realloc(mem_ctx, com_set->data, sizeof(GUMS_DATA_SET) * com_set->count);
	}
	if (data_set == NULL)
		return NT_STATUS_NO_MEMORY;

	com_set->data = data_set;
	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = type;
	new_str = talloc_strdup(mem_ctx, str);
	if (new_str == NULL)
		return NT_STATUS_NO_MEMORY;

	(char *)(data_set->data) = new_str;

	return NT_STATUS_OK;
}

NTSTATUS gums_set_name(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *name)
{
	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, name);
}

NTSTATUS gums_set_description(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *desc)
{
	return gums_set_string(mem_ctx, com_set, GUMS_SET_DESCRIPTION, desc);
}

NTSTATUS gums_set_full_name(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *full_name)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, full_name);
}

NTSTATUS gums_set_home_directory(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *home_dir)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, home_dir);
}

NTSTATUS gums_set_drive(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *drive)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, drive);
}

NTSTATUS gums_set_logon_script(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *logon_script)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, logon_script);
}

NTSTATUS gums_set_profile_path(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *prof_path)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, prof_path);
}

NTSTATUS gums_set_workstations(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *wks)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, wks);
}

NTSTATUS gums_set_unknown_string(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *unkn_str)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, unkn_str);
}

NTSTATUS gums_set_munged_dial(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *munged_dial)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, munged_dial);
}

NTSTATUS gums_set_nttime(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, uint32 type, NTTIME *time)
{
	GUMS_DATA_SET *data_set;
	NTTIME *new_time;

	if (!mem_ctx || !com_set || !time || type < GUMS_SET_LOGON_TIME || type > GUMS_SET_PASS_MUST_CHANGE_TIME)
		return NT_STATUS_INVALID_PARAMETER;

	com_set->count = com_set->count + 1;
	if (com_set->count == 1) { /* first data set */
		data_set = (GUMS_DATA_SET *)talloc(mem_ctx, sizeof(GUMS_DATA_SET));
	} else {
		data_set = (GUMS_DATA_SET *)talloc_realloc(mem_ctx, com_set->data, sizeof(GUMS_DATA_SET) * com_set->count);
	}
	if (data_set == NULL)
		return NT_STATUS_NO_MEMORY;

	com_set->data = data_set;
	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = type;
	new_time = talloc(mem_ctx, sizeof(NTTIME));
	if (new_time == NULL)
		return NT_STATUS_NO_MEMORY;

	new_time->low = time->low;
	new_time->high = time->high;
	(char *)(data_set->data) = new_time;

	return NT_STATUS_OK;
}

NTSTATUS gums_set_logon_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *logon_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_LOGON_TIME, logon_time);
}

NTSTATUS gums_set_logoff_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *logoff_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_LOGOFF_TIME, logoff_time);
}

NTSTATUS gums_set_kickoff_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *kickoff_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_KICKOFF_TIME, kickoff_time);
}

NTSTATUS gums_set_pass_last_set_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *pls_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_LOGON_TIME, pls_time);
}

NTSTATUS gums_set_pass_can_change_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *pcc_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_LOGON_TIME, pcc_time);
}

NTSTATUS gums_set_pass_must_change_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *pmc_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_LOGON_TIME, pmc_time);
}

NTSTATUS gums_add_sids_to_group(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	GUMS_DATA_SET *data_set;
	DOM_SID **new_sids;
	int i;

	if (!mem_ctx || !com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;

	com_set->count = com_set->count + 1;
	if (com_set->count == 1) { /* first data set */
		data_set = (GUMS_DATA_SET *)talloc(mem_ctx, sizeof(GUMS_DATA_SET));
	} else {
		data_set = (GUMS_DATA_SET *)talloc_realloc(mem_ctx, com_set->data, sizeof(GUMS_DATA_SET) * com_set->count);
	}
	if (data_set == NULL)
		return NT_STATUS_NO_MEMORY;

	com_set->data = data_set;
	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_ADD_SID_LIST;
	new_sids = (DOM_SID **)talloc(mem_ctx, (sizeof(void *) * count));
	if (new_sids == NULL)
		return NT_STATUS_NO_MEMORY;
	for (i = 0; i < count; i++) {
		new_sids[i] = sid_dup_talloc(mem_ctx, sids[i]);
		if (new_sids[i] == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	(SEC_DESC *)(data_set->data) = new_sids;

	return NT_STATUS_OK;	
}

NTSTATUS gums_add_users_to_group(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	if (!mem_ctx || !com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;
	if (com_set->type != GUMS_OBJ_GROUP || com_set->type != GUMS_OBJ_ALIAS)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_add_sids_to_group(mem_ctx, com_set, sids, count);	
}

NTSTATUS gums_add_groups_to_group(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	if (!mem_ctx || !com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;
	if (com_set->type != GUMS_OBJ_ALIAS)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_add_sids_to_group(mem_ctx, com_set, sids, count);	
}

NTSTATUS gums_del_sids_from_group(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	GUMS_DATA_SET *data_set;
	DOM_SID **new_sids;
	int i;

	if (!mem_ctx || !com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;
	if (com_set->type != GUMS_OBJ_GROUP || com_set->type != GUMS_OBJ_ALIAS)
		return NT_STATUS_INVALID_PARAMETER;

	com_set->count = com_set->count + 1;
	if (com_set->count == 1) { /* first data set */
		data_set = (GUMS_DATA_SET *)talloc(mem_ctx, sizeof(GUMS_DATA_SET));
	} else {
		data_set = (GUMS_DATA_SET *)talloc_realloc(mem_ctx, com_set->data, sizeof(GUMS_DATA_SET) * com_set->count);
	}
	if (data_set == NULL)
		return NT_STATUS_NO_MEMORY;

	com_set->data = data_set;
	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_DEL_SID_LIST;
	new_sids = (DOM_SID **)talloc(mem_ctx, (sizeof(void *) * count));
	if (new_sids == NULL)
		return NT_STATUS_NO_MEMORY;
	for (i = 0; i < count; i++) {
		new_sids[i] = sid_dup_talloc(mem_ctx, sids[i]);
		if (new_sids[i] == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	(SEC_DESC *)(data_set->data) = new_sids;

	return NT_STATUS_OK;	
}

NTSTATUS gums_set_sids_in_group(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	GUMS_DATA_SET *data_set;
	DOM_SID **new_sids;
	int i;

	if (!mem_ctx || !com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;
	if (com_set->type != GUMS_OBJ_GROUP || com_set->type != GUMS_OBJ_ALIAS)
		return NT_STATUS_INVALID_PARAMETER;

	com_set->count = com_set->count + 1;
	if (com_set->count == 1) { /* first data set */
		data_set = (GUMS_DATA_SET *)talloc(mem_ctx, sizeof(GUMS_DATA_SET));
	} else {
		data_set = (GUMS_DATA_SET *)talloc_realloc(mem_ctx, com_set->data, sizeof(GUMS_DATA_SET) * com_set->count);
	}
	if (data_set == NULL)
		return NT_STATUS_NO_MEMORY;

	com_set->data = data_set;
	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_SET_SID_LIST;
	new_sids = (DOM_SID **)talloc(mem_ctx, (sizeof(void *) * count));
	if (new_sids == NULL)
		return NT_STATUS_NO_MEMORY;
	for (i = 0; i < count; i++) {
		new_sids[i] = sid_dup_talloc(mem_ctx, sids[i]);
		if (new_sids[i] == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	(SEC_DESC *)(data_set->data) = new_sids;

	return NT_STATUS_OK;	
}


NTSTATUS gums_commit_data(GUMS_COMMIT_SET *set)
{
	return gums_storage->set_object_values(set->sid, set->count, set->data);
}

NTSTATUS gums_destroy_data_set(GUMS_COMMIT_SET **com_set)
{
	talloc_destroy((*com_set)->mem_ctx);
	*com_set = NULL;

	return NT_STATUS_OK;
}

