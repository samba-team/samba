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

/* Functions to get/set info from a GUMS object */

NTSTATUS gums_get_object_type(uint32 *type, const GUMS_OBJECT *obj)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	*type = obj->type;
	return NT_STATUS_OK;
}

NTSTATUS gums_create_object(GUMS_OBJECT **obj, uint32 type)
{
	TALLOC_CTX *mem_ctx = talloc_init();
	GUMS_OBJECT *go;
	NT_STATUS ret;
	
	go = talloc_zero(mem_ctx, sizeof(GUMS_OBJECT));
	go->mem_ctx = mem_ctx;
	go->type = type;
	go->version = GUMS_OBJECT_VERSION;

	switch(type) {
		case GUMS_OBJ_DOMAIN:
			break;

/*
		case GUMS_OBJ_WORKSTATION_TRUST:
		case GUMS_OBJ_SERVER_TRUST:
		case GUMS_OBJ_DOMAIN_TRUST:
*/
		case GUMS_OBJ_NORMAL_USER:
			go->data = (GUMS_USER *)talloc_zero(mem_ctx, sizeof(GUMS_USER));
			break;

		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			go->data = (GUMS_GROUP *)talloc_zero(mem_ctx, sizeof(GUMS_GROUP));
			break;

		default:
			/* TODO: throw error */
			ret = NT_STATUS_OBJECT_TYPE_MISMATCH;
			goto error;
	}

	if (!(go->data)) {
		ret = NT_STATUS_NO_MEMORY;
		goto error;
	}

	*obj = go;
	return NT_STATUS_OK;
	
error:
	talloc_destroy(go->mem_ctx);
	*obj = NULL;
	return ret;
}

NTSTATUS gums_get_object_seq_num(uint32 *version, const GUMS_OBJECT *obj)
{
	if (!version || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	*version = obj->version;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_object_seq_num(GUMS_OBJECT *obj, uint32 version)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	obj->version = version;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_sec_desc(SEC_DESC **sec_desc, const GUMS_OBJECT *obj)
{
	if (!sec_desc || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	*sec_desc = obj->sec_desc;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_sec_desc(GUMS_OBJECT *obj, const SEC_DESC *sec_desc)
{
	if (!obj || !sec_desc)
		return NT_STATUS_INVALID_PARAMETER;

	obj->sec_desc = dup_sec_desc(obj->mem_ctx, sec_desc);
	if (!(obj->sec_desc)) return NT_STATUS_UNSUCCESSFUL;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_object_sid(DOM_SID **sid, const GUMS_OBJECT *obj)
{
	if (!sid || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	*sid = obj->sid;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_object_sid(GUMS_OBJECT *obj, const DOM_SID *sid)
{
	if (!obj || !sid)
		return NT_STATUS_INVALID_PARAMETER;

	obj->sid = sid_dup_talloc(obj->mem_ctx, sid);
	if (!(obj->sid)) return NT_STATUS_UNSUCCESSFUL;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_object_name(char **name, const GUMS_OBJECT *obj)
{
	if (!name || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	*name = obj->name;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_object_name(GUMS_OBJECT *obj, const char *name)
{
	if (!obj || !name)
		return NT_STATUS_INVALID_PARAMETER;

	obj->name = (char *)talloc_strdup(obj->mem_ctx, name);
	if (!(obj->name)) return NT_STATUS_UNSUCCESSFUL;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_object_description(char **description, const GUMS_OBJECT *obj)
{
	if (!description || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	*description = obj->description;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_object_description(GUMS_OBJECT *obj, const char *description)
{
	if (!obj || !description)
		return NT_STATUS_INVALID_PARAMETER;

	obj->description = (char *)talloc_strdup(obj->mem_ctx, description);
	if (!(obj->description)) return NT_STATUS_UNSUCCESSFUL;
	return NT_STATUS_OK;
}

/* User specific functions */

/*
NTSTATUS gums_get_object_privileges(PRIVILEGE_SET **priv_set, const GUMS_OBJECT *obj)
{
	if (!priv_set)
		return NT_STATUS_INVALID_PARAMETER;

	*priv_set = obj->priv_set;
	return NT_STATUS_OK;
}
*/

NTSTATUS gums_get_user_pri_group(DOM_SID **sid, const GUMS_OBJECT *obj)
{
	if (!sid || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*sid = obj->data.user->group_sid;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_pri_group(GUMS_OBJECT *obj, const DOM_SID *sid)
{
	if (!obj || !sid)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->group_sid = sid_dup_talloc(obj->mem_ctx, sid);
	if (!(obj->data.user->group_sid)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_nt_pwd(DATA_BLOB **nt_pwd, const GUMS_OBJECT *obj)
{
	if (!nt_pwd || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*nt_pwd = obj->data.user->nt_pw;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_nt_pwd(GUMS_OBJECT *obj, const DATA_BLOB nt_pwd)
{
	if (!obj || !nt_pwd || nt_pwd != NT_HASH_LEN)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->nt_pwd = data_blob_talloc(obj->mem_ctx, nt_pwd.data, nt_pwd.lenght);
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_lm_pwd(DATA_BLOB **lm_pwd, const GUMS_OBJECT *obj)
{ 
	if (!lm_pwd || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*lm_pwd = obj->data.user->lm_pw;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_lm_pwd(GUMS_OBJECT *obj, const DATA_BLOB lm_pwd)
{
	if (!obj || !lm_pwd || lm_pwd != LM_HASH_LEN)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->lm_pwd = data_blob_talloc(obj->mem_ctx, lm_pwd.data, lm_pwd.lenght);
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_fullname(char **fullname, const GUMS_OBJECT *obj)
{
	if (!fullname || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*fullname = obj->data.user->full_name;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_fullname(GUMS_OBJECT *obj, const char *fullname)
{
	if (!obj || !fullname)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->full_name = (char *)talloc_strdup(obj->mem_ctx, fullname);
	if (!(obj->data.user->full_name)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_homedir(char **homedir, const GUMS_OBJECT *obj)
{
	if (!homedir || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*homedir = obj->data.user->home_dir;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_homedir(GUMS_OBJECT *obj, const char *homedir)
{
	if (!obj || !homedir)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->home_dir = (char *)talloc_strdup(obj->mem_ctx, homedir);
	if (!(obj->data.user->home_dir)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_dir_drive(char **dirdrive, const GUMS_OBJECT *obj)
{
	if (!dirdrive || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*dirdrive = obj->data.user->dir_drive;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_dir_drive(GUMS_OBJECT *obj, const char *dir_drive)
{
	if (!obj || !dir_drive)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->dir_drive = (char *)talloc_strdup(obj->mem_ctx, dir_drive);
	if (!(obj->data.user->dir_drive)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_logon_script(char **logon_script, const GUMS_OBJECT *obj)
{
	if (!logon_script || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*logon_script = obj->data.user->logon_script;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_logon_script(GUMS_OBJECT *obj, const char *logon_script)
{
	if (!obj || !logon_script)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->logon_script = (char *)talloc_strdup(obj->mem_ctx, logon_script);
	if (!(obj->data.user->logon_script)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_profile_path(char **profile_path, const GUMS_OBJECT *obj)
{
	if (!profile_path || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*profile_path = obj->data.user->profile_path;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_profile_path(GUMS_OBJECT *obj, const char *profile_path)
{
	if (!obj || !profile_path)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->profile_path = (char *)talloc_strdup(obj->mem_ctx, profile_path);
	if (!(obj->data.user->profile_path)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_workstations(char **workstations, const GUMS_OBJECT *obj)
{
	if (!workstations || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*workstations = obj->data.user->workstations;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_workstations(GUMS_OBJECT *obj, const char *workstations)
{
	if (!obj || !workstations)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->workstations = (char *)talloc_strdup(obj->mem_ctx, workstations);
	if (!(obj->data.user->workstations)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_unknown_str(char **unknown_str, const GUMS_OBJECT *obj)
{
	if (!unknown_str || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*unknown_str = obj->data.user->unknown_str;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_unknown_str(GUMS_OBJECT *obj, const char *unknown_str)
{
	if (!obj || !unknown_str)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->unknown_str = (char *)talloc_strdup(obj->mem_ctx, unknown_str);
	if (!(obj->data.user->unknown_str)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_munged_dial(char **munged_dial, const GUMS_OBJECT *obj)
{
	if (!munged_dial || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*munged_dial = obj->data.user->munged_dial;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_munged_dial(GUMS_OBJECT *obj, const char *munged_dial)
{
	if (!obj || !munged_dial)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->munged_dial = (char *)talloc_strdup(obj->mem_ctx, munged_dial);
	if (!(obj->data.user->munged_dial)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_logon_time(NTTIME *logon_time, const GUMS_OBJECT *obj)
{
	if (!logon_time || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*logon_time = obj->data.user->logon_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_logon_time(GUMS_OBJECT *obj, NTTIME logon_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->logon_time = logon_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_logoff_time(NTTIME *logoff_time, const GUMS_OBJECT *obj)
{
	if (!logoff_time || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*logoff_time = obj->data.user->logoff_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_logoff_time(GUMS_OBJECT *obj, NTTIME logoff_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->logoff_time = logoff_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_kickoff_time(NTTIME *kickoff_time, const GUMS_OBJECT *obj)
{
	if (!kickoff_time || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*kickoff_time = obj->data.user->kickoff_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_kickoff_time(GUMS_OBJECT *obj, NTTIME kickoff_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->kickoff_time = kickoff_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_pass_last_set_time(NTTIME *pass_last_set_time, const GUMS_OBJECT *obj)
{
	if (!pass_last_set_time || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*pass_last_set_time = obj->data.user->pass_last_set_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_pass_last_set_time(GUMS_OBJECT *obj, NTTIME pass_last_set_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->pass_last_set_time = pass_last_set_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_pass_can_change_time(NTTIME *pass_can_change_time, const GUMS_OBJECT *obj)
{
	if (!pass_can_change_time || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*pass_can_change_time = obj->data.user->pass_can_change_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_pass_can_change_time(GUMS_OBJECT *obj, NTTIME pass_can_change_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->pass_can_change_time = pass_can_change_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_pass_must_change_time(NTTIME *pass_must_change_time, const GUMS_OBJECT *obj)
{
	if (!pass_must_change_time || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*pass_must_change_time = obj->data-user->pass_must_change_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_pass_must_change_time(GUMS_OBJECT *obj, NTTIME pass_must_change_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->pass_must_change_time = pass_must_change_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_logon_divs(uint16 *logon_divs, const GUMS_OBJECT *obj)
{
	if (!logon_divs || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*logon_divs = obj->data.user->logon_divs;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_logon_divs(GUMS_OBJECT *obj, uint16 logon_divs)
{
	if (!obj || !logon_divs)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->logon_divs = logon_divs;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_hours_len(uint32 *hours_len, const GUMS_OBJECT *obj)
{
	if (!hours_len || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*hours_len = obj->data.user->hours_len;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_hours_len(GUMS_OBJECT *obj, uint32 hours_len)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->hours_len = hours_len;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_hours(uint8 **hours, const GUMS_OBJECT *obj)
{
	if (!hours || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*hours = obj->data.user->hours;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_hours(GUMS_OBJECT *obj, const uint8 *hours)
{
	if (!obj || !hours)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->hours = (uint8 *)talloc_memdup(obj->mem_ctx, hours, obj->data.user->hours_len);
	if (!(obj->data.user->hours) & (obj->data.user->hours_len != 0)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_unknown_3(uint32 *unknown_3, const GUMS_OBJECT *obj)
{
	if (!unknown_3 || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*unknown_3 = obj->data.user->unknown_3;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_unknown_3(GUMS_OBJECT *obj, uint32 unknown_3)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->unknown_3 = unknown_3;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_unknown_5(uint32 *unknown_5, const GUMS_OBJECT *obj)
{
	if (!unknown_5 || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*unknown_5 = obj->data.user->unknown_5;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_unknown_5(GUMS_OBJECT *obj, uint32 unknown_5)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->unknown_5 = unknown_5;
	return NT_STATUS_OK;
}

NTSTATUS gums_get_user_unknown_6(uint32 *unknown_6, const GUMS_OBJECT *obj)
{
	if (!unknown_6 || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*unknown_6 = obj->data.user->unknown_6;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_unknown_6(GUMS_OBJECT *obj, uint32 unknown_6)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.user->unknown_6 = unknown_6;
	return NT_STATUS_OK;
}

/* Group specific functions */

NTSTATUS gums_get_group_members(uint32 *count, DOM_SID **members, const GUMS_OBJECT *obj)
{
	if (!count || !members || !obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_GROUP &&
		obj->type != GUMS_OBJ_ALIAS)
			return NT_STATUS_OBJECT_TYPE_MISMATCH;

	*count = obj->data.group->count;
	*members = obj->data.group->members;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_group_members(GUMS_OBJECT *obj, uint32 count, const DOM_SID **members)
{
	uint32 n;

	if (!obj || !members)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_GROUP &&
		obj->type != GUMS_OBJ_ALIAS)
			return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->data.group->count = count;
	n = 0;
	do {
		obj->data.group->members[n] = dup_sec_desc(obj->mem_ctx, members[n]);
		if (!(obj->data.group->members[n])) return NT_STATUS_NO_MEMORY;
		n++;
	} while (n < count);
	return NT_STATUS_OK;
}

/* data_store set functions */

NTSTATUS gums_create_commit_set(GUMS_COMMIT_SET **com_set, TALLOC_CTX *ctx, DOM_SID *sid, uint32 type)
{
	TALLOC_CTX *mem_ctx;
	GUMS_COMMIT_SET *set;

	mem_ctx = talloc_init("commit_set");
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

NTSTATUS gums_cs_set_sec_desc(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, SEC_DESC *sec_desc)
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

NTSTATUS gums_cs_add_privilege(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, LUID_ATTR priv)
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

NTSTATUS gums_cs_del_privilege(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, LUID_ATTR priv)
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

NTSTATUS gums_cs_set_privilege_set(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, PRIVILEGE_SET *priv_set)
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

NTSTATUS gums_cs_set_string(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, uint32 type, char *str)
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

NTSTATUS gums_cs_set_name(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *name)
{
	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, name);
}

NTSTATUS gums_cs_set_description(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *desc)
{
	return gums_set_string(mem_ctx, com_set, GUMS_SET_DESCRIPTION, desc);
}

NTSTATUS gums_cs_set_full_name(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *full_name)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, full_name);
}

NTSTATUS gums_cs_set_home_directory(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *home_dir)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, home_dir);
}

NTSTATUS gums_cs_set_drive(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *drive)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, drive);
}

NTSTATUS gums_cs_set_logon_script(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *logon_script)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, logon_script);
}

NTSTATUS gums_cs_set_profile_path(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *prof_path)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, prof_path);
}

NTSTATUS gums_cs_set_workstations(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *wks)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, wks);
}

NTSTATUS gums_cs_set_unknown_string(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *unkn_str)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, unkn_str);
}

NTSTATUS gums_cs_set_munged_dial(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, char *munged_dial)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_string(mem_ctx, com_set, GUMS_SET_NAME, munged_dial);
}

NTSTATUS gums_cs_set_nttime(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, uint32 type, NTTIME *time)
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

NTSTATUS gums_cs_set_logon_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *logon_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_LOGON_TIME, logon_time);
}

NTSTATUS gums_cs_set_logoff_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *logoff_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_LOGOFF_TIME, logoff_time);
}

NTSTATUS gums_cs_set_kickoff_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *kickoff_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_KICKOFF_TIME, kickoff_time);
}

NTSTATUS gums_cs_set_pass_last_set_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *pls_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_LOGON_TIME, pls_time);
}

NTSTATUS gums_cs_set_pass_can_change_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *pcc_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_LOGON_TIME, pcc_time);
}

NTSTATUS gums_cs_set_pass_must_change_time(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, NTTIME *pmc_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_set_nttime(mem_ctx, com_set, GUMS_SET_LOGON_TIME, pmc_time);
}

NTSTATUS gums_cs_add_sids_to_group(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
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

NTSTATUS gums_cs_add_users_to_group(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	if (!mem_ctx || !com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;
	if (com_set->type != GUMS_OBJ_GROUP || com_set->type != GUMS_OBJ_ALIAS)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_add_sids_to_group(mem_ctx, com_set, sids, count);	
}

NTSTATUS gums_cs_add_groups_to_group(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	if (!mem_ctx || !com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;
	if (com_set->type != GUMS_OBJ_ALIAS)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_add_sids_to_group(mem_ctx, com_set, sids, count);	
}

NTSTATUS gums_cs_del_sids_from_group(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
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

NTSTATUS gums_ds_set_sids_in_group(TALLOC_CTX *mem_ctx, GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
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

NTSTATUS gums_destroy_commit_set(GUMS_COMMIT_SET **com_set)
{
	talloc_destroy((*com_set)->mem_ctx);
	*com_set = NULL;

	return NT_STATUS_OK;
}

