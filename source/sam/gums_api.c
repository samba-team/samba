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

/* Functions to get/set info from a GUMS object */

NTSTATUS gums_create_object(GUMS_OBJECT **obj, uint32 type)
{
	TALLOC_CTX *mem_ctx;
	GUMS_OBJECT *go;
	NTSTATUS ret;

       	mem_ctx = talloc_init("gums_create_object");
	if (!mem_ctx) {
		DEBUG(0, ("gums_create_object: Out of memory!\n"));
		*obj = NULL;
		return NT_STATUS_NO_MEMORY;
	}

	go = talloc_zero(mem_ctx, sizeof(GUMS_OBJECT));
	if (!go) {
		DEBUG(0, ("gums_create_object: Out of memory!\n"));
		talloc_destroy(mem_ctx);
		*obj = NULL;
		return NT_STATUS_NO_MEMORY;
	}

	go->mem_ctx = mem_ctx;
	go->type = type;
	go->version = GUMS_OBJECT_VERSION;

	switch(type) {
		case GUMS_OBJ_DOMAIN:
			go->domain = (GUMS_DOMAIN *)talloc_zero(mem_ctx, sizeof(GUMS_DOMAIN));
			if (!(go->domain)) {
				ret = NT_STATUS_NO_MEMORY;
				DEBUG(0, ("gums_create_object: Out of memory!\n"));
				goto error;
			}

			break;

/*
		case GUMS_OBJ_WORKSTATION_TRUST:
		case GUMS_OBJ_SERVER_TRUST:
		case GUMS_OBJ_DOMAIN_TRUST:
*/
		case GUMS_OBJ_NORMAL_USER:
			go->user = (GUMS_USER *)talloc_zero(mem_ctx, sizeof(GUMS_USER));
			if (!(go->user)) {
				ret = NT_STATUS_NO_MEMORY;
				DEBUG(0, ("gums_create_object: Out of memory!\n"));
				goto error;
			}
			gums_set_user_acct_ctrl(go, ACB_NORMAL);
			gums_set_user_hours(go, 0, NULL);

			break;

		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			go->group = (GUMS_GROUP *)talloc_zero(mem_ctx, sizeof(GUMS_GROUP));
			if (!(go->group)) {
				ret = NT_STATUS_NO_MEMORY;
				DEBUG(0, ("gums_create_object: Out of memory!\n"));
				goto error;
			}

			break;

		default:
			/* TODO: throw error */
			ret = NT_STATUS_OBJECT_TYPE_MISMATCH;
			goto error;
	}

	*obj = go;
	return NT_STATUS_OK;

error:
	talloc_destroy(go->mem_ctx);
	*obj = NULL;
	return ret;
}

NTSTATUS gums_create_privilege(GUMS_PRIVILEGE **priv)
{
	TALLOC_CTX *mem_ctx;
	GUMS_PRIVILEGE *pri;

       	mem_ctx = talloc_init("gums_create_privilege");
	if (!mem_ctx) {
		DEBUG(0, ("gums_create_privilege: Out of memory!\n"));
		*priv = NULL;
		return NT_STATUS_NO_MEMORY;
	}

	pri = talloc_zero(mem_ctx, sizeof(GUMS_PRIVILEGE));
	if (!pri) {
		DEBUG(0, ("gums_create_privilege: Out of memory!\n"));
		talloc_destroy(mem_ctx);
		*priv = NULL;
		return NT_STATUS_NO_MEMORY;
	}

	pri->mem_ctx = mem_ctx;
	pri->version = GUMS_PRIVILEGE_VERSION;

	*priv = pri;
	return NT_STATUS_OK;
}

NTSTATUS gums_destroy_object(GUMS_OBJECT **obj)
{
	if (!obj || !(*obj))
		return NT_STATUS_INVALID_PARAMETER;

	if ((*obj)->mem_ctx)
		talloc_destroy((*obj)->mem_ctx);
	*obj = NULL;

	return NT_STATUS_OK;
}

NTSTATUS gums_destroy_privilege(GUMS_PRIVILEGE **priv)
{
	if (!priv || !(*priv))
		return NT_STATUS_INVALID_PARAMETER;

	if ((*priv)->mem_ctx)
		talloc_destroy((*priv)->mem_ctx);
	*priv = NULL;

	return NT_STATUS_OK;
}

void gums_reset_object(GUMS_OBJECT *go)
{
	go->seq_num = 0;
	go->sid = NULL;
	go->name = NULL;
	go->description = NULL;

	switch(go->type) {
		case GUMS_OBJ_DOMAIN:
			memset(go->domain, 0, sizeof(GUMS_DOMAIN));
			break;

/*
		case GUMS_OBJ_WORKSTATION_TRUST:
		case GUMS_OBJ_SERVER_TRUST:
		case GUMS_OBJ_DOMAIN_TRUST:
*/
		case GUMS_OBJ_NORMAL_USER:
			memset(go->user, 0, sizeof(GUMS_USER));
			gums_set_user_acct_ctrl(go, ACB_NORMAL);
			break;

		case GUMS_OBJ_GROUP:
		case GUMS_OBJ_ALIAS:
			memset(go->group, 0, sizeof(GUMS_GROUP));
			break;

		default:
			return;
	}
}

uint32 gums_get_object_type(const GUMS_OBJECT *obj)
{
	if (!obj)
		return 0;

	return obj->type;
}

uint32 gums_get_object_seq_num(const GUMS_OBJECT *obj)
{
	if (!obj)
		return 0;

	return obj->seq_num;
}

uint32 gums_get_object_version(const GUMS_OBJECT *obj)
{
	if (!obj)
		return 0;

	return obj->version;
}

const SEC_DESC *gums_get_sec_desc(const GUMS_OBJECT *obj)
{
	if (!obj)
		return NULL;

	return obj->sec_desc;
}

const DOM_SID *gums_get_object_sid(const GUMS_OBJECT *obj)
{
	if (!obj)
		return NULL;

	return obj->sid;
}

const char *gums_get_object_name(const GUMS_OBJECT *obj)
{
	if (!obj)
		return NULL;

	return obj->name;
}

const char *gums_get_object_description(const GUMS_OBJECT *obj)
{
	if (!obj)
		return NULL;

	return obj->description;
}

NTSTATUS gums_set_object_seq_num(GUMS_OBJECT *obj, uint32 seq_num)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	obj->seq_num = seq_num;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_object_version(GUMS_OBJECT *obj, uint32 version)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	obj->version = version;
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

NTSTATUS gums_set_object_sid(GUMS_OBJECT *obj, const DOM_SID *sid)
{
	if (!obj || !sid)
		return NT_STATUS_INVALID_PARAMETER;

	obj->sid = sid_dup_talloc(obj->mem_ctx, sid);
	if (!(obj->sid)) return NT_STATUS_UNSUCCESSFUL;
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

NTSTATUS gums_set_object_description(GUMS_OBJECT *obj, const char *description)
{
	if (!obj || !description)
		return NT_STATUS_INVALID_PARAMETER;

	obj->description = (char *)talloc_strdup(obj->mem_ctx, description);
	if (!(obj->description)) return NT_STATUS_UNSUCCESSFUL;
	return NT_STATUS_OK;
}

/*
NTSTATUS gums_get_object_privileges(PRIVILEGE_SET **priv_set, const GUMS_OBJECT *obj)
{
	if (!priv_set)
		return NT_STATUS_INVALID_PARAMETER;

	*priv_set = obj->priv_set;
	return NT_STATUS_OK;
}
*/

uint32 gums_get_domain_next_rid(const GUMS_OBJECT *obj)
{
	if (obj->type != GUMS_OBJ_DOMAIN)
		return -1;

	return obj->domain->next_rid;
}

NTSTATUS gums_set_domain_next_rid(GUMS_OBJECT *obj, uint32 rid)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_DOMAIN)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->domain->next_rid = rid;
	return NT_STATUS_OK;
}

/* User specific functions */

const DOM_SID *gums_get_user_pri_group(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return NULL;

	return  obj->user->group_sid;
}

const DATA_BLOB gums_get_user_nt_pwd(const GUMS_OBJECT *obj)
{
	fstring p;

	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return data_blob(NULL, 0);

	smbpasswd_sethexpwd(p, (unsigned char *)(obj->user->nt_pw.data), 0);
	DEBUG(100, ("Reading NT Password=[%s]\n", p));

	return obj->user->nt_pw;
}

const DATA_BLOB gums_get_user_lm_pwd(const GUMS_OBJECT *obj)
{ 
	fstring p;

	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return data_blob(NULL, 0);

	smbpasswd_sethexpwd(p, (unsigned char *)(obj->user->lm_pw.data), 0);
	DEBUG(100, ("Reading LM Password=[%s]\n", p));

	return obj->user->lm_pw;
}

const char *gums_get_user_fullname(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return NULL;

	return obj->user->full_name;
}

const char *gums_get_user_homedir(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return NULL;

	return obj->user->home_dir;
}

const char *gums_get_user_dir_drive(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return NULL;

	return obj->user->dir_drive;
}

const char *gums_get_user_profile_path(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return NULL;

	return obj->user->profile_path;
}

const char *gums_get_user_logon_script(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return NULL;

	return obj->user->logon_script;
}

const char *gums_get_user_workstations(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return NULL;

	return obj->user->workstations;
}

const char *gums_get_user_unknown_str(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return NULL;

	return obj->user->unknown_str;
}

const char *gums_get_user_munged_dial(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return NULL;

	return obj->user->munged_dial;
}

NTTIME gums_get_user_logon_time(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER) {
		NTTIME null_time;
		init_nt_time(&null_time);
		return null_time;
	}

	return obj->user->logon_time;
}

NTTIME gums_get_user_logoff_time(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER) {
		NTTIME null_time;
		init_nt_time(&null_time);
		return null_time;
	}

	return obj->user->logoff_time;
}

NTTIME gums_get_user_kickoff_time(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER) {
		NTTIME null_time;
		init_nt_time(&null_time);
		return null_time;
	}

	return obj->user->kickoff_time;
}

NTTIME gums_get_user_pass_last_set_time(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER) {
		NTTIME null_time;
		init_nt_time(&null_time);
		return null_time;
	}

	return obj->user->pass_last_set_time;
}

NTTIME gums_get_user_pass_can_change_time(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER) {
		NTTIME null_time;
		init_nt_time(&null_time);
		return null_time;
	}

	return obj->user->pass_can_change_time;
}

NTTIME gums_get_user_pass_must_change_time(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER) {
		NTTIME null_time;
		init_nt_time(&null_time);
		return null_time;
	}

	return obj->user->pass_must_change_time;
}

uint16 gums_get_user_acct_ctrl(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return 0;

	return obj->user->acct_ctrl;
}

uint16 gums_get_user_logon_divs(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return 0;

	return obj->user->logon_divs;
}

uint32 gums_get_user_hours_len(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return 0;

	return obj->user->hours_len;
}

const uint8 *gums_get_user_hours(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return NULL;

	return obj->user->hours;
}

uint32 gums_get_user_unknown_3(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return 0;

	return obj->user->unknown_3;
}

uint16 gums_get_user_bad_password_count(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return 0;

	return obj->user->bad_password_count;
}

uint16 gums_get_user_logon_count(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return 0;

	return obj->user->logon_count;
}

uint32 gums_get_user_unknown_6(const GUMS_OBJECT *obj)
{
	if (!obj || obj->type != GUMS_OBJ_NORMAL_USER)
		return 0;

	return obj->user->unknown_6;
}

NTSTATUS gums_set_user_pri_group(GUMS_OBJECT *obj, const DOM_SID *sid)
{
	if (!obj || !sid)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->group_sid = sid_dup_talloc(obj->mem_ctx, sid);
	if (!(obj->user->group_sid)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_nt_pwd(GUMS_OBJECT *obj, const DATA_BLOB nt_pwd)
{
	fstring p;
	unsigned char r[16];

	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->nt_pw = data_blob_talloc(obj->mem_ctx, nt_pwd.data, nt_pwd.length);

	memcpy(r, nt_pwd.data, 16);
	smbpasswd_sethexpwd(p, r, 0);
	DEBUG(100, ("Setting NT Password=[%s]\n", p));

	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_lm_pwd(GUMS_OBJECT *obj, const DATA_BLOB lm_pwd)
{
	fstring p;
	unsigned char r[16];

	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->lm_pw = data_blob_talloc(obj->mem_ctx, lm_pwd.data, lm_pwd.length);

	memcpy(r, lm_pwd.data, 16);
	smbpasswd_sethexpwd(p, r, 0);
	DEBUG(100, ("Setting LM Password=[%s]\n", p));

	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_fullname(GUMS_OBJECT *obj, const char *fullname)
{
	if (!obj || !fullname)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->full_name = (char *)talloc_strdup(obj->mem_ctx, fullname);
	if (!(obj->user->full_name)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_homedir(GUMS_OBJECT *obj, const char *homedir)
{
	if (!obj || !homedir)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->home_dir = (char *)talloc_strdup(obj->mem_ctx, homedir);
	if (!(obj->user->home_dir)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_dir_drive(GUMS_OBJECT *obj, const char *dir_drive)
{
	if (!obj || !dir_drive)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->dir_drive = (char *)talloc_strdup(obj->mem_ctx, dir_drive);
	if (!(obj->user->dir_drive)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_logon_script(GUMS_OBJECT *obj, const char *logon_script)
{
	if (!obj || !logon_script)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->logon_script = (char *)talloc_strdup(obj->mem_ctx, logon_script);
	if (!(obj->user->logon_script)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_profile_path(GUMS_OBJECT *obj, const char *profile_path)
{
	if (!obj || !profile_path)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->profile_path = (char *)talloc_strdup(obj->mem_ctx, profile_path);
	if (!(obj->user->profile_path)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_workstations(GUMS_OBJECT *obj, const char *workstations)
{
	if (!obj || !workstations)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->workstations = (char *)talloc_strdup(obj->mem_ctx, workstations);
	if (!(obj->user->workstations)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_unknown_str(GUMS_OBJECT *obj, const char *unknown_str)
{
	if (!obj || !unknown_str)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->unknown_str = (char *)talloc_strdup(obj->mem_ctx, unknown_str);
	if (!(obj->user->unknown_str)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_munged_dial(GUMS_OBJECT *obj, const char *munged_dial)
{
	if (!obj || !munged_dial)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->munged_dial = (char *)talloc_strdup(obj->mem_ctx, munged_dial);
	if (!(obj->user->munged_dial)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_logon_time(GUMS_OBJECT *obj, NTTIME logon_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->logon_time = logon_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_logoff_time(GUMS_OBJECT *obj, NTTIME logoff_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->logoff_time = logoff_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_kickoff_time(GUMS_OBJECT *obj, NTTIME kickoff_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->kickoff_time = kickoff_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_pass_last_set_time(GUMS_OBJECT *obj, NTTIME pass_last_set_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->pass_last_set_time = pass_last_set_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_pass_can_change_time(GUMS_OBJECT *obj, NTTIME pass_can_change_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->pass_can_change_time = pass_can_change_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_pass_must_change_time(GUMS_OBJECT *obj, NTTIME pass_must_change_time)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->pass_must_change_time = pass_must_change_time;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_acct_ctrl(GUMS_OBJECT *obj, uint16 acct_ctrl)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->acct_ctrl = acct_ctrl;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_logon_divs(GUMS_OBJECT *obj, uint16 logon_divs)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->logon_divs = logon_divs;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_hours(GUMS_OBJECT *obj, uint32 hours_len, const uint8 *hours)
{
	if (!obj || !hours)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->hours_len = hours_len;
	if (hours_len == 0)
		DEBUG(10, ("gums_set_user_hours: Warning, hours_len is zero!\n"));

	obj->user->hours = (uint8 *)talloc(obj->mem_ctx, MAX_HOURS_LEN);
	if (!(obj->user->hours))
		return NT_STATUS_NO_MEMORY;
	if (hours_len)
		memcpy(obj->user->hours, hours, hours_len);

	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_unknown_3(GUMS_OBJECT *obj, uint32 unknown_3)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->unknown_3 = unknown_3;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_bad_password_count(GUMS_OBJECT *obj, uint16 bad_password_count)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->bad_password_count = bad_password_count;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_logon_count(GUMS_OBJECT *obj, uint16 logon_count)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->logon_count = logon_count;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_user_unknown_6(GUMS_OBJECT *obj, uint32 unknown_6)
{
	if (!obj)
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->user->unknown_6 = unknown_6;
	return NT_STATUS_OK;
}

/* Group specific functions */

const DOM_SID *gums_get_group_members(int *count, const GUMS_OBJECT *obj)
{
	if (!count || !obj || !(obj->type == GUMS_OBJ_GROUP || obj->type == GUMS_OBJ_ALIAS)) {
		*count = -1;
		return NULL;
	}

	*count = obj->group->count;
	return obj->group->members;
}

NTSTATUS gums_set_group_members(GUMS_OBJECT *obj, uint32 count, DOM_SID *members)
{
	uint32 n;

	if (!obj || ((count > 0) && !members))
		return NT_STATUS_INVALID_PARAMETER;

	if (obj->type != GUMS_OBJ_GROUP &&
		obj->type != GUMS_OBJ_ALIAS)
			return NT_STATUS_OBJECT_TYPE_MISMATCH;

	obj->group->count = count;

	if (count) {
		obj->group->members = (DOM_SID *)talloc(obj->mem_ctx, count * sizeof(DOM_SID));
		if (!(obj->group->members)) {
			return NT_STATUS_NO_MEMORY;
		}


		n = 0;
		do {
			sid_copy(&(obj->group->members[n]), &(members[n]));
			n++;
		} while (n < count);
	} else {
		obj->group->members = 0;
	}

	return NT_STATUS_OK;
}

/* Privilege specific functions */

const LUID_ATTR *gums_get_priv_luid_attr(const GUMS_PRIVILEGE *priv)
{
	if (!priv) {
		return NULL;
	}

	return priv->privilege;
}

const DOM_SID *gums_get_priv_members(int *count, const GUMS_PRIVILEGE *priv)
{
	if (!count || !priv) {
		*count = -1;
		return NULL;
	}

	*count = priv->count;
	return priv->members;
}

NTSTATUS gums_set_priv_luid_attr(GUMS_PRIVILEGE *priv, LUID_ATTR *luid_attr)
{
	if (!luid_attr || !priv)
		return NT_STATUS_INVALID_PARAMETER;

	priv->privilege = (LUID_ATTR *)talloc_memdup(priv->mem_ctx, luid_attr, sizeof(LUID_ATTR));
	if (!(priv->privilege)) return NT_STATUS_NO_MEMORY;
	return NT_STATUS_OK;
}

NTSTATUS gums_set_priv_members(GUMS_PRIVILEGE *priv, uint32 count, DOM_SID *members)
{
	uint32 n;

	if (!priv || !members || !members)
		return NT_STATUS_INVALID_PARAMETER;

	priv->count = count;
	priv->members = (DOM_SID *)talloc(priv->mem_ctx, count * sizeof(DOM_SID));
	if (!(priv->members))
		return NT_STATUS_NO_MEMORY;

	n = 0;
	do {
		sid_copy(&(priv->members[n]), &(members[n]));
		n++;
	} while (n < count);

	return NT_STATUS_OK;
}

/* data_store set functions */

NTSTATUS gums_create_commit_set(GUMS_COMMIT_SET **com_set, DOM_SID *sid, uint32 type)
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("commit_set");
	if (mem_ctx == NULL)
		return NT_STATUS_NO_MEMORY;

	*com_set = (GUMS_COMMIT_SET *)talloc_zero(mem_ctx, sizeof(GUMS_COMMIT_SET));
	if (*com_set == NULL) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	(*com_set)->mem_ctx = mem_ctx;
	(*com_set)->type = type;
	sid_copy(&((*com_set)->sid), sid);

	return NT_STATUS_OK;
}

NTSTATUS gums_cs_grow_data_set(GUMS_COMMIT_SET *com_set, int size)
{
	GUMS_DATA_SET *data_set;

	com_set->count = com_set->count + size;
	if (com_set->count == size) { /* data set is empty*/
		data_set = (GUMS_DATA_SET *)talloc_zero(com_set->mem_ctx, sizeof(GUMS_DATA_SET));
	} else {
		data_set = (GUMS_DATA_SET *)talloc_realloc(com_set->mem_ctx, com_set->data, sizeof(GUMS_DATA_SET) * com_set->count);
	}
	if (data_set == NULL)
		return NT_STATUS_NO_MEMORY;

	com_set->data = data_set;

	return NT_STATUS_OK;
}

NTSTATUS gums_cs_set_sec_desc(GUMS_COMMIT_SET *com_set, SEC_DESC *sec_desc)
{
	NTSTATUS ret;
	GUMS_DATA_SET *data_set;
	SEC_DESC *new_sec_desc;

	if (!com_set || !sec_desc)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = gums_cs_grow_data_set(com_set, 1)))
		return ret;

	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_SET_SEC_DESC;
	new_sec_desc = dup_sec_desc(com_set->mem_ctx, sec_desc);
	if (new_sec_desc == NULL)
		return NT_STATUS_NO_MEMORY;

	(SEC_DESC *)(data_set->data) = new_sec_desc;

	return NT_STATUS_OK;
}

/*
NTSTATUS gums_cs_add_privilege(GUMS_PRIV_COMMIT_SET *com_set, LUID_ATTR priv)
{
	NTSTATUS ret;
	GUMS_DATA_SET *data_set;
	LUID_ATTR *new_priv;

	if (!com_set)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_OK(ret = gums_pcs_grow_data_set(com_set, 1)))
		return ret;

	data_set = ((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_ADD_PRIVILEGE;
	if (!NT_STATUS_IS_OK(ret = dupalloc_luid_attr(com_set->mem_ctx, &new_priv, priv)))
		return ret;

	(SEC_DESC *)(data_set->data) = new_priv;

	return NT_STATUS_OK;	
}

NTSTATUS gums_cs_del_privilege(GUMS_PRIV_COMMIT_SET *com_set, LUID_ATTR priv)
{
	NTSTATUS ret;
	GUMS_DATA_SET *data_set;
	LUID_ATTR *new_priv;

	if (!com_set)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_OK(ret = gums_pcs_grow_data_set(com_set, 1)))
		return ret;

	data_set = ((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_DEL_PRIVILEGE;
	if (!NT_STATUS_IS_OK(ret = dupalloc_luid_attr(com_set->mem_ctx, &new_priv, priv)))
		return ret;

	(SEC_DESC *)(data_set->data) = new_priv;

	return NT_STATUS_OK;	
}

NTSTATUS gums_cs_set_privilege_set(GUMS_PRIV_COMMIT_SET *com_set, PRIVILEGE_SET *priv_set)
{
	NTSTATUS ret;
	GUMS_DATA_SET *data_set;
	PRIVILEGE_SET *new_priv_set;

	if (!com_set || !priv_set)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_OK(ret = gums_pcs_grow_data_set(com_set, 1)))
		return ret;

	data_set = ((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_SET_PRIVILEGE;
	if (!NT_STATUS_IS_OK(ret = init_priv_set_with_ctx(com_set->mem_ctx, &new_priv_set)))
		return ret;
		
	if (!NT_STATUS_IS_OK(ret = dup_priv_set(new_priv_set, priv_set)))
		return ret;

	(SEC_DESC *)(data_set->data) = new_priv_set;

	return NT_STATUS_OK;
}
*/

NTSTATUS gums_cs_set_string(GUMS_COMMIT_SET *com_set, uint32 type, char *str)
{
	NTSTATUS ret;
	GUMS_DATA_SET *data_set;
	char *new_str;

	if (!com_set || !str || type < GUMS_SET_NAME || type > GUMS_SET_MUNGED_DIAL)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = gums_cs_grow_data_set(com_set, 1)))
		return ret;

	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = type;
	new_str = talloc_strdup(com_set->mem_ctx, str);
	if (new_str == NULL)
		return NT_STATUS_NO_MEMORY;

	(char *)(data_set->data) = new_str;

	return NT_STATUS_OK;
}

NTSTATUS gums_cs_set_name(GUMS_COMMIT_SET *com_set, char *name)
{
	return gums_cs_set_string(com_set, GUMS_SET_NAME, name);
}

NTSTATUS gums_cs_set_description(GUMS_COMMIT_SET *com_set, char *desc)
{
	return gums_cs_set_string(com_set, GUMS_SET_DESCRIPTION, desc);
}

NTSTATUS gums_cs_set_full_name(GUMS_COMMIT_SET *com_set, char *full_name)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_string(com_set, GUMS_SET_NAME, full_name);
}

NTSTATUS gums_cs_set_home_directory(GUMS_COMMIT_SET *com_set, char *home_dir)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_string(com_set, GUMS_SET_NAME, home_dir);
}

NTSTATUS gums_cs_set_drive(GUMS_COMMIT_SET *com_set, char *drive)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_string(com_set, GUMS_SET_NAME, drive);
}

NTSTATUS gums_cs_set_logon_script(GUMS_COMMIT_SET *com_set, char *logon_script)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_string(com_set, GUMS_SET_NAME, logon_script);
}

NTSTATUS gums_cs_set_profile_path(GUMS_COMMIT_SET *com_set, char *prof_path)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_string(com_set, GUMS_SET_NAME, prof_path);
}

NTSTATUS gums_cs_set_workstations(GUMS_COMMIT_SET *com_set, char *wks)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_string(com_set, GUMS_SET_NAME, wks);
}

NTSTATUS gums_cs_set_unknown_string(GUMS_COMMIT_SET *com_set, char *unkn_str)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_string(com_set, GUMS_SET_NAME, unkn_str);
}

NTSTATUS gums_cs_set_munged_dial(GUMS_COMMIT_SET *com_set, char *munged_dial)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_string(com_set, GUMS_SET_NAME, munged_dial);
}

NTSTATUS gums_cs_set_nttime(GUMS_COMMIT_SET *com_set, uint32 type, NTTIME *nttime)
{
	NTSTATUS ret;
	GUMS_DATA_SET *data_set;
	NTTIME *new_time;

	if (!com_set || !nttime || type < GUMS_SET_LOGON_TIME || type > GUMS_SET_PASS_MUST_CHANGE_TIME)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = gums_cs_grow_data_set(com_set, 1)))
		return ret;

	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = type;
	new_time = talloc(com_set->mem_ctx, sizeof(NTTIME));
	if (new_time == NULL)
		return NT_STATUS_NO_MEMORY;

	new_time->low = nttime->low;
	new_time->high = nttime->high;
	(char *)(data_set->data) = new_time;

	return NT_STATUS_OK;
}

NTSTATUS gums_cs_set_logon_time(GUMS_COMMIT_SET *com_set, NTTIME *logon_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_nttime(com_set, GUMS_SET_LOGON_TIME, logon_time);
}

NTSTATUS gums_cs_set_logoff_time(GUMS_COMMIT_SET *com_set, NTTIME *logoff_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_nttime(com_set, GUMS_SET_LOGOFF_TIME, logoff_time);
}

NTSTATUS gums_cs_set_kickoff_time(GUMS_COMMIT_SET *com_set, NTTIME *kickoff_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_nttime(com_set, GUMS_SET_KICKOFF_TIME, kickoff_time);
}

NTSTATUS gums_cs_set_pass_last_set_time(GUMS_COMMIT_SET *com_set, NTTIME *pls_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_nttime(com_set, GUMS_SET_LOGON_TIME, pls_time);
}

NTSTATUS gums_cs_set_pass_can_change_time(GUMS_COMMIT_SET *com_set, NTTIME *pcc_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_nttime(com_set, GUMS_SET_LOGON_TIME, pcc_time);
}

NTSTATUS gums_cs_set_pass_must_change_time(GUMS_COMMIT_SET *com_set, NTTIME *pmc_time)
{
	if (com_set->type != GUMS_OBJ_NORMAL_USER)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_set_nttime(com_set, GUMS_SET_LOGON_TIME, pmc_time);
}

NTSTATUS gums_cs_add_sids_to_group(GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	NTSTATUS ret;
	GUMS_DATA_SET *data_set;
	DOM_SID **new_sids;
	int i;

	if (!com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = gums_cs_grow_data_set(com_set, 1)))
		return ret;

	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_ADD_SID_LIST;
	new_sids = (DOM_SID **)talloc(com_set->mem_ctx, (sizeof(void *) * count));
	if (new_sids == NULL)
		return NT_STATUS_NO_MEMORY;
	for (i = 0; i < count; i++) {
		new_sids[i] = sid_dup_talloc(com_set->mem_ctx, sids[i]);
		if (new_sids[i] == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	(SEC_DESC *)(data_set->data) = new_sids;

	return NT_STATUS_OK;	
}

NTSTATUS gums_cs_add_users_to_group(GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	if (!com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;
	if (com_set->type != GUMS_OBJ_GROUP || com_set->type != GUMS_OBJ_ALIAS)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_add_sids_to_group(com_set, sids, count);	
}

NTSTATUS gums_cs_add_groups_to_group(GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	if (!com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;
	if (com_set->type != GUMS_OBJ_ALIAS)
		return NT_STATUS_INVALID_PARAMETER;

	return gums_cs_add_sids_to_group(com_set, sids, count);	
}

NTSTATUS gums_cs_del_sids_from_group(GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	NTSTATUS ret;
	GUMS_DATA_SET *data_set;
	DOM_SID **new_sids;
	int i;

	if (!com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;
	if (com_set->type != GUMS_OBJ_GROUP || com_set->type != GUMS_OBJ_ALIAS)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = gums_cs_grow_data_set(com_set, 1)))
		return ret;

	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_DEL_SID_LIST;
	new_sids = (DOM_SID **)talloc(com_set->mem_ctx, (sizeof(void *) * count));
	if (new_sids == NULL)
		return NT_STATUS_NO_MEMORY;
	for (i = 0; i < count; i++) {
		new_sids[i] = sid_dup_talloc(com_set->mem_ctx, sids[i]);
		if (new_sids[i] == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	(SEC_DESC *)(data_set->data) = new_sids;

	return NT_STATUS_OK;	
}

NTSTATUS gums_ds_set_sids_in_group(GUMS_COMMIT_SET *com_set, const DOM_SID **sids, const uint32 count)
{
	NTSTATUS ret;
	GUMS_DATA_SET *data_set;
	DOM_SID **new_sids;
	int i;

	if (!com_set || !sids)
		return NT_STATUS_INVALID_PARAMETER;
	if (com_set->type != GUMS_OBJ_GROUP || com_set->type != GUMS_OBJ_ALIAS)
		return NT_STATUS_INVALID_PARAMETER;

	if (!NT_STATUS_IS_OK(ret = gums_cs_grow_data_set(com_set, 1)))
		return ret;

	data_set = &((com_set->data)[com_set->count - 1]);
	
	data_set->type = GUMS_SET_SID_LIST;
	new_sids = (DOM_SID **)talloc(com_set->mem_ctx, (sizeof(void *) * count));
	if (new_sids == NULL)
		return NT_STATUS_NO_MEMORY;
	for (i = 0; i < count; i++) {
		new_sids[i] = sid_dup_talloc(com_set->mem_ctx, sids[i]);
		if (new_sids[i] == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	(SEC_DESC *)(data_set->data) = new_sids;

	return NT_STATUS_OK;	
}

NTSTATUS gums_commit_data(GUMS_COMMIT_SET *set)
{
	NTSTATUS ret;
	GUMS_FUNCTIONS *fns;

	if (!NT_STATUS_IS_OK(ret = get_gums_fns(&fns))) {
		DEBUG(0, ("gums_commit_data: unable to get gums functions! backend uninitialized?\n"));
		return ret;
	}
	return fns->set_object_values(&(set->sid), set->count, set->data);
}

NTSTATUS gums_destroy_commit_set(GUMS_COMMIT_SET **com_set)
{
	talloc_destroy((*com_set)->mem_ctx);
	*com_set = NULL;

	return NT_STATUS_OK;
}

