/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Guenther Deschner                  2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo1(struct samr_DomInfo1 *r,
			uint16_t min_password_length,
			uint16_t password_history_length,
			uint32_t password_properties,
			int64_t max_password_age,
			int64_t min_password_age)
{
	r->min_password_length = min_password_length;
	r->password_history_length = password_history_length;
	r->password_properties = password_properties;
	r->max_password_age = max_password_age;
	r->min_password_age = min_password_age;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo2(struct samr_DomInfo2 *r,
			NTTIME force_logoff_time,
			const char *comment,
			const char *domain_name,
			const char *primary,
			uint64_t sequence_num,
			uint32_t unknown2,
			enum samr_Role role,
			uint32_t unknown3,
			uint32_t num_users,
			uint32_t num_groups,
			uint32_t num_aliases)
{
	r->force_logoff_time = force_logoff_time;
	init_lsa_String(&r->comment, comment);
	init_lsa_String(&r->domain_name, domain_name);
	init_lsa_String(&r->primary, primary);
	r->sequence_num = sequence_num;
	r->unknown2 = unknown2;
	r->role = role;
	r->unknown3 = unknown3;
	r->num_users = num_users;
	r->num_groups = num_groups;
	r->num_aliases = num_aliases;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo3(struct samr_DomInfo3 *r,
			NTTIME force_logoff_time)
{
	r->force_logoff_time = force_logoff_time;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo4(struct samr_DomInfo4 *r,
			const char *comment)
{
	init_lsa_String(&r->comment, comment);
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo5(struct samr_DomInfo5 *r,
			const char *domain_name)
{
	init_lsa_String(&r->domain_name, domain_name);
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo6(struct samr_DomInfo6 *r,
			const char *primary)
{
	init_lsa_String(&r->primary, primary);
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo7(struct samr_DomInfo7 *r,
			enum samr_Role role)
{
	r->role = role;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo8(struct samr_DomInfo8 *r,
			uint64_t sequence_num,
			NTTIME domain_create_time)
{
	r->sequence_num = sequence_num;
	r->domain_create_time = domain_create_time;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo9(struct samr_DomInfo9 *r,
			uint32_t unknown)
{
	r->unknown = unknown;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo12(struct samr_DomInfo12 *r,
			 uint64_t lockout_duration,
			 uint64_t lockout_window,
			 uint16_t lockout_threshold)
{
	r->lockout_duration = lockout_duration;
	r->lockout_window = lockout_window;
	r->lockout_threshold = lockout_threshold;
}

/*******************************************************************
 inits a samr_GroupInfoAll structure.
********************************************************************/

void init_samr_group_info1(struct samr_GroupInfoAll *r,
			   const char *name,
			   uint32_t attributes,
			   uint32_t num_members,
			   const char *description)
{
	DEBUG(5, ("init_samr_group_info1\n"));

	init_lsa_String(&r->name, name);
	r->attributes = attributes;
	r->num_members = num_members;
	init_lsa_String(&r->description, description);
}

/*******************************************************************
 inits a lsa_String structure
********************************************************************/

void init_samr_group_info2(struct lsa_String *r, const char *group_name)
{
	DEBUG(5, ("init_samr_group_info2\n"));

	init_lsa_String(r, group_name);
}

/*******************************************************************
 inits a samr_GroupInfoAttributes structure.
********************************************************************/

void init_samr_group_info3(struct samr_GroupInfoAttributes *r,
			   uint32_t attributes)
{
	DEBUG(5, ("init_samr_group_info3\n"));

	r->attributes = attributes;
}

/*******************************************************************
 inits a lsa_String structure
********************************************************************/

void init_samr_group_info4(struct lsa_String *r, const char *description)
{
	DEBUG(5, ("init_samr_group_info4\n"));

	init_lsa_String(r, description);
}

/*******************************************************************
 inits a samr_GroupInfoAll structure.
********************************************************************/

void init_samr_group_info5(struct samr_GroupInfoAll *r,
			   const char *name,
			   uint32_t attributes,
			   uint32_t num_members,
			   const char *description)
{
	DEBUG(5, ("init_samr_group_info5\n"));

	init_lsa_String(&r->name, name);
	r->attributes = attributes;
	r->num_members = num_members;
	init_lsa_String(&r->description, description);
}

/*******************************************************************
 inits a samr_AliasInfoAll structure.
********************************************************************/

void init_samr_alias_info1(struct samr_AliasInfoAll *r,
			   const char *name,
			   uint32_t num_members,
			   const char *description)
{
	DEBUG(5, ("init_samr_alias_info1\n"));

	init_lsa_String(&r->name, name);
	r->num_members = num_members;
	init_lsa_String(&r->description, description);
}

/*******************************************************************
inits a lsa_String structure.
********************************************************************/

void init_samr_alias_info3(struct lsa_String *r,
			   const char *description)
{
	DEBUG(5, ("init_samr_alias_info3\n"));

	init_lsa_String(r, description);
}

/*******************************************************************
 inits a samr_UserInfo7 structure.
********************************************************************/

void init_samr_user_info7(struct samr_UserInfo7 *r,
			  const char *account_name)
{
	DEBUG(5, ("init_samr_user_info7\n"));

	init_lsa_String(&r->account_name, account_name);
}

/*******************************************************************
 inits a samr_UserInfo9 structure.
********************************************************************/

void init_samr_user_info9(struct samr_UserInfo9 *r,
			  uint32_t primary_gid)
{
	DEBUG(5, ("init_samr_user_info9\n"));

	r->primary_gid = primary_gid;
}

/*******************************************************************
 inits a SAM_USER_INFO_16 structure.
********************************************************************/

void init_samr_user_info16(struct samr_UserInfo16 *r,
			   uint32_t acct_flags)
{
	DEBUG(5, ("init_samr_user_info16\n"));

	r->acct_flags = acct_flags;
}

/*******************************************************************
 inits a samr_UserInfo18 structure.
********************************************************************/

void init_samr_user_info18(struct samr_UserInfo18 *r,
			   const uint8 lm_pwd[16],
			   const uint8 nt_pwd[16])
{
	DEBUG(5, ("init_samr_user_info18\n"));

	r->lm_pwd_active =
		memcpy(r->lm_pwd.hash, lm_pwd, sizeof(r->lm_pwd.hash)) ? true : false;
	r->nt_pwd_active =
		memcpy(r->nt_pwd.hash, nt_pwd, sizeof(r->nt_pwd.hash)) ? true : false;
}

/*******************************************************************
 inits a samr_UserInfo20 structure.
********************************************************************/

void init_samr_user_info20(struct samr_UserInfo20 *r,
			   struct lsa_BinaryString *parameters)
{
	r->parameters = *parameters;
}

/*************************************************************************
 inits a samr_UserInfo21 structure
 *************************************************************************/

void init_samr_user_info21(struct samr_UserInfo21 *r,
			   NTTIME last_logon,
			   NTTIME last_logoff,
			   NTTIME last_password_change,
			   NTTIME acct_expiry,
			   NTTIME allow_password_change,
			   NTTIME force_password_change,
			   const char *account_name,
			   const char *full_name,
			   const char *home_directory,
			   const char *home_drive,
			   const char *logon_script,
			   const char *profile_path,
			   const char *description,
			   const char *workstations,
			   const char *comment,
			   struct lsa_BinaryString *parameters,
			   uint32_t rid,
			   uint32_t primary_gid,
			   uint32_t acct_flags,
			   uint32_t fields_present,
			   struct samr_LogonHours logon_hours,
			   uint16_t bad_password_count,
			   uint16_t logon_count,
			   uint16_t country_code,
			   uint16_t code_page,
			   uint8_t nt_password_set,
			   uint8_t lm_password_set,
			   uint8_t password_expired)
{
	r->last_logon = last_logon;
	r->last_logoff = last_logoff;
	r->last_password_change = last_password_change;
	r->acct_expiry = acct_expiry;
	r->allow_password_change = allow_password_change;
	r->force_password_change = force_password_change;
	init_lsa_String(&r->account_name, account_name);
	init_lsa_String(&r->full_name, full_name);
	init_lsa_String(&r->home_directory, home_directory);
	init_lsa_String(&r->home_drive, home_drive);
	init_lsa_String(&r->logon_script, logon_script);
	init_lsa_String(&r->profile_path, profile_path);
	init_lsa_String(&r->description, description);
	init_lsa_String(&r->workstations, workstations);
	init_lsa_String(&r->comment, comment);
	r->parameters = *parameters;
	r->rid = rid;
	r->primary_gid = primary_gid;
	r->acct_flags = acct_flags;
	r->fields_present = fields_present;
	r->logon_hours = logon_hours;
	r->bad_password_count = bad_password_count;
	r->logon_count = logon_count;
	r->country_code = country_code;
	r->code_page = code_page;
	r->nt_password_set = nt_password_set;
	r->lm_password_set = lm_password_set;
	r->password_expired = password_expired;
}

/*************************************************************************
 init_samr_user_info23
 *************************************************************************/

void init_samr_user_info23(struct samr_UserInfo23 *r,
			   NTTIME last_logon,
			   NTTIME last_logoff,
			   NTTIME last_password_change,
			   NTTIME acct_expiry,
			   NTTIME allow_password_change,
			   NTTIME force_password_change,
			   const char *account_name,
			   const char *full_name,
			   const char *home_directory,
			   const char *home_drive,
			   const char *logon_script,
			   const char *profile_path,
			   const char *description,
			   const char *workstations,
			   const char *comment,
			   struct lsa_BinaryString *parameters,
			   uint32_t rid,
			   uint32_t primary_gid,
			   uint32_t acct_flags,
			   uint32_t fields_present,
			   struct samr_LogonHours logon_hours,
			   uint16_t bad_password_count,
			   uint16_t logon_count,
			   uint16_t country_code,
			   uint16_t code_page,
			   uint8_t nt_password_set,
			   uint8_t lm_password_set,
			   uint8_t password_expired,
			   uint8_t data[516],
			   uint8_t pw_len)
{
	memset(r, '\0', sizeof(*r));
	init_samr_user_info21(&r->info,
			      last_logon,
			      last_logoff,
			      last_password_change,
			      acct_expiry,
			      allow_password_change,
			      force_password_change,
			      account_name,
			      full_name,
			      home_directory,
			      home_drive,
			      logon_script,
			      profile_path,
			      description,
			      workstations,
			      comment,
			      parameters,
			      rid,
			      primary_gid,
			      acct_flags,
			      fields_present,
			      logon_hours,
			      bad_password_count,
			      logon_count,
			      country_code,
			      code_page,
			      nt_password_set,
			      lm_password_set,
			      password_expired);

	memcpy(r->password.data, data, sizeof(r->password.data));
}

/*************************************************************************
 init_samr_user_info24
 *************************************************************************/

void init_samr_user_info24(struct samr_UserInfo24 *r,
			   uint8_t data[516],
			   uint8_t pw_len)
{
	DEBUG(10, ("init_samr_user_info24:\n"));

	memcpy(r->password.data, data, sizeof(r->password.data));
	r->pw_len = pw_len;
}
