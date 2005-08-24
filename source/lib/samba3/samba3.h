/* 
   Unix SMB/CIFS implementation.
   Samba3 interfaces
   Copyright (C) Jelmer Vernooij			2005.
   
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

#ifndef _SAMBA3_H /* _SAMBA3_H */
#define _SAMBA3_H 

#include "librpc/gen_ndr/security.h"

struct samba3_samaccount {
	uint32_t logon_time,
		logoff_time,
		kickoff_time,
		bad_password_time,
		pass_last_set_time,
		pass_can_change_time,
		pass_must_change_time;
	char *username;
	char *domain;
	char *nt_username;
	char *dir_drive;
	char *unknown_str;
	char *munged_dial;
	char *fullname;
	char *homedir;
	char *logon_script;
	char *profile_path;
	char *acct_desc;
	char *workstations;
	uint32_t user_rid, group_rid, hours_len, unknown_6;
	uint16_t acct_ctrl, logon_divs;
	uint16_t bad_password_count, logon_count;
	uint8_t	*lm_pw_ptr, *nt_pw_ptr;
	uint8_t *nt_pw_hist_ptr;
	uint8_t	*hours;
};

/* SID Types */
enum SID_NAME_USE
{
	SID_NAME_USE_NONE = 0,
	SID_NAME_USER    = 1, /* user */
	SID_NAME_DOM_GRP,     /* domain group */
	SID_NAME_DOMAIN,      /* domain sid */
	SID_NAME_ALIAS,       /* local group */
	SID_NAME_WKN_GRP,     /* well-known group */
	SID_NAME_DELETED,     /* deleted account: needed for c2 rating */
	SID_NAME_INVALID,     /* invalid account */
	SID_NAME_UNKNOWN,     /* unknown sid type */
	SID_NAME_COMPUTER     /* sid for a computer */
};

struct samba3_groupmapping {
	struct pdb_methods *methods;
	gid_t gid;
	struct dom_sid *sid;
	enum SID_NAME_USE sid_name_use;
	const char *nt_name;
	const char *comment;
};

struct samba3_alias {
	struct dom_sid *sid;
	uint32_t member_count;
	struct dom_sid **members;
};

struct samba3_groupdb {
	uint32_t groupmap_count;
	struct samba3_groupmapping *groupmappings;

	uint32_t alias_count;
	struct samba3_alias *aliases;
};

struct samba3_idmap_mapping
{
	enum { IDMAP_GROUP, IDMAP_USER } type;
	uint32_t unix_id;
	struct dom_sid *sid;
};

struct samba3_idmapdb
{
	/* High water marks */
	uint32_t user_hwm;
	uint32_t group_hwm;

	uint32_t mapping_count;
	struct samba3_idmap_mapping *mappings;
};

struct samba3_winsdb_entry 
{
	char *name;
	int nb_flags;
	int type;
	time_t ttl;
	uint32_t ip_count;
	struct ipv4_addr *ips;
};

struct samba3_policy
{
	uint32_t min_password_length;
	uint32_t password_history;
	uint32_t user_must_logon_to_change_password;
	uint32_t maximum_password_age;
	uint32_t minimum_password_age;
	uint32_t lockout_duration;
	uint32_t reset_count_minutes;
	uint32_t bad_lockout_minutes;
	uint32_t disconnect_time;
	uint32_t refuse_machine_password_change;
};

struct samba3 
{
	uint32_t winsdb_count;
	struct samba3_winsdb_entry *winsdb_entries;
	
	uint32_t samaccount_count;
	struct samba3_samaccount *samaccounts;

	struct samba3_groupdb group;
	struct samba3_idmapdb idmap;
	struct samba3_policy policy;
};

#endif /* _SAMBA3_H */
