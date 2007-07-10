/* 
   Unix SMB/CIFS implementation.
   Samba3 interfaces
   Copyright (C) Jelmer Vernooij			2005.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SAMBA3_H /* _SAMBA3_H */
#define _SAMBA3_H 

#include "librpc/gen_ndr/security.h"
#include "librpc/gen_ndr/samr.h"
#include "param/param.h"

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
	struct samr_Password lm_pw, nt_pw;
	uint8_t *nt_pw_hist_ptr;
	uint8_t	*hours;
};

struct samba3_groupmapping {
	gid_t gid;
	struct dom_sid *sid;
	int sid_name_use;
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

struct samba3_regval {
	char *name;
	uint16_t		type;
	DATA_BLOB 		data;
};

struct samba3_regkey {
	char *name;
	
	uint32_t value_count;
	struct samba3_regval *values;

	uint32_t subkey_count;
	char **subkeys;
};

struct samba3_regdb
{
	uint32_t key_count;
	struct samba3_regkey *keys;
};

struct samba3_secrets
{
	struct cli_credentials *ipc_cred;
	
	uint32_t ldappw_count;
	struct samba3_ldappw 
	{
		char *dn;
		char *password;
	} *ldappws;

	uint32_t domain_count;
	struct samba3_domainsecrets 
	{
		char *name;
		struct dom_sid sid;
		struct GUID guid;
		char *plaintext_pw;
		time_t last_change_time;
		struct {
			uint8_t hash[16];
			time_t mod_time;
		} hash_pw;
		int sec_channel_type;
	} *domains;

	uint32_t trusted_domain_count;
	struct samba3_trusted_dom_pass {
		uint32_t uni_name_len;
		const char *uni_name[32]; /* unicode domain name */
		const char *pass;		/* trust relationship's password */
		time_t mod_time;
		struct dom_sid domain_sid;	/* remote domain's sid */
	} *trusted_domains;

	uint32_t afs_keyfile_count;

	struct samba3_afs_keyfile {
		uint32_t nkeys;
		struct {
			uint32_t kvno;
			char key[8];
		} entry[8];
		char *cell;
	} *afs_keyfiles;
};

struct samba3_share_info {
	char *name;
	struct security_descriptor secdesc;
};

struct samba3 
{
	struct param_context *configuration;

	uint32_t winsdb_count;
	struct samba3_winsdb_entry *winsdb_entries;
	
	uint32_t samaccount_count;
	struct samba3_samaccount *samaccounts;

	uint32_t share_count;
	struct samba3_share_info *shares;

	struct samba3_secrets secrets;
	struct samba3_groupdb group;
	struct samba3_idmapdb idmap;
	struct samba3_policy policy;
	struct samba3_regdb registry;
};

#include "lib/samba3/samba3_proto.h"
#include "lib/samba3/samba3_smbpasswd_proto.h"

#endif /* _SAMBA3_H */
