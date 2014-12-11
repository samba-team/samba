/* 
   Unix SMB/CIFS implementation.
   passdb structures and parameters
   Copyright (C) Gerald Carter 2001
   Copyright (C) Luke Kenneth Casson Leighton 1998 - 2000
   Copyright (C) Andrew Bartlett 2002
   Copyright (C) Simo Sorce 2003

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

#ifndef _PASSDB_H
#define _PASSDB_H

#ifndef NT_HASH_LEN
#define NT_HASH_LEN 16
#endif

#ifndef LM_HASH_LEN
#define LM_HASH_LEN 16
#endif

#include "../librpc/gen_ndr/lsa.h"
#include <tevent.h>
struct unixid;
struct cli_credentials;

/* group mapping headers */

#define ENUM_ONLY_MAPPED True
#define ENUM_ALL_MAPPED False

typedef struct _GROUP_MAP {
	struct pdb_methods *methods;
	gid_t gid;
	struct dom_sid sid;
	enum lsa_SidType sid_name_use;
	char *nt_name;
	char *comment;
} GROUP_MAP;

struct acct_info {
	char *acct_name; /* account name */
	char *acct_desc; /* account name */
	uint32_t rid; /* domain-relative RID */
};

/* The following definitions come from groupdb/mapping.c  */

NTSTATUS add_initial_entry(gid_t gid, const char *sid, enum lsa_SidType sid_name_use, const char *nt_name, const char *comment);
bool get_domain_group_from_sid(struct dom_sid sid, GROUP_MAP *map);
int smb_create_group(const char *unix_group, gid_t *new_gid);
int smb_delete_group(const char *unix_group);
int smb_set_primary_group(const char *unix_group, const char* unix_user);
int smb_add_user_group(const char *unix_group, const char *unix_user);
int smb_delete_user_group(const char *unix_group, const char *unix_user);
NTSTATUS pdb_default_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 struct dom_sid sid);
NTSTATUS pdb_default_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid);
NTSTATUS pdb_default_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 const char *name);
NTSTATUS pdb_default_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map);
NTSTATUS pdb_default_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map);
NTSTATUS pdb_default_delete_group_mapping_entry(struct pdb_methods *methods,
						   struct dom_sid sid);
NTSTATUS pdb_default_enum_group_mapping(struct pdb_methods *methods,
					const struct dom_sid *sid,
					enum lsa_SidType sid_name_use,
					GROUP_MAP ***pp_rmap,
					size_t *p_num_entries,
					bool unix_only);
NTSTATUS pdb_default_create_alias(struct pdb_methods *methods,
				  const char *name, uint32_t *rid);
NTSTATUS pdb_default_delete_alias(struct pdb_methods *methods,
				  const struct dom_sid *sid);
NTSTATUS pdb_default_get_aliasinfo(struct pdb_methods *methods,
				   const struct dom_sid *sid,
				   struct acct_info *info);
NTSTATUS pdb_default_set_aliasinfo(struct pdb_methods *methods,
				   const struct dom_sid *sid,
				   struct acct_info *info);
NTSTATUS pdb_default_add_aliasmem(struct pdb_methods *methods,
				  const struct dom_sid *alias, const struct dom_sid *member);
NTSTATUS pdb_default_del_aliasmem(struct pdb_methods *methods,
				  const struct dom_sid *alias, const struct dom_sid *member);
NTSTATUS pdb_default_enum_aliasmem(struct pdb_methods *methods,
				   const struct dom_sid *alias, TALLOC_CTX *mem_ctx,
				   struct dom_sid **pp_members,
				   size_t *p_num_members);
NTSTATUS pdb_default_alias_memberships(struct pdb_methods *methods,
				       TALLOC_CTX *mem_ctx,
				       const struct dom_sid *domain_sid,
				       const struct dom_sid *members,
				       size_t num_members,
				       uint32_t **pp_alias_rids,
				       size_t *p_num_alias_rids);
NTSTATUS pdb_nop_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 struct dom_sid sid);
NTSTATUS pdb_nop_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid);
NTSTATUS pdb_nop_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 const char *name);
NTSTATUS pdb_nop_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map);
NTSTATUS pdb_nop_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map);
NTSTATUS pdb_nop_delete_group_mapping_entry(struct pdb_methods *methods,
						   struct dom_sid sid);
NTSTATUS pdb_nop_enum_group_mapping(struct pdb_methods *methods,
					   enum lsa_SidType sid_name_use,
					   GROUP_MAP **rmap, size_t *num_entries,
					   bool unix_only);
NTSTATUS pdb_create_builtin_alias(uint32_t rid, gid_t gid);


/* passdb headers */

/**********************************************************************
 * Masks for mappings between unix uid and gid types and
 * NT RIDS.
 **********************************************************************/

/* Take the bottom bit. */
#define RID_TYPE_MASK 		1
#define RID_MULTIPLIER 		2

/* The two common types. */
#define USER_RID_TYPE 		0
#define GROUP_RID_TYPE 		1

/*
 * Flags for local user manipulation.
 */

#define LOCAL_ADD_USER 0x1
#define LOCAL_DELETE_USER 0x2
#define LOCAL_DISABLE_USER 0x4
#define LOCAL_ENABLE_USER 0x8
#define LOCAL_TRUST_ACCOUNT 0x10
#define LOCAL_SET_NO_PASSWORD 0x20
#define LOCAL_SET_PASSWORD 0x40
#define LOCAL_SET_LDAP_ADMIN_PW 0x80
#define LOCAL_INTERDOM_ACCOUNT 0x100
#define LOCAL_AM_ROOT 0x200  /* Act as root */

/*
 * Size of new password account encoding string.  This is enough space to
 * hold 11 ACB characters, plus the surrounding [] and a terminating null.
 * Do not change unless you are adding new ACB bits!
 */

#define NEW_PW_FORMAT_SPACE_PADDED_LEN 14

/* Password history contants. */
#define PW_HISTORY_SALT_LEN 16
#define SALTED_MD5_HASH_LEN 16
#define PW_HISTORY_ENTRY_LEN (PW_HISTORY_SALT_LEN+SALTED_MD5_HASH_LEN)
#define MAX_PW_HISTORY_LEN 24

/*
 * bit flags representing initialized fields in struct samu
 */
enum pdb_elements {
	PDB_UNINIT,
	PDB_SMBHOME,
	PDB_PROFILE,
	PDB_DRIVE,
	PDB_LOGONSCRIPT,
	PDB_LOGONTIME,
	PDB_LOGOFFTIME,
	PDB_KICKOFFTIME,
	PDB_BAD_PASSWORD_TIME,
	PDB_CANCHANGETIME,
	PDB_PLAINTEXT_PW,
	PDB_USERNAME,
	PDB_FULLNAME,
	PDB_DOMAIN,
	PDB_NTUSERNAME,
	PDB_HOURSLEN,
	PDB_LOGONDIVS,
	PDB_USERSID,
	PDB_GROUPSID,
	PDB_ACCTCTRL,
	PDB_PASSLASTSET,
	PDB_ACCTDESC,
	PDB_WORKSTATIONS,
	PDB_COMMENT,
	PDB_MUNGEDDIAL,
	PDB_HOURS,
	PDB_FIELDS_PRESENT,
	PDB_BAD_PASSWORD_COUNT,
	PDB_LOGON_COUNT,
	PDB_COUNTRY_CODE,
	PDB_CODE_PAGE,
	PDB_UNKNOWN6,
	PDB_LMPASSWD,
	PDB_NTPASSWD,
	PDB_PWHISTORY,
	PDB_BACKEND_PRIVATE_DATA,

	/* this must be the last element */
	PDB_COUNT
};

enum pdb_group_elements {
	PDB_GROUP_NAME,
	PDB_GROUP_SID,
	PDB_GROUP_SID_NAME_USE,
	PDB_GROUP_MEMBERS,

	/* this must be the last element */
	PDB_GROUP_COUNT
};


enum pdb_value_state {
	PDB_DEFAULT=0,
	PDB_SET,
	PDB_CHANGED
};

#define IS_SAM_SET(x, flag)	(pdb_get_init_flags(x, flag) == PDB_SET)
#define IS_SAM_CHANGED(x, flag)	(pdb_get_init_flags(x, flag) == PDB_CHANGED)
#define IS_SAM_DEFAULT(x, flag)	(pdb_get_init_flags(x, flag) == PDB_DEFAULT)

/* cache for bad password lockout data, to be used on replicated SAMs */
struct login_cache {
	time_t entry_timestamp;
	uint32_t acct_ctrl;
	uint16_t bad_password_count;
	time_t bad_password_time;
};

#define SAMU_BUFFER_V0		0
#define SAMU_BUFFER_V1		1
#define SAMU_BUFFER_V2		2
#define SAMU_BUFFER_V3		3
/* nothing changed from V3 to V4 */
#define SAMU_BUFFER_V4		4
#define SAMU_BUFFER_LATEST	SAMU_BUFFER_V4

#define MAX_HOURS_LEN 32

struct samu {
	struct pdb_methods *methods;

	/* initialization flags */
	struct bitmap *change_flags;
	struct bitmap *set_flags;

	time_t logon_time;            /* logon time */
	time_t logoff_time;           /* logoff time */
	time_t kickoff_time;          /* kickoff time */
	time_t bad_password_time;     /* last bad password entered */
	time_t pass_last_set_time;    /* password last set time */
	time_t pass_can_change_time;  /* password can change time */

	const char *username;     /* UNIX username string */
	const char *domain;       /* Windows Domain name */
	const char *nt_username;  /* Windows username string */
	const char *full_name;    /* user's full name string */
	const char *home_dir;     /* home directory string */
	const char *dir_drive;    /* home directory drive string */
	const char *logon_script; /* logon script string */
	const char *profile_path; /* profile path string */
	const char *acct_desc;    /* user description string */
	const char *workstations; /* login from workstations string */
	const char *comment;
	const char *munged_dial;  /* munged path name and dial-back tel number */

	struct dom_sid user_sid;
	struct dom_sid *group_sid;

	DATA_BLOB lm_pw; /* .data is Null if no password */
	DATA_BLOB nt_pw; /* .data is Null if no password */
	DATA_BLOB nt_pw_his; /* nt hashed password history .data is Null if not available */
	char* plaintext_pw; /* is Null if not available */

	uint32_t acct_ctrl; /* account info (ACB_xxxx bit-mask) */
	uint32_t fields_present; /* 0x00ff ffff */

	uint16_t logon_divs; /* 168 - number of hours in a week */
	uint32_t hours_len; /* normally 21 bytes */
	uint8_t hours[MAX_HOURS_LEN];

	/* Was unknown_5. */
	uint16_t bad_password_count;
	uint16_t logon_count;

	uint16_t country_code;
	uint16_t code_page;

	uint32_t unknown_6; /* 0x0000 04ec */

	/* a tag for who added the private methods */

	const struct pdb_methods *backend_private_methods;
	void *backend_private_data; 
	void (*backend_private_data_free_fn)(void **);

	/* maintain a copy of the user's struct passwd */

	struct passwd *unix_pw;
};

struct samr_displayentry {
	uint32_t idx;
	uint32_t rid;
	uint32_t acct_flags;
	const char *account_name;
	const char *fullname;
	const char *description;
};

enum pdb_search_type {
	PDB_USER_SEARCH,
	PDB_GROUP_SEARCH,
	PDB_ALIAS_SEARCH
};

struct pdb_search {
	enum pdb_search_type type;
	struct samr_displayentry *cache;
	uint32_t num_entries;
	ssize_t cache_size;
	bool search_ended;
	void *private_data;
	bool (*next_entry)(struct pdb_search *search,
			   struct samr_displayentry *entry);
	void (*search_end)(struct pdb_search *search);
};

struct pdb_domain_info {
	char *name;
	char *dns_domain;
	char *dns_forest;
	struct dom_sid sid;
	struct GUID guid;
};

struct pdb_trusted_domain {
	char *domain_name;
	char *netbios_name;
	struct dom_sid security_identifier;
	DATA_BLOB trust_auth_incoming;
	DATA_BLOB trust_auth_outgoing;
	uint32_t trust_direction;
	uint32_t trust_type;
	uint32_t trust_attributes;
	uint32_t *trust_posix_offset;
	uint32_t *supported_enc_type;
	DATA_BLOB trust_forest_trust_info;
};

/*
 * trusted domain entry/entries returned by secrets_get_trusted_domains
 * (used in _lsa_enum_trust_dom call)
 */
struct trustdom_info {
	char *name;
	struct dom_sid sid;
};

/*
 * Types of account policy.
 */
enum pdb_policy_type {
	PDB_POLICY_MIN_PASSWORD_LEN = 1,
	PDB_POLICY_PASSWORD_HISTORY = 2,
	PDB_POLICY_USER_MUST_LOGON_TO_CHG_PASS	= 3,
	PDB_POLICY_MAX_PASSWORD_AGE = 4,
	PDB_POLICY_MIN_PASSWORD_AGE = 5,
	PDB_POLICY_LOCK_ACCOUNT_DURATION = 6,
	PDB_POLICY_RESET_COUNT_TIME = 7,
	PDB_POLICY_BAD_ATTEMPT_LOCKOUT = 8,
	PDB_POLICY_TIME_TO_LOGOUT = 9,
	PDB_POLICY_REFUSE_MACHINE_PW_CHANGE = 10
};

#define PDB_CAP_STORE_RIDS		0x0001
#define PDB_CAP_ADS			0x0002
#define PDB_CAP_TRUSTED_DOMAINS_EX	0x0004

/*****************************************************************
 Functions to be implemented by the new (v2) passdb API 
****************************************************************/

/*
 * This next constant specifies the version number of the PASSDB interface
 * this SAMBA will load. Increment this if *ANY* changes are made to the interface. 
 * Changed interface to fix int -> size_t problems. JRA.
 * There's no point in allocating arrays in
 * samr_lookup_rids twice. It was done in the srv_samr_nt.c code as well as in
 * the pdb module. Remove the latter, this might happen more often. VL.
 * changed to version 14 to move lookup_rids and lookup_names to return
 * enum lsa_SidType rather than uint32_t.
 * Changed to 16 for access to the trusted domain passwords (obnox).
 * Changed to 17, the sampwent interface is gone.
 * Changed to 18, pdb_rid_algorithm -> pdb_capabilities
 * Changed to 19, removed uid_to_rid
 * Changed to 20, pdb_secret calls
 * Changed to 21, set/enum_upn_suffixes. AB.
 * Changed to 22, idmap control functions
 * Changed to 23, new idmap control functions
 * Changed to 24, removed uid_to_sid and gid_to_sid, replaced with id_to_sid
 * Leave at 24, add optional get_trusteddom_creds()
 */

#define PASSDB_INTERFACE_VERSION 24

struct pdb_methods 
{
	const char *name; /* What name got this module */

	struct pdb_domain_info *(*get_domain_info)(struct pdb_methods *,
						   TALLOC_CTX *mem_ctx);

	NTSTATUS (*getsampwnam)(struct pdb_methods *, struct samu *sam_acct, const char *username);

	NTSTATUS (*getsampwsid)(struct pdb_methods *, struct samu *sam_acct, const struct dom_sid *sid);

	NTSTATUS (*create_user)(struct pdb_methods *, TALLOC_CTX *tmp_ctx,
				const char *name, uint32_t acct_flags,
				uint32_t *rid);

	NTSTATUS (*delete_user)(struct pdb_methods *, TALLOC_CTX *tmp_ctx,
				struct samu *sam_acct);

	NTSTATUS (*add_sam_account)(struct pdb_methods *, struct samu *sampass);

	NTSTATUS (*update_sam_account)(struct pdb_methods *, struct samu *sampass);

	NTSTATUS (*delete_sam_account)(struct pdb_methods *, struct samu *username);

	NTSTATUS (*rename_sam_account)(struct pdb_methods *, struct samu *oldname, const char *newname);

	NTSTATUS (*update_login_attempts)(struct pdb_methods *methods, struct samu *sam_acct, bool success);

	NTSTATUS (*getgrsid)(struct pdb_methods *methods, GROUP_MAP *map, struct dom_sid sid);

	NTSTATUS (*getgrgid)(struct pdb_methods *methods, GROUP_MAP *map, gid_t gid);

	NTSTATUS (*getgrnam)(struct pdb_methods *methods, GROUP_MAP *map, const char *name);

	NTSTATUS (*create_dom_group)(struct pdb_methods *methods,
				     TALLOC_CTX *mem_ctx, const char *name,
				     uint32_t *rid);

	NTSTATUS (*delete_dom_group)(struct pdb_methods *methods,
				     TALLOC_CTX *mem_ctx, uint32_t rid);

	NTSTATUS (*add_group_mapping_entry)(struct pdb_methods *methods,
					    GROUP_MAP *map);

	NTSTATUS (*update_group_mapping_entry)(struct pdb_methods *methods,
					       GROUP_MAP *map);

	NTSTATUS (*delete_group_mapping_entry)(struct pdb_methods *methods,
					       struct dom_sid sid);

	NTSTATUS (*enum_group_mapping)(struct pdb_methods *methods,
				       const struct dom_sid *sid, enum lsa_SidType sid_name_use,
				       GROUP_MAP ***pp_rmap, size_t *p_num_entries,
				       bool unix_only);

	NTSTATUS (*enum_group_members)(struct pdb_methods *methods,
				       TALLOC_CTX *mem_ctx,
				       const struct dom_sid *group,
				       uint32_t **pp_member_rids,
				       size_t *p_num_members);

	NTSTATUS (*enum_group_memberships)(struct pdb_methods *methods,
					   TALLOC_CTX *mem_ctx,
					   struct samu *user,
					   struct dom_sid **pp_sids, gid_t **pp_gids,
					   uint32_t *p_num_groups);

	NTSTATUS (*set_unix_primary_group)(struct pdb_methods *methods,
					   TALLOC_CTX *mem_ctx,
					   struct samu *user);

	NTSTATUS (*add_groupmem)(struct pdb_methods *methods,
				 TALLOC_CTX *mem_ctx,
				 uint32_t group_rid, uint32_t member_rid);

	NTSTATUS (*del_groupmem)(struct pdb_methods *methods,
				 TALLOC_CTX *mem_ctx,
				 uint32_t group_rid, uint32_t member_rid);

	NTSTATUS (*create_alias)(struct pdb_methods *methods,
				 const char *name, uint32_t *rid);

	NTSTATUS (*delete_alias)(struct pdb_methods *methods,
				 const struct dom_sid *sid);

	NTSTATUS (*get_aliasinfo)(struct pdb_methods *methods,
				  const struct dom_sid *sid,
				  struct acct_info *info);

	NTSTATUS (*set_aliasinfo)(struct pdb_methods *methods,
				  const struct dom_sid *sid,
				  struct acct_info *info);

	NTSTATUS (*add_aliasmem)(struct pdb_methods *methods,
				 const struct dom_sid *alias, const struct dom_sid *member);
	NTSTATUS (*del_aliasmem)(struct pdb_methods *methods,
				 const struct dom_sid *alias, const struct dom_sid *member);
	NTSTATUS (*enum_aliasmem)(struct pdb_methods *methods,
				  const struct dom_sid *alias, TALLOC_CTX *mem_ctx,
				  struct dom_sid **members, size_t *p_num_members);
	NTSTATUS (*enum_alias_memberships)(struct pdb_methods *methods,
					   TALLOC_CTX *mem_ctx,
					   const struct dom_sid *domain_sid,
					   const struct dom_sid *members,
					   size_t num_members,
					   uint32_t **pp_alias_rids,
					   size_t *p_num_alias_rids);

	NTSTATUS (*lookup_rids)(struct pdb_methods *methods,
				const struct dom_sid *domain_sid,
				int num_rids,
				uint32_t *rids,
				const char **pp_names,
				enum lsa_SidType *attrs);

	NTSTATUS (*lookup_names)(struct pdb_methods *methods,
				 const struct dom_sid *domain_sid,
				 int num_names,
				 const char **pp_names,
				 uint32_t *rids,
				 enum lsa_SidType *attrs);

	NTSTATUS (*get_account_policy)(struct pdb_methods *methods,
				       enum pdb_policy_type type,
				       uint32_t *value);

	NTSTATUS (*set_account_policy)(struct pdb_methods *methods,
				       enum pdb_policy_type type,
				       uint32_t value);

	NTSTATUS (*get_seq_num)(struct pdb_methods *methods, time_t *seq_num);

	bool (*search_users)(struct pdb_methods *methods,
			     struct pdb_search *search,
			     uint32_t acct_flags);
	bool (*search_groups)(struct pdb_methods *methods,
			      struct pdb_search *search);
	bool (*search_aliases)(struct pdb_methods *methods,
			       struct pdb_search *search,
			       const struct dom_sid *sid);

	/* 
	 * Instead of passing down a gid or uid, this function sends down a pointer
	 * to a unixid. 
	 *
	 * This acts as an in-out variable so that the idmap functions can correctly
	 * receive ID_TYPE_BOTH, filling in cache details correctly rather than forcing
	 * the cache to store ID_TYPE_UID or ID_TYPE_GID. 
	 */
	bool (*id_to_sid)(struct pdb_methods *methods, struct unixid *id,
			  struct dom_sid *sid);
	bool (*sid_to_id)(struct pdb_methods *methods, const struct dom_sid *sid,
			  struct unixid *id);

	uint32_t (*capabilities)(struct pdb_methods *methods);
	bool (*new_rid)(struct pdb_methods *methods, uint32_t *rid);


	bool (*get_trusteddom_pw)(struct pdb_methods *methods,
				  const char *domain, char** pwd, 
				  struct dom_sid *sid, time_t *pass_last_set_time);
	NTSTATUS (*get_trusteddom_creds)(struct pdb_methods *methods,
					 const char *domain,
					 TALLOC_CTX *mem_ctx,
					 struct cli_credentials **creds);
	bool (*set_trusteddom_pw)(struct pdb_methods *methods, 
				  const char* domain, const char* pwd,
				  const struct dom_sid *sid);
	bool (*del_trusteddom_pw)(struct pdb_methods *methods, 
				  const char *domain);
	NTSTATUS (*enum_trusteddoms)(struct pdb_methods *methods,
				     TALLOC_CTX *mem_ctx, uint32_t *num_domains,
				     struct trustdom_info ***domains);

	NTSTATUS (*get_trusted_domain)(struct pdb_methods *methods,
				       TALLOC_CTX *mem_ctx,
				       const char *domain,
				       struct pdb_trusted_domain **td);
	NTSTATUS (*get_trusted_domain_by_sid)(struct pdb_methods *methods,
					      TALLOC_CTX *mem_ctx,
					      struct dom_sid *sid,
					      struct pdb_trusted_domain **td);
	NTSTATUS (*set_trusted_domain)(struct pdb_methods *methods,
				       const char* domain,
				       const struct pdb_trusted_domain *td);
	NTSTATUS (*del_trusted_domain)(struct pdb_methods *methods,
				       const char *domain);
	NTSTATUS (*enum_trusted_domains)(struct pdb_methods *methods,
					 TALLOC_CTX *mem_ctx,
					 uint32_t *num_domains,
					 struct pdb_trusted_domain ***domains);

	NTSTATUS (*get_secret)(struct pdb_methods *methods,
			       TALLOC_CTX *mem_ctx,
			       const char *secret_name,
			       DATA_BLOB *secret_current,
			       NTTIME *secret_current_lastchange,
			       DATA_BLOB *secret_old,
			       NTTIME *secret_old_lastchange,
			       struct security_descriptor **sd);
	NTSTATUS (*set_secret)(struct pdb_methods *methods,
			       const char *secret_name,
			       DATA_BLOB *secret_current,
			       DATA_BLOB *secret_old,
			       struct security_descriptor *sd);
	NTSTATUS (*delete_secret)(struct pdb_methods *methods,
				  const char *secret_name);

	NTSTATUS (*enum_upn_suffixes)(struct pdb_methods *methods,
				      TALLOC_CTX *mem_ctx,
				      uint32_t *num_suffixes,
				      char ***suffixes);

	NTSTATUS (*set_upn_suffixes)(struct pdb_methods *methods,
				     uint32_t num_suffixes,
				     const char **suffixes);

	bool (*is_responsible_for_our_sam)(struct pdb_methods *methods);
	bool (*is_responsible_for_builtin)(struct pdb_methods *methods);
	bool (*is_responsible_for_wellknown)(struct pdb_methods *methods);
	bool (*is_responsible_for_unix_users)(struct pdb_methods *methods);
	bool (*is_responsible_for_unix_groups)(struct pdb_methods *methods);
	bool (*is_responsible_for_everything_else)(struct pdb_methods *methods);

	void *private_data;  /* Private data of some kind */

	void (*free_private_data)(void **);
};

typedef NTSTATUS (*pdb_init_function)(struct pdb_methods **, const char *);

struct pdb_init_function_entry {
	const char *name;

	/* Function to create a member of the pdb_methods list */
	pdb_init_function init;

	struct pdb_init_function_entry *prev, *next;
};

/* The following definitions come from passdb/account_pol.c  */

void account_policy_names_list(TALLOC_CTX *mem_ctx, const char ***names, int *num_names);
const char *decode_account_policy_name(enum pdb_policy_type type);
const char *get_account_policy_attr(enum pdb_policy_type type);
const char *account_policy_get_desc(enum pdb_policy_type type);
enum pdb_policy_type account_policy_name_to_typenum(const char *name);
bool account_policy_get_default(enum pdb_policy_type type, uint32_t *val);
bool init_account_policy(void);
bool account_policy_get(enum pdb_policy_type type, uint32_t *value);
bool account_policy_set(enum pdb_policy_type type, uint32_t value);
bool cache_account_policy_set(enum pdb_policy_type type, uint32_t value);
bool cache_account_policy_get(enum pdb_policy_type type, uint32_t *value);
struct db_context *get_account_pol_db( void );

/* The following definitions come from passdb/login_cache.c  */

bool login_cache_init(void);
bool login_cache_shutdown(void);
bool login_cache_read(struct samu *sampass, struct login_cache *entry);
bool login_cache_write(const struct samu *sampass,
		       const struct login_cache *entry);
bool login_cache_delentry(const struct samu *sampass);

/* The following definitions come from passdb/passdb.c  */

const char *my_sam_name(void);
struct samu *samu_new( TALLOC_CTX *ctx );
NTSTATUS samu_set_unix(struct samu *user, const struct passwd *pwd);
NTSTATUS samu_alloc_rid_unix(struct pdb_methods *methods,
			     struct samu *user, const struct passwd *pwd);
char *pdb_encode_acct_ctrl(uint32_t acct_ctrl, size_t length);
uint32_t pdb_decode_acct_ctrl(const char *p);
void pdb_sethexpwd(char p[33], const unsigned char *pwd, uint32_t acct_ctrl);
bool pdb_gethexpwd(const char *p, unsigned char *pwd);
void pdb_sethexhours(char *p, const unsigned char *hours);
bool pdb_gethexhours(const char *p, unsigned char *hours);
int algorithmic_rid_base(void);
uid_t algorithmic_pdb_user_rid_to_uid(uint32_t user_rid);
uid_t max_algorithmic_uid(void);
uint32_t algorithmic_pdb_uid_to_user_rid(uid_t uid);
gid_t pdb_group_rid_to_gid(uint32_t group_rid);
gid_t max_algorithmic_gid(void);
uint32_t algorithmic_pdb_gid_to_group_rid(gid_t gid);
bool algorithmic_pdb_rid_is_user(uint32_t rid);
bool lookup_global_sam_name(const char *name, int flags, uint32_t *rid,
			    enum lsa_SidType *type);
NTSTATUS local_password_change(const char *user_name,
				int local_flags,
				const char *new_passwd,
				char **pp_err_str,
				char **pp_msg_str);
bool init_samu_from_buffer(struct samu *sampass, uint32_t level,
			   uint8_t *buf, uint32_t buflen);
uint32_t init_buffer_from_samu (uint8_t **buf, struct samu *sampass, bool size_only);
bool pdb_copy_sam_account(struct samu *dst, struct samu *src );
bool pdb_update_bad_password_count(struct samu *sampass, bool *updated);
bool pdb_update_autolock_flag(struct samu *sampass, bool *updated);
bool pdb_increment_bad_password_count(struct samu *sampass);
bool is_dc_trusted_domain_situation(const char *domain_name);
bool get_trust_pw_clear(const char *domain, char **ret_pwd,
			const char **account_name,
			enum netr_SchannelType *channel);
bool get_trust_pw_hash(const char *domain, uint8_t ret_pwd[16],
		       const char **account_name,
		       enum netr_SchannelType *channel);
struct cli_credentials;
NTSTATUS pdb_get_trust_credentials(const char *netbios_domain,
				   const char *dns_domain, /* optional */
				   TALLOC_CTX *mem_ctx,
				   struct cli_credentials **_creds);

/* The following definitions come from passdb/pdb_compat.c  */

uint32_t pdb_get_user_rid (const struct samu *sampass);
uint32_t pdb_get_group_rid (struct samu *sampass);
bool pdb_set_user_sid_from_rid (struct samu *sampass, uint32_t rid, enum pdb_value_state flag);
bool pdb_set_group_sid_from_rid (struct samu *sampass, uint32_t grid, enum pdb_value_state flag);

/* The following definitions come from passdb/pdb_get_set.c  */

bool pdb_is_password_change_time_max(time_t test_time);
uint32_t pdb_get_acct_ctrl(const struct samu *sampass);
time_t pdb_get_logon_time(const struct samu *sampass);
time_t pdb_get_logoff_time(const struct samu *sampass);
time_t pdb_get_kickoff_time(const struct samu *sampass);
time_t pdb_get_bad_password_time(const struct samu *sampass);
time_t pdb_get_pass_last_set_time(const struct samu *sampass);
time_t pdb_get_pass_can_change_time(const struct samu *sampass);
time_t pdb_get_pass_can_change_time_noncalc(const struct samu *sampass);
time_t pdb_get_pass_must_change_time(const struct samu *sampass);
bool pdb_get_pass_can_change(const struct samu *sampass);
uint16_t pdb_get_logon_divs(const struct samu *sampass);
uint32_t pdb_get_hours_len(const struct samu *sampass);
const uint8_t *pdb_get_hours(const struct samu *sampass);
const uint8_t *pdb_get_nt_passwd(const struct samu *sampass);
const uint8_t *pdb_get_lanman_passwd(const struct samu *sampass);
const uint8_t *pdb_get_pw_history(const struct samu *sampass, uint32_t *current_hist_len);
const char *pdb_get_plaintext_passwd(const struct samu *sampass);
const struct dom_sid *pdb_get_user_sid(const struct samu *sampass);
const struct dom_sid *pdb_get_group_sid(struct samu *sampass);
enum pdb_value_state pdb_get_init_flags(const struct samu *sampass, enum pdb_elements element);
const char *pdb_get_username(const struct samu *sampass);
const char *pdb_get_domain(const struct samu *sampass);
const char *pdb_get_nt_username(const struct samu *sampass);
const char *pdb_get_fullname(const struct samu *sampass);
const char *pdb_get_homedir(const struct samu *sampass);
const char *pdb_get_dir_drive(const struct samu *sampass);
const char *pdb_get_logon_script(const struct samu *sampass);
const char *pdb_get_profile_path(const struct samu *sampass);
const char *pdb_get_acct_desc(const struct samu *sampass);
const char *pdb_get_workstations(const struct samu *sampass);
const char *pdb_get_comment(const struct samu *sampass);
const char *pdb_get_munged_dial(const struct samu *sampass);
uint16_t pdb_get_bad_password_count(const struct samu *sampass);
uint16_t pdb_get_logon_count(const struct samu *sampass);
uint16_t pdb_get_country_code(const struct samu *sampass);
uint16_t pdb_get_code_page(const struct samu *sampass);
uint32_t pdb_get_unknown_6(const struct samu *sampass);
void *pdb_get_backend_private_data(const struct samu *sampass, const struct pdb_methods *my_methods);
bool pdb_set_acct_ctrl(struct samu *sampass, uint32_t acct_ctrl, enum pdb_value_state flag);
bool pdb_set_logon_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_logoff_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_kickoff_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_bad_password_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_pass_can_change_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_pass_last_set_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_hours_len(struct samu *sampass, uint32_t len, enum pdb_value_state flag);
bool pdb_set_logon_divs(struct samu *sampass, uint16_t hours, enum pdb_value_state flag);
bool pdb_set_init_flags(struct samu *sampass, enum pdb_elements element, enum pdb_value_state value_flag);
bool pdb_set_user_sid(struct samu *sampass, const struct dom_sid *u_sid, enum pdb_value_state flag);
bool pdb_set_user_sid_from_string(struct samu *sampass, const char *u_sid, enum pdb_value_state flag);
bool pdb_set_group_sid(struct samu *sampass, const struct dom_sid *g_sid, enum pdb_value_state flag);
bool pdb_set_username(struct samu *sampass, const char *username, enum pdb_value_state flag);
bool pdb_set_domain(struct samu *sampass, const char *domain, enum pdb_value_state flag);
bool pdb_set_nt_username(struct samu *sampass, const char *nt_username, enum pdb_value_state flag);
bool pdb_set_fullname(struct samu *sampass, const char *full_name, enum pdb_value_state flag);
bool pdb_set_logon_script(struct samu *sampass, const char *logon_script, enum pdb_value_state flag);
bool pdb_set_profile_path(struct samu *sampass, const char *profile_path, enum pdb_value_state flag);
bool pdb_set_dir_drive(struct samu *sampass, const char *dir_drive, enum pdb_value_state flag);
bool pdb_set_homedir(struct samu *sampass, const char *home_dir, enum pdb_value_state flag);
bool pdb_set_acct_desc(struct samu *sampass, const char *acct_desc, enum pdb_value_state flag);
bool pdb_set_workstations(struct samu *sampass, const char *workstations, enum pdb_value_state flag);
bool pdb_set_comment(struct samu *sampass, const char *comment, enum pdb_value_state flag);
bool pdb_set_munged_dial(struct samu *sampass, const char *munged_dial, enum pdb_value_state flag);
bool pdb_set_nt_passwd(struct samu *sampass, const uint8_t pwd[NT_HASH_LEN], enum pdb_value_state flag);
bool pdb_set_lanman_passwd(struct samu *sampass, const uint8_t pwd[LM_HASH_LEN], enum pdb_value_state flag);
bool pdb_set_pw_history(struct samu *sampass, const uint8_t *pwd, uint32_t historyLen, enum pdb_value_state flag);
bool pdb_set_plaintext_pw_only(struct samu *sampass, const char *password, enum pdb_value_state flag);
bool pdb_set_bad_password_count(struct samu *sampass, uint16_t bad_password_count, enum pdb_value_state flag);
bool pdb_set_logon_count(struct samu *sampass, uint16_t logon_count, enum pdb_value_state flag);
bool pdb_set_country_code(struct samu *sampass, uint16_t country_code,
			  enum pdb_value_state flag);
bool pdb_set_code_page(struct samu *sampass, uint16_t code_page,
		       enum pdb_value_state flag);
bool pdb_set_unknown_6(struct samu *sampass, uint32_t unkn, enum pdb_value_state flag);
bool pdb_set_hours(struct samu *sampass, const uint8_t *hours, int hours_len,
		   enum pdb_value_state flag);
bool pdb_set_backend_private_data(struct samu *sampass, void *private_data,
				   void (*free_fn)(void **),
				   const struct pdb_methods *my_methods,
				   enum pdb_value_state flag);
bool pdb_set_pass_can_change(struct samu *sampass, bool canchange);
bool pdb_set_plaintext_passwd(struct samu *sampass, const char *plaintext);
uint32_t pdb_build_fields_present(struct samu *sampass);
bool pdb_element_is_changed(const struct samu *sampass,
			    enum pdb_elements element);
bool pdb_element_is_set_or_changed(const struct samu *sampass,
				   enum pdb_elements element);

/* The following definitions come from passdb/pdb_interface.c  */

NTSTATUS smb_register_passdb(int version, const char *name, pdb_init_function init) ;
struct pdb_init_function_entry *pdb_find_backend_entry(const char *name);
const struct pdb_init_function_entry *pdb_get_backends(void);
struct tevent_context *pdb_get_tevent_context(void);
NTSTATUS make_pdb_method_name(struct pdb_methods **methods, const char *selected);
struct pdb_domain_info *pdb_get_domain_info(TALLOC_CTX *mem_ctx);
bool pdb_getsampwnam(struct samu *sam_acct, const char *username) ;
bool pdb_getsampwsid(struct samu *sam_acct, const struct dom_sid *sid) ;
NTSTATUS pdb_create_user(TALLOC_CTX *mem_ctx, const char *name, uint32_t flags,
			 uint32_t *rid);
NTSTATUS pdb_delete_user(TALLOC_CTX *mem_ctx, struct samu *sam_acct);
NTSTATUS pdb_add_sam_account(struct samu *sam_acct) ;
NTSTATUS pdb_update_sam_account(struct samu *sam_acct) ;
NTSTATUS pdb_delete_sam_account(struct samu *sam_acct) ;
NTSTATUS pdb_rename_sam_account(struct samu *oldname, const char *newname);
NTSTATUS pdb_update_login_attempts(struct samu *sam_acct, bool success);
bool pdb_getgrsid(GROUP_MAP *map, struct dom_sid sid);
bool pdb_getgrgid(GROUP_MAP *map, gid_t gid);
bool pdb_getgrnam(GROUP_MAP *map, const char *name);
NTSTATUS pdb_create_dom_group(TALLOC_CTX *mem_ctx, const char *name,
			      uint32_t *rid);
NTSTATUS pdb_delete_dom_group(TALLOC_CTX *mem_ctx, uint32_t rid);
NTSTATUS pdb_add_group_mapping_entry(GROUP_MAP *map);
NTSTATUS pdb_update_group_mapping_entry(GROUP_MAP *map);
NTSTATUS pdb_delete_group_mapping_entry(struct dom_sid sid);
bool pdb_enum_group_mapping(const struct dom_sid *sid,
			    enum lsa_SidType sid_name_use,
			    GROUP_MAP ***pp_rmap,
			    size_t *p_num_entries,
			    bool unix_only);
NTSTATUS pdb_enum_group_members(TALLOC_CTX *mem_ctx,
				const struct dom_sid *sid,
				uint32_t **pp_member_rids,
				size_t *p_num_members);
NTSTATUS pdb_enum_group_memberships(TALLOC_CTX *mem_ctx, struct samu *user,
				    struct dom_sid **pp_sids, gid_t **pp_gids,
				    uint32_t *p_num_groups);
NTSTATUS pdb_set_unix_primary_group(TALLOC_CTX *mem_ctx, struct samu *user);
NTSTATUS pdb_add_groupmem(TALLOC_CTX *mem_ctx, uint32_t group_rid,
			  uint32_t member_rid);
NTSTATUS pdb_del_groupmem(TALLOC_CTX *mem_ctx, uint32_t group_rid,
			  uint32_t member_rid);
NTSTATUS pdb_create_alias(const char *name, uint32_t *rid);
NTSTATUS pdb_delete_alias(const struct dom_sid *sid);
NTSTATUS pdb_get_aliasinfo(const struct dom_sid *sid, struct acct_info *info);
NTSTATUS pdb_set_aliasinfo(const struct dom_sid *sid, struct acct_info *info);
NTSTATUS pdb_add_aliasmem(const struct dom_sid *alias, const struct dom_sid *member);
NTSTATUS pdb_del_aliasmem(const struct dom_sid *alias, const struct dom_sid *member);
NTSTATUS pdb_enum_aliasmem(const struct dom_sid *alias, TALLOC_CTX *mem_ctx,
			   struct dom_sid **pp_members, size_t *p_num_members);
NTSTATUS pdb_enum_alias_memberships(TALLOC_CTX *mem_ctx,
				    const struct dom_sid *domain_sid,
				    const struct dom_sid *members, size_t num_members,
				    uint32_t **pp_alias_rids,
				    size_t *p_num_alias_rids);
NTSTATUS pdb_lookup_rids(const struct dom_sid *domain_sid,
			 int num_rids,
			 uint32_t *rids,
			 const char **names,
			 enum lsa_SidType *attrs);
NTSTATUS pdb_lookup_names(const struct dom_sid *domain_sid,
			  int num_names,
			  const char **names,
			  uint32_t *rids,
			  enum lsa_SidType *attrs);
bool pdb_get_account_policy(enum pdb_policy_type type, uint32_t *value);
bool pdb_set_account_policy(enum pdb_policy_type type, uint32_t value);
bool pdb_get_seq_num(time_t *seq_num);
/* 
 * Instead of passing down a gid or uid, this function sends down a pointer
 * to a unixid. 
 *
 * This acts as an in-out variable so that the idmap functions can correctly
 * receive ID_TYPE_BOTH, filling in cache details correctly rather than forcing
 * the cache to store ID_TYPE_UID or ID_TYPE_GID. 
 */
bool pdb_id_to_sid(struct unixid *id, struct dom_sid *sid);
bool pdb_sid_to_id(const struct dom_sid *sid, struct unixid *id);
uint32_t pdb_capabilities(void);
bool pdb_new_rid(uint32_t *rid);
bool initialize_password_db(bool reload, struct tevent_context *tevent_ctx);
struct pdb_search *pdb_search_init(TALLOC_CTX *mem_ctx,
				   enum pdb_search_type type);
struct pdb_search *pdb_search_users(TALLOC_CTX *mem_ctx, uint32_t acct_flags);
struct pdb_search *pdb_search_groups(TALLOC_CTX *mem_ctx);
struct pdb_search *pdb_search_aliases(TALLOC_CTX *mem_ctx, const struct dom_sid *sid);
uint32_t pdb_search_entries(struct pdb_search *search,
			  uint32_t start_idx, uint32_t max_entries,
			  struct samr_displayentry **result);
bool pdb_get_trusteddom_pw(const char *domain, char** pwd, struct dom_sid *sid,
			   time_t *pass_last_set_time);
NTSTATUS pdb_get_trusteddom_creds(const char *domain, TALLOC_CTX *mem_ctx,
				  struct cli_credentials **creds);
bool pdb_set_trusteddom_pw(const char* domain, const char* pwd,
			   const struct dom_sid *sid);
bool pdb_del_trusteddom_pw(const char *domain);
NTSTATUS pdb_enum_trusteddoms(TALLOC_CTX *mem_ctx, uint32_t *num_domains,
			      struct trustdom_info ***domains);
NTSTATUS pdb_get_trusted_domain(TALLOC_CTX *mem_ctx, const char *domain,
				struct pdb_trusted_domain **td);
NTSTATUS pdb_get_trusted_domain_by_sid(TALLOC_CTX *mem_ctx, struct dom_sid *sid,
				struct pdb_trusted_domain **td);
NTSTATUS pdb_set_trusted_domain(const char* domain,
				const struct pdb_trusted_domain *td);
NTSTATUS pdb_del_trusted_domain(const char *domain);
NTSTATUS pdb_enum_trusted_domains(TALLOC_CTX *mem_ctx, uint32_t *num_domains,
				  struct pdb_trusted_domain ***domains);
NTSTATUS make_pdb_method( struct pdb_methods **methods ) ;
NTSTATUS pdb_get_secret(TALLOC_CTX *mem_ctx,
			const char *secret_name,
			DATA_BLOB *secret_current,
			NTTIME *secret_current_lastchange,
			DATA_BLOB *secret_old,
			NTTIME *secret_old_lastchange,
			struct security_descriptor **sd);
NTSTATUS pdb_set_secret(const char *secret_name,
			DATA_BLOB *secret_current,
			DATA_BLOB *secret_old,
			struct security_descriptor *sd);
NTSTATUS pdb_delete_secret(const char *secret_name);
bool pdb_sid_to_id_unix_users_and_groups(const struct dom_sid *sid,
					 struct unixid *id);

NTSTATUS pdb_enum_upn_suffixes(TALLOC_CTX *mem_ctx,
			       uint32_t *num_suffixes,
			       char ***suffixes);

NTSTATUS pdb_set_upn_suffixes(uint32_t num_suffixes,
			      const char **suffixes);
bool pdb_is_responsible_for_our_sam(void);
bool pdb_is_responsible_for_builtin(void);
bool pdb_is_responsible_for_wellknown(void);
bool pdb_is_responsible_for_unix_users(void);
bool pdb_is_responsible_for_unix_groups(void);
bool pdb_is_responsible_for_everything_else(void);

/* The following definitions come from passdb/pdb_util.c  */

NTSTATUS pdb_create_builtin(uint32_t rid);
NTSTATUS create_builtin_users(const struct dom_sid *sid);
NTSTATUS create_builtin_administrators(const struct dom_sid *sid);

#include "passdb/machine_sid.h"
#include "passdb/lookup_sid.h"

/* The following definitions come from passdb/pdb_unixid.c */
void unixid_from_uid(struct unixid *id, uint32_t some_uid);
void unixid_from_gid(struct unixid *id, uint32_t some_gid);
void unixid_from_both(struct unixid *id, uint32_t some_id);

/* The following definitions come from passdb/pdb_secrets.c
 * and should be used by PDB modules if they need to store
 * sid/guid information for the domain in secrets database
 */
bool PDB_secrets_mark_domain_protected(const char *domain);
bool PDB_secrets_clear_domain_protection(const char *domain);
bool PDB_secrets_store_domain_sid(const char *domain, const struct dom_sid  *sid);
bool PDB_secrets_fetch_domain_sid(const char *domain, struct dom_sid  *sid);
bool PDB_secrets_store_domain_guid(const char *domain, struct GUID *guid);
bool PDB_secrets_fetch_domain_guid(const char *domain, struct GUID *guid);

#endif /* _PASSDB_H */
