/* 
   Unix SMB/CIFS implementation.
   SAM structures
   Copyright (C) Kai Krueger 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Simo Sorce 2002
   Copyright (C) Andrew Bartlett 2002
   Copyright (C) Jelmer Vernooij 2002
   
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

#ifndef _SAM_H
#define _SAM_H

/* We want to track down bugs early */
#if 1
#define SAM_ASSERT(x) SMB_ASSERT(x)
#else
#define SAM_ASSERT(x) while (0) { \
	if (!(x)) {
		DEBUG(0, ("SAM_ASSERT failed!\n"))
		return NT_STATUS_FAIL_CHECK;\
	} \
    }
#endif


/* let it be 0 until we have a stable interface --metze */
#define SAM_INTERFACE_VERSION 0

/* use this inside a passdb module */
#define SAM_MODULE_VERSIONING_MAGIC \
int sam_version(void)\
{\
	return SAM_INTERFACE_VERSION;\
}

/* Backend to use by default when no backend was specified */
#define SAM_DEFAULT_BACKEND "plugin"

typedef struct sam_domain_handle {
	TALLOC_CTX *mem_ctx;
	uint32 access_granted;
	const struct sam_methods *current_sam_methods; /* sam_methods creating this handle */
	void (*free_fn)(struct sam_domain_handle **);
	struct domain_data {
		DOM_SID sid; /*SID of the domain. Should not be changed */
		char *name; /* Name of the domain */
		char *servername; /* */
		NTTIME max_passwordage; /* time till next password expiration */
		NTTIME min_passwordage; /* time till password can be changed again */
		NTTIME lockout_duration; /* time till login is allowed again after lockout*/
		NTTIME reset_count; /* time till bad login counter is reset */
		uint16 min_passwordlength; /* minimum number of characters for a password */
		uint16 password_history; /* number of passwords stored in history */
		uint16 lockout_count; /* number of bad login attempts before lockout */
		BOOL force_logoff; /* force logoff after logon hours have expired */
		BOOL login_pwdchange; /* Users need to logon to change their password */
		uint32 num_accounts; /* number of accounts in the domain */
		uint32 num_groups; /* number of global groups */
		uint32 num_aliases; /* number of local groups */
		uint32 sam_sequence_number; /* global sequence number */
	} private;
} SAM_DOMAIN_HANDLE;

typedef struct sam_account_handle {
	TALLOC_CTX *mem_ctx;
	uint32 access_granted;
	const struct sam_methods *current_sam_methods; /* sam_methods creating this handle */
	void (*free_fn)(struct sam_account_handle **);
	struct sam_account_data {
		uint32 init_flag;
		NTTIME logon_time; /* logon time */
		NTTIME logoff_time; /* logoff time */
		NTTIME kickoff_time; /* kickoff time */
		NTTIME pass_last_set_time; /* password last set time */
		NTTIME pass_can_change_time; /* password can change time */
		NTTIME pass_must_change_time; /* password must change time */
		char * account_name; /* account_name string */
		SAM_DOMAIN_HANDLE * domain; /* domain of account */
		char *full_name; /* account's full name string */
		char *unix_home_dir; /* UNIX home directory string */
		char *home_dir; /* home directory string */
		char *dir_drive; /* home directory drive string */
		char *logon_script; /* logon script string */
		char *profile_path; /* profile path string */
		char *acct_desc; /* account description string */
		char *workstations; /* login from workstations string */
		char *unknown_str; /* don't know what this is, yet. */
		char *munged_dial; /* munged path name and dial-back tel number */
		DOM_SID account_sid; /* Primary Account SID */
		DOM_SID group_sid; /* Primary Group SID */
		DATA_BLOB lm_pw; /* .data is Null if no password */
		DATA_BLOB nt_pw; /* .data is Null if no password */
		char *plaintext_pw; /* if Null not available */
		uint16 acct_ctrl; /* account info (ACB_xxxx bit-mask) */
		uint32 unknown_1; /* 0x00ff ffff */
		uint16 logon_divs; /* 168 - number of hours in a week */
		uint32 hours_len; /* normally 21 bytes */
		uint8 hours[MAX_HOURS_LEN];
		uint32 unknown_2; /* 0x0002 0000 */
		uint32 unknown_3; /* 0x0000 04ec */
	} private;
} SAM_ACCOUNT_HANDLE;

typedef struct sam_group_handle {
	TALLOC_CTX *mem_ctx;
	uint32 access_granted;
	const struct sam_methods *current_sam_methods; /* sam_methods creating this handle */
	void (*free_fn)(struct sam_group_handle **);
	struct sam_group_data {
		char *group_name;
		char *group_desc;
		DOM_SID sid;
		uint16 group_ctrl; /* specifies if the group is a local group or a global group */
		uint32 num_members;
	} private;
} SAM_GROUP_HANDLE;


typedef struct sam_group_member {
	DOM_SID sid; 
	BOOL group; /* specifies if it is a group or a account */ 
} SAM_GROUP_MEMBER;

typedef struct sam_account_enum {
	DOM_SID sid; 
	char *account_name; 
	char *full_name; 
	char *account_desc; 
	uint16 acct_ctrl; 
} SAM_ACCOUNT_ENUM;

typedef struct sam_group_enum {
	DOM_SID sid;
	char *group_name;
	char *group_desc;
	uint16 group_ctrl;
} SAM_GROUP_ENUM;


/* bits for group_ctrl: to spezify if the group is global group or alias */
#define GCB_LOCAL_GROUP		0x0001
#define GCB_ALIAS_GROUP		(GCB_LOCAL_GROUP |GCB_BUILTIN)
#define GCB_GLOBAL_GROUP	0x0002
#define GCB_BUILTIN		0x1000

typedef struct sam_context 
{
	struct sam_methods *methods;
	TALLOC_CTX *mem_ctx;
	
	void (*free_fn)(struct sam_context **);
} SAM_CONTEXT;

typedef struct sam_methods 
{
	struct sam_context		*parent;
	struct sam_methods		*next;
	struct sam_methods		*prev;
	const char			*backendname;
	const char			*domain_name;
	DOM_SID				domain_sid;
	void				*private_data;
	
	/* General API */
	
	NTSTATUS (*sam_get_sec_desc) (const struct sam_methods *, const NT_USER_TOKEN *access_token, const DOM_SID *sid, SEC_DESC **sd);
	NTSTATUS (*sam_set_sec_desc) (const struct sam_methods *, const NT_USER_TOKEN *access_token, const DOM_SID *sid, const SEC_DESC *sd);
	
	NTSTATUS (*sam_lookup_sid) (const struct sam_methods *, const NT_USER_TOKEN *access_token, TALLOC_CTX *mem_ctx, const DOM_SID *sid, char **name, uint32 *type);
	NTSTATUS (*sam_lookup_name) (const struct sam_methods *, const NT_USER_TOKEN *access_token, const char *name, DOM_SID *sid, uint32 *type);
	
	/* Domain API */

	NTSTATUS (*sam_update_domain) (const struct sam_methods *, const SAM_DOMAIN_HANDLE *domain);
	NTSTATUS (*sam_get_domain_handle) (const struct sam_methods *, const NT_USER_TOKEN *access_token, uint32 access_desired, SAM_DOMAIN_HANDLE **domain);

	/* Account API */

	NTSTATUS (*sam_create_account) (const struct sam_methods *, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *account_name, uint16 acct_ctrl, SAM_ACCOUNT_HANDLE **account);
	NTSTATUS (*sam_add_account) (const struct sam_methods *, const SAM_ACCOUNT_HANDLE *account);
	NTSTATUS (*sam_update_account) (const struct sam_methods *, const SAM_ACCOUNT_HANDLE *account);
	NTSTATUS (*sam_delete_account) (const struct sam_methods *, const SAM_ACCOUNT_HANDLE *account);
	NTSTATUS (*sam_enum_accounts) (const struct sam_methods *, const NT_USER_TOKEN *access_token, uint16 acct_ctrl, uint32 *account_count, SAM_ACCOUNT_ENUM **accounts);

	NTSTATUS (*sam_get_account_by_sid) (const struct sam_methods *, const NT_USER_TOKEN *access_token, uint32 access_desired, const DOM_SID *accountsid, SAM_ACCOUNT_HANDLE **account);
	NTSTATUS (*sam_get_account_by_name) (const struct sam_methods *, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *name, SAM_ACCOUNT_HANDLE **account);

	/* Group API */

	NTSTATUS (*sam_create_group) (const struct sam_methods *, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *group_name, uint16 group_ctrl, SAM_GROUP_HANDLE **group);
	NTSTATUS (*sam_add_group) (const struct sam_methods *, const SAM_GROUP_HANDLE *group);
	NTSTATUS (*sam_update_group) (const struct sam_methods *, const SAM_GROUP_HANDLE *group);
	NTSTATUS (*sam_delete_group) (const struct sam_methods *, const SAM_GROUP_HANDLE *group);
	NTSTATUS (*sam_enum_groups) (const struct sam_methods *, const NT_USER_TOKEN *access_token, uint16 group_ctrl, uint32 *groups_count, SAM_GROUP_ENUM **groups);
	NTSTATUS (*sam_get_group_by_sid) (const struct sam_methods *, const NT_USER_TOKEN *access_token, uint32 access_desired, const DOM_SID *groupsid, SAM_GROUP_HANDLE **group);
	NTSTATUS (*sam_get_group_by_name) (const struct sam_methods *, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *name, SAM_GROUP_HANDLE **group);

	NTSTATUS (*sam_add_member_to_group) (const struct sam_methods *, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member);
	NTSTATUS (*sam_delete_member_from_group) (const struct sam_methods *, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member);
	NTSTATUS (*sam_enum_groupmembers) (const struct sam_methods *, const SAM_GROUP_HANDLE *group, uint32 *members_count, SAM_GROUP_MEMBER **members);

	NTSTATUS (*sam_get_groups_of_sid) (const struct sam_methods *, const NT_USER_TOKEN *access_token, const DOM_SID **sids, uint16 group_ctrl, uint32 *group_count, SAM_GROUP_ENUM **groups);

	void (*free_private_data)(void **);
} SAM_METHODS;

typedef NTSTATUS (*sam_init_function)(SAM_METHODS *, const char *);

struct sam_init_function_entry {
	char *module_name;
	/* Function to create a member of the sam_methods list */
	sam_init_function init;
};

typedef struct sam_backend_entry {
	char    *module_name;
	char    *module_params;
	char    *domain_name;
	DOM_SID *domain_sid;
} SAM_BACKEND_ENTRY;


#endif /* _SAM_H */
