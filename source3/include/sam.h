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

#define SAM_INTERFACE_VERSION 1

/* use this inside a passdb module */
#define SAM_MODULE_VERSIONING_MAGIC \
int sam_version(void)\
{\
	return SAM_INTERFACE_VERSION;\
}

typedef struct sam_domain {
 TALLOC_CTX *mem_ctx;
 uint32 access_granted;
 struct sam_methods *current_sam_methods; /* sam_methods creating this
handle */
 void (*free_fn)(struct sam_domain **);
 struct domain_data {
  DOM_SID sid; /*SID of the domain. Should not be changed */
  char *name; /* Name of the domain */
  char *servername; /* */
  NTTIME max_passwordage; /* time till next password expiration */
  NTTIME min_passwordage; /* time till password can be changed again */
  NTTIME lockout_duration; /* time till login is allowed again after
lockout*/
  NTTIME reset_count; /* time till bad login counter is reset */
  uint16 min_passwordlength; /* minimum number of characters for a password
*/
  uint16 password_history; /* number of passwords stored in history */
  uint16 lockout_count; /* number of bad login attempts before lockout */
  BOOL force_logoff; /* force logoff after logon hours have expired */
  BOOL login_pwdchange; /* Users need to logon to change their password */
  uint32 num_users; /* number of users in the domain */
  uint32 num_groups; /* number of global groups */
  uint32 num_aliases; /* number of local groups */
 } private;
} SAM_DOMAIN_HANDLE;

typedef struct sam_user {
 TALLOC_CTX *mem_ctx;
 uint32 access_granted;
 struct sam_methods *current_sam_methods; /* sam_methods creating this
handle */
 void (*free_fn)(struct sam_user **);
 struct sam_user_data {
  uint32 init_flag;
  NTTIME logon_time; /* logon time */
  NTTIME logoff_time; /* logoff time */
  NTTIME kickoff_time; /* kickoff time */
  NTTIME pass_last_set_time; /* password last set time */
  NTTIME pass_can_change_time; /* password can change time */
  NTTIME pass_must_change_time; /* password must change time */
  char * username; /* username string */
  SAM_DOMAIN_HANDLE * domain; /* domain of user */
  char * full_name; /* user's full name string */
  char * unix_home_dir; /* UNIX home directory string */
  char * home_dir; /* home directory string */
  char * dir_drive; /* home directory drive string */
  char * logon_script; /* logon script string */
  char * profile_path; /* profile path string */
  char * acct_desc; /* user description string */
  char * workstations; /* login from workstations string */
  char * unknown_str; /* don't know what this is, yet. */
  char * munged_dial; /* munged path name and dial-back tel number */
  DOM_SID user_sid; /* Primary User SID */
  DOM_SID group_sid; /* Primary Group SID */
  DATA_BLOB lm_pw; /* .data is Null if no password */
  DATA_BLOB nt_pw; /* .data is Null if no password */
  DATA_BLOB plaintext_pw; /* .data is Null if not available */
  uint16 acct_ctrl; /* account info (ACB_xxxx bit-mask) */
  uint32 unknown_1; /* 0x00ff ffff */
  uint16 logon_divs; /* 168 - number of hours in a week */
  uint32 hours_len; /* normally 21 bytes */
  uint8 hours[MAX_HOURS_LEN];
  uint32 unknown_2; /* 0x0002 0000 */
  uint32 unknown_3; /* 0x0000 04ec */
 } private;
} SAM_USER_HANDLE;

typedef struct sam_group {
 TALLOC_CTX *mem_ctx;
 uint32 access_granted;
 struct sam_methods *current_sam_methods; /* sam_methods creating this
handle */
 void (*free_fn)(struct sam_group **);
 struct sam_group_data {
  char *name;
  char *comment;
  DOM_SID sid;
  int32 flags; /* specifies if the group is a lokal group or a global group
*/
  uint32 num_members;
  PRIVILEGE_SET privileges;
 } private;
} SAM_GROUP_HANDLE;


typedef struct sam_group_member {
	DOM_SID sid; 
	BOOL group; /* specifies if it is a group or a user */ 

} SAM_GROUP_MEMBER;

typedef struct sam_user_enum {
	DOM_SID sid; 
	char *username; 
	char *full_name; 
	char *user_desc; 
	uint16 acc_ctrl; 
} SAM_USER_ENUM;

typedef struct sam_group_enum {
	DOM_SID sid;
	char *groupname;
	char *comment;
} SAM_GROUP_ENUM;

typedef struct sam_context 
{
	struct sam_methods *methods;
	TALLOC_CTX *mem_ctx;
	
	/* General API */
	
	NTSTATUS (*sam_get_sec_desc) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const DOM_SID *sid, SEC_DESC **sd);
	NTSTATUS (*sam_set_sec_desc) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const DOM_SID *sid, const SEC_DESC *sd);
	
	NTSTATUS (*sam_lookup_sid) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const DOM_SID *sid, char **name, uint32 *type);
	NTSTATUS (*sam_lookup_name) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const char *domain, const char *name, DOM_SID **sid,  uint32 *type);	


	/* Domain API */

	NTSTATUS (*sam_update_domain) ( const struct sam_context *, SAM_DOMAIN_HANDLE *domain);

	NTSTATUS (*sam_enum_domains) ( const struct sam_context *, const NT_USER_TOKEN *access_token, int32 *domain_count, DOM_SID **domains, char **domain_names);
	NTSTATUS (*sam_lookup_domain) ( const struct sam_context *, const NT_USER_TOKEN * access_token, const char *domain, DOM_SID **domainsid);

	NTSTATUS (*sam_get_domain_by_sid) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *domainsid, SAM_DOMAIN_HANDLE **domain);


	/* User API */

	NTSTATUS (*sam_create_user) ( const struct sam_context *context, const NT_USER_TOKEN *access_token, const uint32 access_desired, DOM_SID *domainsid, SAM_USER_HANDLE **user);
	NTSTATUS (*sam_add_user) ( const struct sam_context *, DOM_SID *domainsid, SAM_USER_HANDLE *user);
	NTSTATUS (*sam_update_user) ( const struct sam_context *, SAM_USER_HANDLE *user);
	NTSTATUS (*sam_delete_user) ( const struct sam_context *, SAM_USER_HANDLE * user);
	NTSTATUS (*sam_enum_users) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const DOM_SID *domain, int32 *user_count, SAM_USER_ENUM **users);

	NTSTATUS (*sam_get_user_by_sid) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *usersid, SAM_USER_HANDLE **user);
	NTSTATUS (*sam_get_user_by_name) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *domain, const char *name, SAM_USER_HANDLE **user);

	/* Group API */


	NTSTATUS (*sam_add_group) ( const struct sam_context *, DOM_SID *domainsid, SAM_GROUP_HANDLE *samgroup);
	NTSTATUS (*sam_update_group) ( const struct sam_context *, SAM_GROUP_HANDLE *samgroup);
	NTSTATUS (*sam_delete_group) ( const struct sam_context *, SAM_GROUP_HANDLE *groupsid);
	NTSTATUS (*sam_enum_groups) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const DOM_SID *domainsid, const uint32 type, uint32 *groups_count, SAM_GROUP_ENUM **groups);
	NTSTATUS (*sam_get_group_by_sid) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *groupsid, SAM_GROUP_HANDLE **group);
	NTSTATUS (*sam_get_group_by_name) ( const struct sam_context *, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *domain, const char *name, SAM_GROUP_HANDLE **group);

	NTSTATUS (*sam_add_member_to_group) ( const struct sam_context *, SAM_GROUP_HANDLE *group, SAM_GROUP_MEMBER *member);
	NTSTATUS (*sam_delete_member_from_group) ( const struct sam_context *, SAM_GROUP_HANDLE *group, SAM_GROUP_MEMBER *member);
	NTSTATUS (*sam_enum_groupmembers) ( const struct sam_context *, SAM_GROUP_HANDLE *group, uint32 *members_count, SAM_GROUP_MEMBER **members);

	NTSTATUS (*sam_get_groups_of_user) ( const struct sam_context *, SAM_USER_HANDLE *user, const uint32 type, uint32 *group_count, SAM_GROUP_ENUM **groups);

	void (*free_fn)(struct sam_context **);
} SAM_CONTEXT;

typedef struct sam_methods 
{
	struct sam_context	*parent;
	struct sam_methods	*next;
	struct sam_methods	*prev;
	const char			*backendname;
	struct sam_domain   *domain;
	void				*private_data;
	
	/* General API */
	
	NTSTATUS (*sam_get_sec_desc) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const DOM_SID *sid, SEC_DESC **sd);
	NTSTATUS (*sam_set_sec_desc) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const DOM_SID *sid, const SEC_DESC *sd);
	
	NTSTATUS (*sam_lookup_sid) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const DOM_SID *sid, char **name, uint32 *type);
	NTSTATUS (*sam_lookup_name) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const char *name, DOM_SID **sid,  uint32 *type);	
	
	/* Domain API */

	NTSTATUS (*sam_update_domain) ( const struct sam_methods *, SAM_DOMAIN_HANDLE *domain);
	NTSTATUS (*sam_get_domain_handle) (const struct sam_methods *, const NT_USER_TOKEN *access_token, const uint32 access_desired, SAM_DOMAIN_HANDLE **domain);

	/* User API */

	NTSTATUS (*sam_create_user) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const uint32 access_desired, SAM_USER_HANDLE **user);
	NTSTATUS (*sam_add_user) ( const struct sam_methods *, const SAM_USER_HANDLE *user);
	NTSTATUS (*sam_update_user) ( const struct sam_methods *, const SAM_USER_HANDLE *user);
	NTSTATUS (*sam_delete_user) ( const struct sam_methods *, const SAM_USER_HANDLE *user);
	NTSTATUS (*sam_enum_users) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, int32 *user_count, SAM_USER_ENUM **users);

	NTSTATUS (*sam_get_user_by_sid) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *usersid, SAM_USER_HANDLE **user);
	NTSTATUS (*sam_get_user_by_name) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *name, SAM_USER_HANDLE **user);

	/* Group API */

	NTSTATUS (*sam_create_group) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const uint32 access_desired, const uint32 type, SAM_GROUP_HANDLE **group);
	NTSTATUS (*sam_add_group) ( const struct sam_methods *, SAM_GROUP_HANDLE *samgroup);
	NTSTATUS (*sam_update_group) ( const struct sam_methods *, SAM_GROUP_HANDLE *samgroup);
	NTSTATUS (*sam_delete_group) ( const struct sam_methods *, SAM_GROUP_HANDLE *groupsid);
	NTSTATUS (*sam_enum_groups) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const uint32 type, uint32 *groups_count, SAM_GROUP_ENUM **groups);
	NTSTATUS (*sam_get_group_by_sid) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *groupsid, SAM_GROUP_HANDLE **group);
	NTSTATUS (*sam_get_group_by_name) ( const struct sam_methods *, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *name, SAM_GROUP_HANDLE **group);

	NTSTATUS (*sam_add_member_to_group) ( const struct sam_methods *, SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member);
	NTSTATUS (*sam_delete_member_from_group) ( const struct sam_methods *, SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member);
	NTSTATUS (*sam_enum_groupmembers) ( const struct sam_methods *, SAM_GROUP_HANDLE *group, uint32 *members_count, SAM_GROUP_MEMBER **members);

	NTSTATUS (*sam_get_groups_of_user) ( const struct sam_methods *, SAM_USER_HANDLE *user, const uint32 type, uint32 *group_count, SAM_GROUP_ENUM **groups);

	void (*free_private_data)(void **);
} SAM_METHODS;

typedef NTSTATUS (*sam_init_function)( const struct sam_context *, struct sam_methods **, const char *);

struct sam_init_function_entry {
	char *name;
	/* Function to create a member of the sam_methods list */
	sam_init_function init;
};


#endif /* _SAM_H */
