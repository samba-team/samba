/* 
   Unix SMB/CIFS implementation.
   Standardised Authentication types
   Copyright (C) Andrew Bartlett 2001
   
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

#ifndef _SAMBA_AUTH_H
#define _SAMBA_AUTH_H

/* modules can use the following to determine if the interface has changed
 * please increment the version number after each interface change
 * with a comment and maybe update struct auth_critical_sizes.
 */
/* version 1 - version from samba 3.0 - metze */
/* version 2 - initial samba4 version - metze */
/* version 3 - subsequent samba4 version - abartlet */
#define AUTH_INTERFACE_VERSION 3

/* AUTH_STR - string */
typedef struct auth_str
{
	int len;
	char *str;
} AUTH_STR;

struct auth_usersupplied_info
{
	
 	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;
 	DATA_BLOB lm_interactive_pwd;
	DATA_BLOB nt_interactive_pwd;
 	DATA_BLOB plaintext_password;
	
	BOOL encrypted;
	
	AUTH_STR           client_domain;          /* domain name string */
	AUTH_STR           domain;               /* domain name after mapping */
	AUTH_STR           internal_username;    /* username after mapping */
	AUTH_STR           smb_name;        /* username before mapping */
	AUTH_STR           wksta_name;           /* workstation name (netbios calling name) unicode string */
	
};

#define SAM_FILL_NAME  0x01
#define SAM_FILL_INFO3 0x02
#define SAM_FILL_SAM   0x04
#define SAM_FILL_UNIX  0x08
#define SAM_FILL_ALL (SAM_FILL_NAME | SAM_FILL_INFO3 | SAM_FILL_SAM | SAM_FILL_UNIX)

struct auth_serversupplied_info 
{
	TALLOC_CTX *mem_ctx;

	BOOL guest;
	
	struct dom_sid *user_sid;
	struct dom_sid *primary_group_sid;

	size_t n_domain_groups;
	struct dom_sid **domain_groups;
	
	DATA_BLOB user_session_key;
	DATA_BLOB lm_session_key;
	
};

struct auth_session_info 
{
	TALLOC_CTX *mem_ctx;
	/* NT group information taken from the info3 structure */
	
	NT_USER_TOKEN *nt_user_token;

	struct auth_serversupplied_info *server_info;

	DATA_BLOB session_key;
};

struct auth_context {
	DATA_BLOB challenge; 

	/* Who set this up in the first place? */ 
	const char *challenge_set_by; 

	BOOL challenge_may_be_modified;

	struct auth_methods *challenge_set_method; 
	/* What order are the various methods in?   Try to stop it changing under us */ 
	struct auth_methods *auth_method_list;	

	TALLOC_CTX *mem_ctx;
	const uint8_t *(*get_ntlm_challenge)(struct auth_context *auth_context);
	NTSTATUS (*check_ntlm_password)(const struct auth_context *auth_context,
					const struct auth_usersupplied_info *user_info, 
					struct auth_serversupplied_info **server_info);
	NTSTATUS (*nt_status_squash)(NTSTATUS nt_status);
	void (*free)(struct auth_context **auth_context);
};

struct auth_methods
{
	struct auth_methods *prev, *next;
	const char *name; /* What name got this module */

	NTSTATUS (*auth)(const struct auth_context *auth_context,
			 void *my_private_data, 
			 TALLOC_CTX *mem_ctx,
			 const struct auth_usersupplied_info *user_info, 
			 struct auth_serversupplied_info **server_info);

	DATA_BLOB (*get_chal)(const struct auth_context *auth_context,
			      void **my_private_data, 
			      TALLOC_CTX *mem_ctx);
	
	/* Used to keep tabs on things like the cli for SMB server authentication */
	void *private_data;
	
	/* Function to clean up the above arbitary structure */
	void (*free_private_data)(void **private_data);

	/* Function to send a keepalive message on the above structure */
	void (*send_keepalive)(void **private_data);

};

typedef NTSTATUS (*auth_init_function)(struct auth_context *, const char *, struct auth_methods **);

struct auth_init_function_entry {
	const char *name;
	/* Function to create a member of the authmethods list */

	auth_init_function init;

	struct auth_init_function_entry *prev, *next;
};

struct auth_ntlmssp_state
{
	TALLOC_CTX *mem_ctx;
	struct auth_context *auth_context;
	struct auth_serversupplied_info *server_info;
	struct ntlmssp_state *ntlmssp_state;
};

#define auth_ops __XXX_ERROR_BLA
struct auth_operations {
	/* the name of the backend */
	const char *name;

	/* Function to create a member of the authmethods list */
	NTSTATUS (*init)(struct auth_context *, const char *, struct auth_methods **);
};

/* this structure is used by backends to determine the size of some critical types */
struct auth_critical_sizes {
	int interface_version;
	int sizeof_auth_operations;
	int sizeof_auth_methods;
	int sizeof_auth_context;
	int sizeof_auth_ntlmssp_state;
	int sizeof_auth_usersupplied_info;
	int sizeof_auth_serversupplied_info;
	int sizeof_auth_str;
	int sizeof_auth_unistr;
};

#endif /* _SMBAUTH_H_ */
