#ifndef _SMBAUTH_H_
#define _SMBAUTH_H_
/* 
   Unix SMB/Netbios implementation.
   Version 2.2
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

/* AUTH_STR - string */
typedef struct normal_string
{
	int len;
	char *str;
} AUTH_STR;

/* AUTH_UNISTR - unicode string or buffer */
typedef struct unicode_string
{
	int len;
	uchar *unistr;
} AUTH_UNISTR;

typedef struct interactive_password
{
	OWF_INFO          lm_owf;              /* LM OWF Password */
	OWF_INFO          nt_owf;              /* NT OWF Password */
} auth_interactive_password;

typedef struct auth_usersupplied_info
{
	
 	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;
	auth_interactive_password * interactive_password;
 	DATA_BLOB plaintext_password;
	
	BOOL encrypted;
	
	uint32 ntlmssp_flags;

	AUTH_STR           client_domain;          /* domain name string */
	AUTH_STR           domain;               /* domain name after mapping */
	AUTH_STR           internal_username;    /* username after mapping */
	AUTH_STR           smb_name;        /* username before mapping */
	AUTH_STR           wksta_name;           /* workstation name (netbios calling name) unicode string */
	
} auth_usersupplied_info;

#define SAM_FILL_NAME  0x01
#define SAM_FILL_INFO3 0x02
#define SAM_FILL_SAM   0x04
#define SAM_FILL_UNIX  0x08
#define SAM_FILL_ALL (SAM_FILL_NAME | SAM_FILL_INFO3 | SAM_FILL_SAM | SAM_FILL_UNIX)

typedef struct auth_serversupplied_info 
{
	BOOL guest;
	
	/* This groups info is needed for when we become_user() for this uid */
	int n_groups;
	gid_t *groups;
	
	/* NT group information taken from the info3 structure */
	
	NT_USER_TOKEN *ptok;
	
	uchar session_key[16];
	
	uint8 first_8_lm_hash[8];

	uint32 sam_fill_level;  /* How far is this structure filled? */
	
	SAM_ACCOUNT *sam_account;
	
	void *pam_handle;
	
} auth_serversupplied_info;

struct auth_context {
	DATA_BLOB challenge; 

	/* Who set this up in the first place? */ 
	char *challenge_set_by; 

	struct auth_methods *challenge_set_method; 
	/* What order are the various methods in?   Try to stop it changing under us */ 
	struct auth_methods *auth_method_list;	

	TALLOC_CTX *mem_ctx;
	const uint8 *(*get_ntlm_challenge)(struct auth_context *auth_context);
	NTSTATUS (*check_ntlm_password)(const struct auth_context *auth_context,
					const struct auth_usersupplied_info *user_info, 
					struct auth_serversupplied_info **server_info);
	NTSTATUS (*nt_status_squash)(NTSTATUS nt_status);
	void (*free)(struct auth_context **auth_context);
};

typedef struct auth_methods
{
	struct auth_methods *prev, *next;
	char *name; /* What name got this module */

	NTSTATUS (*auth)(const struct auth_context *auth_context,
			 void *my_private_data, 
			 TALLOC_CTX *mem_ctx,
			 const struct auth_usersupplied_info *user_info, 
			 auth_serversupplied_info **server_info);

	DATA_BLOB (*get_chal)(const struct auth_context *auth_context,
			      void **my_private_data, 
			      TALLOC_CTX *mem_ctx);
	
	/* Used to keep tabs on things like the cli for SMB server authentication */
	void *private_data;
	
	/* Function to clean up the above arbitary structure */
	void (*free_private_data)(void **private_data);

	/* Function to send a keepalive message on the above structure */
	void (*send_keepalive)(void **private_data);

} auth_methods;

struct auth_init_function {
	char *name;
	/* Function to create a member of the authmethods list */
	BOOL (*init)(struct auth_context *auth_context, struct auth_methods **auth_method);
};


#endif /* _SMBAUTH_H_ */
