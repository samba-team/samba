/* 
   Unix SMB/CIFS implementation.
   Standardised Authentication types
   Copyright (C) Andrew Bartlett   2001
   Copyright (C) Stefan Metzmacher 2005
   
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

union netr_Validation;
struct netr_SamBaseInfo;
struct netr_SamInfo3;

/* modules can use the following to determine if the interface has changed
 * please increment the version number after each interface change
 * with a comment and maybe update struct auth_critical_sizes.
 */
/* version 1 - version from samba 3.0 - metze */
/* version 2 - initial samba4 version - metze */
/* version 3 - subsequent samba4 version - abartlet */
/* version 4 - subsequent samba4 version - metze */
/* version 0 - till samba4 is stable - metze */
#define AUTH_INTERFACE_VERSION 0

#define USER_INFO_CASE_INSENSITIVE_USERNAME 0x01 /* username may be in any case */
#define USER_INFO_CASE_INSENSITIVE_PASSWORD 0x02 /* password may be in any case */
#define USER_INFO_DONT_CHECK_UNIX_ACCOUNT   0x04 /* dont check unix account status */
#define USER_INFO_INTERACTIVE_LOGON         0x08 /* dont check unix account status */

enum auth_password_state {
	AUTH_PASSWORD_RESPONSE,
	AUTH_PASSWORD_HASH,
	AUTH_PASSWORD_PLAIN
};

struct auth_usersupplied_info
{
	const char *workstation_name;
	struct socket_address *remote_host;

	uint32_t logon_parameters;

	BOOL mapped_state;
	/* the values the client gives us */
	struct {
		const char *account_name;
		const char *domain_name;
	} client, mapped;

	enum auth_password_state password_state;

	union {
		struct {
			DATA_BLOB lanman;
			DATA_BLOB nt;
		} response;
		struct {
			struct samr_Password *lanman;
			struct samr_Password *nt;
		} hash;
		
		char *plaintext;
	} password;
	uint32_t flags;
};

struct auth_serversupplied_info 
{
	struct dom_sid *account_sid;
	struct dom_sid *primary_group_sid;

	size_t n_domain_groups;
	struct dom_sid **domain_groups;

	DATA_BLOB user_session_key;
	DATA_BLOB lm_session_key;

	const char *account_name;
	const char *domain_name;

	const char *full_name;
	const char *logon_script;
	const char *profile_path;
	const char *home_directory;
	const char *home_drive;
	const char *logon_server;
	
	NTTIME last_logon;
	NTTIME last_logoff;
	NTTIME acct_expiry;
	NTTIME last_password_change;
	NTTIME allow_password_change;
	NTTIME force_password_change;

	uint16_t logon_count;
	uint16_t bad_password_count;

	uint32_t acct_flags;

	BOOL authenticated;
};

struct auth_session_info {
	struct security_token *security_token;
	struct auth_serversupplied_info *server_info;
	DATA_BLOB session_key;
	struct cli_credentials *credentials;
};

struct auth_method_context;
struct auth_check_password_request;

struct auth_operations {
	const char *name;

	/* If you are using this interface, then you are probably
	 * getting something wrong.  This interface is only for
	 * security=server, and makes a number of compromises to allow
	 * that.  It is not compatible with being a PDC.  */

	NTSTATUS (*get_challenge)(struct auth_method_context *ctx, TALLOC_CTX *mem_ctx, DATA_BLOB *challenge);

	/* Given the user supplied info, check if this backend want to handle the password checking */

	NTSTATUS (*want_check)(struct auth_method_context *ctx, TALLOC_CTX *mem_ctx,
			       const struct auth_usersupplied_info *user_info);

	/* Given the user supplied info, check a password */

	NTSTATUS (*check_password)(struct auth_method_context *ctx, TALLOC_CTX *mem_ctx,
				   const struct auth_usersupplied_info *user_info,
				   struct auth_serversupplied_info **server_info);
};

struct auth_method_context {
	struct auth_method_context *prev, *next;
	struct auth_context *auth_ctx;
	const struct auth_operations *ops;
	int depth;
	void *private_data;
};

struct auth_context {
	struct {
		/* Who set this up in the first place? */ 
		const char *set_by;

		BOOL may_be_modified;

		DATA_BLOB data; 
	} challenge;

	/* methods, in the order they should be called */
	struct auth_method_context *methods;

	/* the event context to use for calls that can block */
	struct event_context *event_ctx;

	/* the messaging context which can be used by backends */
	struct messaging_context *msg_ctx;
};

/* this structure is used by backends to determine the size of some critical types */
struct auth_critical_sizes {
	int interface_version;
	int sizeof_auth_operations;
	int sizeof_auth_methods;
	int sizeof_auth_context;
	int sizeof_auth_usersupplied_info;
	int sizeof_auth_serversupplied_info;
};

 NTSTATUS encrypt_user_info(TALLOC_CTX *mem_ctx, struct auth_context *auth_context, 
			   enum auth_password_state to_state,
			   const struct auth_usersupplied_info *user_info_in,
			   const struct auth_usersupplied_info **user_info_encrypted);

#include "auth/auth_proto.h"

#endif /* _SMBAUTH_H_ */
