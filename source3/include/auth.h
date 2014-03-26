#ifndef _SMBAUTH_H_
#define _SMBAUTH_H_
/* 
   Unix SMB/CIFS implementation.
   Standardised Authentication types
   Copyright (C) Andrew Bartlett 2001

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

#include "../auth/common_auth.h"

struct gensec_security;

struct extra_auth_info {
	struct dom_sid user_sid;
	struct dom_sid pgid_sid;
};

struct auth_serversupplied_info {
	bool guest;
	bool system;

	struct security_unix_token utok;

	/* NT group information taken from the info3 structure */

	struct security_token *security_token;

	/* These are the intermediate session keys, as provided by a
	 * NETLOGON server and used by NTLMSSP to negotiate key
	 * exchange etc (which will provide the session_key in the
	 * auth_session_info).  It is usually the same as the keys in
	 * the info3, but is a variable length structure here to allow
	 * it to be omitted if the auth module does not know it.
	 */

	DATA_BLOB session_key;
	DATA_BLOB lm_session_key;

	struct netr_SamInfo3 *info3;

	/* this structure is filled *only* in pathological cases where the user
	 * sid or the primary group sid are not sids of the domain. Normally
	 * this happens only for unix accounts that have unix domain sids.
	 * This is checked only when info3.rid and/or info3.primary_gid are set
	 * to the special invalid value of 0xFFFFFFFF */
	struct extra_auth_info extra;

	/*
	 * This is a token from /etc/passwd and /etc/group
	 */
	bool nss_token;

	char *unix_name;
};

struct auth_context;

typedef NTSTATUS (*prepare_gensec_fn)(const struct auth_context *auth_context, 
				      TALLOC_CTX *mem_ctx,
				      struct gensec_security **gensec_context);

typedef NTSTATUS (*make_auth4_context_fn)(const struct auth_context *auth_context, 
					  TALLOC_CTX *mem_ctx,
					  struct auth4_context **auth4_context);

struct auth_context {
	DATA_BLOB challenge; 

	/* Who set this up in the first place? */ 
	const char *challenge_set_by; 

	/* What order are the various methods in?   Try to stop it changing under us */ 
	struct auth_methods *auth_method_list;	

	prepare_gensec_fn prepare_gensec;
	make_auth4_context_fn make_auth4_context;
	const char *forced_samba4_methods;
};

typedef struct auth_methods
{
	struct auth_methods *prev, *next;
	const char *name; /* What name got this module */

	NTSTATUS (*auth)(const struct auth_context *auth_context,
			 void *my_private_data, 
			 TALLOC_CTX *mem_ctx,
			 const struct auth_usersupplied_info *user_info, 
			 struct auth_serversupplied_info **server_info);

	/* Optional methods allowing this module to provide a way to get a gensec context and an auth4_context */
	prepare_gensec_fn prepare_gensec;
	make_auth4_context_fn make_auth4_context;
	/* Used to keep tabs on things like the cli for SMB server authentication */
	void *private_data;

	uint32_t flags;

} auth_methods;

typedef NTSTATUS (*auth_init_function)(struct auth_context *, const char *, struct auth_methods **);

struct auth_init_function_entry {
	const char *name;
	/* Function to create a member of the authmethods list */

	auth_init_function init;

	struct auth_init_function_entry *prev, *next;
};

extern const struct gensec_security_ops gensec_ntlmssp3_server_ops;

/* Intent of use for session key. LSA and SAMR pipes use 16 bytes of session key when doing create/modify calls */
enum session_key_use_intent {
	KEY_USE_FULL = 0,
	KEY_USE_16BYTES
};

/* Changed from 1 -> 2 to add the logon_parameters field. */
/* Changed from 2 -> 3 when we reworked many auth structures to use IDL or be in common with Samba4 */
/* Changed from 3 -> 4 when we reworked added the flags */
#define AUTH_INTERFACE_VERSION 4

#include "auth/proto.h"

#endif /* _SMBAUTH_H_ */
