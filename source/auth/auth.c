/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett         2001-2002
   Copyright (C) Stefan Metzmacher       2005
   
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

#include "includes.h"
#include "dlinklist.h"
#include "auth/auth.h"
#include "lib/events/events.h"
#include "build.h"

/***************************************************************************
 Set a fixed challenge
***************************************************************************/
NTSTATUS auth_context_set_challenge(struct auth_context *auth_ctx, const uint8_t chal[8], const char *set_by) 
{
	auth_ctx->challenge.set_by = talloc_strdup(auth_ctx, set_by);
	NT_STATUS_HAVE_NO_MEMORY(auth_ctx->challenge.set_by);

	auth_ctx->challenge.data = data_blob_talloc(auth_ctx, chal, 8);
	NT_STATUS_HAVE_NO_MEMORY(auth_ctx->challenge.data.data);

	return NT_STATUS_OK;
}

/***************************************************************************
 Set a fixed challenge
***************************************************************************/
BOOL auth_challenge_may_be_modified(struct auth_context *auth_ctx) 
{
	return auth_ctx->challenge.may_be_modified;
}

/****************************************************************************
 Try to get a challenge out of the various authentication modules.
 Returns a const char of length 8 bytes.
****************************************************************************/
NTSTATUS auth_get_challenge(struct auth_context *auth_ctx, const uint8_t **_chal)
{
	NTSTATUS nt_status;
	struct auth_method_context *method;

	if (auth_ctx->challenge.data.length) {
		DEBUG(5, ("auth_get_challenge: returning previous challenge by module %s (normal)\n", 
			  auth_ctx->challenge.set_by));
		*_chal = auth_ctx->challenge.data.data;
		return NT_STATUS_OK;
	}

	for (method = auth_ctx->methods; method; method = method->next) {
		DATA_BLOB challenge = data_blob(NULL,0);

		nt_status = method->ops->get_challenge(method, auth_ctx, &challenge);
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NOT_IMPLEMENTED)) {
			continue;
		}

		NT_STATUS_NOT_OK_RETURN(nt_status);

		if (challenge.length != 8) {
			DEBUG(0, ("auth_get_challenge: invalid challenge (length %u) by mothod [%s]\n",
				(unsigned)challenge.length, method->ops->name));
			return NT_STATUS_INTERNAL_ERROR;
		}

		auth_ctx->challenge.data	= challenge;
		auth_ctx->challenge.set_by	= method->ops->name;

		break;
	}

	if (!auth_ctx->challenge.set_by) {
		uint8_t chal[8];
		generate_random_buffer(chal, 8);

		auth_ctx->challenge.data		= data_blob_talloc(auth_ctx, chal, 8);
		NT_STATUS_HAVE_NO_MEMORY(auth_ctx->challenge.data.data);
		auth_ctx->challenge.set_by		= "random";

		auth_ctx->challenge.may_be_modified	= True;
	}

	DEBUG(10,("auth_get_challenge: challenge set by %s\n",
		 auth_ctx->challenge.set_by));

	*_chal = auth_ctx->challenge.data.data;
	return NT_STATUS_OK;
}

/**
 * Check a user's Plaintext, LM or NTLM password.
 *
 * Check a user's password, as given in the user_info struct and return various
 * interesting details in the server_info struct.
 *
 * The return value takes precedence over the contents of the server_info 
 * struct.  When the return is other than NT_STATUS_OK the contents 
 * of that structure is undefined.
 *
 * @param user_info Contains the user supplied components, including the passwords.
 *
 * @param auth_context Supplies the challenges and some other data. 
 *                  Must be created with make_auth_context(), and the challenges should be 
 *                  filled in, either at creation or by calling the challenge geneation 
 *                  function auth_get_challenge().  
 *
 * @param server_info If successful, contains information about the authentication, 
 *                    including a SAM_ACCOUNT struct describing the user.
 *
 * @return An NTSTATUS with NT_STATUS_OK or an appropriate error.
 *
 **/

NTSTATUS auth_check_password(struct auth_context *auth_ctx,
			     TALLOC_CTX *mem_ctx,
			     const struct auth_usersupplied_info *user_info, 
			     struct auth_serversupplied_info **server_info)
{
	/* if all the modules say 'not for me' this is reasonable */
	NTSTATUS nt_status;
	struct auth_method_context *method;
	const char *method_name = "NO METHOD";
	const uint8_t *challenge;
	struct auth_usersupplied_info *user_info_tmp; 

	DEBUG(3,   ("auth_check_password:  Checking password for unmapped user [%s]\\[%s]@[%s]\n", 
		    user_info->client.domain_name, user_info->client.account_name, user_info->workstation_name));

	if (!user_info->mapped_state) {
		nt_status = map_user_info(mem_ctx, user_info, &user_info_tmp);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
		user_info = user_info_tmp;
	}

	DEBUGADD(3,("auth_check_password:  mapped user is: [%s]\\[%s]@[%s]\n", 
		    user_info->mapped.domain_name, user_info->mapped.account_name, user_info->workstation_name));

	nt_status = auth_get_challenge(auth_ctx, &challenge);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("auth_check_password:  Invalid challenge (length %u) stored for this auth context set_by %s - cannot continue: %s\n",
			(unsigned)auth_ctx->challenge.data.length, auth_ctx->challenge.set_by, nt_errstr(nt_status)));
		return nt_status;
	}

	if (auth_ctx->challenge.set_by) {
		DEBUG(10, ("auth_check_password: auth_context challenge created by %s\n",
					auth_ctx->challenge.set_by));
	}

	DEBUG(10, ("challenge is: \n"));
	dump_data(5, auth_ctx->challenge.data.data, auth_ctx->challenge.data.length);

	nt_status = NT_STATUS_NO_SUCH_USER; /* If all the modules say 'not for me', then this is reasonable */
	for (method = auth_ctx->methods; method; method = method->next) {
		NTSTATUS result;

		result = method->ops->check_password(method, mem_ctx, user_info, server_info);

		/* check if the module did anything */
		if (!NT_STATUS_EQUAL(result, NT_STATUS_NOT_IMPLEMENTED)) {
			method_name = method->ops->name;
			nt_status = result;
			break;
		}

		DEBUG(11,("auth_check_password: %s had nothing to say\n", method->ops->name));
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(2,("auth_check_password: %s authentication for user [%s\\%s] FAILED with error %s\n", 
			 method_name, user_info->mapped.domain_name, user_info->mapped.account_name, 
			 nt_errstr(nt_status)));
		return nt_status;
	}

	DEBUG(5,("auth_check_password: %s authentication for user [%s\\%s] succeeded\n",
		 method_name, (*server_info)->domain_name, (*server_info)->account_name));

	return nt_status;
}

/***************************************************************************
 Make a auth_info struct for the auth subsystem
***************************************************************************/
NTSTATUS auth_context_create(TALLOC_CTX *mem_ctx, const char **methods, 
			     struct auth_context **auth_ctx,
			     struct event_context *ev) 
{
	int i;
	struct auth_context *ctx;

	if (!methods) {
		DEBUG(0,("auth_context_create: No auth method list!?\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	ctx = talloc(mem_ctx, struct auth_context);
	NT_STATUS_HAVE_NO_MEMORY(ctx);
	ctx->challenge.set_by		= NULL;
	ctx->challenge.may_be_modified	= False;
	ctx->challenge.data		= data_blob(NULL, 0);
	ctx->methods			= NULL;
	
	if (ev == NULL) {
		ev = event_context_init(ctx);
		if (ev == NULL) {
			talloc_free(ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	ctx->event_ctx = ev;

	for (i=0; methods[i] ; i++) {
		struct auth_method_context *method;

		method = talloc(ctx, struct auth_method_context);
		NT_STATUS_HAVE_NO_MEMORY(method);

		method->ops = auth_backend_byname(methods[i]);
		if (!method->ops) {
			DEBUG(1,("auth_context_create: failed to find method=%s\n",
				methods[i]));
			return NT_STATUS_INTERNAL_ERROR;
		}
		method->auth_ctx	= ctx;
		method->depth		= i;
		DLIST_ADD_END(ctx->methods, method, struct auth_method_context *);
	}

	if (!ctx->methods) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	*auth_ctx = ctx;

	return NT_STATUS_OK;
}

/* the list of currently registered AUTH backends */
static struct auth_backend {
	const struct auth_operations *ops;
} *backends = NULL;
static int num_backends;

/*
  register a AUTH backend. 

  The 'name' can be later used by other backends to find the operations
  structure for this backend.
*/
NTSTATUS auth_register(const void *_ops)
{
	const struct auth_operations *ops = _ops;
	struct auth_operations *new_ops;
	
	if (auth_backend_byname(ops->name) != NULL) {
		/* its already registered! */
		DEBUG(0,("AUTH backend '%s' already registered\n", 
			 ops->name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	backends = realloc_p(backends, struct auth_backend, num_backends+1);
	if (!backends) {
		return NT_STATUS_NO_MEMORY;
	}

	new_ops = smb_xmemdup(ops, sizeof(*ops));
	new_ops->name = smb_xstrdup(ops->name);

	backends[num_backends].ops = new_ops;

	num_backends++;

	DEBUG(3,("AUTH backend '%s' registered\n", 
		 ops->name));

	return NT_STATUS_OK;
}

/*
  return the operations structure for a named backend of the specified type
*/
const struct auth_operations *auth_backend_byname(const char *name)
{
	int i;

	for (i=0;i<num_backends;i++) {
		if (strcmp(backends[i].ops->name, name) == 0) {
			return backends[i].ops;
		}
	}

	return NULL;
}

/*
  return the AUTH interface version, and the size of some critical types
  This can be used by backends to either detect compilation errors, or provide
  multiple implementations for different smbd compilation options in one module
*/
const struct auth_critical_sizes *auth_interface_version(void)
{
	static const struct auth_critical_sizes critical_sizes = {
		AUTH_INTERFACE_VERSION,
		sizeof(struct auth_operations),
		sizeof(struct auth_method_context),
		sizeof(struct auth_context),
		sizeof(struct auth_usersupplied_info),
		sizeof(struct auth_serversupplied_info)
	};

	return &critical_sizes;
}

NTSTATUS auth_init(void)
{
	static BOOL initialized = False;

	init_module_fn static_init[] = STATIC_auth_MODULES;
	init_module_fn *shared_init;
	
	if (initialized) return NT_STATUS_OK;
	initialized = True;
	
	shared_init = load_samba_modules(NULL, "auth");

	run_init_functions(static_init);
	run_init_functions(shared_init);

	talloc_free(shared_init);
	
	return NT_STATUS_OK;	
}

NTSTATUS server_service_auth_init(void)
{
	return auth_init();
}
