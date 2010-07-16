/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett         2001-2002
   Copyright (C) Stefan Metzmacher       2005
   
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

#include "includes.h"
#include <tevent.h>
#include "../lib/util/tevent_ntstatus.h"
#include "../lib/util/dlinklist.h"
#include "auth/auth.h"
#include "auth/ntlm/auth_proto.h"
#include "param/param.h"
#include "dsdb/samdb/samdb.h"


/***************************************************************************
 Set a fixed challenge
***************************************************************************/
_PUBLIC_ NTSTATUS auth_context_set_challenge(struct auth_context *auth_ctx, const uint8_t chal[8], const char *set_by) 
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
_PUBLIC_ bool auth_challenge_may_be_modified(struct auth_context *auth_ctx)
{
	return auth_ctx->challenge.may_be_modified;
}

/****************************************************************************
 Try to get a challenge out of the various authentication modules.
 Returns a const char of length 8 bytes.
****************************************************************************/
_PUBLIC_ NTSTATUS auth_get_challenge(struct auth_context *auth_ctx, uint8_t chal[8])
{
	NTSTATUS nt_status;
	struct auth_method_context *method;

	if (auth_ctx->challenge.data.length == 8) {
		DEBUG(5, ("auth_get_challenge: returning previous challenge by module %s (normal)\n", 
			  auth_ctx->challenge.set_by));
		memcpy(chal, auth_ctx->challenge.data.data, 8);
		return NT_STATUS_OK;
	}

	for (method = auth_ctx->methods; method; method = method->next) {
		nt_status = method->ops->get_challenge(method, auth_ctx, chal);
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NOT_IMPLEMENTED)) {
			continue;
		}

		NT_STATUS_NOT_OK_RETURN(nt_status);

		auth_ctx->challenge.data	= data_blob_talloc(auth_ctx, chal, 8);
		NT_STATUS_HAVE_NO_MEMORY(auth_ctx->challenge.data.data);
		auth_ctx->challenge.set_by	= method->ops->name;

		break;
	}

	if (!auth_ctx->challenge.set_by) {
		generate_random_buffer(chal, 8);

		auth_ctx->challenge.data		= data_blob_talloc(auth_ctx, chal, 8);
		NT_STATUS_HAVE_NO_MEMORY(auth_ctx->challenge.data.data);
		auth_ctx->challenge.set_by		= "random";

		auth_ctx->challenge.may_be_modified	= true;
	}

	DEBUG(10,("auth_get_challenge: challenge set by %s\n",
		 auth_ctx->challenge.set_by));

	return NT_STATUS_OK;
}

/****************************************************************************
Used in the gensec_gssapi and gensec_krb5 server-side code, where the
PAC isn't available, and for tokenGroups in the DSDB stack.

 Supply either a principal or a DN
****************************************************************************/
_PUBLIC_ NTSTATUS auth_get_server_info_principal(TALLOC_CTX *mem_ctx, 
						 struct auth_context *auth_ctx,
						 const char *principal,
						 struct ldb_dn *user_dn,
						 struct auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status;
	struct auth_method_context *method;

	for (method = auth_ctx->methods; method; method = method->next) {
		if (!method->ops->get_server_info_principal) {
			continue;
		}

		nt_status = method->ops->get_server_info_principal(mem_ctx, auth_ctx, principal, user_dn, server_info);
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NOT_IMPLEMENTED)) {
			continue;
		}

		NT_STATUS_NOT_OK_RETURN(nt_status);

		break;
	}

	return NT_STATUS_OK;
}

/**
 * Check a user's Plaintext, LM or NTLM password.
 * (sync version)
 *
 * Check a user's password, as given in the user_info struct and return various
 * interesting details in the server_info struct.
 *
 * The return value takes precedence over the contents of the server_info 
 * struct.  When the return is other than NT_STATUS_OK the contents 
 * of that structure is undefined.
 *
 * @param auth_ctx Supplies the challenges and some other data. 
 *                  Must be created with auth_context_create(), and the challenges should be 
 *                  filled in, either at creation or by calling the challenge geneation 
 *                  function auth_get_challenge().  
 *
 * @param user_info Contains the user supplied components, including the passwords.
 *
 * @param mem_ctx The parent memory context for the server_info structure
 *
 * @param server_info If successful, contains information about the authentication, 
 *                    including a SAM_ACCOUNT struct describing the user.
 *
 * @return An NTSTATUS with NT_STATUS_OK or an appropriate error.
 *
 **/

_PUBLIC_ NTSTATUS auth_check_password(struct auth_context *auth_ctx,
			     TALLOC_CTX *mem_ctx,
			     const struct auth_usersupplied_info *user_info, 
			     struct auth_serversupplied_info **server_info)
{
	struct tevent_req *subreq;
	struct tevent_context *ev;
	bool ok;
	NTSTATUS status;

	/*TODO: create a new event context here! */
	ev = auth_ctx->event_ctx;

	subreq = auth_check_password_send(mem_ctx,
					  ev,
					  auth_ctx,
					  user_info);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = auth_check_password_recv(subreq, mem_ctx, server_info);
	TALLOC_FREE(subreq);

	return status;
}

struct auth_check_password_state {
	struct auth_context *auth_ctx;
	const struct auth_usersupplied_info *user_info;
	struct auth_serversupplied_info *server_info;
	struct auth_method_context *method;
};

static void auth_check_password_async_trigger(struct tevent_context *ev,
					      struct tevent_immediate *im,
					      void *private_data);
/**
 * Check a user's Plaintext, LM or NTLM password.
 * async send hook
 *
 * Check a user's password, as given in the user_info struct and return various
 * interesting details in the server_info struct.
 *
 * The return value takes precedence over the contents of the server_info 
 * struct.  When the return is other than NT_STATUS_OK the contents 
 * of that structure is undefined.
 *
 * @param mem_ctx The memory context the request should operate on
 *
 * @param ev The tevent context the request should operate on
 *
 * @param auth_ctx Supplies the challenges and some other data. 
 *                  Must be created with make_auth_context(), and the challenges should be 
 *                  filled in, either at creation or by calling the challenge geneation 
 *                  function auth_get_challenge().  
 *
 * @param user_info Contains the user supplied components, including the passwords.
 *
 * @return The request handle or NULL on no memory error.
 *
 **/

_PUBLIC_ struct tevent_req *auth_check_password_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct auth_context *auth_ctx,
				const struct auth_usersupplied_info *user_info)
{
	struct tevent_req *req;
	struct auth_check_password_state *state;
	/* if all the modules say 'not for me' this is reasonable */
	NTSTATUS nt_status;
	struct auth_method_context *method;
	uint8_t chal[8];
	struct auth_usersupplied_info *user_info_tmp;
	struct tevent_immediate *im;

	DEBUG(3,("auth_check_password_send: "
		 "Checking password for unmapped user [%s]\\[%s]@[%s]\n",
		 user_info->client.domain_name, user_info->client.account_name,
		 user_info->workstation_name));

	req = tevent_req_create(mem_ctx, &state,
				struct auth_check_password_state);
	if (req == NULL) {
		return NULL;
	}

	state->auth_ctx		= auth_ctx;
	state->user_info	= user_info;
	state->method		= NULL;

	if (!user_info->mapped_state) {
		nt_status = map_user_info(req, lpcfg_workgroup(auth_ctx->lp_ctx),
					  user_info, &user_info_tmp);
		if (tevent_req_nterror(req, nt_status)) {
			return tevent_req_post(req, ev);
		}
		user_info = user_info_tmp;
		state->user_info = user_info_tmp;
	}

	DEBUGADD(3,("auth_check_password_send: "
		    "mapped user is: [%s]\\[%s]@[%s]\n",
		    user_info->mapped.domain_name,
		    user_info->mapped.account_name,
		    user_info->workstation_name));

	nt_status = auth_get_challenge(auth_ctx, chal);
	if (tevent_req_nterror(req, nt_status)) {
		DEBUG(0,("auth_check_password_send: "
			 "Invalid challenge (length %u) stored for "
			 "this auth context set_by %s - cannot continue: %s\n",
			(unsigned)auth_ctx->challenge.data.length,
			auth_ctx->challenge.set_by,
			nt_errstr(nt_status)));
		return tevent_req_post(req, ev);
	}

	if (auth_ctx->challenge.set_by) {
		DEBUG(10,("auth_check_password_send: "
			  "auth_context challenge created by %s\n",
			  auth_ctx->challenge.set_by));
	}

	DEBUG(10, ("auth_check_password_send: challenge is: \n"));
	dump_data(5, auth_ctx->challenge.data.data,
		  auth_ctx->challenge.data.length);

	im = tevent_create_immediate(state);
	if (tevent_req_nomem(im, req)) {
		return tevent_req_post(req, ev);
	}

	for (method = auth_ctx->methods; method; method = method->next) {
		NTSTATUS result;

		/* check if the module wants to chek the password */
		result = method->ops->want_check(method, req, user_info);
		if (NT_STATUS_EQUAL(result, NT_STATUS_NOT_IMPLEMENTED)) {
			DEBUG(11,("auth_check_password_send: "
				  "%s had nothing to say\n",
				  method->ops->name));
			continue;
		}

		state->method = method;

		if (tevent_req_nterror(req, result)) {
			return tevent_req_post(req, ev);
		}

		tevent_schedule_immediate(im,
					  auth_ctx->event_ctx,
					  auth_check_password_async_trigger,
					  req);

		return req;
	}

	/* If all the modules say 'not for me', then this is reasonable */
	tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
	return tevent_req_post(req, ev);
}

static void auth_check_password_async_trigger(struct tevent_context *ev,
					      struct tevent_immediate *im,
					      void *private_data)
{
	struct tevent_req *req =
		talloc_get_type_abort(private_data, struct tevent_req);
	struct auth_check_password_state *state =
		tevent_req_data(req, struct auth_check_password_state);
	NTSTATUS status;

	status = state->method->ops->check_password(state->method,
						    state,
						    state->user_info,
						    &state->server_info);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

/**
 * Check a user's Plaintext, LM or NTLM password.
 * async receive function
 *
 * The return value takes precedence over the contents of the server_info 
 * struct.  When the return is other than NT_STATUS_OK the contents 
 * of that structure is undefined.
 *
 *
 * @param req The async request state
 *
 * @param mem_ctx The parent memory context for the server_info structure
 *
 * @param server_info If successful, contains information about the authentication, 
 *                    including a SAM_ACCOUNT struct describing the user.
 *
 * @return An NTSTATUS with NT_STATUS_OK or an appropriate error.
 *
 **/

_PUBLIC_ NTSTATUS auth_check_password_recv(struct tevent_req *req,
				  TALLOC_CTX *mem_ctx,
				  struct auth_serversupplied_info **server_info)
{
	struct auth_check_password_state *state =
		tevent_req_data(req, struct auth_check_password_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		DEBUG(2,("auth_check_password_recv: "
			 "%s authentication for user [%s\\%s]"
			 "FAILED with error %s\n",
			 (state->method ? state->method->ops->name : "NO_METHOD"),
			 state->user_info->mapped.domain_name,
			 state->user_info->mapped.account_name,
			 nt_errstr(status)));
		tevent_req_received(req);
		return status;
	}

	DEBUG(5,("auth_check_password_recv: "
		 "%s authentication for user [%s\\%s] succeeded\n",
		 state->method->ops->name,
		 state->server_info->domain_name,
		 state->server_info->account_name));

	*server_info = talloc_move(mem_ctx, &state->server_info);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

/***************************************************************************
 Make a auth_info struct for the auth subsystem
 - Allow the caller to specify the methods to use, including optionally the SAM to use
***************************************************************************/
_PUBLIC_ NTSTATUS auth_context_create_methods(TALLOC_CTX *mem_ctx, const char **methods, 
					      struct tevent_context *ev,
					      struct messaging_context *msg,
					      struct loadparm_context *lp_ctx,
					      struct ldb_context *sam_ctx,
					      struct auth_context **auth_ctx)
{
	int i;
	struct auth_context *ctx;

	auth_init();

	if (!methods) {
		DEBUG(0,("auth_context_create: No auth method list!?\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (!ev) {
		DEBUG(0,("auth_context_create: called with out event context\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	ctx = talloc(mem_ctx, struct auth_context);
	NT_STATUS_HAVE_NO_MEMORY(ctx);
	ctx->challenge.set_by		= NULL;
	ctx->challenge.may_be_modified	= false;
	ctx->challenge.data		= data_blob(NULL, 0);
	ctx->methods			= NULL;
	ctx->event_ctx			= ev;
	ctx->msg_ctx			= msg;
	ctx->lp_ctx			= lp_ctx;

	if (sam_ctx) {
		ctx->sam_ctx = sam_ctx;
	} else {
		ctx->sam_ctx = samdb_connect(ctx, ctx->event_ctx, ctx->lp_ctx, system_session(ctx->lp_ctx));
	}

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

	ctx->check_password = auth_check_password;
	ctx->get_challenge = auth_get_challenge;
	ctx->set_challenge = auth_context_set_challenge;
	ctx->challenge_may_be_modified = auth_challenge_may_be_modified;
	ctx->get_server_info_principal = auth_get_server_info_principal;
	ctx->generate_session_info = auth_generate_session_info;

	*auth_ctx = ctx;

	return NT_STATUS_OK;
}

static const char **auth_methods_from_lp(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	const char **auth_methods = NULL;
	switch (lpcfg_server_role(lp_ctx)) {
	case ROLE_STANDALONE:
		auth_methods = lpcfg_parm_string_list(mem_ctx, lp_ctx, NULL, "auth methods", "standalone", NULL);
		break;
	case ROLE_DOMAIN_MEMBER:
		auth_methods = lpcfg_parm_string_list(mem_ctx, lp_ctx, NULL, "auth methods", "member server", NULL);
		break;
	case ROLE_DOMAIN_CONTROLLER:
		auth_methods = lpcfg_parm_string_list(mem_ctx, lp_ctx, NULL, "auth methods", "domain controller", NULL);
		break;
	}
	return auth_methods;
}

/***************************************************************************
 Make a auth_info struct for the auth subsystem
 - Uses default auth_methods, depending on server role and smb.conf settings
***************************************************************************/
_PUBLIC_ NTSTATUS auth_context_create(TALLOC_CTX *mem_ctx,
			     struct tevent_context *ev,
			     struct messaging_context *msg,
			     struct loadparm_context *lp_ctx,
			     struct auth_context **auth_ctx)
{
	NTSTATUS status;
	const char **auth_methods;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	auth_methods = auth_methods_from_lp(tmp_ctx, lp_ctx);
	if (!auth_methods) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	status = auth_context_create_methods(mem_ctx, auth_methods, ev, msg, lp_ctx, NULL, auth_ctx);
	talloc_free(tmp_ctx);
	return status;
}

/* Create an auth context from an open LDB.

   This allows us not to re-open the LDB when we need to do a some authentication logic (such as tokenGroups)

 */
NTSTATUS auth_context_create_from_ldb(TALLOC_CTX *mem_ctx, struct ldb_context *ldb, struct auth_context **auth_ctx)
{
	NTSTATUS status;
	const char **auth_methods;
	struct loadparm_context *lp_ctx = talloc_get_type_abort(ldb_get_opaque(ldb, "loadparm"), struct loadparm_context);
	struct tevent_context *ev = ldb_get_event_context(ldb);

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	auth_methods = auth_methods_from_lp(tmp_ctx, lp_ctx);
	if (!auth_methods) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	status = auth_context_create_methods(mem_ctx, auth_methods, ev, NULL, lp_ctx, ldb, auth_ctx);
	talloc_free(tmp_ctx);
	return status;
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
_PUBLIC_ NTSTATUS auth_register(const struct auth_operations *ops)
{
	struct auth_operations *new_ops;
	
	if (auth_backend_byname(ops->name) != NULL) {
		/* its already registered! */
		DEBUG(0,("AUTH backend '%s' already registered\n", 
			 ops->name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	backends = talloc_realloc(talloc_autofree_context(), backends, 
				  struct auth_backend, num_backends+1);
	NT_STATUS_HAVE_NO_MEMORY(backends);

	new_ops = (struct auth_operations *)talloc_memdup(backends, ops, sizeof(*ops));
	NT_STATUS_HAVE_NO_MEMORY(new_ops);
	new_ops->name = talloc_strdup(new_ops, ops->name);
	NT_STATUS_HAVE_NO_MEMORY(new_ops->name);

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

_PUBLIC_ NTSTATUS auth_init(void)
{
	static bool initialized = false;
	extern NTSTATUS auth_developer_init(void);
	extern NTSTATUS auth_winbind_init(void);
	extern NTSTATUS auth_anonymous_init(void);
	extern NTSTATUS auth_unix_init(void);
	extern NTSTATUS auth_sam_init(void);
	extern NTSTATUS auth_server_init(void);

	init_module_fn static_init[] = { STATIC_auth_MODULES };
	
	if (initialized) return NT_STATUS_OK;
	initialized = true;
	
	run_init_functions(static_init);
	
	return NT_STATUS_OK;	
}
