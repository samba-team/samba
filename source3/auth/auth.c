/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett         2001-2002

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
#include "auth.h"
#include "../lib/tsocket/tsocket.h"

#include "param/param.h"
#include "../lib/messaging/messaging.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

static_decl_auth;

static struct auth_init_function_entry *auth_backends = NULL;

static struct auth_init_function_entry *auth_find_backend_entry(const char *name);

NTSTATUS smb_register_auth(int version, const char *name, auth_init_function init)
{
	struct auth_init_function_entry *entry = NULL;

	if (version != AUTH_INTERFACE_VERSION) {
		DEBUG(0,("Can't register auth_method!\n"
			 "You tried to register an auth module with AUTH_INTERFACE_VERSION %d, while this version of samba uses %d\n",
			 version,AUTH_INTERFACE_VERSION));
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!name || !init) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(5,("Attempting to register auth backend %s\n", name));

	if (auth_find_backend_entry(name)) {
		DEBUG(0,("There already is an auth method registered with the name %s!\n", name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = SMB_XMALLOC_P(struct auth_init_function_entry);
	entry->name = smb_xstrdup(name);
	entry->init = init;

	DLIST_ADD(auth_backends, entry);
	DEBUG(5,("Successfully added auth method '%s'\n", name));
	return NT_STATUS_OK;
}

static struct auth_init_function_entry *auth_find_backend_entry(const char *name)
{
	struct auth_init_function_entry *entry = auth_backends;

	while(entry) {
		if (strcmp(entry->name, name)==0) return entry;
		entry = entry->next;
	}

	return NULL;
}

/****************************************************************************
 Try to get a challenge out of the various authentication modules.
 Returns a const char of length 8 bytes.
****************************************************************************/

NTSTATUS auth_get_ntlm_challenge(struct auth_context *auth_context,
				 uint8_t chal[8])
{
	if (auth_context->challenge.length) {
		DEBUG(5, ("get_ntlm_challenge (auth subsystem): returning previous challenge by module %s (normal)\n", 
			  auth_context->challenge_set_by));
		memcpy(chal, auth_context->challenge.data, 8);
		return NT_STATUS_OK;
	}

	auth_context->challenge = data_blob_talloc(auth_context, NULL, 8);
	if (auth_context->challenge.data == NULL) {
		DBG_WARNING("data_blob_talloc failed\n");
		return NT_STATUS_NO_MEMORY;
	}
	generate_random_buffer(
		auth_context->challenge.data, auth_context->challenge.length);

	auth_context->challenge_set_by = "random";

	memcpy(chal, auth_context->challenge.data, 8);
	return NT_STATUS_OK;
}


/**
 * Check user is in correct domain (if required)
 *
 * @param user Only used to fill in the debug message
 * 
 * @param domain The domain to be verified
 *
 * @return True if the user can connect with that domain, 
 *         False otherwise.
**/

static bool check_domain_match(const char *user, const char *domain) 
{
	/*
	 * If we aren't serving to trusted domains, we must make sure that
	 * the validation request comes from an account in the same domain
	 * as the Samba server
	 */

	if (!lp_allow_trusted_domains() &&
	    !(strequal("", domain) || 
	      strequal(lp_workgroup(), domain) || 
	      is_myname(domain))) {
		DEBUG(1, ("check_domain_match: Attempt to connect as user %s from domain %s denied.\n", user, domain));
		return False;
	} else {
		return True;
	}
}

/**
 * Check a user's Plaintext, LM or NTLM password.
 *
 * Check a user's password, as given in the user_info struct and return various
 * interesting details in the server_info struct.
 *
 * This function does NOT need to be in a become_root()/unbecome_root() pair
 * as it makes the calls itself when needed.
 *
 * The return value takes precedence over the contents of the server_info 
 * struct.  When the return is other than NT_STATUS_OK the contents 
 * of that structure is undefined.
 *
 * @param user_info Contains the user supplied components, including the passwords.
 *                  Must be created with make_user_info() or one of its wrappers.
 *
 * @param auth_context Supplies the challenges and some other data. 
 *                  Must be created with make_auth_context(), and the challenges should be 
 *                  filled in, either at creation or by calling the challenge geneation 
 *                  function auth_get_challenge().  
 *
 * @param pserver_info If successful, contains information about the authentication,
 *                     including a struct samu struct describing the user.
 *
 * @param pauthoritative Indicates if the result should be treated as final
 *                       result.
 *
 * @return An NTSTATUS with NT_STATUS_OK or an appropriate error.
 *
 **/
NTSTATUS auth_check_ntlm_password(TALLOC_CTX *mem_ctx,
				  const struct auth_context *auth_context,
				  const struct auth_usersupplied_info *user_info,
				  struct auth_serversupplied_info **pserver_info,
				  uint8_t *pauthoritative)
{
	TALLOC_CTX *frame;
	const char *auth_method_name = "";
	/* if all the modules say 'not for me' this is reasonable */
	NTSTATUS nt_status = NT_STATUS_NOT_IMPLEMENTED;
	const char *unix_username;
	struct auth_methods *auth_method;
	struct auth_serversupplied_info *server_info = NULL;
	struct dom_sid sid = {0};
	struct imessaging_context *msg_ctx = NULL;
	struct loadparm_context *lp_ctx = NULL;

	if (user_info == NULL || auth_context == NULL || pserver_info == NULL) {
		return NT_STATUS_LOGON_FAILURE;
	}

	frame = talloc_stackframe();

	if (lp_auth_event_notification()) {
		lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
		msg_ctx = imessaging_client_init(
		    frame, lp_ctx, global_event_context());
	}

	*pauthoritative = 1;

	DEBUG(3, ("check_ntlm_password:  Checking password for unmapped user [%s]\\[%s]@[%s] with the new password interface\n", 
		  user_info->client.domain_name, user_info->client.account_name, user_info->workstation_name));

	DEBUG(3, ("check_ntlm_password:  mapped user is: [%s]\\[%s]@[%s]\n", 
		  user_info->mapped.domain_name, user_info->mapped.account_name, user_info->workstation_name));

	if (auth_context->challenge.length != 8) {
		DEBUG(0, ("check_ntlm_password:  Invalid challenge stored for this auth context - cannot continue\n"));
		nt_status = NT_STATUS_LOGON_FAILURE;
		goto fail;
	}

	if (auth_context->challenge_set_by)
		DEBUG(10, ("check_ntlm_password: auth_context challenge created by %s\n",
					auth_context->challenge_set_by));

	DEBUG(10, ("challenge is: \n"));
	dump_data(5, auth_context->challenge.data, auth_context->challenge.length);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("user_info has passwords of length %d and %d\n", 
		    (int)user_info->password.response.lanman.length, (int)user_info->password.response.nt.length));
	DEBUG(100, ("lm:\n"));
	dump_data(100, user_info->password.response.lanman.data, user_info->password.response.lanman.length);
	DEBUG(100, ("nt:\n"));
	dump_data(100, user_info->password.response.nt.data, user_info->password.response.nt.length);
#endif

	/* This needs to be sorted:  If it doesn't match, what should we do? */
	if (!check_domain_match(user_info->client.account_name,
				user_info->mapped.domain_name)) {
		nt_status = NT_STATUS_LOGON_FAILURE;
		goto fail;
	}

	for (auth_method = auth_context->auth_method_list;auth_method; auth_method = auth_method->next) {

		auth_method_name = auth_method->name;

		nt_status = auth_method->auth(auth_context,
					      auth_method->private_data,
					      talloc_tos(),
					      user_info,
					      &server_info);

		if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_NOT_IMPLEMENTED)) {
			break;
		}

		DBG_DEBUG("%s had nothing to say\n", auth_method->name);
	}

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NOT_IMPLEMENTED)) {
		*pauthoritative = 0;
		nt_status = NT_STATUS_NO_SUCH_USER;
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_INFO("%s authentication for user [%s] FAILED with "
			 "error %s, authoritative=%u\n",
			 auth_method_name,
			 user_info->client.account_name,
			 nt_errstr(nt_status),
			 *pauthoritative);
		goto fail;
	}

	DBG_NOTICE("%s authentication for user [%s] succeeded\n",
		   auth_method_name, user_info->client.account_name);

	unix_username = server_info->unix_name;

	/* We skip doing this step if the caller asked us not to */
	if (!(user_info->flags & USER_INFO_INFO3_AND_NO_AUTHZ)
	    && !(server_info->guest)) {
		const char *rhost;

		if (tsocket_address_is_inet(user_info->remote_host, "ip")) {
			rhost = tsocket_address_inet_addr_string(
				user_info->remote_host, talloc_tos());
			if (rhost == NULL) {
				nt_status = NT_STATUS_NO_MEMORY;
				goto fail;
			}
		} else {
			rhost = "127.0.0.1";
		}

		/* We might not be root if we are an RPC call */
		become_root();
		nt_status = smb_pam_accountcheck(unix_username, rhost);
		unbecome_root();

		if (NT_STATUS_IS_OK(nt_status)) {
			DEBUG(5, ("check_ntlm_password:  PAM Account for user [%s] "
				  "succeeded\n", unix_username));
		} else {
			DEBUG(3, ("check_ntlm_password:  PAM Account for user [%s] "
				  "FAILED with error %s\n",
				  unix_username, nt_errstr(nt_status)));
		}
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		goto fail;
	}

	nt_status = get_user_sid_info3_and_extra(server_info->info3,
						 &server_info->extra,
						 &sid);
	if (!NT_STATUS_IS_OK(nt_status)) {
		sid = (struct dom_sid) {0};
	}

	log_authentication_event(msg_ctx,
				 lp_ctx,
				 &auth_context->start_time,
				 user_info,
				 nt_status,
				 server_info->info3->base.logon_domain.string,
				 server_info->info3->base.account_name.string,
				 &sid);

	DEBUG(server_info->guest ? 5 : 2,
	      ("check_ntlm_password:  %sauthentication for user "
	       "[%s] -> [%s] -> [%s] succeeded\n",
	       server_info->guest ? "guest " : "",
	       user_info->client.account_name,
	       user_info->mapped.account_name,
	       unix_username));

	*pserver_info = talloc_move(mem_ctx, &server_info);

	TALLOC_FREE(frame);
	return NT_STATUS_OK;

fail:

	/* failed authentication; check for guest lapping */

	/*
	 * Please try not to change this string, it is probably in use
	 * in audit logging tools
	 */
	DEBUG(2, ("check_ntlm_password:  Authentication for user "
		  "[%s] -> [%s] FAILED with error %s, authoritative=%u\n",
		  user_info->client.account_name, user_info->mapped.account_name,
		  nt_errstr(nt_status), *pauthoritative));

	log_authentication_event(msg_ctx,
				 lp_ctx,
				 &auth_context->start_time,
				 user_info,
				 nt_status,
				 NULL,
				 NULL,
				 NULL);

	ZERO_STRUCTP(pserver_info);

	TALLOC_FREE(frame);

	return nt_status;
}

/***************************************************************************
 Clear out a auth_context, and destroy the attached TALLOC_CTX
***************************************************************************/

static int auth_context_destructor(void *ptr)
{
	struct auth_context *ctx = talloc_get_type(ptr, struct auth_context);
	struct auth_methods *am;


	/* Free private data of context's authentication methods */
	for (am = ctx->auth_method_list; am; am = am->next) {
		TALLOC_FREE(am->private_data);
	}

	return 0;
}

/***************************************************************************
 Make a auth_info struct
***************************************************************************/

static NTSTATUS make_auth_context(TALLOC_CTX *mem_ctx,
				  struct auth_context **auth_context)
{
	struct auth_context *ctx;

	ctx = talloc_zero(mem_ctx, struct auth_context);
	if (!ctx) {
		DEBUG(0,("make_auth_context: talloc failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ctx->start_time = timeval_current();

	talloc_set_destructor((TALLOC_CTX *)ctx, auth_context_destructor);

	*auth_context = ctx;
	return NT_STATUS_OK;
}

bool load_auth_module(struct auth_context *auth_context, 
		      const char *module,
		      struct auth_methods **ret)
{
	static bool initialised_static_modules = False;

	struct auth_init_function_entry *entry;
	char *module_name = smb_xstrdup(module);
	char *module_params = NULL;
	char *p;
	bool good = False;

	/* Initialise static modules if not done so yet */
	if(!initialised_static_modules) {
		static_init_auth(NULL);
		initialised_static_modules = True;
	}

	DEBUG(5,("load_auth_module: Attempting to find an auth method to match %s\n",
		 module));

	p = strchr(module_name, ':');
	if (p) {
		*p = 0;
		module_params = p+1;
		trim_char(module_params, ' ', ' ');
	}

	trim_char(module_name, ' ', ' ');

	entry = auth_find_backend_entry(module_name);

	if (entry == NULL) {
		if (NT_STATUS_IS_OK(smb_probe_module("auth", module_name))) {
			entry = auth_find_backend_entry(module_name);
		}
	}

	if (entry != NULL) {
		if (!NT_STATUS_IS_OK(entry->init(auth_context, module_params, ret))) {
			DEBUG(0,("load_auth_module: auth method %s did not correctly init\n",
				 module_name));
		} else {
			DEBUG(5,("load_auth_module: auth method %s has a valid init\n",
				 module_name));
			good = True;
		}
	} else {
		DEBUG(0,("load_auth_module: can't find auth method %s!\n", module_name));
	}

	SAFE_FREE(module_name);
	return good;
}

/***************************************************************************
 Make a auth_info struct for the auth subsystem
***************************************************************************/

static NTSTATUS make_auth_context_text_list(TALLOC_CTX *mem_ctx,
					    struct auth_context **auth_context,
					    char **text_list)
{
	struct auth_methods *list = NULL;
	struct auth_methods *t, *method = NULL;
	NTSTATUS nt_status;

	if (!text_list) {
		DEBUG(2,("make_auth_context_text_list: No auth method list!?\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	nt_status = make_auth_context(mem_ctx, auth_context);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	for (;*text_list; text_list++) { 
		if (load_auth_module(*auth_context, *text_list, &t)) {
		    DLIST_ADD_END(list, t);
		}
	}

	(*auth_context)->auth_method_list = list;

	/* Look for the first module to provide a prepare_gensec and
	 * make_auth4_context hook, and set that if provided */
	for (method = (*auth_context)->auth_method_list; method; method = method->next) {
		if (method->prepare_gensec && method->make_auth4_context) {
			(*auth_context)->prepare_gensec = method->prepare_gensec;
			(*auth_context)->make_auth4_context = method->make_auth4_context;
			break;
		}
	}
	return NT_STATUS_OK;
}

static NTSTATUS make_auth_context_specific(TALLOC_CTX *mem_ctx,
					   struct auth_context **auth_context,
					   const char *methods)
{
	char **method_list;
	NTSTATUS status;

	method_list = str_list_make_v3(talloc_tos(), methods, NULL);
	if (method_list == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = make_auth_context_text_list(
		mem_ctx, auth_context, method_list);

	TALLOC_FREE(method_list);

	return status;
}

/***************************************************************************
 Make a auth_context struct for the auth subsystem
***************************************************************************/

NTSTATUS make_auth3_context_for_ntlm(TALLOC_CTX *mem_ctx,
				     struct auth_context **auth_context)
{
	const char *methods = NULL;

	switch (lp_server_role()) {
	case ROLE_ACTIVE_DIRECTORY_DC:
		DEBUG(5,("Making default auth method list for server role = "
			 "'active directory domain controller'\n"));
		methods = "samba4";
		break;
	case ROLE_DOMAIN_MEMBER:
		DEBUG(5,("Making default auth method list for server role = 'domain member'\n"));
		methods = "anonymous sam winbind sam_ignoredomain";
		break;
	case ROLE_DOMAIN_BDC:
	case ROLE_DOMAIN_PDC:
		DEBUG(5,("Making default auth method list for DC\n"));
		methods = "anonymous sam winbind sam_ignoredomain";
		break;
	case ROLE_STANDALONE:
		DEBUG(5,("Making default auth method list for server role = 'standalone server', encrypt passwords = yes\n"));
		if (lp_encrypt_passwords()) {
			methods = "anonymous sam_ignoredomain";
		} else {
			DEBUG(5,("Making default auth method list for server role = 'standalone server', encrypt passwords = no\n"));
			methods = "anonymous unix";
		}
		break;
	default:
		DEBUG(5,("Unknown auth method!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return make_auth_context_specific(mem_ctx, auth_context, methods);
}

NTSTATUS make_auth3_context_for_netlogon(TALLOC_CTX *mem_ctx,
					 struct auth_context **auth_context)
{
	const char *methods = NULL;

	switch (lp_server_role()) {
	case ROLE_DOMAIN_BDC:
	case ROLE_DOMAIN_PDC:
		methods = "sam_netlogon3 winbind";
		break;

	default:
		DBG_ERR("Invalid server role!\n");
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	return make_auth_context_specific(mem_ctx, auth_context, methods);
}

NTSTATUS make_auth3_context_for_winbind(TALLOC_CTX *mem_ctx,
				        struct auth_context **auth_context)
{
	const char *methods = NULL;

	switch (lp_server_role()) {
	case ROLE_STANDALONE:
	case ROLE_DOMAIN_MEMBER:
	case ROLE_DOMAIN_BDC:
	case ROLE_DOMAIN_PDC:
		methods = "sam";
		break;
	case ROLE_ACTIVE_DIRECTORY_DC:
		methods = "samba4:sam";
		break;
	default:
		DEBUG(5,("Unknown auth method!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return make_auth_context_specific(mem_ctx, auth_context, methods);
}

bool auth3_context_set_challenge(struct auth_context *ctx, uint8_t chal[8],
				 const char *challenge_set_by)
{
	ctx->challenge = data_blob_talloc(ctx, chal, 8);
	if (ctx->challenge.data == NULL) {
		return false;
	}
	ctx->challenge_set_by = talloc_strdup(ctx, challenge_set_by);
	if (ctx->challenge_set_by == NULL) {
		return false;
	}
	return true;
}
