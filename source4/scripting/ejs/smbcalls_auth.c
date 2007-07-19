/* 
   Unix SMB/CIFS implementation.

   ejs auth functions

   Copyright (C) Simo Sorce 2005
   Copyright (C) Andrew Tridgell 2005
   
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
#include "lib/appweb/ejs/ejs.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "scripting/ejs/smbcalls.h"
#include "lib/events/events.h"
#include "lib/messaging/irpc.h"
#include "libcli/security/security.h"

static int ejs_doauth(MprVarHandle eid,
		      TALLOC_CTX *tmp_ctx, struct MprVar *auth, const char *username, 
		      const char *password, const char *domain, const char *workstation,
		      struct socket_address *remote_host, const char **auth_types)
{
	struct auth_usersupplied_info *user_info = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_session_info *session_info = NULL;
	struct auth_context *auth_context;
	struct MprVar *session_info_obj;
	NTSTATUS nt_status;
	bool set;

	struct smbcalls_context *c;
	struct event_context *ev;
	struct messaging_context *msg;

	/* Hope we can find an smbcalls_context somewhere up there... */
	c = talloc_find_parent_bytype(tmp_ctx, struct smbcalls_context);
	if (c) {
		ev = c->event_ctx;
		msg = c->msg_ctx;
	} else {
		/* Hope we can find the event context somewhere up there... */
		ev = event_context_find(tmp_ctx);
		msg = messaging_client_init(tmp_ctx, ev);
	}

	if (auth_types) {
		nt_status = auth_context_create_methods(tmp_ctx, auth_types, ev, msg, &auth_context);
	} else {
		nt_status = auth_context_create(tmp_ctx, ev, msg, &auth_context);
	}
	if (!NT_STATUS_IS_OK(nt_status)) {
		mprSetPropertyValue(auth, "result", mprCreateBoolVar(False));
		mprSetPropertyValue(auth, "report", mprString("Auth System Failure"));
		goto done;
	}

	user_info = talloc(tmp_ctx, struct auth_usersupplied_info);
	if (!user_info) {
		mprSetPropertyValue(auth, "result", mprCreateBoolVar(False));
		mprSetPropertyValue(auth, "report", mprString("talloc failed"));
		goto done;
	}

	user_info->mapped_state = True;
	user_info->client.account_name = username;
	user_info->mapped.account_name = username;
	user_info->client.domain_name = domain;
	user_info->mapped.domain_name = domain;

	user_info->workstation_name = workstation;

	user_info->remote_host = remote_host;

	user_info->password_state = AUTH_PASSWORD_PLAIN;
	user_info->password.plaintext = talloc_strdup(user_info, password);

	user_info->flags = USER_INFO_CASE_INSENSITIVE_USERNAME |
		USER_INFO_DONT_CHECK_UNIX_ACCOUNT;

	user_info->logon_parameters = 0;

	nt_status = auth_check_password(auth_context, tmp_ctx, user_info, &server_info);

	/* Don't give the game away (any difference between no such
	 * user and wrong password) */
	nt_status = auth_nt_status_squash(nt_status);

	if (!NT_STATUS_IS_OK(nt_status)) {
		mprSetPropertyValue(auth, "report", 
				    mprString(talloc_strdup(mprMemCtx(), get_friendly_nt_error_msg(nt_status))));
		mprSetPropertyValue(auth, "result", mprCreateBoolVar(False));
		goto done;
	}

	nt_status = auth_generate_session_info(tmp_ctx, server_info, &session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		mprSetPropertyValue(auth, "report", mprString("Session Info generation failed"));
		mprSetPropertyValue(auth, "result", mprCreateBoolVar(False));
		goto done;
	}

	if (security_token_has_nt_authenticated_users(session_info->security_token)) {
		mprSetPropertyValue(auth, "user_class", mprString("USER"));
		set = true;
	}
	
	if (security_token_has_builtin_administrators(session_info->security_token)) {
		mprSetPropertyValue(auth, "user_class", mprString("ADMINISTRATOR"));
		set = true;
	}

	if (security_token_is_system(session_info->security_token)) {
		mprSetPropertyValue(auth, "user_class", mprString("SYSTEM"));
		set = true;
	}

	if (security_token_is_anonymous(session_info->security_token)) {
		mprSetPropertyValue(auth, "report", mprString("Anonymous login not permitted"));
		mprSetPropertyValue(auth, "result", mprCreateBoolVar(False));
		goto done;
	}

	if (!set) {
		mprSetPropertyValue(auth, "report", mprString("Session Info generation failed"));
		mprSetPropertyValue(auth, "result", mprCreateBoolVar(False));
	}
	
	session_info_obj = mprInitObject(eid, "session_info", 0, NULL);

	mprSetPtrChild(session_info_obj, "session_info", session_info);
	talloc_steal(mprMemCtx(), session_info);

	mprSetProperty(auth, "session_info", session_info_obj);
	mprSetPropertyValue(auth, "result", mprCreateBoolVar(server_info->authenticated));
	mprSetPropertyValue(auth, "username", mprString(server_info->account_name));
	mprSetPropertyValue(auth, "domain", mprString(server_info->domain_name));

	if (security_token_is_system(session_info->security_token)) {
		mprSetPropertyValue(auth, "report", mprString("SYSTEM"));
	}

	if (security_token_is_anonymous(session_info->security_token)) {
		mprSetPropertyValue(auth, "report", mprString("ANONYMOUS"));
	}

	if (security_token_has_builtin_administrators(session_info->security_token)) {
		mprSetPropertyValue(auth, "report", mprString("ADMINISTRATOR"));
	}

	if (security_token_has_nt_authenticated_users(session_info->security_token)) {
		mprSetPropertyValue(auth, "report", mprString("USER"));
	}


done:
	return 0;
}

/*
  perform user authentication, returning an array of results

*/
static int ejs_userAuth(MprVarHandle eid, int argc, struct MprVar **argv)
{
	TALLOC_CTX *tmp_ctx;
	const char *username;
	const char *password;
	const char *domain;
	const char *workstation;
	struct MprVar auth;
	struct cli_credentials *creds;
	struct socket_address *remote_host;
	const char *auth_types_unix[] = { "unix", NULL };

	if (argc != 2 || argv[0]->type != MPR_TYPE_OBJECT || argv[1]->type != MPR_TYPE_OBJECT) {
		ejsSetErrorMsg(eid, "userAuth invalid arguments, this function requires an object.");
		return -1;
	}

	/* get credential values from credentials object */
	creds = mprGetPtr(argv[0], "creds");
	if (creds == NULL) {
		ejsSetErrorMsg(eid, "userAuth requires a 'creds' first parameter");
		return -1;
	}

	remote_host = mprGetPtr(argv[1], "socket_address");
	if (remote_host == NULL) {
		ejsSetErrorMsg(eid, "userAuth requires a socket address second parameter");
		return -1;
	}

 	tmp_ctx = talloc_new(mprMemCtx());	
	
	username    = cli_credentials_get_username(creds);
	password    = cli_credentials_get_password(creds);
	domain      = cli_credentials_get_domain(creds);
	workstation = cli_credentials_get_workstation(creds);

	if (username == NULL || password == NULL || domain == NULL) {
		mpr_Return(eid, mprCreateUndefinedVar());
		talloc_free(tmp_ctx);
		return 0;
	}

	auth = mprObject("auth");

	if (domain && (strcmp("SYSTEM USER", domain) == 0)) {
		ejs_doauth(eid, tmp_ctx, &auth, username, password, domain, workstation, remote_host, auth_types_unix);
	} else {
		ejs_doauth(eid, tmp_ctx, &auth, username, password, domain, workstation, remote_host, NULL);
	}

	mpr_Return(eid, auth);
	talloc_free(tmp_ctx);
	return 0;
}

/*
  initialise credentials ejs object
*/
static int ejs_system_session(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *obj = mprInitObject(eid, "session_info", argc, argv);
	struct auth_session_info *session_info = system_session(mprMemCtx());

	if (session_info == NULL) {
		return -1;
	}

	mprSetPtrChild(obj, "session_info", session_info);
	return 0;
}

/*
  setup C functions that be called from ejs
*/
NTSTATUS smb_setup_ejs_auth(void)
{
	ejsDefineCFunction(-1, "userAuth", ejs_userAuth, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "system_session", ejs_system_session, NULL, MPR_VAR_SCRIPT_HANDLE);
	return NT_STATUS_OK;
}
