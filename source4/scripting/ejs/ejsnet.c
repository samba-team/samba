/* 
   Unix SMB/CIFS implementation.

   provide interfaces to libnet calls from ejs scripts

   Copyright (C) Rafal Szczesniak  2005
   
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
#include "lib/appweb/ejs/ejs.h"
#include "scripting/ejs/smbcalls.h"
#include "scripting/ejs/ejsnet.h"
#include "libnet/libnet.h"
#include "events/events.h"
#include "auth/credentials/credentials.h"

static int ejs_net_userman(MprVarHandle eid, int argc, struct MprVar** argv);
static int ejs_net_createuser(MprVarHandle eid, int argc, char **argv);
static int ejs_net_deleteuser(MprVarHandle eid, int argc, char **argv);
static int ejs_net_userinfo(MprVarHandle eid, int argc, char **argv);
static int ejs_net_join_domain(MprVarHandle eid, int argc, struct MprVar **argv);
static int ejs_net_samsync_ldb(MprVarHandle eid, int argc, struct MprVar **argv);

/*
  Usage:
  net = NetContext(credentials);
*/

static int ejs_net_context(MprVarHandle eid, int argc, struct MprVar **argv)
{
	TALLOC_CTX *event_mem_ctx = talloc_new(mprMemCtx());
	struct cli_credentials *creds;
	struct libnet_context *ctx;
	struct MprVar obj;
	struct event_context *ev;

	if (!event_mem_ctx) {
		ejsSetErrorMsg(eid, "talloc_new() failed");
		return -1;
	}
	ev = event_context_find(event_mem_ctx);
	ctx = libnet_context_init(ev);
	/* IF we generated a new event context, it will be under here,
	 * and we need it to last as long as the libnet context, so
	 * make it a child */
	talloc_steal(ctx, event_mem_ctx);

	if (argc == 0 || (argc == 1 && argv[0]->type == MPR_TYPE_NULL)) {
		creds = cli_credentials_init(ctx);
		if (creds == NULL) {
			ejsSetErrorMsg(eid, "cli_credential_init() failed");
			talloc_free(ctx);
			return -1;
		}
		cli_credentials_set_conf(creds);
		cli_credentials_set_anonymous(creds);
	} else if (argc == 1 && argv[0]->type == MPR_TYPE_OBJECT) {
		/* get credential values from credentials object */
		creds = mprGetPtr(argv[0], "creds");
		if (creds == NULL) {
			ejsSetErrorMsg(eid, "userAuth requires a 'creds' first parameter");
			talloc_free(ctx);
			return -1;
		}
	} else {
		ejsSetErrorMsg(eid, "NetContext invalid arguments, this function requires an object.");
		talloc_free(ctx);
		return -1;
	}
	ctx->cred = creds;

	obj = mprObject("NetCtx");
	mprSetPtrChild(&obj, "ctx", ctx);
	
	mprSetCFunction(&obj, "UserMgr", ejs_net_userman);
	mprSetCFunction(&obj, "JoinDomain", ejs_net_join_domain);
	mprSetCFunction(&obj, "SamSyncLdb", ejs_net_samsync_ldb);
	mpr_Return(eid, obj);

	return 0;
}


static int ejs_net_join_domain(MprVarHandle eid, int argc, struct MprVar **argv)
{
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	struct libnet_Join *join;
	NTSTATUS status;
	ctx = mprGetThisPtr(eid, "ctx");
	mem_ctx = talloc_new(mprMemCtx());

	join = talloc(mem_ctx, struct libnet_Join);
	if (!join) {
		talloc_free(mem_ctx);
		return -1;
	}

	/* prepare parameters for the join */
	join->in.netbios_name  = NULL;
	join->in.join_type     = SEC_CHAN_WKSTA;
	join->in.domain_name   = cli_credentials_get_domain(ctx->cred);
	join->in.level         = LIBNET_JOIN_AUTOMATIC;
	join->out.error_string = NULL;

	if (argc == 1 && argv[0]->type == MPR_TYPE_OBJECT) {
		MprVar *netbios_name = mprGetProperty(argv[0], "netbios_name", NULL);
		MprVar *domain_name = mprGetProperty(argv[0], "domain_name", NULL);
		MprVar *join_type = mprGetProperty(argv[0], "join_type", NULL);
		if (netbios_name) {
			join->in.netbios_name = mprToString(netbios_name);
		}
		if (domain_name) {
			join->in.domain_name = mprToString(domain_name);
		}
		if (join_type) {
			join->in.join_type = mprToInt(join_type);
		}
	}

	if (!join->in.domain_name) {
		ejsSetErrorMsg(eid, "a domain must be specified for to join");
		talloc_free(mem_ctx);
		return -1;
	}

	/* do the domain join */
	status = libnet_Join(ctx, join, join);
	
	if (!NT_STATUS_IS_OK(status)) {
		MprVar error_string = mprString(join->out.error_string);
		
		mprSetPropertyValue(argv[0], "error_string", error_string);
		mpr_Return(eid, mprCreateBoolVar(False));
	} else {
		mpr_Return(eid, mprCreateBoolVar(True));
	}
	talloc_free(mem_ctx);
	return 0;
}


static int ejs_net_samsync_ldb(MprVarHandle eid, int argc, struct MprVar **argv)
{
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	struct libnet_samsync_ldb *samsync;
	NTSTATUS status;
	ctx = mprGetThisPtr(eid, "ctx");
	mem_ctx = talloc_new(mprMemCtx());

	samsync = talloc(mem_ctx, struct libnet_samsync_ldb);
	if (!samsync) {
		talloc_free(mem_ctx);
		return -1;
	}

	/* prepare parameters for the samsync */
	samsync->in.machine_account = NULL;
	samsync->in.session_info = NULL;
	samsync->in.binding_string = NULL;
	samsync->out.error_string = NULL;

	if (argc == 1 && argv[0]->type == MPR_TYPE_OBJECT) {
		MprVar *credentials = mprGetProperty(argv[0], "machine_account", NULL);
		MprVar *session_info = mprGetProperty(argv[0], "session_info", NULL);
		if (credentials) {
			samsync->in.machine_account = talloc_get_type(mprGetPtr(credentials, "creds"), struct cli_credentials);
		}
		if (session_info) {
			samsync->in.session_info = talloc_get_type(mprGetPtr(session_info, "session_info"), struct auth_session_info);
		}
	}

	/* do the domain samsync */
	status = libnet_samsync_ldb(ctx, samsync, samsync);
	
	if (!NT_STATUS_IS_OK(status)) {
		MprVar error_string = mprString(samsync->out.error_string);
		
		mprSetPropertyValue(argv[0], "error_string", error_string);
		mpr_Return(eid, mprCreateBoolVar(False));
	} else {
		mpr_Return(eid, mprCreateBoolVar(True));
	}
	talloc_free(mem_ctx);
	return 0;
}


/*
  Usage:
  usrCtx = net.UserMgr(domain);
*/
static int ejs_net_userman(MprVarHandle eid, int argc, struct MprVar **argv)
{
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	const char *userman_domain = NULL;
	struct MprVar *obj = NULL;

	ctx = mprGetThisPtr(eid, "ctx");
	mem_ctx = talloc_new(mprMemCtx());

	if (argc == 0) {
		userman_domain = cli_credentials_get_domain(ctx->cred);

	} else if (argc == 1 && mprVarIsString(argv[0]->type)) {
		userman_domain = talloc_strdup(ctx, mprToString(argv[0]));

	} else {
		ejsSetErrorMsg(eid, "too many arguments");
		goto done;
	}
	
	if (!userman_domain) {
		ejsSetErrorMsg(eid, "a domain must be specified for user management");
		goto done;
	}

	obj = mprInitObject(eid, "NetUsrCtx", argc, argv);
	mprSetPtrChild(obj, "ctx", ctx);
	mprSetPtrChild(obj, "domain", userman_domain);

	mprSetStringCFunction(obj, "Create", ejs_net_createuser);
	mprSetStringCFunction(obj, "Delete", ejs_net_deleteuser);
	mprSetStringCFunction(obj, "Info", ejs_net_userinfo);

	return 0;
done:
	talloc_free(mem_ctx);
	return -1;
}


static int ejs_net_createuser(MprVarHandle eid, int argc, char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	const char *userman_domain = NULL;
	struct libnet_CreateUser req;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "argument 1 must be a string");
		return -1;
	}

	ctx = mprGetThisPtr(eid, "ctx");
	if (!ctx) {
		ejsSetErrorMsg(eid, "ctx property returns null pointer");
		return -1;
	}

	userman_domain = mprGetThisPtr(eid, "domain");
	if (!userman_domain) {
		ejsSetErrorMsg(eid, "domain property returns null pointer");
		return -1;
	}
	
	mem_ctx = talloc_new(mprMemCtx());

    	req.in.domain_name = userman_domain;
	req.in.user_name   = argv[0];

	status = libnet_CreateUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		ejsSetErrorMsg(eid, "%s", req.out.error_string);
	}

	talloc_free(mem_ctx);
	mpr_Return(eid, mprNTSTATUS(status));
	return 0;
}


static int ejs_net_deleteuser(MprVarHandle eid, int argc, char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	const char *userman_domain = NULL;
	struct libnet_DeleteUser req;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "argument 1 must be a string");
		return -1;
	}

	ctx = mprGetThisPtr(eid, "ctx");
	if (!ctx) {
		ejsSetErrorMsg(eid, "ctx property returns null pointer");
		return -1;
	}

	userman_domain = mprGetThisPtr(eid, "domain");
	if (!userman_domain) {
		ejsSetErrorMsg(eid, "domain property returns null pointer");
		return -1;
	}
	
	mem_ctx = talloc_new(mprMemCtx());

    	req.in.domain_name = userman_domain;
	req.in.user_name   = argv[0];

	status = libnet_DeleteUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		ejsSetErrorMsg(eid, "%s", req.out.error_string);
	}

	talloc_free(mem_ctx);
	mpr_Return(eid, mprNTSTATUS(status));
	return 0;
}


static int ejs_net_userinfo(MprVarHandle eid, int argc, char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	const char *userman_domain = NULL;
	struct libnet_UserInfo req;
	struct MprVar mprUserInfo;
	struct MprVar mprAccountName, mprFullName, mprDescription;
	struct MprVar mprHomeDir, mprHomeDrive, mprComment;
	struct MprVar mprLogonScript;
	struct MprVar mprAcctExpiry, mprAllowPassChange, mprForcePassChange;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "argument 1 must be a string");
		return -1;
	}

	ctx = mprGetThisPtr(eid, "ctx");
	if (!ctx) {
		ejsSetErrorMsg(eid, "ctx property returns null pointer");
		return -1;
	}

	userman_domain = mprGetThisPtr(eid, "domain");
	if (!userman_domain) {
		ejsSetErrorMsg(eid, "domain property returns null pointer");
		return -1;
	}

	mem_ctx = talloc_new(mprMemCtx());
	
	req.in.domain_name = userman_domain;
	req.in.user_name   = argv[0];
	
	status = libnet_UserInfo(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		ejsSetErrorMsg(eid, "%s", req.out.error_string);
	}

	/* create UserInfo object */
	mprUserInfo = mprObject("UserInfo");

	mprAccountName = mprString(req.out.account_name);
	mprFullName = mprString(req.out.full_name);
	mprDescription = mprString(req.out.description);
	mprHomeDir = mprString(req.out.home_directory);
	mprHomeDrive = mprString(req.out.home_drive);
	mprComment = mprString(req.out.comment);
	mprLogonScript = mprString(req.out.logon_script);
	mprAcctExpiry = mprString(timestring(mem_ctx, req.out.acct_expiry->tv_sec));
	mprAllowPassChange = mprString(timestring(mem_ctx, req.out.allow_password_change->tv_sec));
	mprForcePassChange = mprString(timestring(mem_ctx, req.out.force_password_change->tv_sec));

	status = mprSetVar(&mprUserInfo, "AccountName", mprAccountName);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "FullName", mprFullName);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "Description", mprDescription);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "HomeDirectory", mprHomeDir);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "HomeDrive", mprHomeDrive);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "Comment", mprComment);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "LogonScript", mprLogonScript);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "AcctExpiry", mprAcctExpiry);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "AllowPasswordChange", mprAllowPassChange);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprUserInfo, "ForcePasswordChange", mprForcePassChange);
	if (!NT_STATUS_IS_OK(status)) goto done;

done:
	talloc_free(mem_ctx);
	mpr_Return(eid, mprUserInfo);
	return 0;
}


void ejsnet_setup(void)
{
	ejsDefineCFunction(-1, "NetContext", ejs_net_context, NULL, MPR_VAR_SCRIPT_HANDLE);
}
