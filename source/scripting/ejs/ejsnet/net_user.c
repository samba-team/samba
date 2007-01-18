/* 
   Unix SMB/CIFS implementation.

   provides interfaces to libnet calls from ejs scripts

   Copyright (C) Rafal Szczesniak  2005-2007
   
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
#include "libnet/libnet.h"
#include "scripting/ejs/ejsnet/proto.h"
#include "scripting/ejs/smbcalls.h"
#include "events/events.h"
#include "auth/credentials/credentials.h"


static int ejs_net_createuser(MprVarHandle eid, int argc, char **argv);
static int ejs_net_deleteuser(MprVarHandle eid, int argc, char **argv);
static int ejs_net_userinfo(MprVarHandle eid, int argc, char **argv);
static int ejs_net_userlist(MprVarHandle eid, int argc, struct MprVar **argv);


/*
  Usage:
  usrCtx = net.UserMgr(domain = <default from credentials>);
*/
int ejs_net_userman(MprVarHandle eid, int argc, struct MprVar **argv)
{
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	const char *userman_domain = NULL;
	struct MprVar *obj = NULL;

	/* fetch the arguments: domain name */
	if (argc == 0) {
		/* default domain name is supplied in credentials */
		userman_domain = cli_credentials_get_domain(ctx->cred);

	} else if (argc == 1 && mprVarIsString(argv[0]->type)) {
		/* domain name can also be specified explicitly 
		   (e.g. to connect remote domain) */
		userman_domain = talloc_strdup(ctx, mprToString(argv[0]));

	} else {
		ejsSetErrorMsg(eid, "too many arguments");
		goto done;
	}

	/* libnet context */
	ctx = mprGetThisPtr(eid, "ctx");
	if (ctx == NULL) {
		ejsSetErrorMsg(eid, "ctx property returns null pointer");
		goto done;
	}
	
	mem_ctx = talloc_new(mprMemCtx());

	/* any domain name must be specified anyway */
	if (userman_domain == NULL) {
		ejsSetErrorMsg(eid, "a domain must be specified for user management");
		goto done;
	}
	
	/* create 'net user' subcontext */
	obj = mprInitObject(eid, "NetUsrCtx", argc, argv);

	/* add properties */
	mprSetPtrChild(obj, "ctx", ctx);
	mprSetPtrChild(obj, "domain", userman_domain);

	/* add methods */
	mprSetStringCFunction(obj, "Create", ejs_net_createuser);
	mprSetStringCFunction(obj, "Delete", ejs_net_deleteuser);
	mprSetStringCFunction(obj, "Info", ejs_net_userinfo);
	mprSetCFunction(obj, "List", ejs_net_userlist);

done:
	talloc_free(mem_ctx);
	return 0;
}


/*
  Usage:
  NTSTATUS = NetUsrCtx.Create(Username)
*/
static int ejs_net_createuser(MprVarHandle eid, int argc, char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	const char *userman_domain = NULL;
	const char *username = NULL;
	struct libnet_CreateUser req;

	mem_ctx = talloc_new(mprMemCtx());
	if (mem_ctx == NULL) {
		ejsSetErrorMsg(eid, "could not create memory context - out of memory");
		goto done;
	}

	/* fetch the arguments: username */
	if (argc == 0) {
		ejsSetErrorMsg(eid, "too little arguments");
		goto done;

	} else if (argc == 1) {
		username = argv[0];

	} else {
		ejsSetErrorMsg(eid, "too many arguments");
		goto done;
	}
	
	/* libnet context */
	ctx = mprGetThisPtr(eid, "ctx");
	if (ctx == NULL) {
		ejsSetErrorMsg(eid, "ctx property returns null pointer");
		goto done;
	}

	/* domain where the account is to be created */
	userman_domain = mprGetThisPtr(eid, "domain");
	if (userman_domain == NULL) {
		ejsSetErrorMsg(eid, "domain property returns null pointer");
		goto done;
	}
	
	/* call the libnet function */
    	req.in.domain_name = userman_domain;
	req.in.user_name   = argv[0];

	status = libnet_CreateUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		ejsSetErrorMsg(eid, "%s", req.out.error_string);
	}

done:
	talloc_free(mem_ctx);
	mpr_Return(eid, mprNTSTATUS(status));
	return 0;
}


/*
  Usage:
  NTSTATUS = NetUsrCtx.Delete(Username)
*/
static int ejs_net_deleteuser(MprVarHandle eid, int argc, char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	const char *userman_domain = NULL;
	const char *username = NULL;
	struct libnet_DeleteUser req;

	mem_ctx = talloc_new(mprMemCtx());
	if (mem_ctx == NULL) {
		ejsSetErrorMsg(eid, "could not create memory context - out of memory");
		goto done;
	}

	/* fetch the arguments: username */
	if (argc == 0) {
		ejsSetErrorMsg(eid, "too little arguments");
		goto done;

	} else if (argc == 1) {
		username = argv[0];

	} else {
		ejsSetErrorMsg(eid, "too many arguments");
		goto done;
	}

	/* libnet context */
	ctx = mprGetThisPtr(eid, "ctx");
	if (ctx == NULL) {
		ejsSetErrorMsg(eid, "ctx property returns null pointer");
		goto done;
	}
	
	/* domain where the account is to be deleted */
	userman_domain = mprGetThisPtr(eid, "domain");
	if (!userman_domain) {
		ejsSetErrorMsg(eid, "domain property returns null pointer");
		goto done;
	}
	
	/* call the libnet function */
    	req.in.domain_name = userman_domain;
	req.in.user_name   = username;

	status = libnet_DeleteUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		ejsSetErrorMsg(eid, "%s", req.out.error_string);
	}

done:
	talloc_free(mem_ctx);
	mpr_Return(eid, mprNTSTATUS(status));
	return 0;
}


/*
  Usage:
  UserInfo = NetUsrCtx.Info(Username)
*/
static int ejs_net_userinfo(MprVarHandle eid, int argc, char **argv)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	const char *userman_domain = NULL;
	const char *username = NULL;
	struct libnet_UserInfo req;
	struct MprVar mprUserInfo;

	mem_ctx = talloc_new(mprMemCtx());
	if (mem_ctx == NULL) {
		ejsSetErrorMsg(eid, "could not create memory context - out of memory");
		goto done;
	}
	
	/* fetch the arguments: username */
	if (argc == 0) {
		ejsSetErrorMsg(eid, "too little arguments");
		goto done;

	} else if (argc == 1) {
		username = argv[0];

	} else {
		ejsSetErrorMsg(eid, "too many arguments");
		goto done;
	}

	/* libnet context */
	ctx = mprGetThisPtr(eid, "ctx");
	if (ctx == NULL) {
		ejsSetErrorMsg(eid, "ctx property returns null pointer");
		goto done;
	}
	
	/* domain where the user account is to be queried */
	userman_domain = mprGetThisPtr(eid, "domain");
	if (userman_domain == NULL) {
		ejsSetErrorMsg(eid, "domain property returns null pointer");
		return -1;
	}

	/* call the libnet function */
	req.in.domain_name = userman_domain;
	req.in.user_name   = username;
	
	status = libnet_UserInfo(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		ejsSetErrorMsg(eid, "%s", req.out.error_string);
		
		/* create null object to return */
		mprUserInfo = mprCreateNullVar();
		goto done;
	}

	/* create UserInfo object */
	mprUserInfo = mprCreateUserInfo(ctx, &req);

done:
	talloc_free(mem_ctx);
	mpr_Return(eid, mprUserInfo);
	return 0;
}


/*
  Usage:
  UserListCtx = NetUsrCtx.List(UserListCtx)
*/
static int ejs_net_userlist(MprVarHandle eid, int argc, struct MprVar **argv)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	struct libnet_context *ctx;
	const char *userlist_domain;
	int page_size = 512;         /* TODO: this should be specified in a nicer way */
	struct libnet_UserList req;
	struct MprVar mprListCtx, *mprInListCtx;
	
	mem_ctx = talloc_new(mprMemCtx());
	if (mem_ctx == NULL) {
		ejsSetErrorMsg(eid, "could not create memory context - out of memory");
		goto done;
	}
	
	/* fetch the arguments */
	if (argc == 0) {
		ejsSetErrorMsg(eid, "too little arguments");
		goto done;

	} else if (argc == 1) {
		if (mprVarIsObject(argv[0]->type)) {
			/* this is a continuation call */
			mprInListCtx = argv[0];
			req.in.resume_index = mprListGetResumeIndex(mprInListCtx);

		} else {
			/* this is a first call */
			req.in.resume_index = 0;
		}

	} else {
		ejsSetErrorMsg(eid, "too many arguments");
		goto done;
	}

	/* libnet context */
	ctx = mprGetThisPtr(eid, "ctx");
	if (ctx == NULL) {
		ejsSetErrorMsg(eid, "ctx property returns null pointer");
		goto done;
	}
	
	/* domain where user accounts are to be enumerated */
	userlist_domain = mprGetThisPtr(eid, "domain");
	if (userlist_domain == NULL) {
		ejsSetErrorMsg(eid, "domain property returns null pointer");
		goto done;
	}

	/* call the libnet function */
	req.in.domain_name   = userlist_domain;
	req.in.page_size     = page_size;
	
	status = libnet_UserList(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {

		ejsSetErrorMsg(eid, "%s", req.out.error_string);
		
		mprListCtx = mprCreateNullVar();
		goto done;
	}

	mprListCtx = mprUserListCtx(mem_ctx, &req, status);

done:
	talloc_free(mem_ctx);
	mpr_Return(eid, mprListCtx);
	return 0;
}
