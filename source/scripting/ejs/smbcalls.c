/* 
   Unix SMB/CIFS implementation.

   provide hooks into smbd C calls from ejs scripts

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Tim Potter 2005
   
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
#include "lib/ejs/ejs.h"
#include "auth/auth.h"

/*
  return the type of a variable
*/
static int ejs_typeof(MprVarHandle eid, int argc, struct MprVar **argv)
{
	const struct {
		MprType type;
		const char *name;
	} types[] = {
		{ MPR_TYPE_UNDEFINED,        "undefined" },
		{ MPR_TYPE_NULL,             "object" },
		{ MPR_TYPE_BOOL,             "boolean" },
		{ MPR_TYPE_CFUNCTION,        "function" },
		{ MPR_TYPE_FLOAT,            "number" },
		{ MPR_TYPE_INT,              "number" },
		{ MPR_TYPE_INT64,            "number" },
		{ MPR_TYPE_OBJECT,           "object" },
		{ MPR_TYPE_FUNCTION,         "function" },
		{ MPR_TYPE_STRING,           "string" },
		{ MPR_TYPE_STRING_CFUNCTION, "function" }
	};
	int i;
	const char *type = NULL;

	if (argc != 1) return -1;
	
	for (i=0;i<ARRAY_SIZE(types);i++) {
		if (argv[0]->type == types[i].type) {
			type = types[i].name;
			break;
		}
	}
	if (type == NULL) return -1;

	ejsSetReturnString(eid, type);
	return 0;
}

/*
  setup a return of a string list
*/
 void ejs_returnlist(MprVarHandle eid, const char *name, const char **list)
{
	ejsSetReturnValue(eid, mprList(name, list));
}

static int ejs_userAuth(MprVarHandle eid, int argc, char **argv)
{
	struct auth_usersupplied_info *user_info = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_context *auth_context;
	TALLOC_CTX *tmp_ctx;
	struct MprVar auth;
	NTSTATUS nt_status;
	DATA_BLOB pw_blob;

	if (argc != 3 || *argv[0] == 0 || *argv[2] == 0) {
		ejsSetErrorMsg(eid, "userAuth invalid arguments");
		return -1;
	}

 	tmp_ctx = talloc_new(mprMemCtx());	
	auth = mprCreateObjVar("auth", MPR_DEFAULT_HASH_SIZE);

	if (strcmp("System User", argv[2]) == 0) {
		const char *auth_unix[] = { "unix", NULL };

		nt_status = auth_context_create(tmp_ctx, auth_unix, &auth_context);
		if (!NT_STATUS_IS_OK(nt_status)) {
			mprSetPropertyValue(&auth, "result", mprCreateBoolVar(False));
			mprSetPropertyValue(&auth, "report", mprCreateStringVar("Auth System Failure", 0));
			goto done;
		}

		pw_blob = data_blob(argv[1], strlen(argv[1])),
		make_user_info(tmp_ctx, argv[0], argv[0],
					argv[2], argv[2],
					"foowks", "fooip",
					NULL, NULL,
					NULL, NULL,
					&pw_blob, False,
					0x05, &user_info);
		nt_status = auth_check_password(auth_context, tmp_ctx, user_info, &server_info);
		if (!NT_STATUS_IS_OK(nt_status)) {
			mprSetPropertyValue(&auth, "result", mprCreateBoolVar(False));
			mprSetPropertyValue(&auth, "report", mprCreateStringVar("Login Failed", 0));
			goto done;
		}

		mprSetPropertyValue(&auth, "result", mprCreateBoolVar(server_info->authenticated));
		mprSetPropertyValue(&auth, "username", mprCreateStringVar(server_info->account_name, 0));
		mprSetPropertyValue(&auth, "domain", mprCreateStringVar(server_info->domain_name, 0));

	}  else {
		mprSetPropertyValue(&auth, "result", mprCreateBoolVar(False));
		mprSetPropertyValue(&auth, "report", mprCreateStringVar("Unknown Domain", 0));
	}

done:
	ejsSetReturnValue(eid, auth);
	talloc_free(tmp_ctx);
	return 0;
}

static int ejs_domain_list(MprVarHandle eid, int argc, char **argv)
{
	struct MprVar list;
	struct MprVar dom;

	if (argc != 0) {
		ejsSetErrorMsg(eid, "domList invalid arguments");
		return -1;
	}

	list = mprCreateObjVar("list", MPR_DEFAULT_HASH_SIZE);
	dom = mprCreateStringVar("System User", 1);
	mprCreateProperty(&list, "0", &dom);

	ejsSetReturnValue(eid, list);

	return 0;
}


/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_functions(void)
{
	smb_setup_ejs_config();
	smb_setup_ejs_ldb();
	smb_setup_ejs_nbt();

	ejsDefineCFunction(-1, "typeof", ejs_typeof, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "getDomainList", ejs_domain_list, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "userAuth", ejs_userAuth, NULL, MPR_VAR_SCRIPT_HANDLE);
}
