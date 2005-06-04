/* 
   Unix SMB/CIFS implementation.

   provide hooks into smbd C calls from ejs scripts

   Copyright (C) Andrew Tridgell 2005
   
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
#include "param/loadparm.h"
#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/ndr_nbt.h"
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
static void ejs_returnlist(MprVarHandle eid, 
			   const char *name, const char **list)
{
	ejsSetReturnValue(eid, mprList(name, list));
}

/*
  return a list of defined services
*/
static int ejs_lpServices(MprVarHandle eid, int argc, char **argv)
{
	int i;
	const char **list = NULL;
	if (argc != 0) return -1;
	
	for (i=0;i<lp_numservices();i++) {
		list = str_list_add(list, lp_servicename(i));
	}
	talloc_steal(mprMemCtx(), list);
	ejs_returnlist(eid, "services", list);
	return 0;
}


/*
  allow access to loadparm variables from inside ejs scripts in swat
  
  can be called in 4 ways:

    v = lpGet("type:parm");             gets a parametric variable
    v = lpGet("share", "type:parm");    gets a parametric variable on a share
    v = lpGet("parm");                  gets a global variable
    v = lpGet("share", "parm");         gets a share variable

  the returned variable is a ejs object. It is an array object for lists.  
*/
static int ejs_lpGet(MprVarHandle eid, int argc, char **argv)
{
	struct parm_struct *parm = NULL;
	void *parm_ptr = NULL;
	int i;

	if (argc < 1) return -1;

	if (argc == 2) {
		/* its a share parameter */
		int snum = lp_servicenumber(argv[0]);
		if (snum == -1) {
			return -1;
		}
		if (strchr(argv[1], ':')) {
			/* its a parametric option on a share */
			const char *type = talloc_strndup(mprMemCtx(), 
							  argv[1], 
							  strcspn(argv[1], ":"));
			const char *option = strchr(argv[1], ':') + 1;
			const char *value;
			if (type == NULL || option == NULL) return -1;
			value = lp_get_parametric(snum, type, option);
			if (value == NULL) return -1;
			ejsSetReturnString(eid, value);
			return 0;
		}

		parm = lp_parm_struct(argv[1]);
		if (parm == NULL || parm->class == P_GLOBAL) {
			return -1;
		}
		parm_ptr = lp_parm_ptr(snum, parm);
	} else if (strchr(argv[0], ':')) {
		/* its a global parametric option */
		const char *type = talloc_strndup(mprMemCtx(), 
						  argv[0], strcspn(argv[0], ":"));
		const char *option = strchr(argv[0], ':') + 1;
		const char *value;
		if (type == NULL || option == NULL) return -1;
		value = lp_get_parametric(-1, type, option);
		if (value == NULL) return -1;
		ejsSetReturnString(eid, value);
		return 0;
	} else {
		/* its a global parameter */
		parm = lp_parm_struct(argv[0]);
		if (parm == NULL) return -1;
		parm_ptr = parm->ptr;
	}

	if (parm == NULL || parm_ptr == NULL) {
		return -1;
	}

	/* construct and return the right type of ejs object */
	switch (parm->type) {
	case P_STRING:
	case P_USTRING:
		ejsSetReturnString(eid, *(char **)parm_ptr);
		break;
	case P_BOOL:
		ejsSetReturnValue(eid, mprCreateBoolVar(*(BOOL *)parm_ptr));
		break;
	case P_INTEGER:
		ejsSetReturnValue(eid, mprCreateIntegerVar(*(int *)parm_ptr));
		break;
	case P_ENUM:
		for (i=0; parm->enum_list[i].name; i++) {
			if (*(int *)parm_ptr == parm->enum_list[i].value) {
				ejsSetReturnString(eid, parm->enum_list[i].name);
				return 0;
			}
		}
		return -1;	
	case P_LIST: 
		ejs_returnlist(eid, parm->label, *(const char ***)parm_ptr);
		break;
	case P_SEP:
		return -1;
	}
	return 0;
}


/*
  perform an ldb search, returning an array of results

  syntax:
     ldbSearch("dbfile", "expression");
     var attrs = new Array("attr1", "attr2", "attr3");
     ldbSearch("dbfile", "expression", attrs);
*/
static int ejs_ldbSearch(MprVarHandle eid, int argc, struct MprVar **argv)
{
	const char **attrs = NULL;
	const char *expression, *dbfile;
	TALLOC_CTX *tmp_ctx = talloc_new(mprMemCtx());
	struct ldb_context *ldb;
	int ret;
	struct ldb_message **res;

	/* validate arguments */
	if (argc < 2 || argc > 3 ||
	    argv[0]->type != MPR_TYPE_STRING) {
		ejsSetErrorMsg(eid, "ldbSearch invalid arguments");
		goto failed;
	}
	if (argc == 3 && argv[2]->type != MPR_TYPE_OBJECT) {
		ejsSetErrorMsg(eid, "ldbSearch attributes must be an object");
		goto failed;
	}

	dbfile     = mprToString(argv[0]);
	expression = mprToString(argv[1]);
	if (argc > 2) {
		attrs = mprToList(tmp_ctx, argv[2]);
	}
	if (dbfile == NULL || expression == NULL) {
		ejsSetErrorMsg(eid, "ldbSearch invalid arguments");
		goto failed;
	}

	ldb = ldb_wrap_connect(tmp_ctx, dbfile, 0, NULL);
	if (ldb == NULL) {
		ejsSetErrorMsg(eid, "ldbSearch failed to open %s", dbfile);
		goto failed;
	}

	ret = ldb_search(ldb, NULL, LDB_SCOPE_DEFAULT, expression, attrs, &res);
	if (ret == -1) {
		ejsSetErrorMsg(eid, "ldbSearch failed - %s", ldb_errstring(ldb));
		goto failed;
	}

	ejsSetReturnValue(eid, mprLdbArray(res, ret, "ldb_message"));

	talloc_free(tmp_ctx);
	return 0;

failed:
	talloc_free(tmp_ctx);
	return -1;
}

/*
  look up a netbios name

  syntax:
    resolveName(result, "frogurt");
    resolveName(result, "frogurt", 0x1c);
*/

static int ejs_resolve_name(MprVarHandle eid, int argc, struct MprVar **argv)
{
	int result = -1;
	struct nbt_name name;
	TALLOC_CTX *tmp_ctx = talloc_new(mprMemCtx());	
	NTSTATUS nt_status;
	const char *reply_addr;

	/* validate arguments */
	if (argc < 2 || argc > 3) {
		ejsSetErrorMsg(eid, "resolveName invalid arguments");
		goto done;
	}

	if (argv[0]->type != MPR_TYPE_OBJECT) {
		ejsSetErrorMsg(eid, "resolvename invalid arguments");
		goto done;
	}

	if (argv[1]->type != MPR_TYPE_STRING) {
		ejsSetErrorMsg(eid, "resolveName invalid arguments");
		goto done;
	}
	
	if (argc == 2) {
		make_nbt_name_client(&name, mprToString(argv[1]));
	} else {
		if (argv[1]->type != MPR_TYPE_INT) {
			ejsSetErrorMsg(eid, "resolveName invalid arguments");
			goto done;
		}
		make_nbt_name(&name, mprToString(argv[1]), mprToInt(argv[2]));
	}

	result = 0;

	nt_status = resolve_name(&name, tmp_ctx, &reply_addr);

	if (NT_STATUS_IS_OK(nt_status)) {
		mprSetPropertyValue(argv[0], "value", 
				    mprCreateStringVar(reply_addr, 1));
	}

	ejsSetReturnValue(eid, mprNTSTATUS(nt_status));

 done:
	talloc_free(tmp_ctx);
	return result;
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
  setup the C functions that be called from ejs
*/
void smb_setup_ejs_functions(void)
{
	ejsDefineStringCFunction(-1, "lpGet", ejs_lpGet, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "lpServices", ejs_lpServices, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "typeof", ejs_typeof, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "ldbSearch", ejs_ldbSearch, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "resolveName", ejs_resolve_name, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "getDomainList", ejs_domain_list, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "userAuth", ejs_userAuth, NULL, MPR_VAR_SCRIPT_HANDLE);
}
