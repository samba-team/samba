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

/*
  return the type of a variable
*/
static int ejs_typeof(MprVarHandle eid, int argc, struct MprVar **argv)
{
	const struct {
		MprType type;
		const char *name;
	} types[] = {
		{ MPR_TYPE_UNDEFINED, "undefined" },
		{ MPR_TYPE_NULL, "null" },
		{ MPR_TYPE_BOOL, "boolean" },
		{ MPR_TYPE_CFUNCTION, "function" },
		{ MPR_TYPE_FLOAT, "float" },
		{ MPR_TYPE_INT, "int" },
		{ MPR_TYPE_INT64, "int64" },
		{ MPR_TYPE_OBJECT, "object" },
		{ MPR_TYPE_FUNCTION, "function" },
		{ MPR_TYPE_STRING, "string" },
		{ MPR_TYPE_STRING_CFUNCTION, "function" }
	};
	int i;
	const char *type = "unknown";

	if (argc != 1) return -1;
	
	for (i=0;i<ARRAY_SIZE(types);i++) {
		if (argv[0]->type == types[i].type) {
			type = types[i].name;
			break;
		}
	}

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
  setup the C functions that be called from ejs
*/
void smb_setup_ejs_functions(void)
{
	ejsDefineStringCFunction(-1, "lpGet", ejs_lpGet, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "lpServices", ejs_lpServices, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "typeof", ejs_typeof, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "ldbSearch", ejs_ldbSearch, NULL, MPR_VAR_SCRIPT_HANDLE);
}
