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
#include "scripting/ejs/smbcalls.h"
#include "lib/appweb/ejs/ejs.h"
#include "lib/ldb/include/ldb.h"

/*
  get the connected db
 */
static struct ldb_context *ejs_get_ldb_context(int eid)
{
	struct ldb_context *ldb = mprGetThisPtr(eid, "db");
	if (ldb == NULL) {
		ejsSetErrorMsg(eid, "invalid ldb connection");
	}
	return ldb;
}

/*
  perform an ldb search, returning an array of results

  syntax:
     res = ldb.search("expression");
     var attrs = new Array("attr1", "attr2", "attr3");
     ldb.search("expression", attrs);
     var basedn = "cn=this,dc=is,dc=a,dc=test";
     ldb.search("expression", attrs, ldb.SCOPE_SUBTREE, basedn);
*/
static int ejs_ldbSearch(MprVarHandle eid, int argc, struct MprVar **argv)
{
	const char **attrs = NULL;
	const char *expression;
	const char *basedn = NULL;
	int scope = LDB_SCOPE_DEFAULT;
	TALLOC_CTX *tmp_ctx = talloc_new(mprMemCtx());
	struct ldb_context *ldb;
	int ret;
	struct ldb_message **res;

	/* validate arguments */
	if (argc < 1 || argc > 4) {
		ejsSetErrorMsg(eid, "ldb.search invalid number of arguments");
		goto failed;
	}
	if (argc > 3 && argv[3]->type != MPR_TYPE_OBJECT) {
		ejsSetErrorMsg(eid, "ldb.search attributes must be an object");
		goto failed;
	}

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}
	
	expression = mprToString(argv[0]);
	if (expression == NULL) {
		ejsSetErrorMsg(eid, "ldb.search invalid expression");
		goto failed;
	}
	if (argc > 1) {
		basedn = mprToString(argv[1]);
		/* a null basedn is valid */
	}
	if (argc > 2) {
		scope = mprToInt(argv[2]);
		switch (scope) {
			case LDB_SCOPE_DEFAULT:
			case LDB_SCOPE_BASE:
			case LDB_SCOPE_ONELEVEL:
			case LDB_SCOPE_SUBTREE:
				break; /* ok */
			default:
				ejsSetErrorMsg(eid, "ldb.search invalid scope");
				goto failed;
		}
	}
	if (argc > 3) {
		attrs = mprToList(tmp_ctx, argv[3]);
	}
	ret = ldb_search(ldb, basedn, scope, expression, attrs, &res);
	if (ret == -1) {
		ejsSetErrorMsg(eid, "ldb.search failed - %s", ldb_errstring(ldb));
		mpr_Return(eid, mprCreateUndefinedVar());
	} else {
		mpr_Return(eid, mprLdbArray(ldb, res, ret, "ldb_message"));
	}

	talloc_free(tmp_ctx);
	return 0;

failed:
	talloc_free(tmp_ctx);
	return -1;
}


/*
  perform an ldb add or modify
*/
static int ejs_ldbAddModify(MprVarHandle eid, int argc, struct MprVar **argv,
			    int fn(struct ldb_context *, const struct ldb_message *))
{
	const char *ldifstring;
	struct ldb_context *ldb;
	struct ldb_ldif *ldif;
	int ret;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "ldb.add/modify invalid arguments");
		return -1;
	}

	ldifstring = mprToString(argv[0]);
	if (ldifstring == NULL) {
		ejsSetErrorMsg(eid, "ldb.add/modify invalid arguments");
		return -1;
	}

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}

	while ((ldif = ldb_ldif_read_string(ldb, &ldifstring))) {
		ret = fn(ldb, ldif->msg);
		talloc_free(ldif);
		if (ret != 0) break;
	}

	mpr_Return(eid, mprCreateBoolVar(ret == 0));
	return 0;
}


/*
  perform an ldb delete
  usage:
   ok = ldb.delete(dn);
*/
static int ejs_ldbDelete(MprVarHandle eid, int argc, struct MprVar **argv)
{
	const char *dn;
	struct ldb_context *ldb;
	int ret;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "ldb.delete invalid arguments");
		return -1;
	}

	dn = mprToString(argv[0]);

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}
	ret = ldb_delete(ldb, dn);

	mpr_Return(eid, mprCreateBoolVar(ret == 0));
	return 0;
}

/*
  perform an ldb rename
  usage:
   ok = ldb.rename(dn1, dn2);
*/
static int ejs_ldbRename(MprVarHandle eid, int argc, struct MprVar **argv)
{
	const char *dn1, *dn2;
	struct ldb_context *ldb;
	int ret;

	if (argc != 2) {
		ejsSetErrorMsg(eid, "ldb.rename invalid arguments");
		return -1;
	}

	dn1 = mprToString(argv[0]);
	dn2 = mprToString(argv[1]);
	if (dn1 == NULL || dn2 == NULL) {
		ejsSetErrorMsg(eid, "ldb.rename invalid arguments");
		return -1;
	}

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}

	ret = ldb_rename(ldb, dn1, dn2);

	mpr_Return(eid, mprCreateBoolVar(ret == 0));
	return 0;
}

/*
  get last error message
  usage:
   ok = ldb.errstring();
*/
static int ejs_ldbErrstring(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct ldb_context *ldb;

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}

	mpr_Return(eid, mprString(ldb_errstring(ldb)));
	return 0;
}

/*
  perform an ldb modify

  syntax:
    ok = ldb.modify(ldifstring);
*/
static int ejs_ldbAdd(MprVarHandle eid, int argc, struct MprVar **argv)
{
	return ejs_ldbAddModify(eid, argc, argv, ldb_add);
}

/*
  perform an ldb add

  syntax:
    ok = ldb.add(ldifstring);
*/
static int ejs_ldbModify(MprVarHandle eid, int argc, struct MprVar **argv)
{
	return ejs_ldbAddModify(eid, argc, argv, ldb_modify);
}

/*
  connect to a database
  usage:
   ok = ldb.connect(dbfile);
   ok = ldb.connect(dbfile, "modules:modlist");
*/
static int ejs_ldbConnect(MprVarHandle eid, int argc, char **argv)
{
	struct ldb_context *ldb;
	const char *dbfile;

	if (argc < 1) {
		ejsSetErrorMsg(eid, "ldb.connect invalid arguments");
		return -1;
	}

	dbfile = argv[0];

	ldb = ldb_wrap_connect(mprMemCtx(), dbfile, 0, (const char **)(argv+1));
	if (ldb == NULL) {
		ejsSetErrorMsg(eid, "ldb.connect failed to open %s", dbfile);
	}

	mprSetThisPtr(eid, "db", ldb);
	mpr_Return(eid, mprCreateBoolVar(ldb != NULL));
	return 0;
}


/*
  initialise ldb ejs subsystem
*/
static int ejs_ldb_init(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *ldb = mprInitObject(eid, "ldb", argc, argv);

	mprSetStringCFunction(ldb, "connect", ejs_ldbConnect);
	mprSetCFunction(ldb, "search", ejs_ldbSearch);
	mprSetCFunction(ldb, "add", ejs_ldbAdd);
	mprSetCFunction(ldb, "modify", ejs_ldbModify);
	mprSetCFunction(ldb, "del", ejs_ldbDelete);
	mprSetCFunction(ldb, "rename", ejs_ldbRename);
	mprSetCFunction(ldb, "errstring", ejs_ldbErrstring);
	mprSetVar(ldb, "SCOPE_BASE", mprCreateNumberVar(LDB_SCOPE_BASE));
	mprSetVar(ldb, "SCOPE_ONE", mprCreateNumberVar(LDB_SCOPE_ONELEVEL));
	mprSetVar(ldb, "SCOPE_SUBTREE", mprCreateNumberVar(LDB_SCOPE_SUBTREE));

	return 0;
}


/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_ldb(void)
{
	ejsDefineCFunction(-1, "ldb_init", ejs_ldb_init, NULL, MPR_VAR_SCRIPT_HANDLE);
}
