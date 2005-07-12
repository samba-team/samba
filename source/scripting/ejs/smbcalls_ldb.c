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
#include "lib/ejs/ejs.h"
#include "lib/ldb/include/ldb.h"

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

	mpr_Return(eid, mprLdbArray(res, ret, "ldb_message"));

	talloc_free(tmp_ctx);
	return 0;

failed:
	talloc_free(tmp_ctx);
	return -1;
}


/*
  perform an ldb add or modify
*/
static int ejs_ldbAddModify(MprVarHandle eid, int argc, char **argv,
			    int fn(struct ldb_context *, const struct ldb_message *))
{
	const char *ldifstring, *dbfile;
	struct ldb_context *ldb;
	struct ldb_ldif *ldif;
	int ret;

	if (argc != 2) {
		ejsSetErrorMsg(eid, "ldbAddModify invalid arguments");
		return -1;
	}

	dbfile     = argv[0];
	ldifstring = argv[1];

	ldb = ldb_wrap_connect(mprMemCtx(), dbfile, 0, NULL);
	if (ldb == NULL) {
		ejsSetErrorMsg(eid, "ldbAddModify failed to open %s", dbfile);
		goto failed;
	}

	ldif = ldb_ldif_read_string(ldb, ldifstring);
	if (ldif == NULL) {
		ejsSetErrorMsg(eid, "ldbAddModify invalid ldif");
		goto failed;
	}
	ret = fn(ldb, ldif->msg);

	mpr_Return(eid, mprCreateBoolVar(ret == 0));
	talloc_free(ldb);
	return 0;

failed:
	talloc_free(ldb);
	return -1;
}


/*
  perform an ldb delete
  usage:
   ok = ldbDelete(dbfile, dn);
*/
static int ejs_ldbDelete(MprVarHandle eid, int argc, char **argv)
{
	const char *dn, *dbfile;
	struct ldb_context *ldb;
	int ret;

	if (argc != 2) {
		ejsSetErrorMsg(eid, "ldbDelete invalid arguments");
		return -1;
	}

	dbfile  = argv[0];
	dn      = argv[1];

	ldb = ldb_wrap_connect(mprMemCtx(), dbfile, 0, NULL);
	if (ldb == NULL) {
		ejsSetErrorMsg(eid, "ldbDelete failed to open %s", dbfile);
		goto failed;
	}

	ret = ldb_delete(ldb, dn);

	mpr_Return(eid, mprCreateBoolVar(ret == 0));
	talloc_free(ldb);
	return 0;

failed:
	talloc_free(ldb);
	return -1;
}

/*
  perform an ldb rename
  usage:
   ok = ldbRename(dbfile, dn1, dn2);
*/
static int ejs_ldbRename(MprVarHandle eid, int argc, char **argv)
{
	const char *dn1, *dn2, *dbfile;
	struct ldb_context *ldb;
	int ret;

	if (argc != 3) {
		ejsSetErrorMsg(eid, "ldbRename invalid arguments");
		return -1;
	}

	dbfile = argv[0];
	dn1    = argv[1];
	dn2    = argv[2];

	ldb = ldb_wrap_connect(mprMemCtx(), dbfile, 0, NULL);
	if (ldb == NULL) {
		ejsSetErrorMsg(eid, "ldbRename failed to open %s", dbfile);
		goto failed;
	}

	ret = ldb_rename(ldb, dn1, dn2);

	mpr_Return(eid, mprCreateBoolVar(ret == 0));
	talloc_free(ldb);
	return 0;

failed:
	talloc_free(ldb);
	return -1;
}

/*
  perform an ldb modify

  syntax:
    ok = ldbModify("dbfile", ldifstring);
*/
static int ejs_ldbAdd(MprVarHandle eid, int argc, char **argv)
{
	return ejs_ldbAddModify(eid, argc, argv, ldb_add);
}

/*
  perform an ldb add

  syntax:
    ok = ldbAdd("dbfile", ldifstring);
*/
static int ejs_ldbModify(MprVarHandle eid, int argc, char **argv)
{
	return ejs_ldbAddModify(eid, argc, argv, ldb_modify);
}



/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_ldb(void)
{
	ejsDefineCFunction(-1, "ldbSearch", ejs_ldbSearch, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "ldbAdd", ejs_ldbAdd, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "ldbModify", ejs_ldbModify, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "ldbDelete", ejs_ldbDelete, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "ldbRename", ejs_ldbRename, NULL, MPR_VAR_SCRIPT_HANDLE);
}
