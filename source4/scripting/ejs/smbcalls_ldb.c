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
  setup C functions that be called from ejs
*/
void smb_setup_ejs_ldb(void)
{
	ejsDefineCFunction(-1, "ldbSearch", ejs_ldbSearch, NULL, MPR_VAR_SCRIPT_HANDLE);
}
