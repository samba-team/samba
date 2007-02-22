/* 
   Unix SMB/CIFS implementation.

   provide hooks into smbd C calls from ejs scripts

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Jelmer Vernooij 2005
   
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
#include "lib/ldb/include/ldb_errors.h"
#include "db_wrap.h"

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
     ldb.search("expression", basedn, ldb.SCOPE_SUBTREE, attrs);
     ldb.search("expression", basedn, ldb.SCOPE_SUBTREE, attrs, controls);
*/
static int ejs_ldbSearch(MprVarHandle eid, int argc, struct MprVar **argv)
{
	const char **attrs = NULL;
	const char *expression;
	const char *base = NULL;
	struct ldb_dn *basedn = NULL;
	int scope = LDB_SCOPE_DEFAULT;
	TALLOC_CTX *tmp_ctx = talloc_new(mprMemCtx());
	struct ldb_context *ldb;
	int ret;
	struct ldb_control **parsed_controls = NULL;
	struct ldb_result *res=NULL;
	struct ldb_request *req;

	/* validate arguments */
	if (argc < 1 || argc > 5) {
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
	if (argc > 1) {
		base = mprToString(argv[1]);
		/* a null basedn is valid */
	}
	if (base != NULL) {
		basedn = ldb_dn_new(tmp_ctx, ldb, base);
		if ( ! ldb_dn_validate(basedn)) {
			ejsSetErrorMsg(eid, "ldb.search malformed base dn");
			goto failed;
		}
	} else {
		basedn = ldb_get_default_basedn(ldb);
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
	if (argc > 4) {
		const char **controls;
		controls = mprToList(tmp_ctx, argv[4]);
		if (controls) {
			parsed_controls = ldb_parse_control_strings(ldb, tmp_ctx, controls);
			if (!parsed_controls) {
				ejsSetErrorMsg(eid, "ldb.search cannot parse controls: %s", 
					       ldb_errstring(ldb));
				goto failed;
			}
		}
	}

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&req, ldb, tmp_ctx,
				   basedn,
				   scope,
				   expression,
				   attrs,
				   parsed_controls,
				   res,
				   ldb_search_default_callback);

	if (ret == LDB_SUCCESS) {

		ldb_set_timeout(ldb, req, 0); /* use default timeout */
		
		ret = ldb_request(ldb, req);
		
		if (ret == LDB_SUCCESS) {
			ret = ldb_wait(req->handle, LDB_WAIT_ALL);
		}
	}

	if (ret != LDB_SUCCESS) {
		ejsSetErrorMsg(eid, "ldb.search failed - %s", ldb_errstring(ldb));
		mpr_Return(eid, mprLdbResult(ldb, ret, NULL));
	} else {
		mpr_Return(eid, mprLdbResult(ldb, ret, res));
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
	int ret = 0, count=0;

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
		count++;
		ret = fn(ldb, ldif->msg);
		talloc_free(ldif);
		if (ret != 0) break;
	}

	if (count == 0) {
		ejsSetErrorMsg(eid, "ldb.add/modify invalid ldif");
		return -1;
	}

	mpr_Return(eid, mprLdbResult(ldb, ret, NULL));
	return 0;
}


/*
  perform an ldb delete
  usage:
   ok = ldb.delete(dn);
*/
static int ejs_ldbDelete(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct ldb_dn *dn;
	struct ldb_context *ldb;
	int ret;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "ldb.delete invalid arguments");
		return -1;
	}

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}

	dn = ldb_dn_new(ldb, ldb, mprToString(argv[0]));
	if ( ! ldb_dn_validate(dn)) {
		ejsSetErrorMsg(eid, "ldb.delete malformed dn");
		return -1;
	}

	ret = ldb_delete(ldb, dn);

	talloc_free(dn);

	mpr_Return(eid, mprLdbResult(ldb, ret, NULL));
	return 0;
}

/*
  perform an ldb rename
  usage:
   ok = ldb.rename(dn1, dn2);
*/
static int ejs_ldbRename(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct ldb_dn *dn1, *dn2;
	struct ldb_context *ldb;
	int ret;

	if (argc != 2) {
		ejsSetErrorMsg(eid, "ldb.rename invalid arguments");
		return -1;
	}

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}

	dn1 = ldb_dn_new(ldb, ldb, mprToString(argv[0]));
	dn2 = ldb_dn_new(ldb, ldb, mprToString(argv[1]));
	if ( ! ldb_dn_validate(dn1) ||  ! ldb_dn_validate(dn2)) {
		ejsSetErrorMsg(eid, "ldb.rename invalid or malformed arguments");
		return -1;
	}

	ret = ldb_rename(ldb, dn1, dn2);

	talloc_free(dn1);
	talloc_free(dn2);

	mpr_Return(eid, mprLdbResult(ldb, ret, NULL));
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
   base64 encode 
   usage: 
    dataout = ldb.encode(datain)
 */
static int ejs_base64encode(MprVarHandle eid, int argc, struct MprVar **argv)
{
	char *ret;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "ldb.base64encode invalid argument count");
		return -1;
	}

	if (argv[0]->type == MPR_TYPE_STRING) {
		const char *orig = mprToString(argv[0]);
		ret = ldb_base64_encode(mprMemCtx(), orig, strlen(orig));
	} else {
		DATA_BLOB *blob;

		blob = mprToDataBlob(argv[0]);
		mprAssert(blob);
		ret = ldb_base64_encode(mprMemCtx(), (char *)blob->data, blob->length);
	}
		
	if (!ret) {
		mpr_Return(eid, mprCreateUndefinedVar());
	} else {
		mpr_Return(eid, mprString(ret));
	}

	talloc_free(ret);

	return 0;
}

/* 
   base64 decode
   usage:
     dataout = ldb.decode(datain)
 */
static int ejs_base64decode(MprVarHandle eid, int argc, struct MprVar **argv)
{
	char *tmp;
	int ret;
	
	if (argc != 1) {
		ejsSetErrorMsg(eid, "ldb.base64encode invalid argument count");
		return -1;
	}

	tmp = talloc_strdup(mprMemCtx(), mprToString(argv[0]));
	ret = ldb_base64_decode(tmp);
	if (ret == -1) {
		mpr_Return(eid, mprCreateUndefinedVar());
	} else {
		DATA_BLOB blob;
		blob.data = (uint8_t *)tmp;
		blob.length = ret;
		mpr_Return(eid, mprDataBlob(blob));
	}

	talloc_free(tmp);

	return 0;
}

/* 
   escape a DN
   usage:
     dataout = ldb.dn_escape(datain)
 */
static int ejs_dn_escape(MprVarHandle eid, int argc, struct MprVar **argv)
{
	char *ret;
	struct ldb_val val;
	
	if (argc != 1) {
		ejsSetErrorMsg(eid, "ldb.dn_escape invalid argument count");
		return -1;
	}

	val = data_blob_string_const(mprToString(argv[0]));

	ret = ldb_dn_escape_value(mprMemCtx(), val);
	if (ret == NULL) {
		mpr_Return(eid, mprCreateUndefinedVar());
	} else {
		mpr_Return(eid, mprString(ret));
		talloc_free(ret);
	}

	return 0;
}

/*
  perform an ldb add 

  syntax:
    ok = ldb.add(ldifstring);
*/
static int ejs_ldbAdd(MprVarHandle eid, int argc, struct MprVar **argv)
{
	return ejs_ldbAddModify(eid, argc, argv, ldb_add);
}

/*
  perform an ldb modify

  syntax:
    ok = ldb.modify(ldifstring);
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

  ldb.credentials or ldb.session_info may be setup first

*/
static int ejs_ldbConnect(MprVarHandle eid, int argc, char **argv)
{
	struct ldb_context *ldb;
	struct auth_session_info *session_info = NULL;
	struct cli_credentials *creds = NULL;
	struct MprVar *credentials, *session;
	struct MprVar *this = mprGetProperty(ejsGetLocalObject(eid), "this", 0);

	const char *dbfile;

	if (argc < 1) {
		ejsSetErrorMsg(eid, "ldb.connect invalid arguments");
		return -1;
	}

	credentials = mprGetProperty(this, "credentials", NULL);
	if (credentials) {
		creds = talloc_get_type(mprGetPtr(credentials, "creds"), struct cli_credentials);
	}

	session = mprGetProperty(this, "session_info", NULL);
	if (session) {
		session_info = talloc_get_type(mprGetPtr(session, "session_info"), struct auth_session_info);
	}

	dbfile = argv[0];

	ldb = ldb_wrap_connect(mprMemCtx(), dbfile, 
			       session_info, creds,
			       0, (const char **)(argv+1));
	if (ldb == NULL) {
		ejsSetErrorMsg(eid, "ldb.connect failed to open %s", dbfile);
	}

	mprSetThisPtr(eid, "db", ldb);
	mpr_Return(eid, mprCreateBoolVar(ldb != NULL));
	return 0;
}


/*
  close a db connection
*/
static int ejs_ldbClose(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct ldb_context *ldb;

	if (argc != 0) {
		ejsSetErrorMsg(eid, "ldb.close invalid arguments");
		return -1;
	}

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}

	mprSetThisPtr(eid, "db", NULL);
	mpr_Return(eid, mprCreateBoolVar(True));
	return 0;
}


/*
  start a ldb transaction
  usage:
   ok = ldb.transaction_start();
*/
static int ejs_ldbTransactionStart(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct ldb_context *ldb;
	int ret;

	if (argc != 0) {
		ejsSetErrorMsg(eid, "ldb.transaction_start invalid arguments");
		return -1;
	}

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}

	ret = ldb_transaction_start(ldb);

	mpr_Return(eid, mprCreateBoolVar(ret == 0));
	return 0;
}

/*
  cancel a ldb transaction
  usage:
   ok = ldb.transaction_cancel();
*/
static int ejs_ldbTransactionCancel(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct ldb_context *ldb;
	int ret;

	if (argc != 0) {
		ejsSetErrorMsg(eid, "ldb.transaction_cancel invalid arguments");
		return -1;
	}

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}

	ret = ldb_transaction_cancel(ldb);

	mpr_Return(eid, mprCreateBoolVar(ret == 0));
	return 0;
}

/*
  commit a ldb transaction
  usage:
   ok = ldb.transaction_commit();
*/
static int ejs_ldbTransactionCommit(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct ldb_context *ldb;
	int ret;

	if (argc != 0) {
		ejsSetErrorMsg(eid, "ldb.transaction_commit invalid arguments");
		return -1;
	}

	ldb = ejs_get_ldb_context(eid);
	if (ldb == NULL) {
		return -1;
	}

	ret = ldb_transaction_commit(ldb);

	mpr_Return(eid, mprCreateBoolVar(ret == 0));
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
	mprSetCFunction(ldb, "encode", ejs_base64encode);
	mprSetCFunction(ldb, "decode", ejs_base64decode);
	mprSetCFunction(ldb, "dn_escape", ejs_dn_escape);
	mprSetCFunction(ldb, "close", ejs_ldbClose);
	mprSetCFunction(ldb, "transaction_start", ejs_ldbTransactionStart);
	mprSetCFunction(ldb, "transaction_cancel", ejs_ldbTransactionCancel);
	mprSetCFunction(ldb, "transaction_commit", ejs_ldbTransactionCommit);
	mprSetVar(ldb, "SCOPE_BASE", mprCreateNumberVar(LDB_SCOPE_BASE));
	mprSetVar(ldb, "SCOPE_ONE", mprCreateNumberVar(LDB_SCOPE_ONELEVEL));
	mprSetVar(ldb, "SCOPE_SUBTREE", mprCreateNumberVar(LDB_SCOPE_SUBTREE));
	mprSetVar(ldb, "SCOPE_DEFAULT", mprCreateNumberVar(LDB_SCOPE_DEFAULT));

	return 0;
}


/*
  setup C functions that be called from ejs
*/
NTSTATUS smb_setup_ejs_ldb(void)
{
	ejsDefineCFunction(-1, "ldb_init", ejs_ldb_init, NULL, MPR_VAR_SCRIPT_HANDLE);
	return NT_STATUS_OK;
}
