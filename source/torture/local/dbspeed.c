/* 
   Unix SMB/CIFS implementation.

   local test for tdb/ldb speed

   Copyright (C) Andrew Tridgell 2004
   
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
#include "system/filesys.h"
#include "lib/tdb/include/tdb.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/db_wrap.h"
#include "torture/torture.h"


static BOOL tdb_add_record(struct tdb_wrap *tdbw, const char *fmt1, const char *fmt2, int i)
{
	TDB_DATA key, data;
	int ret;
	key.dptr = (uint8_t *)talloc_asprintf(tdbw, fmt1, i);
	key.dsize = strlen((char *)key.dptr)+1;
	data.dptr = (uint8_t *)talloc_asprintf(tdbw, fmt2, i+10000);
	data.dsize = strlen((char *)data.dptr)+1;

	ret = tdb_store(tdbw->tdb, key, data, TDB_INSERT);

	talloc_free(key.dptr);
	talloc_free(data.dptr);
	return ret == 0;
}

/*
  test tdb speed
*/
static BOOL test_tdb_speed(struct torture_context *torture, const void *_data)
{
	struct timeval tv;
	struct tdb_wrap *tdbw;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	int i, count;
	TALLOC_CTX *tmp_ctx = talloc_new(torture);

	unlink("test.tdb");

	torture_comment(torture, "Testing tdb speed for sidmap");

	tdbw = tdb_wrap_open(tmp_ctx, "test.tdb", 
			     10000, 0, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (!tdbw) {
		torture_fail(torture, "Failed to open test.tdb");
		goto failed;
	}

	torture_comment(torture, "Adding %d SID records", torture_entries);

	for (i=0;i<torture_entries;i++) {
		if (!tdb_add_record(tdbw, 
				    "S-1-5-21-53173311-3623041448-2049097239-%u",
				    "UID %u", i)) {
			_torture_fail_ext(torture, "Failed to add SID %d", i);
			goto failed;
		}
		if (!tdb_add_record(tdbw, 
				    "UID %u",
				    "S-1-5-21-53173311-3623041448-2049097239-%u", i)) {
			_torture_fail_ext(torture, "Failed to add UID %d", i);
			goto failed;
		}
	}

	torture_comment(torture, "Testing for %d seconds", timelimit);

	tv = timeval_current();

	for (count=0;timeval_elapsed(&tv) < timelimit;count++) {
		TDB_DATA key, data;
		i = random() % torture_entries;
		key.dptr = (uint8_t *)talloc_asprintf(tmp_ctx, "S-1-5-21-53173311-3623041448-2049097239-%u", i);
		key.dsize = strlen((char *)key.dptr)+1;
		data = tdb_fetch(tdbw->tdb, key);
		if (data.dptr == NULL) {
			_torture_fail_ext(torture, "Failed to fetch SID %d", i);
			goto failed;
		}
		free(data.dptr);
		key.dptr = (uint8_t *)talloc_asprintf(tmp_ctx, "UID %u", i);
		key.dsize = strlen((char *)key.dptr)+1;
		data = tdb_fetch(tdbw->tdb, key);
		if (data.dptr == NULL) {
			_torture_fail_ext(torture, "Failed to fetch UID %d", i);
			goto failed;
		}
		free(data.dptr);
	}

	torture_comment(torture, "tdb speed %.2f ops/sec", count/timeval_elapsed(&tv));
	

	unlink("test.tdb");
	talloc_free(tmp_ctx);
	return True;

failed:
	unlink("test.tdb");
	talloc_free(tmp_ctx);
	return False;
}


static BOOL ldb_add_record(struct ldb_context *ldb, unsigned rid)
{
	struct ldb_message *msg;	
	int ret;

	msg = ldb_msg_new(ldb);
	if (msg == NULL) {
		return False;
	}

	msg->dn = ldb_dn_string_compose(msg, NULL, "SID=S-1-5-21-53173311-3623041448-2049097239-%u", 
					rid);
	if (msg->dn == NULL) {
		return False;
	}

	if (ldb_msg_add_fmt(msg, "UID", "%u", rid) != 0) {
		return False;
	}

	ret = ldb_add(ldb, msg);

	talloc_free(msg);

	return ret == LDB_SUCCESS;
}


/*
  test ldb speed
*/
static BOOL test_ldb_speed(struct torture_context *torture, const void *_data)
{
	struct timeval tv;
	struct ldb_context *ldb;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	int i, count;
	TALLOC_CTX *tmp_ctx = talloc_new(torture);
	struct ldb_ldif *ldif;
	const char *init_ldif = "dn: @INDEXLIST\n" \
		"@IDXATTR: UID\n";

	unlink("./test.ldb");

	torture_comment(torture, "Testing ldb speed for sidmap");

	ldb = ldb_wrap_connect(tmp_ctx, "tdb://test.ldb", 
				NULL, NULL, LDB_FLG_NOSYNC, NULL);
	if (!ldb) {
		torture_fail(torture, "Failed to open test.ldb");
		goto failed;
	}

	/* add an index */
	ldif = ldb_ldif_read_string(ldb, &init_ldif);
	if (ldif == NULL) goto failed;
	if (ldb_add(ldb, ldif->msg) != LDB_SUCCESS) goto failed;
	talloc_free(ldif);

	torture_comment(torture, "Adding %d SID records", torture_entries);

	for (i=0;i<torture_entries;i++) {
		if (!ldb_add_record(ldb, i)) {
			_torture_fail_ext(torture, "Failed to add SID %d", i);
			goto failed;
		}
	}

	if (talloc_total_blocks(torture) > 100) {
		_torture_fail_ext(torture, "memory leak in ldb add");
		goto failed;
	}

	torture_comment(torture, "Testing for %d seconds", timelimit);

	tv = timeval_current();

	for (count=0;timeval_elapsed(&tv) < timelimit;count++) {
		struct ldb_dn *dn;
		struct ldb_result *res;
		char *expr;

		i = random() % torture_entries;
		dn = ldb_dn_string_compose(tmp_ctx, NULL, "SID=S-1-5-21-53173311-3623041448-2049097239-%u", 
					i);
		if (ldb_search(ldb, dn, LDB_SCOPE_BASE, NULL, NULL, &res) != LDB_SUCCESS ||
		    res->count != 1) {
			torture_fail(torture, talloc_asprintf(torture,
												  "Failed to find SID %d", i));
		}
		talloc_free(res);
		talloc_free(dn);
		expr = talloc_asprintf(tmp_ctx, "(UID=%u)", i);
		if (ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, expr, NULL, &res) != LDB_SUCCESS ||
		    res->count != 1) {
			torture_fail(torture, talloc_asprintf(torture, 
												  "Failed to find UID %d", i));
		}
		talloc_free(res);
		talloc_free(expr);
	}
	
	if (talloc_total_blocks(torture) > 100) {
		torture_fail(torture, "memory leak in ldb search");
		goto failed;
	}

	torture_comment(torture, "ldb speed %.2f ops/sec", count/timeval_elapsed(&tv));
	

	unlink("./test.ldb");
	talloc_free(tmp_ctx);
	return True;

failed:
	unlink("./test.ldb");
	talloc_free(tmp_ctx);
	return False;
}

struct torture_suite *torture_local_dbspeed(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *s = torture_suite_create(mem_ctx, "DBSPEED");
	torture_suite_add_simple_tcase(s, "tdb_speed", test_tdb_speed, NULL);
	torture_suite_add_simple_tcase(s, "ldb_speed", test_ldb_speed, NULL);
	return s;
}
