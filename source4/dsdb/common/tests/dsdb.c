/*
   Unix SMB/CIFS implementation.

   Test DSDB search

   Copyright (C) Andrew Bartlet <abartlet@samba.org> 2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include <ldb_module.h>
#include "ldb_wrap.h"
#include "param/param.h"
#include "param/loadparm.h"
#include "torture/smbtorture.h"
#include "torture/dsdb_proto.h"
#include "auth/auth.h"

bool torture_ldb_no_attrs(struct torture_context *torture)
{
	struct ldb_context *ldb;
	int ret;
	struct ldb_request *req;
	struct ldb_result *ctx;
	struct ldb_dn *dn;
	const char *attrs[] = { NULL };

	struct auth_session_info *session;
	struct dom_sid *domain_sid = NULL;
	const char *path;

	path = lpcfg_private_path(NULL, torture->lp_ctx, "sam.ldb");
	torture_assert(torture, path != NULL,
		       "Couldn't find sam.ldb. Run with -s $SERVERCONFFILE");

	domain_sid = dom_sid_parse_talloc(NULL, SID_BUILTIN);
	session = admin_session(NULL, torture->lp_ctx, domain_sid);
	ldb = ldb_wrap_connect(torture, torture->ev, torture->lp_ctx,
			       path, session, NULL, 0);
	torture_assert(torture, ldb, "Failed to connect to LDB target");

	ctx = talloc_zero(ldb, struct ldb_result);

	dn = ldb_get_default_basedn(ldb);
	ldb_dn_add_child_fmt(dn, "cn=users");
	ret = ldb_build_search_req(&req, ldb, ctx, dn, LDB_SCOPE_SUBTREE,
				   "(objectClass=*)", attrs, NULL,
				   ctx, ldb_search_default_callback, NULL);
	torture_assert(torture, ret == LDB_SUCCESS,
		       "Failed to build search request");
	ldb_req_mark_untrusted(req);

	ret = ldb_request(ldb, req);
	torture_assert(torture, ret == LDB_SUCCESS, ldb_errstring(ldb));

	ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	torture_assert(torture, ret == LDB_SUCCESS, ldb_errstring(ldb));

	torture_assert(torture, ctx->count > 0, "Users container empty");
	torture_assert_int_equal(torture, ctx->msgs[0]->num_elements, 0,
				 "Attributes returned for request "
				 "with empty attribute list");

	return true;
}

NTSTATUS torture_dsdb_init(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "dsdb");

	if (suite == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	torture_suite_add_simple_test(suite, "no_attrs", torture_ldb_no_attrs);

	suite->description = talloc_strdup(suite, "DSDB tests");

	torture_register_suite(mem_ctx, suite);

	return NT_STATUS_OK;
}
