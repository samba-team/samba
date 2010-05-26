/*
   Unix SMB/CIFS implementation.
   Test suite for libnet calls.

   Copyright (C) Rafal Szczesniak 2005

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
#include "system/time.h"
#include "lib/cmdline/popt_common.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "torture/rpc/torture_rpc.h"
#include "torture/libnet/usertest.h"
#include "param/param.h"
#include "lib/ldb_wrap.h"


/**
 * Find out user's samAccountName for given
 * user RDN. We need samAccountName value
 * when deleting users.
 */
static bool _get_account_name_for_user_rdn(struct torture_context *tctx,
					   struct dcerpc_binding_handle *b,
					   const char *user_rdn,
					   TALLOC_CTX *mem_ctx,
					   const char **_account_name)
{
	const char *url;
	struct ldb_context *ldb;
	TALLOC_CTX *tmp_ctx;
	bool test_res = true;
	struct dcerpc_pipe *p = talloc_get_type_abort(b->private_data, struct dcerpc_pipe);
	int ldb_ret;
	struct ldb_result *ldb_res;
	const char *account_name = NULL;
	static const char *attrs[] = {
		"samAccountName",
		NULL
	};

	tmp_ctx = talloc_new(tctx);
	torture_assert(tctx, tmp_ctx != NULL, "Failed to create temporary mem context");

	url = talloc_asprintf(tmp_ctx, "ldap://%s/", p->binding->target_hostname);
	torture_assert_goto(tctx, url != NULL, test_res, done, "Failed to allocate URL for ldb");

	ldb = ldb_wrap_connect(tmp_ctx,
	                       tctx->ev, tctx->lp_ctx,
	                       url, NULL, cmdline_credentials, 0);
	torture_assert_goto(tctx, ldb != NULL, test_res, done, "Failed to make LDB connection");

	ldb_ret = ldb_search(ldb, tmp_ctx, &ldb_res,
	                     ldb_get_default_basedn(ldb), LDB_SCOPE_SUBTREE,
	                     attrs,
	                     "(&(objectClass=user)(name=%s))", user_rdn);
	if (LDB_SUCCESS == ldb_ret && 1 == ldb_res->count) {
		account_name = ldb_msg_find_attr_as_string(ldb_res->msgs[0], "samAccountName", NULL);
	}

	/* return user_rdn by default */
	if (!account_name) {
		account_name = user_rdn;
	}

	/* duplicate memory in parent context */
	*_account_name = talloc_strdup(mem_ctx, account_name);

done:
	talloc_free(tmp_ctx);
	return test_res;
}

/**
 * Deletes a user account when given user RDN name
 *
 * @param username RDN for the user to be deleted
 */
static bool test_cleanup(struct torture_context *tctx,
			 struct dcerpc_binding_handle *b, TALLOC_CTX *mem_ctx,
			 struct policy_handle *domain_handle, const char *username)
{
	struct samr_LookupNames r1;
	struct samr_OpenUser r2;
	struct samr_DeleteUser r3;
	struct lsa_String names[2];
	uint32_t rid;
	struct policy_handle user_handle;
	struct samr_Ids rids, types;
	const char *account_name;

	if (!_get_account_name_for_user_rdn(tctx, b, username, mem_ctx, &account_name)) {
		torture_result(tctx, TORTURE_FAIL,
		               __location__": Failed to find samAccountName for %s", username);
		return false;
	}

	names[0].string = account_name;

	r1.in.domain_handle  = domain_handle;
	r1.in.num_names      = 1;
	r1.in.names          = names;
	r1.out.rids          = &rids;
	r1.out.types         = &types;

	torture_comment(tctx, "user account lookup '%s'\n", account_name);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_LookupNames_r(b, mem_ctx, &r1),
		"LookupNames failed");
	torture_assert_ntstatus_ok(tctx, r1.out.result,
		"LookupNames failed");

	rid = r1.out.rids->ids[0];

	r2.in.domain_handle  = domain_handle;
	r2.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	r2.in.rid            = rid;
	r2.out.user_handle   = &user_handle;

	torture_comment(tctx, "opening user account\n");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_OpenUser_r(b, mem_ctx, &r2),
		"OpenUser failed");
	torture_assert_ntstatus_ok(tctx, r2.out.result,
		"OpenUser failed");

	r3.in.user_handle  = &user_handle;
	r3.out.user_handle = &user_handle;

	torture_comment(tctx, "deleting user account\n");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_DeleteUser_r(b, mem_ctx, &r3),
		"DeleteUser failed");
	torture_assert_ntstatus_ok(tctx, r3.out.result,
		"DeleteUser failed");

	return true;
}


static bool test_opendomain(struct torture_context *tctx,
			    struct dcerpc_binding_handle *b, TALLOC_CTX *mem_ctx,
			    struct policy_handle *handle, struct lsa_String *domname)
{
	struct policy_handle h, domain_handle;
	struct samr_Connect r1;
	struct samr_LookupDomain r2;
	struct dom_sid2 *sid = NULL;
	struct samr_OpenDomain r3;

	torture_comment(tctx, "connecting\n");

	r1.in.system_name = 0;
	r1.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r1.out.connect_handle = &h;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_Connect_r(b, mem_ctx, &r1),
		"Connect failed");
	torture_assert_ntstatus_ok(tctx, r1.out.result,
		"Connect failed");

	r2.in.connect_handle = &h;
	r2.in.domain_name = domname;
	r2.out.sid = &sid;

	torture_comment(tctx, "domain lookup on %s\n", domname->string);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_LookupDomain_r(b, mem_ctx, &r2),
		"LookupDomain failed");
	torture_assert_ntstatus_ok(tctx, r2.out.result,
		"LookupDomain failed");

	r3.in.connect_handle = &h;
	r3.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r3.in.sid = *r2.out.sid;
	r3.out.domain_handle = &domain_handle;

	torture_comment(tctx, "opening domain\n");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_OpenDomain_r(b, mem_ctx, &r3),
		"OpenDomain failed");
	torture_assert_ntstatus_ok(tctx, r3.out.result,
		"OpenDomain failed");

	*handle = domain_handle;

	return true;
}


static bool test_samr_close(struct torture_context *tctx,
			    struct dcerpc_binding_handle *b, TALLOC_CTX *mem_ctx,
			    struct policy_handle *domain_handle)
{
	struct samr_Close r;

	r.in.handle = domain_handle;
	r.out.handle = domain_handle;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_Close_r(b, mem_ctx, &r),
		"Close samr domain failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"Close samr domain failed");

	return true;
}


static bool test_lsa_close(struct torture_context *tctx,
			   struct dcerpc_binding_handle *b, TALLOC_CTX *mem_ctx,
			   struct policy_handle *domain_handle)
{
	struct lsa_Close r;

	r.in.handle = domain_handle;
	r.out.handle = domain_handle;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_lsa_Close_r(b, mem_ctx, &r),
		"Close lsa domain failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"Close lsa domain failed");

	return true;
}


static bool test_createuser(struct torture_context *tctx,
			    struct dcerpc_binding_handle *b, TALLOC_CTX *mem_ctx,
 			    struct policy_handle *handle, const char* user)
{
	struct policy_handle user_handle;
	struct lsa_String username;
	struct samr_CreateUser r1;
	struct samr_Close r2;
	uint32_t user_rid;

	username.string = user;

	r1.in.domain_handle = handle;
	r1.in.account_name = &username;
	r1.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r1.out.user_handle = &user_handle;
	r1.out.rid = &user_rid;

	torture_comment(tctx, "creating user '%s'\n", username.string);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_CreateUser_r(b, mem_ctx, &r1),
		"CreateUser failed");
	if (!NT_STATUS_IS_OK(r1.out.result)) {
		torture_comment(tctx, "CreateUser failed - %s\n", nt_errstr(r1.out.result));

		if (NT_STATUS_EQUAL(r1.out.result, NT_STATUS_USER_EXISTS)) {
			torture_comment(tctx, "User (%s) already exists - attempting to delete and recreate account again\n", user);
			if (!test_cleanup(tctx, b, mem_ctx, handle, user)) {
				return false;
			}

			torture_comment(tctx, "creating user account\n");

			torture_assert_ntstatus_ok(tctx,
				dcerpc_samr_CreateUser_r(b, mem_ctx, &r1),
				"CreateUser failed");
			torture_assert_ntstatus_ok(tctx, r1.out.result,
				"CreateUser failed");

			return true;
		}
		return false;
	}

	r2.in.handle = &user_handle;
	r2.out.handle = &user_handle;

	torture_comment(tctx, "closing user '%s'\n", username.string);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_Close_r(b, mem_ctx, &r2),
		"Close failed");
	torture_assert_ntstatus_ok(tctx, r2.out.result,
		"Close failed");

	return true;
}


bool torture_createuser(struct torture_context *torture)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	struct libnet_CreateUser req;
	bool ret = true;

	mem_ctx = talloc_init("test_createuser");

	ctx = libnet_context_init(torture->ev, torture->lp_ctx);
	ctx->cred = cmdline_credentials;

	req.in.user_name = TEST_USERNAME;
	req.in.domain_name = lp_workgroup(torture->lp_ctx);
	req.out.error_string = NULL;

	status = libnet_CreateUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(torture, "libnet_CreateUser call failed: %s\n", nt_errstr(status));
		ret = false;
		goto done;
	}

	if (!test_cleanup(torture, ctx->samr.pipe->binding_handle, mem_ctx, &ctx->samr.handle, TEST_USERNAME)) {
		torture_comment(torture, "cleanup failed\n");
		ret = false;
		goto done;
	}

	if (!test_samr_close(torture, ctx->samr.pipe->binding_handle, mem_ctx, &ctx->samr.handle)) {
		torture_comment(torture, "domain close failed\n");
		ret = false;
	}

done:
	talloc_free(ctx);
	talloc_free(mem_ctx);
	return ret;
}


bool torture_deleteuser(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	TALLOC_CTX *prep_mem_ctx, *mem_ctx;
	struct policy_handle h;
	struct lsa_String domain_name;
	const char *name = TEST_USERNAME;
	struct libnet_context *ctx;
	struct libnet_DeleteUser req;
	bool ret = true;

	prep_mem_ctx = talloc_init("prepare test_deleteuser");

	ctx = libnet_context_init(torture->ev, torture->lp_ctx);
	ctx->cred = cmdline_credentials;

	req.in.user_name = TEST_USERNAME;
	req.in.domain_name = lp_workgroup(torture->lp_ctx);

	status = torture_rpc_connection(torture,
					&p,
					&ndr_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		ret = false;
		goto done;
	}

	domain_name.string = lp_workgroup(torture->lp_ctx);
	if (!test_opendomain(torture, p->binding_handle, prep_mem_ctx, &h, &domain_name)) {
		ret = false;
		goto done;
	}

	if (!test_createuser(torture, p->binding_handle, prep_mem_ctx, &h, name)) {
		ret = false;
		goto done;
	}

	mem_ctx = talloc_init("test_deleteuser");

	status = libnet_DeleteUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(torture, "libnet_DeleteUser call failed: %s\n", nt_errstr(status));
		ret = false;
	}

	talloc_free(mem_ctx);

done:
	talloc_free(ctx);
	talloc_free(prep_mem_ctx);
	return ret;
}


/*
  Generate testing set of random changes
*/

static void set_test_changes(struct torture_context *tctx,
			     TALLOC_CTX *mem_ctx, struct libnet_ModifyUser *r,
			     int num_changes, char **user_name, enum test_fields req_change)
{
	const char* logon_scripts[] = { "start_login.cmd", "login.bat", "start.cmd" };
	const char* home_dirs[] = { "\\\\srv\\home", "\\\\homesrv\\home\\user", "\\\\pdcsrv\\domain" };
	const char* home_drives[] = { "H:", "z:", "I:", "J:", "n:" };
	const uint32_t flags[] = { (ACB_DISABLED | ACB_NORMAL | ACB_PW_EXPIRED),
				   (ACB_NORMAL | ACB_PWNOEXP),
				   (ACB_NORMAL | ACB_PW_EXPIRED) };
	const char *homedir, *homedrive, *logonscript;
	struct timeval now;
	int i, testfld;

	torture_comment(tctx, "Fields to change: [");

	for (i = 0; i < num_changes && i <= USER_FIELD_LAST; i++) {
		const char *fldname;

		testfld = (req_change == none) ? (random() % USER_FIELD_LAST) + 1 : req_change;

		/* get one in case we hit time field this time */
		gettimeofday(&now, NULL);

		switch (testfld) {
		case acct_name:
			continue_if_field_set(r->in.account_name);
			r->in.account_name = talloc_asprintf(mem_ctx, TEST_CHG_ACCOUNTNAME,
							     (int)(random() % 100));
			fldname = "account_name";

			/* update the test's user name in case it's about to change */
			*user_name = talloc_strdup(mem_ctx, r->in.account_name);
			break;

		case acct_full_name:
			continue_if_field_set(r->in.full_name);
			r->in.full_name = talloc_asprintf(mem_ctx, TEST_CHG_FULLNAME,
							  (unsigned int)random(), (unsigned int)random());
			fldname = "full_name";
			break;

		case acct_description:
			continue_if_field_set(r->in.description);
			r->in.description = talloc_asprintf(mem_ctx, TEST_CHG_DESCRIPTION,
							    (long)random());
			fldname = "description";
			break;

		case acct_home_directory:
			continue_if_field_set(r->in.home_directory);
			homedir = home_dirs[random() % ARRAY_SIZE(home_dirs)];
			r->in.home_directory = talloc_strdup(mem_ctx, homedir);
			fldname = "home_dir";
			break;

		case acct_home_drive:
			continue_if_field_set(r->in.home_drive);
			homedrive = home_drives[random() % ARRAY_SIZE(home_drives)];
			r->in.home_drive = talloc_strdup(mem_ctx, homedrive);
			fldname = "home_drive";
			break;

		case acct_comment:
			continue_if_field_set(r->in.comment);
			r->in.comment = talloc_asprintf(mem_ctx, TEST_CHG_COMMENT,
							(unsigned long)random(), (unsigned long)random());
			fldname = "comment";
			break;

		case acct_logon_script:
			continue_if_field_set(r->in.logon_script);
			logonscript = logon_scripts[random() % ARRAY_SIZE(logon_scripts)];
			r->in.logon_script = talloc_strdup(mem_ctx, logonscript);
			fldname = "logon_script";
			break;

		case acct_profile_path:
			continue_if_field_set(r->in.profile_path);
			r->in.profile_path = talloc_asprintf(mem_ctx, TEST_CHG_PROFILEPATH,
							     (unsigned long)random(), (unsigned int)random());
			fldname = "profile_path";
			break;

		case acct_expiry:
			continue_if_field_set(r->in.acct_expiry);
			now = timeval_add(&now, (random() % (31*24*60*60)), 0);
			r->in.acct_expiry = (struct timeval *)talloc_memdup(mem_ctx, &now, sizeof(now));
			fldname = "acct_expiry";
			break;

		case acct_flags:
			continue_if_field_set(r->in.acct_flags);
			r->in.acct_flags = flags[random() % ARRAY_SIZE(flags)];
			fldname = "acct_flags";
			break;

		default:
			fldname = "unknown_field";
		}

		torture_comment(tctx, ((i < num_changes - 1) ? "%s," : "%s"), fldname);

		/* disable requested field (it's supposed to be the only one used) */
		if (req_change != none) req_change = none;
	}

	torture_comment(tctx, "]\n");
}


#define TEST_STR_FLD(fld) \
	if (!strequal(req.in.fld, user_req.out.fld)) { \
		torture_comment(torture, "failed to change '%s'\n", #fld); \
		ret = false; \
		goto cleanup; \
	}

#define TEST_TIME_FLD(fld) \
	if (timeval_compare(req.in.fld, user_req.out.fld)) { \
		torture_comment(torture, "failed to change '%s'\n", #fld); \
		ret = false; \
		goto cleanup; \
	}

#define TEST_NUM_FLD(fld) \
	if (req.in.fld != user_req.out.fld) { \
		torture_comment(torture, "failed to change '%s'\n", #fld); \
		ret = false; \
		goto cleanup; \
	}


bool torture_modifyuser(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_binding *binding;
	struct dcerpc_pipe *p;
	TALLOC_CTX *prep_mem_ctx;
	struct policy_handle h;
	struct lsa_String domain_name;
	char *name;
	struct libnet_context *ctx;
	struct libnet_ModifyUser req;
	struct libnet_UserInfo user_req;
	int fld;
	bool ret = true;
	struct dcerpc_binding_handle *b;

	prep_mem_ctx = talloc_init("prepare test_deleteuser");

	ctx = libnet_context_init(torture->ev, torture->lp_ctx);
	ctx->cred = cmdline_credentials;

	status = torture_rpc_connection(torture,
					&p,
					&ndr_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		ret = false;
		goto done;
	}
	b = p->binding_handle;

	name = talloc_strdup(prep_mem_ctx, TEST_USERNAME);

	domain_name.string = lp_workgroup(torture->lp_ctx);
	if (!test_opendomain(torture, b, prep_mem_ctx, &h, &domain_name)) {
		ret = false;
		goto done;
	}

	if (!test_createuser(torture, b, prep_mem_ctx, &h, name)) {
		ret = false;
		goto done;
	}

	status = torture_rpc_binding(torture, &binding);
	if (!NT_STATUS_IS_OK(status)) {
		ret = false;
		goto done;
	}

	torture_comment(torture, "Testing change of all fields - each single one in turn\n");

	for (fld = USER_FIELD_FIRST; fld <= USER_FIELD_LAST; fld++) {
		ZERO_STRUCT(req);
		req.in.domain_name = lp_workgroup(torture->lp_ctx);
		req.in.user_name = name;

		set_test_changes(torture, torture, &req, 1, &name, fld);

		status = libnet_ModifyUser(ctx, torture, &req);
		if (!NT_STATUS_IS_OK(status)) {
			torture_comment(torture, "libnet_ModifyUser call failed: %s\n", nt_errstr(status));
			ret = false;
			continue;
		}

		ZERO_STRUCT(user_req);
		user_req.in.domain_name = lp_workgroup(torture->lp_ctx);
		user_req.in.data.user_name = name;
		user_req.in.level = USER_INFO_BY_NAME;

		status = libnet_UserInfo(ctx, torture, &user_req);
		if (!NT_STATUS_IS_OK(status)) {
			torture_comment(torture, "libnet_UserInfo call failed: %s\n", nt_errstr(status));
			ret = false;
			continue;
		}

		switch (fld) {
		case acct_name: TEST_STR_FLD(account_name);
			break;
		case acct_full_name: TEST_STR_FLD(full_name);
			break;
		case acct_comment: TEST_STR_FLD(comment);
			break;
		case acct_description: TEST_STR_FLD(description);
			break;
		case acct_home_directory: TEST_STR_FLD(home_directory);
			break;
		case acct_home_drive: TEST_STR_FLD(home_drive);
			break;
		case acct_logon_script: TEST_STR_FLD(logon_script);
			break;
		case acct_profile_path: TEST_STR_FLD(profile_path);
			break;
		case acct_expiry: TEST_TIME_FLD(acct_expiry);
			break;
		case acct_flags: TEST_NUM_FLD(acct_flags);
			break;
		default:
			break;
		}
	}

cleanup:
	if (!test_cleanup(torture, ctx->samr.pipe->binding_handle,
	                  torture, &ctx->samr.handle, TEST_USERNAME)) {
		torture_comment(torture, "cleanup failed\n");
		ret = false;
		goto done;
	}

	if (!test_samr_close(torture, ctx->samr.pipe->binding_handle, torture, &ctx->samr.handle)) {
		torture_comment(torture, "domain close failed\n");
		ret = false;
	}

done:
	talloc_free(ctx);
	talloc_free(prep_mem_ctx);
	return ret;
}


bool torture_userinfo_api(struct torture_context *torture)
{
	const char *name = TEST_USERNAME;
	bool ret = true;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = NULL, *prep_mem_ctx;
	struct libnet_context *ctx;
	struct dcerpc_pipe *p;
	struct policy_handle h;
	struct lsa_String domain_name;
	struct libnet_UserInfo req;
	struct dcerpc_binding_handle *b;

	prep_mem_ctx = talloc_init("prepare torture user info");

	ctx = libnet_context_init(torture->ev, torture->lp_ctx);
	ctx->cred = cmdline_credentials;

	status = torture_rpc_connection(torture,
					&p,
					&ndr_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	b = p->binding_handle;

	domain_name.string = lp_workgroup(torture->lp_ctx);
	if (!test_opendomain(torture, b, prep_mem_ctx, &h, &domain_name)) {
		ret = false;
		goto done;
	}

	if (!test_createuser(torture, b, prep_mem_ctx, &h, name)) {
		ret = false;
		goto done;
	}

	mem_ctx = talloc_init("torture user info");

	ZERO_STRUCT(req);

	req.in.domain_name = domain_name.string;
	req.in.data.user_name   = name;
	req.in.level = USER_INFO_BY_NAME;

	status = libnet_UserInfo(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(torture, "libnet_UserInfo call failed: %s\n", nt_errstr(status));
		ret = false;
		goto done;
	}

	if (!test_cleanup(torture, ctx->samr.pipe->binding_handle, mem_ctx, &ctx->samr.handle, TEST_USERNAME)) {
		torture_comment(torture, "cleanup failed\n");
		ret = false;
		goto done;
	}

	if (!test_samr_close(torture, ctx->samr.pipe->binding_handle, mem_ctx, &ctx->samr.handle)) {
		torture_comment(torture, "domain close failed\n");
		ret = false;
	}

	talloc_free(ctx);

done:
	talloc_free(mem_ctx);
	return ret;
}


bool torture_userlist(struct torture_context *torture)
{
	bool ret = true;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = NULL;
	struct libnet_context *ctx;
	struct lsa_String domain_name;
	struct libnet_UserList req;
	int i;

	ctx = libnet_context_init(torture->ev, torture->lp_ctx);
	ctx->cred = cmdline_credentials;

	domain_name.string = lp_workgroup(torture->lp_ctx);
	mem_ctx = talloc_init("torture user list");

	ZERO_STRUCT(req);

	torture_comment(torture, "listing user accounts:\n");

	do {

		req.in.domain_name = domain_name.string;
		req.in.page_size   = 128;
		req.in.resume_index = req.out.resume_index;

		status = libnet_UserList(ctx, mem_ctx, &req);
		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) break;

		for (i = 0; i < req.out.count; i++) {
			torture_comment(torture, "\tuser: %s, sid=%s\n",
			       req.out.users[i].username, req.out.users[i].sid);
		}

	} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));

	if (!(NT_STATUS_IS_OK(status) ||
	      NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES))) {
		torture_comment(torture, "libnet_UserList call failed: %s\n", nt_errstr(status));
		ret = false;
		goto done;
	}

	if (!test_samr_close(torture, ctx->samr.pipe->binding_handle, mem_ctx, &ctx->samr.handle)) {
		torture_comment(torture, "samr domain close failed\n");
		ret = false;
		goto done;
	}

	if (!test_lsa_close(torture, ctx->lsa.pipe->binding_handle, mem_ctx, &ctx->lsa.handle)) {
		torture_comment(torture, "lsa domain close failed\n");
		ret = false;
	}

	talloc_free(ctx);

done:
	talloc_free(mem_ctx);
	return ret;
}
