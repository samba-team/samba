/*
 * Unix SMB/CIFS implementation.
 * test suite for samr rpc operations
 *
 * Copyright (c) 2011      Andreas Schneider
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "param/param.h"
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "libcli/security/security.h"
#include "torture/rpc/torture_rpc.h"

#define TEST_ACCOUNT_NAME "guru"

struct torture_user {
	const char *username;
	const char *password;
	const char *domain;
	uint32_t *builtin_memberships;
	uint32_t num_builtin_memberships;
	bool admin_rights;
};

struct torture_access_context {
	struct dcerpc_pipe *pipe;
	struct torture_user user;
	struct test_join *join;
};

static void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
}

static bool test_samr_queryUserInfo(struct torture_context *tctx,
				    struct dcerpc_binding_handle *b,
				    struct policy_handle *user_handle)
{
	struct samr_QueryUserInfo r;
	union samr_UserInfo *info;
	NTSTATUS status;

	r.in.level = UserGeneralInformation;
	r.in.user_handle = user_handle;
	r.out.info = &info;

	status = dcerpc_samr_QueryUserInfo_r(b,
					     tctx,
					     &r);
	torture_assert_ntstatus_ok(tctx, status, "queryUserInfo failed");
	torture_assert_ntstatus_ok(tctx, r.out.result, "queryUserInfo failed");

	return true;
}

static bool test_LookupName(struct dcerpc_binding_handle *b,
			    struct torture_context *tctx,
			    struct policy_handle *domain_handle,
			    const char *name,
			    uint32_t *rid)
{
	NTSTATUS status;
	struct samr_LookupNames n;
	struct lsa_String sname[1];
	struct samr_Ids rids, types;

	init_lsa_String(&sname[0], name);

	n.in.domain_handle = domain_handle;
	n.in.num_names = 1;
	n.in.names = sname;
	n.out.rids = &rids;
	n.out.types = &types;

	status = dcerpc_samr_LookupNames_r(b, tctx, &n);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	if (!NT_STATUS_IS_OK(n.out.result)) {
		return false;
	}

	*rid = n.out.rids->ids[0];
	return true;
}

static bool test_samr_CreateUser(struct torture_context *tctx,
			         struct dcerpc_binding_handle *b,
			         struct policy_handle *domain_handle,
			         const char *name,
			         struct policy_handle *user_handle)
{
	struct lsa_String username;
	struct samr_CreateUser r;
	uint32_t rid = 0;
	NTSTATUS status;

	init_lsa_String(&username, name);

	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.domain_handle = domain_handle;
	r.in.account_name = &username;
	r.out.user_handle = user_handle;
	r.out.rid = &rid;

	status = dcerpc_samr_CreateUser_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "CreateUser failed");

	return NT_STATUS_IS_OK(r.out.result);
}

static bool test_samr_OpenUser(struct torture_context *tctx,
			       struct dcerpc_binding_handle *b,
			       struct policy_handle *domain_handle,
			       const char *name,
			       struct policy_handle *user_handle,
			       bool expected)
{
	struct samr_OpenUser r;
	uint32_t rid = 0;
	NTSTATUS status;
	bool ok;

	ok = test_LookupName(b, tctx, domain_handle, name, &rid);
	if (!ok && expected) {
		torture_comment(tctx, " - lookup name for %s failed\n", name);
		return true;
	} else if (!ok) {
		return false;
	}

	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.domain_handle = domain_handle;
	r.in.rid = rid;
	r.out.user_handle = user_handle;

	status = dcerpc_samr_OpenUser_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "OpenUser failed");
	torture_assert_ntstatus_ok(tctx, r.out.result, "OpenUser failed");

	return true;
}

static bool test_samr_openDomain(struct torture_context *tctx,
				 struct dcerpc_binding_handle *b,
				 struct policy_handle *connect_handle,
				 const char *domain,
				 struct policy_handle *domain_handle)
{
	struct samr_LookupDomain r;
	struct samr_OpenDomain r2;
	struct lsa_String n;
	struct dom_sid *sid;
	NTSTATUS status;

	r.in.connect_handle = connect_handle;
	init_lsa_String(&n, domain);
	r.in.domain_name = &n;
	r.out.sid = &sid;

	status = dcerpc_samr_LookupDomain_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "LookupDomain failed");
	torture_assert_ntstatus_ok(tctx, r.out.result, "LookupDomain failed");

	r2.in.connect_handle = connect_handle;
	r2.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r2.in.sid = sid;
	r2.out.domain_handle = domain_handle;

	status = dcerpc_samr_OpenDomain_r(b, tctx, &r2);
	torture_assert_ntstatus_ok(tctx, status, "OpenDomain failed");
	torture_assert_ntstatus_ok(tctx, r2.out.result, "OpenDomain failed");

	return true;
}

static bool test_samr_Connect(struct torture_context *tctx,
			      struct dcerpc_binding_handle *b,
			      struct policy_handle *connect_handle)
{
	struct samr_Connect r;
	NTSTATUS status;

	r.in.system_name = 0;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.connect_handle = connect_handle;

	status = dcerpc_samr_Connect_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "SAMR connect failed");
	torture_assert_ntstatus_ok(tctx, r.out.result, "SAMR connect failed");

	return true;
}

static bool test_samr_create_user(struct torture_context *tctx,
				  struct torture_access_context *t,
				  const char *name)
{
	struct dcerpc_binding_handle *b = t->pipe->binding_handle;
	struct policy_handle connect_handle;
	struct policy_handle domain_handle;
	struct policy_handle user_handle;
	bool ok = false;

	torture_comment(tctx, "Connecting to SAMR\n");
	ZERO_STRUCT(connect_handle);
	ok = test_samr_Connect(tctx, b, &connect_handle);
	torture_assert(tctx, ok, "Unable to connect to domain");

	torture_comment(tctx, "Opening domain %s\n", t->user.domain);
	ZERO_STRUCT(domain_handle);
	ok = test_samr_openDomain(tctx,
				  b,
				  &connect_handle,
				  t->user.domain,
				  &domain_handle);
	torture_assert(tctx, ok, "Unable to open to domain");

	torture_comment(tctx, "Creating account %s\n", name);
	ZERO_STRUCT(user_handle);
	ok = test_samr_CreateUser(tctx,
				  b,
				  &domain_handle,
				  name,
				  &user_handle);

	/* We don't check ok with torture macros here because the
	 * caller might be looking for failure */
	test_samr_handle_Close(b, tctx, &domain_handle);
	test_samr_handle_Close(b, tctx, &connect_handle);

	return ok;
}

static bool test_samr_userinfo_getinfo(struct torture_context *tctx,
				       struct dcerpc_pipe *p,
				       bool expected)
{
	const char *name;
	struct dcerpc_pipe *p2 = NULL;
	struct dcerpc_binding_handle *b;
	struct policy_handle connect_handle;
	struct policy_handle domain_handle;
	struct policy_handle user_handle;
	NTSTATUS status;
	uint32_t i = 0;
	bool ok;

	status = torture_rpc_connection(tctx, &p2, &ndr_table_samr);
	torture_assert_ntstatus_ok(tctx, status,
			"Creating secondary connection failed");
	b = p2->binding_handle;

	torture_comment(tctx, " - 2nd connect\n");
	/* connect */
	ZERO_STRUCT(connect_handle);
	ok = test_samr_Connect(tctx, b, &connect_handle);
	torture_assert(tctx, ok, "Unable to connect to domain");

	torture_comment(tctx, " - 2nd open domain\n");
	/* open domain */
	ZERO_STRUCT(domain_handle);
	ok = test_samr_openDomain(tctx,
				  b,
				  &connect_handle,
				  torture_setting_string(tctx, "workgroup",
							 lpcfg_workgroup(tctx->lp_ctx)),
				  &domain_handle);
	torture_assert(tctx, ok, "Unable to open to domain");

	/* create user */
	name = talloc_asprintf(tctx,
			       "%s%04d",
			       TEST_ACCOUNT_NAME,
			       i);

	torture_comment(tctx, " - 2nd open user\n");
	ZERO_STRUCT(user_handle);
	ok = test_samr_OpenUser(tctx,
				b,
				&domain_handle,
				name,
				&user_handle,
				expected);
	torture_assert(tctx, ok, "Unable to open user");

	if (!expected) {
		torture_comment(tctx, " - 2nd query user\n");
		ok = test_samr_queryUserInfo(tctx, b, &user_handle);
		torture_assert(tctx, ok, "Unable to query user");

		test_samr_handle_Close(b, tctx, &user_handle);
	}

	test_samr_handle_Close(b, tctx, &domain_handle);
	test_samr_handle_Close(b, tctx, &connect_handle);

	talloc_free(p2);

	return true;
}

#define NUM_RUNS 20
static bool torture_rpc_samr_caching(struct torture_context *tctx,
				     struct dcerpc_pipe *p)
{
	struct test_join *join;
	const char *password = NULL;
	const char *name;
	NTSTATUS status;
	uint32_t i = 0;
	bool ok;

	torture_comment(tctx, ">>> Testing User Info Caching\n");

	/* create user */
	name = talloc_asprintf(tctx,
			       "%s%04d",
			       TEST_ACCOUNT_NAME,
			       i);

	torture_comment(tctx, "- Creating user %s\n", name);

	join = torture_create_testuser(tctx,
				       name,
				       torture_setting_string(tctx, "workgroup",
				                              lpcfg_workgroup(tctx->lp_ctx)),
				       ACB_NORMAL,
				       &password);
	torture_assert(tctx, join, "failed to join domain");

	torture_comment(tctx, "- Query user information\n");
	for (i = 0; i < NUM_RUNS; i++) {
		ok = test_samr_userinfo_getinfo(tctx, p, false);
		torture_assert(tctx, ok, "test_samr_userinfo_getinfo failed");
	}

	torture_comment(tctx, "- Delete user\n");
	status = torture_delete_testuser(tctx,
					 join,
					 name);
	torture_assert_ntstatus_ok(tctx, status, "DeleteUser failed");

	torture_comment(tctx, "- Try to query user information again (should fail)\n");
	for (i = 0; i < NUM_RUNS; i++) {
		ok = test_samr_userinfo_getinfo(tctx,
						p,
						true);
		torture_assert(tctx, ok, "test_samr_userinfo_getinfo failed");
	}

	return true;
}
#undef NUM_RUNS

static bool torture_rpc_samr_access_setup_membership(struct torture_context *tctx,
						     struct dcerpc_pipe *p,
						     uint32_t num_members,
						     uint32_t *members,
						     struct dom_sid *user_sid)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct policy_handle connect_handle, domain_handle;
	int i;

	torture_comment(tctx,
		"Setting up BUILTIN membership for %s\n",
		dom_sid_string(tctx, user_sid));

	for (i=0; i < num_members; i++) {
		torture_comment(tctx, "adding user to S-1-5-32-%d\n", members[i]);
	}

	/* connect */
	{
		struct samr_Connect2 r;
		r.in.system_name = "";
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		ZERO_STRUCT(connect_handle);
		r.out.connect_handle = &connect_handle;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_samr_Connect2_r(b, tctx, &r),
			"samr_Connect2 failed");
		torture_assert_ntstatus_ok(tctx, r.out.result,
			"samr_Connect2 failed");
	}

	/* open domain */
	{
		struct samr_OpenDomain r;
		r.in.connect_handle = &connect_handle;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.in.sid = dom_sid_parse_talloc(tctx, "S-1-5-32");
		ZERO_STRUCT(domain_handle);
		r.out.domain_handle = &domain_handle;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_samr_OpenDomain_r(b, tctx, &r),
			"samr_OpenDomain failed");
		torture_assert_ntstatus_ok(tctx, r.out.result,
			"samr_OpenDomain failed");
	}

	for (i = 0; i < num_members; i++) {

		struct policy_handle alias_handle;

		/* open alias */
		{
			struct samr_OpenAlias r;
			r.in.domain_handle = &domain_handle;
			r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
			r.in.rid = members[i];
			ZERO_STRUCT(alias_handle);
			r.out.alias_handle = &alias_handle;

			torture_assert_ntstatus_ok(tctx,
					dcerpc_samr_OpenAlias_r(b, tctx, &r),
					"samr_OpenAlias failed");
			torture_assert_ntstatus_ok(tctx, r.out.result,
					"samr_OpenAlias failed");
		}

		/* add alias member */
		{
			struct samr_AddAliasMember r;
			ZERO_STRUCT(alias_handle);
			r.in.alias_handle = &alias_handle;
			r.in.sid = user_sid;

			torture_assert_ntstatus_ok(tctx,
					dcerpc_samr_AddAliasMember_r(b, tctx, &r),
					"samr_AddAliasMember failed");
			torture_assert_ntstatus_ok(tctx, r.out.result,
					"samr_AddAliasMember failed");
		}

		test_samr_handle_Close(b, tctx, &alias_handle);
	}

	test_samr_handle_Close(b, tctx, &domain_handle);
	test_samr_handle_Close(b, tctx, &connect_handle);

	return true;
}

static bool torture_rpc_samr_access_setup(struct torture_context *tctx,
					  struct dcerpc_pipe *p,
					  struct torture_access_context *t)
{
	const char *binding = torture_setting_string(tctx, "binding", NULL);
	struct cli_credentials *test_credentials;
	struct test_join *join;
	struct dom_sid *test_sid;
	struct dcerpc_pipe *samr_pipe;

	t->user.domain = torture_setting_string(tctx, "workgroup",
						lpcfg_workgroup(tctx->lp_ctx)),

	join = torture_create_testuser(tctx,
				       t->user.username,
				       t->user.domain,
				       ACB_NORMAL,
				       &t->user.password);
	torture_assert(tctx, join, "failed to join domain");
	t->join = join;

	test_credentials = cli_credentials_init(tctx);

	cli_credentials_set_workstation(test_credentials,
					"localhost",
					CRED_SPECIFIED);
	cli_credentials_set_domain(test_credentials,
				   torture_setting_string(tctx, "workgroup",
							  lpcfg_workgroup(tctx->lp_ctx)),
				   CRED_SPECIFIED);
	cli_credentials_set_username(test_credentials,
				     t->user.username,
				     CRED_SPECIFIED);
	cli_credentials_set_password(test_credentials,
				     t->user.password,
				     CRED_SPECIFIED);
	test_sid = discard_const_p(struct dom_sid,
				   torture_join_user_sid(t->join));

	if (t->user.num_builtin_memberships) {
		torture_assert(tctx,
			torture_rpc_samr_access_setup_membership(tctx,
								 p,
								 t->user.num_builtin_memberships,
								 t->user.builtin_memberships,
								 test_sid),
			"failed to setup membership");
	}

	torture_assert_ntstatus_ok(tctx,
		dcerpc_pipe_connect(tctx,
				    &samr_pipe,
				    binding,
				    &ndr_table_samr,
				    test_credentials,
				    tctx->ev,
				    tctx->lp_ctx),
		"Error connecting to server");

	t->pipe = samr_pipe;

	return true;
}

static bool torture_rpc_samr_access(struct torture_context *tctx,
				    struct dcerpc_pipe *p)
{
	struct torture_access_context *t;
	const char *testuser;
	bool ok;

	torture_comment(tctx, "Testing non-privileged user access\n");

	t = talloc_zero(tctx, struct torture_access_context);
	torture_assert(tctx, t, "talloc failed");

	t->user.username = talloc_asprintf(t, "%s%04d", TEST_ACCOUNT_NAME, 100);

	torture_comment(tctx, "*** Setting up non-privleged user\n"
			      "***\n");

	ok = torture_rpc_samr_access_setup(tctx, p, t);
	torture_assert(tctx, ok, "torture_rpc_samr_access_setup failed");

	testuser = talloc_asprintf(t, "%s%04d", TEST_ACCOUNT_NAME, 200);

	torture_comment(tctx, "*** Try to create user (%s) as non-privileged "
			      "user - should fail\n"
			      "***\n", testuser);

	ok = test_samr_create_user(tctx, t, testuser);

	torture_assert(tctx, ok == false, "*** Creating user was successful but it should fail");

	return true;
}

struct torture_suite *torture_rpc_samr_priv(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite =
		torture_suite_create(mem_ctx, "samr.priv");
	struct torture_rpc_tcase *tcase;

	tcase = torture_suite_add_rpc_iface_tcase(suite,
						  "samr",
						  &ndr_table_samr);

	torture_rpc_tcase_add_test(tcase,
				   "caching",
				   torture_rpc_samr_caching);

	torture_rpc_tcase_add_test(tcase,
				   "access",
				   torture_rpc_samr_access);

	return suite;
}
