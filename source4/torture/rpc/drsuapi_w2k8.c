/*
   Unix SMB/CIFS implementation.

   DRSUapi tests

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2006

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
#include "librpc/gen_ndr/ndr_drsuapi_c.h"
#include "torture/rpc/torture_rpc.h"
#include "param/param.h"

#define TEST_MACHINE_NAME "torturetest"

/*
 * DsBind as sent from W2K8 Client.
 * This should work regardless of functional level, and accept
 * any info <=48
 */
bool test_DsBind_w2k8(struct torture_context *tctx,
		      struct DsPrivate_w2k8 *priv)
{
	NTSTATUS status;
	struct dcerpc_pipe *p = priv->drs_pipe;
	struct drsuapi_DsBind r;
	struct drsuapi_DsBindInfo48 *bind_info48;
	struct drsuapi_DsBindInfoCtr bind_info_ctr;

	/* We send info48 */
	ZERO_STRUCT(bind_info_ctr);
	bind_info_ctr.length = 48;

	bind_info48 = &bind_info_ctr.info.info48;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_BASE;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ASYNC_REPLICATION;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_REMOVEAPI;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_MOVEREQ_V2;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHG_COMPRESS;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V1;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_RESTORE_USN_OPTIMIZATION;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY_V2;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_LINKED_VALUE_REPLICATION;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V2;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_INSTANCE_TYPE_NOT_REQ_ON_MOD;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_CRYPTO_BIND;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GET_REPL_INFO;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_STRONG_ENCRYPTION;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V01;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_TRANSITIVE_MEMBERSHIP;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADD_SID_HISTORY;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_POST_BETA3;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GET_MEMBERSHIPS2;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V6;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_NONDOMAIN_NCS;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V5;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V6;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V7;
	bind_info48->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_VERIFY_OBJECT;

	/*
	 * We wish for DRSUAPI_SUPPORTED_EXTENSION_LH_BETA2,
	 * needed for DsGetDomainControllerInfo level 3
	 */
	bind_info48->supported_extensions_ext  |= DRSUAPI_SUPPORTED_EXTENSION_LH_BETA2;

	GUID_from_string(DRSUAPI_DS_BIND_GUID, &priv->bind_guid);

	r.in.bind_guid = &priv->bind_guid;
	r.in.bind_info = &bind_info_ctr;
	r.out.bind_handle = &priv->bind_handle;

	torture_comment(tctx, "Testing DsBind W2K8\n");

	status = dcerpc_drsuapi_DsBind_r(p->binding_handle, tctx, &r);
	torture_drsuapi_assert_call(tctx, p, status, &r, "dcerpc_drsuapi_DsBind");

	torture_assert_not_null(tctx, r.out.bind_info,
				"DsBind with info48 results in NULL");

	/* cache server supported extensions, i.e. bind_info */
	priv->srv_bind_info = *r.out.bind_info;

	/*
	 * We do not check for length here, because it should be valid to return
	 * any valid info
	 */

	return true;
}

static bool test_DsGetDomainControllerInfo_w2k8(struct torture_context *tctx,
					        struct DsPrivate_w2k8 *priv)
{
	NTSTATUS status;
	struct dcerpc_pipe *p = priv->drs_pipe;
	struct drsuapi_DsGetDomainControllerInfo r;
	union drsuapi_DsGetDCInfoCtr ctr;
	int32_t level_out = 0;
	uint32_t supported_extensions_ext = 0;
	bool found = false;
	int j, k;

	struct {
		const char *name;
		WERROR expected;
	} names[] = {
		{
			.name = torture_join_dom_netbios_name(priv->join),
			.expected = WERR_OK
		},
		{
			.name = torture_join_dom_dns_name(priv->join),
			.expected = WERR_OK
		},
		{
			.name = "__UNKNOWN_DOMAIN__",
			.expected = WERR_DS_OBJ_NOT_FOUND
		},
		{
			.name = "unknown.domain.samba.example.com",
			.expected = WERR_DS_OBJ_NOT_FOUND
		},
	};

	/* Levels 1 and 2 are tested in standard drsuapi tests */
	int level = 3;

	/* Do Bind first. */
	if (!test_DsBind_w2k8(tctx, priv)) {
		return false;
	}

	/*
	 * We used DsBind_w2k8, so DRSUAPI_SUPPORTED_EXTENSION_LH_BETA2
	 * should mean support for level 3
	 */

	/*
	 * We are looking for an extension found in info32 and later
	 */
	switch (priv->srv_bind_info.length) {
	case 32:
		supported_extensions_ext = priv->srv_bind_info.info.info32.supported_extensions_ext;
		break;
	case 48:
		supported_extensions_ext = priv->srv_bind_info.info.info48.supported_extensions_ext;
		break;
	default:
		supported_extensions_ext = 0;
		break;
	}

	supported_extensions_ext &= DRSUAPI_SUPPORTED_EXTENSION_LH_BETA2;
	torture_assert(tctx, (supported_extensions_ext > 0),
		       "Server does not support DRSUAPI_SUPPORTED_EXTENSION_LH_BETA2");

	for (j=0; j < ARRAY_SIZE(names); j++) {
		union drsuapi_DsGetDCInfoRequest req;
		r.in.bind_handle = &priv->bind_handle;
		r.in.level = 1;
		r.in.req = &req;

		r.in.req->req1.domain_name = names[j].name;
		r.in.req->req1.level = level;

		r.out.ctr = &ctr;
		r.out.level_out = &level_out;

		torture_comment(tctx,
			   "Testing DsGetDomainControllerInfo level %d on domainname '%s'\n",
		       r.in.req->req1.level, r.in.req->req1.domain_name);

		status = dcerpc_drsuapi_DsGetDomainControllerInfo_r(p->binding_handle, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status,
			   "dcerpc_drsuapi_DsGetDomainControllerInfo with dns domain failed");
		torture_assert_werr_equal(tctx, r.out.result, names[j].expected,
				   "DsGetDomainControllerInfo level with dns domain failed");

		if (!W_ERROR_IS_OK(r.out.result)) {
			/* If this was an error, we can't read the result structure */
			continue;
		}

		torture_assert_int_equal(tctx, r.in.req->req1.level, *r.out.level_out,
					 "dcerpc_drsuapi_DsGetDomainControllerInfo in/out level differs");

		for (k=0; k < r.out.ctr->ctr3.count; k++) {
			if (strcasecmp_m(r.out.ctr->ctr3.array[k].netbios_name,
					 torture_join_netbios_name(priv->join)) == 0) {
				found = true;
				priv->dcinfo	= r.out.ctr->ctr3.array[k];
				break;
			}
		}
		break;

		torture_assert(tctx, found,
			 "dcerpc_drsuapi_DsGetDomainControllerInfo: Failed to find the domain controller we just created during the join");
	}

	return true;
}


bool test_DsUnbind_w2k8(struct torture_context *tctx,
			struct DsPrivate_w2k8 *priv)
{
	NTSTATUS status;
	struct dcerpc_pipe *p = priv->drs_pipe;
	struct drsuapi_DsUnbind r;

	r.in.bind_handle = &priv->bind_handle;
	r.out.bind_handle = &priv->bind_handle;

	torture_comment(tctx, "Testing DsUnbind W2K8\n");

	status = dcerpc_drsuapi_DsUnbind_r(p->binding_handle, tctx, &r);
	torture_drsuapi_assert_call(tctx, p, status, &r, "dcerpc_drsuapi_DsUnbind");

	return true;
}

/**
 * Common test case setup function to be used
 * in DRS suit of test when appropriate
 */
bool torture_drsuapi_w2k8_tcase_setup_common(struct torture_context *tctx,
					     struct DsPrivate_w2k8 *priv)
{
	NTSTATUS status;
	int rnd = rand() % 1000;
	char *name = talloc_asprintf(tctx, "%s%d", TEST_MACHINE_NAME, rnd);
	struct cli_credentials *machine_credentials;

	torture_assert(tctx, priv, "Invalid argument");

	torture_comment(tctx, "Create DRSUAPI pipe\n");
	status = torture_rpc_connection(tctx,
					&priv->drs_pipe,
					&ndr_table_drsuapi);
	torture_assert(tctx, NT_STATUS_IS_OK(status), "Unable to connect to DRSUAPI pipe");

	torture_comment(tctx, "About to join domain with name %s\n", name);
	priv->join = torture_join_domain(tctx, name, ACB_SVRTRUST,
					 &machine_credentials);
	torture_assert(tctx, priv->join, "Failed to join as BDC");

	/*
	 * After that every test should use DsBind and DsGetDomainControllerInfo
	 */
	if (!test_DsBind_w2k8(tctx, priv)) {
		/* clean up */
		torture_drsuapi_w2k8_tcase_teardown_common(tctx, priv);
		torture_fail(tctx, "Failed execute test_DsBind_w2k8()");
	}


	return true;
}

/**
 * Common test case teardown function to be used
 * in DRS suit of test when appropriate
 */
bool torture_drsuapi_w2k8_tcase_teardown_common(struct torture_context *tctx,
						struct DsPrivate_w2k8 *priv)
{
	if (priv->join) {
		torture_leave_domain(tctx, priv->join);
	}

	return true;
}

/**
 * Test case setup for DRSUAPI test case
 */
static bool torture_drsuapi_w2k8_tcase_setup(struct torture_context *tctx, void **data)
{
	struct DsPrivate_w2k8 *priv;

	*data = priv = talloc_zero(tctx, struct DsPrivate_w2k8);

	return torture_drsuapi_w2k8_tcase_setup_common(tctx, priv);
}

/**
 * Test case tear-down for DRSUAPI test case
 */
static bool torture_drsuapi_w2k8_tcase_teardown(struct torture_context *tctx, void *data)
{
	bool ret;
	struct DsPrivate_w2k8 *priv = talloc_get_type(data, struct DsPrivate_w2k8);

	ret = torture_drsuapi_w2k8_tcase_teardown_common(tctx, priv);

	talloc_free(priv);
	return ret;
}

/**
 * DRSUAPI test case implementation
 */
void torture_rpc_drsuapi_w2k8_tcase(struct torture_suite *suite)
{
	typedef bool (*run_func) (struct torture_context *test, void *tcase_data);

	struct torture_tcase *tcase = torture_suite_add_tcase(suite, "drsuapi_w2k8");

	torture_tcase_set_fixture(tcase, torture_drsuapi_w2k8_tcase_setup,
				  torture_drsuapi_w2k8_tcase_teardown);

	torture_tcase_add_simple_test(tcase, "DsBind_W2K8", (run_func)test_DsBind_w2k8);
	torture_tcase_add_simple_test(tcase, "DsGetDomainControllerInfo_W2K8", (run_func)test_DsGetDomainControllerInfo_w2k8);
}
