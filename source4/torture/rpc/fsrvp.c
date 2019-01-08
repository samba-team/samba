/*
   Unix SMB/CIFS implementation.

   test suite for File Server Remote VSS Protocol operations

   Copyright (C) David Disseldorp 2012-2013

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

/*
 * Windows Server "8" Beta is very picky in how it accepts FSRVP requests, the
 * client must be a member of the same AD domain, ndr64 and signing must be
 * negotiated for the DCE/RPC bind. E.g.
 *
 * smbtorture ncacn_np:LUTZE[/pipe/FssagentRpc,smb2,ndr64,sign] \
 * 	      -U 'DOM\user%pw' rpc.fsrvp
 *
 * This test suite requires a snapshotable share named FSHARE (see #def below).
 */
#include "includes.h"
#include "lib/param/param.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb_composite/smb_composite.h"
#include "libcli/resolve/resolve.h"
#include "libcli/util/hresult.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/security_descriptor.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "torture/rpc/torture_rpc.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_srvsvc_c.h"
#include "librpc/gen_ndr/ndr_fsrvp_c.h"
#include "lib/cmdline/popt_common.h"

#define FSHARE	"fsrvp_share"
#define FNAME	"testfss.dat"

static bool test_fsrvp_is_path_supported(struct torture_context *tctx,
					 struct dcerpc_pipe *p)
{
	struct fss_IsPathSupported r;
	struct dcerpc_binding_handle *b = p->binding_handle;
	NTSTATUS status;

	ZERO_STRUCT(r);
	r.in.ShareName = talloc_asprintf(tctx,"\\\\%s\\%s\\",
					 dcerpc_server_name(p),
					 FSHARE);
	status = dcerpc_fss_IsPathSupported_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status,
				   "IsPathSupported failed");

	torture_assert(tctx, *r.out.SupportedByThisProvider,
		       "path not supported");

	torture_comment(tctx, "path %s is supported by fsrvp server %s\n",
			r.in.ShareName, *r.out.OwnerMachineName);

	return true;
}

static bool test_fsrvp_get_version(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	struct fss_GetSupportedVersion r;
	struct dcerpc_binding_handle *b = p->binding_handle;
	NTSTATUS status;

	ZERO_STRUCT(r);
	status = dcerpc_fss_GetSupportedVersion_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status,
				   "GetSupportedVersion failed");

	torture_comment(tctx, "got MinVersion %u\n", *r.out.MinVersion);
	torture_comment(tctx, "got MaxVersion %u\n", *r.out.MaxVersion);

	return true;
}

static bool test_fsrvp_set_ctx(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct fss_SetContext r;
	struct dcerpc_binding_handle *b = p->binding_handle;
	NTSTATUS status;

	ZERO_STRUCT(r);
	r.in.Context = FSRVP_CTX_BACKUP;
	status = dcerpc_fss_SetContext_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "SetContext failed");

	return true;
}

enum test_fsrvp_inject {
	TEST_FSRVP_TOUT_NONE = 0,
	TEST_FSRVP_TOUT_SET_CTX,
	TEST_FSRVP_TOUT_START_SET,
	TEST_FSRVP_TOUT_ADD_TO_SET,
	TEST_FSRVP_TOUT_PREPARE,
	TEST_FSRVP_TOUT_COMMIT,

	TEST_FSRVP_STOP_B4_EXPOSE,
};

static bool test_fsrvp_sc_create(struct torture_context *tctx,
				 struct dcerpc_pipe *p,
				 const char *share,
				 enum test_fsrvp_inject inject,
				 struct fssagent_share_mapping_1 **sc_map)
{
	struct fss_IsPathSupported r_pathsupport_get;
	struct fss_GetSupportedVersion r_version_get;
	struct fss_SetContext r_context_set;
	struct fss_StartShadowCopySet r_scset_start;
	struct fss_AddToShadowCopySet r_scset_add1;
	struct fss_AddToShadowCopySet r_scset_add2;
	struct fss_PrepareShadowCopySet r_scset_prep;
	struct fss_CommitShadowCopySet r_scset_commit;
	struct fss_ExposeShadowCopySet r_scset_expose;
	struct fss_GetShareMapping r_sharemap_get;
	struct dcerpc_binding_handle *b = p->binding_handle;
	NTSTATUS status;
	time_t start_time;
	TALLOC_CTX *tmp_ctx = talloc_new(tctx);
	struct fssagent_share_mapping_1 *map = NULL;
	int sleep_time;

	/*
	 * PrepareShadowCopySet & CommitShadowCopySet often exceed the default
	 * 60 second dcerpc request timeout against Windows Server "8" Beta.
	 */
	dcerpc_binding_handle_set_timeout(b, 240);

	ZERO_STRUCT(r_pathsupport_get);
	r_pathsupport_get.in.ShareName = share;
	status = dcerpc_fss_IsPathSupported_r(b, tmp_ctx, &r_pathsupport_get);
	torture_assert_ntstatus_ok(tctx, status,
				   "IsPathSupported failed");
	torture_assert_int_equal(tctx, r_pathsupport_get.out.result, 0,
				 "failed IsPathSupported response");
	torture_assert(tctx, r_pathsupport_get.out.SupportedByThisProvider,
		       "path not supported");

	ZERO_STRUCT(r_version_get);
	status = dcerpc_fss_GetSupportedVersion_r(b, tmp_ctx, &r_version_get);
	torture_assert_ntstatus_ok(tctx, status,
				   "GetSupportedVersion failed");
	torture_assert_int_equal(tctx, r_version_get.out.result, 0,
				 "failed GetSupportedVersion response");

	ZERO_STRUCT(r_context_set);
	r_context_set.in.Context = FSRVP_CTX_BACKUP;
	status = dcerpc_fss_SetContext_r(b, tmp_ctx, &r_context_set);
	torture_assert_ntstatus_ok(tctx, status, "SetContext failed");
	torture_assert_int_equal(tctx, r_context_set.out.result, 0,
				 "failed SetContext response");

	if (inject == TEST_FSRVP_TOUT_SET_CTX) {
		sleep_time = lpcfg_parm_int(tctx->lp_ctx, NULL, "fss",
					    "sequence timeout", 180);
		torture_comment(tctx, "sleeping for %d\n", sleep_time);
		smb_msleep((sleep_time * 1000) + 500);
	}

	ZERO_STRUCT(r_scset_start);
	r_scset_start.in.ClientShadowCopySetId = GUID_random();
	status = dcerpc_fss_StartShadowCopySet_r(b, tmp_ctx, &r_scset_start);
	torture_assert_ntstatus_ok(tctx, status,
				   "StartShadowCopySet failed");
	if (inject == TEST_FSRVP_TOUT_SET_CTX) {
		/* expect error due to message sequence timeout after set_ctx */
		torture_assert_int_equal(tctx, r_scset_start.out.result,
					 FSRVP_E_BAD_STATE,
					 "StartShadowCopySet timeout response");
		goto done;
	}
	torture_assert_int_equal(tctx, r_scset_start.out.result, 0,
				 "failed StartShadowCopySet response");
	torture_comment(tctx, "%s: shadow-copy set created\n",
			GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId));

	if (inject == TEST_FSRVP_TOUT_START_SET) {
		sleep_time = lpcfg_parm_int(tctx->lp_ctx, NULL, "fss",
					    "sequence timeout", 180);
		torture_comment(tctx, "sleeping for %d\n", sleep_time);
		smb_msleep((sleep_time * 1000) + 500);
	}

	ZERO_STRUCT(r_scset_add1);
	r_scset_add1.in.ClientShadowCopyId = GUID_random();
	r_scset_add1.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_add1.in.ShareName = share;
	status = dcerpc_fss_AddToShadowCopySet_r(b, tmp_ctx, &r_scset_add1);
	torture_assert_ntstatus_ok(tctx, status,
				   "AddToShadowCopySet failed");
	if (inject == TEST_FSRVP_TOUT_START_SET) {
		torture_assert_int_equal(tctx, r_scset_add1.out.result,
					 HRES_ERROR_V(HRES_E_INVALIDARG),
					 "AddToShadowCopySet timeout response");
		goto done;
	}
	torture_assert_int_equal(tctx, r_scset_add1.out.result, 0,
				 "failed AddToShadowCopySet response");
	torture_comment(tctx, "%s(%s): %s added to shadow-copy set\n",
			GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
			GUID_string(tmp_ctx, r_scset_add1.out.pShadowCopyId),
			r_scset_add1.in.ShareName);

	/* attempts to add the same share twice should fail */
	ZERO_STRUCT(r_scset_add2);
	r_scset_add2.in.ClientShadowCopyId = GUID_random();
	r_scset_add2.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_add2.in.ShareName = share;
	status = dcerpc_fss_AddToShadowCopySet_r(b, tmp_ctx, &r_scset_add2);
	torture_assert_ntstatus_ok(tctx, status,
				   "AddToShadowCopySet failed");
	torture_assert_int_equal(tctx, r_scset_add2.out.result,
				 FSRVP_E_OBJECT_ALREADY_EXISTS,
				 "failed AddToShadowCopySet response");

	if (inject == TEST_FSRVP_TOUT_ADD_TO_SET) {
		sleep_time = lpcfg_parm_int(tctx->lp_ctx, NULL, "fss",
					    "sequence timeout", 1800);
		torture_comment(tctx, "sleeping for %d\n", sleep_time);
		smb_msleep((sleep_time * 1000) + 500);
	}

	start_time = time_mono(NULL);
	ZERO_STRUCT(r_scset_prep);
	r_scset_prep.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
//	r_scset_prep.in.TimeOutInMilliseconds = (1800 * 1000);	/* win8 */
	r_scset_prep.in.TimeOutInMilliseconds = (240 * 1000);
	status = dcerpc_fss_PrepareShadowCopySet_r(b, tmp_ctx, &r_scset_prep);
	torture_assert_ntstatus_ok(tctx, status,
				   "PrepareShadowCopySet failed");
	if (inject == TEST_FSRVP_TOUT_ADD_TO_SET) {
		torture_assert_int_equal(tctx, r_scset_prep.out.result,
					 HRES_ERROR_V(HRES_E_INVALIDARG),
					 "PrepareShadowCopySet tout response");
		goto done;
	}
	torture_assert_int_equal(tctx, r_scset_prep.out.result, 0,
				 "failed PrepareShadowCopySet response");
	torture_comment(tctx, "%s: prepare completed in %llu secs\n",
			GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
			(unsigned long long)(time_mono(NULL) - start_time));

	if (inject == TEST_FSRVP_TOUT_PREPARE) {
		sleep_time = lpcfg_parm_int(tctx->lp_ctx, NULL, "fss",
					    "sequence timeout", 1800);
		torture_comment(tctx, "sleeping for %d\n", sleep_time);
		smb_msleep((sleep_time * 1000) + 500);
	}

	start_time = time_mono(NULL);
	ZERO_STRUCT(r_scset_commit);
	r_scset_commit.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_commit.in.TimeOutInMilliseconds = (180 * 1000);	/* win8 */
	status = dcerpc_fss_CommitShadowCopySet_r(b, tmp_ctx, &r_scset_commit);
	torture_assert_ntstatus_ok(tctx, status,
				   "CommitShadowCopySet failed");
	if (inject == TEST_FSRVP_TOUT_PREPARE) {
		torture_assert_int_equal(tctx, r_scset_commit.out.result,
					 HRES_ERROR_V(HRES_E_INVALIDARG),
					 "CommitShadowCopySet tout response");
		goto done;
	}
	torture_assert_int_equal(tctx, r_scset_commit.out.result, 0,
				 "failed CommitShadowCopySet response");
	torture_comment(tctx, "%s: commit completed in %llu secs\n",
			GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
			(unsigned long long)(time_mono(NULL) - start_time));

	if (inject == TEST_FSRVP_TOUT_COMMIT) {
		sleep_time = lpcfg_parm_int(tctx->lp_ctx, NULL, "fss",
					    "sequence timeout", 180);
		torture_comment(tctx, "sleeping for %d\n", sleep_time);
		smb_msleep((sleep_time * 1000) + 500);
	} else if (inject == TEST_FSRVP_STOP_B4_EXPOSE) {
		/* return partial snapshot information */
		map = talloc_zero(tctx, struct fssagent_share_mapping_1);
		map->ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
		map->ShadowCopyId = *r_scset_add1.out.pShadowCopyId;
		goto done;
	}

	start_time = time_mono(NULL);
	ZERO_STRUCT(r_scset_expose);
	r_scset_expose.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_expose.in.TimeOutInMilliseconds = (120 * 1000);	/* win8 */
	status = dcerpc_fss_ExposeShadowCopySet_r(b, tmp_ctx, &r_scset_expose);
	torture_assert_ntstatus_ok(tctx, status,
				   "ExposeShadowCopySet failed");
	if (inject == TEST_FSRVP_TOUT_COMMIT) {
		torture_assert_int_equal(tctx, r_scset_expose.out.result,
					 HRES_ERROR_V(HRES_E_INVALIDARG),
					 "ExposeShadowCopySet tout response");
		goto done;
	}
	torture_assert_int_equal(tctx, r_scset_expose.out.result, 0,
				 "failed ExposeShadowCopySet response");
	torture_comment(tctx, "%s: expose completed in %llu secs\n",
			GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
			(unsigned long long)(time_mono(NULL) - start_time));

	ZERO_STRUCT(r_sharemap_get);
	r_sharemap_get.in.ShadowCopyId = *r_scset_add1.out.pShadowCopyId;
	r_sharemap_get.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_sharemap_get.in.ShareName = r_scset_add1.in.ShareName;
	r_sharemap_get.in.Level = 1;
	status = dcerpc_fss_GetShareMapping_r(b, tmp_ctx, &r_sharemap_get);
	torture_assert_ntstatus_ok(tctx, status, "GetShareMapping failed");
	torture_assert_int_equal(tctx, r_sharemap_get.out.result, 0,
				 "failed GetShareMapping response");
	torture_comment(tctx, "%s(%s): %s is a snapshot of %s at %s\n",
			GUID_string(tmp_ctx, &r_sharemap_get.out.ShareMapping->ShareMapping1->ShadowCopySetId),
			GUID_string(tmp_ctx, &r_sharemap_get.out.ShareMapping->ShareMapping1->ShadowCopyId),
			r_sharemap_get.out.ShareMapping->ShareMapping1->ShadowCopyShareName,
			r_sharemap_get.out.ShareMapping->ShareMapping1->ShareNameUNC,
			nt_time_string(tmp_ctx, r_sharemap_get.out.ShareMapping->ShareMapping1->tstamp));

	map = talloc_zero(tctx, struct fssagent_share_mapping_1);
	map->ShadowCopySetId = r_sharemap_get.out.ShareMapping->ShareMapping1->ShadowCopySetId;
	map->ShadowCopyId = r_sharemap_get.out.ShareMapping->ShareMapping1->ShadowCopyId;
	map->ShadowCopyShareName
		= talloc_strdup(tctx, r_sharemap_get.out.ShareMapping->ShareMapping1->ShadowCopyShareName);
	map->ShareNameUNC
		= talloc_strdup(tctx, r_sharemap_get.out.ShareMapping->ShareMapping1->ShareNameUNC);
	map->tstamp = r_sharemap_get.out.ShareMapping->ShareMapping1->tstamp;

	torture_assert(tctx, !GUID_compare(&r_sharemap_get.in.ShadowCopySetId,
					   &map->ShadowCopySetId),
		       "sc_set GUID mismatch in GetShareMapping");
	torture_assert(tctx, !GUID_compare(&r_sharemap_get.in.ShadowCopyId,
					   &map->ShadowCopyId),
		       "sc GUID mismatch in GetShareMapping");

done:
	talloc_free(tmp_ctx);
	*sc_map = map;

	return true;
}

static bool test_fsrvp_sc_delete(struct torture_context *tctx,
				 struct dcerpc_pipe *p,
				 struct fssagent_share_mapping_1 *sc_map)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct fss_DeleteShareMapping r_sharemap_del;
	NTSTATUS status;

	ZERO_STRUCT(r_sharemap_del);
	r_sharemap_del.in.ShadowCopySetId = sc_map->ShadowCopySetId;
	r_sharemap_del.in.ShadowCopyId = sc_map->ShadowCopyId;
	r_sharemap_del.in.ShareName = sc_map->ShareNameUNC;
	status = dcerpc_fss_DeleteShareMapping_r(b, tctx, &r_sharemap_del);
	torture_assert_ntstatus_ok(tctx, status, "DeleteShareMapping failed");
	torture_assert_int_equal(tctx, r_sharemap_del.out.result, 0,
				 "failed DeleteShareMapping response");

	return true;
}

static bool test_fsrvp_sc_create_simple(struct torture_context *tctx,
					 struct dcerpc_pipe *p)
{
	struct fssagent_share_mapping_1 *sc_map;
	/* no trailing backslash - should work. See note in cmd_fss.c */
	char *share_unc = talloc_asprintf(tctx, "\\\\%s\\%s",
					  dcerpc_server_name(p), FSHARE);

	torture_assert(tctx, test_fsrvp_sc_create(tctx, p, share_unc, TEST_FSRVP_TOUT_NONE, &sc_map),
		       "sc create");

	torture_assert(tctx, test_fsrvp_sc_delete(tctx, p, sc_map), "sc del");

	return true;
}

static bool test_fsrvp_sc_set_abort(struct torture_context *tctx,
				    struct dcerpc_pipe *p)
{
	char *share_unc = talloc_asprintf(tctx, "\\\\%s\\%s\\",
					  dcerpc_server_name(p), FSHARE);
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct fss_IsPathSupported r_pathsupport_get;
	struct fss_GetSupportedVersion r_version_get;
	struct fss_SetContext r_context_set;
	struct fss_StartShadowCopySet r_scset_start;
	struct fss_AbortShadowCopySet r_scset_abort;
	struct fss_AddToShadowCopySet r_scset_add;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tctx);

	ZERO_STRUCT(r_pathsupport_get);
	r_pathsupport_get.in.ShareName = share_unc;
	status = dcerpc_fss_IsPathSupported_r(b, tmp_ctx, &r_pathsupport_get);
	torture_assert_ntstatus_ok(tctx, status,
				   "IsPathSupported failed");
	torture_assert(tctx, r_pathsupport_get.out.SupportedByThisProvider,
		       "path not supported");

	ZERO_STRUCT(r_version_get);
	status = dcerpc_fss_GetSupportedVersion_r(b, tmp_ctx, &r_version_get);
	torture_assert_ntstatus_ok(tctx, status,
				   "GetSupportedVersion failed");

	ZERO_STRUCT(r_context_set);
	r_context_set.in.Context = FSRVP_CTX_BACKUP;
	status = dcerpc_fss_SetContext_r(b, tmp_ctx, &r_context_set);
	torture_assert_ntstatus_ok(tctx, status, "SetContext failed");

	ZERO_STRUCT(r_scset_start);
	r_scset_start.in.ClientShadowCopySetId = GUID_random();
	status = dcerpc_fss_StartShadowCopySet_r(b, tmp_ctx, &r_scset_start);
	torture_assert_ntstatus_ok(tctx, status,
				   "StartShadowCopySet failed");

	ZERO_STRUCT(r_scset_abort);
	r_scset_abort.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	status = dcerpc_fss_AbortShadowCopySet_r(b, tmp_ctx, &r_scset_abort);
	torture_assert_ntstatus_ok(tctx, status,
				   "AbortShadowCopySet failed");

	ZERO_STRUCT(r_scset_add);
	r_scset_add.in.ClientShadowCopyId = GUID_random();
	r_scset_add.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_add.in.ShareName = share_unc;
	status = dcerpc_fss_AddToShadowCopySet_r(b, tmp_ctx, &r_scset_add);
	torture_assert_ntstatus_ok(tctx, status, "AddToShadowCopySet failed "
				   "following abort");
	/*
	 * XXX Windows 8 server beta returns FSRVP_E_BAD_STATE here rather than
	 * FSRVP_E_BAD_ID / HRES_E_INVALIDARG.
	 */
	torture_assert(tctx, (r_scset_add.out.result != 0),
		       "incorrect AddToShadowCopySet response following abort");

	talloc_free(tmp_ctx);
	return true;
}

static bool test_fsrvp_bad_id(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	struct fssagent_share_mapping_1 *sc_map;
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct fss_DeleteShareMapping r_sharemap_del;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tctx);
	char *share_unc = talloc_asprintf(tmp_ctx, "\\\\%s\\%s\\",
					  dcerpc_server_name(p), FSHARE);

	torture_assert(tctx, test_fsrvp_sc_create(tctx, p, share_unc, TEST_FSRVP_TOUT_NONE, &sc_map),
		       "sc create");

	ZERO_STRUCT(r_sharemap_del);
	r_sharemap_del.in.ShadowCopySetId = sc_map->ShadowCopySetId;
	r_sharemap_del.in.ShadowCopySetId.time_low++;	/* bogus */
	r_sharemap_del.in.ShadowCopyId = sc_map->ShadowCopyId;
	r_sharemap_del.in.ShareName = sc_map->ShareNameUNC;
	status = dcerpc_fss_DeleteShareMapping_r(b, tmp_ctx, &r_sharemap_del);
	torture_assert_ntstatus_ok(tctx, status,
				   "DeleteShareMapping failed");
	torture_assert_int_equal(tctx, r_sharemap_del.out.result,
				 FSRVP_E_OBJECT_NOT_FOUND,
				 "incorrect DeleteShareMapping response");

	r_sharemap_del.in.ShadowCopySetId = sc_map->ShadowCopySetId;
	r_sharemap_del.in.ShadowCopyId.time_mid++;	/* bogus */
	status = dcerpc_fss_DeleteShareMapping_r(b, tmp_ctx, &r_sharemap_del);
	torture_assert_ntstatus_ok(tctx, status,
				   "DeleteShareMapping failed");
	torture_assert_int_equal(tctx, r_sharemap_del.out.result,
				 HRES_ERROR_V(HRES_E_INVALIDARG),
				 "incorrect DeleteShareMapping response");

	torture_assert(tctx, test_fsrvp_sc_delete(tctx, p, sc_map), "sc del");

	talloc_free(sc_map);
	talloc_free(tmp_ctx);

	return true;
}

static bool test_fsrvp_sc_share_io(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	struct fssagent_share_mapping_1 *sc_map;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tctx);
	char *share_unc = talloc_asprintf(tmp_ctx, "\\\\%s\\%s",
					  dcerpc_server_name(p), FSHARE);
	struct smb2_tree *tree_base;
	struct smb2_tree *tree_snap;
	struct smbcli_options options;
	struct smb2_handle base_fh;
	struct smb2_read r;
	struct smb2_create io;
	lpcfg_smbcli_options(tctx->lp_ctx, &options);

	status = smb2_connect(tmp_ctx,
			      dcerpc_server_name(p),
			      lpcfg_smb_ports(tctx->lp_ctx),
			      FSHARE,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      popt_get_cmdline_credentials(),
			      &tree_base,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status,
				   "Failed to connect to SMB2 share");

	smb2_util_unlink(tree_base, FNAME);
	status = torture_smb2_testfile(tree_base, FNAME, &base_fh);
	torture_assert_ntstatus_ok(tctx, status, "base write open");

	status = smb2_util_write(tree_base, base_fh, "pre-snap", 0,
				 sizeof("pre-snap"));
	torture_assert_ntstatus_ok(tctx, status, "src write");


	torture_assert(tctx, test_fsrvp_sc_create(tctx, p, share_unc, TEST_FSRVP_TOUT_NONE, &sc_map),
		       "sc create");

	status = smb2_util_write(tree_base, base_fh, "post-snap", 0,
				 sizeof("post-snap"));
	torture_assert_ntstatus_ok(tctx, status, "base write");

	/* connect to snapshot share and verify pre-snapshot data */
	status = smb2_connect(tmp_ctx,
			      dcerpc_server_name(p),
			      lpcfg_smb_ports(tctx->lp_ctx),
			      sc_map->ShadowCopyShareName,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      popt_get_cmdline_credentials(),
			      &tree_snap,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status,
				   "Failed to connect to SMB2 shadow-copy share");
	/* Windows server 8 allows RW open to succeed here for a ro snapshot */
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_RIGHTS_FILE_READ;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = FNAME;
	status = smb2_create(tree_snap, tmp_ctx, &io);
	torture_assert_ntstatus_ok(tctx, status, "snap read open");

	ZERO_STRUCT(r);
	r.in.file.handle = io.out.file.handle;
	r.in.length      = sizeof("pre-snap");
	status = smb2_read(tree_snap, tmp_ctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "read");
	torture_assert_u64_equal(tctx, r.out.data.length, r.in.length,
				 "read data len mismatch");
	torture_assert_str_equal(tctx, (char *)r.out.data.data, "pre-snap",
				 "bad snapshot data");

	torture_assert(tctx, test_fsrvp_sc_delete(tctx, p, sc_map), "sc del");

	talloc_free(sc_map);
	talloc_free(tmp_ctx);

	return true;
}

static bool test_fsrvp_enum_snaps(struct torture_context *tctx,
				  TALLOC_CTX *mem_ctx,
				  struct smb2_tree *tree,
				  struct smb2_handle fh,
				  int *_count)
{
	struct smb2_ioctl io;
	NTSTATUS status;

	ZERO_STRUCT(io);
	io.level = RAW_IOCTL_SMB2;
	io.in.file.handle = fh;
	io.in.function = FSCTL_SRV_ENUM_SNAPS;
	io.in.max_output_response = 16;
	io.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	status = smb2_ioctl(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok(tctx, status, "enum ioctl");

	*_count = IVAL(io.out.out.data, 0);

	/* with max_output_response=16, no labels should be sent */
	torture_assert_int_equal(tctx, IVAL(io.out.out.data, 4), 0,
				 "enum snaps labels");

	/* TODO with 0 snaps, needed_data_count should be 0? */
	if (*_count != 0) {
		torture_assert(tctx, IVAL(io.out.out.data, 8) != 0,
			       "enum snaps needed non-zero");
	}

	return true;
}

static bool test_fsrvp_enum_created(struct torture_context *tctx,
				    struct dcerpc_pipe *p)
{
	struct fssagent_share_mapping_1 *sc_map;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tctx);
	char *share_unc = talloc_asprintf(tmp_ctx, "\\\\%s\\%s\\",
					  dcerpc_server_name(p), FSHARE);
	struct smb2_tree *tree_base;
	struct smbcli_options options;
	struct smb2_handle base_fh;
	int count;
	lpcfg_smbcli_options(tctx->lp_ctx, &options);

	status = smb2_connect(tmp_ctx,
			      dcerpc_server_name(p),
			      lpcfg_smb_ports(tctx->lp_ctx),
			      FSHARE,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      popt_get_cmdline_credentials(),
			      &tree_base,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status,
				   "Failed to connect to SMB2 share");

	smb2_util_unlink(tree_base, FNAME);
	status = torture_smb2_testfile(tree_base, FNAME, &base_fh);
	torture_assert_ntstatus_ok(tctx, status, "base write open");

	status = smb2_util_write(tree_base, base_fh, "pre-snap", 0,
				 sizeof("pre-snap"));
	torture_assert_ntstatus_ok(tctx, status, "src write");

	torture_assert(tctx,
		       test_fsrvp_enum_snaps(tctx, tmp_ctx, tree_base, base_fh,
					     &count),
		       "count");
	torture_assert_int_equal(tctx, count, 0, "num snaps");

	torture_assert(tctx, test_fsrvp_sc_create(tctx, p, share_unc, TEST_FSRVP_TOUT_NONE, &sc_map),
		       "sc create");
	talloc_free(sc_map);

	torture_assert(tctx,
		       test_fsrvp_enum_snaps(tctx, tmp_ctx, tree_base, base_fh,
					     &count),
		       "count");
	/*
	 * Snapshots created via FSRVP on Windows Server 2012 are not added to
	 * the previous versions list, so it will fail here...
	 */
	torture_assert_int_equal(tctx, count, 1, "num snaps");

	smb_msleep(1100);	/* @GMT tokens have a 1 second resolution */
	torture_assert(tctx, test_fsrvp_sc_create(tctx, p, share_unc, TEST_FSRVP_TOUT_NONE, &sc_map),
		       "sc create");
	talloc_free(sc_map);

	torture_assert(tctx,
		       test_fsrvp_enum_snaps(tctx, tmp_ctx, tree_base, base_fh,
					     &count),
		       "count");
	torture_assert_int_equal(tctx, count, 2, "num snaps");

	talloc_free(tmp_ctx);

	return true;
}

static bool test_fsrvp_seq_timeout(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	int i;
	struct fssagent_share_mapping_1 *sc_map;
	char *share_unc = talloc_asprintf(tctx, "\\\\%s\\%s",
					  dcerpc_server_name(p), FSHARE);

	for (i = TEST_FSRVP_TOUT_NONE; i <= TEST_FSRVP_TOUT_COMMIT; i++) {
		torture_assert(tctx, test_fsrvp_sc_create(tctx, p, share_unc,
							  i, &sc_map),
			       "sc create");

		/* only need to delete if create process didn't timeout */
		if (i == TEST_FSRVP_TOUT_NONE) {
			torture_assert(tctx, test_fsrvp_sc_delete(tctx, p, sc_map),
				       "sc del");
		}
	}

	return true;
}

static bool test_fsrvp_share_sd(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct dcerpc_pipe *srvsvc_p;
	struct srvsvc_NetShareGetInfo q;
	struct srvsvc_NetShareSetInfo s;
	struct srvsvc_NetShareInfo502 *info502;
	struct fssagent_share_mapping_1 *sc_map;
	struct fss_ExposeShadowCopySet r_scset_expose;
	struct fss_GetShareMapping r_sharemap_get;
	struct security_descriptor *sd_old;
	struct security_descriptor *sd_base;
	struct security_descriptor *sd_snap;
	struct security_ace *ace;
	int i;
	int aces_found;
	char *share_unc = talloc_asprintf(tctx, "\\\\%s\\%s",
					  dcerpc_server_name(p), FSHARE);
	ZERO_STRUCT(q);
	q.in.server_unc = dcerpc_server_name(p);
	q.in.share_name = FSHARE;
	q.in.level = 502;

	status = torture_rpc_connection(tctx, &srvsvc_p, &ndr_table_srvsvc);
	torture_assert_ntstatus_ok(tctx, status, "srvsvc rpc conn failed");

	/* ensure srvsvc out pointers are allocated during unmarshalling */
	srvsvc_p->conn->flags |= DCERPC_NDR_REF_ALLOC;

	/* obtain the existing DACL for the base share */
	status = dcerpc_srvsvc_NetShareGetInfo_r(srvsvc_p->binding_handle,
						 tctx, &q);
	torture_assert_ntstatus_ok(tctx, status, "NetShareGetInfo failed");
	torture_assert_werr_ok(tctx, q.out.result, "NetShareGetInfo failed");

	info502 = q.out.info->info502;

	/* back up the existing share SD, so it can be restored on completion */
	sd_old = info502->sd_buf.sd;
	sd_base = security_descriptor_copy(tctx, info502->sd_buf.sd);
	torture_assert(tctx, sd_base != NULL, "sd dup");
	torture_assert(tctx, sd_base->dacl != NULL, "no existing share DACL");

	/* the Builtin_X_Operators placeholder ACEs need to be unique */
	for (i = 0; i < sd_base->dacl->num_aces; i++) {
		ace = &sd_base->dacl->aces[i];
		if (dom_sid_equal(&ace->trustee,
				  &global_sid_Builtin_Backup_Operators)
		 || dom_sid_equal(&ace->trustee,
				  &global_sid_Builtin_Print_Operators)) {
			torture_skip(tctx, "placeholder ACE already exists\n");
		}
	}

	/* add Backup_Operators placeholder ACE and set base share DACL */
	ace = talloc_zero(tctx, struct security_ace);
	ace->type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace->access_mask = SEC_STD_SYNCHRONIZE;
	ace->trustee = global_sid_Builtin_Backup_Operators;

	status = security_descriptor_dacl_add(sd_base, ace);
	torture_assert_ntstatus_ok(tctx, status,
				   "failed to add placeholder ACE to DACL");

	info502->sd_buf.sd = sd_base;
	info502->sd_buf.sd_size = ndr_size_security_descriptor(sd_base, 0);

	ZERO_STRUCT(s);
	s.in.server_unc = dcerpc_server_name(p);
	s.in.share_name = FSHARE;
	s.in.level = 502;
	s.in.info = q.out.info;

	status = dcerpc_srvsvc_NetShareSetInfo_r(srvsvc_p->binding_handle,
						 tctx, &s);
	torture_assert_ntstatus_ok(tctx, status, "NetShareSetInfo failed");
	torture_assert_werr_ok(tctx, s.out.result, "NetShareSetInfo failed");

	/* create a snapshot, but don't expose yet */
	torture_assert(tctx,
		       test_fsrvp_sc_create(tctx, p, share_unc,
					    TEST_FSRVP_STOP_B4_EXPOSE, &sc_map),
		       "sc create");

	/*
	 * Add another unique placeholder ACE.
	 * By changing the share DACL between snapshot creation and exposure we
	 * can determine at which point the server clones the base share DACL.
	 */
	ace = talloc_zero(tctx, struct security_ace);
	ace->type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace->access_mask = SEC_STD_SYNCHRONIZE;
	ace->trustee = global_sid_Builtin_Print_Operators;

	status = security_descriptor_dacl_add(sd_base, ace);
	torture_assert_ntstatus_ok(tctx, status,
				   "failed to add placeholder ACE to DACL");

	info502->sd_buf.sd = sd_base;
	info502->sd_buf.sd_size = ndr_size_security_descriptor(sd_base, 0);

	ZERO_STRUCT(s);
	s.in.server_unc = dcerpc_server_name(p);
	s.in.share_name = FSHARE;
	s.in.level = 502;
	s.in.info = q.out.info;

	status = dcerpc_srvsvc_NetShareSetInfo_r(srvsvc_p->binding_handle,
						 tctx, &s);
	torture_assert_ntstatus_ok(tctx, status, "NetShareSetInfo failed");
	torture_assert_werr_ok(tctx, s.out.result, "NetShareSetInfo failed");

	/* expose the snapshot share and get the new share details */
	ZERO_STRUCT(r_scset_expose);
	r_scset_expose.in.ShadowCopySetId = sc_map->ShadowCopySetId;
	r_scset_expose.in.TimeOutInMilliseconds = (120 * 1000);	/* win8 */
	status = dcerpc_fss_ExposeShadowCopySet_r(p->binding_handle, tctx,
						  &r_scset_expose);
	torture_assert_ntstatus_ok(tctx, status,
				   "ExposeShadowCopySet failed");
	torture_assert_int_equal(tctx, r_scset_expose.out.result, 0,
				 "failed ExposeShadowCopySet response");

	ZERO_STRUCT(r_sharemap_get);
	r_sharemap_get.in.ShadowCopyId = sc_map->ShadowCopyId;
	r_sharemap_get.in.ShadowCopySetId = sc_map->ShadowCopySetId;
	r_sharemap_get.in.ShareName = share_unc;
	r_sharemap_get.in.Level = 1;
	status = dcerpc_fss_GetShareMapping_r(p->binding_handle, tctx,
					      &r_sharemap_get);
	torture_assert_ntstatus_ok(tctx, status, "GetShareMapping failed");
	torture_assert_int_equal(tctx, r_sharemap_get.out.result, 0,
				 "failed GetShareMapping response");
	talloc_free(sc_map);
	sc_map = r_sharemap_get.out.ShareMapping->ShareMapping1;

	/* restore the original base share ACL */
	info502->sd_buf.sd = sd_old;
	info502->sd_buf.sd_size = ndr_size_security_descriptor(sd_old, 0);
	status = dcerpc_srvsvc_NetShareSetInfo_r(srvsvc_p->binding_handle,
						 tctx, &s);
	torture_assert_ntstatus_ok(tctx, status, "NetShareSetInfo failed");
	torture_assert_werr_ok(tctx, s.out.result, "NetShareSetInfo failed");

	/* check for placeholder ACEs in the snapshot share DACL */
	ZERO_STRUCT(q);
	q.in.server_unc = dcerpc_server_name(p);
	q.in.share_name = sc_map->ShadowCopyShareName;
	q.in.level = 502;
	status = dcerpc_srvsvc_NetShareGetInfo_r(srvsvc_p->binding_handle,
						 tctx, &q);
	torture_assert_ntstatus_ok(tctx, status, "NetShareGetInfo failed");
	torture_assert_werr_ok(tctx, q.out.result, "NetShareGetInfo failed");
	info502 = q.out.info->info502;

	sd_snap = info502->sd_buf.sd;
	torture_assert(tctx, sd_snap != NULL, "sd");
	torture_assert(tctx, sd_snap->dacl != NULL, "no snap share DACL");

	aces_found = 0;
	for (i = 0; i < sd_snap->dacl->num_aces; i++) {
		ace = &sd_snap->dacl->aces[i];
		if (dom_sid_equal(&ace->trustee,
				  &global_sid_Builtin_Backup_Operators)) {
			torture_comment(tctx,
				"found share ACE added before snapshot\n");
			aces_found++;
		} else if (dom_sid_equal(&ace->trustee,
					 &global_sid_Builtin_Print_Operators)) {
			torture_comment(tctx,
				"found share ACE added after snapshot\n");
			aces_found++;
		}
	}
	/*
	 * Expect snapshot share to match the base share DACL at the time of
	 * exposure, not at the time of snapshot creation. This is in line with
	 * Windows Server 2012 behaviour.
	 */
	torture_assert_int_equal(tctx, aces_found, 2,
				"placeholder ACE missing from snap share DACL");

	torture_assert(tctx, test_fsrvp_sc_delete(tctx, p, sc_map), "sc del");

	return true;
}

static bool fsrvp_rpc_setup(struct torture_context *tctx, void **data)
{
	NTSTATUS status;
	struct torture_rpc_tcase *tcase = talloc_get_type(
						tctx->active_tcase, struct torture_rpc_tcase);
	struct torture_rpc_tcase_data *tcase_data;

	*data = tcase_data = talloc_zero(tctx, struct torture_rpc_tcase_data);
	tcase_data->credentials = popt_get_cmdline_credentials();

	status = torture_rpc_connection(tctx,
				&(tcase_data->pipe),
				tcase->table);

	torture_assert_ntstatus_ok(tctx, status, "Error connecting to server");

	/* XXX required, otherwise ndr out ptrs are not allocated */
	tcase_data->pipe->conn->flags |= DCERPC_NDR_REF_ALLOC;

	return true;
}

/*
   testing of FSRVP (FSS agent)
*/
struct torture_suite *torture_rpc_fsrvp(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "fsrvp");

	struct torture_rpc_tcase *tcase
		= torture_suite_add_rpc_iface_tcase(suite, "fsrvp",
						&ndr_table_FileServerVssAgent);
	/* override torture_rpc_setup() to set DCERPC_NDR_REF_ALLOC */
	tcase->tcase.setup = fsrvp_rpc_setup;

	torture_rpc_tcase_add_test(tcase, "share_sd",
				   test_fsrvp_share_sd);
	torture_rpc_tcase_add_test(tcase, "seq_timeout",
				   test_fsrvp_seq_timeout);
	torture_rpc_tcase_add_test(tcase, "enum_created",
				   test_fsrvp_enum_created);
	torture_rpc_tcase_add_test(tcase, "sc_share_io",
				   test_fsrvp_sc_share_io);
	torture_rpc_tcase_add_test(tcase, "bad_id",
				   test_fsrvp_bad_id);
	torture_rpc_tcase_add_test(tcase, "sc_set_abort",
				   test_fsrvp_sc_set_abort);
	torture_rpc_tcase_add_test(tcase, "create_simple",
				   test_fsrvp_sc_create_simple);
	torture_rpc_tcase_add_test(tcase, "set_ctx",
				   test_fsrvp_set_ctx);
	torture_rpc_tcase_add_test(tcase, "get_version",
				   test_fsrvp_get_version);
	torture_rpc_tcase_add_test(tcase, "is_path_supported",
				   test_fsrvp_is_path_supported);

	return suite;
}
