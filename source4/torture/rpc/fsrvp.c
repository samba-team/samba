/*
   Unix SMB/CIFS implementation.

   test suite for File Server Remote VSS Protocol operations

   Copyright (C) David Disseldorp 2012

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
#include "librpc/gen_ndr/security.h"
#include "lib/param/param.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb_composite/smb_composite.h"
#include "libcli/resolve/resolve.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "torture/rpc/torture_rpc.h"
#include "librpc/gen_ndr/ndr_fsrvp.h"
#include "librpc/gen_ndr/ndr_fsrvp_c.h"

#define FSHARE	"hyper"
#define FNAME	"testfss.dat"
#define FNAME2	"testfss2.dat"

uint8_t fsrvp_magic[] = {0x8a, 0xe3, 0x13, 0x71, 0x02, 0xf4, 0x36, 0x71,
			 0x02, 0x40, 0x28, 0x00, 0x3c, 0x65, 0xe0, 0xa8,
			 0x44, 0x27, 0x89, 0x43, 0xa6, 0x1d, 0x73, 0x73,
			 0xdf, 0x8b, 0x22, 0x92, 0x01, 0x00, 0x00, 0x00,
			 0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49,
			 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
			 0x01, 0x00, 0x00, 0x00};

static bool test_fsrvp_is_path_supported(struct torture_context *tctx,
					 struct dcerpc_pipe *p)
{
	struct fss_IsPathSupported r;
	struct dcerpc_binding_handle *b = p->binding_handle;
	NTSTATUS status;

	ZERO_STRUCT(r);
	r.in.ShareName = talloc_asprintf(tctx,"\\\\%s\\%s",
					 dcerpc_server_name(p),
					 FSHARE);
	/* win8 beta sends this */
	memcpy(r.in.magic, fsrvp_magic, sizeof(fsrvp_magic));
	status = dcerpc_fss_IsPathSupported_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status,
				   "IsPathSupported failed");

	ZERO_STRUCT(r);
	r.in.ShareName = talloc_asprintf(tctx,"\\\\%s\\%s",
					 dcerpc_server_name(p),
					 FSHARE);
	/* also works without magic */
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
	/* win8 beta sends this */
	memcpy(r.in.magic, fsrvp_magic, sizeof(fsrvp_magic));
	status = dcerpc_fss_GetSupportedVersion_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status,
				   "GetSupportedVersion failed with magic");

	ZERO_STRUCT(r);
	/* also works without magic */
	status = dcerpc_fss_GetSupportedVersion_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status,
				   "GetSupportedVersion failed without magic");

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

static bool test_fsrvp_sc_create(struct torture_context *tctx,
				 struct dcerpc_pipe *p,
				 const char *share,
				 struct fssagent_share_mapping_1 **sc_map)
{
	struct fss_IsPathSupported r_pathsupport_get;
	struct fss_GetSupportedVersion r_version_get;
	struct fss_SetContext r_context_set;
	struct fss_StartShadowCopySet r_scset_start;
	struct fss_AddToShadowCopySet r_scset_add;
	struct fss_PrepareShadowCopySet r_scset_prep;
	struct fss_CommitShadowCopySet r_scset_commit;
	struct fss_ExposeShadowCopySet r_scset_expose;
	struct fss_GetShareMapping r_sharemap_get;
	struct dcerpc_binding_handle *b = p->binding_handle;
	NTSTATUS status;
	time_t start_time;
	TALLOC_CTX *tmp_ctx = talloc_new(tctx);
	struct fssagent_share_mapping_1 *map;

	/*
	 * PrepareShadowCopySet & CommitShadowCopySet often exceed the default
	 * 60 second dcerpc request timeout against Windows Server "8" Beta.
	 */
	dcerpc_binding_handle_set_timeout(b, 240);

	ZERO_STRUCT(r_pathsupport_get);	/* sending with zeroed magic */
	r_pathsupport_get.in.ShareName = share;
	status = dcerpc_fss_IsPathSupported_r(b, tmp_ctx, &r_pathsupport_get);
	torture_assert_ntstatus_ok(tctx, status,
				   "IsPathSupported failed");
	torture_assert_int_equal(tctx, r_pathsupport_get.out.result, 0,
				 "failed IsPathSupported response");
	torture_assert(tctx, r_pathsupport_get.out.SupportedByThisProvider,
		       "path not supported");

	ZERO_STRUCT(r_version_get);	/* sending with zeroed magic */
	status = dcerpc_fss_GetSupportedVersion_r(b, tmp_ctx, &r_version_get);
	torture_assert_ntstatus_ok(tctx, status,
				   "GetSupportedVersion failed without magic");
	torture_assert_int_equal(tctx, r_version_get.out.result, 0,
				 "failed GetSupportedVersion response");

	ZERO_STRUCT(r_context_set);
	r_context_set.in.Context = FSRVP_CTX_BACKUP;
	status = dcerpc_fss_SetContext_r(b, tmp_ctx, &r_context_set);
	torture_assert_ntstatus_ok(tctx, status, "SetContext failed");
	torture_assert_int_equal(tctx, r_context_set.out.result, 0,
				 "failed SetContext response");

	ZERO_STRUCT(r_scset_start);
	r_scset_start.in.ClientShadowCopySetId = GUID_random();
	status = dcerpc_fss_StartShadowCopySet_r(b, tmp_ctx, &r_scset_start);
	torture_assert_ntstatus_ok(tctx, status,
				   "StartShadowCopySet failed");
	torture_assert_int_equal(tctx, r_scset_start.out.result, 0,
				 "failed StartShadowCopySet response");
	torture_comment(tctx, "%s: shadow-copy set created\n",
			GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId));

	ZERO_STRUCT(r_scset_add);
	r_scset_add.in.ClientShadowCopyId = GUID_random();
	r_scset_add.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_add.in.ShareName = share;
	status = dcerpc_fss_AddToShadowCopySet_r(b, tmp_ctx, &r_scset_add);
	torture_assert_ntstatus_ok(tctx, status,
				   "AddToShadowCopySet failed");
	torture_assert_int_equal(tctx, r_scset_add.out.result, 0,
				 "failed AddToShadowCopySet response");
	torture_comment(tctx, "%s(%s): %s added to shadow-copy set\n",
			GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
			GUID_string(tmp_ctx, r_scset_add.out.pShadowCopyId),
			r_scset_add.in.ShareName);

	start_time = time_mono(NULL);
	ZERO_STRUCT(r_scset_prep);
	r_scset_prep.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
//	r_scset_prep.in.TimeOutInMilliseconds = (1800 * 1000);	/* win8 */
	r_scset_prep.in.TimeOutInMilliseconds = (240 * 1000);
	status = dcerpc_fss_PrepareShadowCopySet_r(b, tmp_ctx, &r_scset_prep);
	torture_assert_ntstatus_ok(tctx, status,
				   "PrepareShadowCopySet failed");
	torture_assert_int_equal(tctx, r_scset_prep.out.result, 0,
				 "failed PrepareShadowCopySet response");
	torture_comment(tctx, "%s: prepare completed in %llu secs\n",
			GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
			(unsigned long long)(time_mono(NULL) - start_time));

	start_time = time_mono(NULL);
	ZERO_STRUCT(r_scset_commit);
	r_scset_commit.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_commit.in.TimeOutInMilliseconds = (180 * 1000);	/* win8 */
	status = dcerpc_fss_CommitShadowCopySet_r(b, tmp_ctx, &r_scset_commit);
	torture_assert_ntstatus_ok(tctx, status,
				   "CommitShadowCopySet failed");
	torture_assert_int_equal(tctx, r_scset_commit.out.result, 0,
				 "failed CommitShadowCopySet response");
	torture_comment(tctx, "%s: commit completed in %llu secs\n",
			GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
			(unsigned long long)(time_mono(NULL) - start_time));

	start_time = time_mono(NULL);
	ZERO_STRUCT(r_scset_expose);
	r_scset_expose.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_expose.in.TimeOutInMilliseconds = (120 * 1000);	/* win8 */
	status = dcerpc_fss_ExposeShadowCopySet_r(b, tmp_ctx, &r_scset_expose);
	torture_assert_ntstatus_ok(tctx, status,
				   "ExposeShadowCopySet failed");
	torture_assert_int_equal(tctx, r_scset_expose.out.result, 0,
				 "failed ExposeShadowCopySet response");
	torture_comment(tctx, "%s: expose completed in %llu secs\n",
			GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
			(unsigned long long)(time_mono(NULL) - start_time));

	ZERO_STRUCT(r_sharemap_get);
	r_sharemap_get.in.ShadowCopyId = *r_scset_add.out.pShadowCopyId;
	r_sharemap_get.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_sharemap_get.in.ShareName = r_scset_add.in.ShareName;
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
		       "sc_set GUID missmatch in GetShareMapping");
	torture_assert(tctx, !GUID_compare(&r_sharemap_get.in.ShadowCopyId,
					   &map->ShadowCopyId),
		       "sc GUID missmatch in GetShareMapping");

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
	char *share_unc = talloc_asprintf(tctx, "\\\\%s\\%s",
					  dcerpc_server_name(p), FSHARE);

	torture_assert(tctx, test_fsrvp_sc_create(tctx, p, share_unc, &sc_map),
		       "sc create");

	torture_assert(tctx, test_fsrvp_sc_delete(tctx, p, sc_map), "sc del");

	return true;
}

static bool test_fsrvp_sc_set_abort(struct torture_context *tctx,
				    struct dcerpc_pipe *p)
{
	char *share_unc = talloc_asprintf(tctx, "\\\\%s\\%s",
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

	ZERO_STRUCT(r_pathsupport_get);	/* sending with zeroed magic */
	r_pathsupport_get.in.ShareName = share_unc;
	status = dcerpc_fss_IsPathSupported_r(b, tmp_ctx, &r_pathsupport_get);
	torture_assert_ntstatus_ok(tctx, status,
				   "IsPathSupported failed");
	torture_assert(tctx, r_pathsupport_get.out.SupportedByThisProvider,
		       "path not supported");

	ZERO_STRUCT(r_version_get);	/* sending with zeroed magic */
	status = dcerpc_fss_GetSupportedVersion_r(b, tmp_ctx, &r_version_get);
	torture_assert_ntstatus_ok(tctx, status,
				   "GetSupportedVersion failed without magic");

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
	 * FSRVP_E_BAD_ID / E_INVALIDARG.
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
	char *share_unc = talloc_asprintf(tmp_ctx, "\\\\%s\\%s",
					  dcerpc_server_name(p), FSHARE);

	torture_assert(tctx, test_fsrvp_sc_create(tctx, p, share_unc, &sc_map),
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
				 FSRVP_E_BAD_ID,
				 "incorrect DeleteShareMapping response");

	r_sharemap_del.in.ShadowCopySetId = sc_map->ShadowCopySetId;
	r_sharemap_del.in.ShadowCopyId.time_mid++;	/* bogus */
	status = dcerpc_fss_DeleteShareMapping_r(b, tmp_ctx, &r_sharemap_del);
	torture_assert_ntstatus_ok(tctx, status,
				   "DeleteShareMapping failed");
	torture_assert_int_equal(tctx, r_sharemap_del.out.result,
				 FSRVP_E_BAD_ID,
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
	extern struct cli_credentials *cmdline_credentials;
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
			      cmdline_credentials,
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


	torture_assert(tctx, test_fsrvp_sc_create(tctx, p, share_unc, &sc_map),
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
			      cmdline_credentials,
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

static bool fsrvp_rpc_setup (struct torture_context *tctx, void **data)
{
	NTSTATUS status;
	struct torture_rpc_tcase *tcase = talloc_get_type(
						tctx->active_tcase, struct torture_rpc_tcase);
	struct torture_rpc_tcase_data *tcase_data;
	extern struct cli_credentials *cmdline_credentials;

	*data = tcase_data = talloc_zero(tctx, struct torture_rpc_tcase_data);
	tcase_data->credentials = cmdline_credentials;

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
