/*
 * Unix SMB/CIFS implementation.
 *
 * test SMB2 multichannel operations
 *
 * Copyright (C) Guenther Deschner, 2016
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_ioctl.h"
#include "../libcli/smb/smbXcli_base.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) Incorrect status %s - should be %s\n", \
			 __location__, nt_errstr(status), nt_errstr(correct)); \
		return false; \
	} } while (0)

static bool test_ioctl_network_interface_info(struct torture_context *tctx,
					      struct smb2_tree *tree,
					      struct fsctl_net_iface_info *info)
{
	union smb_ioctl ioctl;
	struct smb2_handle fh;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_MULTI_CHANNEL)) {
		torture_skip(tctx,
			    "server doesn't support SMB2_CAP_MULTI_CHANNEL\n");
	}

	ZERO_STRUCT(ioctl);

	ioctl.smb2.level = RAW_IOCTL_SMB2;

	fh.data[0] = UINT64_MAX;
	fh.data[1] = UINT64_MAX;

	ioctl.smb2.in.file.handle = fh;
	ioctl.smb2.in.function = FSCTL_QUERY_NETWORK_INTERFACE_INFO;
	/* Windows client sets this to 64KiB */
	ioctl.smb2.in.max_output_response = 0x10000;
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	torture_assert_ntstatus_ok(tctx,
		smb2_ioctl(tree, tctx, &ioctl.smb2),
		"FSCTL_QUERY_NETWORK_INTERFACE_INFO failed");

	torture_assert(tctx,
		(ioctl.smb2.out.out.length != 0),
		"no interface info returned???");

	torture_assert_ndr_success(tctx,
		ndr_pull_struct_blob(&ioctl.smb2.out.out, tctx, info,
			(ndr_pull_flags_fn_t)ndr_pull_fsctl_net_iface_info),
		"failed to ndr pull");

	if (DEBUGLVL(1)) {
		NDR_PRINT_DEBUG(fsctl_net_iface_info, info);
	}

	return true;
}

static bool test_multichannel_interface_info(struct torture_context *tctx,
					     struct smb2_tree *tree)
{
	struct fsctl_net_iface_info info;

	return test_ioctl_network_interface_info(tctx, tree, &info);
}

struct torture_suite *torture_smb2_multichannel_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "multichannel");

	torture_suite_add_1smb2_test(suite, "interface_info",
				     test_multichannel_interface_info);

	suite->description = talloc_strdup(suite, "SMB2 Multichannel tests");

	return suite;
}
