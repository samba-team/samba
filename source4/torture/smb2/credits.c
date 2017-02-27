/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 credits

   Copyright (C) Ralph Boehme 2017

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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/param/param.h"

/**
 * Request 64k credits in negprot/sessionsetup and require at least 8k
 *
 * This passes against Windows 2016
 **/
static bool test_session_setup_credits_granted(struct torture_context *tctx,
					       struct smb2_tree *_tree)
{
	struct smbcli_options options;
	struct smb2_transport *transport = NULL;
	struct smb2_tree *tree = NULL;
	uint16_t cur_credits;
	NTSTATUS status;
	bool ret = true;

	transport = _tree->session->transport;
	options = transport->options;

	status = smb2_logoff(_tree->session);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_logoff failed\n");
	TALLOC_FREE(_tree);

	options.max_credits = 65535;

	ret = torture_smb2_connection_ext(tctx, 0, &options, &tree);
	torture_assert_goto(tctx, ret == true, ret, done,
			    "torture_smb2_connection_ext failed\n");

	transport = tree->session->transport;

	cur_credits = smb2cli_conn_get_cur_credits(transport->conn);
	if (cur_credits < 8192) {
		torture_result(tctx, TORTURE_FAIL,
			       "Server only granted %" PRIu16" credits\n",
			       cur_credits);
		ret = false;
		goto done;
	}

done:
	TALLOC_FREE(tree);
	return ret;
}

/**
 * Request 64K credits in a single SMB2 request and requite at least 8192
 *
 * This passes against Windows 2016
 **/
static bool test_single_req_credits_granted(struct torture_context *tctx,
					    struct smb2_tree *_tree)
{
	struct smbcli_options options;
	struct smb2_transport *transport = NULL;
	struct smb2_tree *tree = NULL;
	struct smb2_handle h = {{0}};
	struct smb2_create create;
	const char *fname = "single_req_credits_granted.dat";
	uint16_t cur_credits;
	NTSTATUS status;
	bool ret = true;

	smb2_util_unlink(_tree, fname);

	transport = _tree->session->transport;
	options = transport->options;

	status = smb2_logoff(_tree->session);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_logoff failed\n");
	TALLOC_FREE(_tree);

	options.max_credits = 1;

	ret = torture_smb2_connection_ext(tctx, 0, &options, &tree);
	torture_assert_goto(tctx, ret == true, ret, done,
			    "torture_smb2_connection_ext failed\n");

	transport = tree->session->transport;

	cur_credits = smb2cli_conn_get_cur_credits(transport->conn);
	if (cur_credits != 1) {
		torture_result(tctx, TORTURE_FAIL,
			       "Only wanted 1 credit but server granted %" PRIu16"\n",
			       cur_credits);
		ret = false;
		goto done;
	}

	smb2cli_conn_set_max_credits(transport->conn, 65535);

	ZERO_STRUCT(create);
	create.in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	create.in.desired_access	= SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes	= FILE_ATTRIBUTE_NORMAL;
	create.in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	create.in.fname			= fname;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h = create.out.file.handle;

	cur_credits = smb2cli_conn_get_cur_credits(transport->conn);
	if (cur_credits < 8192) {
		torture_result(tctx, TORTURE_FAIL,
			       "Server only granted %" PRIu16" credits\n",
			       cur_credits);
		ret = false;
		goto done;
	}

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_util_unlink(tree, fname);
	TALLOC_FREE(tree);
	return ret;
}

struct torture_suite *torture_smb2_crediting_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "credits");

	torture_suite_add_1smb2_test(suite, "session_setup_credits_granted", test_session_setup_credits_granted);
	torture_suite_add_1smb2_test(suite, "single_req_credits_granted", test_single_req_credits_granted);

	suite->description = talloc_strdup(suite, "SMB2-CREDITS tests");

	return suite;
}
