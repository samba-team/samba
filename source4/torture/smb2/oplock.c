/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 oplocks

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan Metzmacher 2008

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
#include "libcli/smb_composite/smb_composite.h"
#include "libcli/resolve/resolve.h"
#include "libcli/smb/smbXcli_base.h"

#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"

#include "param/param.h"
#include "system/filesys.h"

#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "torture/smb2/block.h"

#include "lib/util/sys_rw.h"
#include "libcli/security/security.h"

#define CHECK_RANGE(v, min, max) do { \
	if ((v) < (min) || (v) > (max)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): wrong value for %s " \
			       "got %d - should be between %d and %d\n", \
				__location__, #v, (int)v, (int)min, (int)max); \
		ret = false; \
	}} while (0)

#define CHECK_STRMATCH(v, correct) do { \
	if (!v || strstr((v),(correct)) == NULL) { \
		torture_result(tctx, TORTURE_FAIL,  "(%s): wrong value for %s "\
			       "got '%s' - should be '%s'\n", \
				__location__, #v, v?v:"NULL", correct); \
		ret = false; \
	}} while (0)

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): wrong value for %s " \
			       "got 0x%x - should be 0x%x\n", \
				__location__, #v, (int)v, (int)correct); \
		ret = false; \
	}} while (0)

#define BASEDIR "oplock_test"

static struct {
	struct smb2_handle handle;
	uint8_t level;
	struct smb2_break br;
	int count;
	int failures;
	NTSTATUS failure_status;
} break_info;

static void torture_oplock_break_callback(struct smb2_request *req)
{
	NTSTATUS status;
	struct smb2_break br;

	ZERO_STRUCT(br);
	status = smb2_break_recv(req, &break_info.br);
	if (!NT_STATUS_IS_OK(status)) {
		break_info.failures++;
		break_info.failure_status = status;
	}

	return;
}

/* A general oplock break notification handler.  This should be used when a
 * test expects to break from batch or exclusive to a lower level. */
static bool torture_oplock_handler(struct smb2_transport *transport,
				   const struct smb2_handle *handle,
				   uint8_t level,
				   void *private_data)
{
	struct smb2_tree *tree = private_data;
	const char *name;
	struct smb2_request *req;
	ZERO_STRUCT(break_info.br);

	break_info.handle	= *handle;
	break_info.level	= level;
	break_info.count++;

	switch (level) {
	case SMB2_OPLOCK_LEVEL_II:
		name = "level II";
		break;
	case SMB2_OPLOCK_LEVEL_NONE:
		name = "none";
		break;
	default:
		name = "unknown";
		break_info.failures++;
	}
	printf("Acking to %s [0x%02X] in oplock handler\n", name, level);

	break_info.br.in.file.handle	= *handle;
	break_info.br.in.oplock_level	= level;
	break_info.br.in.reserved	= 0;
	break_info.br.in.reserved2	= 0;

	req = smb2_break_send(tree, &break_info.br);
	req->async.fn = torture_oplock_break_callback;
	req->async.private_data = NULL;
	return true;
}

/*
  A handler function for oplock break notifications. Send a break to none
  request.
*/
static bool torture_oplock_handler_ack_to_none(struct smb2_transport *transport,
					       const struct smb2_handle *handle,
					       uint8_t level,
					       void *private_data)
{
	struct smb2_tree *tree = private_data;
	struct smb2_request *req;

	break_info.handle = *handle;
	break_info.level = level;
	break_info.count++;

	printf("Acking to none in oplock handler\n");

	ZERO_STRUCT(break_info.br);
	break_info.br.in.file.handle    = *handle;
	break_info.br.in.oplock_level   = SMB2_OPLOCK_LEVEL_NONE;
	break_info.br.in.reserved       = 0;
	break_info.br.in.reserved2      = 0;

	req = smb2_break_send(tree, &break_info.br);
	req->async.fn = torture_oplock_break_callback;
	req->async.private_data = NULL;

	return true;
}

/*
  A handler function for oplock break notifications. Break from level II to
  none.  SMB2 requires that the client does not send an oplock break request to
  the server in this case.
*/
static bool torture_oplock_handler_level2_to_none(
					       struct smb2_transport *transport,
					       const struct smb2_handle *handle,
					       uint8_t level,
					       void *private_data)
{
	break_info.handle = *handle;
	break_info.level = level;
	break_info.count++;

	printf("Break from level II to none in oplock handler\n");

	return true;
}

/* A handler function for oplock break notifications.  This should be used when
 * test expects two break notifications, first to level II, then to none. */
static bool torture_oplock_handler_two_notifications(
					struct smb2_transport *transport,
					const struct smb2_handle *handle,
					uint8_t level,
					void *private_data)
{
	struct smb2_tree *tree = private_data;
	const char *name;
	struct smb2_request *req;
	ZERO_STRUCT(break_info.br);

	break_info.handle	= *handle;
	break_info.level	= level;
	break_info.count++;

	switch (level) {
	case SMB2_OPLOCK_LEVEL_II:
		name = "level II";
		break;
	case SMB2_OPLOCK_LEVEL_NONE:
		name = "none";
		break;
	default:
		name = "unknown";
		break_info.failures++;
	}
	printf("Breaking to %s [0x%02X] in oplock handler\n", name, level);

	if (level == SMB2_OPLOCK_LEVEL_NONE)
		return true;

	break_info.br.in.file.handle	= *handle;
	break_info.br.in.oplock_level	= level;
	break_info.br.in.reserved	= 0;
	break_info.br.in.reserved2	= 0;

	req = smb2_break_send(tree, &break_info.br);
	req->async.fn = torture_oplock_break_callback;
	req->async.private_data = NULL;
	return true;
}
static void torture_oplock_handler_close_recv(struct smb2_request *req)
{
	if (!smb2_request_receive(req)) {
		printf("close failed in oplock_handler_close\n");
		break_info.failures++;
	}
}

/*
  a handler function for oplock break requests - close the file
*/
static bool torture_oplock_handler_close(struct smb2_transport *transport,
					 const struct smb2_handle *handle,
					 uint8_t level,
					 void *private_data)
{
	struct smb2_close io;
	struct smb2_tree *tree = private_data;
	struct smb2_request *req;

	break_info.handle = *handle;
	break_info.level = level;
	break_info.count++;

	ZERO_STRUCT(io);
	io.in.file.handle       = *handle;
	io.in.flags	     = RAW_CLOSE_SMB2;
	req = smb2_close_send(tree, &io);
	if (req == NULL) {
		printf("failed to send close in oplock_handler_close\n");
		return false;
	}

	req->async.fn = torture_oplock_handler_close_recv;
	req->async.private_data = NULL;

	return true;
}

/*
  a handler function for oplock break requests. Let it timeout
*/
static bool torture_oplock_handler_timeout(struct smb2_transport *transport,
					   const struct smb2_handle *handle,
					   uint8_t level,
					   void *private_data)
{
	break_info.handle = *handle;
	break_info.level = level;
	break_info.count++;

	printf("Let oplock break timeout\n");
	return true;
}

static bool open_smb2_connection_no_level2_oplocks(struct torture_context *tctx,
						   struct smb2_tree **tree)
{
	NTSTATUS status;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct smbcli_options options;

	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	options.use_level2_oplocks = false;

	status = smb2_connect(tctx, host,
			      lpcfg_smb_ports(tctx->lp_ctx), share,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      popt_get_cmdline_credentials(),
			      tree, tctx->ev, &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to connect to SMB2 share "
				"\\\\%s\\%s - %s\n", host, share,
				nt_errstr(status));
		return false;
	}
	return true;
}

static bool test_smb2_oplock_exclusive1(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_exclusive1.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h1;
	struct smb2_handle h;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "EXCLUSIVE1: open a file with an exclusive "
			"oplock (share mode: none)\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_EXCLUSIVE);

	torture_comment(tctx, "a 2nd open should not cause a break\n");
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	torture_comment(tctx, "unlink it - should also be no break\n");
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_exclusive2(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_exclusive2.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "EXCLUSIVE2: open a file with an exclusive "
			"oplock (share mode: all)\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_EXCLUSIVE);

	torture_comment(tctx, "a 2nd open should cause a break to level 2\n");
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h2 = io.smb2.out.file.handle;
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);
	ZERO_STRUCT(break_info);

	/* now we have 2 level II oplocks... */
	torture_comment(tctx, "try to unlink it - should cause a break\n");
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_ok(tctx, status, "Error unlinking the file");
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	torture_comment(tctx, "close both handles\n");
	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_exclusive3(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_exclusive3.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_setfileinfo sfi;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "EXCLUSIVE3: open a file with an exclusive "
			"oplock (share mode: none)\n");

	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_EXCLUSIVE);

	torture_comment(tctx, "setpathinfo EOF should trigger a break to "
			"none\n");
	ZERO_STRUCT(sfi);
	sfi.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sfi.generic.in.file.path = fname;
	sfi.end_of_file_info.in.size = 100;

	status = smb2_composite_setpathinfo(tree2, &sfi);

	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.level, OPLOCK_BREAK_TO_NONE);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_exclusive4(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_exclusive4.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "EXCLUSIVE4: open with exclusive oplock\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_EXCLUSIVE);

	ZERO_STRUCT(break_info);
	torture_comment(tctx, "second open with attributes only shouldn't "
			"cause oplock break\n");

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE |
				SEC_STD_SYNCHRONIZE;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, NO_OPLOCK_RETURN);
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_exclusive5(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_exclusive5.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	tree2->session->transport->oplock.handler = torture_oplock_handler;
	tree2->session->transport->oplock.private_data = tree2;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "EXCLUSIVE5: open with exclusive oplock\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_EXCLUSIVE);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "second open with attributes only and "
			"NTCREATEX_DISP_OVERWRITE_IF dispostion causes "
			"oplock break\n");

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE |
				SEC_STD_SYNCHRONIZE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_II;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_exclusive6(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	const char *fname1 = BASEDIR "\\test_exclusive6_1.dat";
	const char *fname2 = BASEDIR "\\test_exclusive6_2.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_setfileinfo sinfo;
	struct smb2_close closeio;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree2, fname2);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname1;

	torture_comment(tctx, "EXCLUSIVE6: open a file with an exclusive "
			"oplock (share mode: none)\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_EXCLUSIVE);

	torture_comment(tctx, "rename with the parent directory handle open "
			"for DELETE should not generate a break but get "
			"a sharing violation\n");
	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h1;
	sinfo.rename_information.in.overwrite = true;
	sinfo.rename_information.in.new_name = fname2;
	status = smb2_setinfo_file(tree1, &sinfo);

	torture_comment(tctx, "trying rename while parent handle open for delete.\n");
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	/* Close the parent directory handle. */
	ZERO_STRUCT(closeio);
	closeio.in.file.handle = h;
	status = smb2_close(tree1, &closeio);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_OK,
				      "Incorrect status");

	/* Re-open without DELETE access. */
	ZERO_STRUCT(io);
	io.smb2.in.oplock_level = 0;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL & (~SEC_STD_DELETE);
	io.smb2.in.file_attributes   = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.fname = BASEDIR;

	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the base directory");

	torture_comment(tctx, "rename with the parent directory handle open "
			"without DELETE should succeed without a break\n");
	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h1;
	sinfo.rename_information.in.overwrite = true;
	sinfo.rename_information.in.new_name = fname2;
	status = smb2_setinfo_file(tree1, &sinfo);

	torture_comment(tctx, "trying rename while parent handle open without delete\n");
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_OK,
				      "Incorrect status");
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_exclusive9(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_exclusive9.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h1, h2;
	int i;

	struct {
		uint32_t create_disposition;
		uint32_t break_level;
	} levels[] = {
		{ NTCREATEX_DISP_SUPERSEDE, SMB2_OPLOCK_LEVEL_NONE },
		{ NTCREATEX_DISP_OPEN, SMB2_OPLOCK_LEVEL_II },
		{ NTCREATEX_DISP_OVERWRITE_IF, SMB2_OPLOCK_LEVEL_NONE },
		{ NTCREATEX_DISP_OPEN_IF, SMB2_OPLOCK_LEVEL_II },
	};


	status = torture_smb2_testdir(tree1, BASEDIR, &h1);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");
	smb2_util_close(tree1, h1);

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	for (i=0; i<ARRAY_SIZE(levels); i++) {

		io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
		io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

		status = smb2_create(tree1, tctx, &(io.smb2));
		torture_assert_ntstatus_ok(tctx, status,
					   "Error opening the file");
		h1 = io.smb2.out.file.handle;
		CHECK_VAL(io.smb2.out.oplock_level,
			  SMB2_OPLOCK_LEVEL_EXCLUSIVE);

		ZERO_STRUCT(break_info);

		io.smb2.in.create_disposition = levels[i].create_disposition;
		status = smb2_create(tree2, tctx, &(io.smb2));
		torture_assert_ntstatus_ok(tctx, status,
					   "Error opening the file");
		h2 = io.smb2.out.file.handle;
		CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

		CHECK_VAL(break_info.count, 1);
		CHECK_VAL(break_info.level, levels[i].break_level);
		CHECK_VAL(break_info.failures, 0);

		smb2_util_close(tree2, h2);
		smb2_util_close(tree1, h1);
	}

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch1(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch1.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1;
	char c = 0;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/*
	  with a batch oplock we get a break
	*/
	torture_comment(tctx, "BATCH1: open with batch oplock\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "unlink should generate a break\n");
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);

	torture_comment(tctx, "2nd unlink should not generate a break\n");
	ZERO_STRUCT(break_info);
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	torture_comment(tctx, "writing should generate a self break to none\n");
	tree1->session->transport->oplock.handler =
	    torture_oplock_handler_level2_to_none;
	smb2_util_write(tree1, h1, &c, 0, 1);

	torture_wait_for_oplock_break(tctx);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_NONE);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch2(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch2.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	char c = 0;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH2: open with batch oplock\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "unlink should generate a break, which we ack "
			"as break to none\n");
	tree1->session->transport->oplock.handler =
				torture_oplock_handler_ack_to_none;
	tree1->session->transport->oplock.private_data = tree1;
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				     "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);

	torture_comment(tctx, "2nd unlink should not generate a break\n");
	ZERO_STRUCT(break_info);
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	torture_comment(tctx, "writing should not generate a break\n");
	smb2_util_write(tree1, h1, &c, 0, 1);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch3(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch3.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);
	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH3: if we close on break then the unlink "
			"can succeed\n");
	ZERO_STRUCT(break_info);
	tree1->session->transport->oplock.handler =
					torture_oplock_handler_close;
	tree1->session->transport->oplock.private_data = tree1;

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(break_info);
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.level, 1);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch4(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch4.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_read r;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH4: a self read should not cause a break\n");
	ZERO_STRUCT(break_info);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(r);
	r.in.file.handle = h1;
	r.in.offset      = 0;

	status = smb2_read(tree1, tree1, &r);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch5(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch5.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH5: a 2nd open should give a break\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.level, 1);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch6(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch6.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;
	char c = 0;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH6: a 2nd open should give a break to "
			"level II if the first open allowed shared read\n");
	ZERO_STRUCT(break_info);
	tree2->session->transport->oplock.handler = torture_oplock_handler;
	tree2->session->transport->oplock.private_data = tree2;

	io.smb2.in.desired_access = SEC_RIGHTS_FILE_READ |
				SEC_RIGHTS_FILE_WRITE;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(break_info);

	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.level, 1);
	CHECK_VAL(break_info.failures, 0);
	ZERO_STRUCT(break_info);

	torture_comment(tctx, "write should trigger a break to none on both\n");
	tree1->session->transport->oplock.handler =
	    torture_oplock_handler_level2_to_none;
	tree2->session->transport->oplock.handler =
	    torture_oplock_handler_level2_to_none;
	smb2_util_write(tree1, h1, &c, 0, 1);

	/* We expect two breaks */
	torture_wait_for_oplock_break(tctx);
	torture_wait_for_oplock_break(tctx);

	CHECK_VAL(break_info.count, 2);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch7(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch7.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH7: a 2nd open should get an oplock when "
			"we close instead of ack\n");
	ZERO_STRUCT(break_info);
	tree1->session->transport->oplock.handler =
			torture_oplock_handler_close;
	tree1->session->transport->oplock.private_data = tree1;

	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h2.data[0]);
	CHECK_VAL(break_info.level, 1);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree2, h1);
	smb2_util_close(tree2, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch8(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch8.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH8: open with batch oplock\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(break_info);
	torture_comment(tctx, "second open with attributes only shouldn't "
			"cause oplock break\n");

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE |
				SEC_STD_SYNCHRONIZE;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch9(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch9.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;
	char c = 0;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH9: open with attributes only can create "
			"file\n");

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE |
				SEC_STD_SYNCHRONIZE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "Subsequent normal open should break oplock on "
			"attribute only open to level II\n");

	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);
	smb2_util_close(tree2, h2);

	torture_comment(tctx, "third oplocked open should grant level2 without "
			"break\n");
	ZERO_STRUCT(break_info);

	tree2->session->transport->oplock.handler = torture_oplock_handler;
	tree2->session->transport->oplock.private_data = tree2;

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "write should trigger a break to none on both\n");
	tree1->session->transport->oplock.handler =
	    torture_oplock_handler_level2_to_none;
	tree2->session->transport->oplock.handler =
	    torture_oplock_handler_level2_to_none;
	smb2_util_write(tree2, h2, &c, 0, 1);

	/* We expect two breaks */
	torture_wait_for_oplock_break(tctx);
	torture_wait_for_oplock_break(tctx);

	CHECK_VAL(break_info.count, 2);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch9a(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch9a.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2, h3;
	char c = 0;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH9: open with attributes only can create "
			"file\n");

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE |
				SEC_STD_SYNCHRONIZE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error creating the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.create_action, FILE_WAS_CREATED);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "Subsequent attributes open should not break\n");

	ZERO_STRUCT(break_info);

	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h3 = io.smb2.out.file.handle;
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(io.smb2.out.create_action, FILE_WAS_OPENED);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);
	smb2_util_close(tree2, h3);

	torture_comment(tctx, "Subsequent normal open should break oplock on "
			"attribute only open to level II\n");

	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);
	smb2_util_close(tree2, h2);

	torture_comment(tctx, "third oplocked open should grant level2 without "
			"break\n");
	ZERO_STRUCT(break_info);

	tree2->session->transport->oplock.handler = torture_oplock_handler;
	tree2->session->transport->oplock.private_data = tree2;

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "write should trigger a break to none on both\n");
	tree1->session->transport->oplock.handler =
	    torture_oplock_handler_level2_to_none;
	tree2->session->transport->oplock.handler =
	    torture_oplock_handler_level2_to_none;
	smb2_util_write(tree2, h2, &c, 0, 1);

	/* We expect two breaks */
	torture_wait_for_oplock_break(tctx);
	torture_wait_for_oplock_break(tctx);

	CHECK_VAL(break_info.count, 2);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}


static bool test_smb2_oplock_batch10(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch10.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH10: Open with oplock after a non-oplock "
			"open should grant level2\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.smb2.out.oplock_level, 0);

	tree2->session->transport->oplock.handler =
	    torture_oplock_handler_level2_to_none;
	tree2->session->transport->oplock.private_data = tree2;

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	torture_comment(tctx, "write should trigger a break to none\n");
	{
		struct smb2_write wr;
		DATA_BLOB data;
		data = data_blob_talloc_zero(tree1, UINT16_MAX);
		data.data[0] = (const uint8_t)'x';
		ZERO_STRUCT(wr);
		wr.in.file.handle = h1;
		wr.in.offset      = 0;
		wr.in.data        = data;
		status = smb2_write(tree1, &wr);
		torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	}

	torture_wait_for_oplock_break(tctx);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h2.data[0]);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch11(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch11.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_setfileinfo sfi;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler =
	    torture_oplock_handler_two_notifications;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/* Test if a set-eof on pathname breaks an exclusive oplock. */
	torture_comment(tctx, "BATCH11: Test if setpathinfo set EOF breaks "
			"oplocks.\n");

	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
				NTCREATEX_SHARE_ACCESS_WRITE|
				NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h1 = io.smb2.out.file.handle;
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(sfi);
	sfi.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sfi.generic.in.file.path = fname;
	sfi.end_of_file_info.in.size = 100;

	status = smb2_composite_setpathinfo(tree2, &sfi);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");

	/* We expect two breaks */
	torture_wait_for_oplock_break(tctx);
	torture_wait_for_oplock_break(tctx);

	CHECK_VAL(break_info.count, 2);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.level, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch12(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch12.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_setfileinfo sfi;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler =
	    torture_oplock_handler_two_notifications;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/* Test if a set-allocation size on pathname breaks an exclusive
	 * oplock. */
	torture_comment(tctx, "BATCH12: Test if setpathinfo allocation size "
			"breaks oplocks.\n");

	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
				NTCREATEX_SHARE_ACCESS_WRITE|
				NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h1 = io.smb2.out.file.handle;
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(sfi);
	sfi.generic.level = RAW_SFILEINFO_ALLOCATION_INFORMATION;
	sfi.generic.in.file.path = fname;
	sfi.allocation_info.in.alloc_size = 65536 * 8;

	status = smb2_composite_setpathinfo(tree2, &sfi);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");

	/* We expect two breaks */
	torture_wait_for_oplock_break(tctx);
	torture_wait_for_oplock_break(tctx);

	CHECK_VAL(break_info.count, 2);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.level, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch13(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch13.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	tree2->session->transport->oplock.handler = torture_oplock_handler;
	tree2->session->transport->oplock.private_data = tree2;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH13: open with batch oplock\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "second open with attributes only and "
			"NTCREATEX_DISP_OVERWRITE dispostion causes "
			"oplock break\n");

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE |
				SEC_STD_SYNCHRONIZE;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
				NTCREATEX_SHARE_ACCESS_WRITE|
				NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);

	return ret;
}

static bool test_smb2_oplock_batch14(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch14.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH14: open with batch oplock\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "second open with attributes only and "
			"NTCREATEX_DISP_SUPERSEDE dispostion causes "
			"oplock break\n");

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE |
				SEC_STD_SYNCHRONIZE;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
				NTCREATEX_SHARE_ACCESS_WRITE|
				NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch15(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch15.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_fileinfo qfi;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/* Test if a qpathinfo all info on pathname breaks a batch oplock. */
	torture_comment(tctx, "BATCH15: Test if qpathinfo all info breaks "
			"a batch oplock (should not).\n");

	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
				NTCREATEX_SHARE_ACCESS_WRITE|
				NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(qfi);
	qfi.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	qfi.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree2, tctx, &qfi);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch16(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch16.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	tree2->session->transport->oplock.handler = torture_oplock_handler;
	tree2->session->transport->oplock.private_data = tree2;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH16: open with batch oplock\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "second open with attributes only and "
			"NTCREATEX_DISP_OVERWRITE_IF dispostion causes "
			"oplock break\n");

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE |
				SEC_STD_SYNCHRONIZE;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
				NTCREATEX_SHARE_ACCESS_WRITE|
				NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

/* This function is a placeholder for the SMB1 RAW-OPLOCK-BATCH17 test.  Since
 * SMB2 doesn't have a RENAME command this test isn't applicable.  However,
 * it's much less confusing, when comparing test, to keep the SMB1 and SMB2
 * test numbers in sync. */
#if 0
static bool test_raw_oplock_batch17(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	return true;
}
#endif

/* This function is a placeholder for the SMB1 RAW-OPLOCK-BATCH18 test.  Since
 * SMB2 doesn't have an NTRENAME command this test isn't applicable.  However,
 * it's much less confusing, when comparing tests, to keep the SMB1 and SMB2
 * test numbers in sync. */
#if 0
static bool test_raw_oplock_batch18(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	return true;
}
#endif

static bool test_smb2_oplock_batch19(struct torture_context *tctx,
				     struct smb2_tree *tree1)
{
	const char *fname1 = BASEDIR "\\test_batch19_1.dat";
	const char *fname2 = BASEDIR "\\test_batch19_2.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_fileinfo qfi;
	union smb_setfileinfo sfi;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname1;

	torture_comment(tctx, "BATCH19: open a file with an batch oplock "
			"(share mode: none)\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "setfileinfo rename info should not trigger "
			"a break but should cause a sharing violation\n");
	ZERO_STRUCT(sfi);
	sfi.generic.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sfi.generic.in.file.path = fname1;
	sfi.rename_information.in.file.handle   = h1;
	sfi.rename_information.in.overwrite     = 0;
	sfi.rename_information.in.root_fid      = 0;
	sfi.rename_information.in.new_name      = fname2;

	status = smb2_setinfo_file(tree1, &sfi);

	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	ZERO_STRUCT(qfi);
	qfi.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	qfi.generic.in.file.handle = h1;

	status = smb2_getinfo_file(tree1, tctx, &qfi);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	CHECK_STRMATCH(qfi.all_info2.out.fname.s, fname1);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, fname1);
	smb2_deltree(tree1, fname2);
	return ret;
}

static bool test_smb2_oplock_batch20(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname1 = BASEDIR "\\test_batch20_1.dat";
	const char *fname2 = BASEDIR "\\test_batch20_2.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_fileinfo qfi;
	union smb_setfileinfo sfi;
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname1;

	torture_comment(tctx, "BATCH20: open a file with an batch oplock "
			"(share mode: all)\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
				NTCREATEX_SHARE_ACCESS_WRITE|
				NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "setfileinfo rename info should not trigger "
			"a break but should cause a sharing violation\n");
	ZERO_STRUCT(sfi);
	sfi.generic.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sfi.rename_information.in.file.handle	= h1;
	sfi.rename_information.in.overwrite     = 0;
	sfi.rename_information.in.new_name      = fname2;

	status = smb2_setinfo_file(tree1, &sfi);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	ZERO_STRUCT(qfi);
	qfi.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	qfi.generic.in.file.handle = h1;

	status = smb2_getinfo_file(tree1, tctx, &qfi);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	CHECK_STRMATCH(qfi.all_info2.out.fname.s, fname1);

	torture_comment(tctx, "open the file a second time requesting batch "
			"(share mode: all)\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
				NTCREATEX_SHARE_ACCESS_WRITE|
				NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.fname = fname1;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);

	torture_comment(tctx, "setfileinfo rename info should not trigger "
			"a break but should cause a sharing violation\n");
	ZERO_STRUCT(break_info);
	ZERO_STRUCT(sfi);
	sfi.generic.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sfi.rename_information.in.file.handle	= h2;
	sfi.rename_information.in.overwrite     = 0;
	sfi.rename_information.in.new_name      = fname2;

	status = smb2_setinfo_file(tree2, &sfi);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	ZERO_STRUCT(qfi);
	qfi.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	qfi.generic.in.file.handle = h1;

	status = smb2_getinfo_file(tree1, tctx, &qfi);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	CHECK_STRMATCH(qfi.all_info2.out.fname.s, fname1);

	ZERO_STRUCT(qfi);
	qfi.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	qfi.generic.in.file.handle = h2;

	status = smb2_getinfo_file(tree2, tctx, &qfi);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	CHECK_STRMATCH(qfi.all_info2.out.fname.s, fname1);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, fname1);
	return ret;
}

static bool test_smb2_oplock_batch21(struct torture_context *tctx,
				     struct smb2_tree *tree1)
{
	const char *fname = BASEDIR "\\test_batch21.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1;
	char c = 0;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/*
	  with a batch oplock we get a break
	*/
	torture_comment(tctx, "BATCH21: open with batch oplock\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "writing should not generate a break\n");
	status = smb2_util_write(tree1, h1, &c, 0, 1);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch22a(struct torture_context *tctx,
				      struct smb2_tree *tree1)
{
	const char *fname = BASEDIR "\\test_batch22a.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;
	struct timeval tv;
	int timeout = torture_setting_int(tctx, "oplocktimeout", 35);
	int te;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;
	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/*
	  with a batch oplock we get a break
	*/
	torture_comment(tctx, "BATCH22: open with batch oplock\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "a 2nd open should succeed after the oplock "
			"break timeout\n");
	tv = timeval_current();
	tree1->session->transport->oplock.handler =
				torture_oplock_handler_timeout;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	torture_wait_for_oplock_break(tctx);
	te = (int)timeval_elapsed(&tv);
	CHECK_RANGE(te, timeout - 1, timeout + 15);
	torture_comment(tctx, "waited %d seconds for oplock timeout\n", te);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch22b(struct torture_context *tctx,
				      struct smb2_tree *tree1,
				      struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch22b.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;
	struct timeval tv;
	int timeout = torture_setting_int(tctx, "oplocktimeout", 35);
	struct smb2_transport *transport1 = tree1->session->transport;
	bool block_setup = false;
	bool block_ok = false;
	int te;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;
	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/*
	  with a batch oplock we get a break
	*/
	torture_comment(tctx, "BATCH22: open with batch oplock\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "a 2nd open should succeed after the oplock "
			"break timeout\n");
	tv = timeval_current();
	tree1->session->transport->oplock.handler =
				torture_oplock_handler_timeout;
	block_setup = test_setup_blocked_transports(tctx);
	torture_assert(tctx, block_setup, "test_setup_blocked_transports");
	block_ok = test_block_smb2_transport(tctx, transport1);
	torture_assert(tctx, block_ok, "test_block_smb2_transport");

	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_wait_for_oplock_break(tctx);
	te = (int)timeval_elapsed(&tv);
	CHECK_RANGE(te, 0, timeout);
	torture_comment(tctx, "waited %d seconds for oplock timeout\n", te);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);

done:
	if (block_ok) {
		test_unblock_smb2_transport(tctx, transport1);
	}
	test_cleanup_blocked_transports(tctx);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h2);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch23(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch23.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2, h3;
	struct smb2_tree *tree3 = NULL;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	ret = open_smb2_connection_no_level2_oplocks(tctx, &tree3);
	CHECK_VAL(ret, true);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	tree2->session->transport->oplock.handler = torture_oplock_handler;
	tree2->session->transport->oplock.private_data = tree2;

	tree3->session->transport->oplock.handler = torture_oplock_handler;
	tree3->session->transport->oplock.private_data = tree3;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH23: an open and ask for a batch oplock\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.desired_access = SEC_RIGHTS_FILE_READ |
				SEC_RIGHTS_FILE_WRITE;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "a 2nd open without level2 oplock support "
			"should generate a break to level2\n");
	status = smb2_create(tree3, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h3 = io.smb2.out.file.handle;

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "a 3rd open with level2 oplock support should "
			"not generate a break\n");
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree3, h3);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch24(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch24.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1, h2;
	struct smb2_tree *tree3 = NULL;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	ret = open_smb2_connection_no_level2_oplocks(tctx, &tree3);
	CHECK_VAL(ret, true);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	tree2->session->transport->oplock.handler = torture_oplock_handler;
	tree2->session->transport->oplock.private_data = tree2;

	tree3->session->transport->oplock.handler = torture_oplock_handler;
	tree3->session->transport->oplock.private_data = tree3;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH24: a open without level support and "
			"ask for a batch oplock\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.desired_access = SEC_RIGHTS_FILE_READ |
				SEC_RIGHTS_FILE_WRITE;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	status = smb2_create(tree3, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h2 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "a 2nd open with level2 oplock support should "
			"generate a break\n");
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.handle.data[0], h2.data[0]);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree3, h2);
	smb2_util_close(tree2, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_batch25(struct torture_context *tctx,
			             struct smb2_tree *tree1)
{
	const char *fname = BASEDIR "\\test_batch25.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "BATCH25: open a file with an batch oplock "
			"(share mode: none)\n");

	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "changing the file attribute info should trigger "
			"a break and a violation\n");

	status = smb2_util_setatr(tree1, fname, FILE_ATTRIBUTE_HIDDEN);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_SHARING_VIOLATION,
				      "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, fname);
	return ret;
}

static bool test_smb2_oplock_batch26(struct torture_context *tctx,
                                        struct smb2_tree *tree1)
{

        NTSTATUS status;
        bool ret = true;
        union smb_open io;
        struct smb2_handle h, h1, h2, h3;
        const char *fname_base = BASEDIR "\\test_oplock.txt";
        const char *stream = "Stream One:$DATA";
        const char *fname_stream;

        status = torture_smb2_testdir(tree1, BASEDIR, &h);
        torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

        tree1->session->transport->oplock.handler = torture_oplock_handler;
        tree1->session->transport->oplock.private_data = tree1;

        fname_stream = talloc_asprintf(tctx, "%s:%s", fname_base, stream);

        /*
          base ntcreatex parms
        */
        ZERO_STRUCT(io.smb2);
        io.generic.level = RAW_OPEN_SMB2;
        io.smb2.in.desired_access = 0x120089;
        io.smb2.in.alloc_size = 0;
        io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
        io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_DELETE |
                                  NTCREATEX_SHARE_ACCESS_WRITE;
        io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
        io.smb2.in.create_options = 0;
        io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
        io.smb2.in.security_flags = 0;
        io.smb2.in.fname = fname_base;

        /*
          Open base file with a batch oplock.
        */
        torture_comment(tctx, "Open the base file with batch oplock\n");
        io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
        io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

        status = smb2_create(tree1, tctx, &(io.smb2));
        torture_assert_ntstatus_ok(tctx, status, "Error opening base file");
        h1 = io.smb2.out.file.handle;
        CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

        torture_comment(tctx, "Got batch oplock on base file\n");

        torture_comment(tctx, "Opening stream file with batch oplock..\n");

        io.smb2.in.fname = fname_stream;

        status = smb2_create(tree1, tctx, &(io.smb2));
        torture_assert_ntstatus_ok(tctx, status, "Error opening stream file");
        h2 = io.smb2.out.file.handle;
        CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

        torture_comment(tctx, "Got batch oplock on stream file\n");

        torture_comment(tctx, "Open base file again with batch oplock\n");

        io.smb2.in.fname = fname_base;

        status = smb2_create(tree1, tctx, &(io.smb2));
        torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
        h3 = io.smb2.out.file.handle;
        CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

        smb2_util_close(tree1, h1);
        smb2_util_close(tree1, h2);
        smb2_util_close(tree1, h3);
        smb2_util_close(tree1, h);
        smb2_deltree(tree1, BASEDIR);
        return ret;

}

/* Test how oplocks work on streams. */
static bool test_raw_oplock_stream1(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname_base = BASEDIR "\\test_stream1.txt";
	const char *fname_stream, *fname_default_stream;
	const char *default_stream = "::$DATA";
	const char *stream = "Stream One:$DATA";
	bool ret = true;
	struct smb2_handle h, h_base, h_stream;
	int i;

#define NSTREAM_OPLOCK_RESULTS 8
	struct {
		const char **fname;
		bool open_base_file;
		uint32_t oplock_req;
		uint32_t oplock_granted;
	} stream_oplock_results[NSTREAM_OPLOCK_RESULTS] = {
		/* Request oplock on stream without the base file open. */
		{&fname_stream, false, SMB2_OPLOCK_LEVEL_BATCH, SMB2_OPLOCK_LEVEL_BATCH},
		{&fname_default_stream, false, SMB2_OPLOCK_LEVEL_BATCH, SMB2_OPLOCK_LEVEL_BATCH},
		{&fname_stream, false, SMB2_OPLOCK_LEVEL_EXCLUSIVE, SMB2_OPLOCK_LEVEL_EXCLUSIVE},
		{&fname_default_stream, false,  SMB2_OPLOCK_LEVEL_EXCLUSIVE, SMB2_OPLOCK_LEVEL_EXCLUSIVE},

		/* Request oplock on stream with the base file open. */
		{&fname_stream, true, SMB2_OPLOCK_LEVEL_BATCH, SMB2_OPLOCK_LEVEL_BATCH},
		{&fname_default_stream, true, SMB2_OPLOCK_LEVEL_BATCH, SMB2_OPLOCK_LEVEL_II},
		{&fname_stream, true, SMB2_OPLOCK_LEVEL_EXCLUSIVE, SMB2_OPLOCK_LEVEL_EXCLUSIVE},
		{&fname_default_stream, true,  SMB2_OPLOCK_LEVEL_EXCLUSIVE, SMB2_OPLOCK_LEVEL_II},
	};

	fname_stream = talloc_asprintf(tctx, "%s:%s", fname_base, stream);
	fname_default_stream = talloc_asprintf(tctx, "%s%s", fname_base,
					       default_stream);

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* Initialize handles to "closed".  Using -1 in the first 64-bytes
	 * as the sentry for this */
	h_stream.data[0] = -1;

	/* cleanup */
	smb2_util_unlink(tree1, fname_base);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	tree2->session->transport->oplock.handler = torture_oplock_handler;
	tree2->session->transport->oplock.private_data = tree2;

	/* Setup generic open parameters. */
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = (SEC_FILE_READ_DATA |
				     SEC_FILE_WRITE_DATA |
				     SEC_FILE_APPEND_DATA |
				     SEC_STD_READ_CONTROL);
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				  NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;

	/* Create the file with a stream */
	io.smb2.in.fname = fname_stream;
	io.smb2.in.create_flags = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error creating file");
	smb2_util_close(tree1, io.smb2.out.file.handle);

	/* Change the disposition to open now that the file has been created. */
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;

	/* Try some permutations of taking oplocks on streams. */
	for (i = 0; i < NSTREAM_OPLOCK_RESULTS; i++) {
		const char *fname = *stream_oplock_results[i].fname;
		bool open_base_file = stream_oplock_results[i].open_base_file;
		uint32_t oplock_req = stream_oplock_results[i].oplock_req;
		uint32_t oplock_granted =
		    stream_oplock_results[i].oplock_granted;

		if (open_base_file) {
			torture_comment(tctx, "Opening base file: %s with "
			    "%d\n", fname_base, SMB2_OPLOCK_LEVEL_BATCH);
			io.smb2.in.fname = fname_base;
			io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
			io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
			status = smb2_create(tree2, tctx, &(io.smb2));
			torture_assert_ntstatus_ok(tctx, status,
			    "Error opening file");
			CHECK_VAL(io.smb2.out.oplock_level,
			    SMB2_OPLOCK_LEVEL_BATCH);
			h_base = io.smb2.out.file.handle;
		}

		torture_comment(tctx, "%d: Opening stream: %s with %d\n", i,
		    fname, oplock_req);
		io.smb2.in.fname = fname;
		io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
		io.smb2.in.oplock_level = oplock_req;

		/* Do the open with the desired oplock on the stream. */
		status = smb2_create(tree1, tctx, &(io.smb2));
		torture_assert_ntstatus_ok(tctx, status, "Error opening file");
		CHECK_VAL(io.smb2.out.oplock_level, oplock_granted);
		smb2_util_close(tree1, io.smb2.out.file.handle);

		/* Cleanup the base file if it was opened. */
		if (open_base_file)
			smb2_util_close(tree2, h_base);
	}

	/* Open the stream with an exclusive oplock. */
	torture_comment(tctx, "Opening stream: %s with %d\n",
	    fname_stream, SMB2_OPLOCK_LEVEL_EXCLUSIVE);
	io.smb2.in.fname = fname_stream;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening file");
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_EXCLUSIVE);
	h_stream = io.smb2.out.file.handle;

	/* Open the base file and see if it contends. */
	ZERO_STRUCT(break_info);
	torture_comment(tctx, "Opening base file: %s with %d\n",
	    fname_base, SMB2_OPLOCK_LEVEL_BATCH);
	io.smb2.in.fname = fname_base;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening file");
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);
	smb2_util_close(tree2, io.smb2.out.file.handle);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	/* Open the stream again to see if it contends. */
	ZERO_STRUCT(break_info);
	torture_comment(tctx, "Opening stream again: %s with "
	    "%d\n", fname_base, SMB2_OPLOCK_LEVEL_BATCH);
	io.smb2.in.fname = fname_stream;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening file");
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);
	smb2_util_close(tree2, io.smb2.out.file.handle);

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.level, OPLOCK_BREAK_TO_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);

	/* Close the stream. */
	if (h_stream.data[0] != -1) {
		smb2_util_close(tree1, h_stream);
	}

	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool test_smb2_oplock_doc(struct torture_context *tctx, struct smb2_tree *tree,
				 struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_oplock_doc.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1;
	union smb_setfileinfo sfinfo;

	status = torture_smb2_testdir(tree, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");
	smb2_util_close(tree, h);

	/* cleanup */
	smb2_util_unlink(tree, fname);
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "open a file with a batch oplock\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	status = smb2_create(tree, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	torture_comment(tctx, "Set delete on close\n");
	ZERO_STRUCT(sfinfo);
	sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	sfinfo.disposition_info.in.delete_on_close = 1;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");

	torture_comment(tctx, "2nd open should not break and get "
			"DELETE_PENDING\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.create_options = 0;
	io.smb2.in.desired_access = SEC_FILE_READ_DATA;
	status = smb2_create(tree2, tctx, &io.smb2);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_DELETE_PENDING,
				      "Incorrect status");
	CHECK_VAL(break_info.count, 0);

	smb2_util_close(tree, h1);

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);
	return ret;
}

/* Open a file with a batch oplock, then open it again from a second client
 * requesting no oplock. Having two open file handles should break our own
 * oplock during BRL acquisition.
 */
static bool test_smb2_oplock_brl1(struct torture_context *tctx,
				struct smb2_tree *tree1,
				struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_batch_brl.dat";
	/*int fname, f;*/
	bool ret = true;
	uint8_t buf[1000];
	union smb_open io;
	NTSTATUS status;
	struct smb2_lock lck;
	struct smb2_lock_element lock[1];
	struct smb2_handle h, h1, h2;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler =
	    torture_oplock_handler_two_notifications;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_READ |
				    SEC_RIGHTS_FILE_WRITE;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				  NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/*
	  with a batch oplock we get a break
	*/
	torture_comment(tctx, "open with batch oplock\n");
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* create a file with bogus data */
	memset(buf, 0, sizeof(buf));

	status = smb2_util_write(tree1, h1,buf, 0, sizeof(buf));
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		torture_comment(tctx, "Failed to create file\n");
		ret = false;
		goto done;
	}

	torture_comment(tctx, "a 2nd open should give a break\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = 0;
	status = smb2_create(tree2, tctx, &(io.smb2));
	h2 = io.smb2.out.file.handle;
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "a self BRL acquisition should break to none\n");

	ZERO_STRUCT(lock);

	lock[0].offset = 0;
	lock[0].length = 4;
	lock[0].flags = SMB2_LOCK_FLAG_EXCLUSIVE |
			SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;

	ZERO_STRUCT(lck);
	lck.in.file.handle = h1;
	lck.in.locks = &lock[0];
	lck.in.lock_count = 1;
	status = smb2_lock(tree1, &lck);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_NONE);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.failures, 0);

	/* expect no oplock break */
	ZERO_STRUCT(break_info);
	lock[0].offset = 2;
	status = smb2_lock(tree1, &lck);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_LOCK_NOT_GRANTED,
				      "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_close(tree1, h);

done:
	smb2_deltree(tree1, BASEDIR);
	return ret;

}

/* Open a file with a batch oplock on one tree and then acquire a brl.
 * We should not contend our own oplock.
 */
static bool test_smb2_oplock_brl2(struct torture_context *tctx, struct smb2_tree *tree1)
{
	const char *fname = BASEDIR "\\test_batch_brl.dat";
	/*int fname, f;*/
	bool ret = true;
	uint8_t buf[1000];
	union smb_open io;
	NTSTATUS status;
	struct smb2_handle h, h1;
	struct smb2_lock lck;
	struct smb2_lock_element lock[1];

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_READ |
				    SEC_RIGHTS_FILE_WRITE;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				  NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/*
	  with a batch oplock we get a break
	*/
	torture_comment(tctx, "open with batch oplock\n");
	ZERO_STRUCT(break_info);
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* create a file with bogus data */
	memset(buf, 0, sizeof(buf));

	status = smb2_util_write(tree1, h1, buf, 0, sizeof(buf));
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		torture_comment(tctx, "Failed to create file\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "a self BRL acquisition should not break to "
			"none\n");

	ZERO_STRUCT(lock);

	lock[0].offset = 0;
	lock[0].length = 4;
	lock[0].flags = SMB2_LOCK_FLAG_EXCLUSIVE |
			SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;

	ZERO_STRUCT(lck);
	lck.in.file.handle = h1;
	lck.in.locks = &lock[0];
	lck.in.lock_count = 1;
	status = smb2_lock(tree1, &lck);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");

	lock[0].offset = 2;
	status = smb2_lock(tree1, &lck);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_LOCK_NOT_GRANTED,
				      "Incorrect status");

	/* With one file handle open a BRL should not contend our oplock.
	 * Thus, no oplock break will be received and the entire break_info
	 * struct will be 0 */
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

done:
	smb2_deltree(tree1, BASEDIR);
	return ret;
}

/* Open a file with a batch oplock twice from one tree and then acquire a
 * brl. BRL acquisition should break our own oplock.
 */
static bool test_smb2_oplock_brl3(struct torture_context *tctx, struct smb2_tree *tree1)
{
	const char *fname = BASEDIR "\\test_batch_brl.dat";
	bool ret = true;
	uint8_t buf[1000];
	union smb_open io;
	NTSTATUS status;
	struct smb2_handle h, h1, h2;
	struct smb2_lock lck;
	struct smb2_lock_element lock[1];

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);
	tree1->session->transport->oplock.handler =
	    torture_oplock_handler_two_notifications;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_READ |
				    SEC_RIGHTS_FILE_WRITE;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				  NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/*
	  with a batch oplock we get a break
	*/
	torture_comment(tctx, "open with batch oplock\n");
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* create a file with bogus data */
	memset(buf, 0, sizeof(buf));
	status = smb2_util_write(tree1, h1, buf, 0, sizeof(buf));

	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		torture_comment(tctx, "Failed to create file\n");
		ret = false;
		goto done;
	}

	torture_comment(tctx, "a 2nd open should give a break\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = 0;
	status = smb2_create(tree1, tctx, &(io.smb2));
	h2 = io.smb2.out.file.handle;
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "a self BRL acquisition should break to none\n");

	ZERO_STRUCT(lock);

	lock[0].offset = 0;
	lock[0].length = 4;
	lock[0].flags = SMB2_LOCK_FLAG_EXCLUSIVE |
			SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;

	ZERO_STRUCT(lck);
	lck.in.file.handle = h1;
	lck.in.locks = &lock[0];
	lck.in.lock_count = 1;
	status = smb2_lock(tree1, &lck);
	torture_assert_ntstatus_ok(tctx, status, "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.level, SMB2_OPLOCK_LEVEL_NONE);
	CHECK_VAL(break_info.handle.data[0], h1.data[0]);
	CHECK_VAL(break_info.failures, 0);

	/* expect no oplock break */
	ZERO_STRUCT(break_info);
	lock[0].offset = 2;
	status = smb2_lock(tree1, &lck);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_LOCK_NOT_GRANTED,
				      "Incorrect status");

	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 0);

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h2);
	smb2_util_close(tree1, h);

done:
	smb2_deltree(tree1, BASEDIR);
	return ret;

}

/* Starting the SMB2 specific oplock tests at 500 so we can keep the SMB1
 * tests in sync with an identically numbered SMB2 test */

/* Test whether the server correctly returns an error when we send
 * a response to a levelII to none oplock notification. */
static bool test_smb2_oplock_levelII500(struct torture_context *tctx,
				      struct smb2_tree *tree1)
{
	const char *fname = BASEDIR "\\test_levelII500.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_handle h, h1;
	char c = 0;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(tctx, "LEVELII500: acknowledging a break from II to "
			"none should return an error\n");
	ZERO_STRUCT(break_info);

	io.smb2.in.desired_access = SEC_RIGHTS_FILE_READ |
				SEC_RIGHTS_FILE_WRITE;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_II;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	h1 = io.smb2.out.file.handle;
	CHECK_VAL(io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_II);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "write should trigger a break to none and when "
			"we reply, an oplock break failure\n");
	smb2_util_write(tree1, h1, &c, 0, 1);

	/* Wait several times to receive both the break notification, and the
	 * NT_STATUS_INVALID_OPLOCK_PROTOCOL error in the break response */
	torture_wait_for_oplock_break(tctx);
	torture_wait_for_oplock_break(tctx);
	torture_wait_for_oplock_break(tctx);
	torture_wait_for_oplock_break(tctx);

	/* There appears to be a race condition in W2K8 and W2K8R2 where
	 * sometimes the server will happily reply to our break response with
	 * NT_STATUS_OK, and sometimes it will return the OPLOCK_PROTOCOL
	 * error.  As the MS-SMB2 doc states that a client should not reply to
	 * a level2 to none break notification, I'm leaving the protocol error
	 * as the expected behavior. */
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 1);
	torture_assert_ntstatus_equal(tctx, break_info.failure_status,
				      NT_STATUS_INVALID_OPLOCK_PROTOCOL,
				      "Incorrect status");

	smb2_util_close(tree1, h1);
	smb2_util_close(tree1, h);

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

/*
 * Test a double-break. Open a file with exclusive. Send off a second open
 * request with OPEN_IF, triggering a break to level2. This should respond
 * with level2. Before replying to the break to level2, fire off a third open
 * with OVERWRITE_IF. The expected sequence would be that the 3rd opener gets
 * a level2 immediately triggered by a break to none, but that seems not the
 * case. Still investigating what the right behaviour should be.
 */

struct levelII501_state {
	struct torture_context *tctx;
	struct smb2_tree *tree1;
	struct smb2_tree *tree2;
	struct smb2_tree *tree3;
	struct smb2_handle h;
	struct smb2_handle h1;
	union smb_open io;

	struct smb2_handle break_handle;
	uint8_t break_to;
	struct smb2_break br;

	bool done;
};

static bool torture_oplock_break_delay(struct smb2_transport *transport,
				       const struct smb2_handle *handle,
				       uint8_t level, void *private_data);
static void levelII501_break_done(struct smb2_request *req);
static void levelII501_open1_done(struct smb2_request *req);
static void levelII501_open2_done(struct smb2_request *req);
static void levelII501_2ndopen_cb(struct tevent_context *ev,
				  struct tevent_timer *te,
				  struct timeval current_time,
				  void *private_data);
static void levelII501_break_timeout_cb(struct tevent_context *ev,
					struct tevent_timer *te,
					struct timeval current_time,
					void *private_data);
static void levelII501_timeout_cb(struct tevent_context *ev,
				  struct tevent_timer *te,
				  struct timeval current_time,
				  void *private_data);

static bool test_smb2_oplock_levelII501(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_levelII501.dat";
	NTSTATUS status;
	bool ret = true;
	struct levelII501_state *state;
	struct smb2_request *req;
	struct tevent_timer *te;

	state = talloc(tctx, struct levelII501_state);
	state->tctx = tctx;
	state->done = false;
	state->tree1 = tree1;
	state->tree2 = tree2;

	if (!torture_smb2_connection(tctx, &state->tree3)) {
		torture_fail(tctx, "Establishing SMB2 connection failed\n");
		return false;
	}

	status = torture_smb2_testdir(tree1, BASEDIR, &state->h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(state->io.smb2);
	state->io.generic.level = RAW_OPEN_SMB2;
	state->io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	state->io.smb2.in.alloc_size = 0;
	state->io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	state->io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	state->io.smb2.in.create_options = 0;
	state->io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	state->io.smb2.in.security_flags = 0;
	state->io.smb2.in.fname = fname;

	torture_comment(tctx, "LEVELII501: Test double break sequence\n");
	ZERO_STRUCT(break_info);

	state->io.smb2.in.desired_access = SEC_RIGHTS_FILE_READ |
				SEC_RIGHTS_FILE_WRITE;
	state->io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	state->io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	state->io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	tree1->session->transport->oplock.handler = torture_oplock_break_delay;
	tree1->session->transport->oplock.private_data = state;

	status = smb2_create(tree1, tctx, &(state->io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	state->h1 = state->io.smb2.out.file.handle;
	CHECK_VAL(state->io.smb2.out.oplock_level, SMB2_OPLOCK_LEVEL_EXCLUSIVE);

	/*
	 * Trigger a break to level2
	 */

	req = smb2_create_send(tree2, &state->io.smb2);
	req->async.fn = levelII501_open1_done;
	req->async.private_data = state;

	te = tevent_add_timer(
		tctx->ev, tctx, tevent_timeval_current_ofs(0, 200000),
		levelII501_2ndopen_cb, state);
	torture_assert(tctx, te != NULL, "tevent_add_timer failed\n");

	te = tevent_add_timer(
		tctx->ev, tctx, tevent_timeval_current_ofs(2, 0),
		levelII501_timeout_cb, state);
	torture_assert(tctx, te != NULL, "tevent_add_timer failed\n");

	while (!state->done) {
		if (tevent_loop_once(tctx->ev) != 0) {
			torture_comment(tctx, "tevent_loop_once failed\n");
		}
	}

	return ret;
}

/*
 * Fire off a second open after a little timeout
 */

static void levelII501_2ndopen_cb(struct tevent_context *ev,
				  struct tevent_timer *te,
				  struct timeval current_time,
				  void *private_data)
{
	struct levelII501_state *state = talloc_get_type_abort(
		private_data, struct levelII501_state);
	struct smb2_request *req;

	state->io.smb2.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	req = smb2_create_send(state->tree3, &state->io.smb2);
	req->async.fn = levelII501_open2_done;
	req->async.private_data = state;
}

/*
 * Postpone the break response by 500 msec
 */
static bool torture_oplock_break_delay(struct smb2_transport *transport,
				       const struct smb2_handle *handle,
				       uint8_t level, void *private_data)
{
	struct levelII501_state *state = talloc_get_type_abort(
		private_data, struct levelII501_state);
	const char *name;
	struct tevent_timer *te;

	break_info.handle	= *handle;
	break_info.level	= level;
	break_info.count++;

	state->break_handle = *handle;
	state->break_to = level;

	switch(level) {
	case SMB2_OPLOCK_LEVEL_II:
		name = "level II";
		break;
	case SMB2_OPLOCK_LEVEL_NONE:
		name = "none";
		break;
	default:
		name = "unknown";
		break;
	}
	printf("Got break to %s [0x%02X] in oplock handler, postponing "
	       "break response for 500msec\n", name, level);

	te = tevent_add_timer(
		state->tctx->ev, state->tctx,
		tevent_timeval_current_ofs(0, 500000),
		levelII501_break_timeout_cb, state);
	torture_assert(state->tctx, te != NULL, "tevent_add_timer failed\n");

	return true;
}

static void levelII501_break_timeout_cb(struct tevent_context *ev,
					struct tevent_timer *te,
					struct timeval current_time,
					void *private_data)
{
	struct levelII501_state *state = talloc_get_type_abort(
		private_data, struct levelII501_state);
	struct smb2_request *req;

	talloc_free(te);

	ZERO_STRUCT(state->br);
	state->br.in.file.handle = state->break_handle;
	state->br.in.oplock_level = state->break_to;

	req = smb2_break_send(state->tree1, &state->br);
	req->async.fn = levelII501_break_done;
	req->async.private_data = state;
}

static void levelII501_break_done(struct smb2_request *req)
{
	struct smb2_break io;
	NTSTATUS status;

	status = smb2_break_recv(req, &io);
	printf("break done: %s\n", nt_errstr(status));
}

static void levelII501_open1_done(struct smb2_request *req)
{
	struct levelII501_state *state = talloc_get_type_abort(
		req->async.private_data, struct levelII501_state);
	struct smb2_create io;
	NTSTATUS status;

	status = smb2_create_recv(req, state, &io);
	printf("open1 done: %s\n", nt_errstr(status));
}

static void levelII501_open2_done(struct smb2_request *req)
{
	struct levelII501_state *state = talloc_get_type_abort(
		req->async.private_data, struct levelII501_state);
	struct smb2_create io;
	NTSTATUS status;

	status = smb2_create_recv(req, state, &io);
	printf("open2 done: %s\n", nt_errstr(status));
}

static void levelII501_timeout_cb(struct tevent_context *ev,
				  struct tevent_timer *te,
				  struct timeval current_time,
				  void *private_data)
{
	struct levelII501_state *state = talloc_get_type_abort(
		private_data, struct levelII501_state);
	talloc_free(te);
	state->done = true;
}

static bool test_smb2_oplock_levelII502(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)

{
	const char *fname = BASEDIR "\\test_levelII502.dat";
	NTSTATUS status;
	union smb_open io;
	struct smb2_close closeio;
	struct smb2_handle h;

	status = torture_smb2_testdir(tree1, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	/* cleanup */
	smb2_util_unlink(tree1, fname);

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	torture_comment(
		tctx,
		"LEVELII502: Open a stale LEVEL2 oplock with OVERWRITE");

	io.smb2.in.desired_access = SEC_RIGHTS_FILE_READ |
				SEC_RIGHTS_FILE_WRITE;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_II;
	status = smb2_create(tree1, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	torture_assert(tctx,
		       io.smb2.out.oplock_level==SMB2_OPLOCK_LEVEL_II,
		       "Did not get LEVEL_II oplock\n");

	status = smbXcli_conn_samba_suicide(
		tree1->session->transport->conn, 93);
	torture_assert_ntstatus_ok(tctx, status, "suicide failed");

	sleep(1);

	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;

	status = smb2_create(tree2, tctx, &(io.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");
	torture_assert(tctx,
		       io.smb2.out.oplock_level==SMB2_OPLOCK_LEVEL_BATCH,
		       "Did not get BATCH oplock\n");

	closeio = (struct smb2_close) {
		.in.file.handle = io.smb2.out.file.handle,
	};
	status = smb2_close(tree2, &closeio);
	torture_assert_ntstatus_equal(
		tctx, status, NT_STATUS_OK, "close failed");

	return true;
}

static bool test_oplock_statopen1_do(struct torture_context *tctx,
				     struct smb2_tree *tree,
				     uint32_t access_mask,
				     bool expect_stat_open)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create cr;
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	NTSTATUS status;
	const char *fname = "oplock_statopen1.dat";
	bool ret = true;

	/* Open file with exclusive oplock. */
	cr = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = fname,
		.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH,
	};
	status = smb2_create(tree, mem_ctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = cr.out.file.handle;
	CHECK_VAL(cr.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* Stat open */
	cr = (struct smb2_create) {
		.in.desired_access = access_mask,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION,
		.in.fname = fname,
	};
	status = smb2_create(tree, mem_ctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = cr.out.file.handle;

	if (expect_stat_open) {
		torture_wait_for_oplock_break(tctx);
		CHECK_VAL(break_info.count, 0);
		CHECK_VAL(break_info.level, 0);
		CHECK_VAL(break_info.failures, 0);
		if (!ret) {
			goto done;
		}
	} else {
		CHECK_VAL(break_info.count, 1);
	}

done:
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	talloc_free(mem_ctx);
	return ret;
}

static bool test_smb2_oplock_statopen1(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	const char *fname = "oplock_statopen1.dat";
	size_t i;
	bool ret = true;
	struct {
		uint32_t access_mask;
		bool expect_stat_open;
	} tests[] = {
		{
			.access_mask = FILE_READ_DATA,
			.expect_stat_open = false,
		},
		{
			.access_mask = FILE_WRITE_DATA,
			.expect_stat_open = false,
		},
		{
			.access_mask = FILE_READ_EA,
			.expect_stat_open = false,
		},
		{
			.access_mask = FILE_WRITE_EA,
			.expect_stat_open = false,
		},
		{
			.access_mask = FILE_EXECUTE,
			.expect_stat_open = false,
		},
		{
			.access_mask = FILE_READ_ATTRIBUTES,
			.expect_stat_open = true,
		},
		{
			.access_mask = FILE_WRITE_ATTRIBUTES,
			.expect_stat_open = true,
		},
		{
			.access_mask = DELETE_ACCESS,
			.expect_stat_open = false,
		},
		{
			.access_mask = READ_CONTROL_ACCESS,
			.expect_stat_open = false,
		},
		{
			.access_mask = WRITE_DAC_ACCESS,
			.expect_stat_open = false,
		},
		{
			.access_mask = WRITE_OWNER_ACCESS,
			.expect_stat_open = false,
		},
		{
			.access_mask = SYNCHRONIZE_ACCESS,
			.expect_stat_open = true,
		},
	};

	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		ZERO_STRUCT(break_info);

		ret = test_oplock_statopen1_do(tctx,
					       tree,
					       tests[i].access_mask,
					       tests[i].expect_stat_open);
		if (ret == true) {
			continue;
		}
		torture_result(tctx, TORTURE_FAIL,
			       "test %zu: access_mask: %s, "
			       "expect_stat_open: %s\n",
			       i,
			       get_sec_mask_str(tree, tests[i].access_mask),
			       tests[i].expect_stat_open ? "yes" : "no");
		goto done;
	}

done:
	smb2_util_unlink(tree, fname);
	return ret;
}

struct torture_suite *torture_smb2_oplocks_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "oplock");

	torture_suite_add_2smb2_test(suite, "exclusive1", test_smb2_oplock_exclusive1);
	torture_suite_add_2smb2_test(suite, "exclusive2", test_smb2_oplock_exclusive2);
	torture_suite_add_2smb2_test(suite, "exclusive3", test_smb2_oplock_exclusive3);
	torture_suite_add_2smb2_test(suite, "exclusive4", test_smb2_oplock_exclusive4);
	torture_suite_add_2smb2_test(suite, "exclusive5", test_smb2_oplock_exclusive5);
	torture_suite_add_2smb2_test(suite, "exclusive6", test_smb2_oplock_exclusive6);
	torture_suite_add_2smb2_test(suite, "exclusive9",
				     test_smb2_oplock_exclusive9);
	torture_suite_add_2smb2_test(suite, "batch1", test_smb2_oplock_batch1);
	torture_suite_add_2smb2_test(suite, "batch2", test_smb2_oplock_batch2);
	torture_suite_add_2smb2_test(suite, "batch3", test_smb2_oplock_batch3);
	torture_suite_add_2smb2_test(suite, "batch4", test_smb2_oplock_batch4);
	torture_suite_add_2smb2_test(suite, "batch5", test_smb2_oplock_batch5);
	torture_suite_add_2smb2_test(suite, "batch6", test_smb2_oplock_batch6);
	torture_suite_add_2smb2_test(suite, "batch7", test_smb2_oplock_batch7);
	torture_suite_add_2smb2_test(suite, "batch8", test_smb2_oplock_batch8);
	torture_suite_add_2smb2_test(suite, "batch9", test_smb2_oplock_batch9);
	torture_suite_add_2smb2_test(suite, "batch9a", test_smb2_oplock_batch9a);
	torture_suite_add_2smb2_test(suite, "batch10", test_smb2_oplock_batch10);
	torture_suite_add_2smb2_test(suite, "batch11", test_smb2_oplock_batch11);
	torture_suite_add_2smb2_test(suite, "batch12", test_smb2_oplock_batch12);
	torture_suite_add_2smb2_test(suite, "batch13", test_smb2_oplock_batch13);
	torture_suite_add_2smb2_test(suite, "batch14", test_smb2_oplock_batch14);
	torture_suite_add_2smb2_test(suite, "batch15", test_smb2_oplock_batch15);
	torture_suite_add_2smb2_test(suite, "batch16", test_smb2_oplock_batch16);
	torture_suite_add_1smb2_test(suite, "batch19", test_smb2_oplock_batch19);
	torture_suite_add_2smb2_test(suite, "batch20", test_smb2_oplock_batch20);
	torture_suite_add_1smb2_test(suite, "batch21", test_smb2_oplock_batch21);
	torture_suite_add_1smb2_test(suite, "batch22a", test_smb2_oplock_batch22a);
	torture_suite_add_2smb2_test(suite, "batch22b", test_smb2_oplock_batch22b);
	torture_suite_add_2smb2_test(suite, "batch23", test_smb2_oplock_batch23);
	torture_suite_add_2smb2_test(suite, "batch24", test_smb2_oplock_batch24);
	torture_suite_add_1smb2_test(suite, "batch25", test_smb2_oplock_batch25);
	torture_suite_add_1smb2_test(suite, "batch26", test_smb2_oplock_batch26);
	torture_suite_add_2smb2_test(suite, "stream1", test_raw_oplock_stream1);
	torture_suite_add_2smb2_test(suite, "doc", test_smb2_oplock_doc);
	torture_suite_add_2smb2_test(suite, "brl1", test_smb2_oplock_brl1);
	torture_suite_add_1smb2_test(suite, "brl2", test_smb2_oplock_brl2);
	torture_suite_add_1smb2_test(suite, "brl3", test_smb2_oplock_brl3);
	torture_suite_add_1smb2_test(suite, "levelii500", test_smb2_oplock_levelII500);
	torture_suite_add_2smb2_test(suite, "levelii501",
				     test_smb2_oplock_levelII501);
	torture_suite_add_2smb2_test(suite, "levelii502",
				     test_smb2_oplock_levelII502);
	torture_suite_add_1smb2_test(suite, "statopen1", test_smb2_oplock_statopen1);
	suite->description = talloc_strdup(suite, "SMB2-OPLOCK tests");

	return suite;
}

/*
   stress testing of oplocks
*/
bool test_smb2_bench_oplock(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_tree **trees;
	bool ret = true;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int i, count=0;
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	union smb_open io;
	struct timeval tv;
	struct smb2_handle h;

	trees = talloc_array(mem_ctx, struct smb2_tree *, torture_nprocs);

	torture_comment(tctx, "Opening %d connections\n", torture_nprocs);
	for (i=0;i<torture_nprocs;i++) {
		if (!torture_smb2_connection(tctx, &trees[i])) {
			return false;
		}
		talloc_steal(mem_ctx, trees[i]);
		trees[i]->session->transport->oplock.handler =
					torture_oplock_handler_close;
		trees[i]->session->transport->oplock.private_data = trees[i];
	}

	status = torture_smb2_testdir(trees[0], BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	ZERO_STRUCT(io.smb2);
	io.smb2.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR "\\test.dat";
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	tv = timeval_current();

	/*
	  we open the same file with SHARE_ACCESS_NONE from all the
	  connections in a round robin fashion. Each open causes an
	  oplock break on the previous connection, which is answered
	  by the oplock_handler_close() to close the file.

	  This measures how fast we can pass on oplocks, and stresses
	  the oplock handling code
	*/
	torture_comment(tctx, "Running for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		for (i=0;i<torture_nprocs;i++) {
			status = smb2_create(trees[i], mem_ctx, &(io.smb2));
			torture_assert_ntstatus_ok(tctx, status, "Incorrect status");
			count++;
		}

		if (torture_setting_bool(tctx, "progress", true)) {
			torture_comment(tctx, "%.2f ops/second\r",
					count/timeval_elapsed(&tv));
		}
	}

	torture_comment(tctx, "%.2f ops/second\n", count/timeval_elapsed(&tv));
	smb2_util_close(trees[0], io.smb2.out.file.handle);
	smb2_util_unlink(trees[0], BASEDIR "\\test.dat");
	smb2_deltree(trees[0], BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static struct hold_oplock_info {
	const char *fname;
	bool close_on_break;
	uint32_t share_access;
	struct smb2_handle handle;
} hold_info[] = {
	{
		.fname          = BASEDIR "\\notshared_close",
		.close_on_break = true,
		.share_access   = NTCREATEX_SHARE_ACCESS_NONE,
	},
	{
		.fname          = BASEDIR "\\notshared_noclose",
		.close_on_break = false,
		.share_access   = NTCREATEX_SHARE_ACCESS_NONE,
	},
	{
		.fname          = BASEDIR "\\shared_close",
		.close_on_break = true,
		.share_access   = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
	},
	{
		.fname          = BASEDIR "\\shared_noclose",
		.close_on_break = false,
		.share_access   = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
	},
};

static bool torture_oplock_handler_hold(struct smb2_transport *transport,
					const struct smb2_handle *handle,
					uint8_t level, void *private_data)
{
	struct hold_oplock_info *info;
	int i;

	for (i=0;i<ARRAY_SIZE(hold_info);i++) {
		if (smb2_util_handle_equal(hold_info[i].handle, *handle))
			break;
	}

	if (i == ARRAY_SIZE(hold_info)) {
		printf("oplock break for unknown handle 0x%llx%llx\n",
		       (unsigned long long) handle->data[0],
		       (unsigned long long) handle->data[1]);
		return false;
	}

	info = &hold_info[i];

	if (info->close_on_break) {
		printf("oplock break on %s - closing\n", info->fname);
		torture_oplock_handler_close(transport, handle,
					     level, private_data);
		return true;
	}

	printf("oplock break on %s - acking break\n", info->fname);
	printf("Acking to none in oplock handler\n");

	torture_oplock_handler_ack_to_none(transport, handle,
					   level, private_data);
	return true;
}

/*
   used for manual testing of oplocks - especially interaction with
   other filesystems (such as NFS and local access)
*/
bool test_smb2_hold_oplock(struct torture_context *tctx,
			   struct smb2_tree *tree)
{
	struct torture_context *mem_ctx = talloc_new(tctx);
	struct tevent_context *ev = tctx->ev;
	int i;
	struct smb2_handle h;
	NTSTATUS status;

	torture_comment(tctx, "Setting up open files with oplocks in %s\n",
			BASEDIR);

	status = torture_smb2_testdir(tree, BASEDIR, &h);
	torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

	tree->session->transport->oplock.handler = torture_oplock_handler_hold;
	tree->session->transport->oplock.private_data = tree;

	/* setup the files */
	for (i=0;i<ARRAY_SIZE(hold_info);i++) {
		union smb_open io;
		char c = 1;

		ZERO_STRUCT(io.smb2);
		io.generic.level = RAW_OPEN_SMB2;
		io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
		io.smb2.in.alloc_size = 0;
		io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		io.smb2.in.share_access = hold_info[i].share_access;
		io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
		io.smb2.in.create_options = 0;
		io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
		io.smb2.in.security_flags = 0;
		io.smb2.in.fname = hold_info[i].fname;
		io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
		io.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

		torture_comment(tctx, "opening %s\n", hold_info[i].fname);

		status = smb2_create(tree, mem_ctx, &(io.smb2));
		if (!NT_STATUS_IS_OK(status)) {
			torture_comment(tctx, "Failed to open %s - %s\n",
			       hold_info[i].fname, nt_errstr(status));
			return false;
		}

		if (io.smb2.out.oplock_level != SMB2_OPLOCK_LEVEL_BATCH) {
			torture_comment(tctx, "Oplock not granted for %s - "
					"expected %d but got %d\n",
					hold_info[i].fname,
					SMB2_OPLOCK_LEVEL_BATCH,
					io.smb2.out.oplock_level);
			return false;
		}
		hold_info[i].handle = io.smb2.out.file.handle;

		/* make the file non-zero size */
		status = smb2_util_write(tree, hold_info[i].handle, &c, 0, 1);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
			torture_comment(tctx, "Failed to write to file\n");
			return false;
		}
	}

	torture_comment(tctx, "Waiting for oplock events\n");
	tevent_loop_wait(ev);
	smb2_deltree(tree, BASEDIR);
	talloc_free(mem_ctx);
	return true;
}


static bool test_smb2_kernel_oplocks1(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	const char *fname = "test_kernel_oplock1.dat";
	NTSTATUS status;
	bool ret = true;
	struct smb2_create create;
	struct smb2_handle h1 = {{0}}, h2 = {{0}};

	smb2_util_unlink(tree, fname);

	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;
	ZERO_STRUCT(break_info);

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = fname;
	create.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h1 = create.out.file.handle;

	torture_assert_goto(tctx, create.out.oplock_level == SMB2_OPLOCK_LEVEL_EXCLUSIVE, ret, done,
			    "Oplock level is not SMB2_OPLOCK_LEVEL_EXCLUSIVE\n");

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = fname;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_SHARING_VIOLATION, ret, done,
					   "Open didn't return NT_STATUS_SHARING_VIOLATION\n");
	h2 = create.out.file.handle;

	torture_wait_for_oplock_break(tctx);
	if (break_info.count != 0) {
		torture_warning(tctx, "Open caused oplock break\n");
	}

	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_util_unlink(tree, fname);
	return ret;
}

static bool test_smb2_kernel_oplocks2(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	const char *fname = "test_kernel_oplock2.dat";
	const char *sname = "test_kernel_oplock2.dat:foo";
	NTSTATUS status;
	bool ret = true;
	struct smb2_create create;
	struct smb2_handle h1 = {{0}}, h2 = {{0}};

	smb2_util_unlink(tree, fname);

	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;
	ZERO_STRUCT(break_info);

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = fname;
	create.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h1 = create.out.file.handle;

	torture_assert_goto(tctx, create.out.oplock_level == SMB2_OPLOCK_LEVEL_EXCLUSIVE, ret, done,
			    "Oplock level is not SMB2_OPLOCK_LEVEL_EXCLUSIVE\n");

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = sname;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h2 = create.out.file.handle;

	torture_wait_for_oplock_break(tctx);
	if (break_info.count != 0) {
		torture_warning(tctx, "Stream open caused oplock break\n");
	}

	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_util_unlink(tree, fname);
	return ret;
}

/**
 * 1. 1st client opens file with oplock
 * 2. 2nd client opens file
 *
 * Verify 2 triggers an oplock break
 **/
static bool test_smb2_kernel_oplocks3(struct torture_context *tctx,
				      struct smb2_tree *tree,
				      struct smb2_tree *tree2)
{
	const char *fname = "test_kernel_oplock3.dat";
	NTSTATUS status;
	bool ret = true;
	struct smb2_create create;
	struct smb2_handle h1 = {{0}}, h2 = {{0}};

	smb2_util_unlink(tree, fname);
	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Error creating testfile\n");
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;
	ZERO_STRUCT(break_info);

	/* 1 */
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = fname;
	create.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h1 = create.out.file.handle;

	torture_assert_goto(tctx, create.out.oplock_level == SMB2_OPLOCK_LEVEL_EXCLUSIVE, ret, done,
			    "Oplock level is not SMB2_OPLOCK_LEVEL_EXCLUSIVE\n");

	/* 2 */
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_READ;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = fname;

	status = smb2_create(tree2, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h2 = create.out.file.handle;

	torture_wait_for_oplock_break(tctx);
	torture_assert_goto(tctx, break_info.count == 1, ret, done, "Expected 1 oplock break\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_util_unlink(tree, fname);
	return ret;
}

/**
 * 1) create testfile with stream
 * 2) open file r/w with batch oplock, sharing read/delete
 * 3) open stream on file for reading
 *
 * Verify 3) doesn't trigger an oplock break
 **/
static bool test_smb2_kernel_oplocks4(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	const char *fname = "test_kernel_oplock4.dat";
	const char *sname = "test_kernel_oplock4.dat:foo";
	NTSTATUS status;
	bool ret = true;
	struct smb2_create create;
	struct smb2_handle h1 = {{0}}, h2 = {{0}};

	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;
	ZERO_STRUCT(break_info);
	smb2_util_unlink(tree, fname);

	/* 1 */
	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Error creating testfile\n");
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_READ;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = sname;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h1 = create.out.file.handle;
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* 2 */
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_DELETE;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = fname;
	create.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h1 = create.out.file.handle;

	torture_assert_goto(tctx, create.out.oplock_level == SMB2_OPLOCK_LEVEL_BATCH, ret, done,
			    "Oplock level is not SMB2_OPLOCK_LEVEL_BATCH\n");

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_READ;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_DELETE;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = sname;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h2 = create.out.file.handle;

	torture_wait_for_oplock_break(tctx);
	if (break_info.count != 0) {
		torture_warning(tctx, "Stream open caused oplock break\n");
	}

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_util_unlink(tree, fname);
	return ret;
}

/**
 * 1) create testfile with stream
 * 2) open stream r/w with batch oplock -> batch oplock granted
 * 3) open stream r/o with batch oplock
 *
 * Verify 3) does trigger an oplock break
 **/
static bool test_smb2_kernel_oplocks5(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	const char *fname = "test_kernel_oplock4.dat";
	const char *sname = "test_kernel_oplock4.dat:foo";
	NTSTATUS status;
	bool ret = true;
	struct smb2_create create;
	struct smb2_handle h1 = {{0}}, h2 = {{0}};

	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;
	ZERO_STRUCT(break_info);
	smb2_util_unlink(tree, fname);

	/* 1 */
	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Error creating testfile\n");
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_READ;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = sname;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h1 = create.out.file.handle;
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* 2 */
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = sname;
	create.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h1 = create.out.file.handle;

	torture_assert_goto(tctx, create.out.oplock_level == SMB2_OPLOCK_LEVEL_BATCH, ret, done,
			    "Oplock level is not SMB2_OPLOCK_LEVEL_BATCH\n");

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_READ;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = sname;
	create.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h2 = create.out.file.handle;

	torture_assert_goto(tctx, create.out.oplock_level == SMB2_OPLOCK_LEVEL_NONE, ret, done,
			    "Oplock level is not SMB2_OPLOCK_LEVEL_NONE\n");

	torture_wait_for_oplock_break(tctx);
	if (break_info.count != 1) {
		torture_warning(tctx, "Stream open didn't cause oplock break\n");
	}

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_util_unlink(tree, fname);
	return ret;
}

/**
 * 1) create testfile with stream
 * 2) 1st client opens stream r/w with batch oplock -> batch oplock granted
 * 3) 2nd client opens stream r/o with batch oplock
 *
 * Verify 3) does trigger an oplock break
 **/
static bool test_smb2_kernel_oplocks6(struct torture_context *tctx,
				      struct smb2_tree *tree,
				      struct smb2_tree *tree2)
{
	const char *fname = "test_kernel_oplock6.dat";
	const char *sname = "test_kernel_oplock6.dat:foo";
	NTSTATUS status;
	bool ret = true;
	struct smb2_create create;
	struct smb2_handle h1 = {{0}}, h2 = {{0}};

	smb2_util_unlink(tree, fname);
	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Error creating testfile\n");
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;
	ZERO_STRUCT(break_info);

	/* 1 */
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_READ;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = sname;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h1 = create.out.file.handle;
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* 2 */
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = fname;
	create.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h1 = create.out.file.handle;

	torture_assert_goto(tctx, create.out.oplock_level == SMB2_OPLOCK_LEVEL_EXCLUSIVE, ret, done,
			    "Oplock level is not SMB2_OPLOCK_LEVEL_EXCLUSIVE\n");

	/* 3 */
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_READ;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = fname;

	status = smb2_create(tree2, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "Error opening the file\n");
	h2 = create.out.file.handle;

	torture_assert_goto(tctx, create.out.oplock_level == SMB2_OPLOCK_LEVEL_NONE, ret, done,
			    "Oplock level is not SMB2_OPLOCK_LEVEL_NONE\n");

	torture_wait_for_oplock_break(tctx);
	torture_assert_goto(tctx, break_info.count == 1, ret, done, "Expected 1 oplock break\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_util_unlink(tree, fname);
	return ret;
}

/**
 * Recreate regression test from bug:
 *
 * https://bugzilla.samba.org/show_bug.cgi?id=13058
 *
 * 1. smbd-1 opens the file and sets the oplock
 * 2. smbd-2 tries to open the file. open() fails(EAGAIN) and open is deferred.
 * 3. smbd-1 sends oplock break request to the client.
 * 4. smbd-1 closes the file.
 * 5. smbd-1 opens the file and sets the oplock.
 * 6. smbd-2 calls defer_open_done(), and should re-break the oplock.
 **/

static bool test_smb2_kernel_oplocks7(struct torture_context *tctx,
				      struct smb2_tree *tree,
				      struct smb2_tree *tree2)
{
	const char *fname = "test_kernel_oplock7.dat";
	NTSTATUS status;
	bool ret = true;
	struct smb2_create create;
	struct smb2_handle h1 = {{0}}, h2 = {{0}};
	struct smb2_create create_2;
        struct smb2_create io;
	struct smb2_request *req;

	smb2_util_unlink(tree, fname);
	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Error creating testfile\n");
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* Close the open file on break. */
	tree->session->transport->oplock.handler = torture_oplock_handler_close;
	tree->session->transport->oplock.private_data = tree;
	ZERO_STRUCT(break_info);

	/* 1 - open file with oplock */
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.fname = fname;
	create.in.oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"Error opening the file\n");
	CHECK_VAL(create.out.oplock_level, SMB2_OPLOCK_LEVEL_EXCLUSIVE);

	/* 2 - open file to break oplock */
	ZERO_STRUCT(create_2);
	create_2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create_2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create_2.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	create_2.in.create_disposition = NTCREATEX_DISP_OPEN;
	create_2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create_2.in.fname = fname;
	create_2.in.oplock_level = SMB2_OPLOCK_LEVEL_NONE;

	/* Open on tree2 - should cause a break on tree */
	req = smb2_create_send(tree2, &create_2);
	torture_assert(tctx, req != NULL, "smb2_create_send");

	/* The oplock break handler should close the file. */
	/* Steps 3 & 4. */
	torture_wait_for_oplock_break(tctx);

	tree->session->transport->oplock.handler = torture_oplock_handler;

	/*
	 * 5 - re-open on tree. NB. There is a race here
	 * depending on which smbd goes first. We either get
	 * an oplock level of SMB2_OPLOCK_LEVEL_EXCLUSIVE if
	 * the close and re-open on tree is processed first, or
	 * SMB2_OPLOCK_LEVEL_NONE if the pending create on
	 * tree2 is processed first.
	 */
	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"Error opening the file\n");

	h1 = create.out.file.handle;
	if (create.out.oplock_level != SMB2_OPLOCK_LEVEL_EXCLUSIVE &&
	    create.out.oplock_level != SMB2_OPLOCK_LEVEL_NONE) {
		torture_result(tctx,
			TORTURE_FAIL,
			"(%s): wrong value for oplock got 0x%x\n",
			__location__,
			(unsigned int)create.out.oplock_level);
                ret = false;
		goto done;

	}

	/* 6 - retrieve the second open. */
	status = smb2_create_recv(req, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"Error opening the file\n");
	h2 = io.out.file.handle;
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}
	smb2_util_unlink(tree, fname);
	return ret;
}

#ifdef HAVE_KERNEL_OPLOCKS_LINUX

#ifndef F_SETLEASE
#define F_SETLEASE      1024
#endif

#ifndef RT_SIGNAL_LEASE
#define RT_SIGNAL_LEASE (SIGRTMIN+1)
#endif

#ifndef F_SETSIG
#define F_SETSIG 10
#endif

static int got_break;

/*
 * Signal handler.
 */

static void got_rt_break(int sig)
{
	got_break = 1;
}

static int got_alarm;

/*
 * Signal handler.
 */

static void got_alarm_fn(int sig)
{
	got_alarm = 1;
}

/*
 * Child process function.
 */

static int do_child_process(int pipefd, const char *name)
{
	int ret = 0;
	int fd = -1;
	char c = 0;
	struct sigaction act;
	sigset_t set;
	sigset_t empty_set;

	/* Block RT_SIGNAL_LEASE and SIGALRM. */
	sigemptyset(&set);
	sigemptyset(&empty_set);
	sigaddset(&set, RT_SIGNAL_LEASE);
	sigaddset(&set, SIGALRM);
	ret = sigprocmask(SIG_SETMASK, &set, NULL);
	if (ret == -1) {
		return 11;
	}

	/* Set up a signal handler for RT_SIGNAL_LEASE. */
	ZERO_STRUCT(act);
	act.sa_handler = got_rt_break;
	ret = sigaction(RT_SIGNAL_LEASE, &act, NULL);
	if (ret == -1) {
		return 1;
	}
	/* Set up a signal handler for SIGALRM. */
	ZERO_STRUCT(act);
	act.sa_handler = got_alarm_fn;
	ret = sigaction(SIGALRM, &act, NULL);
	if (ret == -1) {
		return 1;
	}
	/* Open the passed in file and get a kernel oplock. */
	fd = open(name, O_RDWR, 0666);
	if (fd == -1) {
		return 2;
	}

	ret = fcntl(fd, F_SETSIG, RT_SIGNAL_LEASE);
	if (ret == -1) {
		close(fd);
		return 3;
	}

	ret = fcntl(fd, F_SETLEASE, F_WRLCK);
	if (ret == -1) {
		close(fd);
		return 4;
	}

	/* Tell the parent we're ready. */
	ret = sys_write(pipefd, &c, 1);
	if (ret != 1) {
		close(fd);
		return 5;
	}

	/* Ensure the pause doesn't hang forever. */
	alarm(5);

	/* Wait for RT_SIGNAL_LEASE or SIGALRM. */
	ret = sigsuspend(&empty_set);
	if (ret != -1 || errno != EINTR) {
		close(fd);
		return 6;
	}

	if (got_alarm == 1) {
		close(fd);
		return 10;
	}

	if (got_break != 1) {
		close(fd);
		return 7;
	}

	/* Cancel any pending alarm. */
	alarm(0);

	/* Force the server to wait for 3 seconds. */
	sleep(3);

	/* Remove our lease. */
	ret = fcntl(fd, F_SETLEASE, F_UNLCK);
	if (ret == -1) {
		close(fd);
		return 8;
	}

	ret = close(fd);
	if (ret == -1) {
		return 9;
	}

	/* All is well. */
	return 0;
}

static bool wait_for_child_oplock(struct torture_context *tctx,
				const char *localdir,
				const char *fname)
{
	int fds[2];
	int ret;
	pid_t pid;
	char *name = talloc_asprintf(tctx,
				"%s/%s",
				localdir,
				fname);

	torture_assert(tctx, name != NULL, "talloc failed");

	ret = pipe(fds);
	torture_assert(tctx, ret != -1, "pipe failed");

	pid = fork();
	torture_assert(tctx, pid != (pid_t)-1, "fork failed");

	if (pid != (pid_t)0) {
		char c;
		/* Parent. */
		TALLOC_FREE(name);
		close(fds[1]);
		ret = sys_read(fds[0], &c, 1);
		torture_assert(tctx, ret == 1, "read failed");
		return true;
	}

	/* Child process. */
	close(fds[0]);
	ret = do_child_process(fds[1], name);
	_exit(ret);
	/* Notreached. */
}
#else
static bool wait_for_child_oplock(struct torture_context *tctx,
				const char *localdir,
				const char *fname)
{
	return false;
}
#endif

static void child_sig_term_handler(struct tevent_context *ev,
				struct tevent_signal *se,
				int signum,
				int count,
				void *siginfo,
				void *private_data)
{
	int *pstatus = (int *)private_data;
	int status = 0;

	wait(&status);
	if (WIFEXITED(status)) {
		*pstatus = WEXITSTATUS(status);
	} else {
		*pstatus = status;
	}
}

/*
 * Deal with a non-smbd process holding a kernel oplock.
 */

static bool test_smb2_kernel_oplocks8(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	const char *fname = "test_kernel_oplock8.dat";
	const char *fname1 = "tmp_test_kernel_oplock8.dat";
	NTSTATUS status;
	bool ret = true;
	struct smb2_create io;
	struct smb2_request *req = NULL;
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	const char *localdir = torture_setting_string(tctx, "localdir", NULL);
	struct tevent_signal *se = NULL;
	int child_exit_code = -1;
	time_t start;
	time_t end;

#ifndef HAVE_KERNEL_OPLOCKS_LINUX
	torture_skip(tctx, "Need kernel oplocks for test");
#endif

	if (localdir == NULL) {
		torture_skip(tctx, "Need localdir for test");
	}

	smb2_util_unlink(tree, fname);
	smb2_util_unlink(tree, fname1);
	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Error creating testfile\n");
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	se = tevent_add_signal(tctx->ev,
				tctx,
				SIGCHLD,
				0,
				child_sig_term_handler,
				&child_exit_code);
	torture_assert(tctx, se != NULL, "tevent_add_signal failed\n");

	/* Take the oplock locally in a sub-process. */
	ret = wait_for_child_oplock(tctx, localdir, fname);
	torture_assert_goto(tctx, ret, ret, done,
		"Wait for child process failed.\n");

	/*
	 * Now try and open. This should block for 3 seconds.
	 * while the child process is still alive.
	 */

	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = fname;

	req = smb2_create_send(tree, &io);
	torture_assert_goto(tctx, req != NULL,
			    ret, done, "smb2_create_send");

	/* Ensure while the open is blocked the smbd is
	   still serving other requests. */
	io.in.fname = fname1;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;

	/* Time the start -> end of the request. */
	start = time(NULL);
	status = smb2_create(tree, tctx, &io);
	end = time(NULL);

	/* Should succeed. */
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"Error opening the second file\n");
	h1 = io.out.file.handle;

	/* in less than 2 seconds. Otherwise the server blocks. */
	torture_assert_goto(tctx, end - start < 2,
			    ret, done, "server was blocked !");

	/* Pick up the return for the initial blocking open. */
	status = smb2_create_recv(req, tctx, &io);

	/* Which should also have succeeded. */
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"Error opening the file\n");
	h2 = io.out.file.handle;

	/* Wait for the exit code from the child. */
	while (child_exit_code == -1) {
		int rval = tevent_loop_once(tctx->ev);
		torture_assert_goto(tctx, rval == 0, ret,
				    done, "tevent_loop_once error\n");
	}

	torture_assert_int_equal_goto(tctx, child_exit_code, 0,
				      ret, done, "Bad child exit code");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_util_unlink(tree, fname);
	smb2_util_unlink(tree, fname1);
	return ret;
}

struct torture_suite *torture_smb2_kernel_oplocks_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "kernel-oplocks");

	torture_suite_add_1smb2_test(suite, "kernel_oplocks1", test_smb2_kernel_oplocks1);
	torture_suite_add_1smb2_test(suite, "kernel_oplocks2", test_smb2_kernel_oplocks2);
	torture_suite_add_2smb2_test(suite, "kernel_oplocks3", test_smb2_kernel_oplocks3);
	torture_suite_add_1smb2_test(suite, "kernel_oplocks4", test_smb2_kernel_oplocks4);
	torture_suite_add_1smb2_test(suite, "kernel_oplocks5", test_smb2_kernel_oplocks5);
	torture_suite_add_2smb2_test(suite, "kernel_oplocks6", test_smb2_kernel_oplocks6);
	torture_suite_add_2smb2_test(suite, "kernel_oplocks7", test_smb2_kernel_oplocks7);
	torture_suite_add_1smb2_test(suite, "kernel_oplocks8", test_smb2_kernel_oplocks8);

	suite->description = talloc_strdup(suite, "SMB2-KERNEL-OPLOCK tests");

	return suite;
}
