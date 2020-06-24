/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 replay

   Copyright (C) Anubhav Rakshit 2014
   Copyright (C) Stefan Metzmacher 2014

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
#include "lib/cmdline/popt_common.h"
#include "auth/credentials/credentials.h"
#include "libcli/security/security.h"
#include "libcli/resolve/resolve.h"
#include "lib/param/param.h"
#include "lib/events/events.h"
#include "oplock_break_handler.h"

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): wrong value for %s got 0x%x - should be 0x%x\n", \
				__location__, #v, (int)v, (int)correct); \
		ret = false; \
		goto done; \
	}} while (0)

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": Incorrect status %s - should be %s", \
		       nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define CHECK_CREATED(__io, __created, __attribute)			\
	do {								\
		CHECK_VAL((__io)->out.create_action, NTCREATEX_ACTION_ ## __created); \
		CHECK_VAL((__io)->out.size, 0);				\
		CHECK_VAL((__io)->out.file_attr, (__attribute));	\
		CHECK_VAL((__io)->out.reserved2, 0);			\
	} while(0)

#define CHECK_HANDLE(__h1, __h2)					\
	do {								\
		CHECK_VAL((__h1)->data[0], (__h2)->data[0]);		\
		CHECK_VAL((__h1)->data[1], (__h2)->data[1]);		\
	} while(0)

#define __IO_OUT_VAL(__io1, __io2, __m) \
	CHECK_VAL((__io1)->out.__m, (__io2)->out.__m)

#define CHECK_CREATE_OUT(__io1, __io2)				\
	do {							\
		CHECK_HANDLE(&(__io1)->out.file.handle,		\
			     &(__io2)->out.file.handle);	\
		__IO_OUT_VAL(__io1, __io2, oplock_level);	\
		__IO_OUT_VAL(__io1, __io2, create_action);	\
		__IO_OUT_VAL(__io1, __io2, create_time);	\
		__IO_OUT_VAL(__io1, __io2, access_time);	\
		__IO_OUT_VAL(__io1, __io2, write_time);		\
		__IO_OUT_VAL(__io1, __io2, change_time);	\
		__IO_OUT_VAL(__io1, __io2, alloc_size);		\
		__IO_OUT_VAL(__io1, __io2, size);		\
		__IO_OUT_VAL(__io1, __io2, file_attr);		\
		__IO_OUT_VAL(__io1, __io2, durable_open);	\
		__IO_OUT_VAL(__io1, __io2, durable_open_v2);	\
		__IO_OUT_VAL(__io1, __io2, persistent_open);	\
		__IO_OUT_VAL(__io1, __io2, timeout);		\
		__IO_OUT_VAL(__io1, __io2, blobs.num_blobs);	\
		if ((__io1)->out.oplock_level == SMB2_OPLOCK_LEVEL_LEASE) { \
			__IO_OUT_VAL(__io1, __io2, lease_response.lease_state);\
			__IO_OUT_VAL(__io1, __io2, lease_response.lease_key.data[0]);\
			__IO_OUT_VAL(__io1, __io2, lease_response.lease_key.data[1]);\
		} \
	} while(0)

#define BASEDIR "replaytestdir"

/**
 * Test what happens when SMB2_FLAGS_REPLAY_OPERATION is enabled for various
 * commands. We want to verify if the server returns an error code or not.
 */
static bool test_replay_commands(struct torture_context *tctx, struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle h;
	uint8_t buf[200];
	struct smb2_read rd;
	union smb_setfileinfo sfinfo;
	union smb_fileinfo qfinfo;
	union smb_ioctl ioctl;
	struct smb2_lock lck;
	struct smb2_lock_element el[2];
	struct smb2_flush f;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	const char *fname = BASEDIR "\\replay_commands.dat";
	struct smb2_transport *transport = tree->session->transport;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "Replay tests\n");
	}

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	status = torture_smb2_testdir(tree, BASEDIR, &h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, h);

	smb2cli_session_start_replay(tree->session->smbXcli);

	torture_comment(tctx, "Try Commands with Replay Flags Enabled\n");

	torture_comment(tctx, "Trying create\n");
	status = torture_smb2_testfile(tree, fname, &h);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(break_info.count, 0);
	/*
	 * Wireshark shows that the response has SMB2_FLAGS_REPLAY_OPERATION
	 * flags set. The server should ignore this flag.
	 */

	torture_comment(tctx, "Trying write\n");
	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	CHECK_STATUS(status, NT_STATUS_OK);

	f = (struct smb2_flush) {
		.in.file.handle = h
	};
	torture_comment(tctx, "Trying flush\n");
	status = smb2_flush(tree, &f);
	CHECK_STATUS(status, NT_STATUS_OK);

	rd = (struct smb2_read) {
		.in.file.handle = h,
		.in.length = 10,
		.in.offset = 0,
		.in.min_count = 1
	};
	torture_comment(tctx, "Trying read\n");
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(rd.out.data.length, 10);

	sfinfo.generic.level = RAW_SFILEINFO_POSITION_INFORMATION;
	sfinfo.position_information.in.file.handle = h;
	sfinfo.position_information.in.position = 0x1000;
	torture_comment(tctx, "Trying setinfo\n");
	status = smb2_setinfo_file(tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	qfinfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_POSITION_INFORMATION,
		.generic.in.file.handle = h
	};
	torture_comment(tctx, "Trying getinfo\n");
	status = smb2_getinfo_file(tree, tmp_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0x1000);

	ioctl = (union smb_ioctl) {
		.smb2.level = RAW_IOCTL_SMB2,
		.smb2.in.file.handle = h,
		.smb2.in.function = FSCTL_CREATE_OR_GET_OBJECT_ID,
		.smb2.in.max_output_response = 64,
		.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL
	};
	torture_comment(tctx, "Trying ioctl\n");
	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	CHECK_STATUS(status, NT_STATUS_OK);

	lck = (struct smb2_lock) {
		.in.locks = el,
		.in.lock_count = 0x0001,
		.in.lock_sequence = 0x00000000,
		.in.file.handle	= h
	};
	el[0].reserved		= 0x00000000;
	el[0].flags		= SMB2_LOCK_FLAG_EXCLUSIVE |
		SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;

	torture_comment(tctx, "Trying lock\n");
	el[0].offset		= 0x0000000000000000;
	el[0].length		= 0x0000000000000100;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

	lck.in.file.handle	= h;
	el[0].flags		= SMB2_LOCK_FLAG_UNLOCK;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(break_info.count, 0);
done:
	smb2cli_session_stop_replay(tree->session->smbXcli);
	smb2_util_close(tree, h);
	smb2_deltree(tree, BASEDIR);

	talloc_free(tmp_ctx);

	return ret;
}

/**
 * Test replay detection without create GUID on single channel.
 * Regular creates can not be replayed.
 * The return code is unaffected of the REPLAY_OPERATION flag.
 */
static bool test_replay_regular(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	uint32_t perms = 0;
	bool ret = true;
	const char *fname = BASEDIR "\\replay_regular.dat";
	struct smb2_transport *transport = tree->session->transport;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	smb2_util_unlink(tree, fname);
	status = torture_smb2_testdir(tree, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h);
	CHECK_VAL(break_info.count, 0);

	torture_comment(tctx, "No replay detection for regular create\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE |
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE |
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	io = (struct smb2_create) {
		.in.desired_access  = perms,
		.in.file_attributes = 0,
		.in.create_disposition = NTCREATEX_DISP_CREATE,
		.in.share_access    = NTCREATEX_SHARE_ACCESS_DELETE,
		.in.create_options  = 0x0,
		.in.fname   = fname
	};

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(break_info.count, 0);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, tctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_COLLISION);
	CHECK_VAL(break_info.count, 0);

	smb2_util_close(tree, *h);
	h = NULL;
	smb2_util_unlink(tree, fname);

	/*
	 * Same experiment with different create disposition.
	 */
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(break_info.count, 0);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, tctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);
	CHECK_VAL(break_info.count, 0);

	smb2_util_close(tree, *h);
	h = NULL;
	smb2_util_unlink(tree, fname);

	/*
	 * Now with more generous share mode.
	 */
	io.in.share_access = smb2_util_share_access("RWD");
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(break_info.count, 0);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, tctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(break_info.count, 0);

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test Durability V2 Create Replay Detection on Single Channel.
 */
static bool test_replay_dhv2_oplock1(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io, ref1;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\replay_dhv2_oplock1.dat";
	struct smb2_transport *transport = tree->session->transport;
	uint32_t share_capabilities;
	bool share_is_so;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_comment(tctx, "Replay of DurableHandleReqV2 on Single "
			      "Channel\n");
	smb2_util_unlink(tree, fname);
	status = torture_smb2_testdir(tree, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h);
	CHECK_VAL(break_info.count, 0);

	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access(""),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	ref1 = io;
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	if (share_is_so) {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("s"));
		CHECK_VAL(io.out.durable_open_v2, false);
		CHECK_VAL(io.out.timeout, 0);
	} else {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
		CHECK_VAL(io.out.durable_open_v2, true);
		CHECK_VAL(io.out.timeout, 300*1000);
	}

	/*
	 * Replay Durable V2 Create on single channel
	 */
	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATE_OUT(&io, &ref1);
	CHECK_VAL(break_info.count, 0);

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test Durability V2 Create Replay Detection on Single Channel.
 * Hand in a different oplock level in the replay.
 * Server responds with the handed in oplock level and
 * corresponding durable status, but does not change the
 * oplock level or durable status of the opened file.
 */
static bool test_replay_dhv2_oplock2(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io, ref1, ref2;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\replay_dhv2_oplock2.dat";
	struct smb2_transport *transport = tree->session->transport;
	uint32_t share_capabilities;
	bool share_is_so;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_comment(tctx, "Replay of DurableHandleReqV2 on Single "
			      "Channel\n");
	smb2_util_unlink(tree, fname);
	status = torture_smb2_testdir(tree, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h);
	CHECK_VAL(break_info.count, 0);

	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access(""),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	ref1 = io;
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	if (share_is_so) {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("s"));
		CHECK_VAL(io.out.durable_open_v2, false);
		CHECK_VAL(io.out.timeout, 0);
	} else {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
		CHECK_VAL(io.out.durable_open_v2, true);
		CHECK_VAL(io.out.timeout, 300*1000);
	}

	/*
	 * Replay durable v2 create on single channel:
	 *
	 * Replay the create with a different oplock (none).
	 * The server replies with the requested oplock level
	 * and also only replies with durable handle based
	 * on whether it could have been granted based on
	 * the requested oplock type.
	 */
	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access(""),
			smb2_util_oplock_level(""));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	/*
	 * Adapt the response to the exepected values
	 */
	ref2 = ref1;
	ref2.out.oplock_level = smb2_util_oplock_level("");
	ref2.out.durable_open_v2 = false;
	ref2.out.timeout = 0;
	ref2.out.blobs.num_blobs = 0;

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATE_OUT(&io, &ref2);
	CHECK_VAL(break_info.count, 0);

	/*
	 * Prove that the open file still has a batch oplock
	 * by breaking it with another open.
	 */
	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access(""),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = GUID_random();
	io.in.timeout = UINT32_MAX;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	if (!share_is_so) {
		CHECK_VAL(break_info.count, 1);
		CHECK_HANDLE(&break_info.handle, &ref1.out.file.handle);
		CHECK_VAL(break_info.level, smb2_util_oplock_level("s"));
		ZERO_STRUCT(break_info);
	}

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test Durability V2 Create Replay Detection on Single Channel.
 * Replay with a different share mode. The share mode of
 * the opened file is not changed by this.
 */
static bool test_replay_dhv2_oplock3(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io, ref1;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\replay_dhv2_oplock3.dat";
	struct smb2_transport *transport = tree->session->transport;
	uint32_t share_capabilities;
	bool share_is_so;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_comment(tctx, "Replay of DurableHandleReqV2 on Single "
			      "Channel\n");
	smb2_util_unlink(tree, fname);
	status = torture_smb2_testdir(tree, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h);
	CHECK_VAL(break_info.count, 0);

	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access(""),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	ref1 = io;
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	if (share_is_so) {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("s"));
		CHECK_VAL(io.out.durable_open_v2, false);
		CHECK_VAL(io.out.timeout, 0);
	} else {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
		CHECK_VAL(io.out.durable_open_v2, true);
		CHECK_VAL(io.out.timeout, 300*1000);
	}

	/*
	 * Replay durable v2 create on single channel:
	 *
	 * Replay the create with a different share mode.
	 * The server replies with the requested share
	 * mode instead of that which is associated to
	 * the handle.
	 */
	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATE_OUT(&io, &ref1);
	CHECK_VAL(break_info.count, 0);

	/*
	 * In order to prove that the different share mode in the
	 * replayed create had no effect on the open file handle,
	 * show that a new create yields NT_STATUS_SHARING_VIOLATION.
	 */
	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access(""),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = GUID_random();
	io.in.timeout = UINT32_MAX;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	if (!share_is_so) {
		CHECK_VAL(break_info.count, 1);
		CHECK_HANDLE(&break_info.handle, &ref1.out.file.handle);
		CHECK_VAL(break_info.level, smb2_util_oplock_level("s"));
		ZERO_STRUCT(break_info);
	}

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test Durability V2 Create Replay Detection on Single Channel.
 * Create with an oplock, and replay with a lease.
 */
static bool test_replay_dhv2_oplock_lease(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\replay_dhv2_oplock1.dat";
	struct smb2_transport *transport = tree->session->transport;
	uint32_t share_capabilities;
	bool share_is_so;
	uint32_t server_capabilities;
	struct smb2_lease ls;
	uint64_t lease_key;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	server_capabilities = smb2cli_conn_server_capabilities(transport->conn);
	if (!(server_capabilities & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_comment(tctx, "Replay of DurableHandleReqV2 on Single "
			      "Channel\n");
	smb2_util_unlink(tree, fname);
	status = torture_smb2_testdir(tree, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h);
	CHECK_VAL(break_info.count, 0);

	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access(""),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	if (share_is_so) {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("s"));
		CHECK_VAL(io.out.durable_open_v2, false);
		CHECK_VAL(io.out.timeout, 0);
	} else {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
		CHECK_VAL(io.out.durable_open_v2, true);
		CHECK_VAL(io.out.timeout, 300*1000);
	}

	/*
	 * Replay Durable V2 Create on single channel
	 * but replay it with a lease instead of an oplock.
	 */
	lease_key = random();
	smb2_lease_create(&io, &ls, false /* dir */, fname,
			lease_key, smb2_util_lease_state("RH"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}


/**
 * Test durability v2 create replay detection on single channel.
 * Variant with leases instead of oplocks:
 * - open a file with a rh lease
 * - upgrade to a rwh lease with a second create
 * - replay the first create.
 *   ==> it gets back the upgraded lease level
 */
static bool test_replay_dhv2_lease1(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io1, io2, ref1;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\replay2_lease1.dat";
	struct smb2_transport *transport = tree->session->transport;
	uint32_t share_capabilities;
	bool share_is_so;
	uint32_t server_capabilities;
	struct smb2_lease ls1, ls2;
	uint64_t lease_key;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	server_capabilities = smb2cli_conn_server_capabilities(transport->conn);
	if (!(server_capabilities & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_comment(tctx, "Replay of DurableHandleReqV2 with Lease "
			      "on Single Channel\n");
	smb2_util_unlink(tree, fname);
	status = torture_smb2_testdir(tree, BASEDIR, &_h1);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h1);
	CHECK_VAL(break_info.count, 0);

	lease_key = random();

	smb2_lease_create(&io1, &ls1, false /* dir */, fname,
			lease_key, smb2_util_lease_state("RH"));
	io1.in.durable_open = false;
	io1.in.durable_open_v2 = true;
	io1.in.persistent_open = false;
	io1.in.create_guid = create_guid;
	io1.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	ref1 = io1;
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, false);
	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io1.out.lease_response.lease_key.data[0], lease_key);
	CHECK_VAL(io1.out.lease_response.lease_key.data[1], ~lease_key);
	if (share_is_so) {
		CHECK_VAL(io1.out.lease_response.lease_state,
			  smb2_util_lease_state("R"));
		CHECK_VAL(io1.out.durable_open_v2, false);
		CHECK_VAL(io1.out.timeout, 0);
	} else {
		CHECK_VAL(io1.out.lease_response.lease_state,
			  smb2_util_lease_state("RH"));
		CHECK_VAL(io1.out.durable_open_v2, true);
		CHECK_VAL(io1.out.timeout, 300*1000);
	}

	/*
	 * Upgrade the lease to RWH
	 */
	smb2_lease_create(&io2, &ls2, false /* dir */, fname,
			lease_key, smb2_util_lease_state("RHW"));
	io2.in.durable_open = false;
	io2.in.durable_open_v2 = true;
	io2.in.persistent_open = false;
	io2.in.create_guid = GUID_random(); /* new guid... */
	io2.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io2.out.file.handle;
	h2 = &_h2;

	/*
	 * Replay Durable V2 Create on single channel.
	 * We get the io from open #1 but with the
	 * upgraded lease.
	 */

	/* adapt expected lease in response */
	if (!share_is_so) {
		ref1.out.lease_response.lease_state =
			smb2_util_lease_state("RHW");
	}

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io1);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATE_OUT(&io1, &ref1);
	CHECK_VAL(break_info.count, 0);

done:
	smb2cli_session_stop_replay(tree->session->smbXcli);

	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}
	if (h2 != NULL) {
		smb2_util_close(tree, *h2);
	}
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test durability v2 create replay detection on single channel.
 * Variant with leases instead of oplocks, where the
 * replay does not specify the original lease level but
 * just a "R" lease. This still gives the upgraded lease
 * level in the reply.
 * - open a file with a rh lease
 * - upgrade to a rwh lease with a second create
 * - replay the first create.
 *   ==> it gets back the upgraded lease level
 */
static bool test_replay_dhv2_lease2(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io1, io2, ref1;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\replay2_lease2.dat";
	struct smb2_transport *transport = tree->session->transport;
	uint32_t share_capabilities;
	bool share_is_so;
	uint32_t server_capabilities;
	struct smb2_lease ls1, ls2;
	uint64_t lease_key;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	server_capabilities = smb2cli_conn_server_capabilities(transport->conn);
	if (!(server_capabilities & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_comment(tctx, "Replay of DurableHandleReqV2 with Lease "
			      "on Single Channel\n");
	smb2_util_unlink(tree, fname);
	status = torture_smb2_testdir(tree, BASEDIR, &_h1);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h1);
	CHECK_VAL(break_info.count, 0);

	lease_key = random();

	smb2_lease_create(&io1, &ls1, false /* dir */, fname,
			lease_key, smb2_util_lease_state("RH"));
	io1.in.durable_open = false;
	io1.in.durable_open_v2 = true;
	io1.in.persistent_open = false;
	io1.in.create_guid = create_guid;
	io1.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, false);
	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io1.out.lease_response.lease_key.data[0], lease_key);
	CHECK_VAL(io1.out.lease_response.lease_key.data[1], ~lease_key);
	if (share_is_so) {
		CHECK_VAL(io1.out.lease_response.lease_state,
			  smb2_util_lease_state("R"));
		CHECK_VAL(io1.out.durable_open_v2, false);
		CHECK_VAL(io1.out.timeout, 0);
	} else {
		CHECK_VAL(io1.out.lease_response.lease_state,
			  smb2_util_lease_state("RH"));
		CHECK_VAL(io1.out.durable_open_v2, true);
		CHECK_VAL(io1.out.timeout, 300*1000);
	}
	ref1 = io1;
	_h1 = io1.out.file.handle;
	h1 = &_h1;

	/*
	 * Upgrade the lease to RWH
	 */
	smb2_lease_create(&io2, &ls2, false /* dir */, fname,
			lease_key, smb2_util_lease_state("RHW"));
	io2.in.durable_open = false;
	io2.in.durable_open_v2 = true;
	io2.in.persistent_open = false;
	io2.in.create_guid = GUID_random(); /* new guid... */
	io2.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io2.out.file.handle;
	h2 = &_h2;

	/*
	 * Replay Durable V2 Create on single channel.
	 * Changing the requested lease level to "R"
	 * does not change the response:
	 * We get the reply from open #1 but with the
	 * upgraded lease.
	 */

	/* adapt the expected response */
	if (!share_is_so) {
		ref1.out.lease_response.lease_state =
					smb2_util_lease_state("RHW");
	}

	smb2_lease_create(&io1, &ls1, false /* dir */, fname,
			lease_key, smb2_util_lease_state("R"));
	io1.in.durable_open = false;
	io1.in.durable_open_v2 = true;
	io1.in.persistent_open = false;
	io1.in.create_guid = create_guid;
	io1.in.timeout = UINT32_MAX;

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io1);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATE_OUT(&io1, &ref1);
	CHECK_VAL(break_info.count, 0);

done:
	smb2cli_session_stop_replay(tree->session->smbXcli);

	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}
	if (h2 != NULL) {
		smb2_util_close(tree, *h2);
	}
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test durability v2 create replay detection on single channel.
 * create with a lease, and replay with a different lease key
 */
static bool test_replay_dhv2_lease3(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io1, io2;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\replay2_lease2.dat";
	struct smb2_transport *transport = tree->session->transport;
	uint32_t share_capabilities;
	bool share_is_so;
	uint32_t server_capabilities;
	struct smb2_lease ls1, ls2;
	uint64_t lease_key;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	server_capabilities = smb2cli_conn_server_capabilities(transport->conn);
	if (!(server_capabilities & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_comment(tctx, "Replay of DurableHandleReqV2 with Lease "
			      "on Single Channel\n");
	smb2_util_unlink(tree, fname);
	status = torture_smb2_testdir(tree, BASEDIR, &_h1);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h1);
	CHECK_VAL(break_info.count, 0);

	lease_key = random();

	smb2_lease_create(&io1, &ls1, false /* dir */, fname,
			lease_key, smb2_util_lease_state("RH"));
	io1.in.durable_open = false;
	io1.in.durable_open_v2 = true;
	io1.in.persistent_open = false;
	io1.in.create_guid = create_guid;
	io1.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, false);
	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io1.out.lease_response.lease_key.data[0], lease_key);
	CHECK_VAL(io1.out.lease_response.lease_key.data[1], ~lease_key);
	if (share_is_so) {
		CHECK_VAL(io1.out.lease_response.lease_state,
			  smb2_util_lease_state("R"));
		CHECK_VAL(io1.out.durable_open_v2, false);
		CHECK_VAL(io1.out.timeout, 0);
	} else {
		CHECK_VAL(io1.out.lease_response.lease_state,
			  smb2_util_lease_state("RH"));
		CHECK_VAL(io1.out.durable_open_v2, true);
		CHECK_VAL(io1.out.timeout, 300*1000);
	}
	_h1 = io1.out.file.handle;
	h1 = &_h1;

	/*
	 * Upgrade the lease to RWH
	 */
	smb2_lease_create(&io2, &ls2, false /* dir */, fname,
			lease_key, smb2_util_lease_state("RHW"));
	io2.in.durable_open = false;
	io2.in.durable_open_v2 = true;
	io2.in.persistent_open = false;
	io2.in.create_guid = GUID_random(); /* new guid... */
	io2.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io2.out.file.handle;
	h2 = &_h2;

	/*
	 * Replay Durable V2 Create on single channel.
	 * use a different lease key.
	 */

	smb2_lease_create(&io1, &ls1, false /* dir */, fname,
			random() /* lease key */,
			smb2_util_lease_state("RH"));
	io1.in.durable_open = false;
	io1.in.durable_open_v2 = true;
	io1.in.persistent_open = false;
	io1.in.create_guid = create_guid;
	io1.in.timeout = UINT32_MAX;

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io1);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

done:
	smb2cli_session_stop_replay(tree->session->smbXcli);

	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}
	if (h2 != NULL) {
		smb2_util_close(tree, *h2);
	}
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test durability v2 create replay detection on single channel.
 * Do the original create with a lease, and do the replay
 * with an oplock.
 */
static bool test_replay_dhv2_lease_oplock(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io1, io2, ref1;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\replay2_lease1.dat";
	struct smb2_transport *transport = tree->session->transport;
	uint32_t share_capabilities;
	bool share_is_so;
	uint32_t server_capabilities;
	struct smb2_lease ls1, ls2;
	uint64_t lease_key;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	server_capabilities = smb2cli_conn_server_capabilities(transport->conn);
	if (!(server_capabilities & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_comment(tctx, "Replay of DurableHandleReqV2 with Lease "
			      "on Single Channel\n");
	smb2_util_unlink(tree, fname);
	status = torture_smb2_testdir(tree, BASEDIR, &_h1);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h1);
	CHECK_VAL(break_info.count, 0);

	lease_key = random();

	smb2_lease_create(&io1, &ls1, false /* dir */, fname,
			lease_key, smb2_util_lease_state("RH"));
	io1.in.durable_open = false;
	io1.in.durable_open_v2 = true;
	io1.in.persistent_open = false;
	io1.in.create_guid = create_guid;
	io1.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	ref1 = io1;
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, false);
	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io1.out.lease_response.lease_key.data[0], lease_key);
	CHECK_VAL(io1.out.lease_response.lease_key.data[1], ~lease_key);
	if (share_is_so) {
		CHECK_VAL(io1.out.lease_response.lease_state,
			  smb2_util_lease_state("R"));
		CHECK_VAL(io1.out.durable_open_v2, false);
		CHECK_VAL(io1.out.timeout, 0);
	} else {
		CHECK_VAL(io1.out.lease_response.lease_state,
			  smb2_util_lease_state("RH"));
		CHECK_VAL(io1.out.durable_open_v2, true);
		CHECK_VAL(io1.out.timeout, 300*1000);
	}

	/*
	 * Upgrade the lease to RWH
	 */
	smb2_lease_create(&io2, &ls2, false /* dir */, fname,
			lease_key, smb2_util_lease_state("RHW"));
	io2.in.durable_open = false;
	io2.in.durable_open_v2 = true;
	io2.in.persistent_open = false;
	io2.in.create_guid = GUID_random(); /* new guid... */
	io2.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io2.out.file.handle;
	h2 = &_h2;

	/*
	 * Replay Durable V2 Create on single channel.
	 * We get the io from open #1 but with the
	 * upgraded lease.
	 */

	smb2_oplock_create_share(&io2, fname,
			smb2_util_share_access(""),
			smb2_util_oplock_level("b"));
	io2.in.durable_open = false;
	io2.in.durable_open_v2 = true;
	io2.in.persistent_open = false;
	io2.in.create_guid = create_guid;
	io2.in.timeout = UINT32_MAX;

	/* adapt expected lease in response */
	if (!share_is_so) {
		ref1.out.lease_response.lease_state =
			smb2_util_lease_state("RHW");
	}

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io1);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATE_OUT(&io1, &ref1);
	CHECK_VAL(break_info.count, 0);

done:
	smb2cli_session_stop_replay(tree->session->smbXcli);

	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}
	if (h2 != NULL) {
		smb2_util_close(tree, *h2);
	}
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

static bool test_channel_sequence_table(struct torture_context *tctx,
					struct smb2_tree *tree,
					bool do_replay,
					uint16_t opcode)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle handle;
	struct smb2_handle *phandle = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\channel_sequence.dat";
	uint16_t csn = 0;
	uint16_t limit = UINT16_MAX - 0x7fff;
	int i;
	struct {
		uint16_t csn;
		bool csn_rand_low;
		bool csn_rand_high;
		NTSTATUS expected_status;
	} tests[] = {
		{
			.csn			= 0,
			.expected_status	= NT_STATUS_OK,
		},{
			.csn			= 0x7fff + 1,
			.expected_status	= NT_STATUS_FILE_NOT_AVAILABLE,
		},{
			.csn			= 0x7fff + 2,
			.expected_status	= NT_STATUS_FILE_NOT_AVAILABLE,
		},{
			.csn			= -1,
			.csn_rand_high		= true,
			.expected_status	= NT_STATUS_FILE_NOT_AVAILABLE,
		},{
			.csn			= 0xffff,
			.expected_status	= NT_STATUS_FILE_NOT_AVAILABLE,
		},{
			.csn			= 0x7fff,
			.expected_status	= NT_STATUS_OK,
		},{
			.csn			= 0x7ffe,
			.expected_status	= NT_STATUS_FILE_NOT_AVAILABLE,
		},{
			.csn			= 0,
			.expected_status	= NT_STATUS_FILE_NOT_AVAILABLE,
		},{
			.csn			= -1,
			.csn_rand_low		= true,
			.expected_status	= NT_STATUS_FILE_NOT_AVAILABLE,
		},{
			.csn			= 0x7fff + 1,
			.expected_status	= NT_STATUS_OK,
		},{
			.csn			= 0xffff,
			.expected_status	= NT_STATUS_OK,
		},{
			.csn			= 0,
			.expected_status	= NT_STATUS_OK,
		},{
			.csn			= 1,
			.expected_status	= NT_STATUS_OK,
		},{
			.csn			= 0,
			.expected_status	= NT_STATUS_FILE_NOT_AVAILABLE,
		},{
			.csn			= 1,
			.expected_status	= NT_STATUS_OK,
		},{
			.csn			= 0xffff,
			.expected_status	= NT_STATUS_FILE_NOT_AVAILABLE,
		}
	};

	smb2cli_session_reset_channel_sequence(tree->session->smbXcli, 0);

	csn = smb2cli_session_current_channel_sequence(tree->session->smbXcli);
	torture_comment(tctx, "Testing create with channel sequence number: 0x%04x\n", csn);

	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	torture_assert_ntstatus_ok_goto(tctx,
		smb2_create(tree, mem_ctx, &io),
		ret, done, "failed to call smb2_create");

	handle = io.out.file.handle;
	phandle = &handle;

	for (i=0; i <ARRAY_SIZE(tests); i++) {

		const char *opstr = "";
		union smb_fileinfo qfinfo;

		csn = tests[i].csn;

		if (tests[i].csn_rand_low) {
			csn = rand() % limit;
		} else if (tests[i].csn_rand_high) {
			csn = rand() % limit + 0x7fff;
		}

		switch (opcode) {
		case SMB2_OP_WRITE:
			opstr = "write";
			break;
		case SMB2_OP_IOCTL:
			opstr = "ioctl";
			break;
		case SMB2_OP_SETINFO:
			opstr = "setinfo";
			break;
		default:
			break;
		}

		smb2cli_session_reset_channel_sequence(tree->session->smbXcli, csn);
		csn = smb2cli_session_current_channel_sequence(tree->session->smbXcli);

		torture_comment(tctx, "Testing %s (replay: %s) with CSN 0x%04x, expecting: %s\n",
			opstr, do_replay ? "true" : "false", csn,
			nt_errstr(tests[i].expected_status));

		if (do_replay) {
			smb2cli_session_start_replay(tree->session->smbXcli);
		}

		switch (opcode) {
		case SMB2_OP_WRITE: {
			DATA_BLOB blob = data_blob_talloc(tctx, NULL, 255);

			generate_random_buffer(blob.data, blob.length);

			status = smb2_util_write(tree, handle, blob.data, 0, blob.length);
			if (NT_STATUS_IS_OK(status)) {
				struct smb2_read rd;

				rd = (struct smb2_read) {
					.in.file.handle = handle,
					.in.length = blob.length,
					.in.offset = 0
				};

				torture_assert_ntstatus_ok_goto(tctx,
					smb2_read(tree, tree, &rd),
					ret, done, "failed to read after write");

				torture_assert_data_blob_equal(tctx,
					rd.out.data, blob,
					"read/write mismatch");
			}
			break;
		}
		case SMB2_OP_IOCTL: {
			union smb_ioctl ioctl;
			ioctl = (union smb_ioctl) {
				.smb2.level = RAW_IOCTL_SMB2,
				.smb2.in.file.handle = handle,
				.smb2.in.function = FSCTL_CREATE_OR_GET_OBJECT_ID,
				.smb2.in.max_output_response = 64,
				.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL
			};
			status = smb2_ioctl(tree, mem_ctx, &ioctl.smb2);
			break;
		}
		case SMB2_OP_SETINFO: {
			union smb_setfileinfo sfinfo;
			ZERO_STRUCT(sfinfo);
			sfinfo.generic.level = RAW_SFILEINFO_POSITION_INFORMATION;
			sfinfo.generic.in.file.handle = handle;
			sfinfo.position_information.in.position = 0x1000;
			status = smb2_setinfo_file(tree, &sfinfo);
			break;
		}
		default:
			break;
		}

		qfinfo = (union smb_fileinfo) {
			.generic.level = RAW_FILEINFO_POSITION_INFORMATION,
			.generic.in.file.handle = handle
		};

		torture_assert_ntstatus_ok_goto(tctx,
			smb2_getinfo_file(tree, mem_ctx, &qfinfo),
			ret, done, "failed to read after write");

		if (do_replay) {
			smb2cli_session_stop_replay(tree->session->smbXcli);
		}

		torture_assert_ntstatus_equal_goto(tctx,
			status, tests[i].expected_status,
			ret, done, "got unexpected failure code");

	}
done:
	if (phandle != NULL) {
		smb2_util_close(tree, *phandle);
	}

	smb2_util_unlink(tree, fname);

	return ret;
}

static bool test_channel_sequence(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	bool ret = true;
	const char *fname = BASEDIR "\\channel_sequence.dat";
	struct smb2_transport *transport1 = tree->session->transport;
	struct smb2_handle handle;
	uint16_t opcodes[] = { SMB2_OP_WRITE, SMB2_OP_IOCTL, SMB2_OP_SETINFO };
	int i;

	if (smbXcli_conn_protocol(transport1->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "Replay tests\n");
	}

	torture_comment(tctx, "Testing channel sequence numbers\n");

	smbXcli_conn_set_force_channel_sequence(transport1->conn, true);

	torture_assert_ntstatus_ok_goto(tctx,
		torture_smb2_testdir(tree, BASEDIR, &handle),
		ret, done, "failed to setup test directory");

	smb2_util_close(tree, handle);
	smb2_util_unlink(tree, fname);

	for (i=0; i <ARRAY_SIZE(opcodes); i++) {
		torture_assert(tctx,
			test_channel_sequence_table(tctx, tree, false, opcodes[i]),
			"failed to test CSN without replay flag");
		torture_assert(tctx,
			test_channel_sequence_table(tctx, tree, true, opcodes[i]),
			"failed to test CSN with replay flag");
	}

done:

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test Durability V2 Create Replay Detection on Multi Channel
 */
static bool test_replay3(struct torture_context *tctx, struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\replay3.dat";
	struct smb2_tree *tree2 = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smb2_transport *transport2 = NULL;
	struct smb2_session *session1_1 = tree1->session;
	struct smb2_session *session1_2 = NULL;
	uint32_t share_capabilities;
	bool share_is_so;
	uint32_t server_capabilities;

	if (smbXcli_conn_protocol(transport1->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "Replay tests\n");
	}

	server_capabilities = smb2cli_conn_server_capabilities(
					tree1->session->transport->conn);
	if (!(server_capabilities & SMB2_CAP_MULTI_CHANNEL)) {
		torture_skip(tctx,
			     "Server does not support multi-channel.");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree1->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	transport1->oplock.handler = torture_oplock_ack_handler;
	transport1->oplock.private_data = tree1;

	torture_comment(tctx, "Replay of DurableHandleReqV2 on Multi "
			      "Channel\n");
	status = torture_smb2_testdir(tree1, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, _h);
	smb2_util_unlink(tree1, fname);
	CHECK_VAL(break_info.count, 0);

	/*
	 * use the 1st channel, 1st session
	 */
	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access(""),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	tree1->session = session1_1;
	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	if (share_is_so) {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("s"));
		CHECK_VAL(io.out.durable_open_v2, false);
		CHECK_VAL(io.out.timeout, 0);
	} else {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
		CHECK_VAL(io.out.durable_open_v2, true);
		CHECK_VAL(io.out.timeout, 300*1000);
	}
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(break_info.count, 0);

	status = smb2_connect(tctx,
			host,
			lpcfg_smb_ports(tctx->lp_ctx),
			share,
			lpcfg_resolve_context(tctx->lp_ctx),
			popt_get_cmdline_credentials(),
			&tree2,
			tctx->ev,
			&transport1->options,
			lpcfg_socket_options(tctx->lp_ctx),
			lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"smb2_connect failed");
	transport2 = tree2->session->transport;

	transport2->oplock.handler = torture_oplock_ack_handler;
	transport2->oplock.private_data = tree2;

	/*
	 * Now bind the 1st session to 2nd transport channel
	 */
	session1_2 = smb2_session_channel(transport2,
			lpcfg_gensec_settings(tctx, tctx->lp_ctx),
			tree2, session1_1);
	torture_assert(tctx, session1_2 != NULL, "smb2_session_channel failed");

	status = smb2_session_setup_spnego(session1_2,
			popt_get_cmdline_credentials(),
			0 /* previous_session_id */);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * use the 2nd channel, 1st session
	 */
	tree1->session = session1_2;
	smb2cli_session_start_replay(tree1->session->smbXcli);
	status = smb2_create(tree1, mem_ctx, &io);
	smb2cli_session_stop_replay(tree1->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	if (share_is_so) {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("s"));
		CHECK_VAL(io.out.durable_open_v2, false);
		CHECK_VAL(io.out.timeout, 0);
	} else {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
		CHECK_VAL(io.out.durable_open_v2, true);
		CHECK_VAL(io.out.timeout, 300*1000);
	}
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(break_info.count, 0);

	tree1->session = session1_1;
	smb2_util_close(tree1, *h);
	h = NULL;

done:
	talloc_free(tree2);
	tree1->session = session1_1;

	if (h != NULL) {
		smb2_util_close(tree1, *h);
	}

	smb2_util_unlink(tree1, fname);
	smb2_deltree(tree1, BASEDIR);

	talloc_free(tree1);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test Multichannel IO Ordering using ChannelSequence/Channel Epoch number
 */
static bool test_replay4(struct torture_context *tctx, struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	uint8_t buf[64];
	struct smb2_read rd;
	union smb_setfileinfo sfinfo;
	bool ret = true;
	const char *fname = BASEDIR "\\replay4.dat";
	struct smb2_tree *tree2 = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smb2_transport *transport2 = NULL;
	struct smb2_session *session1_1 = tree1->session;
	struct smb2_session *session1_2 = NULL;
	uint16_t curr_cs;
	uint32_t share_capabilities;
	bool share_is_so;
	uint32_t server_capabilities;

	if (smbXcli_conn_protocol(transport1->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "Replay tests\n");
	}

	server_capabilities = smb2cli_conn_server_capabilities(
					tree1->session->transport->conn);
	if (!(server_capabilities & SMB2_CAP_MULTI_CHANNEL)) {
		torture_skip(tctx,
			     "Server does not support multi-channel.");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree1->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	transport1->oplock.handler = torture_oplock_ack_handler;
	transport1->oplock.private_data = tree1;

	torture_comment(tctx, "IO Ordering for Multi Channel\n");
	status = torture_smb2_testdir(tree1, BASEDIR, &_h1);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, _h1);
	smb2_util_unlink(tree1, fname);
	CHECK_VAL(break_info.count, 0);

	/*
	 * use the 1st channel, 1st session
	 */

	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access(""),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	tree1->session = session1_1;
	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	if (share_is_so) {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("s"));
		CHECK_VAL(io.out.durable_open_v2, false);
		CHECK_VAL(io.out.timeout, 0);
	} else {
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
		CHECK_VAL(io.out.durable_open_v2, true);
		CHECK_VAL(io.out.timeout, 300*1000);
	}
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(break_info.count, 0);

	status = smb2_util_write(tree1, *h1, buf, 0, ARRAY_SIZE(buf));
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * Increment ChannelSequence so that server thinks that there's a
	 * Channel Failure
	 */
	smb2cli_session_increment_channel_sequence(tree1->session->smbXcli);

	/*
	 * Perform a Read with incremented ChannelSequence
	 */
	rd = (struct smb2_read) {
		.in.file.handle = *h1,
		.in.length = sizeof(buf),
		.in.offset = 0
	};
	status = smb2_read(tree1, tree1, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * Performing a Write with Stale ChannelSequence is not allowed by
	 * server
	 */
	curr_cs = smb2cli_session_reset_channel_sequence(
						tree1->session->smbXcli, 0);
	status = smb2_util_write(tree1, *h1, buf, 0, ARRAY_SIZE(buf));
	CHECK_STATUS(status, NT_STATUS_FILE_NOT_AVAILABLE);

	/*
	 * Performing a Write Replay with Stale ChannelSequence is not allowed
	 * by server
	 */
	smb2cli_session_start_replay(tree1->session->smbXcli);
	smb2cli_session_reset_channel_sequence(tree1->session->smbXcli, 0);
	status = smb2_util_write(tree1, *h1, buf, 0, ARRAY_SIZE(buf));
	smb2cli_session_stop_replay(tree1->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_FILE_NOT_AVAILABLE);

	/*
	 * Performing a SetInfo with stale ChannelSequence is not allowed by
	 * server
	 */
	ZERO_STRUCT(sfinfo);
	sfinfo.generic.level = RAW_SFILEINFO_POSITION_INFORMATION;
	sfinfo.generic.in.file.handle = *h1;
	sfinfo.position_information.in.position = 0x1000;
	status = smb2_setinfo_file(tree1, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_FILE_NOT_AVAILABLE);

	/*
	 * Performing a Read with stale ChannelSequence is allowed
	 */
	rd = (struct smb2_read) {
		.in.file.handle = *h1,
		.in.length = ARRAY_SIZE(buf),
		.in.offset = 0
	};
	status = smb2_read(tree1, tree1, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_connect(tctx,
			host,
			lpcfg_smb_ports(tctx->lp_ctx),
			share,
			lpcfg_resolve_context(tctx->lp_ctx),
			popt_get_cmdline_credentials(),
			&tree2,
			tctx->ev,
			&transport1->options,
			lpcfg_socket_options(tctx->lp_ctx),
			lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"smb2_connect failed");
	transport2 = tree2->session->transport;

	transport2->oplock.handler = torture_oplock_ack_handler;
	transport2->oplock.private_data = tree2;

	/*
	 * Now bind the 1st session to 2nd transport channel
	 */
	session1_2 = smb2_session_channel(transport2,
			lpcfg_gensec_settings(tctx, tctx->lp_ctx),
			tree2, session1_1);
	torture_assert(tctx, session1_2 != NULL, "smb2_session_channel failed");

	status = smb2_session_setup_spnego(session1_2,
			popt_get_cmdline_credentials(),
			0 /* previous_session_id */);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * use the 2nd channel, 1st session
	 */
	tree1->session = session1_2;

	/*
	 * Write Replay with Correct ChannelSequence is allowed by the server
	 */
	smb2cli_session_start_replay(tree1->session->smbXcli);
	smb2cli_session_reset_channel_sequence(tree1->session->smbXcli,
					       curr_cs);
	status = smb2_util_write(tree1, *h1, buf, 0, ARRAY_SIZE(buf));
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2cli_session_stop_replay(tree1->session->smbXcli);

	/*
	 * See what happens if we change the Buffer and perform a Write Replay.
	 * This is to show that Write Replay does not really care about the data
	 */
	memset(buf, 'r', ARRAY_SIZE(buf));
	smb2cli_session_start_replay(tree1->session->smbXcli);
	status = smb2_util_write(tree1, *h1, buf, 0, ARRAY_SIZE(buf));
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2cli_session_stop_replay(tree1->session->smbXcli);

	/*
	 * Read back from File to verify what was written
	 */
	rd = (struct smb2_read) {
		.in.file.handle = *h1,
		.in.length = ARRAY_SIZE(buf),
		.in.offset = 0
	};
	status = smb2_read(tree1, tree1, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);

	if ((rd.out.data.length != ARRAY_SIZE(buf)) ||
			memcmp(rd.out.data.data, buf, ARRAY_SIZE(buf))) {
		torture_comment(tctx, "Write Replay Data Mismatch\n");
	}

	tree1->session = session1_1;
	smb2_util_close(tree1, *h1);
	h1 = NULL;

	if (share_is_so) {
		CHECK_VAL(break_info.count, 1);
	} else {
		CHECK_VAL(break_info.count, 0);
	}
done:
	talloc_free(tree2);
	tree1->session = session1_1;

	if (h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}

	smb2_util_unlink(tree1, fname);
	smb2_deltree(tree1, BASEDIR);

	talloc_free(tree1);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test Durability V2 Persistent Create Replay on a Single Channel
 */
static bool test_replay5(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	uint32_t share_capabilities;
	bool share_is_ca;
	bool share_is_so;
	uint32_t server_capabilities;
	const char *fname = BASEDIR "\\replay5.dat";
	struct smb2_transport *transport = tree->session->transport;
	struct smbcli_options options = tree->session->transport->options;
	uint8_t expect_oplock = smb2_util_oplock_level("b");
	NTSTATUS expect_status = NT_STATUS_DUPLICATE_OBJECTID;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				"Replay tests\n");
	}

	server_capabilities = smb2cli_conn_server_capabilities(
					tree->session->transport->conn);
	if (!(server_capabilities & SMB2_CAP_PERSISTENT_HANDLES)) {
		torture_skip(tctx,
			     "Server does not support persistent handles.");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);

	share_is_ca = share_capabilities & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY;
	if (!share_is_ca) {
		torture_skip(tctx, "Share is not continuously available.");
	}

	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;
	if (share_is_so) {
		expect_oplock = smb2_util_oplock_level("s");
		expect_status = NT_STATUS_FILE_NOT_AVAILABLE;
	}

	ZERO_STRUCT(break_info);
	break_info.tctx = tctx;
	transport->oplock.handler = torture_oplock_ack_handler;
	transport->oplock.private_data = tree;

	torture_comment(tctx, "Replay of Persistent DurableHandleReqV2 on Single "
			"Channel\n");
	status = torture_smb2_testdir(tree, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h);
	smb2_util_unlink(tree, fname);
	CHECK_VAL(break_info.count, 0);

	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = true;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, expect_oplock);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, true);
	CHECK_VAL(io.out.timeout, 300*1000);
	CHECK_VAL(break_info.count, 0);

	/* disconnect, leaving the durable open */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/* a re-open of a persistent handle causes an error */
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, expect_status);

	/* SMB2_FLAGS_REPLAY_OPERATION must be set to open the Persistent Handle */
	smb2cli_session_start_replay(tree->session->smbXcli);
	smb2cli_session_increment_channel_sequence(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.persistent_open, true);
	CHECK_VAL(io.out.oplock_level, expect_oplock);
	_h = io.out.file.handle;
	h = &_h;

	smb2_util_close(tree, *h);
	h = NULL;
done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}


/**
 * Test Error Codes when a DurableHandleReqV2 with matching CreateGuid is
 * re-sent with or without SMB2_FLAGS_REPLAY_OPERATION
 */
static bool test_replay6(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io, ref1;
	union smb_fileinfo qfinfo;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	const char *fname = BASEDIR "\\replay6.dat";
	struct smb2_transport *transport = tree->session->transport;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	torture_reset_break_info(tctx, &break_info);
	tree->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_comment(tctx, "Error Codes for DurableHandleReqV2 Replay\n");
	smb2_util_unlink(tree, fname);
	status = torture_smb2_testdir(tree, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, _h);
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	torture_reset_break_info(tctx, &break_info);

	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	ref1 = io;
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);

	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATE_OUT(&io, &ref1);
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	torture_reset_break_info(tctx, &break_info);

	qfinfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_POSITION_INFORMATION,
		.generic.in.file.handle = *h
	};
	torture_comment(tctx, "Trying getinfo\n");
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0);

	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	torture_assert_u64_not_equal_goto(tctx,
		io.out.file.handle.data[0],
		ref1.out.file.handle.data[0],
		ret, done, "data 0");
	torture_assert_u64_not_equal_goto(tctx,
		io.out.file.handle.data[1],
		ref1.out.file.handle.data[1],
		ret, done, "data 1");
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.level, smb2_util_oplock_level("s"));
	torture_reset_break_info(tctx, &break_info);

	/*
	 * Resend the matching Durable V2 Create without
	 * SMB2_FLAGS_REPLAY_OPERATION. This triggers an oplock break and still
	 * gets NT_STATUS_DUPLICATE_OBJECTID
	 */
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_DUPLICATE_OBJECTID);
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);
	torture_reset_break_info(tctx, &break_info);

	/*
	 * According to MS-SMB2 3.3.5.9.10 if Durable V2 Create is replayed and
	 * FileAttributes or CreateDisposition do not match the earlier Create
	 * request the Server fails request with
	 * NT_STATUS_INVALID_PARAMETER. But through this test we see that server
	 * does not really care about changed FileAttributes or
	 * CreateDisposition.
	 */
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	torture_assert_u64_not_equal_goto(tctx,
		io.out.file.handle.data[0],
		ref1.out.file.handle.data[0],
		ret, done, "data 0");
	torture_assert_u64_not_equal_goto(tctx,
		io.out.file.handle.data[1],
		ref1.out.file.handle.data[1],
		ret, done, "data 1");
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

static bool test_replay7(struct torture_context *tctx, struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_transport *transport = tree->session->transport;
	NTSTATUS status;
	struct smb2_handle _dh;
	struct smb2_handle *dh = NULL;
	struct smb2_notify notify;
	struct smb2_request *req;
	union smb_fileinfo qfinfo;
	bool ret = false;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

	torture_comment(tctx, "Notify across increment/decrement of csn\n");

	smbXcli_conn_set_force_channel_sequence(transport->conn, true);

	status = torture_smb2_testdir(tree, BASEDIR, &_dh);
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = &_dh;

	notify.in.recursive		= 0x0000;
	notify.in.buffer_size	= 0xffff;
	notify.in.file.handle	= _dh;
	notify.in.completion_filter	= FILE_NOTIFY_CHANGE_FILE_NAME;
	notify.in.unknown		= 0x00000000;

	/*
	 * This posts a long-running request with csn==0 to "dh". Now
	 * op->request_count==1 in smb2_server.c.
	 */
	smb2cli_session_reset_channel_sequence(tree->session->smbXcli, 0);
	req = smb2_notify_send(tree, &notify);

	qfinfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_POSITION_INFORMATION,
		.generic.in.file.handle = _dh
	};

	/*
	 * This sequence of 2 dummy requests moves
	 * op->request_count==1 to op->pre_request_count. The numbers
	 * used avoid int16 overflow.
	 */

	smb2cli_session_reset_channel_sequence(tree->session->smbXcli, 30000);
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2cli_session_reset_channel_sequence(tree->session->smbXcli, 60000);
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * This final request turns the op->global->channel_sequence
	 * to the same as we had when sending the notify above. The
	 * notify's request count has in the meantime moved to
	 * op->pre_request_count.
	 */

	smb2cli_session_reset_channel_sequence(tree->session->smbXcli, 0);
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * At this point op->request_count==0.
	 *
	 * The next cancel makes us reply to the notify. Because the
	 * csn we currently use is the same as we used when sending
	 * the notify, smbd thinks it must decrement op->request_count
	 * and not op->pre_request_count.
	 */

	status = smb2_cancel(req);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_notify_recv(req, mem_ctx, &notify);
	CHECK_STATUS(status, NT_STATUS_CANCELLED);

	ret = true;

done:
	if (dh != NULL) {
		smb2_util_close(tree, _dh);
	}
	smb2_deltree(tree, BASEDIR);
	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

struct torture_suite *torture_smb2_replay_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
		torture_suite_create(ctx, "replay");

	torture_suite_add_1smb2_test(suite, "replay-commands", test_replay_commands);
	torture_suite_add_1smb2_test(suite, "replay-regular", test_replay_regular);
	torture_suite_add_1smb2_test(suite, "replay-dhv2-oplock1", test_replay_dhv2_oplock1);
	torture_suite_add_1smb2_test(suite, "replay-dhv2-oplock2", test_replay_dhv2_oplock2);
	torture_suite_add_1smb2_test(suite, "replay-dhv2-oplock3", test_replay_dhv2_oplock3);
	torture_suite_add_1smb2_test(suite, "replay-dhv2-oplock-lease", test_replay_dhv2_oplock_lease);
	torture_suite_add_1smb2_test(suite, "replay-dhv2-lease1",  test_replay_dhv2_lease1);
	torture_suite_add_1smb2_test(suite, "replay-dhv2-lease2",  test_replay_dhv2_lease2);
	torture_suite_add_1smb2_test(suite, "replay-dhv2-lease3",  test_replay_dhv2_lease3);
	torture_suite_add_1smb2_test(suite, "replay-dhv2-lease-oplock",  test_replay_dhv2_lease_oplock);
	torture_suite_add_1smb2_test(suite, "channel-sequence", test_channel_sequence);
	torture_suite_add_1smb2_test(suite, "replay3", test_replay3);
	torture_suite_add_1smb2_test(suite, "replay4", test_replay4);
	torture_suite_add_1smb2_test(suite, "replay5", test_replay5);
	torture_suite_add_1smb2_test(suite, "replay6", test_replay6);
	torture_suite_add_1smb2_test(suite, "replay7", test_replay7);

	suite->description = talloc_strdup(suite, "SMB2 REPLAY tests");

	return suite;
}
