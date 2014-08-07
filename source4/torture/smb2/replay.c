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
		CHECK_VAL((__io)->out.alloc_size, 0);			\
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
	} while(0)

#define BASEDIR "replaytestdir"

static struct {
	struct torture_context *tctx;
	struct smb2_handle handle;
	uint8_t level;
	struct smb2_break br;
	int count;
	int failures;
	NTSTATUS failure_status;
} break_info;

static void torture_oplock_ack_callback(struct smb2_request *req)
{
	NTSTATUS status;

	status = smb2_break_recv(req, &break_info.br);
	if (!NT_STATUS_IS_OK(status)) {
		break_info.failures++;
		break_info.failure_status = status;
	}

	return;
}

/**
 * A general oplock break notification handler.  This should be used when a
 * test expects to break from batch or exclusive to a lower level.
 */
static bool torture_oplock_ack_handler(struct smb2_transport *transport,
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
	torture_comment(break_info.tctx,
			"Acking to %s [0x%02X] in oplock handler\n",
			name, level);

	break_info.br.in.file.handle	= *handle;
	break_info.br.in.oplock_level	= level;
	break_info.br.in.reserved	= 0;
	break_info.br.in.reserved2	= 0;

	req = smb2_break_send(tree, &break_info.br);
	req->async.fn = torture_oplock_ack_callback;
	req->async.private_data = NULL;
	return true;
}

/**
 * Test what happens when SMB2_FLAGS_REPLAY_OPERATION is enabled for various
 * commands. We want to verify if the server returns an error code or not.
 */
static bool test_replay1(struct torture_context *tctx, struct smb2_tree *tree)
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
	const char *fname = BASEDIR "\\replay1.dat";
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
		.generic.level = RAW_SFILEINFO_POSITION_INFORMATION,
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
		.smb2.in.max_response_size = 64,
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
 * Test Durablity V2 Create Replay Detection on Single Channel. Also verify that
 * regular creates can not be replayed.
 */
static bool test_replay2(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io, ref1, ref2;
	struct GUID create_guid = GUID_random();
	uint32_t perms = 0;
	bool ret = true;
	const char *fname = BASEDIR "\\replay2.dat";
	struct smb2_transport *transport = tree->session->transport;

	if (smbXcli_conn_protocol(transport->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "replay tests\n");
	}

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
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.timeout, io.in.timeout);

	/*
	 * Replay Durable V2 Create on single channel
	 */
	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, mem_ctx, &io);
	smb2cli_session_stop_replay(tree->session->smbXcli);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATE_OUT(&io, &ref1);
	CHECK_VAL(break_info.count, 0);

	/*
	 * See how server behaves if we change some of the Create params while
	 * Replaying. Change Share Access and Oplock Level. It seems the server
	 * does not care for change in these parameters. The server seems to
	 * only care for the File Name and GUID
	 */
	smb2_oplock_create_share(&io, fname,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level(""));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	/*
	 * The output will just react on the
	 * input, but it doesn't change the oplock
	 * or share access values on the existing open
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
	 * This is a normal open, which triggers an oplock
	 * break and still gets NT_STATUS_SHARING_VIOLATION
	 */
	io = ref1;
	io.in.durable_open_v2 = false;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);
	CHECK_VAL(break_info.count, 1);
	CHECK_HANDLE(&break_info.handle, &ref1.out.file.handle);
	CHECK_VAL(break_info.level, smb2_util_oplock_level("s"));
	ZERO_STRUCT(break_info);

	smb2_util_close(tree, *h);
	h = NULL;
	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(break_info.count, 0);

	/*
	 * No Replay detection for regular Creates
	 */
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

	torture_comment(tctx, "No Replay Detection for regular Create\n");
	/*
	 * Now replay the same create
	 */
	smb2cli_session_start_replay(tree->session->smbXcli);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_COLLISION);
	CHECK_VAL(break_info.count, 0);

done:
	smb2cli_session_stop_replay(tree->session->smbXcli);

	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_deltree(tree, BASEDIR);

	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test Durablity V2 Create Replay Detection on Multi Channel
 */
static bool test_replay3(struct torture_context *tctx, struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = cmdline_credentials;
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

	if (smbXcli_conn_protocol(transport1->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "Replay tests\n");
	}

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
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.timeout, io.in.timeout);
	CHECK_VAL(break_info.count, 0);

	status = smb2_connect(tctx,
			host,
			lpcfg_smb_ports(tctx->lp_ctx),
			share,
			lpcfg_resolve_context(tctx->lp_ctx),
			credentials,
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
			cmdline_credentials,
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
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.timeout, io.in.timeout);
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
	struct cli_credentials *credentials = cmdline_credentials;
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

	if (smbXcli_conn_protocol(transport1->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "SMB 3.X Dialect family required for "
				   "Replay tests\n");
	}

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
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.timeout, io.in.timeout);
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
			credentials,
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
			cmdline_credentials,
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

	CHECK_VAL(break_info.count, 0);
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

struct torture_suite *torture_smb2_replay_init(void)
{
	struct torture_suite *suite =
		torture_suite_create(talloc_autofree_context(), "replay");

	torture_suite_add_1smb2_test(suite, "replay1", test_replay1);
	torture_suite_add_1smb2_test(suite, "replay2", test_replay2);
	torture_suite_add_1smb2_test(suite, "replay3", test_replay3);
	torture_suite_add_1smb2_test(suite, "replay4", test_replay4);

	suite->description = talloc_strdup(suite, "SMB2 REPLAY tests");

	return suite;
}
