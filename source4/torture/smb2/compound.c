/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 compounded requests

   Copyright (C) Stefan Metzmacher 2009

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
#include "tevent.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lease_break_handler.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": Incorrect status %s - should be %s", \
		       nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
		    "(%s) Incorrect value %s=%d - should be %d\n", \
		    __location__, #v, (int)v, (int)correct); \
		ret = false; \
		goto done; \
	}} while (0)

#define CHECK_LEASE(__io, __state, __oplevel, __key, __flags)		\
	do {								\
		CHECK_VAL((__io)->out.lease_response.lease_version, 1); \
		if (__oplevel) {					\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[0], (__key)); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[1], ~(__key)); \
			CHECK_VAL((__io)->out.lease_response.lease_state, smb2_util_lease_state(__state)); \
		} else {						\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_NONE); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[0], 0); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[1], 0); \
			CHECK_VAL((__io)->out.lease_response.lease_state, 0); \
		}							\
									\
		CHECK_VAL((__io)->out.lease_response.lease_flags, (__flags));	\
		CHECK_VAL((__io)->out.lease_response.lease_duration, 0); \
		CHECK_VAL((__io)->out.lease_response.lease_epoch, 0); \
	} while(0)

#define CHECK_LEASE_V2(__io, __state, __oplevel, __key, __flags, __parent, __epoch) \
	do {								\
		CHECK_VAL((__io)->out.lease_response_v2.lease_version, 2); \
		if (__oplevel) {					\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[0], (__key)); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[1], ~(__key)); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_state, smb2_util_lease_state(__state)); \
		} else {						\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_NONE); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[0], 0); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[1], 0); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_state, 0); \
		}							\
									\
		CHECK_VAL((__io)->out.lease_response_v2.lease_flags, __flags); \
		if (__flags & SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET) { \
			CHECK_VAL((__io)->out.lease_response_v2.parent_lease_key.data[0], (__parent)); \
			CHECK_VAL((__io)->out.lease_response_v2.parent_lease_key.data[1], ~(__parent)); \
		} \
		CHECK_VAL((__io)->out.lease_response_v2.lease_duration, 0); \
		CHECK_VAL((__io)->out.lease_response_v2.lease_epoch, (__epoch)); \
	} while(0)

#define WAIT_FOR_ASYNC_RESPONSE(req) \
	while (!req->cancel.can_cancel && req->state <= SMB2_REQUEST_RECV) { \
		if (tevent_loop_once(tctx->ev) != 0) { \
			break; \
		} \
	}

static const uint64_t LEASE1 = 0xBADC0FFEE0DDF00Dull;
static const uint64_t LEASE2 = 0xDEADBEEFFEEDBEADull;

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

static bool test_compound_break(struct torture_context *tctx,
			         struct smb2_tree *tree)
{
	const char *fname1 = "some-file.pptx";
	NTSTATUS status;
	bool ret = true;
	union smb_open io1;
	struct smb2_create io2;
	struct smb2_getinfo gf;
	struct smb2_request *req[2];
	struct smb2_handle h1;
	struct smb2_handle h;

	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	ZERO_STRUCT(break_info);

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io1.smb2);
	io1.generic.level = RAW_OPEN_SMB2;
	io1.smb2.in.desired_access = (SEC_STD_SYNCHRONIZE|
					SEC_STD_READ_CONTROL|
					SEC_FILE_READ_ATTRIBUTE|
					SEC_FILE_READ_EA|
					SEC_FILE_READ_DATA);
	io1.smb2.in.alloc_size = 0;
	io1.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io1.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
			NTCREATEX_SHARE_ACCESS_WRITE|
			NTCREATEX_SHARE_ACCESS_DELETE;
	io1.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io1.smb2.in.create_options = 0;
	io1.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io1.smb2.in.security_flags = 0;
	io1.smb2.in.fname = fname1;

	torture_comment(tctx, "TEST2: open a file with an batch "
			"oplock (share mode: all)\n");
	io1.smb2.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;

	status = smb2_create(tree, tctx, &(io1.smb2));
	torture_assert_ntstatus_ok(tctx, status, "Error opening the file");

	h1 = io1.smb2.out.file.handle;

	torture_comment(tctx, "TEST2: Opening second time with compound\n");

	ZERO_STRUCT(io2);

	io2.in.desired_access = (SEC_STD_SYNCHRONIZE|
				SEC_FILE_READ_ATTRIBUTE|
				SEC_FILE_READ_EA);
	io2.in.alloc_size = 0;
	io2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
			NTCREATEX_SHARE_ACCESS_WRITE|
			NTCREATEX_SHARE_ACCESS_DELETE;
	io2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io2.in.create_options = 0;
	io2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io2.in.security_flags = 0;
	io2.in.fname = fname1;
	io2.in.oplock_level = 0;

	smb2_transport_compound_start(tree->session->transport, 2);

	req[0] = smb2_create_send(tree, &io2);

	smb2_transport_compound_set_related(tree->session->transport, true);

	h.data[0] = UINT64_MAX;
	h.data[1] = UINT64_MAX;

	ZERO_STRUCT(gf);
	gf.in.file.handle = h;
	gf.in.info_type = SMB2_0_INFO_FILE;
	gf.in.info_class = 0x16;
	gf.in.output_buffer_length = 0x1000;
	gf.in.input_buffer = data_blob_null;

	req[1] = smb2_getinfo_send(tree, &gf);

	status = smb2_create_recv(req[0], tree, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_getinfo_recv(req[1], tree, &gf);
	CHECK_STATUS(status, NT_STATUS_OK);

done:

	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname1);
	return ret;
}

static bool test_compound_related1(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_handle hd;
	struct smb2_create cr;
	NTSTATUS status;
	const char *fname = "compound_related1.dat";
	struct smb2_close cl;
	bool ret = true;
	struct smb2_request *req[2];
	struct smbXcli_tcon *saved_tcon = tree->smbXcli;
	struct smbXcli_session *saved_session = tree->session->smbXcli;

	smb2_transport_credits_ask_num(tree->session->transport, 2);

	smb2_util_unlink(tree, fname);

	smb2_transport_credits_ask_num(tree->session->transport, 1);

	ZERO_STRUCT(cr);
	cr.in.security_flags		= 0x00;
	cr.in.oplock_level		= 0;
	cr.in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	cr.in.create_flags		= 0x00000000;
	cr.in.reserved			= 0x00000000;
	cr.in.desired_access		= SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes		= FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access		= NTCREATEX_SHARE_ACCESS_READ |
					  NTCREATEX_SHARE_ACCESS_WRITE |
					  NTCREATEX_SHARE_ACCESS_DELETE;
	cr.in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	cr.in.fname			= fname;

	smb2_transport_compound_start(tree->session->transport, 2);

	req[0] = smb2_create_send(tree, &cr);

	smb2_transport_compound_set_related(tree->session->transport, true);

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;

	tree->smbXcli = smbXcli_tcon_create(tree);
	smb2cli_tcon_set_values(tree->smbXcli,
				NULL, /* session */
				0xFFFFFFFF, /* tcon_id */
				0, /* type */
				0, /* flags */
				0, /* capabilities */
				0 /* maximal_access */);

	tree->session->smbXcli = smbXcli_session_shallow_copy(tree->session,
							tree->session->smbXcli);
	smb2cli_session_set_id_and_flags(tree->session->smbXcli, UINT64_MAX, 0);

	req[1] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tree, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_close_recv(req[1], &cl);
	CHECK_STATUS(status, NT_STATUS_OK);

	TALLOC_FREE(tree->smbXcli);
	tree->smbXcli = saved_tcon;
	TALLOC_FREE(tree->session->smbXcli);
	tree->session->smbXcli = saved_session;

	smb2_util_unlink(tree, fname);
done:
	return ret;
}

static bool test_compound_related2(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_handle hd;
	struct smb2_create cr;
	NTSTATUS status;
	const char *fname = "compound_related2.dat";
	struct smb2_close cl;
	bool ret = true;
	struct smb2_request *req[5];
	struct smbXcli_tcon *saved_tcon = tree->smbXcli;
	struct smbXcli_session *saved_session = tree->session->smbXcli;

	smb2_transport_credits_ask_num(tree->session->transport, 5);

	smb2_util_unlink(tree, fname);

	smb2_transport_credits_ask_num(tree->session->transport, 1);

	ZERO_STRUCT(cr);
	cr.in.security_flags		= 0x00;
	cr.in.oplock_level		= 0;
	cr.in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	cr.in.create_flags		= 0x00000000;
	cr.in.reserved			= 0x00000000;
	cr.in.desired_access		= SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes		= FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access		= NTCREATEX_SHARE_ACCESS_READ |
					  NTCREATEX_SHARE_ACCESS_WRITE |
					  NTCREATEX_SHARE_ACCESS_DELETE;
	cr.in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	cr.in.fname			= fname;

	smb2_transport_compound_start(tree->session->transport, 5);

	req[0] = smb2_create_send(tree, &cr);

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;

	tree->smbXcli = smbXcli_tcon_create(tree);
	smb2cli_tcon_set_values(tree->smbXcli,
				NULL, /* session */
				0xFFFFFFFF, /* tcon_id */
				0, /* type */
				0, /* flags */
				0, /* capabilities */
				0 /* maximal_access */);

	tree->session->smbXcli = smbXcli_session_shallow_copy(tree->session,
							tree->session->smbXcli);
	smb2cli_session_set_id_and_flags(tree->session->smbXcli, UINT64_MAX, 0);

	req[1] = smb2_close_send(tree, &cl);
	req[2] = smb2_close_send(tree, &cl);
	req[3] = smb2_close_send(tree, &cl);
	req[4] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tree, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_close_recv(req[1], &cl);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_close_recv(req[2], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);
	status = smb2_close_recv(req[3], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);
	status = smb2_close_recv(req[4], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);

	TALLOC_FREE(tree->smbXcli);
	tree->smbXcli = saved_tcon;
	TALLOC_FREE(tree->session->smbXcli);
	tree->session->smbXcli = saved_session;

	smb2_util_unlink(tree, fname);
done:
	return ret;
}

static bool test_compound_related3(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_handle hd;
	struct smb2_ioctl io;
	struct smb2_create cr;
	struct smb2_close cl;
	const char *fname = "compound_related3.dat";
	struct smb2_request *req[3];
	NTSTATUS status;
	bool ret = false;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.in.security_flags	= 0x00;
	cr.in.oplock_level	= 0;
	cr.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;
	cr.in.create_flags	= 0x00000000;
	cr.in.reserved		= 0x00000000;
	cr.in.desired_access	= SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes	= FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access	= NTCREATEX_SHARE_ACCESS_READ |
				  NTCREATEX_SHARE_ACCESS_WRITE |
				  NTCREATEX_SHARE_ACCESS_DELETE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options	= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
				  NTCREATEX_OPTIONS_ASYNC_ALERT	|
				  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
				  0x00200000;
	cr.in.fname		= fname;

	smb2_transport_compound_start(tree->session->transport, 3);

	req[0] = smb2_create_send(tree, &cr);

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(io);
	io.in.function = FSCTL_CREATE_OR_GET_OBJECT_ID;
	io.in.file.handle = hd;
	io.in.reserved2 = 0;
	io.in.max_output_response = 64;
	io.in.flags = 1;

	req[1] = smb2_ioctl_send(tree, &io);

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;

	req[2] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tree, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_ioctl_recv(req[1], tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_close_recv(req[2], &cl);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

	ret = true;
done:
	return ret;
}

static bool test_compound_related4(struct torture_context *tctx,
			struct smb2_tree *tree)
{
	const char *fname = "compound_related4.dat";
	struct security_descriptor *sd = NULL;
	struct smb2_handle hd;
	struct smb2_create cr;
	union smb_setfileinfo set;
	struct smb2_ioctl io;
	struct smb2_close cl;
	struct smb2_request *req[4];
	NTSTATUS status;
	bool ret = true;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.level = RAW_OPEN_SMB2;
	cr.in.create_flags = 0;
	cr.in.desired_access = SEC_STD_READ_CONTROL |
				SEC_STD_WRITE_DAC |
				SEC_STD_WRITE_OWNER;
	cr.in.create_options = 0;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE |
				NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.alloc_size = 0;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	cr.in.security_flags = 0;
	cr.in.fname = fname;

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed\n");

	hd = cr.out.file.handle;
	torture_comment(tctx, "set a sec desc allowing no write by CREATOR_OWNER\n");

	sd = security_descriptor_dacl_create(tctx,
			0, NULL, NULL,
			SID_CREATOR_OWNER,
			SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
			0,
			NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
				     "security_descriptor_dacl_create failed\n");

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = hd;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &set);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	torture_comment(tctx, "try open for write\n");
	cr.in.desired_access = SEC_FILE_WRITE_DATA;
	smb2_transport_compound_start(tree->session->transport, 4);

	req[0] = smb2_create_send(tree, &cr);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
				     "smb2_create_send failed\n");

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	smb2_transport_compound_set_related(tree->session->transport, true);
	ZERO_STRUCT(io);
	io.in.function = FSCTL_CREATE_OR_GET_OBJECT_ID;
	io.in.file.handle = hd;
	io.in.flags = 1;

	req[1] = smb2_ioctl_send(tree, &io);
	torture_assert_not_null_goto(tctx, req[1], ret, done,
				     "smb2_ioctl_send failed\n");

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;

	req[2] = smb2_close_send(tree, &cl);
	torture_assert_not_null_goto(tctx, req[2], ret, done,
				     "smb2_create_send failed\n");

	set.set_secdesc.in.file.handle = hd;

	req[3] = smb2_setinfo_file_send(tree, &set);
	torture_assert_not_null_goto(tctx, req[3], ret, done,
				     "smb2_create_send failed\n");

	status = smb2_create_recv(req[0], tree, &cr);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "smb2_create_recv failed\n");

	status = smb2_ioctl_recv(req[1], tree, &io);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "smb2_ioctl_recv failed\n");

	status = smb2_close_recv(req[2], &cl);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "smb2_close_recv failed\n");

	status = smb2_setinfo_recv(req[3]);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "smb2_setinfo_recv failed\n");

done:
	smb2_util_unlink(tree, fname);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

static bool test_compound_related5(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_handle hd;
	struct smb2_ioctl io;
	struct smb2_close cl;
	struct smb2_request *req[2];
	NTSTATUS status;
	bool ret = false;

	smb2_transport_compound_start(tree->session->transport, 2);

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	ZERO_STRUCT(io);
	io.in.function = FSCTL_CREATE_OR_GET_OBJECT_ID;
	io.in.file.handle = hd;
	io.in.flags = 1;

	req[0] = smb2_ioctl_send(tree, &io);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
				     "smb2_ioctl_send failed\n");

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;

	req[1] = smb2_close_send(tree, &cl);
	torture_assert_not_null_goto(tctx, req[1], ret, done,
				     "smb2_create_send failed\n");

	status = smb2_ioctl_recv(req[0], tree, &io);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_FILE_CLOSED,
					   ret, done,
					   "smb2_ioctl_recv failed\n");

	status = smb2_close_recv(req[1], &cl);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_FILE_CLOSED,
					   ret, done,
					   "smb2_close_recv failed\n");

	ret = true;

done:
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

static bool test_compound_related6(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	struct smb2_handle hd;
	struct smb2_create cr;
	struct smb2_read rd;
	struct smb2_write wr;
	struct smb2_close cl;
	NTSTATUS status;
	const char *fname = "compound_related6.dat";
	struct smb2_request *req[5];
	uint8_t buf[64];
	bool ret = true;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.level = RAW_OPEN_SMB2;
	cr.in.create_flags = 0;
	cr.in.desired_access = SEC_RIGHTS_FILE_ALL;
	cr.in.create_options = 0;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE |
				NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.alloc_size = 0;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	cr.in.security_flags = 0;
	cr.in.fname = fname;

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	hd = cr.out.file.handle;

	ZERO_STRUCT(buf);
	status = smb2_util_write(tree, hd, buf, 0, ARRAY_SIZE(buf));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_write failed\n");

	torture_comment(tctx, "try open for read\n");
	cr.in.desired_access = SEC_FILE_READ_DATA;
	smb2_transport_compound_start(tree->session->transport, 5);

	req[0] = smb2_create_send(tree, &cr);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
				     "smb2_create_send failed\n");

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(rd);
	rd.in.file.handle = hd;
	rd.in.length      = 1;
	rd.in.offset      = 0;

	req[1] = smb2_read_send(tree, &rd);
	torture_assert_not_null_goto(tctx, req[1], ret, done,
				     "smb2_read_send failed\n");

	ZERO_STRUCT(wr);
	wr.in.file.handle = hd;
	wr.in.offset = 0;
	wr.in.data = data_blob_talloc(tctx, NULL, 64);

	req[2] = smb2_write_send(tree, &wr);
	torture_assert_not_null_goto(tctx, req[2], ret, done,
				     "smb2_write_send failed\n");

	ZERO_STRUCT(rd);
	rd.in.file.handle = hd;
	rd.in.length      = 1;
	rd.in.offset      = 0;

	req[3] = smb2_read_send(tree, &rd);
	torture_assert_not_null_goto(tctx, req[3], ret, done,
				     "smb2_read_send failed\n");

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;

	req[4] = smb2_close_send(tree, &cl);
	torture_assert_not_null_goto(tctx, req[4], ret, done,
				     "smb2_close_send failed\n");

	status = smb2_create_recv(req[0], tree, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create_recv failed\n");

	status = smb2_read_recv(req[1], tree, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_read_recv failed\n");

	status = smb2_write_recv(req[2], &wr);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "smb2_write_recv failed\n");

	status = smb2_read_recv(req[3], tree, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_read_recv failed\n");

	status = smb2_close_recv(req[4], &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_close_recv failed\n");

  done:
	smb2_util_unlink(tree, fname);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

static bool test_compound_related7(struct torture_context *tctx,
			struct smb2_tree *tree)
{
	const char *fname = "compound_related4.dat";
	struct security_descriptor *sd = NULL;
	struct smb2_handle hd;
	struct smb2_create cr;
	union smb_setfileinfo set;
	struct smb2_notify nt;
	struct smb2_close cl;
	NTSTATUS status;
	struct smb2_request *req[4];
	bool ret = true;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.level = RAW_OPEN_SMB2;
	cr.in.create_flags = 0;
	cr.in.desired_access = SEC_STD_READ_CONTROL |
				SEC_STD_WRITE_DAC |
				SEC_STD_WRITE_OWNER;
	cr.in.create_options = 0;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE |
				NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.alloc_size = 0;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	cr.in.security_flags = 0;
	cr.in.fname = fname;

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	hd = cr.out.file.handle;
	torture_comment(tctx, "set a sec desc allowing no write by CREATOR_OWNER\n");
	sd = security_descriptor_dacl_create(tctx,
			0, NULL, NULL,
			SID_CREATOR_OWNER,
			SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
			0,
			NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
				     "security_descriptor_dacl_create failed\n");

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = hd;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &set);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	torture_comment(tctx, "try open for write\n");
	cr.in.desired_access = SEC_FILE_WRITE_DATA;
	smb2_transport_compound_start(tree->session->transport, 4);

	req[0] = smb2_create_send(tree, &cr);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
				     "smb2_create_send failed\n");

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(nt);
	nt.in.recursive          = true;
	nt.in.buffer_size        = 0x1000;
	nt.in.file.handle        = hd;
	nt.in.completion_filter  = FILE_NOTIFY_CHANGE_NAME;
	nt.in.unknown            = 0x00000000;

	req[1] = smb2_notify_send(tree, &nt);
	torture_assert_not_null_goto(tctx, req[1], ret, done,
				     "smb2_notify_send failed\n");

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;

	req[2] = smb2_close_send(tree, &cl);
	torture_assert_not_null_goto(tctx, req[2], ret, done,
				     "smb2_close_send failed\n");

	set.set_secdesc.in.file.handle = hd;

	req[3] = smb2_setinfo_file_send(tree, &set);
	torture_assert_not_null_goto(tctx, req[3], ret, done,
				     "smb2_setinfo_file_send failed\n");

	status = smb2_create_recv(req[0], tree, &cr);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "smb2_create_recv failed\n");

	status = smb2_notify_recv(req[1], tree, &nt);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "smb2_notify_recv failed\n");

	status = smb2_close_recv(req[2], &cl);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "smb2_close_recv failed\n");

	status = smb2_setinfo_recv(req[3]);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED,
					   ret, done,
					   "smb2_setinfo_recv failed\n");

done:
	smb2_util_unlink(tree, fname);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

static bool test_compound_related8(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	const char *fname = "compound_related8.dat";
	const char *fname_nonexisting = "compound_related8.dat.void";
	struct security_descriptor *sd = NULL;
	struct smb2_handle hd;
	struct smb2_create cr;
	union smb_setfileinfo set;
	struct smb2_notify nt;
	struct smb2_close cl;
	NTSTATUS status;
	struct smb2_request *req[4];
	bool ret = true;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.level = RAW_OPEN_SMB2;
	cr.in.create_flags = 0;
	cr.in.desired_access = SEC_STD_READ_CONTROL |
				SEC_STD_WRITE_DAC |
				SEC_STD_WRITE_OWNER;
	cr.in.create_options = 0;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE |
				NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.alloc_size = 0;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	cr.in.security_flags = 0;
	cr.in.fname = fname;

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	hd = cr.out.file.handle;

	smb2_transport_compound_start(tree->session->transport, 4);

	torture_comment(tctx, "try open for write\n");
	cr.in.fname = fname_nonexisting;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;

	req[0] = smb2_create_send(tree, &cr);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
				     "smb2_create_send failed\n");

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(nt);
	nt.in.recursive          = true;
	nt.in.buffer_size        = 0x1000;
	nt.in.file.handle        = hd;
	nt.in.completion_filter  = FILE_NOTIFY_CHANGE_NAME;
	nt.in.unknown            = 0x00000000;

	req[1] = smb2_notify_send(tree, &nt);
	torture_assert_not_null_goto(tctx, req[1], ret, done,
				     "smb2_notify_send failed\n");

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;

	req[2] = smb2_close_send(tree, &cl);
	torture_assert_not_null_goto(tctx, req[2], ret, done,
				     "smb2_close_send failed\n");

	sd = security_descriptor_dacl_create(tctx,
			0, NULL, NULL,
			SID_CREATOR_OWNER,
			SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
			0,
			NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
				     "security_descriptor_dacl_create failed\n");

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = hd;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	req[3] = smb2_setinfo_file_send(tree, &set);
	torture_assert_not_null_goto(tctx, req[3], ret, done,
				     "smb2_setinfo_file_send failed\n");

	status = smb2_create_recv(req[0], tree, &cr);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "smb2_create_recv failed\n");

	status = smb2_notify_recv(req[1], tree, &nt);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "smb2_notify_recv failed\n");

	status = smb2_close_recv(req[2], &cl);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "smb2_close_recv failed\n");

	status = smb2_setinfo_recv(req[3]);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "smb2_setinfo_recv failed\n");

done:
	smb2_util_unlink(tree, fname);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

static bool test_compound_related9(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	const char *fname = "compound_related9.dat";
	struct security_descriptor *sd = NULL;
	struct smb2_handle hd;
	struct smb2_create cr;
	union smb_setfileinfo set;
	struct smb2_notify nt;
	struct smb2_close cl;
	NTSTATUS status;
	struct smb2_request *req[3];
	bool ret = true;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.level = RAW_OPEN_SMB2;
	cr.in.create_flags = 0;
	cr.in.desired_access = SEC_STD_READ_CONTROL |
				SEC_STD_WRITE_DAC |
				SEC_STD_WRITE_OWNER;
	cr.in.create_options = 0;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE |
				NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.alloc_size = 0;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	cr.in.security_flags = 0;
	cr.in.fname = fname;

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	hd = cr.out.file.handle;

	smb2_transport_compound_start(tree->session->transport, 3);
	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(nt);
	nt.in.recursive          = true;
	nt.in.buffer_size        = 0x1000;
	nt.in.completion_filter  = FILE_NOTIFY_CHANGE_NAME;

	req[0] = smb2_notify_send(tree, &nt);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
				     "smb2_notify_send failed\n");

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;

	req[1] = smb2_close_send(tree, &cl);
	torture_assert_not_null_goto(tctx, req[1], ret, done,
				     "smb2_close_send failed\n");

	sd = security_descriptor_dacl_create(tctx,
			0, NULL, NULL,
			SID_CREATOR_OWNER,
			SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
			0,
			NULL);
	torture_assert_not_null_goto(tctx, sd, ret, done,
				     "security_descriptor_dacl_create failed\n");

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = hd;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	req[2] = smb2_setinfo_file_send(tree, &set);
	torture_assert_not_null_goto(tctx, req[2], ret, done,
				     "smb2_setinfo_file_send failed\n");

	status = smb2_notify_recv(req[0], tree, &nt);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_INVALID_PARAMETER,
					   ret, done,
					   "smb2_notify_recv failed\n");

	status = smb2_close_recv(req[1], &cl);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_INVALID_PARAMETER,
					   ret, done,
					   "smb2_close_recv failed\n");

	status = smb2_setinfo_recv(req[2]);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_INVALID_PARAMETER,
					   ret, done,
					   "smb2_setinfo_recv failed\n");

done:
	smb2_util_unlink(tree, fname);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

static bool test_compound_padding(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	struct smb2_handle h;
	struct smb2_create cr;
	struct smb2_read r;
	struct smb2_read r2;
	const char *fname = "compound_read.dat";
	const char *sname = "compound_read.dat:foo";
	struct smb2_request *req[3];
	NTSTATUS status;
	bool ret = false;

	smb2_util_unlink(tree, fname);

	/* Write file */
	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_WRITE_DATA;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_CREATE;
	cr.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	cr.in.fname = fname;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree, tctx, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = cr.out.file.handle;

	status = smb2_util_write(tree, h, "123", 0, 3);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, h);

	/* Write stream */
	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_WRITE_DATA;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_CREATE;
	cr.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	cr.in.fname = sname;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree, tctx, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = cr.out.file.handle;

	status = smb2_util_write(tree, h, "456", 0, 3);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, h);

	/* Check compound read from basefile */
	smb2_transport_compound_start(tree->session->transport, 3);

	ZERO_STRUCT(cr);
	cr.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	cr.in.desired_access	= SEC_FILE_READ_DATA;
	cr.in.file_attributes	= FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.fname		= fname;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	req[0] = smb2_create_send(tree, &cr);

	smb2_transport_compound_set_related(tree->session->transport, true);

	/*
	 * We send 2 reads in the compound here as the protocol
	 * allows the last read to be split off and possibly
	 * go async. Check the padding on the first read returned,
	 * not the second as the second may not be part of the
	 * returned compound.
	*/

	ZERO_STRUCT(r);
	h.data[0] = UINT64_MAX;
	h.data[1] = UINT64_MAX;
	r.in.file.handle = h;
	r.in.length      = 3;
	r.in.offset      = 0;
	r.in.min_count      = 1;
	req[1] = smb2_read_send(tree, &r);

	ZERO_STRUCT(r2);
	h.data[0] = UINT64_MAX;
	h.data[1] = UINT64_MAX;
	r2.in.file.handle = h;
	r2.in.length      = 3;
	r2.in.offset      = 0;
	r2.in.min_count      = 1;
	req[2] = smb2_read_send(tree, &r2);

	status = smb2_create_recv(req[0], tree, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * We must do a manual smb2_request_receive() in order to be
	 * able to check the transport layer info, as smb2_read_recv()
	 * will destroy the req. smb2_read_recv() will call
	 * smb2_request_receive() again, but that's ok.
	 */
	if (!smb2_request_receive(req[1]) ||
	    !smb2_request_is_ok(req[1])) {
		torture_fail(tctx, "failed to receive read request");
	}

	/*
	 * size must be 24: 16 byte read response header plus 3
	 * requested bytes padded to an 8 byte boundary.
	 */
	CHECK_VAL(req[1]->in.body_size, 24);

	status = smb2_read_recv(req[1], tree, &r);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Pick up the second, possibly async, read. */
	status = smb2_read_recv(req[2], tree, &r2);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, cr.out.file.handle);

	/* Check compound read from stream */
	smb2_transport_compound_start(tree->session->transport, 3);

	ZERO_STRUCT(cr);
	cr.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	cr.in.desired_access	= SEC_FILE_READ_DATA;
	cr.in.file_attributes	= FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.fname		= sname;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	req[0] = smb2_create_send(tree, &cr);

	smb2_transport_compound_set_related(tree->session->transport, true);

	/*
	 * We send 2 reads in the compound here as the protocol
	 * allows the last read to be split off and possibly
	 * go async. Check the padding on the first read returned,
	 * not the second as the second may not be part of the
	 * returned compound.
	 */

	ZERO_STRUCT(r);
	h.data[0] = UINT64_MAX;
	h.data[1] = UINT64_MAX;
	r.in.file.handle = h;
	r.in.length      = 3;
	r.in.offset      = 0;
	r.in.min_count   = 1;
	req[1] = smb2_read_send(tree, &r);

	ZERO_STRUCT(r2);
	h.data[0] = UINT64_MAX;
	h.data[1] = UINT64_MAX;
	r2.in.file.handle = h;
	r2.in.length      = 3;
	r2.in.offset      = 0;
	r2.in.min_count   = 1;
	req[2] = smb2_read_send(tree, &r2);

	status = smb2_create_recv(req[0], tree, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * We must do a manual smb2_request_receive() in order to be
	 * able to check the transport layer info, as smb2_read_recv()
	 * will destroy the req. smb2_read_recv() will call
	 * smb2_request_receive() again, but that's ok.
	 */
	if (!smb2_request_receive(req[1]) ||
	    !smb2_request_is_ok(req[1])) {
		torture_fail(tctx, "failed to receive read request");
	}

	/*
	 * size must be 24: 16 byte read response header plus 3
	 * requested bytes padded to an 8 byte boundary.
	 */
	CHECK_VAL(req[1]->in.body_size, 24);

	status = smb2_read_recv(req[1], tree, &r);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Pick up the second, possibly async, read. */
	status = smb2_read_recv(req[2], tree, &r2);
	CHECK_STATUS(status, NT_STATUS_OK);

	h = cr.out.file.handle;

	/* Check 2 compound (unrelateated) reads from existing stream handle */
	smb2_transport_compound_start(tree->session->transport, 2);

	ZERO_STRUCT(r);
	r.in.file.handle = h;
	r.in.length      = 3;
	r.in.offset      = 0;
	r.in.min_count   = 1;
	req[0] = smb2_read_send(tree, &r);
	req[1] = smb2_read_send(tree, &r);

	/*
	 * We must do a manual smb2_request_receive() in order to be
	 * able to check the transport layer info, as smb2_read_recv()
	 * will destroy the req. smb2_read_recv() will call
	 * smb2_request_receive() again, but that's ok.
	 */
	if (!smb2_request_receive(req[0]) ||
	    !smb2_request_is_ok(req[0])) {
		torture_fail(tctx, "failed to receive read request");
	}
	if (!smb2_request_receive(req[1]) ||
	    !smb2_request_is_ok(req[1])) {
		torture_fail(tctx, "failed to receive read request");
	}

	/*
	 * size must be 24: 16 byte read response header plus 3
	 * requested bytes padded to an 8 byte boundary.
	 */
	CHECK_VAL(req[0]->in.body_size, 24);
	CHECK_VAL(req[1]->in.body_size, 24);

	status = smb2_read_recv(req[0], tree, &r);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_read_recv(req[1], tree, &r);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * now try a single read from the stream and verify there's no padding
	 */
	ZERO_STRUCT(r);
	r.in.file.handle = h;
	r.in.length      = 3;
	r.in.offset      = 0;
	r.in.min_count   = 1;
	req[0] = smb2_read_send(tree, &r);

	/*
	 * We must do a manual smb2_request_receive() in order to be
	 * able to check the transport layer info, as smb2_read_recv()
	 * will destroy the req. smb2_read_recv() will call
	 * smb2_request_receive() again, but that's ok.
	 */
	if (!smb2_request_receive(req[0]) ||
	    !smb2_request_is_ok(req[0])) {
		torture_fail(tctx, "failed to receive read request");
	}

	/*
	 * size must be 19: 16 byte read response header plus 3
	 * requested bytes without padding.
	 */
	CHECK_VAL(req[0]->in.body_size, 19);

	status = smb2_read_recv(req[0], tree, &r);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, h);

	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

	ret = true;
done:
	return ret;
}

static bool test_compound_create_write_close(struct torture_context *tctx,
					     struct smb2_tree *tree)
{
	struct smb2_handle handle = { .data = { UINT64_MAX, UINT64_MAX } };
	struct smb2_create create;
	struct smb2_write write;
	struct smb2_close close;
	const char *fname = "compound_create_write_close.dat";
	struct smb2_request *req[3];
	NTSTATUS status;
	bool ret = false;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(create);
	create.in.security_flags = 0x00;
	create.in.oplock_level = 0;
	create.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;
	create.in.create_flags = 0x00000000;
	create.in.reserved = 0x00000000;
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE |
		NTCREATEX_SHARE_ACCESS_DELETE;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.create_options = NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
		NTCREATEX_OPTIONS_ASYNC_ALERT |
		NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
		0x00200000;
	create.in.fname = fname;

	smb2_transport_compound_start(tree->session->transport, 3);

	req[0] = smb2_create_send(tree, &create);

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(write);
	write.in.file.handle = handle;
	write.in.offset = 0;
	write.in.data = data_blob_talloc(tctx, NULL, 1024);

	req[1] = smb2_write_send(tree, &write);

	ZERO_STRUCT(close);
	close.in.file.handle = handle;

	req[2] = smb2_close_send(tree, &close);

	status = smb2_create_recv(req[0], tree, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CREATE failed.");

	status = smb2_write_recv(req[1], &write);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"WRITE failed.");

	status = smb2_close_recv(req[2], &close);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CLOSE failed.");

	status = smb2_util_unlink(tree, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"File deletion failed.");

	ret = true;
done:
	return ret;
}

static bool test_compound_unrelated1(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	struct smb2_handle hd;
	struct smb2_create cr;
	NTSTATUS status;
	const char *fname = "compound_unrelated1.dat";
	struct smb2_close cl;
	bool ret = true;
	struct smb2_request *req[5];

	smb2_transport_credits_ask_num(tree->session->transport, 5);

	smb2_util_unlink(tree, fname);

	smb2_transport_credits_ask_num(tree->session->transport, 1);

	ZERO_STRUCT(cr);
	cr.in.security_flags		= 0x00;
	cr.in.oplock_level		= 0;
	cr.in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	cr.in.create_flags		= 0x00000000;
	cr.in.reserved			= 0x00000000;
	cr.in.desired_access		= SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes		= FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access		= NTCREATEX_SHARE_ACCESS_READ |
					  NTCREATEX_SHARE_ACCESS_WRITE |
					  NTCREATEX_SHARE_ACCESS_DELETE;
	cr.in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	cr.in.fname			= fname;

	smb2_transport_compound_start(tree->session->transport, 5);

	req[0] = smb2_create_send(tree, &cr);

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;
	req[1] = smb2_close_send(tree, &cl);
	req[2] = smb2_close_send(tree, &cl);
	req[3] = smb2_close_send(tree, &cl);
	req[4] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tree, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_close_recv(req[1], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);
	status = smb2_close_recv(req[2], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);
	status = smb2_close_recv(req[3], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);
	status = smb2_close_recv(req[4], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);

	smb2_util_unlink(tree, fname);
done:
	return ret;
}

static bool test_compound_invalid1(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_handle hd;
	struct smb2_create cr;
	NTSTATUS status;
	const char *fname = "compound_invalid1.dat";
	struct smb2_close cl;
	bool ret = true;
	struct smb2_request *req[3];

	smb2_transport_credits_ask_num(tree->session->transport, 3);

	smb2_util_unlink(tree, fname);

	smb2_transport_credits_ask_num(tree->session->transport, 1);

	ZERO_STRUCT(cr);
	cr.in.security_flags		= 0x00;
	cr.in.oplock_level		= 0;
	cr.in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	cr.in.create_flags		= 0x00000000;
	cr.in.reserved			= 0x00000000;
	cr.in.desired_access		= SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes		= FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access		= NTCREATEX_SHARE_ACCESS_READ |
					  NTCREATEX_SHARE_ACCESS_WRITE |
					  NTCREATEX_SHARE_ACCESS_DELETE;
	cr.in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	cr.in.fname			= fname;

	smb2_transport_compound_start(tree->session->transport, 3);

	/* passing the first request with the related flag is invalid */
	smb2_transport_compound_set_related(tree->session->transport, true);

	req[0] = smb2_create_send(tree, &cr);

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;
	req[1] = smb2_close_send(tree, &cl);

	smb2_transport_compound_set_related(tree->session->transport, false);
	req[2] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tree, &cr);
	/* TODO: check why this fails with --signing=required */
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);
	status = smb2_close_recv(req[1], &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);
	status = smb2_close_recv(req[2], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);

	smb2_util_unlink(tree, fname);
done:
	return ret;
}

static bool test_compound_invalid2(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_handle hd;
	struct smb2_create cr;
	NTSTATUS status;
	const char *fname = "compound_invalid2.dat";
	struct smb2_close cl;
	bool ret = true;
	struct smb2_request *req[5];
	struct smbXcli_tcon *saved_tcon = tree->smbXcli;
	struct smbXcli_session *saved_session = tree->session->smbXcli;

	smb2_transport_credits_ask_num(tree->session->transport, 5);

	smb2_util_unlink(tree, fname);

	smb2_transport_credits_ask_num(tree->session->transport, 1);

	ZERO_STRUCT(cr);
	cr.in.security_flags		= 0x00;
	cr.in.oplock_level		= 0;
	cr.in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	cr.in.create_flags		= 0x00000000;
	cr.in.reserved			= 0x00000000;
	cr.in.desired_access		= SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes		= FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access		= NTCREATEX_SHARE_ACCESS_READ |
					  NTCREATEX_SHARE_ACCESS_WRITE |
					  NTCREATEX_SHARE_ACCESS_DELETE;
	cr.in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	cr.in.fname			= fname;

	smb2_transport_compound_start(tree->session->transport, 5);

	req[0] = smb2_create_send(tree, &cr);

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;

	tree->smbXcli = smbXcli_tcon_create(tree);
	smb2cli_tcon_set_values(tree->smbXcli,
				NULL, /* session */
				0xFFFFFFFF, /* tcon_id */
				0, /* type */
				0, /* flags */
				0, /* capabilities */
				0 /* maximal_access */);

	tree->session->smbXcli = smbXcli_session_shallow_copy(tree->session,
							tree->session->smbXcli);
	smb2cli_session_set_id_and_flags(tree->session->smbXcli, UINT64_MAX, 0);

	req[1] = smb2_close_send(tree, &cl);
	/* strange that this is not generating invalid parameter */
	smb2_transport_compound_set_related(tree->session->transport, false);
	req[2] = smb2_close_send(tree, &cl);
	req[3] = smb2_close_send(tree, &cl);
	smb2_transport_compound_set_related(tree->session->transport, true);
	req[4] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tree, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_close_recv(req[1], &cl);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_close_recv(req[2], &cl);
	CHECK_STATUS(status, NT_STATUS_USER_SESSION_DELETED);
	status = smb2_close_recv(req[3], &cl);
	CHECK_STATUS(status, NT_STATUS_USER_SESSION_DELETED);
	status = smb2_close_recv(req[4], &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	TALLOC_FREE(tree->smbXcli);
	tree->smbXcli = saved_tcon;
	TALLOC_FREE(tree->session->smbXcli);
	tree->session->smbXcli = saved_session;

	smb2_util_unlink(tree, fname);
done:
	return ret;
}

static bool test_compound_invalid3(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_handle hd;
	struct smb2_create cr;
	NTSTATUS status;
	const char *fname = "compound_invalid3.dat";
	struct smb2_close cl;
	bool ret = true;
	struct smb2_request *req[5];

	smb2_transport_credits_ask_num(tree->session->transport, 5);

	smb2_util_unlink(tree, fname);

	smb2_transport_credits_ask_num(tree->session->transport, 1);

	ZERO_STRUCT(cr);
	cr.in.security_flags		= 0x00;
	cr.in.oplock_level		= 0;
	cr.in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	cr.in.create_flags		= 0x00000000;
	cr.in.reserved			= 0x00000000;
	cr.in.desired_access		= SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes		= FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access		= NTCREATEX_SHARE_ACCESS_READ |
					  NTCREATEX_SHARE_ACCESS_WRITE |
					  NTCREATEX_SHARE_ACCESS_DELETE;
	cr.in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	cr.in.fname			= fname;

	smb2_transport_compound_start(tree->session->transport, 5);

	req[0] = smb2_create_send(tree, &cr);

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	ZERO_STRUCT(cl);
	cl.in.file.handle = hd;
	req[1] = smb2_close_send(tree, &cl);
	req[2] = smb2_close_send(tree, &cl);
	/* flipping the related flag is invalid */
	smb2_transport_compound_set_related(tree->session->transport, true);
	req[3] = smb2_close_send(tree, &cl);
	req[4] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tree, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_close_recv(req[1], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);
	status = smb2_close_recv(req[2], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);
	status = smb2_close_recv(req[3], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);
	status = smb2_close_recv(req[4], &cl);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);

	smb2_util_unlink(tree, fname);
done:
	return ret;
}

static bool test_compound_invalid4(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	struct smb2_create cr;
	struct smb2_read rd;
	NTSTATUS status;
	const char *fname = "compound_invalid4.dat";
	struct smb2_close cl;
	bool ret = true;
	bool ok;
	struct smb2_request *req[2];

	smb2_transport_credits_ask_num(tree->session->transport, 2);

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(cr);
	cr.in.security_flags	  = 0x00;
	cr.in.oplock_level	  = 0;
	cr.in.impersonation_level = NTCREATEX_IMPERSONATION_IMPERSONATION;
	cr.in.create_flags	  = 0x00000000;
	cr.in.reserved		  = 0x00000000;
	cr.in.desired_access	  = SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes	  = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access	  = NTCREATEX_SHARE_ACCESS_READ |
				    NTCREATEX_SHARE_ACCESS_WRITE |
				    NTCREATEX_SHARE_ACCESS_DELETE;
	cr.in.create_disposition  = NTCREATEX_DISP_OPEN_IF;
	cr.in.create_options	  = NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
				    NTCREATEX_OPTIONS_ASYNC_ALERT	|
				    NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
				    0x00200000;
	cr.in.fname		  = fname;

	status = smb2_create(tree, tctx, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_transport_compound_start(tree->session->transport, 2);

	ZERO_STRUCT(rd);
	rd.in.file.handle = cr.out.file.handle;
	rd.in.length      = 1;
	rd.in.offset      = 0;
	req[0] = smb2_read_send(tree, &rd);

	smb2_transport_compound_set_related(tree->session->transport, true);

	/*
	 * Send a completely bogus request as second compound
	 * element. This triggers smbd_smb2_request_error() in in
	 * smbd_smb2_request_dispatch() before calling
	 * smbd_smb2_request_dispatch_update_counts().
	 */

	req[1] = smb2_request_init_tree(tree, 0xff, 0x04, false, 0);
	smb2_transport_send(req[1]);

	status = smb2_read_recv(req[0], tctx, &rd);
	CHECK_STATUS(status, NT_STATUS_END_OF_FILE);

	ok = smb2_request_receive(req[1]);
	torture_assert(tctx, ok, "Invalid request failed\n");
	CHECK_STATUS(req[1]->status, NT_STATUS_INVALID_PARAMETER);

	ZERO_STRUCT(cl);
	cl.in.file.handle = cr.out.file.handle;

	status = smb2_close(tree, &cl);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_unlink(tree, fname);
done:
	return ret;
}

/* Send a compound request where we expect the last request (Create, Notify)
 * to go asynchronous. This works against a Win7 server and the reply is
 * sent in two different packets. */
static bool test_compound_interim1(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
    struct smb2_handle hd;
    struct smb2_create cr;
    NTSTATUS status = NT_STATUS_OK;
    const char *dname = "compound_interim_dir";
    struct smb2_notify nt;
    bool ret = true;
    struct smb2_request *req[2];

    /* Win7 compound request implementation deviates substantially from the
     * SMB2 spec as noted in MS-SMB2 <159>, <162>.  This, test currently
     * verifies the Windows behavior, not the general spec behavior. */

    smb2_transport_credits_ask_num(tree->session->transport, 5);

    smb2_deltree(tree, dname);

    smb2_transport_credits_ask_num(tree->session->transport, 1);

    ZERO_STRUCT(cr);
    cr.in.desired_access	= SEC_RIGHTS_FILE_ALL;
    cr.in.create_options	= NTCREATEX_OPTIONS_DIRECTORY;
    cr.in.file_attributes	= FILE_ATTRIBUTE_DIRECTORY;
    cr.in.share_access		= NTCREATEX_SHARE_ACCESS_READ |
				  NTCREATEX_SHARE_ACCESS_WRITE |
				  NTCREATEX_SHARE_ACCESS_DELETE;
    cr.in.create_disposition	= NTCREATEX_DISP_CREATE;
    cr.in.fname			= dname;

    smb2_transport_compound_start(tree->session->transport, 2);

    req[0] = smb2_create_send(tree, &cr);

    smb2_transport_compound_set_related(tree->session->transport, true);

    hd.data[0] = UINT64_MAX;
    hd.data[1] = UINT64_MAX;

    ZERO_STRUCT(nt);
    nt.in.recursive          = true;
    nt.in.buffer_size        = 0x1000;
    nt.in.file.handle        = hd;
    nt.in.completion_filter  = FILE_NOTIFY_CHANGE_NAME;
    nt.in.unknown            = 0x00000000;

    req[1] = smb2_notify_send(tree, &nt);

    status = smb2_create_recv(req[0], tree, &cr);
    CHECK_STATUS(status, NT_STATUS_OK);

    smb2_cancel(req[1]);
    status = smb2_notify_recv(req[1], tree, &nt);
    CHECK_STATUS(status, NT_STATUS_CANCELLED);

    smb2_util_close(tree, cr.out.file.handle);

    smb2_deltree(tree, dname);
done:
    return ret;
}

/* Send a compound request where we expect the middle request (Create, Notify,
 * GetInfo) to go asynchronous. Against Win7 the sync request succeed while
 * the async fails. All are returned in the same compound response. */
static bool test_compound_interim2(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
    struct smb2_handle hd;
    struct smb2_create cr;
    NTSTATUS status = NT_STATUS_OK;
    const char *dname = "compound_interim_dir";
    struct smb2_getinfo gf;
    struct smb2_notify  nt;
    bool ret = true;
    struct smb2_request *req[3];

    /* Win7 compound request implementation deviates substantially from the
     * SMB2 spec as noted in MS-SMB2 <159>, <162>.  This, test currently
     * verifies the Windows behavior, not the general spec behavior. */

    smb2_transport_credits_ask_num(tree->session->transport, 5);

    smb2_deltree(tree, dname);

    smb2_transport_credits_ask_num(tree->session->transport, 1);

    ZERO_STRUCT(cr);
    cr.in.desired_access        = SEC_RIGHTS_FILE_ALL;
    cr.in.create_options        = NTCREATEX_OPTIONS_DIRECTORY;
    cr.in.file_attributes       = FILE_ATTRIBUTE_DIRECTORY;
    cr.in.share_access      = NTCREATEX_SHARE_ACCESS_READ |
                      NTCREATEX_SHARE_ACCESS_WRITE |
                      NTCREATEX_SHARE_ACCESS_DELETE;
    cr.in.create_disposition    = NTCREATEX_DISP_CREATE;
    cr.in.fname         = dname;

    smb2_transport_compound_start(tree->session->transport, 3);

    req[0] = smb2_create_send(tree, &cr);

    smb2_transport_compound_set_related(tree->session->transport, true);

    hd.data[0] = UINT64_MAX;
    hd.data[1] = UINT64_MAX;

    ZERO_STRUCT(nt);
    nt.in.recursive          = true;
    nt.in.buffer_size        = 0x1000;
    nt.in.file.handle        = hd;
    nt.in.completion_filter  = FILE_NOTIFY_CHANGE_NAME;
    nt.in.unknown            = 0x00000000;

    req[1] = smb2_notify_send(tree, &nt);

    ZERO_STRUCT(gf);
    gf.in.file.handle = hd;
    gf.in.info_type   = SMB2_0_INFO_FILE;
    gf.in.info_class  = 0x04; /* FILE_BASIC_INFORMATION */
    gf.in.output_buffer_length = 0x1000;
    gf.in.input_buffer = data_blob_null;

    req[2] = smb2_getinfo_send(tree, &gf);

    status = smb2_create_recv(req[0], tree, &cr);
    CHECK_STATUS(status, NT_STATUS_OK);

    status = smb2_notify_recv(req[1], tree, &nt);
    CHECK_STATUS(status, NT_STATUS_INTERNAL_ERROR);

    status = smb2_getinfo_recv(req[2], tree, &gf);
    CHECK_STATUS(status, NT_STATUS_OK);

    smb2_util_close(tree, cr.out.file.handle);

    smb2_deltree(tree, dname);
done:
    return ret;
}

/*
 * Send a compound related series of CREATE+CLOSE+CREATE+NOTIFY and check
 * CREATE+CLOSE+CREATE responses come in a separate compound response before the
 * STATUS_PENDING for the NOTIFY.
 */
static bool test_compound_interim3(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	const char *dname = "test_compound_interim3";
	struct smb2_handle hd = {};
	struct smb2_create cr = {};
	struct smb2_handle h1 = {};
	struct smb2_notify nt = {};
	struct smb2_request *req[6] = {};
	struct smb2_close cl = {};
	NTSTATUS status;
	int rc;
	bool ret = true;

	smb2_deltree(tree, dname);
	smb2_transport_compound_start(tree->session->transport, 4);

	hd.data[0] = UINT64_MAX;
	hd.data[1] = UINT64_MAX;

	cr.in.desired_access	= SEC_RIGHTS_FILE_ALL;
	cr.in.create_options	= NTCREATEX_OPTIONS_DIRECTORY;
	cr.in.file_attributes	= FILE_ATTRIBUTE_DIRECTORY;
	cr.in.share_access	= NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE |
		NTCREATEX_SHARE_ACCESS_DELETE;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.fname		= dname;

	nt.in.recursive          = true;
	nt.in.buffer_size        = 0x1000;
	nt.in.file.handle        = hd;
	nt.in.completion_filter  = FILE_NOTIFY_CHANGE_NAME;
	nt.in.unknown            = 0x00000000;

	req[0] = smb2_create_send(tree, &cr);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
				     "smb2_create_send failed\n");

	smb2_transport_compound_set_related(tree->session->transport, true);

	cl.in.file.handle = hd;

	req[1] = smb2_close_send(tree, &cl);
	torture_assert_not_null_goto(tctx, req[1], ret, done,
				     "smb2_close_send failed\n");

	req[2] = smb2_create_send(tree, &cr);
	torture_assert_not_null_goto(tctx, req[2], ret, done,
				     "smb2_create_send failed\n");

	req[3] = smb2_notify_send(tree, &nt);
	torture_assert_not_null_goto(tctx, req[3], ret, done,
				     "smb2_create_send failed\n");

	while (req[2]->state < SMB2_REQUEST_DONE) {
		rc = tevent_loop_once(tctx->ev);
		torture_assert_goto(tctx, rc == 0, ret, done,
				    "tevent_loop_once failed\n");
	}

	torture_assert_goto(tctx, req[0]->state == SMB2_REQUEST_DONE, ret, done,
			    "state not SMB2_REQUEST_DONE");
	torture_assert_goto(tctx, req[1]->state == SMB2_REQUEST_DONE, ret, done,
			    "state not SMB2_REQUEST_DONE");
	torture_assert_goto(tctx, req[2]->state == SMB2_REQUEST_DONE, ret, done,
			    "state not SMB2_REQUEST_DONE");
	torture_assert_goto(tctx, req[3]->state == SMB2_REQUEST_RECV, ret, done,
			    "state not SMB2_REQUEST_RECV");

	WAIT_FOR_ASYNC_RESPONSE(req[3]);
	torture_assert_goto(tctx, req[3]->state == SMB2_REQUEST_RECV, ret, done,
			    "state not SMB2_REQUEST_RECV");
	torture_assert_goto(tctx, req[3]->cancel.can_cancel, ret, done, "pending");

	status = smb2_create_recv(req[0], tree, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_recv failed\n");

	status = smb2_close_recv(req[1], &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_recv failed\n");

	status = smb2_create_recv(req[2], tree, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create_recv failed\n");
	h1 = cr.out.file.handle;

	smb2_cancel(req[3]);
	status = smb2_notify_recv(req[3], tree, &nt);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_CANCELLED,
					   ret, done,
					   "smb2_notify_recv failed\n");

done:
	smb2_util_close(tree, h1);
	smb2_deltree(tree, dname);
	return ret;
}

/* Test compound related finds */
static bool test_compound_find_related(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *dname = "compound_find_dir";
	struct smb2_create create;
	struct smb2_find f;
	struct smb2_handle h;
	struct smb2_request *req[2];
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, dname);

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_DIR_ALL;
	create.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	create.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				 NTCREATEX_SHARE_ACCESS_WRITE |
				 NTCREATEX_SHARE_ACCESS_DELETE;
	create.in.create_disposition = NTCREATEX_DISP_CREATE;
	create.in.fname = dname;

	status = smb2_create(tree, mem_ctx, &create);
	h = create.out.file.handle;

	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed\n");

	smb2_transport_compound_start(tree->session->transport, 2);

	ZERO_STRUCT(f);
	f.in.file.handle	= h;
	f.in.pattern		= "*";
	f.in.max_response_size	= 0x100;
	f.in.level              = SMB2_FIND_BOTH_DIRECTORY_INFO;

	req[0] = smb2_find_send(tree, &f);

	smb2_transport_compound_set_related(tree->session->transport, true);

	req[1] = smb2_find_send(tree, &f);

	status = smb2_find_recv(req[0], mem_ctx, &f);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_find_recv failed\n");

	status = smb2_find_recv(req[1], mem_ctx, &f);
	torture_assert_ntstatus_equal_goto(tctx, status, STATUS_NO_MORE_FILES, ret, done, "smb2_find_recv failed\n");

done:
	smb2_util_close(tree, h);
	smb2_deltree(tree, dname);
	TALLOC_FREE(mem_ctx);
	return ret;
}

/* Test compound related finds */
static bool test_compound_find_close(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *dname = "compound_find_dir";
	struct smb2_create create;
	struct smb2_find f;
	struct smb2_handle h;
	struct smb2_request *req = NULL;
	const int num_files = 5000;
	int i;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, dname);

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_DIR_ALL;
	create.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	create.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				 NTCREATEX_SHARE_ACCESS_WRITE |
				 NTCREATEX_SHARE_ACCESS_DELETE;
	create.in.create_disposition = NTCREATEX_DISP_CREATE;
	create.in.fname = dname;

	smb2cli_conn_set_max_credits(tree->session->transport->conn, 256);

	status = smb2_create(tree, mem_ctx, &create);
	h = create.out.file.handle;

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.create_disposition = NTCREATEX_DISP_CREATE;

	for (i = 0; i < num_files; i++) {
		create.in.fname = talloc_asprintf(mem_ctx, "%s\\file%d",
						  dname, i);
		status = smb2_create(tree, mem_ctx, &create);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "");
		smb2_util_close(tree, create.out.file.handle);
	}

	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed\n");

	ZERO_STRUCT(f);
	f.in.file.handle	= h;
	f.in.pattern		= "*";
	f.in.max_response_size	= 8*1024*1024;
	f.in.level              = SMB2_FIND_BOTH_DIRECTORY_INFO;

	req = smb2_find_send(tree, &f);

	status = smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_util_close failed\n");

	status = smb2_find_recv(req, mem_ctx, &f);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_find_recv failed\n");

done:
	smb2_util_close(tree, h);
	smb2_deltree(tree, dname);
	TALLOC_FREE(mem_ctx);
	return ret;
}

/* Test compound unrelated finds */
static bool test_compound_find_unrelated(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *dname = "compound_find_dir";
	struct smb2_create create;
	struct smb2_find f;
	struct smb2_handle h;
	struct smb2_request *req[2];
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, dname);

	ZERO_STRUCT(create);
	create.in.desired_access = SEC_RIGHTS_DIR_ALL;
	create.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	create.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				 NTCREATEX_SHARE_ACCESS_WRITE |
				 NTCREATEX_SHARE_ACCESS_DELETE;
	create.in.create_disposition = NTCREATEX_DISP_CREATE;
	create.in.fname = dname;

	status = smb2_create(tree, mem_ctx, &create);
	h = create.out.file.handle;

	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed\n");

	smb2_transport_compound_start(tree->session->transport, 2);

	ZERO_STRUCT(f);
	f.in.file.handle	= h;
	f.in.pattern		= "*";
	f.in.max_response_size	= 0x100;
	f.in.level              = SMB2_FIND_BOTH_DIRECTORY_INFO;

	req[0] = smb2_find_send(tree, &f);
	req[1] = smb2_find_send(tree, &f);

	status = smb2_find_recv(req[0], mem_ctx, &f);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_find_recv failed\n");

	status = smb2_find_recv(req[1], mem_ctx, &f);
	torture_assert_ntstatus_equal_goto(tctx, status, STATUS_NO_MORE_FILES, ret, done, "smb2_find_recv failed\n");

done:
	smb2_util_close(tree, h);
	smb2_deltree(tree, dname);
	TALLOC_FREE(mem_ctx);
	return ret;
}

static bool test_compound_async_flush_close(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	struct smb2_handle fhandle = { .data = { 0, 0 } };
	struct smb2_handle relhandle = { .data = { UINT64_MAX, UINT64_MAX } };
	struct smb2_close cl;
	struct smb2_flush fl;
	const char *fname = "compound_async_flush_close";
	struct smb2_request *req[2];
	NTSTATUS status;
	bool ret = false;

	/* Start clean. */
	smb2_util_unlink(tree, fname);

	/* Create a file. */
	status = torture_smb2_testfile_access(tree,
					      fname,
					      &fhandle,
					      SEC_RIGHTS_FILE_ALL);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Now do a compound flush + close handle. */
	smb2_transport_compound_start(tree->session->transport, 2);

	ZERO_STRUCT(fl);
	fl.in.file.handle = fhandle;

	req[0] = smb2_flush_send(tree, &fl);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
		"smb2_flush_send failed\n");

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(cl);
	cl.in.file.handle = relhandle;
	req[1] = smb2_close_send(tree, &cl);
	torture_assert_not_null_goto(tctx, req[1], ret, done,
		"smb2_close_send failed\n");

	status = smb2_flush_recv(req[0], &fl);
	/*
	 * On Windows, this flush will usually
	 * succeed as we have nothing to flush,
	 * so allow NT_STATUS_OK. Once bug #15172
	 * is fixed Samba will do the flush synchronously
	 * so allow NT_STATUS_OK.
	 */
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * If we didn't get NT_STATUS_OK, we *must*
		 * get NT_STATUS_INTERNAL_ERROR if the flush
		 * goes async.
		 *
		 * For pre-bugfix #15172 Samba, the flush goes async and
		 * we should get NT_STATUS_INTERNAL_ERROR.
		 */
		torture_assert_ntstatus_equal_goto(tctx,
			status,
			NT_STATUS_INTERNAL_ERROR,
			ret,
			done,
			"smb2_flush_recv didn't return "
			"NT_STATUS_INTERNAL_ERROR.\n");
	}
	status = smb2_close_recv(req[1], &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"smb2_close_recv failed.");

	ZERO_STRUCT(fhandle);

	/*
	 * Do several more operations on the tree, spaced
	 * out by 1 sec sleeps to make sure the server didn't
	 * crash on the close. The sleeps are required to
	 * make test test for a crash reliable, as we ensure
	 * the pthread fsync internally finishes and accesses
	 * freed memory. Without them the test occasionally
	 * passes as we disconnect before the pthread fsync
	 * finishes.
	 */
	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

	sleep(1);
	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	sleep(1);
	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	ret = true;

  done:

	if (fhandle.data[0] != 0) {
		smb2_util_close(tree, fhandle);
	}

	smb2_util_unlink(tree, fname);
	return ret;
}

static bool test_compound_async_flush_flush(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	struct smb2_handle fhandle = { .data = { 0, 0 } };
	struct smb2_handle relhandle = { .data = { UINT64_MAX, UINT64_MAX } };
	struct smb2_flush fl1;
	struct smb2_flush fl2;
	const char *fname = "compound_async_flush_flush";
	struct smb2_request *req[2];
	NTSTATUS status;
	bool ret = false;

	/* Start clean. */
	smb2_util_unlink(tree, fname);

	/* Create a file. */
	status = torture_smb2_testfile_access(tree,
					      fname,
					      &fhandle,
					      SEC_RIGHTS_FILE_ALL);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Now do a compound flush + flush handle. */
	smb2_transport_compound_start(tree->session->transport, 2);

	ZERO_STRUCT(fl1);
	fl1.in.file.handle = fhandle;

	req[0] = smb2_flush_send(tree, &fl1);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
		"smb2_flush_send (1) failed\n");

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(fl2);
	fl2.in.file.handle = relhandle;

	req[1] = smb2_flush_send(tree, &fl2);
	torture_assert_not_null_goto(tctx, req[1], ret, done,
		"smb2_flush_send (2) failed\n");

	status = smb2_flush_recv(req[0], &fl1);
	/*
	 * On Windows, this flush will usually
	 * succeed as we have nothing to flush,
	 * so allow NT_STATUS_OK. Once bug #15172
	 * is fixed Samba will do the flush synchronously
	 * so allow NT_STATUS_OK.
	 */
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * If we didn't get NT_STATUS_OK, we *must*
		 * get NT_STATUS_INTERNAL_ERROR if the flush
		 * goes async.
		 *
		 * For pre-bugfix #15172 Samba, the flush goes async and
		 * we should get NT_STATUS_INTERNAL_ERROR.
		 */
		torture_assert_ntstatus_equal_goto(tctx,
			status,
			NT_STATUS_INTERNAL_ERROR,
			ret,
			done,
			"smb2_flush_recv (1) didn't return "
			"NT_STATUS_INTERNAL_ERROR.\n");
	}

	/*
	 * If the flush is the last entry in a compound,
	 * it should always succeed even if it goes async.
	 */
	status = smb2_flush_recv(req[1], &fl2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_flush_recv (2) failed.");

	status = smb2_util_close(tree, fhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_util_close failed.");
	ZERO_STRUCT(fhandle);

	/*
	 * Do several more operations on the tree, spaced
	 * out by 1 sec sleeps to make sure the server didn't
	 * crash on the close. The sleeps are required to
	 * make test test for a crash reliable, as we ensure
	 * the pthread fsync internally finishes and accesses
	 * freed memory. Without them the test occasionally
	 * passes as we disconnect before the pthread fsync
	 * finishes.
	 */
	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

	sleep(1);
	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	sleep(1);
	status = smb2_util_unlink(tree, fname);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	ret = true;

  done:

	if (fhandle.data[0] != 0) {
		smb2_util_close(tree, fhandle);
	}

	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * For Samba/smbd this test must be run against the aio_delay_inject share
 * as we need to ensure the last write in the compound takes longer than
 * 500 us, which is the threshold for going async in smbd SMB2 writes.
 */

static bool test_compound_async_write_write(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	struct smb2_handle fhandle = { .data = { 0, 0 } };
	struct smb2_handle relhandle = { .data = { UINT64_MAX, UINT64_MAX } };
	struct smb2_write w1;
	struct smb2_write w2;
	const char *fname = "compound_async_write_write";
	struct smb2_request *req[2];
	NTSTATUS status;
	bool is_smbd = torture_setting_bool(tctx, "smbd", true);
	bool ret = false;

	/* Start clean. */
	smb2_util_unlink(tree, fname);

	/* Create a file. */
	status = torture_smb2_testfile_access(tree,
					      fname,
					      &fhandle,
					      SEC_RIGHTS_FILE_ALL);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Now do a compound write + write handle. */
	smb2_transport_compound_start(tree->session->transport, 2);

	ZERO_STRUCT(w1);
	w1.in.file.handle = fhandle;
	w1.in.offset = 0;
	w1.in.data = data_blob_talloc_zero(tctx, 64);
	req[0] = smb2_write_send(tree, &w1);

	torture_assert_not_null_goto(tctx, req[0], ret, done,
		"smb2_write_send (1) failed\n");

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(w2);
	w2.in.file.handle = relhandle;
	w2.in.offset = 64;
	w2.in.data = data_blob_talloc_zero(tctx, 64);
	req[1] = smb2_write_send(tree, &w2);

	torture_assert_not_null_goto(tctx, req[0], ret, done,
		"smb2_write_send (2) failed\n");

	status = smb2_write_recv(req[0], &w1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_write_recv (1) failed.");

	if (!is_smbd) {
		/*
		 * Windows and other servers don't go async.
		 */
		status = smb2_write_recv(req[1], &w2);
	} else {
		/*
		 * For smbd, the second write should go async
		 * as it's the last element of a compound.
		 */
		WAIT_FOR_ASYNC_RESPONSE(req[1]);
		CHECK_VAL(req[1]->cancel.can_cancel, true);
		/*
		 * Now pick up the real return.
		 */
		status = smb2_write_recv(req[1], &w2);
	}

	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_write_recv (2) failed.");

	status = smb2_util_close(tree, fhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_util_close failed.");
	ZERO_STRUCT(fhandle);

	ret = true;

  done:

	if (fhandle.data[0] != 0) {
		smb2_util_close(tree, fhandle);
	}

	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * For Samba/smbd this test must be run against the aio_delay_inject share
 * as we need to ensure the last read in the compound takes longer than
 * 500 us, which is the threshold for going async in smbd SMB2 reads.
 */

static bool test_compound_async_read_read(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	struct smb2_handle fhandle = { .data = { 0, 0 } };
	struct smb2_handle relhandle = { .data = { UINT64_MAX, UINT64_MAX } };
	struct smb2_write w;
	struct smb2_read r1;
	struct smb2_read r2;
	const char *fname = "compound_async_read_read";
	struct smb2_request *req[2];
	NTSTATUS status;
	bool is_smbd = torture_setting_bool(tctx, "smbd", true);
	bool ret = false;

	/* Start clean. */
	smb2_util_unlink(tree, fname);

	/* Create a file. */
	status = torture_smb2_testfile_access(tree,
					      fname,
					      &fhandle,
					      SEC_RIGHTS_FILE_ALL);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Write 128 bytes. */
	ZERO_STRUCT(w);
	w.in.file.handle = fhandle;
	w.in.offset = 0;
	w.in.data = data_blob_talloc_zero(tctx, 128);
	status = smb2_write(tree, &w);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_write_recv (1) failed.");

	/* Now do a compound read + read handle. */
	smb2_transport_compound_start(tree->session->transport, 2);

	ZERO_STRUCT(r1);
	r1.in.file.handle = fhandle;
	r1.in.length      = 64;
	r1.in.offset      = 0;
	req[0] = smb2_read_send(tree, &r1);

	torture_assert_not_null_goto(tctx, req[0], ret, done,
		"smb2_read_send (1) failed\n");

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(r2);
	r2.in.file.handle = relhandle;
	r2.in.length      = 64;
	r2.in.offset      = 64;
	req[1] = smb2_read_send(tree, &r2);

	torture_assert_not_null_goto(tctx, req[0], ret, done,
		"smb2_read_send (2) failed\n");

	status = smb2_read_recv(req[0], tree, &r1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_read_recv (1) failed.");

	if (!is_smbd) {
		/*
		 * Windows and other servers don't go async.
		 */
		status = smb2_read_recv(req[1], tree, &r2);
	} else {
		/*
		 * For smbd, the second write should go async
		 * as it's the last element of a compound.
		 */
		WAIT_FOR_ASYNC_RESPONSE(req[1]);
		CHECK_VAL(req[1]->cancel.can_cancel, true);
		/*
		 * Now pick up the real return.
		 */
		status = smb2_read_recv(req[1], tree, &r2);
	}

	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_read_recv (2) failed.");

	status = smb2_util_close(tree, fhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_util_close failed.");
	ZERO_STRUCT(fhandle);

	ret = true;

  done:

	if (fhandle.data[0] != 0) {
		smb2_util_close(tree, fhandle);
	}

	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * Checks a lease break by a create triggers an pending async response.
 */
static bool test_create_lease_break_async(struct torture_context *tctx,
					  struct smb2_tree *tree1,
					  struct smb2_tree *tree2)
{
	struct smb2_request *req = NULL;
	struct smb2_create c1 = {};
	struct smb2_create c2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_lease_break_ack ack = {};
	const char *fname_src = "test_create_lease_break_async.dat";
	uint32_t caps;
	NTSTATUS status;
	bool ret = true;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree1, fname_src);

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	/* First open with a RWH lease. */
	smb2_lease_create(&c1,
			  &ls1,
			  false,
			  fname_src,
			  LEASE1,
			  smb2_util_lease_state("RWH"));

	status = smb2_create(tree1, tree1, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	CHECK_LEASE(&c1, "RWH", true, LEASE1, 0);
	h1 = c1.out.file.handle;

	/* Second open, triggers lease break to "RH" */

	smb2_lease_create(&c2,
			  &ls2,
			  false,
			  fname_src,
			  LEASE2,
			  smb2_util_lease_state("RH"));

	req = smb2_create_send(tree2, &c2);
	torture_assert_not_null_goto(tctx, req, ret, done,
				     "smb2_create_send failed\n");

	/*
	 * Check we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO("RWH", "RH", LEASE1);

	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Wait for STATUS_PENDING response */
	WAIT_FOR_ASYNC_RESPONSE(req);
	torture_assert_goto(tctx, req->cancel.can_cancel, ret, done, "pending");

	status = smb2_lease_break_ack(tree1, &ack);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lease_break_ack failed\n");
	CHECK_LEASE_BREAK_ACK(&ack, "RH", LEASE1);


	status = smb2_create_recv(req, tree2, &c2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create_recv failed\n");
	h2 = c2.out.file.handle;

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}

	smb2_util_unlink(tree1, fname_src);

	return ret;
}

/*
 * Basic test compound related CREATE+GETINFO+CLOSE where
 * the CREATE triggers a lease break. Verifies CREATE sees
 * an async interim response.
 */
static bool test_compound_getinfo_middle(struct torture_context *tctx,
					 struct smb2_tree *tree1,
					 struct smb2_tree *tree2)
{
	struct smb2_create c1 = {};
	struct smb2_create c2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_handle h1 = {};
	struct smb2_request *req[3] = {};
	union smb_fileinfo info = {};
	struct smb2_getinfo rinfo = {};
	struct smb2_lease_break_ack ack = {};
	struct smb2_close cl = {};
	const char *fname_src = "test_compound_getinfo_middle.dat";
	uint32_t caps;
	NTSTATUS status;
	bool ret = true;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree1, fname_src);

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	/* First open with a RWH lease. */
	smb2_lease_create(&c1,
			  &ls1,
			  false,
			  fname_src,
			  LEASE1,
			  smb2_util_lease_state("RWH"));

	status = smb2_create(tree1, tree1, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	CHECK_LEASE(&c1, "RWH", true, LEASE1, 0);
	h1 = c1.out.file.handle;

	/* Second open, triggers a lease break */

	smb2_transport_compound_start(tree2->session->transport, 3);

	smb2_lease_create(&c2,
			  NULL,
			  false,
			  fname_src,
			  0,
			  smb2_util_lease_state(""));
	req[0] = smb2_create_send(tree2, &c2);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
				     "smb2_create_send failed\n");

	smb2_transport_compound_set_related(tree2->session->transport, true);

	ZERO_STRUCT(info);
	info.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	info.generic.in.file.handle.data[0] = UINT64_MAX;
	info.generic.in.file.handle.data[0] = UINT64_MAX;
	req[1] = smb2_getinfo_file_send(tree2, &info);
	torture_assert(tctx, req[1] != NULL, "smb2_setinfo_file_send");

	cl.in.file.handle.data[0] = UINT64_MAX;
	cl.in.file.handle.data[1] = UINT64_MAX;

	req[2] = smb2_close_send(tree2, &cl);
	torture_assert(tctx, req[2] != NULL, "smb2_close_send");

	/*
	 * Check we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO("RWH", "RH", LEASE1);

	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Wait for async response */
	WAIT_FOR_ASYNC_RESPONSE(req[0]);

	torture_assert_goto(tctx, req[0]->state == SMB2_REQUEST_RECV, ret, done,
			    "smb2_create finished");
	torture_assert_goto(tctx, req[1]->state == SMB2_REQUEST_RECV, ret, done,
			    "smb2_getinfo finished");
	torture_assert_goto(tctx, req[2]->state == SMB2_REQUEST_RECV, ret, done,
			    "smb2_close finished");
	torture_assert_goto(tctx, req[0]->cancel.can_cancel, ret, done, "pending");
	torture_assert_goto(tctx, !req[1]->cancel.can_cancel, ret, done, "pending");
	torture_assert_goto(tctx, !req[2]->cancel.can_cancel, ret, done, "pending");

	status = smb2_lease_break_ack(tree1, &ack);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lease_break_ack failed\n");
	CHECK_LEASE_BREAK_ACK(&ack, "RH", LEASE1);

	status = smb2_create_recv(req[0], tree2, &c2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create_recv failed\n");

	status = smb2_getinfo_recv(req[1], tree2, &rinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_recv failed\n");

	status = smb2_close_recv(req[2], &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_close_recv failed\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	smb2_util_unlink(tree1, fname_src);

	return ret;
}

/*
 * Checks a lease break by a rename where src and dst name are the same does not
 * trigger a pending async response, but does trigger a h-lease break.
 */
static bool test_rename_same_srcdst_non_compound_no_async(
	struct torture_context *tctx,
	struct smb2_tree *tree1,
	struct smb2_tree *tree2)
{
	struct smb2_create c1 = {};
	struct smb2_create c2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_request *req = NULL;
	struct smb2_lease_break_ack ack = {};
	union smb_setfileinfo sinfo = {};
	const char *fname_src = "test_rename_non_compound_no_async.dat";
	const char *fname_dst = "test_rename_non_compound_no_async.dat";
	uint32_t caps;
	NTSTATUS status;
	bool ret = true;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree1, fname_src);
	smb2_util_unlink(tree1, fname_dst);

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	/* First open with a RH lease. */
	smb2_lease_create(&c1,
			  &ls1,
			  false,
			  fname_src,
			  LEASE1,
			  smb2_util_lease_state("RH"));

	status = smb2_create(tree1, tree1, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	CHECK_LEASE(&c1, "RH", true, LEASE1, 0);
	h1 = c1.out.file.handle;

	/* Second open, also with a RH lease, this will do the rename */

	smb2_lease_create(&c2,
			  &ls2,
			  false,
			  fname_src,
			  LEASE2,
			  smb2_util_lease_state("RH"));
	status = smb2_create(tree2, tree2, &c2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	CHECK_LEASE(&c2, "RH", true, LEASE2, 0);
	h2 = c2.out.file.handle;

	/* Break with a rename. */
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h2;
	sinfo.rename_information.in.new_name = fname_dst;
	req = smb2_setinfo_file_send(tree2, &sinfo);
	torture_assert(tctx, req != NULL, "smb2_setinfo_file_send");

	/*
	 * Check we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO("RH", "R", LEASE1);

	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Give the server enough time to possibly send a pending response */
	smb_msleep(1000);

	status = smb2_lease_break_ack(tree1, &ack);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lease_break_ack failed\n");
	CHECK_LEASE_BREAK_ACK(&ack, "R", LEASE1);

	/*
	 * Sending the lease break ACK would have also read the
	 * NT_STATUS_PENDING interim response if any, but a Windows server
	 * doesn't send one, check this. This is in contract to a lease break
	 * triggered by an SMB2-CREATE.
	 */
	torture_assert_goto(tctx, !req->cancel.can_cancel, ret, done, "pending");

	/* Get the rename reply. */
	status = smb2_setinfo_recv(req);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_recv failed\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}

	smb2_util_unlink(tree1, fname_src);
	smb2_util_unlink(tree1, fname_dst);

	return ret;
}

/*
 * Checks a lease break by a rename does not trigger a pending async response.
 */
static bool test_rename_non_compound_no_async(struct torture_context *tctx,
					      struct smb2_tree *tree1,
					      struct smb2_tree *tree2)
{
	struct smb2_create c1 = {};
	struct smb2_create c2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_request *req = NULL;
	struct smb2_lease_break_ack ack = {};
	union smb_setfileinfo sinfo = {};
	const char *fname_src = "test_rename_non_compound_no_async_src.dat";
	const char *fname_dst = "test_rename_non_compound_no_async_dst.dat";
	uint32_t caps;
	NTSTATUS status;
	bool ret = true;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree1, fname_src);
	smb2_util_unlink(tree1, fname_dst);

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	/* First open with a RH lease. */
	smb2_lease_create(&c1,
			  &ls1,
			  false,
			  fname_src,
			  LEASE1,
			  smb2_util_lease_state("RH"));

	status = smb2_create(tree1, tree1, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	CHECK_LEASE(&c1, "RH", true, LEASE1, 0);
	h1 = c1.out.file.handle;

	/* Second open, also with a RH lease, this will to the rename */

	smb2_lease_create(&c2,
			  &ls2,
			  false,
			  fname_src,
			  LEASE2,
			  smb2_util_lease_state("RH"));
	status = smb2_create(tree2, tree2, &c2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	CHECK_LEASE(&c2, "RH", true, LEASE2, 0);
	h2 = c2.out.file.handle;

	/* Break with a rename. */
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h2;
	sinfo.rename_information.in.new_name = fname_dst;
	req = smb2_setinfo_file_send(tree2, &sinfo);
	torture_assert(tctx, req != NULL, "smb2_setinfo_file_send");

	/*
	 * Check we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO("RH", "R", LEASE1);

	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Give the server enough time to possibly send a pending response */
	smb_msleep(1000);

	status = smb2_lease_break_ack(tree1, &ack);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lease_break_ack failed\n");
	CHECK_LEASE_BREAK_ACK(&ack, "R", LEASE1);

	/*
	 * Sending the lease break ACK would have also read the
	 * NT_STATUS_PENDING interim response if any, but a Windows server
	 * doesn't send one, check this. This is in contract to a lease break
	 * triggered by an SMB2-CREATE.
	 */
	torture_assert_goto(tctx, !req->cancel.can_cancel, ret, done, "pending");

	/* Get the rename reply. */
	status = smb2_setinfo_recv(req);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_recv failed\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}

	smb2_util_unlink(tree1, fname_src);
	smb2_util_unlink(tree1, fname_dst);

	return ret;
}

/*
 * Test a compound SMB2-CREATE+SMB2-SETINFO(rename) works and doesn't trigger a
 * pending async response.
 */
static bool test_compound_rename_last(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	struct smb2_create c1 = {};
	struct smb2_create c2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_request *req[2] = {};
	union smb_setfileinfo sinfo = {};
	struct smb2_lease_break_ack ack = {};
	const char *fname_src = "test_compound_rename_last_src.dat";
	const char *fname_dst = "test_compound_rename_last_dst.dat";
	uint32_t caps;
	NTSTATUS status;
	bool ret = true;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree1, fname_src);
	smb2_util_unlink(tree1, fname_dst);

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	/* First open with a RH lease. */
	smb2_lease_create(&c1,
			  &ls1,
			  false,
			  fname_src,
			  LEASE1,
			  smb2_util_lease_state("RH"));

	status = smb2_create(tree1, tree1, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	CHECK_LEASE(&c1, "RH", true, LEASE1, 0);
	h1 = c1.out.file.handle;

	/* Second open, also with a RH lease, this will to the rename */

	smb2_transport_compound_start(tree2->session->transport, 2);

	smb2_lease_create(&c2,
			  &ls2,
			  false,
			  fname_src,
			  LEASE2,
			  smb2_util_lease_state(""));
	req[0] = smb2_create_send(tree2, &c2);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
				     "smb2_create_send failed\n");

	smb2_transport_compound_set_related(tree2->session->transport, true);

	/* Break with a rename. */
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle.data[0] = UINT64_MAX;
	sinfo.rename_information.in.file.handle.data[1] = UINT64_MAX;
	sinfo.rename_information.in.new_name = fname_dst;
	req[1] = smb2_setinfo_file_send(tree2, &sinfo);
	torture_assert(tctx, req[1] != NULL, "smb2_setinfo_file_send");

	/*
	 * Check we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO("RH", "R", LEASE1);

	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Give the server enough time to possibly send a pending response */
	smb_msleep(1000);

	status = smb2_lease_break_ack(tree1, &ack);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lease_break_ack failed\n");
	CHECK_LEASE_BREAK_ACK(&ack, "R", LEASE1);

	/*
	 * Sending the lease break ACK would have also read the
	 * NT_STATUS_PENDING interim response if any, but a Windows server
	 * doesn't send one, check this. This is in contract to a lease break
	 * triggered by an SMB2-CREATE.
	 */
	torture_assert_goto(tctx, req[0]->state == SMB2_REQUEST_RECV, ret, done,
			    "state not SMB2_REQUEST_RECV");
	torture_assert_goto(tctx, req[1]->state == SMB2_REQUEST_RECV, ret, done,
			    "state not SMB2_REQUEST_RECV");
	torture_assert_goto(tctx, !req[1]->cancel.can_cancel, ret, done, "pending");

	status = smb2_create_recv(req[0], tree2, &c2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_recv failed\n");
	h2 = c2.out.file.handle;

	/* Get the rename reply. */
	status = smb2_setinfo_recv(req[1]);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_recv failed\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}

	smb2_util_unlink(tree1, fname_src);
	smb2_util_unlink(tree1, fname_dst);

	return ret;
}

/*
 * Compound related CREATE + SETINFO(rename) + CLOSE, rename triggers a lease
 * break. Verify we don't get an async interim response for the SETINFO and all
 * responses are received in a single compound response.
 */
static bool test_compound_rename_middle(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	struct smb2_create c1 = {};
	struct smb2_create c2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_handle h1 = {};
	struct smb2_request *req[3] = {};
	union smb_setfileinfo sinfo = {};
	struct smb2_lease_break_ack ack = {};
	struct smb2_close cl = {};
	const char *fname_src = "test_compound_rename_middle_src.dat";
	const char *fname_dst = "test_compound_rename_middle_dst.dat";
	uint32_t caps;
	NTSTATUS status;
	bool ret = true;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree1, fname_src);
	smb2_util_unlink(tree1, fname_dst);

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	/* First open with a RH lease. */
	smb2_lease_create(&c1,
			  &ls1,
			  false,
			  fname_src,
			  LEASE1,
			  smb2_util_lease_state("RH"));

	status = smb2_create(tree1, tree1, &c1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	CHECK_LEASE(&c1, "RH", true, LEASE1, 0);
	h1 = c1.out.file.handle;

	/* Second open, this will to the rename */

	smb2_transport_compound_start(tree2->session->transport, 3);

	smb2_lease_create(&c2,
			  NULL,
			  false,
			  fname_src,
			  0,
			  smb2_util_lease_state(""));
	req[0] = smb2_create_send(tree2, &c2);
	torture_assert_not_null_goto(tctx, req[0], ret, done,
				     "smb2_create_send failed\n");

	smb2_transport_compound_set_related(tree2->session->transport, true);

	/* Break with a rename. */
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle.data[0] = UINT64_MAX;
	sinfo.rename_information.in.file.handle.data[1] = UINT64_MAX;
	sinfo.rename_information.in.new_name = fname_dst;
	req[1] = smb2_setinfo_file_send(tree2, &sinfo);
	torture_assert(tctx, req[1] != NULL, "smb2_setinfo_file_send");

	cl.in.file.handle.data[0] = UINT64_MAX;
	cl.in.file.handle.data[1] = UINT64_MAX;

	req[2] = smb2_close_send(tree2, &cl);
	torture_assert(tctx, req[2] != NULL, "smb2_close_send");

	/* Give the server enough time to possibly send a pending response */
	smb_msleep(1000);

	/*
	 * Check we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO("RH", "R", LEASE1);

	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	torture_assert_goto(tctx, !req[0]->cancel.can_cancel, ret, done, "pending");
	torture_assert_goto(tctx, !req[1]->cancel.can_cancel, ret, done, "pending");
	torture_assert_goto(tctx, !req[2]->cancel.can_cancel, ret, done, "pending");
	torture_assert_goto(tctx, req[0]->state == SMB2_REQUEST_RECV, ret, done,
			    "state not SMB2_REQUEST_RECV");
	torture_assert_goto(tctx, req[1]->state == SMB2_REQUEST_RECV, ret, done,
			    "state not SMB2_REQUEST_RECV");
	torture_assert_goto(tctx, req[2]->state == SMB2_REQUEST_RECV, ret, done,
			    "state not SMB2_REQUEST_RECV");

	status = smb2_lease_break_ack(tree1, &ack);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lease_break_ack failed\n");
	CHECK_LEASE_BREAK_ACK(&ack, "R", LEASE1);


	status = smb2_create_recv(req[0], tree2, &c2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_recv failed\n");

	/* Get the rename reply. */
	status = smb2_setinfo_recv(req[1]);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_recv failed\n");

	status = smb2_close_recv(req[2], &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_recv failed\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}

	smb2_util_unlink(tree1, fname_src);
	smb2_util_unlink(tree1, fname_dst);

	return ret;
}

struct torture_suite *torture_smb2_compound_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "compound");

	torture_suite_add_1smb2_test(suite, "related1", test_compound_related1);
	torture_suite_add_1smb2_test(suite, "related2", test_compound_related2);
	torture_suite_add_1smb2_test(suite, "related3",
				     test_compound_related3);
	torture_suite_add_1smb2_test(suite, "related4",
				     test_compound_related4);
	torture_suite_add_1smb2_test(suite, "related5",
				     test_compound_related5);
	torture_suite_add_1smb2_test(suite, "related6",
				     test_compound_related6);
	torture_suite_add_1smb2_test(suite, "related7",
				     test_compound_related7);
	torture_suite_add_1smb2_test(suite, "related8",
				     test_compound_related8);
	torture_suite_add_1smb2_test(suite, "related9",
				     test_compound_related9);
	torture_suite_add_1smb2_test(suite, "unrelated1", test_compound_unrelated1);
	torture_suite_add_1smb2_test(suite, "invalid1", test_compound_invalid1);
	torture_suite_add_1smb2_test(suite, "invalid2", test_compound_invalid2);
	torture_suite_add_1smb2_test(suite, "invalid3", test_compound_invalid3);
	torture_suite_add_1smb2_test(
		suite, "invalid4", test_compound_invalid4);
	torture_suite_add_1smb2_test(suite, "interim1",  test_compound_interim1);
	torture_suite_add_1smb2_test(suite, "interim2",  test_compound_interim2);
	torture_suite_add_1smb2_test(suite, "interim3",  test_compound_interim3);
	torture_suite_add_1smb2_test(suite, "compound-break", test_compound_break);
	torture_suite_add_1smb2_test(suite, "compound-padding", test_compound_padding);
	torture_suite_add_1smb2_test(suite, "create-write-close",
				     test_compound_create_write_close);

	suite->description = talloc_strdup(suite, "SMB2-COMPOUND tests");

	return suite;
}

struct torture_suite *torture_smb2_compound_find_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "compound_find");

	torture_suite_add_1smb2_test(suite, "compound_find_related", test_compound_find_related);
	torture_suite_add_1smb2_test(suite, "compound_find_unrelated", test_compound_find_unrelated);
	torture_suite_add_1smb2_test(suite, "compound_find_close", test_compound_find_close);

	suite->description = talloc_strdup(suite, "SMB2-COMPOUND-FIND tests");

	return suite;
}

struct torture_suite *torture_smb2_compound_async_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx,
					"compound_async");

	torture_suite_add_1smb2_test(suite, "flush_close",
		test_compound_async_flush_close);
	torture_suite_add_1smb2_test(suite, "flush_flush",
		test_compound_async_flush_flush);
	torture_suite_add_1smb2_test(suite, "write_write",
		test_compound_async_write_write);
	torture_suite_add_1smb2_test(suite, "read_read",
		test_compound_async_read_read);
	torture_suite_add_2smb2_test(suite, "create_lease_break_async",
		test_create_lease_break_async);
	torture_suite_add_2smb2_test(suite, "getinfo_middle",
		test_compound_getinfo_middle);
	torture_suite_add_2smb2_test(suite, "rename_same_srcdst_non_compound_no_async",
		test_rename_same_srcdst_non_compound_no_async);
	torture_suite_add_2smb2_test(suite, "rename_non_compound_no_async",
		test_rename_non_compound_no_async);
	torture_suite_add_2smb2_test(suite, "rename_last",
		test_compound_rename_last);
	torture_suite_add_2smb2_test(suite, "rename_middle",
		test_compound_rename_middle);

	suite->description = talloc_strdup(suite, "SMB2-COMPOUND-ASYNC tests");

	return suite;
}
