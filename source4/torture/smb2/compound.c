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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "../libcli/smb/smbXcli_base.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": Incorrect status %s - should be %s", \
		       nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
		    "(%s) Incorrect value %s=%d - should be %d\n", \
		    __location__, #v, (int)v, (int)correct); \
		ret = false; \
	}} while (0)

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

static bool test_compound_padding(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	struct smb2_handle h;
	struct smb2_create cr;
	struct smb2_read r;
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
	smb2_transport_compound_start(tree->session->transport, 2);

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

	ZERO_STRUCT(r);
	h.data[0] = UINT64_MAX;
	h.data[1] = UINT64_MAX;
	r.in.file.handle = h;
	r.in.length      = 3;
	r.in.offset      = 0;
	r.in.min_count      = 1;
	req[1] = smb2_read_send(tree, &r);

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
	CHECK_VALUE(req[1]->in.body_size, 24);

	status = smb2_read_recv(req[1], tree, &r);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, cr.out.file.handle);

	/* Check compound read from stream */
	smb2_transport_compound_start(tree->session->transport, 2);

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

	ZERO_STRUCT(r);
	h.data[0] = UINT64_MAX;
	h.data[1] = UINT64_MAX;
	r.in.file.handle = h;
	r.in.length      = 3;
	r.in.offset      = 0;
	r.in.min_count   = 1;
	req[1] = smb2_read_send(tree, &r);

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
	CHECK_VALUE(req[1]->in.body_size, 24);

	status = smb2_read_recv(req[1], tree, &r);
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
	CHECK_VALUE(req[0]->in.body_size, 24);
	CHECK_VALUE(req[1]->in.body_size, 24);

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
	CHECK_VALUE(req[0]->in.body_size, 19);

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

struct torture_suite *torture_smb2_compound_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "compound");

	torture_suite_add_1smb2_test(suite, "related1", test_compound_related1);
	torture_suite_add_1smb2_test(suite, "related2", test_compound_related2);
	torture_suite_add_1smb2_test(suite, "related3",
				     test_compound_related3);
	torture_suite_add_1smb2_test(suite, "unrelated1", test_compound_unrelated1);
	torture_suite_add_1smb2_test(suite, "invalid1", test_compound_invalid1);
	torture_suite_add_1smb2_test(suite, "invalid2", test_compound_invalid2);
	torture_suite_add_1smb2_test(suite, "invalid3", test_compound_invalid3);
	torture_suite_add_1smb2_test(
		suite, "invalid4", test_compound_invalid4);
	torture_suite_add_1smb2_test(suite, "interim1",  test_compound_interim1);
	torture_suite_add_1smb2_test(suite, "interim2",  test_compound_interim2);
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
