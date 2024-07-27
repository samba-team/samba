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
#include "torture/torture.h"

#include "lib/cmdline/cmdline.h"
#include "lib/param/param.h"
#include "libcli/resolve/resolve.h"
#include "libcli/smb/smbXcli_base.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "torture/smb2/proto.h"
#include "util/tevent_ntstatus.h"

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

static bool test_crediting_skipped_mid(struct torture_context *tctx,
				       struct smb2_tree *_tree)
{
	struct smbcli_options options;
	struct smb2_transport *transport = NULL;
	struct smb2_tree *tree = NULL;
	struct smb2_handle h = {{0}};
	struct smb2_create create;
	const char *fname = "skipped_mid.dat";
	uint64_t mid;
	uint16_t cur_credits;
	NTSTATUS status;
	bool ret = true;
	int i;

	smb2_util_unlink(_tree, fname);

	transport = _tree->session->transport;
	options = transport->options;

	status = smb2_logoff(_tree->session);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_logoff failed\n");
	TALLOC_FREE(_tree);

	options.max_credits = 8192;

	ret = torture_smb2_connection_ext(tctx, 0, &options, &tree);
	torture_assert_goto(tctx, ret == true, ret, done, "torture_smb2_connection_ext failed\n");

	transport = tree->session->transport;

	cur_credits = smb2cli_conn_get_cur_credits(transport->conn);
	if (cur_credits != 8192) {
		torture_result(tctx, TORTURE_FAIL, "Server only granted %" PRIu16" credits\n", cur_credits);
		ret = false;
		goto done;
	}

	ZERO_STRUCT(create);
	create.in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	create.in.desired_access	= SEC_RIGHTS_FILE_ALL;
	create.in.file_attributes	= FILE_ATTRIBUTE_NORMAL;
	create.in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	create.in.fname			= fname;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create failed\n");
	h = create.out.file.handle;

	/*
	 * See what happens if we skip a mid. As we want to avoid triggering our
	 * client side mid window check we keep conn->smb2.cur_credits
	 * unchanged so the server keeps granting credits until it's max mid
	 * windows size is reached at which point it will disconnect us:
	 *
	 * o Windows 2016 currently has a maximum mid window size of 8192 by
	 *   default
	 *
	 * o Samba's limit is 512
	 *
	 * o Windows 2008r2 uses some special algorithm (MS-SMB2 3.3.1.1
	 *   footnote <167>) that kicks in once a mid is skipped, resulting in a
	 *   maximum window size of 100-300 depending on the number of granted
	 *   credits at the moment of skipping a mid.
	 */

	mid = smb2cli_conn_get_mid(tree->session->transport->conn);
	smb2cli_conn_set_mid(tree->session->transport->conn, mid + 1);

	for (i = 0; i < 8191; i++) {
		status = smb2_util_write(tree, h, "\0", 0, 1);
		if (!NT_STATUS_IS_OK(status)) {
			torture_result(tctx, TORTURE_FAIL, "Server only allowed %d writes\n", i);
			ret = false;
			goto done;
		}
	}

	/*
	 * Now use the skipped mid (the smb2_util_close...), we should
	 * immediately get a full mid window of size 8192.
	 */
	smb2cli_conn_set_mid(tree->session->transport->conn, mid);
	status = smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_close failed\n");
	ZERO_STRUCT(h);

	cur_credits = smb2cli_conn_get_cur_credits(transport->conn);
	if (cur_credits != 8192) {
		torture_result(tctx, TORTURE_FAIL, "Server only granted %" PRIu16" credits\n", cur_credits);
		ret = false;
		goto done;
	}

	smb2cli_conn_set_mid(tree->session->transport->conn, mid + 8192);

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_util_unlink(tree, fname);
	TALLOC_FREE(tree);
	return ret;
}

#define SMBXCLI_NP_DESIRED_ACCESS                                          \
	(SEC_STD_READ_CONTROL | SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA | \
	 SEC_FILE_APPEND_DATA | SEC_FILE_READ_EA | SEC_FILE_WRITE_EA |     \
	 SEC_FILE_READ_ATTRIBUTE | SEC_FILE_WRITE_ATTRIBUTE | 0)

struct test_ipc_async_credits_loop;

struct test_ipc_async_credits_state {
	struct torture_context *tctx;
	struct smbXcli_conn *conn;
	struct smbXcli_session *session;
	struct smbXcli_tcon *tcon;
	uint32_t timeout_msec;
	uint16_t pid;
	const char *pipe_name;

	size_t num_loops;
	struct test_ipc_async_credits_loop *loops;
	size_t num_status_received;

	size_t num_status_pending;
	size_t num_status_insufficient;

	bool stop;
};

struct test_ipc_async_credits_loop {
	size_t idx;
	struct test_ipc_async_credits_state *state;
	struct tevent_req *req;
	size_t num_started;

	uint32_t max_data;
	uint64_t fid_persistent;
	uint64_t fid_volatile;

	struct tevent_immediate *im;

	NTSTATUS status;
};

static void test_ipc_async_credits_read_loop_do(
	struct test_ipc_async_credits_loop *loop);

static void test_ipc_async_credits_read_loop_start(struct tevent_context *ctx,
						   struct tevent_immediate *im,
						   void *private_data)
{
	struct test_ipc_async_credits_loop *loop = private_data;

	test_ipc_async_credits_read_loop_do(loop);
}

static void test_ipc_async_credits_read_loop_done(struct tevent_req *req);

static void test_ipc_async_credits_read_loop_do(
	struct test_ipc_async_credits_loop *loop)
{
	struct test_ipc_async_credits_state *state = loop->state;
	bool ok;

	loop->num_started += 1;
	loop->req = smb2cli_read_send(state->loops,
				      state->tctx->ev,
				      state->conn,
				      state->timeout_msec,
				      state->session,
				      state->tcon,
				      loop->max_data, /* length */
				      0,	      /* offset */
				      loop->fid_persistent,
				      loop->fid_volatile,
				      0,  /* minimum_count */
				      0); /* remaining_bytes */
	torture_assert_not_null_goto(
		state->tctx, loop->req, ok, asserted, "smb2cli_read_send");
	smb2cli_read_set_notify_async(loop->req);
	tevent_req_set_callback(loop->req,
				test_ipc_async_credits_read_loop_done,
				loop);

	return;
asserted:
	(void)ok;
	state->stop = true;
}

static void test_ipc_async_credits_read_loop_done(struct tevent_req *req)
{
	struct test_ipc_async_credits_loop *loop = _tevent_req_callback_data(
		req);
	struct test_ipc_async_credits_state *state = loop->state;
	TALLOC_CTX *frame = talloc_stackframe();
	uint8_t *data = NULL;
	uint32_t data_length = 0;
	bool ok;
	bool was_pending = false;
	bool in_progress = false;

	torture_assert_goto(state->tctx,
			    loop->req == req,
			    ok,
			    asserted,
			    __location__);

	if (NT_STATUS_EQUAL(loop->status, NT_STATUS_PENDING)) {
		was_pending = true;
	}

	loop->status = smb2cli_read_recv(req, frame, &data, &data_length);
#if 0
	torture_comment(state->tctx,
			"loop->status: %s\n",
			nt_errstr(loop->status));
#endif
	in_progress = tevent_req_is_in_progress(req);
	state->num_status_received += 1;

	if (NT_STATUS_EQUAL(loop->status, NT_STATUS_PENDING)) {
		state->num_status_pending += 1;
		torture_assert_goto(state->tctx,
				    in_progress,
				    ok,
				    asserted,
				    __location__);
		goto done;
	}
	loop->req = NULL;
	/* We will cancel the request, don't free it. */
	torture_assert_goto(state->tctx,
			    !in_progress,
			    ok,
			    asserted,
			    __location__);
	if (was_pending &&
	    NT_STATUS_EQUAL(loop->status, NT_STATUS_CANCELLED))
	{
		goto done;
	}
	torture_assert_ntstatus_equal_goto(state->tctx,
					   loop->status,
					   NT_STATUS_INSUFFICIENT_RESOURCES,
					   ok,
					   asserted,
					   __location__);
	state->num_status_insufficient += 1;

done:
	TALLOC_FREE(frame);
	return;
asserted:
	(void)ok;
	state->stop = true;
	TALLOC_FREE(frame);
}

static const uint8_t dcerpc_bind_lsa_bytes[] = {
	0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
	0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
	0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
	0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
	0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x78, 0x57, 0x34, 0x12,
	0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23,
	0x45, 0x67, 0x89, 0xab, 0x00, 0x00, 0x00, 0x00,
	0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49,
	0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
	0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
	0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
	0x00, 0x00, 0x00, 0x00, 0x2c, 0x1c, 0xb7, 0x6c,
	0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};

static bool test_ipc_max_async_credits(struct torture_context *tctx,
				   struct smb2_tree *trees[],
				   size_t num_trees,
				   size_t num_loops)
{
	struct test_ipc_async_credits_state *states[num_trees];
	bool stop_loop = false;
	NTSTATUS status;
	size_t i, t;
	bool ok;

	for (t = 0; t < num_trees; t++) {
		uint16_t cur_credits;

		states[t] = NULL;

		cur_credits = smb2cli_conn_get_cur_credits(
			trees[t]->session->transport->conn);
		torture_assert_int_equal_goto(
			tctx,
			cur_credits,
			num_loops,
			ok,
			out,
			"Invalid number of granted credits");
	}

	torture_assert_int_not_equal_goto(
		tctx, num_trees, 0, ok, out, "Invalid number of trees");

	for (i = 0; i < num_trees; i++) {
		struct smb2_tree *tree = trees[i];
		struct test_ipc_async_credits_state *state = NULL;

		state = talloc_zero(tctx,
				    struct test_ipc_async_credits_state);
		torture_assert_not_null_goto(
			tctx, state, ok, out, "tevent_zero failed");

		state->tctx = tctx;
		state->conn = tree->session->transport->conn;
		state->session = tree->session->smbXcli;
		state->tcon = tree->smbXcli;
		state->timeout_msec = 0; /* 10 * 1000; */
		state->pid = 0;
		state->pipe_name = NDR_LSARPC_NAME;

		state->num_loops = num_loops;
		state->loops = talloc_zero_array(
			state,
			struct test_ipc_async_credits_loop,
			state->num_loops);
		torture_assert_not_null_goto(tctx,
					     state->loops,
					     ok,
					     out,
					     "tevent_zero_array failed");

		states[i] = state;
	}

	for (i = 0; i < num_loops; i++) {
		for (t = 0; t < num_trees; t++) {
			struct test_ipc_async_credits_state
				*state = states[t];
			struct test_ipc_async_credits_loop
				*loop = &state->loops[i];
			DATA_BLOB in_input_buffer = data_blob_const(
				dcerpc_bind_lsa_bytes,
				ARRAY_SIZE(dcerpc_bind_lsa_bytes));
			DATA_BLOB in_output_buffer = data_blob_null;
			DATA_BLOB out_input_buffer = data_blob_null;
			DATA_BLOB out_output_buffer = data_blob_null;

			loop->idx = i;
			loop->state = state;
			loop->status = NT_STATUS_UNSUCCESSFUL;
			loop->max_data = 1024;

			loop->im = tevent_create_immediate(state->loops);
			torture_assert_not_null_goto(
				tctx,
				loop->im,
				ok,
				out,
				"tevent_create_immediate failed");

			status = smb2cli_create(
				state->conn,
				state->timeout_msec,
				state->session,
				state->tcon,
				state->pipe_name,
				SMB2_OPLOCK_LEVEL_NONE,
				SMB2_IMPERSONATION_IMPERSONATION,
				SMBXCLI_NP_DESIRED_ACCESS,
				0, /* file_attributes */
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_OPEN,
				0,    /* create_options */
				NULL, /* blobs */
				&loop->fid_persistent,
				&loop->fid_volatile,
				NULL,  /* cr */
				state, /* mem_ctx */
				NULL,  /* ret_blobs */
				NULL); /* psymlink */
			torture_assert_ntstatus_ok_goto(
				tctx, status, ok, out, "smb2cli_create failed");

			status = smb2cli_ioctl(
				state->conn,
				state->timeout_msec,
				state->session,
				state->tcon,
				loop->fid_persistent,
				loop->fid_volatile,
				FSCTL_NAMED_PIPE_READ_WRITE,
				0, /* in_max_input_length */
				&in_input_buffer,
				1024, /* in_max_output_length */
				&in_output_buffer,
				SMB2_IOCTL_FLAG_IS_FSCTL,
				state, /* mem_ctx */
				&out_input_buffer,
				&out_output_buffer);
			torture_assert_ntstatus_ok_goto(
				tctx,
				status,
				ok,
				out,
				"FSCTL_NAMED_PIPE_READ_WRITE failed");

			tevent_schedule_immediate(
				loop->im,
				tctx->ev,
				test_ipc_async_credits_read_loop_start,
				loop);
		}
	}

	/* Loop to send and receive packets */
	while (!stop_loop) {
		size_t loops_ready = 0;
		int rc;

		rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal_goto(
			tctx, rc, 0, ok, out, "tevent_loop_once");

		for (i = 0; i < num_trees; i++) {
			struct test_ipc_async_credits_state
				*state = states[i];
			if (state->stop) {
				stop_loop = true;
			}

			if (state->num_status_received >= state->num_loops) {
				loops_ready += 1;
			}
		}

		if (loops_ready >= num_trees) {
			stop_loop = true;
		}
	}

	for (t = 0; t < num_trees; t++) {
		struct test_ipc_async_credits_state *state = states[t];
		size_t max_async_credits = 512;
		size_t max_credits = max_async_credits + 2;

		torture_assert_goto(state->tctx, !state->stop, ok, out, "");
		torture_assert_int_equal_goto(state->tctx,
					      state->num_status_received,
					      state->num_loops,
					      ok,
					      out,
					      "");
		torture_assert_int_equal_goto(state->tctx,
					      state->num_status_pending,
					      max_async_credits - 1,
					      ok,
					      out,
					      "");
		torture_assert_int_equal_goto(state->tctx,
					      state->num_status_insufficient,
					      max_credits - max_async_credits + 1,
					      ok,
					      out,
					      "");
	}

	for (t = 0; t < num_trees; t++) {
		struct test_ipc_async_credits_state *state = states[t];

		for (i = 0; i < num_loops; i++) {
			struct test_ipc_async_credits_loop
				*loop = &state->loops[i];
			if (loop->req != NULL) {
				ok = tevent_req_cancel(loop->req);
				torture_assert_goto(tctx,
						    ok,
						    ok,
						    out,
						    "tevent_req_cancel failed");
			}
		}
	}

	for (t = 0; t < num_trees; t++) {
		struct test_ipc_async_credits_state *state = states[t];

		for (i = 0; i < num_loops; i++) {
			struct test_ipc_async_credits_loop
				*loop = &state->loops[i];

			if (NT_STATUS_EQUAL(loop->status,
					    NT_STATUS_INSUFFICIENT_RESOURCES))
			{
				continue;
			}

			if (loop->req != NULL) {
				ok = tevent_req_poll(loop->req, tctx->ev);
				torture_assert_goto(state->tctx,
						    ok,
						    ok,
						    out,
						    "tevent_req_poll failed");
			}
			torture_assert_ntstatus_equal_goto(
				tctx,
				loop->status,
				NT_STATUS_CANCELLED,
				ok,
				out,
				__location__);
		}
	}

	ok = true;
out:
	for (t = 0; t < num_trees; t++) {
		TALLOC_FREE(states[t]);
	}

	return ok;
}

static bool test_1conn_ipc_max_async_credits(struct torture_context *tctx,
					     struct smb2_tree *tree0)
{
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options = transport0->options;
	struct smb2_tree *tree1 = NULL;
	struct smb2_tree *trees[1] = {};
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = "IPC$";
	/* We want to check if we IPC connections add to "max async credits" */
	uint16_t max_async_credits = torture_setting_int(
		tctx,
		"maxasynccredits",
		512 /* lpcfg_smb2_max_async_credits(tctx->lp_ctx) */);
	bool ok = false;
	NTSTATUS status;
	uint16_t max_credits = max_async_credits + 2;

	options.client_guid = GUID_random();
	options.max_credits = max_credits;

	/* Create connection to IPC$ */
	status = smb2_connect(tctx,
			      host,
			      lpcfg_smb_ports(tctx->lp_ctx),
			      share,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      samba_cmdline_get_creds(),
			      &tree1,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok_goto(
		tctx, status, ok, out, "smb2_connect failed");

	trees[0] = tree1;
	ok = test_ipc_max_async_credits(tctx,
					trees,
					ARRAY_SIZE(trees),
					max_credits);
out:
	TALLOC_FREE(tree1);

	return ok;
}

struct torture_suite *torture_smb2_crediting_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "credits");

	torture_suite_add_1smb2_test(suite, "session_setup_credits_granted", test_session_setup_credits_granted);
	torture_suite_add_1smb2_test(suite, "single_req_credits_granted", test_single_req_credits_granted);
	torture_suite_add_1smb2_test(suite, "skipped_mid", test_crediting_skipped_mid);

	torture_suite_add_1smb2_test(suite,
				     "1conn_ipc_max_async_credits",
				     test_1conn_ipc_max_async_credits);

	suite->description = talloc_strdup(suite, "SMB2-CREDITS tests");

	return suite;
}
