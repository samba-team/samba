/*
   Unix SMB/CIFS implementation.
   test suite for the mdssvc RPC serice

   Copyright (C) Ralph Boehme 2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "torture/rpc/torture_rpc.h"
#include "librpc/gen_ndr/ndr_mdssvc_c.h"
#include "param/param.h"
#include "lib/cmdline/popt_common.h"
#include "rpc_server/mdssvc/dalloc.h"
#include "rpc_server/mdssvc/marshalling.h"

struct torture_mdsscv_state {
	struct dcerpc_pipe *p;
	struct policy_handle ph;

	/* Known fields used across multiple commands */
	uint32_t dev;
	uint32_t flags;

	/* cmd specific or unknown fields */
	struct {
		const char share_path[1025];
		uint32_t unkn2;
		uint32_t unkn3;
	} mdscmd_open;
	struct {
		uint32_t status;
		uint32_t unkn7;
	} mdscmd_unknown1;
	struct {
		uint32_t fragment;
		uint32_t unkn9;
	} mdscmd_cmd;
	struct {
		uint32_t status;
	} mdscmd_close;
};

static bool torture_rpc_mdssvc_setup(struct torture_context *tctx,
				     void **data)
{
	struct torture_mdsscv_state *state = NULL;
	NTSTATUS status;

	state = talloc_zero(tctx, struct torture_mdsscv_state);
	if (state == NULL) {
		return false;
	}
	*data = state;

	status = torture_rpc_connection(tctx, &state->p, &ndr_table_mdssvc);
	torture_assert_ntstatus_ok(tctx, status,  "Error connecting to server");

	return true;
}

static bool torture_rpc_mdssvc_teardown(struct torture_context *tctx,
					void *data)
{
	struct torture_mdsscv_state *state = talloc_get_type_abort(
		data, struct torture_mdsscv_state);

	TALLOC_FREE(state->p);
	TALLOC_FREE(state);
	return true;
}

static bool torture_rpc_mdssvc_open(struct torture_context *tctx,
				    void **data)
{
	struct torture_mdsscv_state *state = NULL;
	struct dcerpc_binding_handle *b = NULL;
	const char *share_name = NULL;
	const char *share_mount_path = NULL;
	NTSTATUS status;
	bool ok = true;

	state = talloc_zero(tctx, struct torture_mdsscv_state);
	if (state == NULL) {
		return false;
	}
	*data = state;

	status = torture_rpc_connection(tctx, &state->p, &ndr_table_mdssvc);
	torture_assert_ntstatus_ok(tctx, status,  "Error connecting to server");
	b = state->p->binding_handle;

	share_name = torture_setting_string(
		tctx, "spotlight_share", "spotlight");
	share_mount_path = torture_setting_string(
		tctx, "share_mount_path", "/foo/bar");

	state->dev = generate_random();
	state->mdscmd_open.unkn2 = 23;
	state->mdscmd_open.unkn3 = 0;

	ZERO_STRUCT(state->ph);

	status = dcerpc_mdssvc_open(b,
				    state,
				    &state->dev,
				    &state->mdscmd_open.unkn2,
				    &state->mdscmd_open.unkn3,
				    share_mount_path,
				    share_name,
				    state->mdscmd_open.share_path,
				    &state->ph);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done,
					"dcerpc_mdssvc_open failed\n");

	status = dcerpc_mdssvc_unknown1(b,
					state,
					&state->ph,
					0,
					state->dev,
					state->mdscmd_open.unkn2,
					0,
					geteuid(),
					getegid(),
					&state->mdscmd_unknown1.status,
					&state->flags,
					&state->mdscmd_unknown1.unkn7);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done,
					"dcerpc_mdssvc_unknown1 failed\n");

done:
	if (!ok) {
		(void)dcerpc_mdssvc_close(b,
					  state,
					  &state->ph,
					  0,
					  state->dev,
					  state->mdscmd_open.unkn2,
					  0,
					  &state->ph,
					  &state->mdscmd_close.status);
		ZERO_STRUCT(state);
	}
	return ok;
}

static bool torture_rpc_mdssvc_close(struct torture_context *tctx,
				     void *data)
{
	struct torture_mdsscv_state *state = talloc_get_type_abort(
		data, struct torture_mdsscv_state);
	struct dcerpc_binding_handle *b = state->p->binding_handle;
	NTSTATUS status;
	bool ok = true;

	torture_comment(tctx, "test_teardown_mdssvc_disconnect\n");

	status = dcerpc_mdssvc_close(b,
				     state,
				     &state->ph,
				     0,
				     state->dev,
				     state->mdscmd_open.unkn2,
				     0,
				     &state->ph,
				     &state->mdscmd_close.status);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done,
					"dcerpc_mdssvc_close failed\n");

	ZERO_STRUCT(state);

done:
	return ok;
}

/*
 * Test unknown share name
 */
static bool test_mdssvc_open_unknown_share(struct torture_context *tctx,
					   void *data)
{
	struct torture_mdsscv_state *state = talloc_get_type_abort(
		data, struct torture_mdsscv_state);
	struct dcerpc_binding_handle *b = state->p->binding_handle;
	struct policy_handle ph;
	struct policy_handle nullh;
	uint32_t device_id;
	uint32_t unkn2;
	uint32_t unkn3;
	uint32_t device_id_out;
	uint32_t unkn2_out;
	uint32_t unkn3_out;
	const char *share_mount_path = NULL;
	const char *share_name = NULL;
	const char share_path[1025] = "X";
	NTSTATUS status;
	bool ok = true;

	share_name = torture_setting_string(
		tctx, "unknown_share", "choukawoohoo");
	share_mount_path = torture_setting_string(
		tctx, "share_mount_path", "/foo/bar");

	device_id_out = device_id = generate_random();
	unkn2_out = unkn2 = generate_random();
	unkn3_out = unkn3 = generate_random();

	ZERO_STRUCT(ph);
	ZERO_STRUCT(nullh);

	status = dcerpc_mdssvc_open(b,
				    tctx,
				    &device_id_out,
				    &unkn2_out,
				    &unkn3_out,
				    share_mount_path,
				    share_name,
				    share_path,
				    &ph);

	torture_assert_ntstatus_ok_goto(tctx, status, ok, done,
					"dcerpc_mdssvc_open failed\n");

	torture_assert_u32_equal_goto(tctx, device_id_out, device_id, ok, done,
				      "Bad device_id\n");

	torture_assert_u32_equal_goto(tctx, unkn2_out, unkn2, ok, done,
				      "Bad unkn2\n");

	torture_assert_u32_equal_goto(tctx, unkn3_out, unkn3, ok, done,
				      "Bad unkn3\n");

	torture_assert_goto(tctx, share_path[0] == '\0', ok, done,
			    "Expected empty string as share path\n");

	torture_assert_mem_equal_goto(tctx, &ph, &nullh,
				      sizeof(ph), ok, done,
				      "Expected all-zero policy handle\n");

done:
	return ok;
}

/*
 * Test on a share where Spotlight is not enabled
 */
static bool test_mdssvc_open_spotlight_disabled(struct torture_context *tctx,
						void *data)
{
	struct torture_mdsscv_state *state = talloc_get_type_abort(
		data, struct torture_mdsscv_state);
	struct dcerpc_binding_handle *b = state->p->binding_handle;
	struct policy_handle ph;
	const char *localdir = NULL;
	uint32_t device_id;
	uint32_t unkn2;
	uint32_t unkn3;
	uint32_t device_id_out;
	uint32_t unkn2_out;
	uint32_t unkn3_out;
	const char *share_mount_path = NULL;
	const char *share_name = NULL;
	const char share_path[1025] = "";
	NTSTATUS status;
	bool ok = true;

	share_name = torture_setting_string(
		tctx, "no_spotlight_share", "no_spotlight");
	share_mount_path = torture_setting_string(
		tctx, "share_mount_path", "/foo/bar");

	localdir = torture_setting_string(
		tctx, "no_spotlight_localdir", NULL);
	torture_assert_not_null_goto(
		tctx, localdir, ok, done,
		"need 'no_spotlight_localdir' torture option \n");

	device_id_out = device_id = generate_random();
	unkn2_out = unkn2 = 23;
	unkn3_out = unkn3 = 0;

	ZERO_STRUCT(ph);

	status = dcerpc_mdssvc_open(b,
				    tctx,
				    &device_id_out,
				    &unkn2_out,
				    &unkn3_out,
				    share_mount_path,
				    share_name,
				    share_path,
				    &ph);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done,
					"dcerpc_mdssvc_open failed\n");

	torture_assert_u32_equal_goto(tctx, device_id, device_id_out, ok, done,
				      "Bad device_id\n");

	torture_assert_u32_equal_goto(tctx, unkn2, unkn2_out,
				      ok, done, "Bad unkn2\n");

	torture_assert_u32_equal_goto(tctx, unkn3, unkn3_out,
				      ok, done, "Bad unkn3\n");

	torture_assert_str_equal_goto(tctx, share_path, localdir, ok, done,
				      "Wrong share path\n");

done:
	return ok;
}

static bool test_mdssvc_close(struct torture_context *tctx,
			      void *data)
{
	struct torture_mdsscv_state *state = talloc_get_type_abort(
		data, struct torture_mdsscv_state);
	struct dcerpc_binding_handle *b = state->p->binding_handle;
	struct policy_handle ph;
	struct policy_handle close_ph;
	uint32_t device_id;
	uint32_t unkn2;
	uint32_t unkn3;
	const char *share_mount_path = NULL;
	const char *share_name = NULL;
	const char share_path[1025] = "";
	uint32_t close_status;
	DATA_BLOB ph_blob;
	DATA_BLOB close_ph_blob;
	NTSTATUS status;
	bool ok = true;

	share_name = torture_setting_string(
		tctx, "spotlight_share", "spotlight");
	share_mount_path = torture_setting_string(
		tctx, "share_mount_path", "/foo/bar");

	device_id = generate_random();
	unkn2 = 23;
	unkn3 = 0;

	ZERO_STRUCT(ph);
	ZERO_STRUCT(close_ph);

	status = dcerpc_mdssvc_open(b,
				    tctx,
				    &device_id,
				    &unkn2,
				    &unkn3,
				    share_mount_path,
				    share_name,
				    share_path,
				    &ph);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done,
					"dcerpc_mdssvc_open failed\n");

	status = dcerpc_mdssvc_close(b,
				     tctx,
				     &ph,
				     0,
				     device_id,
				     unkn2,
				     0,
				     &close_ph,
				     &close_status);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done,
					"dcerpc_mdssvc_open failed\n");

	ph_blob = (DATA_BLOB) {
		.data = (uint8_t *)&ph,
		.length = sizeof(struct policy_handle)
	};
	close_ph_blob = (DATA_BLOB) {
		.data = (uint8_t *)&close_ph,
		.length = sizeof(struct policy_handle),
	};

	torture_assert_data_blob_equal(tctx, close_ph_blob, ph_blob,
				       "bad blob");

	torture_comment(tctx, "Test close with a all-zero handle\n");

	ZERO_STRUCT(ph);
	status = dcerpc_mdssvc_close(b,
				     tctx,
				     &ph,
				     0,
				     device_id,
				     unkn2,
				     0,
				     &close_ph,
				     &close_status);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done,
					"dcerpc_mdssvc_close failed\n");

	torture_assert_data_blob_equal(tctx, close_ph_blob, ph_blob,
				       "bad blob");

done:
	return ok;
}

static bool test_mdssvc_null_ph(struct torture_context *tctx,
				void *data)
{
	struct torture_mdsscv_state *state = talloc_get_type_abort(
		data, struct torture_mdsscv_state);
	struct dcerpc_binding_handle *b = state->p->binding_handle;
	struct policy_handle nullh;
	struct policy_handle ph;
	uint32_t device_id;
	uint32_t unkn2;
	uint32_t unkn7;
	uint32_t cmd_status;
	uint32_t flags;
	NTSTATUS status;
	bool ok = true;

	device_id = generate_random();
	unkn2 = 23;
	unkn7 = 0;
	cmd_status = 0;

	ZERO_STRUCT(nullh);
	ZERO_STRUCT(ph);

	status = dcerpc_mdssvc_unknown1(b,
					tctx,
					&ph,
					0,
					device_id,
					unkn2,
					0,
					geteuid(),
					getegid(),
					&cmd_status,
					&flags,
					&unkn7);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done,
					"dcerpc_mdssvc_unknown1 failed\n");

	torture_assert_mem_equal_goto(tctx, &ph, &nullh,
				      sizeof(ph), ok, done,
				      "Expected all-zero policy handle\n");

done:
	return ok;
}

static bool test_mdssvc_invalid_ph_unknown1(struct torture_context *tctx,
					    void *data)
{
	struct torture_mdsscv_state *state = talloc_get_type_abort(
		data, struct torture_mdsscv_state);
	struct dcerpc_binding_handle *b = state->p->binding_handle;
	struct policy_handle ph;
	uint32_t device_id;
	uint32_t unkn2;
	uint32_t unkn7;
	uint32_t cmd_status;
	uint32_t flags;
	NTSTATUS status;
	bool ok = true;

	device_id = generate_random();
	unkn2 = 23;
	unkn7 = 0;
	cmd_status = 0;

	ZERO_STRUCT(ph);
	ph.uuid = GUID_random();

	status = dcerpc_mdssvc_unknown1(b,
					tctx,
					&ph,
					0,
					device_id,
					unkn2,
					0,
					geteuid(),
					getegid(),
					&cmd_status,
					&flags,
					&unkn7);
	torture_assert_ntstatus_equal_goto(
		tctx, status, NT_STATUS_RPC_PROTOCOL_ERROR, ok, done,
		"dcerpc_mdssvc_unknown1 failed\n");

done:
	return ok;
}

static bool test_mdssvc_invalid_ph_cmd(struct torture_context *tctx,
				       void *data)
{
	struct torture_mdsscv_state *state = talloc_get_type_abort(
		data, struct torture_mdsscv_state);
	struct dcerpc_binding_handle *b = state->p->binding_handle;
	struct policy_handle ph;
	struct mdssvc_blob request_blob;
	struct mdssvc_blob response_blob;
	uint32_t device_id;
	uint32_t unkn2;
	uint32_t unkn9;
	uint32_t fragment;
	uint32_t flags;
	NTSTATUS status;
	bool ok = true;

	device_id = generate_random();
	unkn2 = 23;
	unkn9 = 0;
	fragment = 0;
	flags = UINT32_C(0x6b000001);

	ZERO_STRUCT(ph);
	ph.uuid = GUID_random();

	request_blob.spotlight_blob = talloc_array(state,
						   uint8_t,
						   0);
	torture_assert_not_null_goto(tctx, request_blob.spotlight_blob,
				     ok, done, "dalloc_zero failed\n");
	request_blob.size = 0;
	request_blob.length = 0;
	request_blob.size = 0;

	response_blob.spotlight_blob = talloc_array(state,
						    uint8_t,
						    0);
	torture_assert_not_null_goto(tctx, response_blob.spotlight_blob,
				     ok, done, "dalloc_zero failed\n");
	response_blob.size = 0;

	status =  dcerpc_mdssvc_cmd(b,
				    state,
				    &ph,
				    0,
				    device_id,
				    unkn2,
				    0,
				    flags,
				    request_blob,
				    0,
				    64 * 1024,
				    1,
				    64 * 1024,
				    0,
				    0,
				    &fragment,
				    &response_blob,
				    &unkn9);
	torture_assert_ntstatus_equal_goto(
		tctx, status, NT_STATUS_RPC_PROTOCOL_ERROR, ok, done,
		"dcerpc_mdssvc_unknown1 failed\n");

done:
	return ok;
}

static bool test_mdssvc_invalid_ph_close(struct torture_context *tctx,
					 void *data)
{
	struct torture_mdsscv_state *state = talloc_get_type_abort(
		data, struct torture_mdsscv_state);
	struct dcerpc_binding_handle *b = state->p->binding_handle;
	struct policy_handle ph;
	uint32_t device_id;
	uint32_t unkn2;
	uint32_t close_status;
	NTSTATUS status;
	bool ok = true;

	device_id = generate_random();
	unkn2 = 23;
	close_status = 0;

	ZERO_STRUCT(ph);
	ph.uuid = GUID_random();

	status = dcerpc_mdssvc_close(b,
				     state,
				     &ph,
				     0,
				     device_id,
				     unkn2,
				     0,
				     &ph,
				     &close_status);
	torture_assert_ntstatus_equal_goto(
		tctx, status, NT_STATUS_RPC_PROTOCOL_ERROR, ok, done,
		"dcerpc_mdssvc_unknown1 failed\n");

done:
	return ok;
}

/*
 * Test fetchAttributes with unknown CNID
 */
static bool test_mdssvc_fetch_attr_unknown_cnid(struct torture_context *tctx,
						void *data)
{
	struct torture_mdsscv_state *state = talloc_get_type_abort(
		data, struct torture_mdsscv_state);
	struct dcerpc_binding_handle *b = state->p->binding_handle;
	uint32_t max_fragment_size = 64 * 1024;
	struct mdssvc_blob request_blob;
	struct mdssvc_blob response_blob;
	DALLOC_CTX *d = NULL, *mds_reply = NULL;
	uint64_t *uint64var = NULL;
	sl_array_t *array = NULL;
	sl_array_t *cmd_array = NULL;
	sl_array_t *attr_array = NULL;
	sl_cnids_t *cnids = NULL;
	void *path = NULL;
	const char *path_type = NULL;
	uint64_t ino64;
	NTSTATUS status;
	ssize_t len;
	int ret;
	bool ok = true;

	d = dalloc_new(state);
	torture_assert_not_null_goto(tctx, d, ret, done, "dalloc_new failed\n");

	array = dalloc_zero(d, sl_array_t);
	torture_assert_not_null_goto(tctx, array, ret, done,
				     "dalloc_zero failed\n");

	ret = dalloc_add(d, array, sl_array_t);
	torture_assert_goto(tctx, ret == 0, ret, done, "dalloc_add failed\n");

	cmd_array = dalloc_zero(d, sl_array_t);
	torture_assert_not_null_goto(tctx, cmd_array, ret, done,
				     "dalloc_zero failed\n");

	ret = dalloc_add(array, cmd_array, sl_array_t);
	torture_assert_goto(tctx, ret == 0, ret, done, "dalloc_add failed\n");

	ret = dalloc_stradd(cmd_array, "fetchAttributes:forOIDArray:context:");
	torture_assert_goto(tctx, ret == 0, ret, done, "dalloc_stradd failed\n");

	uint64var = talloc_zero_array(cmd_array, uint64_t, 2);
	torture_assert_not_null_goto(tctx, uint64var, ret, done,
				     "talloc_zero_array failed\n");
	talloc_set_name(uint64var, "uint64_t *");

	uint64var[0] = 0x500a;
	uint64var[1] = 0;

	ret = dalloc_add(cmd_array, &uint64var[0], uint64_t *);
	torture_assert_goto(tctx, ret == 0, ret, done, "dalloc_add failed\n");

	attr_array = dalloc_zero(d, sl_array_t);
	torture_assert_not_null_goto(tctx, attr_array, ret, done,
				     "dalloc_zero failed\n");

	ret = dalloc_add(array, attr_array, sl_array_t);
	torture_assert_goto(tctx, ret == 0, ret, done, "dalloc_add failed\n");

	ret = dalloc_stradd(attr_array, "kMDItemPath");
	torture_assert_goto(tctx, ret == 0, ret, done, "dalloc_stradd failed\n");

	/* CNIDs */
	cnids = talloc_zero(array, sl_cnids_t);
	torture_assert_not_null_goto(tctx, cnids, ret, done,
				     "talloc_zero failed\n");

	cnids->ca_cnids = dalloc_new(cnids);
	torture_assert_not_null_goto(tctx, cnids->ca_cnids, ret, done,
				     "dalloc_new failed\n");

	cnids->ca_unkn1 = 0xadd;
	cnids->ca_context = 0x6b000020;

	ino64 = UINT64_C(64382947389618974);
	ret = dalloc_add_copy(cnids->ca_cnids, &ino64, uint64_t);
	torture_assert_goto(tctx, ret == 0, ret, done,
			    "dalloc_add_copy failed\n");

	ret = dalloc_add(array, cnids, sl_cnids_t);
	torture_assert_goto(tctx, ret == 0, ret, done, "dalloc_add failed\n");

	request_blob.spotlight_blob = talloc_array(state,
						   uint8_t,
						   max_fragment_size);
	torture_assert_not_null_goto(tctx, request_blob.spotlight_blob,
				     ret, done, "dalloc_zero failed\n");
	request_blob.size = max_fragment_size;

	response_blob.spotlight_blob = talloc_array(state,
						    uint8_t,
						    max_fragment_size);
	torture_assert_not_null_goto(tctx, response_blob.spotlight_blob,
				     ret, done, "dalloc_zero failed\n");
	response_blob.size = max_fragment_size;

	len = sl_pack(d, (char *)request_blob.spotlight_blob, request_blob.size);
	torture_assert_goto(tctx, len != -1, ret, done, "sl_pack failed\n");

	request_blob.length = len;
	request_blob.size = len;

	status =  dcerpc_mdssvc_cmd(b,
				    state,
				    &state->ph,
				    0,
				    state->dev,
				    state->mdscmd_open.unkn2,
				    0,
				    state->flags,
				    request_blob,
				    0,
				    max_fragment_size,
				    1,
				    max_fragment_size,
				    0,
				    0,
				    &state->mdscmd_cmd.fragment,
				    &response_blob,
				    &state->mdscmd_cmd.unkn9);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"dcerpc_mdssvc_cmd failed\n");

	mds_reply = dalloc_new(state);
	torture_assert_not_null_goto(tctx, mds_reply, ret, done,
				     "dalloc_zero failed\n");

	ok = sl_unpack(mds_reply,
		       (char *)response_blob.spotlight_blob,
		       response_blob.length);
	torture_assert_goto(tctx, ok, ret, done, "dalloc_add failed\n");

	torture_comment(tctx, "%s", dalloc_dump(mds_reply, 0));

	path = dalloc_get(mds_reply,
			  "DALLOC_CTX", 0,
			  "DALLOC_CTX", 2,
			  "DALLOC_CTX", 0,
			  "sl_nil_t", 1);
	torture_assert_not_null_goto(tctx, path, ret, done,
				     "dalloc_get path failed\n");

	path_type = talloc_get_name(path);

	torture_assert_str_equal_goto(tctx, path_type, "sl_nil_t", ret, done,
				      "Wrong dalloc object type\n");

done:
	return ok;
}

struct torture_suite *torture_rpc_mdssvc(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(
		mem_ctx, "mdssvc");
	struct torture_tcase *tcase = NULL;

	tcase = torture_suite_add_tcase(suite, "rpccmd");
	if (tcase == NULL) {
		return NULL;
	}
	torture_tcase_set_fixture(tcase,
				  torture_rpc_mdssvc_setup,
				  torture_rpc_mdssvc_teardown);

	torture_tcase_add_simple_test(tcase,
				      "open_unknown_share",
				      test_mdssvc_open_unknown_share);

	torture_tcase_add_simple_test(tcase,
				      "open_spotlight_disabled",
				      test_mdssvc_open_spotlight_disabled);

	torture_tcase_add_simple_test(tcase,
				      "close",
				      test_mdssvc_close);

	torture_tcase_add_simple_test(tcase,
				      "null_ph",
				      test_mdssvc_null_ph);

	tcase = torture_suite_add_tcase(suite, "disconnect1");
	if (tcase == NULL) {
		return NULL;
	}
	torture_tcase_set_fixture(tcase,
				  torture_rpc_mdssvc_open,
				  torture_rpc_mdssvc_close);

	torture_tcase_add_simple_test(tcase,
				      "invalid_ph_unknown1",
				      test_mdssvc_invalid_ph_unknown1);

	tcase = torture_suite_add_tcase(suite, "disconnect2");
	if (tcase == NULL) {
		return NULL;
	}
	torture_tcase_set_fixture(tcase,
				  torture_rpc_mdssvc_open,
				  torture_rpc_mdssvc_close);

	torture_tcase_add_simple_test(tcase,
				      "invalid_ph_cmd",
				      test_mdssvc_invalid_ph_cmd);

	tcase = torture_suite_add_tcase(suite, "disconnect3");
	if (tcase == NULL) {
		return NULL;
	}
	torture_tcase_set_fixture(tcase,
				  torture_rpc_mdssvc_open,
				  torture_rpc_mdssvc_close);

	torture_tcase_add_simple_test(tcase,
				      "invalid_ph_close",
				      test_mdssvc_invalid_ph_close);

	tcase = torture_suite_add_tcase(suite, "mdscmd");
	if (tcase == NULL) {
		return NULL;
	}
	torture_tcase_set_fixture(tcase,
				  torture_rpc_mdssvc_open,
				  torture_rpc_mdssvc_close);

	torture_tcase_add_simple_test(tcase,
				      "fetch_unknown_cnid",
				      test_mdssvc_fetch_attr_unknown_cnid);

	return suite;
}
