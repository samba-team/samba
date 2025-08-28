/*
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Walker (2025)

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
#include "lib/cmdline/cmdline.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "torture/vfs/proto.h"
#include "libcli/resolve/resolve.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "lib/param/param.h"

#define BASEDIR "smb2-testads"


static bool get_stream_handle(struct torture_context *tctx,
			      struct smb2_tree *tree,
			      const char *dname,
			      const char *fname,
			      const char *sname,
			      struct smb2_handle *hdl_in)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle fhandle = {{0}};
	struct smb2_handle dhandle = {{0}};

	torture_comment(tctx, "Create dir\n");

	status = torture_smb2_testdir(tree, dname, &dhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir\n");

	torture_comment(tctx, "Create file\n");

	status = torture_smb2_testfile(tree, fname, &fhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testfile\n");

	status = torture_smb2_testfile(tree, sname, hdl_in);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testfile\n");

done:
	if (!smb2_util_handle_empty(fhandle)) {
		smb2_util_close(tree, fhandle);
	}
	if (!smb2_util_handle_empty(dhandle)) {
		smb2_util_close(tree, dhandle);
	}
	return ret;
}

static bool read_stream(struct torture_context *tctx,
			TALLOC_CTX *mem_ctx,
			struct smb2_tree *tree,
			struct smb2_handle *stream_hdl,
			off_t read_offset,
			size_t read_count,
			char **data_out,
			size_t *data_out_sz)
{
	NTSTATUS status;
	struct smb2_read r;
	bool ret = true;

	ZERO_STRUCT(r);
	r.in.file.handle = *stream_hdl;
	r.in.length = read_count;
	r.in.offset = read_offset;

	status = smb2_read(tree, mem_ctx, &r);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "stream read\n");

	*data_out = (char *)r.out.data.data;
	*data_out_sz = r.out.data.length;

done:
	return ret;
}


#define WRITE_PAYLOAD "canary"
#define ADS_LEN 1024
#define ADS_OFF_TAIL ADS_LEN - sizeof(WRITE_PAYLOAD)

static bool test_streams_pwrite_hole(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ok;
	bool ret = true;
	const char *dname = BASEDIR "\\testdir";
	const char *fname = BASEDIR "\\testdir\\testfile";
	const char *sname = BASEDIR "\\testdir\\testfile:test_stream";
	const char *canary = "canary";
	struct smb2_handle shandle = {{0}};
	TALLOC_CTX *tmp_ctx = NULL;
	char *data = NULL;
	size_t data_sz, i;

	ok = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ok == true, ret, done, "Unable to setup testdir\n");

	tmp_ctx = talloc_new(tree);
	torture_assert_goto(tctx, tmp_ctx != NULL, ret, done, "Memory failure\n");

	ok = get_stream_handle(tctx, tree, dname, fname, sname, &shandle);
	if (!ok) {
		// torture assert already set
		goto done;
	}

	/*
	 * We're going to write a string at the beginning at the ADS, then write the same
	 * string at a later offset, introducing a hole in the file
	 */
	torture_comment(tctx, "writing at varying offsets to create hole\n");
	status = smb2_util_write(tree, shandle, WRITE_PAYLOAD, 0, sizeof(WRITE_PAYLOAD));
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to write %zu bytes to "
		    "stream at offset 0\n", sizeof(canary));
		return false;
	}

	status = smb2_util_write(tree, shandle, WRITE_PAYLOAD, ADS_OFF_TAIL, sizeof(WRITE_PAYLOAD));
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to write %zu bytes to "
		    "stream at offset 1018\n", sizeof(canary));
		return false;
	}

	/* Now we'll read the stream contents */
	torture_comment(tctx, "Read stream data\n");
	ok = read_stream(tctx, tmp_ctx, tree, &shandle, 0, ADS_LEN, &data, &data_sz);
	if (!ok) {
		// torture assert already set
		goto done;
	}

	torture_assert_goto(tctx, data_sz == ADS_LEN, ret, done, "Short read on ADS\n");

	/* Make sure our strings actually got written */
	if (strncmp(data, WRITE_PAYLOAD, sizeof(WRITE_PAYLOAD)) != 0) {
		torture_result(tctx, TORTURE_FAIL,
			       "Payload write at beginning of file failed");
		ret = false;
		goto done;
	}

	if (strncmp(data + ADS_OFF_TAIL, WRITE_PAYLOAD, sizeof(WRITE_PAYLOAD)) != 0) {
		torture_result(tctx, TORTURE_FAIL,
			       "Payload write at end of file failed");
		ret = false;
		goto done;
	}

	/* Now we'll check that the hole is full of null bytes */
	for (i = sizeof(WRITE_PAYLOAD); i < ADS_OFF_TAIL; i++) {
		if (data[i] != '\0') {
			torture_comment(tctx, "idx: %zu, got 0x%02x when expected 0x00\n",
					i, (uint8_t)data[i]);
			torture_result(tctx, TORTURE_FAIL,
				       "0x%08x: unexpected non-null byte in ADS read\n",
				       data[i]);
			ret = false;
			goto done;
		}
	}

done:
	talloc_free(tmp_ctx);

	if (!smb2_util_handle_empty(shandle)) {
		smb2_util_close(tree, shandle);
	}

	smb2_deltree(tree, BASEDIR);

	return ret;
}

/*
   basic testing of vfs_streams_xattr
*/
struct torture_suite *torture_vfs_streams_xattr(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "streams_xattr");

	torture_suite_add_1smb2_test(suite, "streams-pwrite-hole", test_streams_pwrite_hole);

	suite->description = talloc_strdup(suite, "vfs_streams_xattr tests");

	return suite;
}
