/* 
   Unix SMB/CIFS implementation.

   SMB2 getinfo test suite

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/smb/smbXcli_base.h"

#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "torture/util.h"

static struct {
	const char *name;
	uint16_t level;
	NTSTATUS fstatus;
	NTSTATUS dstatus;
	union smb_fileinfo finfo;
	union smb_fileinfo dinfo;
} file_levels[] = {
#define LEVEL(x) #x, x
 { LEVEL(RAW_FILEINFO_BASIC_INFORMATION) },
 { LEVEL(RAW_FILEINFO_STANDARD_INFORMATION) },
 { LEVEL(RAW_FILEINFO_INTERNAL_INFORMATION) },
 { LEVEL(RAW_FILEINFO_EA_INFORMATION) },
 { LEVEL(RAW_FILEINFO_ACCESS_INFORMATION) },
 { LEVEL(RAW_FILEINFO_POSITION_INFORMATION) },
 { LEVEL(RAW_FILEINFO_MODE_INFORMATION) },
 { LEVEL(RAW_FILEINFO_ALIGNMENT_INFORMATION) },
 { LEVEL(RAW_FILEINFO_ALL_INFORMATION) },
 { LEVEL(RAW_FILEINFO_ALT_NAME_INFORMATION) },
 { LEVEL(RAW_FILEINFO_STREAM_INFORMATION) },
 { LEVEL(RAW_FILEINFO_COMPRESSION_INFORMATION) },
 { LEVEL(RAW_FILEINFO_NETWORK_OPEN_INFORMATION) },
 { LEVEL(RAW_FILEINFO_ATTRIBUTE_TAG_INFORMATION) },

 { LEVEL(RAW_FILEINFO_SMB2_ALL_EAS) },

 { LEVEL(RAW_FILEINFO_SMB2_ALL_INFORMATION) },
 { LEVEL(RAW_FILEINFO_SEC_DESC) }
};

static struct {
	const char *name;
	uint16_t level;
	NTSTATUS status;
	union smb_fsinfo info;
} fs_levels[] = {
 { LEVEL(RAW_QFS_VOLUME_INFORMATION) },
 { LEVEL(RAW_QFS_SIZE_INFORMATION) },
 { LEVEL(RAW_QFS_DEVICE_INFORMATION) },
 { LEVEL(RAW_QFS_ATTRIBUTE_INFORMATION) },
 { LEVEL(RAW_QFS_QUOTA_INFORMATION) },
 { LEVEL(RAW_QFS_FULL_SIZE_INFORMATION) },
 { LEVEL(RAW_QFS_OBJECTID_INFORMATION) }
};

#define FNAME "testsmb2_file.dat"
#define DNAME "testsmb2_dir"

/*
  test fileinfo levels
*/
static bool torture_smb2_fileinfo(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_handle hfile, hdir;
	NTSTATUS status;
	int i;

	status = torture_smb2_testfile(tree, FNAME, &hfile);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create test file "
				   FNAME "\n");

	status = torture_smb2_testdir(tree, DNAME, &hdir);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create test dir "
				   DNAME "\n");

	printf("Testing file info levels\n");
	torture_smb2_all_info(tree, hfile);
	torture_smb2_all_info(tree, hdir);

	for (i=0;i<ARRAY_SIZE(file_levels);i++) {
		if (file_levels[i].level == RAW_FILEINFO_SEC_DESC) {
			file_levels[i].finfo.query_secdesc.in.secinfo_flags = 0x7;
			file_levels[i].dinfo.query_secdesc.in.secinfo_flags = 0x7;
		}
		if (file_levels[i].level == RAW_FILEINFO_SMB2_ALL_EAS) {
			file_levels[i].finfo.all_eas.in.continue_flags =
				SMB2_CONTINUE_FLAG_RESTART;
			file_levels[i].dinfo.all_eas.in.continue_flags =
				SMB2_CONTINUE_FLAG_RESTART;
		}
		file_levels[i].finfo.generic.level = file_levels[i].level;
		file_levels[i].finfo.generic.in.file.handle = hfile;
		file_levels[i].fstatus = smb2_getinfo_file(tree, tree, &file_levels[i].finfo);
		torture_assert_ntstatus_ok(tctx, file_levels[i].fstatus,
					   talloc_asprintf(tctx, "%s on file",
							   file_levels[i].name));
		file_levels[i].dinfo.generic.level = file_levels[i].level;
		file_levels[i].dinfo.generic.in.file.handle = hdir;
		file_levels[i].dstatus = smb2_getinfo_file(tree, tree, &file_levels[i].dinfo);
		torture_assert_ntstatus_ok(tctx, file_levels[i].dstatus,
					   talloc_asprintf(tctx, "%s on dir",
							   file_levels[i].name));
	}

	return true;
}


/*
  test fsinfo levels
*/
static bool torture_smb2_fsinfo(struct torture_context *tctx)
{
	bool ret;
	struct smb2_tree *tree;
	int i;
	NTSTATUS status;
	struct smb2_handle handle;

	printf("Testing fsinfo levels\n");

	ret = torture_smb2_connection(tctx, &tree);
	torture_assert(tctx, ret, "connection failed");

	status = smb2_util_roothandle(tree, &handle);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create root handle");

	for (i=0;i<ARRAY_SIZE(fs_levels);i++) {
		fs_levels[i].info.generic.level = fs_levels[i].level;
		fs_levels[i].info.generic.handle = handle;
		fs_levels[i].status = smb2_getinfo_fs(tree, tree, &fs_levels[i].info);
		torture_assert_ntstatus_ok(tctx, fs_levels[i].status,
					   fs_levels[i].name);
	}

	return true;
}

static bool torture_smb2_buffercheck_err(struct torture_context *tctx,
					 struct smb2_tree *tree,
					 struct smb2_getinfo *b,
					 size_t fixed,
					 DATA_BLOB full)
{
	size_t i;

	for (i=0; i<=full.length; i++) {
		NTSTATUS status;

		b->in.output_buffer_length = i;

		status = smb2_getinfo(tree, tree, b);

		if (i < fixed) {
			torture_assert_ntstatus_equal(
				tctx, status, NT_STATUS_INFO_LENGTH_MISMATCH,
				"Wrong error code small buffer");
			continue;
		}

		if (i<full.length) {
			torture_assert_ntstatus_equal(
				tctx, status, STATUS_BUFFER_OVERFLOW,
				"Wrong error code for large buffer");
			/*
			 * TODO: compare the output buffer. That seems a bit
			 * difficult, because for level 5 for example the
			 * label length is adjusted to what is there. And some
			 * reserved fields seem to be not initialized to 0.
			 */
			TALLOC_FREE(b->out.blob.data);
			continue;
		}

		torture_assert_ntstatus_equal(
			tctx, status, NT_STATUS_OK,
			"Wrong error code for right sized buffer");
	}

	return true;
}

struct level_buffersize {
	int level;
	size_t fixed;
};

static bool torture_smb2_qfs_buffercheck(struct torture_context *tctx)
{
	bool ret;
	struct smb2_tree *tree;
	NTSTATUS status;
	struct smb2_handle handle;
	int i;

	struct level_buffersize levels[] = {
		{ 1, 24 },	/* We don't have proper defines here */
		{ 3, 24 },
		{ 4, 8 },
		{ 5, 16 },
		{ 6, 48 },
		{ 7, 32 },
		{ 11, 28 },
	};

	printf("Testing SMB2_GETINFO_FS buffer sizes\n");

	ret = torture_smb2_connection(tctx, &tree);
	torture_assert(tctx, ret, "connection failed");

	status = smb2_util_roothandle(tree, &handle);
	torture_assert_ntstatus_ok(
		tctx, status, "Unable to create root handle");

	for (i=0; i<ARRAY_SIZE(levels); i++) {
		struct smb2_getinfo b;

		if (TARGET_IS_SAMBA3(tctx) &&
		    ((levels[i].level == 6) || (levels[i].level == 11))) {
			continue;
		}

		ZERO_STRUCT(b);
		b.in.info_type			= SMB2_GETINFO_FS;
		b.in.info_class			= levels[i].level;
		b.in.file.handle		= handle;
		b.in.output_buffer_length	= 65535;

		status = smb2_getinfo(tree, tree, &b);

		torture_assert_ntstatus_equal(
			tctx, status, NT_STATUS_OK,
			"Wrong error code for large buffer");

		ret = torture_smb2_buffercheck_err(
			tctx, tree, &b, levels[i].fixed, b.out.blob);
		if (!ret) {
			return ret;
		}
	}

	return true;
}

static bool torture_smb2_qfile_buffercheck(struct torture_context *tctx)
{
	bool ret;
	struct smb2_tree *tree;
	struct smb2_create c;
	NTSTATUS status;
	struct smb2_handle handle;
	int i;

	struct level_buffersize levels[] = {
		{ 4, 40 },
		{ 5, 24 },
		{ 6, 8 },
		{ 7, 4 },
		{ 8, 4 },
		{ 16, 4 },
		{ 17, 4 },
		{ 18, 104 },
		{ 21, 8 },
		{ 22, 32 },
		{ 28, 16 },
		{ 34, 56 },
		{ 35, 8 },
	};

	printf("Testing SMB2_GETINFO_FILE buffer sizes\n");

	ret = torture_smb2_connection(tctx, &tree);
	torture_assert(tctx, ret, "connection failed");

	ZERO_STRUCT(c);
	c.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	c.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	c.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	c.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	c.in.create_options = 0;
	c.in.fname = "bufsize.txt";

	c.in.eas.num_eas = 2;
	c.in.eas.eas = talloc_array(tree, struct ea_struct, 2);
	c.in.eas.eas[0].flags = 0;
	c.in.eas.eas[0].name.s = "EAONE";
	c.in.eas.eas[0].value = data_blob_talloc(c.in.eas.eas, "VALUE1", 6);
	c.in.eas.eas[1].flags = 0;
	c.in.eas.eas[1].name.s = "SECONDEA";
	c.in.eas.eas[1].value = data_blob_talloc(c.in.eas.eas, "ValueTwo", 8);

	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok(
		tctx, status, "Unable to create test file");

	handle = c.out.file.handle;

	for (i=0; i<ARRAY_SIZE(levels); i++) {
		struct smb2_getinfo b;

		ZERO_STRUCT(b);
		b.in.info_type			= SMB2_GETINFO_FILE;
		b.in.info_class			= levels[i].level;
		b.in.file.handle		= handle;
		b.in.output_buffer_length	= 65535;

		status = smb2_getinfo(tree, tree, &b);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
			continue;
		}
		torture_assert_ntstatus_equal(
			tctx, status, NT_STATUS_OK,
			"Wrong error code for large buffer");

		ret = torture_smb2_buffercheck_err(
			tctx, tree, &b, levels[i].fixed, b.out.blob);
		if (!ret) {
			return ret;
		}
	}
	return true;
}

static bool torture_smb2_qsec_buffercheck(struct torture_context *tctx)
{
	struct smb2_getinfo b;
	bool ret;
	struct smb2_tree *tree;
	struct smb2_create c;
	NTSTATUS status;
	struct smb2_handle handle;

	printf("Testing SMB2_GETINFO_SECURITY buffer sizes\n");

	ret = torture_smb2_connection(tctx, &tree);
	torture_assert(tctx, ret, "connection failed");

	ZERO_STRUCT(c);
	c.in.oplock_level = 0;
	c.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_DIR_READ_ATTRIBUTE |
		SEC_DIR_LIST | SEC_STD_READ_CONTROL;
	c.in.file_attributes   = 0;
	c.in.create_disposition = NTCREATEX_DISP_OPEN;
	c.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_DELETE;
	c.in.create_options = NTCREATEX_OPTIONS_ASYNC_ALERT;
	c.in.fname = "";

	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok(
		tctx, status, "Unable to create root handle");

	handle = c.out.file.handle;

	ZERO_STRUCT(b);
	b.in.info_type			= SMB2_GETINFO_SECURITY;
	b.in.info_class			= 0;
	b.in.file.handle		= handle;
	b.in.output_buffer_length	= 0;

	status = smb2_getinfo(tree, tree, &b);
	torture_assert_ntstatus_equal(
		tctx, status, NT_STATUS_BUFFER_TOO_SMALL,
		"Wrong error code for large buffer");

	b.in.output_buffer_length	= 1;
	status = smb2_getinfo(tree, tree, &b);
	torture_assert_ntstatus_equal(
		tctx, status, NT_STATUS_BUFFER_TOO_SMALL,
		"Wrong error code for large buffer");

	return true;
}

/* basic testing of all SMB2 getinfo levels
*/
static bool torture_smb2_getinfo(struct torture_context *torture)
{
	struct smb2_tree *tree;
	bool ret = true;
	NTSTATUS status;

	ret = torture_smb2_connection(torture, &tree);
	torture_assert(torture, ret, "connection failed");

	smb2_deltree(tree, FNAME);
	smb2_deltree(tree, DNAME);

	status = torture_setup_complex_file(tree, FNAME);
	torture_assert_ntstatus_ok(torture, status,
				   "setup complex file " FNAME);

	status = torture_setup_complex_file(tree, FNAME ":streamtwo");
	torture_assert_ntstatus_ok(torture, status,
				   "setup complex file " FNAME ":streamtwo");

	status = torture_setup_complex_dir(tree, DNAME);
	torture_assert_ntstatus_ok(torture, status,
				   "setup complex dir " DNAME);

	status = torture_setup_complex_file(tree, DNAME ":streamtwo");
	torture_assert_ntstatus_ok(torture, status,
				   "setup complex dir " DNAME ":streamtwo");

	ret &= torture_smb2_fileinfo(torture, tree);

	return ret;
}

struct torture_suite *torture_smb2_getinfo_init(void)
{
	struct torture_suite *suite = torture_suite_create(
		talloc_autofree_context(), "getinfo");

	torture_suite_add_simple_test(suite, "complex", torture_smb2_getinfo);
	torture_suite_add_simple_test(suite, "fsinfo",  torture_smb2_fsinfo);
	torture_suite_add_simple_test(suite, "qfs_buffercheck",
				      torture_smb2_qfs_buffercheck);
	torture_suite_add_simple_test(suite, "qfile_buffercheck",
				      torture_smb2_qfile_buffercheck);
	torture_suite_add_simple_test(suite, "qsec_buffercheck",
				      torture_smb2_qsec_buffercheck);
	return suite;
}
