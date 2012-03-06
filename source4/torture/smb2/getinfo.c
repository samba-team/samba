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

#include "torture/torture.h"
#include "torture/smb2/proto.h"

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
static bool torture_smb2_fsinfo(struct torture_context *tctx, struct smb2_tree *tree)
{
	int i;
	NTSTATUS status;
	struct smb2_handle handle;

	printf("Testing fsinfo levels\n");
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


/*
  test for buffer size handling
*/
static bool torture_smb2_buffercheck(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_handle handle;
	struct smb2_getinfo b;

	printf("Testing buffer size handling\n");
	status = smb2_util_roothandle(tree, &handle);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create root handle");

	ZERO_STRUCT(b);
	b.in.info_type            = SMB2_GETINFO_FS;
	b.in.info_class           = 1;
	b.in.output_buffer_length = 0x1;
	b.in.input_buffer_length  = 0;
	b.in.file.handle          = handle;

	status = smb2_getinfo(tree, tree, &b);
	torture_assert_ntstatus_equal(tctx, status,
				      NT_STATUS_INFO_LENGTH_MISMATCH,
				      "Wrong error code for small buffer");
	return true;
}


/* basic testing of all SMB2 getinfo levels
*/
bool torture_smb2_getinfo(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
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
	ret &= torture_smb2_fsinfo(torture, tree);
	ret &= torture_smb2_buffercheck(torture, tree);

	talloc_free(mem_ctx);

	return ret;
}
