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
#define LEVEL(x) .name = #x, .level = x
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
 { LEVEL(RAW_QFS_OBJECTID_INFORMATION) },
 { LEVEL(RAW_QFS_SECTOR_SIZE_INFORMATION) },
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

	torture_comment(tctx, "Testing file info levels\n");
	torture_smb2_all_info(tctx, tree, hfile);
	torture_smb2_all_info(tctx, tree, hdir);

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
  test granted access when desired access includes
  FILE_EXECUTE and does not include FILE_READ_DATA
*/
static bool torture_smb2_fileinfo_grant_read(struct torture_context *tctx)
{
	struct smb2_tree *tree;
	bool ret;
	struct smb2_handle hfile, hdir;
	NTSTATUS status;
	uint32_t file_granted_access, dir_granted_access;

	ret = torture_smb2_connection(tctx, &tree);
	torture_assert(tctx, ret, "connection failed");

	status = torture_smb2_testfile_access(
	    tree, FNAME, &hfile, SEC_FILE_EXECUTE | SEC_FILE_READ_ATTRIBUTE);
	torture_assert_ntstatus_ok(tctx, status,
				   "Unable to create test file " FNAME "\n");
	status =
	    torture_smb2_get_allinfo_access(tree, hfile, &file_granted_access);
	torture_assert_ntstatus_ok(tctx, status,
				   "Unable to query test file access ");
	torture_assert_int_equal(tctx, file_granted_access,
				 SEC_FILE_EXECUTE | SEC_FILE_READ_ATTRIBUTE,
				 "granted file access ");
	smb2_util_close(tree, hfile);

	status = torture_smb2_testdir_access(
	    tree, DNAME, &hdir, SEC_FILE_EXECUTE | SEC_FILE_READ_ATTRIBUTE);
	torture_assert_ntstatus_ok(tctx, status,
				   "Unable to create test dir " DNAME "\n");
	status =
	    torture_smb2_get_allinfo_access(tree, hdir, &dir_granted_access);
	torture_assert_ntstatus_ok(tctx, status,
				   "Unable to query test dir access ");
	torture_assert_int_equal(tctx, dir_granted_access,
				 SEC_FILE_EXECUTE | SEC_FILE_READ_ATTRIBUTE,
				 "granted dir access ");
	smb2_util_close(tree, hdir);

	return true;
}

static bool torture_smb2_fileinfo_normalized(struct torture_context *tctx)
{
	struct smb2_tree *tree = NULL;
	bool ret;
	struct smb2_handle hroot;
	const char *d1 = NULL, *d1l = NULL, *d1u = NULL;
	struct smb2_handle hd1, hd1l, hd1u;
	const char *d2 = NULL, *d2l = NULL, *d2u = NULL;
	struct smb2_handle hd2, hd2l, hd2u;
	const char *d3 = NULL, *d3l = NULL, *d3u = NULL;
	struct smb2_handle hd3, hd3l, hd3u;
	const char *d3s = NULL, *d3sl = NULL, *d3su = NULL, *d3sd = NULL;
	struct smb2_handle hd3s, hd3sl, hd3su, hd3sd;
	const char *f4 = NULL, *f4l = NULL, *f4u = NULL, *f4d = NULL;
	struct smb2_handle hf4, hf4l, hf4u, hf4d;
	const char *f4s = NULL, *f4sl = NULL, *f4su = NULL, *f4sd = NULL;
	struct smb2_handle hf4s, hf4sl, hf4su, hf4sd;
	union smb_fileinfo info = {
		.normalized_name_info = {
			.level = RAW_FILEINFO_NORMALIZED_NAME_INFORMATION,
		},
	};
	NTSTATUS status;
	enum protocol_types protocol;
	struct smb2_tree *tree_3_0 = NULL;
	struct smbcli_options options3_0;
	struct smb2_handle hroot_3_0;

	ret = torture_smb2_connection(tctx, &tree);
	torture_assert(tctx, ret, "connection failed");

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);

	d1 = talloc_asprintf(tctx, "torture_dIr1N");
	torture_assert_not_null(tctx, d1, "d1");
	d1l = strlower_talloc(tctx, d1);
	torture_assert_not_null(tctx, d1l, "d1l");
	d1u = strupper_talloc(tctx, d1);
	torture_assert_not_null(tctx, d1u, "d1u");

	d2 = talloc_asprintf(tctx, "%s\\dIr2Na", d1);
	torture_assert_not_null(tctx, d2, "d2");
	d2l = strlower_talloc(tctx, d2);
	torture_assert_not_null(tctx, d2l, "d2l");
	d2u = strupper_talloc(tctx, d2);
	torture_assert_not_null(tctx, d2u, "d2u");

	d3 = talloc_asprintf(tctx, "%s\\dIr3NaM", d2);
	torture_assert_not_null(tctx, d3, "d3");
	d3l = strlower_talloc(tctx, d3);
	torture_assert_not_null(tctx, d3l, "d3l");
	d3u = strupper_talloc(tctx, d3);
	torture_assert_not_null(tctx, d3u, "d3u");

	d3s = talloc_asprintf(tctx, "%s:sTrEaM3", d3);
	torture_assert_not_null(tctx, d3s, "d3s");
	d3sl = strlower_talloc(tctx, d3s);
	torture_assert_not_null(tctx, d3sl, "d3sl");
	d3su = strupper_talloc(tctx, d3s);
	torture_assert_not_null(tctx, d3su, "d3su");
	d3sd = talloc_asprintf(tctx, "%s:$DaTa", d3s);
	torture_assert_not_null(tctx, d3sd, "d3sd");

	f4 = talloc_asprintf(tctx, "%s\\fIlE4NaMe", d3);
	torture_assert_not_null(tctx, f4, "f4");
	f4l = strlower_talloc(tctx, f4);
	torture_assert_not_null(tctx, f4l, "f4l");
	f4u = strupper_talloc(tctx, f4);
	torture_assert_not_null(tctx, f4u, "f4u");
	f4d = talloc_asprintf(tctx, "%s::$dAtA", f4);
	torture_assert_not_null(tctx, f4d, "f4d");

	f4s = talloc_asprintf(tctx, "%s:StReAm4", f4);
	torture_assert_not_null(tctx, f4s, "f4s");
	f4sl = strlower_talloc(tctx, f4s);
	torture_assert_not_null(tctx, f4sl, "f4sl");
	f4su = strupper_talloc(tctx, f4s);
	torture_assert_not_null(tctx, f4su, "f4su");
	f4sd = talloc_asprintf(tctx, "%s:$dAtA", f4s);
	torture_assert_not_null(tctx, f4sd, "f4sd");

	status = smb2_util_roothandle(tree, &hroot);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create root handle");

	info.normalized_name_info.in.file.handle = hroot;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	if (protocol < PROTOCOL_SMB3_11) {
		/*
		 * Only SMB 3.1.1 and above should offer this.
		 */
		torture_assert_ntstatus_equal(tctx, status,
					      NT_STATUS_NOT_SUPPORTED,
					      "getinfo hroot");
		torture_skip(tctx, "SMB 3.1.1 not supported");
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
		/*
		 * Not all servers support this.
		 * (only Windows 10 1803 and higher)
		 */
		torture_skip(tctx, "NORMALIZED_NAME_INFORMATION not supported");
	}
	torture_assert_ntstatus_ok(tctx, status, "getinfo hroot");
	torture_assert(tctx, info.normalized_name_info.out.fname.s == NULL,
		       "getinfo hroot should be empty");

	smb2_deltree(tree, d1);

	status = torture_smb2_testdir(tree, d1, &hd1);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create hd1");
	status = torture_smb2_open(tree, d1l, SEC_RIGHTS_FILE_ALL, &hd1l);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hd1l");
	status = torture_smb2_open(tree, d1u, SEC_RIGHTS_FILE_ALL, &hd1u);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hd1u");

	status = torture_smb2_testdir(tree, d2, &hd2);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create hd2");
	status = torture_smb2_open(tree, d2l, SEC_RIGHTS_FILE_ALL, &hd2l);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hd2l");
	status = torture_smb2_open(tree, d2u, SEC_RIGHTS_FILE_ALL, &hd2u);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hd2u");

	status = torture_smb2_testdir(tree, d3, &hd3);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create hd3");
	status = torture_smb2_open(tree, d3l, SEC_RIGHTS_FILE_ALL, &hd3l);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hd3l");
	status = torture_smb2_open(tree, d3u, SEC_RIGHTS_FILE_ALL, &hd3u);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hd3u");

	status = torture_smb2_testfile(tree, d3s, &hd3s);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create hd3s");
	status = torture_smb2_open(tree, d3sl, SEC_RIGHTS_FILE_ALL, &hd3sl);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hd3sl");
	status = torture_smb2_open(tree, d3su, SEC_RIGHTS_FILE_ALL, &hd3su);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hd3su");
	status = torture_smb2_open(tree, d3sd, SEC_RIGHTS_FILE_ALL, &hd3sd);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hd3sd");

	status = torture_smb2_testfile(tree, f4, &hf4);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create hf4");
	status = torture_smb2_open(tree, f4l, SEC_RIGHTS_FILE_ALL, &hf4l);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hf4l");
	status = torture_smb2_open(tree, f4u, SEC_RIGHTS_FILE_ALL, &hf4u);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hf4u");
	status = torture_smb2_open(tree, f4d, SEC_RIGHTS_FILE_ALL, &hf4d);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hf4d");

	status = torture_smb2_testfile(tree, f4s, &hf4s);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create hf4s");
	status = torture_smb2_open(tree, f4sl, SEC_RIGHTS_FILE_ALL, &hf4sl);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hf4sl");
	status = torture_smb2_open(tree, f4su, SEC_RIGHTS_FILE_ALL, &hf4su);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hf4su");
	status = torture_smb2_open(tree, f4sd, SEC_RIGHTS_FILE_ALL, &hf4sd);
	torture_assert_ntstatus_ok(tctx, status, "Unable to open hf4sd");

	info.normalized_name_info.in.file.handle = hd1;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd1");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d1, "getinfo hd1");
	info.normalized_name_info.in.file.handle = hd1l;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd1l");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d1, "getinfo hd1l");
	info.normalized_name_info.in.file.handle = hd1u;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd1u");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d1, "getinfo hd1u");

	info.normalized_name_info.in.file.handle = hd2;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd2");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d2, "getinfo hd2");
	info.normalized_name_info.in.file.handle = hd2l;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd2l");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d2, "getinfo hd2l");
	info.normalized_name_info.in.file.handle = hd2u;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd2u");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d2, "getinfo hd2u");

	info.normalized_name_info.in.file.handle = hd3;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd3");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d3, "getinfo hd3");
	info.normalized_name_info.in.file.handle = hd3l;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd3l");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d3, "getinfo hd3l");
	info.normalized_name_info.in.file.handle = hd3u;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd3u");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d3, "getinfo hd3u");

	info.normalized_name_info.in.file.handle = hd3s;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd3s");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d3s, "getinfo hd3s");
	info.normalized_name_info.in.file.handle = hd3sl;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd3sl");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d3s, "getinfo hd3sl");
	info.normalized_name_info.in.file.handle = hd3su;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd3su");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d3s, "getinfo hd3su");
	info.normalized_name_info.in.file.handle = hd3sd;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hd3sd");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 d3s, "getinfo hd3sd");

	info.normalized_name_info.in.file.handle = hf4;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hf4");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 f4, "getinfo hf4");
	info.normalized_name_info.in.file.handle = hf4l;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hf4l");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 f4, "getinfo hf4l");
	info.normalized_name_info.in.file.handle = hf4u;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hf4u");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 f4, "getinfo hf4u");
	info.normalized_name_info.in.file.handle = hf4d;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hf4d");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 f4, "getinfo hf4d");

	info.normalized_name_info.in.file.handle = hf4s;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hf4s");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 f4s, "getinfo hf4s");
	info.normalized_name_info.in.file.handle = hf4sl;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hf4sl");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 f4s, "getinfo hf4sl");
	info.normalized_name_info.in.file.handle = hf4su;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hf4su");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 f4s, "getinfo hf4su");
	info.normalized_name_info.in.file.handle = hf4sd;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree, tree, &info);
	torture_assert_ntstatus_ok(tctx, status, "getinfo hf4sd");
	torture_assert_str_equal(tctx, info.normalized_name_info.out.fname.s,
				 f4s, "getinfo hf4sd");

	/* Set max protocol to SMB 3.0.2 */
	options3_0 = tree->session->transport->options;
	options3_0.max_protocol = PROTOCOL_SMB3_02;
	options3_0.client_guid = GUID_zero();
	ret = torture_smb2_connection_ext(tctx, 0, &options3_0, &tree_3_0);
	torture_assert(tctx, ret, "connection with SMB < 3.1.1 failed");

	status = smb2_util_roothandle(tree_3_0, &hroot_3_0);
	torture_assert_ntstatus_ok(tctx, status, "Unable to create root handle 3_0");

	info.normalized_name_info.in.file.handle = hroot_3_0;
	ZERO_STRUCT(info.normalized_name_info.out);
	status = smb2_getinfo_file(tree_3_0, tree_3_0, &info);
	torture_assert_ntstatus_equal(tctx, status,
				      NT_STATUS_NOT_SUPPORTED,
				      "getinfo hroot");

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

	torture_comment(tctx, "Testing fsinfo levels\n");

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

	torture_comment(tctx, "Testing SMB2_GETINFO_FS buffer sizes\n");

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
		b.in.info_type			= SMB2_0_INFO_FILESYSTEM;
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

	torture_comment(tctx, "Testing SMB2_GETINFO_FILE buffer sizes\n");

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
		b.in.info_type			= SMB2_0_INFO_FILE;
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

	torture_comment(tctx, "Testing SMB2_GETINFO_SECURITY buffer sizes\n");

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
	b.in.info_type			= SMB2_0_INFO_SECURITY;
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
static bool torture_smb2_getinfo(struct torture_context *tctx)
{
	struct smb2_tree *tree;
	bool ret = true;
	NTSTATUS status;

	ret = torture_smb2_connection(tctx, &tree);
	torture_assert(tctx, ret, "connection failed");

	smb2_deltree(tree, FNAME);
	smb2_deltree(tree, DNAME);

	status = torture_setup_complex_file(tctx, tree, FNAME);
	torture_assert_ntstatus_ok(tctx, status,
				   "setup complex file " FNAME);

	status = torture_setup_complex_file(tctx, tree, FNAME ":streamtwo");
	torture_assert_ntstatus_ok(tctx, status,
				   "setup complex file " FNAME ":streamtwo");

	status = torture_setup_complex_dir(tctx, tree, DNAME);
	torture_assert_ntstatus_ok(tctx, status,
				   "setup complex dir " DNAME);

	status = torture_setup_complex_file(tctx, tree, DNAME ":streamtwo");
	torture_assert_ntstatus_ok(tctx, status,
				   "setup complex dir " DNAME ":streamtwo");

	ret &= torture_smb2_fileinfo(tctx, tree);

	return ret;
}

struct torture_suite *torture_smb2_getinfo_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(
		ctx, "getinfo");

	torture_suite_add_simple_test(suite, "complex", torture_smb2_getinfo);
	torture_suite_add_simple_test(suite, "fsinfo",  torture_smb2_fsinfo);
	torture_suite_add_simple_test(suite, "qfs_buffercheck",
				      torture_smb2_qfs_buffercheck);
	torture_suite_add_simple_test(suite, "qfile_buffercheck",
				      torture_smb2_qfile_buffercheck);
	torture_suite_add_simple_test(suite, "qsec_buffercheck",
				      torture_smb2_qsec_buffercheck);
	torture_suite_add_simple_test(suite, "granted",
				      torture_smb2_fileinfo_grant_read);
	torture_suite_add_simple_test(suite, "normalized",
				      torture_smb2_fileinfo_normalized);
	return suite;
}
