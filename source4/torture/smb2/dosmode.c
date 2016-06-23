/*
   Unix SMB/CIFS implementation.

   SMB2 setinfo individual test suite

   Copyright (C) Ralph Boehme 2016

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
#include "system/time.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"

#include "torture/torture.h"
#include "torture/smb2/proto.h"

/*
  test dosmode and hidden files
*/
bool torture_smb2_dosmode(struct torture_context *tctx)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_tree *tree = NULL;
	const char *dname = "torture_dosmode";
	const char *fname = "torture_dosmode\\file";
	const char *hidefile = "torture_dosmode\\hidefile";
	const char *dotfile = "torture_dosmode\\.dotfile";
	struct smb2_handle h1 = {{0}};
	struct smb2_create io;
	union smb_setfileinfo sfinfo;
	union smb_fileinfo finfo2;

	torture_comment(tctx, "Checking dosmode with \"hide files\" "
			"and \"hide dot files\"\n");

	if (!torture_smb2_connection(tctx, &tree)) {
		return false;
	}

	smb2_deltree(tree, dname);

	status = torture_smb2_testdir(tree, dname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed");

	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.create_options = 0;
	io.in.fname = fname;

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");

	ZERO_STRUCT(sfinfo);
	sfinfo.basic_info.in.attrib = FILE_ATTRIBUTE_HIDDEN;
	sfinfo.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	sfinfo.generic.in.file.handle = io.out.file.handle;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_filefailed");

	ZERO_STRUCT(finfo2);
	finfo2.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	finfo2.generic.in.file.handle = io.out.file.handle;
	status = smb2_getinfo_file(tree, tctx, &finfo2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");
	torture_assert_int_equal_goto(tctx, finfo2.all_info2.out.attrib & FILE_ATTRIBUTE_HIDDEN,
				      FILE_ATTRIBUTE_HIDDEN, ret, done,
				      "FILE_ATTRIBUTE_HIDDEN is not set");

	smb2_util_close(tree, io.out.file.handle);

	/* This must fail with attribute mismatch */
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.create_options = 0;
	io.in.fname = fname;

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED,
					   ret, done,"smb2_create failed");

	/* Create a file in "hide files" */
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.create_options = 0;
	io.in.fname = hidefile;

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");

	ZERO_STRUCT(finfo2);
	finfo2.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	finfo2.generic.in.file.handle = io.out.file.handle;
	status = smb2_getinfo_file(tree, tctx, &finfo2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");
	torture_assert_int_equal_goto(tctx, finfo2.all_info2.out.attrib & FILE_ATTRIBUTE_HIDDEN,
				      FILE_ATTRIBUTE_HIDDEN, ret, done,
				      "FILE_ATTRIBUTE_HIDDEN is not set");

	smb2_util_close(tree, io.out.file.handle);

	/* Overwrite a file in "hide files", should pass */
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.create_options = 0;
	io.in.fname = hidefile;

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	smb2_util_close(tree, io.out.file.handle);

	/* Create a "hide dot files" */
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.create_options = 0;
	io.in.fname = dotfile;

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");

	ZERO_STRUCT(finfo2);
	finfo2.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	finfo2.generic.in.file.handle = io.out.file.handle;
	status = smb2_getinfo_file(tree, tctx, &finfo2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");
	torture_assert_int_equal_goto(tctx, finfo2.all_info2.out.attrib & FILE_ATTRIBUTE_HIDDEN,
				      FILE_ATTRIBUTE_HIDDEN, ret, done,
				      "FILE_ATTRIBUTE_HIDDEN is not set");

	smb2_util_close(tree, io.out.file.handle);

	/* Overwrite a "hide dot files", should pass */
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.create_options = 0;
	io.in.fname = dotfile;

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	smb2_util_close(tree, io.out.file.handle);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_deltree(tree, dname);
	return ret;
}
