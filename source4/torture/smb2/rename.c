/*
   Unix SMB/CIFS implementation.

   SMB2 rename test suite

   Copyright (C) Christian Ambach 2012

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

#include "librpc/gen_ndr/security.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(torture, TORTURE_FAIL, \
		       "(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define BASEDIR "test_rename"

/*
 * basic testing of rename: open file with DELETE access
 * this should pass
 */

static bool torture_smb2_rename_simple(struct torture_context *torture,
		struct smb2_tree *tree1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	union smb_close cl;
	union smb_setfileinfo sinfo;
	union smb_fileinfo fi;
	struct smb2_handle h1;

	smb2_deltree(tree1, BASEDIR);
	smb2_util_rmdir(tree1, BASEDIR);

	torture_comment(torture, "Creating base directory\n");

	smb2_util_mkdir(tree1, BASEDIR);


	torture_comment(torture, "Creating test file\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_ALL|SEC_STD_DELETE;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR "\\file.txt";

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	torture_comment(torture, "Renaming test file\n");

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = io.smb2.out.file.handle;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name =
		BASEDIR "\\newname.txt";
	status = smb2_setinfo_file(tree1, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(torture, "Checking for new filename\n");

	ZERO_STRUCT(fi);
	fi.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	fi.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree1, torture, &fi);
	CHECK_STATUS(status, NT_STATUS_OK);


	torture_comment(torture, "Closing test file\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = h1;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(h1);

done:

	torture_comment(torture, "Cleaning up\n");

	if (h1.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = h1;
		status = smb2_close(tree1, &(cl.smb2));
	}
	smb2_deltree(tree1, BASEDIR);
	return ret;
}

/*
 * basic testing of rename, this time do not request DELETE access
 * for the file, this should fail
 */

static bool torture_smb2_rename_simple2(struct torture_context *torture,
		struct smb2_tree *tree1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	union smb_close cl;
	union smb_setfileinfo sinfo;
	struct smb2_handle h1;

	smb2_deltree(tree1, BASEDIR);
	smb2_util_rmdir(tree1, BASEDIR);

	torture_comment(torture, "Creating base directory\n");

	smb2_util_mkdir(tree1, BASEDIR);


	torture_comment(torture, "Creating test file\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_ALL;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR "\\file.txt";

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	torture_comment(torture, "Renaming test file\n");

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = io.smb2.out.file.handle;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name =
		BASEDIR "\\newname.txt";
	status = smb2_setinfo_file(tree1, &sinfo);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(torture, "Closing test file\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = h1;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(h1);

done:

	torture_comment(torture, "Cleaning up\n");

	if (h1.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = h1;
		status = smb2_close(tree1, &(cl.smb2));
	}
	smb2_deltree(tree1, BASEDIR);
	return ret;
}


/*
 * testing of rename with no sharing allowed on file
 * this should work
 */

static bool torture_smb2_rename_no_sharemode(struct torture_context *torture,
		struct smb2_tree *tree1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	union smb_close cl;
	union smb_setfileinfo sinfo;
	union smb_fileinfo fi;
	struct smb2_handle h1;

	smb2_deltree(tree1, BASEDIR);
	smb2_util_rmdir(tree1, BASEDIR);

	torture_comment(torture, "Creating base directory\n");

	smb2_util_mkdir(tree1, BASEDIR);


	torture_comment(torture, "Creating test file\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = 0x0017019f;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR "\\file.txt";

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	torture_comment(torture, "Renaming test file\n");

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = io.smb2.out.file.handle;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name =
		BASEDIR "\\newname.txt";
	status = smb2_setinfo_file(tree1, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(torture, "Checking for new filename\n");

	ZERO_STRUCT(fi);
	fi.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	fi.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree1, torture, &fi);
	CHECK_STATUS(status, NT_STATUS_OK);


	torture_comment(torture, "Closing test file\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = h1;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(h1);

done:

	torture_comment(torture, "Cleaning up\n");

	if (h1.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = h1;
		status = smb2_close(tree1, &(cl.smb2));
	}
	smb2_deltree(tree1, BASEDIR);
	return ret;
}

/*
 * testing of rename when opening parent dir with delete access and delete
 * sharing allowed
 * should result in sharing violation
 */

static bool torture_smb2_rename_with_delete_access(struct torture_context *torture,
		struct smb2_tree *tree1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	union smb_close cl;
	union smb_setfileinfo sinfo;
	struct smb2_handle fh, dh;

	smb2_deltree(tree1, BASEDIR);
	smb2_util_rmdir(tree1, BASEDIR);

	torture_comment(torture, "Creating base directory\n");

	smb2_util_mkdir(tree1, BASEDIR);

	torture_comment(torture, "Opening parent directory\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_STD_DELETE | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR;

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = io.smb2.out.file.handle;


	torture_comment(torture, "Creating test file\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_STD_DELETE | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_WRITE_EA | SEC_FILE_READ_EA |
		SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR "\\file.txt";

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	fh = io.smb2.out.file.handle;

	torture_comment(torture, "Renaming test file\n");

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = fh;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name =
		BASEDIR "\\newname.txt";
	status = smb2_setinfo_file(tree1, &sinfo);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	torture_comment(torture, "Closing test file\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = fh;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(fh);

	torture_comment(torture, "Closing directory\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = dh;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(dh);


done:

	torture_comment(torture, "Cleaning up\n");

	if (fh.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = fh;
		status = smb2_close(tree1, &(cl.smb2));
	}
	if (dh.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = dh;
		status = smb2_close(tree1, &(cl.smb2));
	}

	smb2_deltree(tree1, BASEDIR);
	return ret;
}


/*
 * testing of rename with delete access on parent dir
 * this is a variation of the test above: parent dir is opened
 * without share_delete, so rename must fail
 */

static bool torture_smb2_rename_with_delete_access2(struct torture_context *torture,
		struct smb2_tree *tree1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	union smb_close cl;
	union smb_setfileinfo sinfo;
	struct smb2_handle fh, dh;

	smb2_deltree(tree1, BASEDIR);
	smb2_util_rmdir(tree1, BASEDIR);

	torture_comment(torture, "Creating base directory\n");

	smb2_util_mkdir(tree1, BASEDIR);

	torture_comment(torture, "Opening parent directory\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_STD_DELETE | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR;

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = io.smb2.out.file.handle;


	torture_comment(torture, "Creating test file\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_STD_DELETE | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_WRITE_EA | SEC_FILE_READ_EA |
		SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR "\\file.txt";

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	fh = io.smb2.out.file.handle;

	torture_comment(torture, "Renaming test file\n");

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = fh;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name =
		BASEDIR "\\newname.txt";
	status = smb2_setinfo_file(tree1, &sinfo);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	torture_comment(torture, "Closing test file\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = fh;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(fh);

	torture_comment(torture, "Closing directory\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = dh;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(dh);


done:

	torture_comment(torture, "Cleaning up\n");

	if (fh.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = fh;
		status = smb2_close(tree1, &(cl.smb2));
	}
	if (dh.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = dh;
		status = smb2_close(tree1, &(cl.smb2));
	}

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

/*
 * testing of rename when opening parent dir with no delete access and delete
 * sharing allowed
 * this should pass
 */

static bool torture_smb2_rename_no_delete_access(struct torture_context *torture,
		struct smb2_tree *tree1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	union smb_close cl;
	union smb_setfileinfo sinfo;
	union smb_fileinfo fi;
	struct smb2_handle fh, dh;

	smb2_deltree(tree1, BASEDIR);
	smb2_util_rmdir(tree1, BASEDIR);

	torture_comment(torture, "Creating base directory\n");

	smb2_util_mkdir(tree1, BASEDIR);

	torture_comment(torture, "Opening parent directory\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR;

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = io.smb2.out.file.handle;


	torture_comment(torture, "Creating test file\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_STD_DELETE | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_WRITE_EA | SEC_FILE_READ_EA |
		SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR "\\file.txt";

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	fh = io.smb2.out.file.handle;

	torture_comment(torture, "Renaming test file\n");

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = fh;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name =
		BASEDIR "\\newname.txt";
	status = smb2_setinfo_file(tree1, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(torture, "Checking for new filename\n");

	ZERO_STRUCT(fi);
	fi.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	fi.generic.in.file.handle = fh;
	status = smb2_getinfo_file(tree1, torture, &fi);
	CHECK_STATUS(status, NT_STATUS_OK);


	torture_comment(torture, "Closing test file\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = fh;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(fh);

	torture_comment(torture, "Closing directory\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = dh;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(dh);


done:

	torture_comment(torture, "Cleaning up\n");

	if (fh.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = fh;
		status = smb2_close(tree1, &(cl.smb2));
	}
	if (dh.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = dh;
		status = smb2_close(tree1, &(cl.smb2));
	}

	smb2_deltree(tree1, BASEDIR);
	return ret;
}


/*
 * testing of rename with no delete access on parent dir
 * this is the negative case of the test above: parent dir is opened
 * without share_delete, so rename must fail
 */

static bool torture_smb2_rename_no_delete_access2(struct torture_context *torture,
		struct smb2_tree *tree1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	union smb_close cl;
	union smb_setfileinfo sinfo;
	struct smb2_handle fh, dh;

	smb2_deltree(tree1, BASEDIR);
	smb2_util_rmdir(tree1, BASEDIR);

	torture_comment(torture, "Creating base directory\n");

	smb2_util_mkdir(tree1, BASEDIR);

	torture_comment(torture, "Opening parent directory\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR;

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = io.smb2.out.file.handle;


	torture_comment(torture, "Creating test file\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_STD_DELETE | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_WRITE_EA | SEC_FILE_READ_EA |
		SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR "\\file.txt";

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	fh = io.smb2.out.file.handle;

	torture_comment(torture, "Renaming test file\n");

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = fh;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name =
		BASEDIR "\\newname.txt";
	status = smb2_setinfo_file(tree1, &sinfo);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	torture_comment(torture, "Closing test file\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = fh;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(fh);

	torture_comment(torture, "Closing directory\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = dh;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(dh);


done:

	torture_comment(torture, "Cleaning up\n");

	if (fh.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = fh;
		status = smb2_close(tree1, &(cl.smb2));
	}
	if (dh.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = dh;
		status = smb2_close(tree1, &(cl.smb2));
	}

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

/*
 * this is a replay of how Word 2010 saves a file
 * this should pass
 */

static bool torture_smb2_rename_msword(struct torture_context *torture,
		struct smb2_tree *tree1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	union smb_close cl;
	union smb_setfileinfo sinfo;
	union smb_fileinfo fi;
	struct smb2_handle fh, dh;

	smb2_deltree(tree1, BASEDIR);
	smb2_util_rmdir(tree1, BASEDIR);

	torture_comment(torture, "Creating base directory\n");

	smb2_util_mkdir(tree1, BASEDIR);

	torture_comment(torture, "Creating test file\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = 0x0017019f;
	io.smb2.in.create_options = 0x60;
	io.smb2.in.file_attributes = 0;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR "\\file.txt";

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	fh = io.smb2.out.file.handle;

	torture_comment(torture, "Opening parent directory\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = 0x00100080;
	io.smb2.in.create_options = 0x00800021;
	io.smb2.in.file_attributes = 0;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR;

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = io.smb2.out.file.handle;

	torture_comment(torture, "Renaming test file\n");

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = fh;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name =
		BASEDIR "\\newname.txt";
	status = smb2_setinfo_file(tree1, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(torture, "Checking for new filename\n");

	ZERO_STRUCT(fi);
	fi.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	fi.generic.in.file.handle = fh;
	status = smb2_getinfo_file(tree1, torture, &fi);
	CHECK_STATUS(status, NT_STATUS_OK);


	torture_comment(torture, "Closing test file\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = fh;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(fh);

	torture_comment(torture, "Closing directory\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = dh;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(dh);


done:

	torture_comment(torture, "Cleaning up\n");

	if (fh.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = fh;
		status = smb2_close(tree1, &(cl.smb2));
	}
	if (dh.data) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = dh;
		status = smb2_close(tree1, &(cl.smb2));
	}

	smb2_deltree(tree1, BASEDIR);
	return ret;
}



/*
   basic testing of SMB2 rename
 */
struct torture_suite *torture_smb2_rename_init(void)
{
	struct torture_suite *suite =
		torture_suite_create(talloc_autofree_context(), "rename");

	torture_suite_add_1smb2_test(suite, "simple",
		torture_smb2_rename_simple);

	torture_suite_add_1smb2_test(suite, "simple_nodelete)",
		torture_smb2_rename_simple2);

	torture_suite_add_1smb2_test(suite, "no_sharing",
		torture_smb2_rename_no_sharemode);

	torture_suite_add_1smb2_test(suite,
		"share_delete_and_delete_access",
		torture_smb2_rename_with_delete_access);

	torture_suite_add_1smb2_test(suite,
		"no_share_delete_but_delete_access",
		torture_smb2_rename_with_delete_access2);

	torture_suite_add_1smb2_test(suite,
		"share_delete_no_delete_access",
		torture_smb2_rename_no_delete_access);

	torture_suite_add_1smb2_test(suite,
		"no_share_delete_no_delete_access",
		torture_smb2_rename_no_delete_access2);

	torture_suite_add_1smb2_test(suite,
		"msword",
		torture_smb2_rename_msword);

	suite->description = talloc_strdup(suite, "smb2.rename tests");

	return suite;
}
