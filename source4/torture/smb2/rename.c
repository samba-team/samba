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
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"

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

	ZERO_STRUCT(h1);

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

	if (h1.data[0] || h1.data[1]) {
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

	ZERO_STRUCT(h1);

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

	if (h1.data[0] || h1.data[1]) {
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

	ZERO_STRUCT(h1);

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

	if (h1.data[0] || h1.data[1]) {
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

	ZERO_STRUCT(fh);
	ZERO_STRUCT(dh);

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

	if (fh.data[0] || fh.data[1]) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = fh;
		status = smb2_close(tree1, &(cl.smb2));
	}
	if (dh.data[0] || dh.data[1]) {
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

	ZERO_STRUCT(fh);
	ZERO_STRUCT(dh);

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

	if (fh.data[0] || fh.data[1]) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = fh;
		status = smb2_close(tree1, &(cl.smb2));
	}
	if (dh.data[0] || dh.data[1]) {
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

	ZERO_STRUCT(fh);
	ZERO_STRUCT(dh);

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

	if (fh.data[0] || fh.data[1]) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = fh;
		status = smb2_close(tree1, &(cl.smb2));
	}
	if (dh.data[0] || dh.data[1]) {
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

	ZERO_STRUCT(fh);
	ZERO_STRUCT(dh);

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

	if (fh.data[0] || fh.data[1]) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = fh;
		status = smb2_close(tree1, &(cl.smb2));
	}
	if (dh.data[0] || dh.data[1]) {
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

	ZERO_STRUCT(fh);
	ZERO_STRUCT(dh);

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

	if (fh.data[0] || fh.data[1]) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = fh;
		status = smb2_close(tree1, &(cl.smb2));
	}
	if (dh.data[0] || dh.data[1]) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = dh;
		status = smb2_close(tree1, &(cl.smb2));
	}

	smb2_deltree(tree1, BASEDIR);
	return ret;
}

static bool torture_smb2_rename_dir_openfile(struct torture_context *torture,
					     struct smb2_tree *tree1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_open io;
	union smb_close cl;
	union smb_setfileinfo sinfo;
	struct smb2_handle d1, h1;

	ZERO_STRUCT(d1);
	ZERO_STRUCT(h1);

	smb2_deltree(tree1, BASEDIR);
	smb2_util_rmdir(tree1, BASEDIR);

	torture_comment(torture, "Creating base directory\n");

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = 0x0017019f;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.share_access = 0;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR;

	status = smb2_create(tree1, torture, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	d1 = io.smb2.out.file.handle;

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

	torture_comment(torture, "Renaming directory\n");

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = d1;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name =
		BASEDIR "-new";
	status = smb2_setinfo_file(tree1, &sinfo);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	torture_comment(torture, "Closing directory\n");

	ZERO_STRUCT(cl.smb2);
	cl.smb2.level = RAW_CLOSE_SMB2;
	cl.smb2.in.file.handle = d1;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	ZERO_STRUCT(d1);

	torture_comment(torture, "Closing test file\n");

	cl.smb2.in.file.handle = h1;
	status = smb2_close(tree1, &(cl.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	ZERO_STRUCT(h1);

done:

	torture_comment(torture, "Cleaning up\n");

	if (h1.data[0] || h1.data[1]) {
		ZERO_STRUCT(cl.smb2);
		cl.smb2.level = RAW_CLOSE_SMB2;
		cl.smb2.in.file.handle = h1;
		status = smb2_close(tree1, &(cl.smb2));
	}
	smb2_deltree(tree1, BASEDIR);
	return ret;
}

struct rename_one_dir_cycle_state {
	struct tevent_context *ev;
	struct smb2_tree *tree;
	struct smb2_handle file;
	const char *base_name;
	char *new_name;
	unsigned *rename_counter;

	unsigned current;
	unsigned max;
	union smb_setfileinfo sinfo;
};

static void rename_one_dir_cycle_done(struct smb2_request *subreq);

static struct tevent_req *rename_one_dir_cycle_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct smb2_tree *tree,
						    struct smb2_handle file,
						    unsigned max_renames,
						    const char *base_name,
						    unsigned *rename_counter)
{
	struct tevent_req *req;
	struct rename_one_dir_cycle_state *state;
	struct smb2_request *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct rename_one_dir_cycle_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->tree = tree;
	state->file = file;
	state->base_name = base_name;
	state->rename_counter = rename_counter;
	state->current = 0;
	state->max = max_renames;

	ZERO_STRUCT(state->sinfo);
	state->sinfo.rename_information.level =
		RAW_SFILEINFO_RENAME_INFORMATION;
	state->sinfo.rename_information.in.file.handle = state->file;
	state->sinfo.rename_information.in.overwrite = 0;
	state->sinfo.rename_information.in.root_fid = 0;

	state->new_name = talloc_asprintf(
		state, "%s-%u", state->base_name, state->current);
	if (tevent_req_nomem(state->new_name, req)) {
		return tevent_req_post(req, ev);
	}
	state->sinfo.rename_information.in.new_name = state->new_name;

	subreq = smb2_setinfo_file_send(state->tree, &state->sinfo);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	subreq->async.fn = rename_one_dir_cycle_done;
	subreq->async.private_data = req;
	return req;
}

static void rename_one_dir_cycle_done(struct smb2_request *subreq)
{
	struct tevent_req *req = talloc_get_type_abort(
		subreq->async.private_data, struct tevent_req);
	struct rename_one_dir_cycle_state *state = tevent_req_data(
		req, struct rename_one_dir_cycle_state);
	NTSTATUS status;

	status = smb2_setinfo_recv(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	TALLOC_FREE(state->new_name);

	*state->rename_counter += 1;

	state->current += 1;
	if (state->current >= state->max) {
		tevent_req_done(req);
		return;
	}

	ZERO_STRUCT(state->sinfo);
	state->sinfo.rename_information.level =
		RAW_SFILEINFO_RENAME_INFORMATION;
	state->sinfo.rename_information.in.file.handle = state->file;
	state->sinfo.rename_information.in.overwrite = 0;
	state->sinfo.rename_information.in.root_fid = 0;

	state->new_name = talloc_asprintf(
		state, "%s-%u", state->base_name, state->current);
	if (tevent_req_nomem(state->new_name, req)) {
		return;
	}
	state->sinfo.rename_information.in.new_name = state->new_name;

	subreq = smb2_setinfo_file_send(state->tree, &state->sinfo);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	subreq->async.fn = rename_one_dir_cycle_done;
	subreq->async.private_data = req;
}

static NTSTATUS rename_one_dir_cycle_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct rename_dir_bench_state {
	struct tevent_context *ev;
	struct smb2_tree *tree;
	const char *base_name;
	unsigned max_renames;
	unsigned *rename_counter;

	struct smb2_create io;
	union smb_setfileinfo sinfo;
	struct smb2_close cl;

	struct smb2_handle file;
};

static void rename_dir_bench_opened(struct smb2_request *subreq);
static void rename_dir_bench_renamed(struct tevent_req *subreq);
static void rename_dir_bench_set_doc(struct smb2_request *subreq);
static void rename_dir_bench_closed(struct smb2_request *subreq);

static struct tevent_req *rename_dir_bench_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct smb2_tree *tree,
						const char *base_name,
						unsigned max_renames,
						unsigned *rename_counter)
{
	struct tevent_req *req;
	struct rename_dir_bench_state *state;
	struct smb2_request *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct rename_dir_bench_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->tree = tree;
	state->base_name = base_name;
	state->max_renames = max_renames;
	state->rename_counter = rename_counter;

	ZERO_STRUCT(state->io);
	state->io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	state->io.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	state->io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	state->io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	state->io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	state->io.in.fname = state->base_name;

	subreq = smb2_create_send(state->tree, &state->io);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	subreq->async.fn = rename_dir_bench_opened;
	subreq->async.private_data = req;
	return req;
}

static void rename_dir_bench_opened(struct smb2_request *subreq)
{
	struct tevent_req *req = talloc_get_type_abort(
		subreq->async.private_data, struct tevent_req);
	struct rename_dir_bench_state *state = tevent_req_data(
		req, struct rename_dir_bench_state);
	struct smb2_create *io;
	struct tevent_req *subreq2;
	NTSTATUS status;

	io = talloc(state, struct smb2_create);
	if (tevent_req_nomem(io, req)) {
		return;
	}

	status = smb2_create_recv(subreq, io, io);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	state->file = io->out.file.handle;
	TALLOC_FREE(io);

	subreq2 = rename_one_dir_cycle_send(
		state, state->ev, state->tree, state->file,
		state->max_renames, state->base_name,
		state->rename_counter);
	if (tevent_req_nomem(subreq2, req)) {
		return;
	}
	tevent_req_set_callback(subreq2, rename_dir_bench_renamed, req);
}

static void rename_dir_bench_renamed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rename_dir_bench_state *state = tevent_req_data(
		req, struct rename_dir_bench_state);
	struct smb2_request *subreq2;
	NTSTATUS status;

	status = rename_one_dir_cycle_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	ZERO_STRUCT(state->sinfo);
	state->sinfo.disposition_info.level =
		RAW_SFILEINFO_DISPOSITION_INFORMATION;
	state->sinfo.disposition_info.in.file.handle = state->file;
	state->sinfo.disposition_info.in.delete_on_close = true;

	subreq2 = smb2_setinfo_file_send(state->tree, &state->sinfo);
	if (tevent_req_nomem(subreq2, req)) {
		return;
	}
	subreq2->async.fn = rename_dir_bench_set_doc;
	subreq2->async.private_data = req;
}

static void rename_dir_bench_set_doc(struct smb2_request *subreq)
{
	struct tevent_req *req = talloc_get_type_abort(
		subreq->async.private_data, struct tevent_req);
	struct rename_dir_bench_state *state = tevent_req_data(
		req, struct rename_dir_bench_state);
	NTSTATUS status;

	status = smb2_setinfo_recv(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	ZERO_STRUCT(state->cl);
	state->cl.in.file.handle = state->file;

	subreq = smb2_close_send(state->tree, &state->cl);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	subreq->async.fn = rename_dir_bench_closed;
	subreq->async.private_data = req;
}

static void rename_dir_bench_closed(struct smb2_request *subreq)
{
	struct tevent_req *req = talloc_get_type_abort(
		subreq->async.private_data, struct tevent_req);
	struct smb2_close cl;
	NTSTATUS status;

	status = smb2_close_recv(subreq, &cl);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS rename_dir_bench_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct rename_dirs_bench_state {
	unsigned num_reqs;
	unsigned num_done;
};

static void rename_dirs_bench_done(struct tevent_req *subreq);

static struct tevent_req *rename_dirs_bench_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct smb2_tree *tree,
						 const char *base_name,
						 unsigned num_parallel,
						 unsigned max_renames,
						 unsigned *rename_counter)
{
	struct tevent_req *req;
	struct rename_dirs_bench_state *state;
	unsigned i;

	req = tevent_req_create(mem_ctx, &state,
				struct rename_dirs_bench_state);
	if (req == NULL) {
		return NULL;
	}
	state->num_reqs = num_parallel;
	state->num_done = 0;

	for (i=0; i<num_parallel; i++) {
		struct tevent_req *subreq;
		char *sub_base;

		sub_base = talloc_asprintf(state, "%s-%u", base_name, i);
		if (tevent_req_nomem(sub_base, req)) {
			return tevent_req_post(req, ev);
		}

		subreq = rename_dir_bench_send(state, ev, tree, sub_base,
					       max_renames, rename_counter);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, rename_dirs_bench_done, req);
	}
	return req;
}

static void rename_dirs_bench_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rename_dirs_bench_state *state = tevent_req_data(
		req, struct rename_dirs_bench_state);
	NTSTATUS status;

	status = rename_dir_bench_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->num_done += 1;
	if (state->num_done >= state->num_reqs) {
		tevent_req_done(req);
	}
}

static NTSTATUS rename_dirs_bench_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static bool torture_smb2_rename_dir_bench(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	struct tevent_req *req;
	NTSTATUS status;
	unsigned counter = 0;
	bool ret;

	req = rename_dirs_bench_send(tctx, tctx->ev, tree, "dir", 3, 10,
				     &counter);
	torture_assert(tctx, req != NULL, "rename_dirs_bench_send failed");

	ret = tevent_req_poll(req, tctx->ev);
	torture_assert(tctx, ret, "tevent_req_poll failed");

	status = rename_dirs_bench_recv(req);
	torture_comment(tctx, "rename_dirs_bench returned %s\n",
			nt_errstr(status));
	TALLOC_FREE(req);
	torture_assert_ntstatus_ok(tctx, status, "bench failed");
	return true;
}


/*
   basic testing of SMB2 rename
 */
struct torture_suite *torture_smb2_rename_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
		torture_suite_create(ctx, "rename");

	torture_suite_add_1smb2_test(suite, "simple",
		torture_smb2_rename_simple);

	torture_suite_add_1smb2_test(suite, "simple_nodelete",
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

	torture_suite_add_1smb2_test(
		suite, "rename_dir_openfile",
		torture_smb2_rename_dir_openfile);

	torture_suite_add_1smb2_test(suite,
		"rename_dir_bench",
		torture_smb2_rename_dir_bench);

	suite->description = talloc_strdup(suite, "smb2.rename tests");

	return suite;
}
