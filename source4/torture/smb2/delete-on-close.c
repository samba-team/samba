/*
   Unix SMB/CIFS implementation.

   test delete-on-close in more detail

   Copyright (C) Richard Sharpe, 2013

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
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"

#define DNAME "test_dir"
#define FNAME DNAME "\\test_create.dat"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) Incorrect status %s - should be %s\n", \
			 __location__, nt_errstr(status), nt_errstr(correct)); \
		return false; \
	}} while (0)

static bool create_dir(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_handle handle;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig;
	const char *owner_sid;
	uint32_t perms = 0;

	torture_comment(tctx, "Creating Directory for testing: %s\n", DNAME);

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access =
		SEC_STD_READ_CONTROL |
		SEC_STD_WRITE_DAC |
		SEC_STD_WRITE_OWNER;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = DNAME;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	/*
	 * We create an SD that allows us to do most things but we do not
	 * get DELETE and DELETE CHILD access!
	 */

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_OWNER |
		SEC_STD_WRITE_DAC | SEC_STD_READ_CONTROL | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_TRAVERSE | SEC_DIR_WRITE_EA | 
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA | SEC_FILE_READ_DATA;

	torture_comment(tctx, "Setting permissions on dir to 0x1e01bf\n");
	sd = security_descriptor_dacl_create(tctx,
					0, owner_sid, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					perms,
					SEC_ACE_FLAG_OBJECT_INHERIT,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	set.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, handle);

	return true;
}

static bool set_dir_delete_perms(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_handle handle;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig;
	const char *owner_sid;
	uint32_t perms = 0;

	torture_comment(tctx, "Opening Directory for setting new SD: %s\n", DNAME);

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access =
		SEC_STD_READ_CONTROL |
		SEC_STD_WRITE_DAC |
		SEC_STD_WRITE_OWNER;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = DNAME;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	/*
	 * We create an SD that allows us to do most things including
	 * get DELETE and DELETE CHILD access!
	 */

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_OWNER |
		SEC_STD_WRITE_DAC | SEC_STD_READ_CONTROL | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_TRAVERSE | SEC_DIR_WRITE_EA | 
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA |
		SEC_DIR_DELETE_CHILD | SEC_STD_DELETE |
		SEC_FILE_WRITE_DATA | SEC_FILE_READ_DATA;

	torture_comment(tctx, "Setting permissions on dir to 0x%0x\n", perms);
	sd = security_descriptor_dacl_create(tctx,
					0, owner_sid, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					perms,
					0,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	set.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, handle);

	return true;
}

static bool test_doc_overwrite_if(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on non-existent file (OVERWRITE_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	return true;
}

static bool test_doc_overwrite_if_exist(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	/* And set the SEC Descriptor appropriately */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on existing file (OVERWRITE_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_ACCESS_DENIED\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	/* First, create this file ... */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0x0;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Next, try to open it for Delete On Close */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	status = smb2_util_close(tree, io.out.file.handle);

	return true;
}

static bool test_doc_create(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on non-existent file (CREATE) \n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	return true;
}

static bool test_doc_create_exist(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on non-existent file (CREATE) \n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_COLLISION\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	/* First, create the file */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0x0;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Next, try to open it for Delete on Close */
	status = smb2_util_close(tree, io.out.file.handle);
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_COLLISION);

	status = smb2_util_close(tree, io.out.file.handle);

	return true;
}

static bool test_doc_create_if(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on non-existent file (OPEN_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	return true;
}

static bool test_doc_create_if_exist(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on existing file (OPEN_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_ACCESS_DENIED\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	/* Create the file first */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0x0;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Now try to create it for delete on close */
	ZERO_STRUCT(io);
	io.in.desired_access	 = 0x130196;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	status = smb2_util_close(tree, io.out.file.handle);

	return true;
}

static bool test_doc_find_and_set_doc(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	struct smb2_find find;
	NTSTATUS status;
	union smb_search_data *d;
	union smb_setfileinfo sfinfo;
	unsigned int count;
	uint32_t perms = 0;

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE |
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE |
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA | SEC_DIR_LIST;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "FIND and delete directory\n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	/* open the directory first */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_READ |
				   NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.fname              = DNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* list directory */
	ZERO_STRUCT(find);
	find.in.file.handle        = io.out.file.handle;
	find.in.pattern            = "*";
	find.in.continue_flags     = SMB2_CONTINUE_FLAG_SINGLE;
	find.in.max_response_size  = 0x100;
	find.in.level              = SMB2_FIND_BOTH_DIRECTORY_INFO;

	/* start enumeration on directory */
	status = smb2_find_level(tree, tree, &find, &count, &d);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* set delete-on-close */
	ZERO_STRUCT(sfinfo);
	sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.disposition_info.in.delete_on_close = 1;
	sfinfo.generic.in.file.handle = io.out.file.handle;
	status = smb2_setinfo_file(tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* close directory */
	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);
	return true;
}

static bool test_doc_read_only(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	struct smb2_handle dir_handle;
	union smb_setfileinfo sfinfo = {{0}};
	struct smb2_create create = {0};
	struct smb2_close close = {0};
	NTSTATUS status, expected_status;
	bool ret = true, delete_readonly;

	/*
	 * Allow testing of the Samba 'delete readonly' option.
	 */
	delete_readonly = torture_setting_bool(tctx, "delete_readonly", false);
	expected_status = delete_readonly ?
		NT_STATUS_OK : NT_STATUS_CANNOT_DELETE;

	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &dir_handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CREATE directory failed\n");

	create = (struct smb2_create) {0};
	create.in.desired_access = SEC_RIGHTS_DIR_ALL;
	create.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
		NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	create.in.file_attributes = FILE_ATTRIBUTE_READONLY;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE |
		NTCREATEX_SHARE_ACCESS_DELETE;
	create.in.create_disposition = NTCREATEX_DISP_CREATE;
	create.in.fname = FNAME;
	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status, expected_status, ret,
					   done, "Unexpected status for CREATE "
					   "of new file.\n");

	if (delete_readonly) {
		close.in.file.handle = create.out.file.handle;
		status = smb2_close(tree, &close);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"CLOSE of READONLY file "
						"failed.\n");
	}

	torture_comment(tctx, "Creating file with READ_ONLY attribute.\n");

	create = (struct smb2_create) {0};
	create.in.desired_access = SEC_RIGHTS_DIR_ALL;
	create.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	create.in.file_attributes = FILE_ATTRIBUTE_READONLY;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE |
		NTCREATEX_SHARE_ACCESS_DELETE;
	create.in.create_disposition = NTCREATEX_DISP_CREATE;
	create.in.fname = FNAME;
	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CREATE of READONLY file failed.\n");

	close.in.file.handle = create.out.file.handle;
	status = smb2_close(tree, &close);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CLOSE of READONLY file failed.\n");

	torture_comment(tctx, "Testing CREATE with DELETE_ON_CLOSE on "
			"READ_ONLY attribute file.\n");

	create = (struct smb2_create) {0};
	create.in.desired_access = SEC_RIGHTS_FILE_READ | SEC_STD_DELETE;
	create.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	create.in.file_attributes = 0;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE |
		NTCREATEX_SHARE_ACCESS_DELETE;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.fname = FNAME;
	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   expected_status, ret, done,
					   "CREATE returned unexpected "
					   "status.\n");

	torture_comment(tctx, "Testing setting DELETE_ON_CLOSE disposition on "
			" file with READONLY attribute.\n");

	create = (struct smb2_create) {0};
	create.in.desired_access = SEC_RIGHTS_FILE_READ | SEC_STD_DELETE;;
	create.in.create_options = 0;
	create.in.file_attributes = 0;
	create.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE |
		NTCREATEX_SHARE_ACCESS_DELETE;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.fname = FNAME;
	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Opening file failed.\n");

	sfinfo.disposition_info.in.delete_on_close = 1;
	sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.generic.in.file.handle = create.out.file.handle;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_equal(tctx, status, expected_status,
				      "Set DELETE_ON_CLOSE disposition "
				      "returned un expected status.\n");

	status = smb2_util_close(tree, create.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CLOSE failed\n");

done:
	smb2_deltree(tree, DNAME);
	return ret;
}

/*
 * This is a regression test for
 * https://bugzilla.samba.org/show_bug.cgi?id=14427
 *
 * It's not really a delete-on-close specific test.
 */
static bool test_doc_bug14427(struct torture_context *tctx, struct smb2_tree *tree1)
{
	struct smb2_tree *tree2 = NULL;
	NTSTATUS status;
	char fname[256];
	bool ret = false;
	bool ok;

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "doc_bug14427_%s.dat",
		 generate_random_str(tctx, 8));

	ok = torture_smb2_tree_connect(tctx, tree1->session, tctx, &tree2);
	torture_assert_goto(tctx, ok, ret, done,
		"torture_smb2_tree_connect() failed.\n");

	status = torture_setup_simple_file(tctx, tree1, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"torture_setup_simple_file() failed on tree1.\n");

	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		"smb2_util_unlink() failed on tree2.\n");
	TALLOC_FREE(tree2);
	ret = true;
done:
	if (tree2 != NULL) {
		TALLOC_FREE(tree2);
		smb2_util_unlink(tree1, fname);
	}

	TALLOC_FREE(tree1);
	return ret;
}

/*
 *  Extreme testing of Delete On Close and permissions
 */
struct torture_suite *torture_smb2_doc_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "delete-on-close-perms");

	torture_suite_add_1smb2_test(suite, "OVERWRITE_IF", test_doc_overwrite_if);
	torture_suite_add_1smb2_test(suite, "OVERWRITE_IF Existing", test_doc_overwrite_if_exist);
	torture_suite_add_1smb2_test(suite, "CREATE", test_doc_create);
	torture_suite_add_1smb2_test(suite, "CREATE Existing", test_doc_create_exist);
	torture_suite_add_1smb2_test(suite, "CREATE_IF", test_doc_create_if);
	torture_suite_add_1smb2_test(suite, "CREATE_IF Existing", test_doc_create_if_exist);
	torture_suite_add_1smb2_test(suite, "FIND_and_set_DOC", test_doc_find_and_set_doc);
	torture_suite_add_1smb2_test(suite, "READONLY", test_doc_read_only);
	torture_suite_add_1smb2_test(suite, "BUG14427", test_doc_bug14427);

	suite->description = talloc_strdup(suite, "SMB2-Delete-on-Close-Perms tests");

	return suite;
}
