/*
   Unix SMB/CIFS implementation.

   vfs_fruit tests

   Copyright (C) Ralph Boehme 2014

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
#include "system/filesys.h"
#include "libcli/libcli.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "lib/cmdline/popt_common.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"
#include "MacExtensions.h"

#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "torture/vfs/proto.h"

#define BASEDIR "vfs_fruit_dir"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
		    "(%s) Incorrect status %s - should be %s\n", \
		    __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

/*
 * REVIEW:
 * This is hokey, but what else can we do?
 */
#if defined(HAVE_ATTROPEN) || defined(FREEBSD)
#define AFPINFO_EA_NETATALK "org.netatalk.Metadata"
#define AFPRESOURCE_EA_NETATALK "org.netatalk.ResourceFork"
#else
#define AFPINFO_EA_NETATALK "user.org.netatalk.Metadata"
#define AFPRESOURCE_EA_NETATALK "user.org.netatalk.ResourceFork"
#endif

/*
The metadata xattr char buf below contains the following attributes:

-------------------------------------------------------------------------------
Entry ID   : 00000008 : File Dates Info
Offset     : 00000162 : 354
Length     : 00000010 : 16

-DATE------:          : (GMT)                    : (Local)
create     : 1B442169 : Mon Jun 30 13:23:53 2014 : Mon Jun 30 15:23:53 2014
modify     : 1B442169 : Mon Jun 30 13:23:53 2014 : Mon Jun 30 15:23:53 2014
backup     : 80000000 : Unknown or Initial
access     : 1B442169 : Mon Jun 30 13:23:53 2014 : Mon Jun 30 15:23:53 2014

-RAW DUMP--:  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F : (ASCII)
00000000   : 1B 44 21 69 1B 44 21 69 80 00 00 00 1B 44 21 69 : .D!i.D!i.....D!i

-------------------------------------------------------------------------------
Entry ID   : 00000009 : Finder Info
Offset     : 0000007A : 122
Length     : 00000020 : 32

-FInfo-----:
Type       : 42415252 : BARR
Creator    : 464F4F4F : FOOO
isAlias    : 0
Invisible  : 1
hasBundle  : 0
nameLocked : 0
Stationery : 0
CustomIcon : 0
Reserved   : 0
Inited     : 0
NoINITS    : 0
Shared     : 0
SwitchLaunc: 0
Hidden Ext : 0
color      : 000      : none
isOnDesk   : 0
Location v : 0000     : 0
Location h : 0000     : 0
Fldr       : 0000     : ..

-FXInfo----:
Rsvd|IconID: 0000     : 0
Rsvd       : 0000     : ..
Rsvd       : 0000     : ..
Rsvd       : 0000     : ..
AreInvalid : 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
CustomBadge: 0
ObjctIsBusy: 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
unknown bit: 0
RoutingInfo: 0
unknown bit: 0
unknown bit: 0
Rsvd|commnt: 0000     : 0
PutAway    : 00000000 : 0

-RAW DUMP--:  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F : (ASCII)
00000000   : 42 41 52 52 46 4F 4F 4F 40 00 00 00 00 00 00 00 : BARRFOOO@.......
00000010   : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 : ................

-------------------------------------------------------------------------------
Entry ID   : 0000000E : AFP File Info
Offset     : 00000172 : 370
Length     : 00000004 : 4

-RAW DUMP--:  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F : (ASCII)
00000000   : 00 00 01 A1                                     : ....
 */

char metadata_xattr[] = {
	0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
	0x00, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x00, 0x01, 0x62, 0x00, 0x00,
	0x00, 0x10, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
	0x00, 0x7a, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
	0x00, 0x0e, 0x00, 0x00, 0x01, 0x72, 0x00, 0x00,
	0x00, 0x04, 0x80, 0x44, 0x45, 0x56, 0x00, 0x00,
	0x01, 0x76, 0x00, 0x00, 0x00, 0x08, 0x80, 0x49,
	0x4e, 0x4f, 0x00, 0x00, 0x01, 0x7e, 0x00, 0x00,
	0x00, 0x08, 0x80, 0x53, 0x59, 0x4e, 0x00, 0x00,
	0x01, 0x86, 0x00, 0x00, 0x00, 0x08, 0x80, 0x53,
	0x56, 0x7e, 0x00, 0x00, 0x01, 0x8e, 0x00, 0x00,
	0x00, 0x04, 0x42, 0x41, 0x52, 0x52, 0x46, 0x4f,
	0x4f, 0x4f, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1b, 0x44, 0x21, 0x69, 0x1b, 0x44,
	0x21, 0x69, 0x80, 0x00, 0x00, 0x00, 0x1b, 0x44,
	0x21, 0x69, 0x00, 0x00, 0x01, 0xa1, 0x00, 0xfd,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc1, 0x20,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0xe3,
	0x86, 0x53, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x01,
	0x00, 0x00
};

/**
 * talloc and intialize an AfpInfo
 **/
static AfpInfo *torture_afpinfo_new(TALLOC_CTX *mem_ctx)
{
	AfpInfo *info;

	info = talloc_zero(mem_ctx, AfpInfo);
	if (info == NULL) {
		return NULL;
	}

	info->afpi_Signature = AFP_Signature;
	info->afpi_Version = AFP_Version;
	info->afpi_BackupTime = AFP_BackupTime;

	return info;
}

/**
 * Pack AfpInfo into a talloced buffer
 **/
static char *torture_afpinfo_pack(TALLOC_CTX *mem_ctx,
				  AfpInfo *info)
{
	char *buf;

	buf = talloc_array(mem_ctx, char, AFP_INFO_SIZE);
	if (buf == NULL) {
		return NULL;
	}

	RSIVAL(buf, 0, info->afpi_Signature);
	RSIVAL(buf, 4, info->afpi_Version);
	RSIVAL(buf, 12, info->afpi_BackupTime);
	memcpy(buf + 16, info->afpi_FinderInfo, sizeof(info->afpi_FinderInfo));

	return buf;
}

/**
 * Unpack AfpInfo
 **/
#if 0
static void torture_afpinfo_unpack(AfpInfo *info, char *data)
{
	info->afpi_Signature = RIVAL(data, 0);
	info->afpi_Version = RIVAL(data, 4);
	info->afpi_BackupTime = RIVAL(data, 12);
	memcpy(info->afpi_FinderInfo, (const char *)data + 16,
	       sizeof(info->afpi_FinderInfo));
}
#endif

static bool torture_write_afpinfo(struct smb2_tree *tree,
				  struct torture_context *tctx,
				  TALLOC_CTX *mem_ctx,
				  const char *fname,
				  AfpInfo *info)
{
	struct smb2_handle handle;
	struct smb2_create io;
	NTSTATUS status;
	const char *full_name;
	char *infobuf;
	bool ret = true;

	full_name = talloc_asprintf(mem_ctx, "%s%s", fname, AFPINFO_STREAM);
	if (full_name == NULL) {
	    torture_comment(tctx, "talloc_asprintf error\n");
	    return false;
	}
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.create_options = 0;
	io.in.fname = full_name;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	handle = io.out.file.handle;

	infobuf = torture_afpinfo_pack(mem_ctx, info);
	if (infobuf == NULL) {
		return false;
	}

	status = smb2_util_write(tree, handle, infobuf, 0, AFP_INFO_SIZE);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, handle);

done:
	return ret;
}

/**
 * Read 'count' bytes at 'offset' from stream 'fname:sname' and
 * compare against buffer 'value'
 **/
static bool check_stream(struct smb2_tree *tree,
			 const char *location,
			 struct torture_context *tctx,
			 TALLOC_CTX *mem_ctx,
			 const char *fname,
			 const char *sname,
			 off_t read_offset,
			 size_t read_count,
			 off_t comp_offset,
			 size_t comp_count,
			 const char *value)
{
	struct smb2_handle handle;
	struct smb2_create create;
	struct smb2_read r;
	NTSTATUS status;
	const char *full_name;

	full_name = talloc_asprintf(mem_ctx, "%s%s", fname, sname);
	if (full_name == NULL) {
	    torture_comment(tctx, "talloc_asprintf error\n");
	    return false;
	}
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_FILE_READ_DATA;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.create_disposition = NTCREATEX_DISP_OPEN;
	create.in.fname = full_name;

	torture_comment(tctx, "Open stream %s\n", full_name);

	status = smb2_create(tree, mem_ctx, &create);
	if (!NT_STATUS_IS_OK(status)) {
		if (value == NULL) {
			return true;
		} else {
			torture_comment(tctx, "Unable to open stream %s\n",
			    full_name);
			sleep(10000000);
			return false;
		}
	}

	handle = create.out.file.handle;
	if (value == NULL) {
		return true;
	}


	ZERO_STRUCT(r);
	r.in.file.handle = handle;
	r.in.length      = read_count;
	r.in.offset      = read_offset;

	status = smb2_read(tree, tree, &r);

	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "(%s) Failed to read %lu bytes from "
		    "stream '%s'\n", location, (long)strlen(value), full_name);
		return false;
	}

	if (memcmp(r.out.data.data + comp_offset, value, comp_count) != 0) {
		torture_comment(tctx, "(%s) Bad data in stream\n", location);
		return false;
	}

	smb2_util_close(tree, handle);
	return true;
}

/**
 * Read 'count' bytes at 'offset' from stream 'fname:sname' and
 * compare against buffer 'value'
 **/
static bool write_stream(struct smb2_tree *tree,
			 const char *location,
			 struct torture_context *tctx,
			 TALLOC_CTX *mem_ctx,
			 const char *fname,
			 const char *sname,
			 off_t offset,
			 size_t size,
			 const char *value)
{
	struct smb2_handle handle;
	struct smb2_create create;
	NTSTATUS status;
	const char *full_name;

	full_name = talloc_asprintf(mem_ctx, "%s%s", fname, sname);
	if (full_name == NULL) {
	    torture_comment(tctx, "talloc_asprintf error\n");
	    return false;
	}
	ZERO_STRUCT(create);
	create.in.desired_access = SEC_FILE_WRITE_DATA;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.fname = full_name;

	status = smb2_create(tree, mem_ctx, &create);
	if (!NT_STATUS_IS_OK(status)) {
		if (value == NULL) {
			return true;
		} else {
			torture_comment(tctx, "Unable to open stream %s\n",
			    full_name);
			sleep(10000000);
			return false;
		}
	}

	handle = create.out.file.handle;
	if (value == NULL) {
		return true;
	}

	status = smb2_util_write(tree, handle, value, offset, size);

	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "(%s) Failed to write %lu bytes to "
		    "stream '%s'\n", location, (long)size, full_name);
		return false;
	}

	smb2_util_close(tree, handle);
	return true;
}

static bool torture_setup_local_xattr(struct torture_context *tctx,
				      const char *path_option,
				      const char *name,
				      const char *metadata,
				      size_t size)
{
	int ret = true;
	int result;
	const char *spath;
	char *path;

	spath = torture_setting_string(tctx, path_option, NULL);
	if (spath == NULL) {
		printf("No sharepath for option %s\n", path_option);
		return false;
	}

	path = talloc_asprintf(tctx, "%s/%s", spath, name);

	result = setxattr(path, AFPINFO_EA_NETATALK, metadata, size, 0);
	if (result != 0) {
		ret = false;
	}

	TALLOC_FREE(path);

	return ret;
}

/**
 * Create a file or directory
 **/
static bool torture_setup_file(TALLOC_CTX *mem_ctx, struct smb2_tree *tree,
			       const char *name, bool dir)
{
	struct smb2_create io;
	NTSTATUS status;

	smb2_util_unlink(tree, name);
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = name;
	if (dir) {
		io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
		io.in.share_access &= ~NTCREATEX_SHARE_ACCESS_DELETE;
		io.in.file_attributes   = FILE_ATTRIBUTE_DIRECTORY;
		io.in.create_disposition = NTCREATEX_DISP_CREATE;
	}

	status = smb2_create(tree, mem_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	status = smb2_util_close(tree, io.out.file.handle);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return true;
}

static bool test_read_atalk_metadata(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\torture_read_metadata";
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;

	torture_comment(tctx, "Checking metadata access\n");

	smb2_util_unlink(tree1, fname);

	status = torture_smb2_testdir(tree1, BASEDIR, &testdirh);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, testdirh);

	ret = torture_setup_file(mem_ctx, tree1, fname, false);
	if (ret == false) {
		goto done;
	}

	ret = torture_setup_local_xattr(tctx, "localdir",
					BASEDIR "/torture_read_metadata",
					metadata_xattr, sizeof(metadata_xattr));
	if (ret == false) {
		goto done;
	}

	ret &= check_stream(tree1, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			    0, 60, 0, 4, "AFP");

	ret &= check_stream(tree1, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			    0, 60, 16, 8, "BARRFOOO");

done:
	smb2_deltree(tree1, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_write_atalk_metadata(struct torture_context *tctx,
				      struct smb2_tree *tree1,
				      struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\torture_write_metadata";
	const char *type_creator = "SMB,OLE!";
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;
	AfpInfo *info;

	smb2_util_unlink(tree1, fname);

	status = torture_smb2_testdir(tree1, BASEDIR, &testdirh);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, testdirh);

	ret = torture_setup_file(mem_ctx, tree1, fname, false);
	if (ret == false) {
		goto done;
	}

	info = torture_afpinfo_new(mem_ctx);
	if (info == NULL) {
		goto done;
	}

	memcpy(info->afpi_FinderInfo, type_creator, 8);
	ret = torture_write_afpinfo(tree1, tctx, mem_ctx, fname, info);
	ret &= check_stream(tree1, __location__, tctx, mem_ctx, fname, AFPINFO_STREAM,
			    0, 60, 16, 8, type_creator);

done:
	smb2_deltree(tree1, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_write_atalk_rfork_io(struct torture_context *tctx,
				      struct smb2_tree *tree1,
				      struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = BASEDIR "\\torture_write_rfork_io";
	const char *rfork_content = "1234567890";
	NTSTATUS status;
	struct smb2_handle testdirh;
	bool ret = true;

	smb2_util_unlink(tree1, fname);

	status = torture_smb2_testdir(tree1, BASEDIR, &testdirh);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, testdirh);

	ret = torture_setup_file(mem_ctx, tree1, fname, false);
	if (ret == false) {
		goto done;
	}

	torture_comment(tctx, "(%s) writing to resource fork\n",
	    __location__);

	ret &= write_stream(tree1, __location__, tctx, mem_ctx,
			    fname, AFPRESOURCE_STREAM,
			    10, 10, rfork_content);

	ret &= check_stream(tree1, __location__, tctx, mem_ctx,
			    fname, AFPRESOURCE_STREAM,
			    0, 20, 10, 10, rfork_content);

	torture_comment(tctx, "(%s) writing to resource fork at large offset\n",
	    __location__);

	ret &= write_stream(tree1, __location__, tctx, mem_ctx,
			    fname, AFPRESOURCE_STREAM,
			    (off_t)1<<32, 10, rfork_content);

	ret &= check_stream(tree1, __location__, tctx, mem_ctx,
			    fname, AFPRESOURCE_STREAM,
			    (off_t)1<<32, 10, 0, 10, rfork_content);

done:
	smb2_deltree(tree1, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Note: This test depends on "vfs objects = catia fruit
 * streams_xattr".  Note: To run this test, use
 * "--option=torture:share1=<SHARENAME1>
 * --option=torture:share2=<SHARENAME2>
 * --option=torture:localdir=<SHAREPATH>"
 */
struct torture_suite *torture_vfs_fruit(void)
{
	struct torture_suite *suite = torture_suite_create(
		talloc_autofree_context(), "fruit");

	suite->description = talloc_strdup(suite, "vfs_fruit tests");

	torture_suite_add_2ns_smb2_test(suite, "read metadata", test_read_atalk_metadata);
	torture_suite_add_2ns_smb2_test(suite, "write metadata", test_write_atalk_metadata);
	torture_suite_add_2ns_smb2_test(suite, "resource fork IO", test_write_atalk_rfork_io);

	return suite;
}
