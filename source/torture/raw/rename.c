/* 
   Unix SMB/CIFS implementation.
   rename test suite
   Copyright (C) Andrew Tridgell 2003
   
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
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "torture/util.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect %s %d - should be %d\n", \
		       __location__, #v, (int)v, (int)correct); \
		ret = False; \
	}} while (0)

#define BASEDIR "\\testrename"

/*
  test SMBmv ops
*/
static BOOL test_mv(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_rename io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum = -1;
	const char *fname1 = BASEDIR "\\test1.txt";
	const char *fname2 = BASEDIR "\\test2.txt";
	union smb_open op;

	printf("Testing SMBmv\n");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	printf("Trying simple rename\n");

	op.generic.level = RAW_OPEN_NTCREATEX;
	op.ntcreatex.in.root_fid = 0;
	op.ntcreatex.in.flags = 0;
	op.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	op.ntcreatex.in.create_options = 0;
	op.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	op.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ | 
		NTCREATEX_SHARE_ACCESS_WRITE;
	op.ntcreatex.in.alloc_size = 0;
	op.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	op.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	op.ntcreatex.in.security_flags = 0;
	op.ntcreatex.in.fname = fname1;

	status = smb_raw_open(cli->tree, mem_ctx, &op);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = op.ntcreatex.out.file.fnum;

	io.generic.level = RAW_RENAME_RENAME;
	io.rename.in.pattern1 = fname1;
	io.rename.in.pattern2 = fname2;
	io.rename.in.attrib = 0;
	
	printf("trying rename while first file open\n");
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	smbcli_close(cli->tree, fnum);

	op.ntcreatex.in.access_mask = SEC_FILE_READ_DATA;
	op.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE | 
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb_raw_open(cli->tree, mem_ctx, &op);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = op.ntcreatex.out.file.fnum;

	printf("trying rename while first file open with SHARE_ACCESS_DELETE\n");
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.rename.in.pattern1 = fname2;
	io.rename.in.pattern2 = fname1;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.rename.in.pattern1 = fname1;
	io.rename.in.pattern2 = fname2;

	printf("trying rename while not open\n");
	smb_raw_exit(cli->session);
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	printf("Trying self rename\n");
	io.rename.in.pattern1 = fname2;
	io.rename.in.pattern2 = fname2;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.rename.in.pattern1 = fname1;
	io.rename.in.pattern2 = fname1;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);


	printf("trying wildcard rename\n");
	io.rename.in.pattern1 = BASEDIR "\\*.txt";
	io.rename.in.pattern2 = fname1;
	
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("and again\n");
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying extension change\n");
	io.rename.in.pattern1 = BASEDIR "\\*.txt";
	io.rename.in.pattern2 = BASEDIR "\\*.bak";
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);

	printf("Checking attrib handling\n");
	torture_set_file_attribute(cli->tree, BASEDIR "\\test1.bak", FILE_ATTRIBUTE_HIDDEN);
	io.rename.in.pattern1 = BASEDIR "\\test1.bak";
	io.rename.in.pattern2 = BASEDIR "\\*.txt";
	io.rename.in.attrib = 0;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);

	io.rename.in.attrib = FILE_ATTRIBUTE_HIDDEN;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}



/*
  test SMBntrename ops
*/
static BOOL test_ntrename(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_rename io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum, i;
	const char *fname1 = BASEDIR "\\test1.txt";
	const char *fname2 = BASEDIR "\\test2.txt";
	union smb_fileinfo finfo;

	printf("Testing SMBntrename\n");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	printf("Trying simple rename\n");

	fnum = create_complex_file(cli, mem_ctx, fname1);
	
	io.generic.level = RAW_RENAME_NTRENAME;
	io.ntrename.in.old_name = fname1;
	io.ntrename.in.new_name = fname2;
	io.ntrename.in.attrib = 0;
	io.ntrename.in.cluster_size = 0;
	io.ntrename.in.flags = RENAME_FLAG_RENAME;
	
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);
	
	smb_raw_exit(cli->session);
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying self rename\n");
	io.ntrename.in.old_name = fname2;
	io.ntrename.in.new_name = fname2;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.ntrename.in.old_name = fname1;
	io.ntrename.in.new_name = fname1;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	printf("trying wildcard rename\n");
	io.ntrename.in.old_name = BASEDIR "\\*.txt";
	io.ntrename.in.new_name = fname1;
	
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);

	printf("Checking attrib handling\n");
	torture_set_file_attribute(cli->tree, fname2, FILE_ATTRIBUTE_HIDDEN);
	io.ntrename.in.old_name = fname2;
	io.ntrename.in.new_name = fname1;
	io.ntrename.in.attrib = 0;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);

	io.ntrename.in.attrib = FILE_ATTRIBUTE_HIDDEN;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_set_file_attribute(cli->tree, fname1, FILE_ATTRIBUTE_NORMAL);

	printf("Checking hard link\n");
	io.ntrename.in.old_name = fname1;
	io.ntrename.in.new_name = fname2;
	io.ntrename.in.attrib = 0;
	io.ntrename.in.flags = RENAME_FLAG_HARD_LINK;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_set_file_attribute(cli->tree, fname1, FILE_ATTRIBUTE_SYSTEM);

	finfo.generic.level = RAW_FILEINFO_ALL_INFO;
	finfo.generic.in.file.path = fname2;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(finfo.all_info.out.nlink, 2);
	CHECK_VALUE(finfo.all_info.out.attrib, FILE_ATTRIBUTE_SYSTEM);

	finfo.generic.in.file.path = fname1;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(finfo.all_info.out.nlink, 2);
	CHECK_VALUE(finfo.all_info.out.attrib, FILE_ATTRIBUTE_SYSTEM);

	torture_set_file_attribute(cli->tree, fname1, FILE_ATTRIBUTE_NORMAL);

	smbcli_unlink(cli->tree, fname2);

	finfo.generic.in.file.path = fname1;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(finfo.all_info.out.nlink, 1);
	CHECK_VALUE(finfo.all_info.out.attrib, FILE_ATTRIBUTE_NORMAL);

	printf("Checking copy\n");
	io.ntrename.in.old_name = fname1;
	io.ntrename.in.new_name = fname2;
	io.ntrename.in.attrib = 0;
	io.ntrename.in.flags = RENAME_FLAG_COPY;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	finfo.generic.level = RAW_FILEINFO_ALL_INFO;
	finfo.generic.in.file.path = fname1;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(finfo.all_info.out.nlink, 1);
	CHECK_VALUE(finfo.all_info.out.attrib, FILE_ATTRIBUTE_NORMAL);

	finfo.generic.level = RAW_FILEINFO_ALL_INFO;
	finfo.generic.in.file.path = fname2;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(finfo.all_info.out.nlink, 1);
	CHECK_VALUE(finfo.all_info.out.attrib, FILE_ATTRIBUTE_NORMAL);

	torture_set_file_attribute(cli->tree, fname1, FILE_ATTRIBUTE_SYSTEM);

	finfo.generic.level = RAW_FILEINFO_ALL_INFO;
	finfo.generic.in.file.path = fname2;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(finfo.all_info.out.nlink, 1);
	CHECK_VALUE(finfo.all_info.out.attrib, FILE_ATTRIBUTE_NORMAL);

	finfo.generic.in.file.path = fname1;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(finfo.all_info.out.nlink, 1);
	CHECK_VALUE(finfo.all_info.out.attrib, FILE_ATTRIBUTE_SYSTEM);

	torture_set_file_attribute(cli->tree, fname1, FILE_ATTRIBUTE_NORMAL);

	smbcli_unlink(cli->tree, fname2);

	finfo.generic.in.file.path = fname1;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(finfo.all_info.out.nlink, 1);

	printf("Checking invalid flags\n");
	io.ntrename.in.old_name = fname1;
	io.ntrename.in.new_name = fname2;
	io.ntrename.in.attrib = 0;
	io.ntrename.in.flags = 0;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	io.ntrename.in.flags = 300;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	io.ntrename.in.flags = 0x106;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	printf("Checking unknown field\n");
	io.ntrename.in.old_name = fname1;
	io.ntrename.in.new_name = fname2;
	io.ntrename.in.attrib = 0;
	io.ntrename.in.flags = RENAME_FLAG_RENAME;
	io.ntrename.in.cluster_size = 0xff;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying RENAME_FLAG_MOVE_CLUSTER_INFORMATION\n");

	io.ntrename.in.old_name = fname2;
	io.ntrename.in.new_name = fname1;
	io.ntrename.in.attrib = 0;
	io.ntrename.in.flags = RENAME_FLAG_MOVE_CLUSTER_INFORMATION;
	io.ntrename.in.cluster_size = 1;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	io.ntrename.in.flags = RENAME_FLAG_COPY;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

#if 0
	{
		char buf[16384];
		fnum = smbcli_open(cli->tree, fname1, O_RDWR, DENY_NONE);
		memset(buf, 1, sizeof(buf));
		smbcli_write(cli->tree, fnum, 0, buf, 0, sizeof(buf));
		smbcli_close(cli->tree, fnum);

		fnum = smbcli_open(cli->tree, fname2, O_RDWR, DENY_NONE);
		memset(buf, 1, sizeof(buf));
		smbcli_write(cli->tree, fnum, 0, buf, 0, sizeof(buf)-1);
		smbcli_close(cli->tree, fnum);

		torture_all_info(cli->tree, fname1);
		torture_all_info(cli->tree, fname2);
	}
	

	io.ntrename.in.flags = RENAME_FLAG_MOVE_CLUSTER_INFORMATION;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	for (i=0;i<20000;i++) {
		io.ntrename.in.cluster_size = i;
		status = smb_raw_rename(cli->tree, &io);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
			printf("i=%d status=%s\n", i, nt_errstr(status));
		}
	}
#endif

	printf("Checking other flags\n");

	for (i=0;i<0xFFF;i++) {
		if (i == RENAME_FLAG_RENAME ||
		    i == RENAME_FLAG_HARD_LINK ||
		    i == RENAME_FLAG_COPY) {
			continue;
		}

		io.ntrename.in.old_name = fname2;
		io.ntrename.in.new_name = fname1;
		io.ntrename.in.flags = i;
		io.ntrename.in.attrib = 0;
		io.ntrename.in.cluster_size = 0;
		status = smb_raw_rename(cli->tree, &io);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			printf("flags=0x%x status=%s\n", i, nt_errstr(status));
		}
	}
	
done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/* 
   basic testing of rename calls
*/
BOOL torture_raw_rename(struct torture_context *torture)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_rename");

	if (!test_mv(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_ntrename(cli, mem_ctx)) {
		ret = False;
	}

	torture_close_connection(cli);
	talloc_free(mem_ctx);
	return ret;
}
