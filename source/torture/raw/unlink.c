/* 
   Unix SMB/CIFS implementation.
   unlink test suite
   Copyright (C) Andrew Tridgell 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "system/filesys.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

#define BASEDIR "\\testunlink"

/*
  test unlink ops
*/
static BOOL test_unlink(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	struct smb_unlink io;
	NTSTATUS status;
	BOOL ret = True;
	const char *fname = BASEDIR "\\test.txt";

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	printf("Trying non-existant file\n");
	io.in.pattern = fname;
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	smbcli_close(cli->tree, smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE));

	io.in.pattern = fname;
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying a hidden file\n");
	smbcli_close(cli->tree, smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE));
	torture_set_file_attribute(cli->tree, fname, FILE_ATTRIBUTE_HIDDEN);

	io.in.pattern = fname;
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);

	io.in.pattern = fname;
	io.in.attrib = FILE_ATTRIBUTE_HIDDEN;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.in.pattern = fname;
	io.in.attrib = FILE_ATTRIBUTE_HIDDEN;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	printf("Trying a directory\n");
	io.in.pattern = BASEDIR;
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_IS_A_DIRECTORY);

	io.in.pattern = BASEDIR;
	io.in.attrib = FILE_ATTRIBUTE_DIRECTORY;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_IS_A_DIRECTORY);

	printf("Trying a bad path\n");
	io.in.pattern = "..";
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);

	io.in.pattern = "\\..";
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);

	io.in.pattern = BASEDIR "\\..\\..";
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);

	io.in.pattern = BASEDIR "\\..";
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_IS_A_DIRECTORY);

	printf("Trying wildcards\n");
	smbcli_close(cli->tree, smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE));
	io.in.pattern = BASEDIR "\\t*.t";
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);

	io.in.pattern = BASEDIR "\\z*";
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);

	io.in.pattern = BASEDIR "\\z*";
	io.in.attrib = FILE_ATTRIBUTE_DIRECTORY;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);

	io.in.pattern = BASEDIR "\\*";
	io.in.attrib = FILE_ATTRIBUTE_DIRECTORY;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);

	io.in.pattern = BASEDIR "\\?";
	io.in.attrib = FILE_ATTRIBUTE_DIRECTORY;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);

	io.in.pattern = BASEDIR "\\t*";
	io.in.attrib = FILE_ATTRIBUTE_DIRECTORY;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_close(cli->tree, smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE));

	io.in.pattern = BASEDIR "\\*.dat";
	io.in.attrib = FILE_ATTRIBUTE_DIRECTORY;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);

	io.in.pattern = BASEDIR "\\*.tx?";
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);


done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test delete on close 
*/
static BOOL test_delete_on_close(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	struct smb_unlink io;
	struct smb_rmdir dio;
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	const char *dname = BASEDIR "\\test.dir";
	union smb_setfileinfo sfinfo;

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	dio.in.path = dname;

	io.in.pattern = fname;
	io.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	printf("Testing with delete_on_close 0\n");
	fnum = create_complex_file(cli, mem_ctx, fname);

	sfinfo.disposition_info.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.disposition_info.file.fnum = fnum;
	sfinfo.disposition_info.in.delete_on_close = 0;
	status = smb_raw_setfileinfo(cli->tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_close(cli->tree, fnum);

	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Testing with delete_on_close 1\n");
	fnum = create_complex_file(cli, mem_ctx, fname);
	sfinfo.disposition_info.file.fnum = fnum;
	sfinfo.disposition_info.in.delete_on_close = 1;
	status = smb_raw_setfileinfo(cli->tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_close(cli->tree, fnum);

	status = smb_raw_unlink(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);


	printf("Testing with directory and delete_on_close 0\n");
	fnum = create_directory_handle(cli->tree, dname);

	sfinfo.disposition_info.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.disposition_info.file.fnum = fnum;
	sfinfo.disposition_info.in.delete_on_close = 0;
	status = smb_raw_setfileinfo(cli->tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_close(cli->tree, fnum);

	status = smb_raw_rmdir(cli->tree, &dio);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Testing with directory delete_on_close 1\n");
	fnum = create_directory_handle(cli->tree, dname);
	sfinfo.disposition_info.file.fnum = fnum;
	sfinfo.disposition_info.in.delete_on_close = 1;
	status = smb_raw_setfileinfo(cli->tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_close(cli->tree, fnum);

	status = smb_raw_rmdir(cli->tree, &dio);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

done:
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/* 
   basic testing of unlink calls
*/
BOOL torture_raw_unlink(void)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_unlink");

	ret &= test_unlink(cli, mem_ctx);
	ret &= test_delete_on_close(cli, mem_ctx);

	torture_close_connection(cli);
	talloc_free(mem_ctx);
	return ret;
}
