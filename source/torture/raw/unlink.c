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

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 ||
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Unable to setup %s - %s\n", BASEDIR, smbcli_errstr(cli->tree));
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

	if (!test_unlink(cli, mem_ctx)) {
		ret = False;
	}

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
