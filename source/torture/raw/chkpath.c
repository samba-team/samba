/* 
   Unix SMB/CIFS implementation.
   chkpath individual test suite
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

#define BASEDIR "\\rawchkpath"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


static BOOL test_chkpath(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	struct smb_chkpath io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum = -1;

	io.in.path = BASEDIR;

	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.in.path = BASEDIR "\\nodir";
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	fnum = create_complex_file(cli, mem_ctx, BASEDIR "\\test.txt");
	if (fnum == -1) {
		printf("failed to open test.txt - %s\n", smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	io.in.path = BASEDIR "\\test.txt";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NOT_A_DIRECTORY);
	
	if (!torture_set_file_attribute(cli->tree, BASEDIR, FILE_ATTRIBUTE_HIDDEN)) {
		printf("failed to set basedir hidden\n");
		ret = False;
		goto done;
	}

	io.in.path = BASEDIR;
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.in.path = "";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.in.path = ".";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);

	io.in.path = "\\";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.in.path = "\\.";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);

	io.in.path = "\\..";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);

	io.in.path = BASEDIR "\\.";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);

	io.in.path = BASEDIR "\\..";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.in.path = BASEDIR "\\nt\\Visual Studio\\VB98\\vb600";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	io.in.path = BASEDIR "\\nt\\Visual Studio\\VB98\\vb6.exe";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NOT_A_DIRECTORY);

	io.in.path = BASEDIR "\\nt\\Visual Studio\\VB98\\vb6.exe\\3";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);

	io.in.path = BASEDIR "\\nt\\Visual Studio\\*\\vb6.exe\\3";
	printf("testing %s\n", io.in.path);
	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);

done:
	smbcli_close(cli->tree, fnum);
	return ret;
}

/* 
   basic testing of chkpath calls 
*/
BOOL torture_raw_chkpath(int dummy)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	int fnum;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_chkpath");

	if (smbcli_deltree(cli->tree, BASEDIR) == -1) {
		printf("Failed to clean " BASEDIR "\n");
		return False;
	}
	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Failed to create " BASEDIR " - %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR "\\nt"))) {
		printf("Failed to create " BASEDIR " - %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR "\\nt\\Visual Studio"))) {
		printf("Failed to create " BASEDIR " - %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR "\\nt\\Visual Studio\\VB98"))) {
		printf("Failed to create " BASEDIR " - %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	fnum = create_complex_file(cli, mem_ctx, BASEDIR "\\nt\\Visual Studio\\VB98\\vb6.exe");
	if (fnum == -1) {
		printf("failed to open \\nt\\Visual Studio\\VB98\\vb6.exe - %s\n", smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	if (!test_chkpath(cli, mem_ctx)) {
		ret = False;
	}

 done:

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
