/* 
   Unix SMB/CIFS implementation.
   rename test suite
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
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

#define BASEDIR "\\testrename"

/*
  test SMBmv ops
*/
static BOOL test_mv(struct cli_state *cli, TALLOC_CTX *mem_ctx)
{
	struct smb_rename io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	const char *fname1 = BASEDIR "\\test1.txt";
	const char *fname2 = BASEDIR "\\test2.txt";

	if (cli_deltree(cli, BASEDIR) == -1 ||
	    !cli_mkdir(cli, BASEDIR)) {
		printf("Unable to setup %s - %s\n", BASEDIR, cli_errstr(cli));
		return False;
	}

	printf("Trying simple rename\n");

	fnum = create_complex_file(cli, mem_ctx, fname1);
	
	io.in.pattern1 = fname1;
	io.in.pattern2 = fname2;
	io.in.attrib = 0;
	
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);
	
	smb_raw_exit(cli->session);
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);


	printf("trying wildcard rename\n");
	io.in.pattern1 = BASEDIR "\\*.txt";
	io.in.pattern2 = fname1;
	
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("and again\n");
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying extension change\n");
	io.in.pattern1 = BASEDIR "\\*.txt";
	io.in.pattern2 = BASEDIR "\\*.bak";
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);

	printf("Checking attrib handling\n");
	torture_set_file_attribute(cli->tree, BASEDIR "\\test1.bak", FILE_ATTRIBUTE_HIDDEN);
	io.in.pattern1 = BASEDIR "\\test1.bak";
	io.in.pattern2 = BASEDIR "\\*.txt";
	io.in.attrib = 0;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_NO_SUCH_FILE);

	io.in.attrib = FILE_ATTRIBUTE_HIDDEN;
	status = smb_raw_rename(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smb_raw_exit(cli->session);
	cli_deltree(cli, BASEDIR);
	return ret;
}


/* 
   basic testing of rename calls
*/
BOOL torture_raw_rename(int dummy)
{
	struct cli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_rename");

	if (!test_mv(cli, mem_ctx)) {
		ret = False;
	}

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
