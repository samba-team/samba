/* 
   Unix SMB/CIFS implementation.

   test alternate data streams

   Copyright (C) Andrew Tridgell 2004
   
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
#include "system/filesys.h"
#include "libcli/libcli.h"
#include "torture/util.h"

#define BASEDIR "\\teststreams"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%d - should be %d\n", \
		       __location__, #v, (int)v, (int)correct); \
		ret = False; \
	}} while (0)

/*
  check that a stream has the right contents
*/
static BOOL check_stream(struct smbcli_state *cli, TALLOC_CTX *mem_ctx,
			 const char *fname, const char *sname, 
			 const char *value)
{
	int fnum;
	const char *full_name;
	uint8_t *buf;
	ssize_t ret;

	full_name = talloc_asprintf(mem_ctx, "%s:%s", fname, sname);

	fnum = smbcli_open(cli->tree, full_name, O_RDONLY, DENY_NONE);

	if (value == NULL) {
		if (fnum != -1) {
			printf("should have failed stream open of %s\n", full_name);
			return False;
		}
		return True;
	}
	    
	if (fnum == -1) {
		printf("Failed to open stream '%s' - %s\n", 
		       full_name, smbcli_errstr(cli->tree));
		return False;
	}

	buf = talloc_size(mem_ctx, strlen(value)+11);
	
	ret = smbcli_read(cli->tree, fnum, buf, 0, strlen(value)+11);
	if (ret != strlen(value)) {
		printf("Failed to read %lu bytes from stream '%s' - got %d\n",
		       (long)strlen(value), full_name, (int)ret);
		return False;
	}

	if (memcmp(buf, value, strlen(value)) != 0) {
		printf("Bad data in stream\n");
		return False;
	}

	smbcli_close(cli->tree, fnum);
	return True;
}

/*
  test basic io on streams
*/
static BOOL test_stream_io(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	union smb_open io;
	const char *fname = BASEDIR "\\stream.txt";
	const char *sname1, *sname2;
	BOOL ret = True;
	int fnum = -1;
	ssize_t retsize;

	sname1 = talloc_asprintf(mem_ctx, "%s:%s", fname, "Stream One");
	sname2 = talloc_asprintf(mem_ctx, "%s:%s:$DaTa", fname, "Second Stream");

	printf("opening non-existant directory stream\n");
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FILE_WRITE_DATA;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = 0;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = sname1;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_NOT_A_DIRECTORY);

	printf("creating a stream on a non-existant file\n");
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.fname = sname1;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	ret &= check_stream(cli, mem_ctx, fname, "Stream One", NULL);

	printf("check that open of base file is allowed\n");
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	smbcli_close(cli->tree, io.ntcreatex.out.file.fnum);

	printf("writing to stream\n");
	retsize = smbcli_write(cli->tree, fnum, 0, "test data", 0, 9);
	CHECK_VALUE(retsize, 9);

	smbcli_close(cli->tree, fnum);

	ret &= check_stream(cli, mem_ctx, fname, "Stream One", "test data");

	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.fname = sname1;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	printf("modifying stream\n");
	retsize = smbcli_write(cli->tree, fnum, 0, "MORE DATA ", 5, 10);
	CHECK_VALUE(retsize, 10);

	smbcli_close(cli->tree, fnum);

	ret &= check_stream(cli, mem_ctx, fname, "Stream One:$FOO", NULL);

	printf("creating a stream2 on a existing file\n");
	io.ntcreatex.in.fname = sname2;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	printf("modifying stream\n");
	retsize = smbcli_write(cli->tree, fnum, 0, "SECOND STREAM", 0, 13);
	CHECK_VALUE(retsize, 13);

	smbcli_close(cli->tree, fnum);

	ret &= check_stream(cli, mem_ctx, fname, "Stream One", "test MORE DATA ");
	ret &= check_stream(cli, mem_ctx, fname, "Stream One:$DATA", "test MORE DATA ");
	ret &= check_stream(cli, mem_ctx, fname, "Stream One:", NULL);
	ret &= check_stream(cli, mem_ctx, fname, "Second Stream", "SECOND STREAM");
	ret &= check_stream(cli, mem_ctx, fname, "Second Stream:$DATA", "SECOND STREAM");
	ret &= check_stream(cli, mem_ctx, fname, "Second Stream:", NULL);
	ret &= check_stream(cli, mem_ctx, fname, "Second Stream:$FOO", NULL);

	printf("deleting stream\n");
	status = smbcli_unlink(cli->tree, sname1);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("delete a stream via delete-on-close\n");
	io.ntcreatex.in.fname = sname2;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	
	smbcli_close(cli->tree, fnum);
	status = smbcli_unlink(cli->tree, sname2);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);


	printf("deleting file\n");
	status = smbcli_unlink(cli->tree, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smbcli_close(cli->tree, fnum);
	return ret;
}

/* 
   basic testing of streams calls
*/
BOOL torture_raw_streams(struct torture_context *torture)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_streams");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	ret &= test_stream_io(cli, mem_ctx);

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	torture_close_connection(cli);
	talloc_free(mem_ctx);
	return ret;
}
