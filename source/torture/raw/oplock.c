/* 
   Unix SMB/CIFS implementation.
   basic raw test suite for oplocks
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

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%d) wrong value for %s  0x%x - 0x%x\n", \
		       __LINE__, #v, (int)v, (int)correct); \
		ret = False; \
	}} while (0)

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


static struct {
	int fnum;
	unsigned char level;
	int count;
} break_info;

/*
  a handler function for oplock break requests
*/
static BOOL oplock_handler_ack(struct cli_transport *transport, uint16_t tid, uint16_t fnum, uint8_t level, void *private)
{
	struct cli_tree *tree = private;
	break_info.fnum = fnum;
	break_info.level = level;
	break_info.count++;

	printf("Acking in oplock handler\n");

	return cli_oplock_ack(tree, fnum, level);
}

/*
  a handler function for oplock break requests - close the file
*/
static BOOL oplock_handler_close(struct cli_transport *transport, uint16_t tid, uint16_t fnum, uint8_t level, void *private)
{
	union smb_close io;
	NTSTATUS status;
	struct cli_tree *tree = private;

	break_info.fnum = fnum;
	break_info.level = level;
	break_info.count++;

	io.close.level = RAW_CLOSE_CLOSE;
	io.close.in.fnum = fnum;
	io.close.in.write_time = 0;
	status = smb_raw_close(tree, &io);

	printf("Closing in oplock handler\n");

	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed in oplock_handler_close\n");
		return False;
	}
	return True;
}

/*
  test oplock ops
*/
static BOOL test_oplock(struct cli_state *cli, TALLOC_CTX *mem_ctx)
{
	const char *fname = "\\test_oplock.dat";
	NTSTATUS status;
	BOOL ret = True;
	union smb_open io;
	struct smb_unlink unl;
	union smb_read rd;
	uint16_t fnum, fnum2;

	/* cleanup */
	cli_unlink(cli->tree, fname);

	cli_oplock_handler(cli->transport, oplock_handler_ack, cli->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = GENERIC_RIGHTS_FILE_ALL_ACCESS;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	printf("open a file with a normal oplock\n");
	ZERO_STRUCT(break_info);
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | NTCREATEX_FLAGS_REQUEST_OPLOCK;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, EXCLUSIVE_OPLOCK_RETURN);

	printf("unlink it - should be no break\n");
	unl.in.pattern = fname;
	unl.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &unl);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);
	CHECK_VAL(break_info.count, 0);

	cli_close(cli->tree, fnum);

	/*
	  with a batch oplock we get a break
	*/
	printf("open with batch oplock\n");
	ZERO_STRUCT(break_info);
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	printf("unlink should generate a break\n");
	unl.in.pattern = fname;
	unl.in.attrib = 0;
	status = smb_raw_unlink(cli->tree, &unl);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	CHECK_VAL(break_info.fnum, fnum);
	CHECK_VAL(break_info.level, 2);
	CHECK_VAL(break_info.count, 1);


	cli_close(cli->tree, fnum);

	printf("if we close on break then the unlink can succeed\n");
	ZERO_STRUCT(break_info);
	cli_oplock_handler(cli->transport, oplock_handler_close, cli->tree);
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	unl.in.pattern = fname;
	unl.in.attrib = 0;
	ZERO_STRUCT(break_info);
	status = smb_raw_unlink(cli->tree, &unl);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VAL(break_info.fnum, fnum);
	CHECK_VAL(break_info.level, 2);
	CHECK_VAL(break_info.count, 1);

	printf("a self read should not cause a break\n");
	ZERO_STRUCT(break_info);
	cli_close(cli->tree, fnum);
	cli_oplock_handler(cli->transport, oplock_handler_ack, cli->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	rd.read.level = RAW_READ_READ;
	rd.read.in.fnum = fnum;
	rd.read.in.count = 1;
	rd.read.in.offset = 0;
	rd.read.in.remaining = 0;
	status = smb_raw_read(cli->tree, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(break_info.count, 0);


	printf("a 2nd open should give a break\n");
	ZERO_STRUCT(break_info);
	cli_close(cli->tree, fnum);
	cli_oplock_handler(cli->transport, oplock_handler_ack, cli->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	ZERO_STRUCT(break_info);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum);
	CHECK_VAL(break_info.level, 2);

	printf("a 2nd open should get an oplock when we close instead of ack\n");
	ZERO_STRUCT(break_info);
	cli_close(cli->tree, fnum);
	cli_oplock_handler(cli->transport, oplock_handler_close, cli->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	ZERO_STRUCT(break_info);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum2);
	CHECK_VAL(break_info.level, 2);
	
	cli_close(cli->tree, fnum);

	printf("open with batch oplock\n");
	ZERO_STRUCT(break_info);
	cli_oplock_handler(cli->transport, oplock_handler_ack, cli->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	ZERO_STRUCT(break_info);
	printf("second open with attributes only shouldn't cause oplock break\n");

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.access_mask = SA_RIGHT_FILE_READ_ATTRIBUTES|SA_RIGHT_FILE_WRITE_ATTRIBUTES|STD_RIGHT_SYNCHRONIZE_ACCESS;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, NO_OPLOCK_RETURN);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.fnum, 0);
	CHECK_VAL(break_info.level, 0);

done:
	cli_close(cli->tree, fnum);
	cli_close(cli->tree, fnum2);
	cli_unlink(cli->tree, fname);
	return ret;
}


/* 
   basic testing of oplocks
*/
BOOL torture_raw_oplock(int dummy)
{
	struct cli_state *cli1;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli1)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_oplock");

	if (!test_oplock(cli1, mem_ctx)) {
		ret = False;
	}

	torture_close_connection(cli1);
	talloc_destroy(mem_ctx);
	return ret;
}
