/* 
   Unix SMB/CIFS implementation.
   basic raw test suite for oplocks
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
#include "librpc/gen_ndr/security.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "torture/util.h"
#include "lib/events/events.h"

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_comment(tctx, "(%s): wrong value for %s got 0x%x - should be 0x%x\n", \
				__location__, #v, (int)v, (int)correct); \
		ret = False; \
	}} while (0)

#define CHECK_STATUS(tctx, status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": Incorrect status %s - should be %s", \
		       nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


static struct {
	int fnum;
	uint8_t level;
	int count;
	int failures;
} break_info;

#define BASEDIR "\\test_oplock"

/*
  a handler function for oplock break requests. Ack it as a break to level II if possible
*/
static BOOL oplock_handler_ack_to_levelII(struct smbcli_transport *transport, uint16_t tid, 
			       uint16_t fnum, uint8_t level, void *private)
{
	struct smbcli_tree *tree = private;
	break_info.fnum = fnum;
	break_info.level = level;
	break_info.count++;

	printf("Acking to level II in oplock handler\n");

	return smbcli_oplock_ack(tree, fnum, level);
}

/*
  a handler function for oplock break requests. Ack it as a break to none
*/
static BOOL oplock_handler_ack_to_none(struct smbcli_transport *transport, uint16_t tid, 
				    uint16_t fnum, uint8_t level, 
				    void *private)
{
	struct smbcli_tree *tree = private;
	break_info.fnum = fnum;
	break_info.level = level;
	break_info.count++;

	printf("Acking to none in oplock handler\n");

	return smbcli_oplock_ack(tree, fnum, OPLOCK_BREAK_TO_NONE);
}

static void oplock_handler_close_recv(struct smbcli_request *req)
{
	NTSTATUS status;
	status = smbcli_request_simple_recv(req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed in oplock_handler_close\n");
		break_info.failures++;
	}
}

/*
  a handler function for oplock break requests - close the file
*/
static BOOL oplock_handler_close(struct smbcli_transport *transport, uint16_t tid, 
				 uint16_t fnum, uint8_t level, void *private)
{
	union smb_close io;
	struct smbcli_tree *tree = private;
	struct smbcli_request *req;

	break_info.fnum = fnum;
	break_info.level = level;
	break_info.count++;

	io.close.level = RAW_CLOSE_CLOSE;
	io.close.in.file.fnum = fnum;
	io.close.in.write_time = 0;
	req = smb_raw_close_send(tree, &io);
	if (req == NULL) {
		printf("failed to send close in oplock_handler_close\n");
		return False;
	}

	req->async.fn = oplock_handler_close_recv;
	req->async.private = NULL;

	return True;
}

static bool test_raw_oplock_normal(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_normal.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_unlink unl;
	uint16_t fnum=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "open a file with a normal oplock\n");
	ZERO_STRUCT(break_info);
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | NTCREATEX_FLAGS_REQUEST_OPLOCK;

	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, EXCLUSIVE_OPLOCK_RETURN);

	torture_comment(tctx, "a 2nd open should not cause a break\n");
	status = smb_raw_open(cli2->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_SHARING_VIOLATION);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	torture_comment(tctx, "unlink it - should also be no break\n");
	unl.unlink.in.pattern = fname;
	unl.unlink.in.attrib = 0;
	status = smb_raw_unlink(cli2->tree, &unl);
	CHECK_STATUS(tctx, status, NT_STATUS_SHARING_VIOLATION);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch1(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch1.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_unlink unl;
	uint16_t fnum=0;
	char c = 0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	/*
	  with a batch oplock we get a break
	*/
	torture_comment(tctx, "open with batch oplock\n");
	ZERO_STRUCT(break_info);
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	torture_comment(tctx, "unlink should generate a break\n");
	unl.unlink.in.pattern = fname;
	unl.unlink.in.attrib = 0;
	status = smb_raw_unlink(cli2->tree, &unl);
	CHECK_STATUS(tctx, status, NT_STATUS_SHARING_VIOLATION);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum);
	CHECK_VAL(break_info.level, OPLOCK_BREAK_TO_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);

	torture_comment(tctx, "2nd unlink should not generate a break\n");
	ZERO_STRUCT(break_info);
	status = smb_raw_unlink(cli2->tree, &unl);
	CHECK_STATUS(tctx, status, NT_STATUS_SHARING_VIOLATION);

	CHECK_VAL(break_info.count, 0);

	torture_comment(tctx, "writing should generate a self break to none\n");
	smbcli_write(cli1->tree, fnum, 0, &c, 0, 1);
	msleep(100);
	smbcli_write(cli1->tree, fnum, 0, &c, 1, 1);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum);
	CHECK_VAL(break_info.level, OPLOCK_BREAK_TO_NONE);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch2(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch2.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_unlink unl;
	uint16_t fnum=0;
	char c = 0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "open with batch oplock\n");
	ZERO_STRUCT(break_info);
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	torture_comment(tctx, "unlink should generate a break, which we ack as break to none\n");
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_none, cli1->tree);
	unl.unlink.in.pattern = fname;
	unl.unlink.in.attrib = 0;
	status = smb_raw_unlink(cli2->tree, &unl);
	CHECK_STATUS(tctx, status, NT_STATUS_SHARING_VIOLATION);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum);
	CHECK_VAL(break_info.level, OPLOCK_BREAK_TO_LEVEL_II);
	CHECK_VAL(break_info.failures, 0);

	torture_comment(tctx, "2nd unlink should not generate a break\n");
	ZERO_STRUCT(break_info);
	status = smb_raw_unlink(cli2->tree, &unl);
	CHECK_STATUS(tctx, status, NT_STATUS_SHARING_VIOLATION);

	CHECK_VAL(break_info.count, 0);

	torture_comment(tctx, "writing should not generate a break\n");
	smbcli_write(cli1->tree, fnum, 0, &c, 0, 1);
	msleep(100);
	smbcli_write(cli1->tree, fnum, 0, &c, 1, 1);

	CHECK_VAL(break_info.count, 0);

	smbcli_close(cli1->tree, fnum);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch3(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch3.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_unlink unl;
	uint16_t fnum=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "if we close on break then the unlink can succeed\n");
	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_close, cli1->tree);
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	unl.unlink.in.pattern = fname;
	unl.unlink.in.attrib = 0;
	ZERO_STRUCT(break_info);
	status = smb_raw_unlink(cli2->tree, &unl);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum);
	CHECK_VAL(break_info.level, 1);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch4(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch4.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_read rd;
	uint16_t fnum=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "a self read should not cause a break\n");
	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	rd.read.level = RAW_READ_READ;
	rd.read.in.file.fnum = fnum;
	rd.read.in.count = 1;
	rd.read.in.offset = 0;
	rd.read.in.remaining = 0;
	status = smb_raw_read(cli1->tree, &rd);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch5(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch5.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	uint16_t fnum=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "a 2nd open should give a break\n");
	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	ZERO_STRUCT(break_info);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED;
	status = smb_raw_open(cli2->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_SHARING_VIOLATION);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum);
	CHECK_VAL(break_info.level, 1);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch6(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch6.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	uint16_t fnum=0, fnum2=0;
	char c = 0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "a 2nd open should give a break to level II if the first open allowed shared read\n");
	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);
	smbcli_oplock_handler(cli2->transport, oplock_handler_ack_to_levelII, cli2->tree);

	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_READ | SEC_RIGHTS_FILE_WRITE;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	ZERO_STRUCT(break_info);

	status = smb_raw_open(cli2->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, LEVEL_II_OPLOCK_RETURN);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum);
	CHECK_VAL(break_info.level, 1);
	CHECK_VAL(break_info.failures, 0);
	ZERO_STRUCT(break_info);

	torture_comment(tctx, "write should trigger a break to none on both\n");
	smbcli_write(cli1->tree, fnum, 0, &c, 0, 1);
	msleep(100);
	smbcli_write(cli1->tree, fnum, 0, &c, 1, 1);

	CHECK_VAL(break_info.count, 2);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);
	smbcli_close(cli2->tree, fnum2);


done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch7(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch7.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	uint16_t fnum=0, fnum2=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "a 2nd open should get an oplock when we close instead of ack\n");
	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_close, cli1->tree);

	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	ZERO_STRUCT(break_info);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli2->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum2);
	CHECK_VAL(break_info.level, 1);
	CHECK_VAL(break_info.failures, 0);
	
	smbcli_close(cli2->tree, fnum);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch8(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch8.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	uint16_t fnum=0, fnum2=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "open with batch oplock\n");
	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	ZERO_STRUCT(break_info);
	torture_comment(tctx, "second open with attributes only shouldn't cause oplock break\n");

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.access_mask = SEC_FILE_READ_ATTRIBUTE|SEC_FILE_WRITE_ATTRIBUTE|SEC_STD_SYNCHRONIZE;
	status = smb_raw_open(cli2->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, NO_OPLOCK_RETURN);
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);
	smbcli_close(cli2->tree, fnum2);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch9(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch9.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	uint16_t fnum=0, fnum2=0;
	char c = 0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "open with attributes only can create file\n");

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.access_mask = SEC_FILE_READ_ATTRIBUTE|SEC_FILE_WRITE_ATTRIBUTE|SEC_STD_SYNCHRONIZE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	torture_comment(tctx, "Subsequent normal open should break oplock on attribute only open to level II\n");

	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	status = smb_raw_open(cli2->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.level, OPLOCK_BREAK_TO_LEVEL_II);
	CHECK_VAL(io.ntcreatex.out.oplock_level, LEVEL_II_OPLOCK_RETURN);
	smbcli_close(cli2->tree, fnum2);

	torture_comment(tctx, "third oplocked open should grant level2 without break\n");
	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);
	smbcli_oplock_handler(cli2->transport, oplock_handler_ack_to_levelII, cli2->tree);
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	status = smb_raw_open(cli2->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.ntcreatex.out.oplock_level, LEVEL_II_OPLOCK_RETURN);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "write should trigger a break to none on both\n");
	smbcli_write(cli2->tree, fnum2, 0, &c, 0, 1);

	/* Now the oplock break request comes in. But right now we can't
	 * answer it. Do another write */

	msleep(100);
	smbcli_write(cli2->tree, fnum2, 0, &c, 1, 1);

	CHECK_VAL(break_info.count, 2);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);
	smbcli_close(cli2->tree, fnum2);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch10(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch10.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	uint16_t fnum=0, fnum2=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "Open with oplock after a non-oplock open should grant level2\n");
	ZERO_STRUCT(break_info);
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.ntcreatex.out.oplock_level, 0);

	smbcli_oplock_handler(cli2->transport, oplock_handler_ack_to_levelII, cli1->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED |
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	status = smb_raw_open(cli2->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.ntcreatex.out.oplock_level, LEVEL_II_OPLOCK_RETURN);

	torture_comment(tctx, "write should trigger a break to none\n");
	{
		union smb_write wr;
		wr.write.level = RAW_WRITE_WRITE;
		wr.write.in.file.fnum = fnum;
		wr.write.in.count = 1;
		wr.write.in.offset = 0;
		wr.write.in.remaining = 0;
		wr.write.in.data = (const uint8_t *)"x";
		status = smb_raw_write(cli1->tree, &wr);
		CHECK_STATUS(tctx, status, NT_STATUS_OK);
	}

	/* Now the oplock break request comes in. But right now we can't
	 * answer it. Do another write */

	msleep(100);
	
	{
		union smb_write wr;
		wr.write.level = RAW_WRITE_WRITE;
		wr.write.in.file.fnum = fnum;
		wr.write.in.count = 1;
		wr.write.in.offset = 0;
		wr.write.in.remaining = 0;
		wr.write.in.data = (const uint8_t *)"x";
		status = smb_raw_write(cli1->tree, &wr);
		CHECK_STATUS(tctx, status, NT_STATUS_OK);
	}

	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.fnum, fnum2);
	CHECK_VAL(break_info.level, 0);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);
	smbcli_close(cli2->tree, fnum2);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch11(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch11.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_setfileinfo sfi;
	uint16_t fnum=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	/* Test if a set-eof on pathname breaks an exclusive oplock. */
	torture_comment(tctx, "Test if setpathinfo set EOF breaks oplocks.\n");

	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED |
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);
	
	ZERO_STRUCT(sfi);
	sfi.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sfi.generic.in.file.path = fname;
	sfi.end_of_file_info.in.size = 100;

        status = smb_raw_setpathinfo(cli2->tree, &sfi);

	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.level, 0);

	smbcli_close(cli1->tree, fnum);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch12(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch12.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	union smb_setfileinfo sfi;
	uint16_t fnum=0, fnum2=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	/* Test if a set-allocation size on pathname breaks an exclusive oplock. */
	torture_comment(tctx, "Test if setpathinfo allocation size breaks oplocks.\n");

	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED |
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(break_info.count, 0);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);
	
	ZERO_STRUCT(sfi);
	sfi.generic.level = SMB_SFILEINFO_ALLOCATION_INFORMATION;
	sfi.generic.in.file.path = fname;
	sfi.allocation_info.in.alloc_size = 65536 * 8;

        status = smb_raw_setpathinfo(cli2->tree, &sfi);

	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.failures, 0);
	CHECK_VAL(break_info.level, 0);

	smbcli_close(cli1->tree, fnum);
	smbcli_close(cli2->tree, fnum2);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch13(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch13.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	uint16_t fnum=0, fnum2=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);
	smbcli_oplock_handler(cli2->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "open with batch oplock\n");
	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);


	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "second open with attributes only and NTCREATEX_DISP_OVERWRITE dispostion causes oplock break\n");

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.access_mask = SEC_FILE_READ_ATTRIBUTE|SEC_FILE_WRITE_ATTRIBUTE|SEC_STD_SYNCHRONIZE;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OVERWRITE;
	status = smb_raw_open(cli2->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, LEVEL_II_OPLOCK_RETURN);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);
	smbcli_close(cli2->tree, fnum2);

done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

static bool test_raw_oplock_batch14(struct torture_context *tctx, struct smbcli_state *cli1, struct smbcli_state *cli2)
{
	const char *fname = BASEDIR "\\test_batch14.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	uint16_t fnum=0, fnum2=0;

	if (!torture_setup_dir(cli1, BASEDIR)) {
		return false;
	}

	/* cleanup */
	smbcli_unlink(cli1->tree, fname);

	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	/*
	  base ntcreatex parms
	*/
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;

	torture_comment(tctx, "open with batch oplock\n");
	ZERO_STRUCT(break_info);
	smbcli_oplock_handler(cli1->transport, oplock_handler_ack_to_levelII, cli1->tree);

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb_raw_open(cli1->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, BATCH_OPLOCK_RETURN);

	ZERO_STRUCT(break_info);

	torture_comment(tctx, "second open with attributes only and NTCREATEX_DISP_SUPERSEDE dispostion causes oplock break\n");

	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
	io.ntcreatex.in.access_mask = SEC_FILE_READ_ATTRIBUTE|SEC_FILE_WRITE_ATTRIBUTE|SEC_STD_SYNCHRONIZE;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OVERWRITE;
	status = smb_raw_open(cli2->tree, tctx, &io);
	CHECK_STATUS(tctx, status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;
	CHECK_VAL(io.ntcreatex.out.oplock_level, LEVEL_II_OPLOCK_RETURN);
	CHECK_VAL(break_info.count, 1);
	CHECK_VAL(break_info.failures, 0);

	smbcli_close(cli1->tree, fnum);
	smbcli_close(cli2->tree, fnum2);
done:
	smb_raw_exit(cli1->session);
	smb_raw_exit(cli2->session);
	smbcli_deltree(cli1->tree, BASEDIR);
	return ret;
}

/* 
   basic testing of oplocks
*/
struct torture_suite *torture_raw_oplock(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "OPLOCK");

	torture_suite_add_2smb_test(suite, "NORMAL", test_raw_oplock_normal);
	torture_suite_add_2smb_test(suite, "BATCH1", test_raw_oplock_batch1);
	torture_suite_add_2smb_test(suite, "BATCH2", test_raw_oplock_batch2);
	torture_suite_add_2smb_test(suite, "BATCH3", test_raw_oplock_batch3);
	torture_suite_add_2smb_test(suite, "BATCH4", test_raw_oplock_batch4);
	torture_suite_add_2smb_test(suite, "BATCH5", test_raw_oplock_batch5);
	torture_suite_add_2smb_test(suite, "BATCH6", test_raw_oplock_batch6);
	torture_suite_add_2smb_test(suite, "BATCH7", test_raw_oplock_batch7);
	torture_suite_add_2smb_test(suite, "BATCH8", test_raw_oplock_batch8);
	torture_suite_add_2smb_test(suite, "BATCH9", test_raw_oplock_batch9);
	torture_suite_add_2smb_test(suite, "BATCH10", test_raw_oplock_batch10);
	torture_suite_add_2smb_test(suite, "BATCH11", test_raw_oplock_batch11);
	torture_suite_add_2smb_test(suite, "BATCH12", test_raw_oplock_batch12);
	torture_suite_add_2smb_test(suite, "BATCH13", test_raw_oplock_batch13);
	torture_suite_add_2smb_test(suite, "BATCH14", test_raw_oplock_batch14);

	return suite;
}

/* 
   stress testing of oplocks
*/
BOOL torture_bench_oplock(struct torture_context *torture)
{
	struct smbcli_state **cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx = talloc_new(torture);
	int torture_nprocs = torture_setting_int(torture, "nprocs", 4);
	int i, count=0;
	int timelimit = torture_setting_int(torture, "timelimit", 10);
	union smb_open io;
	struct timeval tv;
	struct event_context *ev = event_context_find(mem_ctx);

	cli = talloc_array(mem_ctx, struct smbcli_state *, torture_nprocs);

	torture_comment(torture, "Opening %d connections\n", torture_nprocs);
	for (i=0;i<torture_nprocs;i++) {
		if (!torture_open_connection_ev(&cli[i], i, ev)) {
			return False;
		}
		talloc_steal(mem_ctx, cli[i]);
		smbcli_oplock_handler(cli[i]->transport, oplock_handler_close, 
				      cli[i]->tree);
	}

	if (!torture_setup_dir(cli[0], BASEDIR)) {
		ret = False;
		goto done;
	}

	io.ntcreatex.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = BASEDIR "\\test.dat";
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED | 
		NTCREATEX_FLAGS_REQUEST_OPLOCK | 
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;

	tv = timeval_current();	

	/*
	  we open the same file with SHARE_ACCESS_NONE from all the
	  connections in a round robin fashion. Each open causes an
	  oplock break on the previous connection, which is answered
	  by the oplock_handler_close() to close the file.

	  This measures how fast we can pass on oplocks, and stresses
	  the oplock handling code
	*/
	torture_comment(torture, "Running for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		for (i=0;i<torture_nprocs;i++) {
			NTSTATUS status;

			status = smb_raw_open(cli[i]->tree, mem_ctx, &io);
			CHECK_STATUS(torture, status, NT_STATUS_OK);
			count++;
		}

		if (torture_setting_bool(torture, "progress", true)) {
			torture_comment(torture, "%.2f ops/second\r", count/timeval_elapsed(&tv));
		}
	}

	torture_comment(torture, "%.2f ops/second\n", count/timeval_elapsed(&tv));

	smb_raw_exit(cli[torture_nprocs-1]->session);
	
done:
	smb_raw_exit(cli[0]->session);
	smbcli_deltree(cli[0]->tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;
}
