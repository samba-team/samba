/* 
   Unix SMB/CIFS implementation.
   test suite for various lock operations
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

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%d) Incorrect value %s=%d - should be %d\n", \
		       __LINE__, #v, v, correct); \
		ret = False; \
		goto done; \
	}} while (0)

#define BASEDIR "\\testlock"


/*
  test SMBlock and SMBunlock ops
*/
static BOOL test_lock(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_lock io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 ||
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Unable to setup %s - %s\n", BASEDIR, smbcli_errstr(cli->tree));
		return False;
	}

	printf("Testing RAW_LOCK_LOCK\n");
	io.generic.level = RAW_LOCK_LOCK;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	printf("Trying 0/0 lock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.fnum = fnum;
	io.lock.in.count = 0;
	io.lock.in.offset = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid--;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying 0/1 lock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.fnum = fnum;
	io.lock.in.count = 1;
	io.lock.in.offset = 0;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);
	cli->session->pid--;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying 0xEEFFFFFF lock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.fnum = fnum;
	io.lock.in.count = 4000;
	io.lock.in.offset = 0xEEFFFFFF;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);
	cli->session->pid--;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying 0xEF000000 lock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.fnum = fnum;
	io.lock.in.count = 4000;
	io.lock.in.offset = 0xEEFFFFFF;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);
	cli->session->pid--;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying max lock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.fnum = fnum;
	io.lock.in.count = 4000;
	io.lock.in.offset = 0xEF000000;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);
	cli->session->pid--;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	printf("Trying wrong pid unlock\n");
	io.lock.level = RAW_LOCK_LOCK;
	io.lock.in.fnum = fnum;
	io.lock.in.count = 4002;
	io.lock.in.offset = 10001;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	cli->session->pid++;
	io.lock.level = RAW_LOCK_UNLOCK;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);
	cli->session->pid--;
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test locking&X ops
*/
static BOOL test_lockx(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_lock io;
	struct smb_lock_entry lock[1];
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 ||
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Unable to setup %s - %s\n", BASEDIR, smbcli_errstr(cli->tree));
		return False;
	}

	printf("Testing RAW_LOCK_LOCKX\n");
	io.generic.level = RAW_LOCK_LOCKX;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 0;
	lock[0].count = 0xFFFFFFFF;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test high pid
*/
static BOOL test_pidhigh(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_lock io;
	struct smb_lock_entry lock[1];
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	char c = 1;

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 ||
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Unable to setup %s - %s\n", BASEDIR, smbcli_errstr(cli->tree));
		return False;
	}

	printf("Testing high pid\n");
	io.generic.level = RAW_LOCK_LOCKX;

	cli->session->pid = 1;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	if (smbcli_write(cli->tree, fnum, 0, &c, 0, 1) != 1) {
		printf("Failed to write 1 byte - %s\n", smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.fnum = fnum;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = 0;
	io.lockx.in.ulock_cnt = 0;
	io.lockx.in.lock_cnt = 1;
	lock[0].pid = cli->session->pid;
	lock[0].offset = 0;
	lock[0].count = 0xFFFFFFFF;
	io.lockx.in.locks = &lock[0];
	status = smb_raw_lock(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (smbcli_read(cli->tree, fnum, &c, 0, 1) != 1) {
		printf("Failed to read 1 byte - %s\n", smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	cli->session->pid |= 0x10000;

	cli->session->pid = 2;

	if (smbcli_read(cli->tree, fnum, &c, 0, 1) == 1) {
		printf("pid is incorrect handled for read with lock!\n");
		ret = False;
		goto done;
	}

	cli->session->pid = 0x10001;

	if (smbcli_read(cli->tree, fnum, &c, 0, 1) != 1) {
		printf("High pid is used on this server!\n");
		ret = False;
	} else {
		printf("High pid is not used on this server (correct)\n");
	}

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/* 
   basic testing of lock calls
*/
BOOL torture_raw_lock(int dummy)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_lock");

	if (!test_lockx(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_lock(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_pidhigh(cli, mem_ctx)) {
		ret = False;
	}

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
