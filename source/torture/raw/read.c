/* 
   Unix SMB/CIFS implementation.
   test suite for various read operations
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
#include "libcli/raw/libcliraw.h"
#include "system/time.h"

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
		       __location__, #v, v, correct); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_BUFFER(buf, seed, len) do { \
	if (!check_buffer(buf, seed, len, __LINE__)) { \
		ret = False; \
		goto done; \
	}} while (0)

#define BASEDIR "\\testread"


/*
  setup a random buffer based on a seed
*/
static void setup_buffer(uint8_t *buf, uint_t seed, int len)
{
	int i;
	srandom(seed);
	for (i=0;i<len;i++) buf[i] = random();
}

/*
  check a random buffer based on a seed
*/
static BOOL check_buffer(uint8_t *buf, uint_t seed, int len, int line)
{
	int i;
	srandom(seed);
	for (i=0;i<len;i++) {
		uint8_t v = random();
		if (buf[i] != v) {
			printf("Buffer incorrect at line %d! ofs=%d v1=0x%x v2=0x%x\n", 
			       line, i, buf[i], v);
			return False;
		}
	}
	return True;
}

/*
  test read ops
*/
static BOOL test_read(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_read io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	uint8_t *buf;
	const int maxsize = 90000;
	const char *fname = BASEDIR "\\test.txt";
	const char *test_data = "TEST DATA";
	uint_t seed = time(NULL);

	buf = talloc_zero(mem_ctx, maxsize);

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	printf("Testing RAW_READ_READ\n");
	io.generic.level = RAW_READ_READ;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	printf("Trying empty file read\n");
	io.read.in.fnum = fnum;
	io.read.in.count = 1;
	io.read.in.offset = 0;
	io.read.in.remaining = 0;
	io.read.out.data = buf;
	status = smb_raw_read(cli->tree, &io);

	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.read.out.nread, 0);

	printf("Trying zero file read\n");
	io.read.in.count = 0;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.read.out.nread, 0);

	printf("Trying bad fnum\n");
	io.read.in.fnum = fnum+1;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);
	io.read.in.fnum = fnum;

	smbcli_write(cli->tree, fnum, 0, test_data, 0, strlen(test_data));

	printf("Trying small read\n");
	io.read.in.fnum = fnum;
	io.read.in.offset = 0;
	io.read.in.remaining = 0;
	io.read.in.count = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.read.out.nread, strlen(test_data));
	if (memcmp(buf, test_data, strlen(test_data)) != 0) {
		ret = False;
		printf("incorrect data at %d!? (%s:%s)\n", __LINE__, test_data, buf);
		goto done;
	}

	printf("Trying short read\n");
	io.read.in.offset = 1;
	io.read.in.count = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.read.out.nread, strlen(test_data)-1);
	if (memcmp(buf, test_data+1, strlen(test_data)-1) != 0) {
		ret = False;
		printf("incorrect data at %d!? (%s:%s)\n", __LINE__, test_data+1, buf);
		goto done;
	}

	printf("Trying max offset\n");
	io.read.in.offset = ~0;
	io.read.in.count = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.read.out.nread, 0);

	setup_buffer(buf, seed, maxsize);
	smbcli_write(cli->tree, fnum, 0, buf, 0, maxsize);
	memset(buf, 0, maxsize);

	printf("Trying large read\n");
	io.read.in.offset = 0;
	io.read.in.count = ~0;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_BUFFER(buf, seed, io.read.out.nread);


	printf("Trying locked region\n");
	cli->session->pid++;
	if (NT_STATUS_IS_ERR(smbcli_lock(cli->tree, fnum, 103, 1, 0, WRITE_LOCK))) {
		printf("Failed to lock file at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	cli->session->pid--;
	memset(buf, 0, maxsize);
	io.read.in.offset = 0;
	io.read.in.count = ~0;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);
	

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test lockread ops
*/
static BOOL test_lockread(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_read io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	uint8_t *buf;
	const int maxsize = 90000;
	const char *fname = BASEDIR "\\test.txt";
	const char *test_data = "TEST DATA";
	uint_t seed = time(NULL);

	buf = talloc_zero(mem_ctx, maxsize);

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	printf("Testing RAW_READ_LOCKREAD\n");
	io.generic.level = RAW_READ_LOCKREAD;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	printf("Trying empty file read\n");
	io.lockread.in.fnum = fnum;
	io.lockread.in.count = 1;
	io.lockread.in.offset = 1;
	io.lockread.in.remaining = 0;
	io.lockread.out.data = buf;
	status = smb_raw_read(cli->tree, &io);

	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.lockread.out.nread, 0);

	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	printf("Trying zero file read\n");
	io.lockread.in.count = 0;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	smbcli_unlock(cli->tree, fnum, 1, 1);

	printf("Trying bad fnum\n");
	io.lockread.in.fnum = fnum+1;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);
	io.lockread.in.fnum = fnum;

	smbcli_write(cli->tree, fnum, 0, test_data, 0, strlen(test_data));

	printf("Trying small read\n");
	io.lockread.in.fnum = fnum;
	io.lockread.in.offset = 0;
	io.lockread.in.remaining = 0;
	io.lockread.in.count = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	smbcli_unlock(cli->tree, fnum, 1, 0);

	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.lockread.out.nread, strlen(test_data));
	if (memcmp(buf, test_data, strlen(test_data)) != 0) {
		ret = False;
		printf("incorrect data at %d!? (%s:%s)\n", __LINE__, test_data, buf);
		goto done;
	}

	printf("Trying short read\n");
	io.lockread.in.offset = 1;
	io.lockread.in.count = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);
	smbcli_unlock(cli->tree, fnum, 0, strlen(test_data));
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_VALUE(io.lockread.out.nread, strlen(test_data)-1);
	if (memcmp(buf, test_data+1, strlen(test_data)-1) != 0) {
		ret = False;
		printf("incorrect data at %d!? (%s:%s)\n", __LINE__, test_data+1, buf);
		goto done;
	}

	printf("Trying max offset\n");
	io.lockread.in.offset = ~0;
	io.lockread.in.count = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.lockread.out.nread, 0);

	setup_buffer(buf, seed, maxsize);
	smbcli_write(cli->tree, fnum, 0, buf, 0, maxsize);
	memset(buf, 0, maxsize);

	printf("Trying large read\n");
	io.lockread.in.offset = 0;
	io.lockread.in.count = ~0;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);
	smbcli_unlock(cli->tree, fnum, 1, strlen(test_data));
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_BUFFER(buf, seed, io.lockread.out.nread);
	smbcli_unlock(cli->tree, fnum, 0, 0xFFFF);


	printf("Trying locked region\n");
	cli->session->pid++;
	if (NT_STATUS_IS_ERR(smbcli_lock(cli->tree, fnum, 103, 1, 0, WRITE_LOCK))) {
		printf("Failed to lock file at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	cli->session->pid--;
	memset(buf, 0, maxsize);
	io.lockread.in.offset = 0;
	io.lockread.in.count = ~0;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);
	

done:
	smbcli_close(cli->tree, fnum);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test readx ops
*/
static BOOL test_readx(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_read io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	uint8_t *buf;
	const int maxsize = 90000;
	const char *fname = BASEDIR "\\test.txt";
	const char *test_data = "TEST DATA";
	uint_t seed = time(NULL);

	buf = talloc_zero(mem_ctx, maxsize);

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	printf("Testing RAW_READ_READX\n");
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	printf("Trying empty file read\n");
	io.generic.level = RAW_READ_READX;
	io.readx.in.fnum = fnum;
	io.readx.in.mincnt = 1;
	io.readx.in.maxcnt = 1;
	io.readx.in.offset = 0;
	io.readx.in.remaining = 0;
	io.readx.out.data = buf;
	status = smb_raw_read(cli->tree, &io);

	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.nread, 0);
	CHECK_VALUE(io.readx.out.remaining, 0xFFFF);
	CHECK_VALUE(io.readx.out.compaction_mode, 0);

	printf("Trying zero file read\n");
	io.readx.in.mincnt = 0;
	io.readx.in.maxcnt = 0;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.nread, 0);
	CHECK_VALUE(io.readx.out.remaining, 0xFFFF);
	CHECK_VALUE(io.readx.out.compaction_mode, 0);

	printf("Trying bad fnum\n");
	io.readx.in.fnum = fnum+1;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);
	io.readx.in.fnum = fnum;

	smbcli_write(cli->tree, fnum, 0, test_data, 0, strlen(test_data));

	printf("Trying small read\n");
	io.readx.in.fnum = fnum;
	io.readx.in.offset = 0;
	io.readx.in.remaining = 0;
	io.readx.in.mincnt = strlen(test_data);
	io.readx.in.maxcnt = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.nread, strlen(test_data));
	CHECK_VALUE(io.readx.out.remaining, 0xFFFF);
	CHECK_VALUE(io.readx.out.compaction_mode, 0);
	if (memcmp(buf, test_data, strlen(test_data)) != 0) {
		ret = False;
		printf("incorrect data at %d!? (%s:%s)\n", __LINE__, test_data, buf);
		goto done;
	}

	printf("Trying short read\n");
	io.readx.in.offset = 1;
	io.readx.in.mincnt = strlen(test_data);
	io.readx.in.maxcnt = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.nread, strlen(test_data)-1);
	CHECK_VALUE(io.readx.out.remaining, 0xFFFF);
	CHECK_VALUE(io.readx.out.compaction_mode, 0);
	if (memcmp(buf, test_data+1, strlen(test_data)-1) != 0) {
		ret = False;
		printf("incorrect data at %d!? (%s:%s)\n", __LINE__, test_data+1, buf);
		goto done;
	}

	printf("Trying max offset\n");
	io.readx.in.offset = 0xffffffff;
	io.readx.in.mincnt = strlen(test_data);
	io.readx.in.maxcnt = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.nread, 0);
	CHECK_VALUE(io.readx.out.remaining, 0xFFFF);
	CHECK_VALUE(io.readx.out.compaction_mode, 0);

	setup_buffer(buf, seed, maxsize);
	smbcli_write(cli->tree, fnum, 0, buf, 0, maxsize);
	memset(buf, 0, maxsize);

	printf("Trying large read\n");
	io.readx.in.offset = 0;
	io.readx.in.mincnt = 0xFFFF;
	io.readx.in.maxcnt = 0xFFFF;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.remaining, 0xFFFF);
	CHECK_VALUE(io.readx.out.compaction_mode, 0);
	CHECK_VALUE(io.readx.out.nread, io.readx.in.maxcnt);
	CHECK_BUFFER(buf, seed, io.readx.out.nread);

	printf("Trying extra large read\n");
	io.readx.in.offset = 0;
	io.readx.in.mincnt = 100;
	io.readx.in.maxcnt = 80000;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.remaining, 0xFFFF);
	CHECK_VALUE(io.readx.out.compaction_mode, 0);
	CHECK_VALUE(io.readx.out.nread, 0);
	CHECK_BUFFER(buf, seed, io.readx.out.nread);

	printf("Trying mincnt > maxcnt\n");
	memset(buf, 0, maxsize);
	io.readx.in.offset = 0;
	io.readx.in.mincnt = 30000;
	io.readx.in.maxcnt = 20000;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.remaining, 0xFFFF);
	CHECK_VALUE(io.readx.out.compaction_mode, 0);
	CHECK_VALUE(io.readx.out.nread, io.readx.in.maxcnt);
	CHECK_BUFFER(buf, seed, io.readx.out.nread);

	printf("Trying mincnt < maxcnt\n");
	memset(buf, 0, maxsize);
	io.readx.in.offset = 0;
	io.readx.in.mincnt = 20000;
	io.readx.in.maxcnt = 30000;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.remaining, 0xFFFF);
	CHECK_VALUE(io.readx.out.compaction_mode, 0);
	CHECK_VALUE(io.readx.out.nread, io.readx.in.maxcnt);
	CHECK_BUFFER(buf, seed, io.readx.out.nread);

	printf("Trying locked region\n");
	cli->session->pid++;
	if (NT_STATUS_IS_ERR(smbcli_lock(cli->tree, fnum, 103, 1, 0, WRITE_LOCK))) {
		printf("Failed to lock file at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	cli->session->pid--;
	memset(buf, 0, maxsize);
	io.readx.in.offset = 0;
	io.readx.in.mincnt = 100;
	io.readx.in.maxcnt = 200;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);	

	printf("Trying large offset read\n");
	io.readx.in.offset = ((uint64_t)0x2) << 32;
	io.readx.in.mincnt = 10;
	io.readx.in.maxcnt = 10;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.nread, 0);

	if (NT_STATUS_IS_ERR(smbcli_lock64(cli->tree, fnum, io.readx.in.offset, 1, 0, WRITE_LOCK))) {
		printf("Failed to lock file at %d\n", __LINE__);
		ret = False;
		goto done;
	}

	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readx.out.nread, 0);

done:
	smbcli_close(cli->tree, fnum);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test readbraw ops
*/
static BOOL test_readbraw(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_read io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	uint8_t *buf;
	const int maxsize = 90000;
	const char *fname = BASEDIR "\\test.txt";
	const char *test_data = "TEST DATA";
	uint_t seed = time(NULL);

	buf = talloc_zero(mem_ctx, maxsize);

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	printf("Testing RAW_READ_READBRAW\n");
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	printf("Trying empty file read\n");
	io.generic.level = RAW_READ_READBRAW;
	io.readbraw.in.fnum = fnum;
	io.readbraw.in.mincnt = 1;
	io.readbraw.in.maxcnt = 1;
	io.readbraw.in.offset = 0;
	io.readbraw.in.timeout = 0;
	io.readbraw.out.data = buf;
	status = smb_raw_read(cli->tree, &io);

	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, 0);

	printf("Trying zero file read\n");
	io.readbraw.in.mincnt = 0;
	io.readbraw.in.maxcnt = 0;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, 0);

	printf("Trying bad fnum\n");
	io.readbraw.in.fnum = fnum+1;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, 0);
	io.readbraw.in.fnum = fnum;

	smbcli_write(cli->tree, fnum, 0, test_data, 0, strlen(test_data));

	printf("Trying small read\n");
	io.readbraw.in.fnum = fnum;
	io.readbraw.in.offset = 0;
	io.readbraw.in.mincnt = strlen(test_data);
	io.readbraw.in.maxcnt = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, strlen(test_data));
	if (memcmp(buf, test_data, strlen(test_data)) != 0) {
		ret = False;
		printf("incorrect data at %d!? (%s:%s)\n", __LINE__, test_data, buf);
		goto done;
	}

	printf("Trying short read\n");
	io.readbraw.in.offset = 1;
	io.readbraw.in.mincnt = strlen(test_data);
	io.readbraw.in.maxcnt = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, strlen(test_data)-1);
	if (memcmp(buf, test_data+1, strlen(test_data)-1) != 0) {
		ret = False;
		printf("incorrect data at %d!? (%s:%s)\n", __LINE__, test_data+1, buf);
		goto done;
	}

	printf("Trying max offset\n");
	io.readbraw.in.offset = ~0;
	io.readbraw.in.mincnt = strlen(test_data);
	io.readbraw.in.maxcnt = strlen(test_data);
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, 0);

	setup_buffer(buf, seed, maxsize);
	smbcli_write(cli->tree, fnum, 0, buf, 0, maxsize);
	memset(buf, 0, maxsize);

	printf("Trying large read\n");
	io.readbraw.in.offset = 0;
	io.readbraw.in.mincnt = ~0;
	io.readbraw.in.maxcnt = ~0;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, 0xFFFF);
	CHECK_BUFFER(buf, seed, io.readbraw.out.nread);

	printf("Trying mincnt > maxcnt\n");
	memset(buf, 0, maxsize);
	io.readbraw.in.offset = 0;
	io.readbraw.in.mincnt = 30000;
	io.readbraw.in.maxcnt = 20000;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, io.readbraw.in.maxcnt);
	CHECK_BUFFER(buf, seed, io.readbraw.out.nread);

	printf("Trying mincnt < maxcnt\n");
	memset(buf, 0, maxsize);
	io.readbraw.in.offset = 0;
	io.readbraw.in.mincnt = 20000;
	io.readbraw.in.maxcnt = 30000;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, io.readbraw.in.maxcnt);
	CHECK_BUFFER(buf, seed, io.readbraw.out.nread);

	printf("Trying locked region\n");
	cli->session->pid++;
	if (NT_STATUS_IS_ERR(smbcli_lock(cli->tree, fnum, 103, 1, 0, WRITE_LOCK))) {
		printf("Failed to lock file at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	cli->session->pid--;
	memset(buf, 0, maxsize);
	io.readbraw.in.offset = 0;
	io.readbraw.in.mincnt = 100;
	io.readbraw.in.maxcnt = 200;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, 0);

	printf("Trying locked region with timeout\n");
	memset(buf, 0, maxsize);
	io.readbraw.in.offset = 0;
	io.readbraw.in.mincnt = 100;
	io.readbraw.in.maxcnt = 200;
	io.readbraw.in.timeout = 10000;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, 0);

	printf("Trying large offset read\n");
	io.readbraw.in.offset = ((uint64_t)0x2) << 32;
	io.readbraw.in.mincnt = 10;
	io.readbraw.in.maxcnt = 10;
	io.readbraw.in.timeout = 0;
	status = smb_raw_read(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.readbraw.out.nread, 0);

done:
	smbcli_close(cli->tree, fnum);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/* 
   basic testing of read calls
*/
BOOL torture_raw_read(void)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_read");

	if (!test_read(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_readx(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_lockread(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_readbraw(cli, mem_ctx)) {
		ret = False;
	}

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
