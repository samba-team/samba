/* 
   Unix SMB/CIFS implementation.
   test suite for various write operations
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

#define CHECK_BUFFER(buf, seed, len) do { \
	if (!check_buffer(buf, seed, len, __LINE__)) { \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_ALL_INFO(v, field) do { \
	finfo.all_info.level = RAW_FILEINFO_ALL_INFO; \
	finfo.all_info.in.fname = fname; \
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	if ((v) != finfo.all_info.out.field) { \
		printf("(%d) wrong value for field %s  %.0f - %.0f\n", \
		       __LINE__, #field, (double)v, (double)finfo.all_info.out.field); \
		dump_all_info(mem_ctx, &finfo); \
		ret = False; \
	}} while (0)


#define BASEDIR "\\testwrite"


/*
  setup a random buffer based on a seed
*/
static void setup_buffer(char *buf, uint_t seed, int len)
{
	int i;
	srandom(seed);
	for (i=0;i<len;i++) buf[i] = random();
}

/*
  check a random buffer based on a seed
*/
static BOOL check_buffer(char *buf, uint_t seed, int len, int line)
{
	int i;
	srandom(seed);
	for (i=0;i<len;i++) {
		char v = random();
		if (buf[i] != v) {
			printf("Buffer incorrect at line %d! ofs=%d buf=0x%x correct=0x%x\n", 
			       line, i, buf[i], v);
			return False;
		}
	}
	return True;
}

/*
  test write ops
*/
static BOOL test_write(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_write io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	char *buf;
	const int maxsize = 90000;
	const char *fname = BASEDIR "\\test.txt";
	uint_t seed = time(NULL);
	union smb_fileinfo finfo;

	buf = talloc_zero(mem_ctx, maxsize);

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 ||
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Unable to setup %s - %s\n", BASEDIR, smbcli_errstr(cli->tree));
		return False;
	}

	printf("Testing RAW_WRITE_WRITE\n");
	io.generic.level = RAW_WRITE_WRITE;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	printf("Trying zero write\n");
	io.write.in.fnum = fnum;
	io.write.in.count = 0;
	io.write.in.offset = 0;
	io.write.in.remaining = 0;
	io.write.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.write.out.nwritten, 0);

	setup_buffer(buf, seed, maxsize);

	printf("Trying small write\n");
	io.write.in.count = 9;
	io.write.in.offset = 4;
	io.write.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.write.out.nwritten, io.write.in.count);

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, 0, 13) != 13) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf+4, seed, 9);
	CHECK_VALUE(IVAL(buf,0), 0);

	setup_buffer(buf, seed, maxsize);

	printf("Trying large write\n");
	io.write.in.count = 4000;
	io.write.in.offset = 0;
	io.write.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.write.out.nwritten, 4000);

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, 0, 4000) != 4000) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf, seed, 4000);

	printf("Trying bad fnum\n");
	io.write.in.fnum = fnum+1;
	io.write.in.count = 4000;
	io.write.in.offset = 0;
	io.write.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	printf("Setting file as sparse\n");
	status = torture_set_sparse(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	printf("Trying 2^32 offset\n");
	setup_buffer(buf, seed, maxsize);
	io.write.in.fnum = fnum;
	io.write.in.count = 4000;
	io.write.in.offset = 0xFFFFFFFF - 2000;
	io.write.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.write.out.nwritten, 4000);
	CHECK_ALL_INFO(io.write.in.count + (uint64_t)io.write.in.offset, size);

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, io.write.in.offset, 4000) != 4000) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf, seed, 4000);

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test writex ops
*/
static BOOL test_writex(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_write io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum, i;
	char *buf;
	const int maxsize = 90000;
	const char *fname = BASEDIR "\\test.txt";
	uint_t seed = time(NULL);
	union smb_fileinfo finfo;

	buf = talloc_zero(mem_ctx, maxsize);

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 ||
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Unable to setup %s - %s\n", BASEDIR, smbcli_errstr(cli->tree));
		return False;
	}

	printf("Testing RAW_WRITE_WRITEX\n");
	io.generic.level = RAW_WRITE_WRITEX;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	printf("Trying zero write\n");
	io.writex.in.fnum = fnum;
	io.writex.in.offset = 0;
	io.writex.in.wmode = 0;
	io.writex.in.remaining = 0;
	io.writex.in.count = 0;
	io.writex.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writex.out.nwritten, 0);

	setup_buffer(buf, seed, maxsize);

	printf("Trying small write\n");
	io.writex.in.count = 9;
	io.writex.in.offset = 4;
	io.writex.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writex.out.nwritten, io.writex.in.count);

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, 0, 13) != 13) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf+4, seed, 9);
	CHECK_VALUE(IVAL(buf,0), 0);

	setup_buffer(buf, seed, maxsize);

	printf("Trying large write\n");
	io.writex.in.count = 4000;
	io.writex.in.offset = 0;
	io.writex.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writex.out.nwritten, 4000);

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, 0, 4000) != 4000) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf, seed, 4000);

	printf("Trying bad fnum\n");
	io.writex.in.fnum = fnum+1;
	io.writex.in.count = 4000;
	io.writex.in.offset = 0;
	io.writex.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	printf("Testing wmode\n");
	io.writex.in.fnum = fnum;
	io.writex.in.count = 1;
	io.writex.in.offset = 0;
	io.writex.in.wmode = 1;
	io.writex.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writex.out.nwritten, io.writex.in.count);

	io.writex.in.wmode = 2;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writex.out.nwritten, io.writex.in.count);


	printf("Trying locked region\n");
	cli->session->pid++;
	if (NT_STATUS_IS_ERR(smbcli_lock(cli->tree, fnum, 3, 1, 0, WRITE_LOCK))) {
		printf("Failed to lock file at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	cli->session->pid--;
	io.writex.in.wmode = 0;
	io.writex.in.count = 4;
	io.writex.in.offset = 0;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	printf("Setting file as sparse\n");
	status = torture_set_sparse(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	printf("Trying 2^32 offset\n");
	setup_buffer(buf, seed, maxsize);
	io.writex.in.fnum = fnum;
	io.writex.in.count = 4000;
	io.writex.in.offset = 0xFFFFFFFF - 2000;
	io.writex.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writex.out.nwritten, 4000);
	CHECK_ALL_INFO(io.writex.in.count + (uint64_t)io.writex.in.offset, size);

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, io.writex.in.offset, 4000) != 4000) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf, seed, 4000);

	for (i=33;i<64;i++) {
		printf("Trying 2^%d offset\n", i);
		setup_buffer(buf, seed+1, maxsize);
		io.writex.in.fnum = fnum;
		io.writex.in.count = 4000;
		io.writex.in.offset = ((uint64_t)1) << i;
		io.writex.in.data = buf;
		status = smb_raw_write(cli->tree, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_VALUE(io.writex.out.nwritten, 4000);
		CHECK_ALL_INFO(io.writex.in.count + (uint64_t)io.writex.in.offset, size);

		memset(buf, 0, maxsize);
		if (smbcli_read(cli->tree, fnum, buf, io.writex.in.offset, 4000) != 4000) {
			printf("read failed at %d\n", __LINE__);
			ret = False;
			goto done;
		}
		CHECK_BUFFER(buf, seed+1, 4000);
	}


	setup_buffer(buf, seed, maxsize);

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test write unlock ops
*/
static BOOL test_writeunlock(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_write io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	char *buf;
	const int maxsize = 90000;
	const char *fname = BASEDIR "\\test.txt";
	uint_t seed = time(NULL);
	union smb_fileinfo finfo;

	buf = talloc_zero(mem_ctx, maxsize);

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 ||
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Unable to setup %s - %s\n", BASEDIR, smbcli_errstr(cli->tree));
		return False;
	}

	printf("Testing RAW_WRITE_WRITEUNLOCK\n");
	io.generic.level = RAW_WRITE_WRITEUNLOCK;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	printf("Trying zero write\n");
	io.writeunlock.in.fnum = fnum;
	io.writeunlock.in.count = 0;
	io.writeunlock.in.offset = 0;
	io.writeunlock.in.remaining = 0;
	io.writeunlock.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writeunlock.out.nwritten, io.writeunlock.in.count);

	setup_buffer(buf, seed, maxsize);

	printf("Trying small write\n");
	io.writeunlock.in.count = 9;
	io.writeunlock.in.offset = 4;
	io.writeunlock.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);
	if (smbcli_read(cli->tree, fnum, buf, 0, 13) != 13) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf+4, seed, 9);
	CHECK_VALUE(IVAL(buf,0), 0);

	setup_buffer(buf, seed, maxsize);
	smbcli_lock(cli->tree, fnum, io.writeunlock.in.offset, io.writeunlock.in.count, 
		 0, WRITE_LOCK);
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writeunlock.out.nwritten, io.writeunlock.in.count);

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, 0, 13) != 13) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf+4, seed, 9);
	CHECK_VALUE(IVAL(buf,0), 0);

	setup_buffer(buf, seed, maxsize);

	printf("Trying large write\n");
	io.writeunlock.in.count = 4000;
	io.writeunlock.in.offset = 0;
	io.writeunlock.in.data = buf;
	smbcli_lock(cli->tree, fnum, io.writeunlock.in.offset, io.writeunlock.in.count, 
		 0, WRITE_LOCK);
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writeunlock.out.nwritten, 4000);

	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, 0, 4000) != 4000) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf, seed, 4000);

	printf("Trying bad fnum\n");
	io.writeunlock.in.fnum = fnum+1;
	io.writeunlock.in.count = 4000;
	io.writeunlock.in.offset = 0;
	io.writeunlock.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	printf("Setting file as sparse\n");
	status = torture_set_sparse(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	printf("Trying 2^32 offset\n");
	setup_buffer(buf, seed, maxsize);
	io.writeunlock.in.fnum = fnum;
	io.writeunlock.in.count = 4000;
	io.writeunlock.in.offset = 0xFFFFFFFF - 2000;
	io.writeunlock.in.data = buf;
	smbcli_lock(cli->tree, fnum, io.writeunlock.in.offset, io.writeunlock.in.count, 
		 0, WRITE_LOCK);
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writeunlock.out.nwritten, 4000);
	CHECK_ALL_INFO(io.writeunlock.in.count + (uint64_t)io.writeunlock.in.offset, size);

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, io.writeunlock.in.offset, 4000) != 4000) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf, seed, 4000);

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}


/*
  test write close ops
*/
static BOOL test_writeclose(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_write io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum;
	char *buf;
	const int maxsize = 90000;
	const char *fname = BASEDIR "\\test.txt";
	uint_t seed = time(NULL);
	union smb_fileinfo finfo;

	buf = talloc_zero(mem_ctx, maxsize);

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 ||
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Unable to setup %s - %s\n", BASEDIR, smbcli_errstr(cli->tree));
		return False;
	}

	printf("Testing RAW_WRITE_WRITECLOSE\n");
	io.generic.level = RAW_WRITE_WRITECLOSE;
	
	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		printf("Failed to create %s - %s\n", fname, smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	printf("Trying zero write\n");
	io.writeclose.in.fnum = fnum;
	io.writeclose.in.count = 0;
	io.writeclose.in.offset = 0;
	io.writeclose.in.mtime = 0;
	io.writeclose.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writeclose.out.nwritten, io.writeclose.in.count);

	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writeclose.out.nwritten, io.writeclose.in.count);

	setup_buffer(buf, seed, maxsize);

	printf("Trying small write\n");
	io.writeclose.in.count = 9;
	io.writeclose.in.offset = 4;
	io.writeclose.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	fnum = smbcli_open(cli->tree, fname, O_RDWR, DENY_NONE);
	io.writeclose.in.fnum = fnum;

	if (smbcli_read(cli->tree, fnum, buf, 0, 13) != 13) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf+4, seed, 9);
	CHECK_VALUE(IVAL(buf,0), 0);

	setup_buffer(buf, seed, maxsize);
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writeclose.out.nwritten, io.writeclose.in.count);

	fnum = smbcli_open(cli->tree, fname, O_RDWR, DENY_NONE);
	io.writeclose.in.fnum = fnum;

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, 0, 13) != 13) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf+4, seed, 9);
	CHECK_VALUE(IVAL(buf,0), 0);

	setup_buffer(buf, seed, maxsize);

	printf("Trying large write\n");
	io.writeclose.in.count = 4000;
	io.writeclose.in.offset = 0;
	io.writeclose.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writeclose.out.nwritten, 4000);

	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	fnum = smbcli_open(cli->tree, fname, O_RDWR, DENY_NONE);
	io.writeclose.in.fnum = fnum;

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, 0, 4000) != 4000) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf, seed, 4000);

	printf("Trying bad fnum\n");
	io.writeclose.in.fnum = fnum+1;
	io.writeclose.in.count = 4000;
	io.writeclose.in.offset = 0;
	io.writeclose.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	printf("Setting file as sparse\n");
	status = torture_set_sparse(cli->tree, fnum);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	printf("Trying 2^32 offset\n");
	setup_buffer(buf, seed, maxsize);
	io.writeclose.in.fnum = fnum;
	io.writeclose.in.count = 4000;
	io.writeclose.in.offset = 0xFFFFFFFF - 2000;
	io.writeclose.in.data = buf;
	status = smb_raw_write(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(io.writeclose.out.nwritten, 4000);
	CHECK_ALL_INFO(io.writeclose.in.count + (uint64_t)io.writeclose.in.offset, size);

	fnum = smbcli_open(cli->tree, fname, O_RDWR, DENY_NONE);
	io.writeclose.in.fnum = fnum;

	memset(buf, 0, maxsize);
	if (smbcli_read(cli->tree, fnum, buf, io.writeclose.in.offset, 4000) != 4000) {
		printf("read failed at %d\n", __LINE__);
		ret = False;
		goto done;
	}
	CHECK_BUFFER(buf, seed, 4000);

done:
	smbcli_close(cli->tree, fnum);
	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);
	return ret;
}

static BOOL test_delayed_write_update(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_fileinfo finfo1, finfo2;
	const char *fname = BASEDIR "\\torture_file.txt";
	NTSTATUS status;
	int fnum1 = -1;
	BOOL ret = True;
	ssize_t written;
	time_t t;

	printf("Testing delayed update of write time\n");

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 ||
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Unable to setup %s - %s\n", BASEDIR, smbcli_errstr(cli->tree));
		return False;
	}

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		printf("Failed to open %s\n", fname);
		return False;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.fnum = fnum1;
	finfo2 = finfo1;

	status = smb_raw_fileinfo(cli->tree, mem_ctx, &finfo1);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		return False;
	}
	
	printf("Initial write time %s\n", 
	       nt_time_string(mem_ctx, finfo1.basic_info.out.write_time));

	/* 3 second delay to ensure we get past any 2 second time
	   granularity (older systems may have that) */
	sleep(3);

	written =  smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);

	if (written != 1) {
		printf("write failed - wrote %d bytes\n", written);
		return False;
	}

	t = time(NULL);

	while (time(NULL) < t+120) {
		status = smb_raw_fileinfo(cli->tree, mem_ctx, &finfo2);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
			ret = False;
			break;
		}
		printf("write time %s\n", 
		       nt_time_string(mem_ctx, finfo2.basic_info.out.write_time));
		if (finfo1.basic_info.out.write_time != finfo2.basic_info.out.write_time) {
			printf("Server updated write_time after %d seconds\n",
			       (int)(time(NULL) - t));
			break;
		}
		sleep(1);
		fflush(stdout);
	}
	
	if (finfo1.basic_info.out.write_time == finfo2.basic_info.out.write_time) {
		printf("Server did not update write time?!\n");
		ret = False;
	}


	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}


/* Windows does obviously not update the stat info during a write call. I
 * *think* this is the problem causing a spurious Excel 2003 on XP error
 * message when saving a file. Excel does a setfileinfo, writes, and then does
 * a getpath(!)info. Or so... For Samba sometimes it displays an error message
 * that the file might have been changed in between. What i've been able to
 * trace down is that this happens if the getpathinfo after the write shows a
 * different last write time than the setfileinfo showed. This is really
 * nasty....
 */

static BOOL test_finfo_after_write(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_fileinfo finfo1, finfo2;
	const char *fname = BASEDIR "\\torture_file.txt";
	NTSTATUS status;
	int fnum1 = -1;
	BOOL ret = True;
	ssize_t written;

	printf("Testing finfo update on close\n");

	if (smbcli_deltree(cli->tree, BASEDIR) == -1 ||
	    NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Unable to setup %s - %s\n", BASEDIR, smbcli_errstr(cli->tree));
		return False;
	}

	fnum1 = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		ret = False;
		goto done;
	}

	finfo1.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo1.basic_info.in.fnum = fnum1;

	status = smb_raw_fileinfo(cli->tree, mem_ctx, &finfo1);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		ret = False;
		goto done;
	}

	msleep(1000);

	written =  smbcli_write(cli->tree, fnum1, 0, "x", 0, 1);

	if (written != 1) {
		ret = False;
		goto done;
	}

	{
		struct smbcli_state *cli2;
		int fnum2;

		if (!torture_open_connection(&cli2)) {
			return False;
		}

		fnum2 = smbcli_open(cli2->tree, fname, O_RDWR, DENY_NONE);
		if (fnum2 == -1) {
			ret = False;
			goto done;
		}

		written =  smbcli_write(cli2->tree, fnum2, 0, "x", 0, 1);

		if (written != 1) {
			ret = False;
			goto done;
		}

		finfo2.basic_info.level = RAW_FILEINFO_BASIC_INFO;
		finfo2.basic_info.in.fname = fname;

		status = smb_raw_pathinfo(cli2->tree, mem_ctx, &finfo2);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
			ret = False;
			goto done;
		}

		if (finfo1.basic_info.out.create_time !=
		    finfo2.basic_info.out.create_time) {
			ret = False;
			goto done;
		}
		
		if (finfo1.basic_info.out.access_time !=
		    finfo2.basic_info.out.access_time) {
			ret = False;
			goto done;
		}
		
		if (finfo1.basic_info.out.write_time !=
		    finfo2.basic_info.out.write_time) {
			ret = False;
			goto done;
		}
		
		if (finfo1.basic_info.out.change_time !=
		    finfo2.basic_info.out.change_time) {
			ret = False;
			goto done;
		}

		/* One of the two following calls updates the qpathinfo. */

		/* If you had skipped the smbcli_write on fnum2, it would
		 * *not* have updated the stat on disk */

		smbcli_close(cli2->tree, fnum2);
		torture_close_connection(cli2);
	}

	/* This call is only for the people looking at ethereal :-) */

	finfo2.basic_info.level = RAW_FILEINFO_BASIC_INFO;
	finfo2.basic_info.in.fname = fname;

	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo2);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("fileinfo failed: %s\n", nt_errstr(status)));
		ret = False;
		goto done;
	}

 done:
	if (fnum1 != -1)
		smbcli_close(cli->tree, fnum1);
	smbcli_unlink(cli->tree, fname);
	smbcli_deltree(cli->tree, BASEDIR);

	return ret;
}

/* 
   basic testing of write calls
*/
BOOL torture_raw_write(int dummy)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_write");

	if (!test_finfo_after_write(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_delayed_write_update(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_write(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_writeunlock(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_writeclose(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_writex(cli, mem_ctx)) {
		ret = False;
	}

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
