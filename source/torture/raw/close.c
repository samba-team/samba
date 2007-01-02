/* 
   Unix SMB/CIFS implementation.
   RAW_CLOSE_* individual test suite
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
#include "torture/torture.h"
#include "system/time.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "torture/util.h"


/* basic testing of all RAW_CLOSE_* calls 
*/
BOOL torture_raw_close(struct torture_context *torture)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;
	union smb_close io;
	union smb_flush io_flush;
	int fnum;
	const char *fname = "\\torture_close.txt";
	time_t basetime = (time(NULL) + 3*86400) & ~1;
	union smb_fileinfo finfo, finfo2;
	NTSTATUS status;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_close");

#define REOPEN do { \
	fnum = create_complex_file(cli, mem_ctx, fname); \
	if (fnum == -1) { \
		printf("(%d) Failed to create %s\n", __LINE__, fname); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

	REOPEN;

	io.close.level = RAW_CLOSE_CLOSE;
	io.close.in.file.fnum = fnum;
	io.close.in.write_time = basetime;
	status = smb_raw_close(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb_raw_close(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);
	
	printf("testing close.in.write_time\n");

	/* the file should have the write time set */
	finfo.generic.level = RAW_FILEINFO_ALL_INFO;
	finfo.generic.in.file.path = fname;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (basetime != nt_time_to_unix(finfo.all_info.out.write_time)) {
		printf("Incorrect write time on file - %s - %s\n",
		       timestring(mem_ctx, basetime), 
		       nt_time_string(mem_ctx, finfo.all_info.out.write_time));
		dump_all_info(mem_ctx, &finfo);
		ret = False;
	}

	printf("testing other times\n");

	/* none of the other times should be set to that time */
	if (nt_time_equal(&finfo.all_info.out.write_time, 
			  &finfo.all_info.out.access_time) ||
	    nt_time_equal(&finfo.all_info.out.write_time, 
			  &finfo.all_info.out.create_time) ||
	    nt_time_equal(&finfo.all_info.out.write_time, 
			  &finfo.all_info.out.change_time)) {
		printf("Incorrect times after close - only write time should be set\n");
		dump_all_info(mem_ctx, &finfo);

		if (!lp_parm_bool(-1, "torture", "samba3", False)) {
			/*
			 * In Samba3 as of 3.0.23d we don't yet support all
			 * file times, so don't mark this as a critical
			 * failure
			 */
			ret = False;
		}
	}
	    

	smbcli_unlink(cli->tree, fname);
	REOPEN;

	finfo2.generic.level = RAW_FILEINFO_ALL_INFO;
	finfo2.generic.in.file.path = fname;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo2);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.close.level = RAW_CLOSE_CLOSE;
	io.close.in.file.fnum = fnum;
	io.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* the file should have the write time set equal to access time */
	finfo.generic.level = RAW_FILEINFO_ALL_INFO;
	finfo.generic.in.file.path = fname;
	status = smb_raw_pathinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (!nt_time_equal(&finfo.all_info.out.write_time, 
			   &finfo2.all_info.out.write_time)) {
		printf("Incorrect write time on file - 0 time should be ignored\n");
		dump_all_info(mem_ctx, &finfo);
		ret = False;
	}

	printf("testing splclose\n");

	/* check splclose on a file */
	REOPEN;
	io.splclose.level = RAW_CLOSE_SPLCLOSE;
	io.splclose.in.file.fnum = fnum;
	status = smb_raw_close(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRSRV, ERRerror));

	printf("testing flush\n");
	smbcli_close(cli->tree, fnum);

	io_flush.flush.level		= RAW_FLUSH_FLUSH;
	io_flush.flush.in.file.fnum	= fnum;
	status = smb_raw_flush(cli->tree, &io_flush);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	io_flush.flush_all.level	= RAW_FLUSH_ALL;
	status = smb_raw_flush(cli->tree, &io_flush);
	CHECK_STATUS(status, NT_STATUS_OK);

	REOPEN;

	io_flush.flush.level		= RAW_FLUSH_FLUSH;
	io_flush.flush.in.file.fnum	= fnum;
	status = smb_raw_flush(cli->tree, &io_flush);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Testing SMBexit\n");
	smb_raw_exit(cli->session);

	io_flush.flush.level		= RAW_FLUSH_FLUSH;
	io_flush.flush.in.file.fnum	= fnum;
	status = smb_raw_flush(cli->tree, &io_flush);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);
	

done:
	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);
	torture_close_connection(cli);
	talloc_free(mem_ctx);
	return ret;
}
