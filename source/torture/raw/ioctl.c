/* 
   Unix SMB/CIFS implementation.
   ioctl individual test suite
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   
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

#define BASEDIR "\\rawioctl"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


/* test some ioctls */
static BOOL test_ioctl(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_ioctl ctl;
	int fnum;
	NTSTATUS status;
	BOOL ret = True;
	const char *fname = BASEDIR "\\test.dat";

	printf("TESTING IOCTL FUNCTIONS\n");

	fnum = create_complex_file(cli, mem_ctx, fname);
	if (fnum == -1) {
		printf("Failed to create test.dat - %s\n", smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

 	printf("Trying QUERY_JOB_INFO\n");
 	ctl.ioctl.level = RAW_IOCTL_IOCTL;
	ctl.ioctl.in.fnum = fnum;
	ctl.ioctl.in.request = IOCTL_QUERY_JOB_INFO;

	status = smb_raw_ioctl(cli->tree, mem_ctx, &ctl);
	CHECK_STATUS(status, NT_STATUS_UNSUCCESSFUL);

 	printf("Trying bad handle\n");
	ctl.ioctl.in.fnum = fnum+1;
	status = smb_raw_ioctl(cli->tree, mem_ctx, &ctl);
	CHECK_STATUS(status, NT_STATUS_UNSUCCESSFUL);

done:
	smbcli_close(cli->tree, fnum);
	return ret;
}

/* test some filesystem control functions */
static BOOL test_fsctl(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	int fnum;
	NTSTATUS status;
	BOOL ret = True;
	const char *fname = BASEDIR "\\test.dat";
	union smb_ioctl nt;

	printf("\nTESTING FSCTL FUNCTIONS\n");

	fnum = create_complex_file(cli, mem_ctx, fname);
	if (fnum == -1) {
		printf("Failed to create test.dat - %s\n", smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	printf("trying sparse file\n");
	nt.ioctl.level = RAW_IOCTL_NTIOCTL;
	nt.ntioctl.in.function = FSCTL_SET_SPARSE;
	nt.ntioctl.in.fnum = fnum;
	nt.ntioctl.in.fsctl = True;
	nt.ntioctl.in.filter = 0;

	status = smb_raw_ioctl(cli->tree, mem_ctx, &nt);
	CHECK_STATUS(status, NT_STATUS_OK);

 	printf("Trying bad handle\n");
	nt.ntioctl.in.fnum = fnum+1;
	status = smb_raw_ioctl(cli->tree, mem_ctx, &nt);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

#if 0
	nt.ntioctl.in.fnum = fnum;
	for (i=0;i<100;i++) {
		nt.ntioctl.in.function = FSCTL_FILESYSTEM + (i<<2);
		status = smb_raw_ioctl(cli->tree, mem_ctx, &nt);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			printf("filesystem fsctl 0x%x - %s\n",
			       i, nt_errstr(status));
		}
	}
#endif

done:
	smbcli_close(cli->tree, fnum);
	return ret;
}

/* 
   basic testing of some ioctl calls 
*/
BOOL torture_raw_ioctl(int dummy)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_ioctl");

	if (smbcli_deltree(cli->tree, BASEDIR) == -1) {
		printf("Failed to clean " BASEDIR "\n");
		return False;
	}
	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR))) {
		printf("Failed to create " BASEDIR " - %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (!test_ioctl(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_fsctl(cli, mem_ctx)) {
		ret = False;
	}

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}
