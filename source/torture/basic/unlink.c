/* 
   Unix SMB/CIFS implementation.

   unlink tester

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
#include "librpc/gen_ndr/ndr_security.h"

/*
  This test checks that 

  1) the server does not allow an unlink on a file that is open
*/
BOOL torture_unlinktest(void)
{
	struct smbcli_state *cli;
	const char *fname = "\\unlink.tst";
	int fnum;
	BOOL correct = True;
	union smb_open io;
	NTSTATUS status;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	printf("starting unlink test\n");

	smbcli_unlink(cli->tree, fname);

	cli->session->pid = 1;

	printf("Opening a file\n");

	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		printf("open of %s failed (%s)\n", fname, smbcli_errstr(cli->tree));
		return False;
	}

	printf("Unlinking a open file\n");

	if (NT_STATUS_IS_OK(smbcli_unlink(cli->tree, fname))) {
		printf("(%s) error: server allowed unlink on an open file\n", __location__);
		correct = False;
	} else {
		correct = check_error(__location__, cli, ERRDOS, ERRbadshare, 
				      NT_STATUS_SHARING_VIOLATION);
	}

	smbcli_close(cli->tree, fnum);
	smbcli_unlink(cli->tree, fname);

	printf("testing unlink after ntcreatex with DELETE access\n");

	io.ntcreatex.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED;
	io.ntcreatex.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.ntcreatex.in.file_attr = 0;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_IMPERSONATION;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_DELETE;
	io.ntcreatex.in.access_mask  = SEC_RIGHTS_FILE_ALL;

	status = smb_raw_open(cli->tree, cli, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("(%s) failed to open %s\n", __location__, fname);
	}
	if (NT_STATUS_IS_OK(smbcli_unlink(cli->tree, fname))) {
		printf("(%s) error: server allowed unlink on an open file\n", __location__);
		correct = False;
	} else {
		correct = check_error(__location__, cli, ERRDOS, ERRbadshare, 
				      NT_STATUS_SHARING_VIOLATION);
	}

	if (!torture_close_connection(cli)) {
		correct = False;
	}

	printf("unlink test finished\n");
	
	return correct;
}


