/* 
   Unix SMB/CIFS implementation.

   rename testing

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

/*
  Test rename on files open with share delete and no share delete.
 */
BOOL torture_test_rename(void)
{
	struct smbcli_state *cli1;
	const char *fname = "\\test.txt";
	const char *fname1 = "\\test1.txt";
	BOOL correct = True;
	int fnum1;

	printf("starting rename test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	
	smbcli_unlink(cli1->tree, fname);
	smbcli_unlink(cli1->tree, fname1);
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      GENERIC_RIGHTS_FILE_READ, 
				      FILE_ATTRIBUTE_NORMAL,
				      NTCREATEX_SHARE_ACCESS_READ, 
				      NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("(%s) First open failed - %s\n", 
		       __location__, smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_rename(cli1->tree, fname, fname1))) {
		printf("First rename failed (this is correct) - %s\n", smbcli_errstr(cli1->tree));
	} else {
		printf("(%s) First rename succeeded - this should have failed !\n",
		       __location__);
		correct = False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close - 1 failed (%s)\n", __location__, smbcli_errstr(cli1->tree));
		return False;
	}

	smbcli_unlink(cli1->tree, fname);
	smbcli_unlink(cli1->tree, fname1);
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      GENERIC_RIGHTS_FILE_READ, 
				      FILE_ATTRIBUTE_NORMAL,
				      NTCREATEX_SHARE_ACCESS_DELETE|NTCREATEX_SHARE_ACCESS_READ, 
				      NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("(%s) Second open failed - %s\n", __location__, smbcli_errstr(cli1->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_rename(cli1->tree, fname, fname1))) {
		printf("(%s) Second rename failed - this should have succeeded - %s\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
	} else {
		printf("Second rename succeeded\n");
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close - 2 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		return False;
	}

	smbcli_unlink(cli1->tree, fname);
	smbcli_unlink(cli1->tree, fname1);

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      STD_RIGHT_READ_CONTROL_ACCESS, 
				      FILE_ATTRIBUTE_NORMAL,
				      NTCREATEX_SHARE_ACCESS_NONE, 
				      NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("(%s) Third open failed - %s\n", __location__, smbcli_errstr(cli1->tree));
		return False;
	}


	if (NT_STATUS_IS_ERR(smbcli_rename(cli1->tree, fname, fname1))) {
		printf("(%s) Third rename failed - this should have succeeded - %s\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
	} else {
		printf("Third rename succeeded\n");
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close - 3 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		return False;
	}

	smbcli_unlink(cli1->tree, fname);
	smbcli_unlink(cli1->tree, fname1);

	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	
	return correct;
}

