/* 
   Unix SMB/CIFS implementation.

   delete on close testing

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
  Test delete on close semantics.
 */
BOOL torture_test_delete(void)
{
	struct smbcli_state *cli1;
	struct smbcli_state *cli2 = NULL;
	const char *fname = "\\delete.file";
	int fnum1 = -1;
	int fnum2 = -1;
	BOOL correct = True;
	NTSTATUS status;
	
	printf("starting delete test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}

	/* Test 1 - this should delete the file on close. */
	
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
				   NTCREATEX_SHARE_ACCESS_DELETE, NTCREATEX_DISP_OVERWRITE_IF, 
				   NTCREATEX_OPTIONS_DELETE_ON_CLOSE, 0);
	
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR, DENY_NONE);
	if (fnum1 != -1) {
		printf("(%s) open of %s succeeded (should fail)\n", 
		       __location__, fname);
		correct = False;
		goto fail;
	}
	
	printf("first delete on close test succeeded.\n");
	
	/* Test 2 - this should delete the file on close. */
	
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_ALL_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, NTCREATEX_SHARE_ACCESS_NONE, 
				   NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
	
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("(%s) setting delete_on_close failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("(%s) open of %s succeeded should have been deleted on close !\n", 
		       __location__, fname);
		if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
			printf("(%s) close failed (%s)\n", 
			       __location__, smbcli_errstr(cli1->tree));
			correct = False;
			goto fail;
		}
		smbcli_unlink(cli1->tree, fname);
	} else
		printf("second delete on close test succeeded.\n");
	
	/* Test 3 - ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      GENERIC_RIGHTS_FILE_ALL_ACCESS, 
				      FILE_ATTRIBUTE_NORMAL,
				      NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE, 
				      NTCREATEX_DISP_OVERWRITE_IF, 0, 0);

	if (fnum1 == -1) {
		printf("(%s) open - 1 of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	/* This should fail with a sharing violation - open for delete is only compatible
	   with SHARE_DELETE. */

	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      GENERIC_RIGHTS_FILE_READ, 
				      FILE_ATTRIBUTE_NORMAL,
				      NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE, 
				      NTCREATEX_DISP_OPEN, 0, 0);

	if (fnum2 != -1) {
		printf("(%s) open  - 2 of %s succeeded - should have failed.\n", 
		       __location__, fname);
		correct = False;
		goto fail;
	}

	/* This should succeed. */

	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_READ, FILE_ATTRIBUTE_NORMAL,
			NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE, NTCREATEX_DISP_OPEN, 0, 0);

	if (fnum2 == -1) {
		printf("(%s) open  - 2 of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("(%s) setting delete_on_close failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close 1 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum2))) {
		printf("(%s) close 2 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	/* This should fail - file should no longer be there. */

	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("(%s) open of %s succeeded should have been deleted on close !\n", 
		       __location__, fname);
		if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
			printf("(%s) close failed (%s)\n", 
			       __location__, smbcli_errstr(cli1->tree));
		}
		smbcli_unlink(cli1->tree, fname);
		correct = False;
		goto fail;
	} else
		printf("third delete on close test succeeded.\n");

	/* Test 4 ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	status = smbcli_unlink(cli1->tree, fname);
	if (NT_STATUS_IS_OK(status)) {
		printf("(%s) succeeded unlink of %s\n", __location__, fname);
		correct = False;
		goto fail;
	}

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				   SA_RIGHT_FILE_READ_DATA  | 
				   SA_RIGHT_FILE_WRITE_DATA |
				   STD_RIGHT_DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, 
				   NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE, 
				   NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
								
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	/* This should succeed. */
	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_READ,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ  | 
				      NTCREATEX_SHARE_ACCESS_WRITE |
				      NTCREATEX_SHARE_ACCESS_DELETE, 
				      NTCREATEX_DISP_OPEN, 0, 0);
	if (fnum2 == -1) {
		printf("(%s) open  - 2 of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum2))) {
		printf("(%s) close - 1 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("(%s) setting delete_on_close failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	/* This should fail - no more opens once delete on close set. */
	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      GENERIC_RIGHTS_FILE_READ,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OPEN, 0, 0);
	if (fnum2 != -1) {
		printf("(%s) open  - 3 of %s succeeded ! Should have failed.\n",
		       __location__, fname );
		correct = False;
		goto fail;
	} else
		printf("fourth delete on close test succeeded.\n");
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close - 2 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	/* Test 5 ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	/* This should fail - only allowed on NT opens with DELETE access. */

	if (NT_STATUS_IS_OK(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("(%s) setting delete_on_close on OpenX file succeeded - should fail !\n",
		       __location__);
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close - 2 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	printf("fifth delete on close test succeeded.\n");
	
	/* Test 6 ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				   SA_RIGHT_FILE_READ_DATA | SA_RIGHT_FILE_WRITE_DATA,
				   FILE_ATTRIBUTE_NORMAL, 
				   NTCREATEX_SHARE_ACCESS_READ  |
				   NTCREATEX_SHARE_ACCESS_WRITE |
				   NTCREATEX_SHARE_ACCESS_DELETE,
				   NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
	
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	/* This should fail - only allowed on NT opens with DELETE access. */
	
	if (NT_STATUS_IS_OK(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("(%s) setting delete_on_close on file with no delete access succeeded - should fail !\n",
		       __location__);
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close - 2 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	printf("sixth delete on close test succeeded.\n");
	
	/* Test 7 ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				   SA_RIGHT_FILE_READ_DATA  | 
				   SA_RIGHT_FILE_WRITE_DATA |
				   STD_RIGHT_DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, 0, NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
								
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("(%s) setting delete_on_close on file failed !\n",
		       __location__);
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, False))) {
		printf("(%s) unsetting delete_on_close on file failed !\n",
		       __location__);
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close - 2 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}
	
	/* This next open should succeed - we reset the flag. */
	
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close - 2 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	printf("seventh delete on close test succeeded.\n");
	
	/* Test 7 ... */
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	if (!torture_open_connection(&cli2)) {
		printf("(%s) failed to open second connection.\n",
		       __location__);
		correct = False;
		goto fail;
	}

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, SA_RIGHT_FILE_READ_DATA|SA_RIGHT_FILE_WRITE_DATA|STD_RIGHT_DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
				   NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
	
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, SA_RIGHT_FILE_READ_DATA|SA_RIGHT_FILE_WRITE_DATA|STD_RIGHT_DELETE_ACCESS,
				   FILE_ATTRIBUTE_NORMAL, NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
				   NTCREATEX_DISP_OPEN, 0, 0);
	
	if (fnum2 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, True))) {
		printf("(%s) setting delete_on_close on file failed !\n",
		       __location__);
		correct = False;
		goto fail;
	}
	
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close - 1 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli2->tree, fnum2))) {
		printf("(%s) close - 2 failed (%s)\n", 
		       __location__, smbcli_errstr(cli2->tree));
		correct = False;
		goto fail;
	}

	/* This should fail.. */
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("(%s) open of %s succeeded should have been deleted on close !\n",
		       __location__, fname);
		goto fail;
		correct = False;
	} else
		printf("eighth delete on close test succeeded.\n");

	/* This should fail - we need to set DELETE_ACCESS. */
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0,
				      SA_RIGHT_FILE_READ_DATA|SA_RIGHT_FILE_WRITE_DATA,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_NONE, 
				      NTCREATEX_DISP_OVERWRITE_IF, 
				      NTCREATEX_OPTIONS_DELETE_ON_CLOSE, 0);
	
	if (fnum1 != -1) {
		printf("(%s) open of %s succeeded should have failed!\n", 
		       __location__, fname);
		correct = False;
		goto fail;
	}

	printf("ninth delete on close test succeeded.\n");

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      SA_RIGHT_FILE_READ_DATA|SA_RIGHT_FILE_WRITE_DATA|STD_RIGHT_DELETE_ACCESS,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_NONE, 
				      NTCREATEX_DISP_OVERWRITE_IF, 
				      NTCREATEX_OPTIONS_DELETE_ON_CLOSE, 0);
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	/* This should delete the file. */
	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	/* This should fail.. */
	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);
	if (fnum1 != -1) {
		printf("(%s) open of %s succeeded should have been deleted on close !\n",
		       __location__, fname);
		goto fail;
		correct = False;
	} else
		printf("tenth delete on close test succeeded.\n");

	/* test 11 - does having read only attribute still allow delete on close. */

	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
                                                                                                                                        
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      GENERIC_RIGHTS_FILE_ALL_ACCESS,
				      FILE_ATTRIBUTE_READONLY, 
				      NTCREATEX_SHARE_ACCESS_NONE, 
				      NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
	
        if (fnum1 == -1) {
                printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
                correct = False;
                goto fail;
        }

	status = smbcli_nt_delete_on_close(cli1->tree, fnum1, True);

	if (NT_STATUS_V(status) != NT_STATUS_V(NT_STATUS_CANNOT_DELETE)) {
		printf("(%s) setting delete_on_close should fail with NT_STATUS_CANNOT_DELETE. Got %s instead)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
                                                                                                                                        
        printf("eleventh delete on close test succeeded.\n");

	/* test 12 - does having read only attribute still allow delete on close at time of open. */

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, GENERIC_RIGHTS_FILE_ALL_ACCESS, FILE_ATTRIBUTE_READONLY,
				   NTCREATEX_SHARE_ACCESS_DELETE, NTCREATEX_DISP_OVERWRITE_IF, 
				   NTCREATEX_OPTIONS_DELETE_ON_CLOSE, 0);
	
	if (fnum1 != -1) {
		printf("(%s) open of %s succeeded. Should fail with NT_STATUS_CANNOT_DELETE.\n", 
		       __location__, fname);
		smbcli_close(cli1->tree, fnum1);
		correct = False;
		goto fail;
	} else {
		status = smbcli_nt_error(cli1->tree);
		if (NT_STATUS_V(status) != NT_STATUS_V(NT_STATUS_CANNOT_DELETE)) {
			printf("(%s) setting delete_on_close on open should fail with NT_STATUS_CANNOT_DELETE. Got %s instead)\n", 
			       __location__, smbcli_errstr(cli1->tree));
			correct = False;
			goto fail;
		}
	}
	
        printf("twelvth delete on close test succeeded.\n");

	printf("finished delete test\n");

  fail:
	/* FIXME: This will crash if we aborted before cli2 got
	 * intialized, because these functions don't handle
	 * uninitialized connections. */
		
	smbcli_close(cli1->tree, fnum1);
	smbcli_close(cli1->tree, fnum2);
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);

	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	if (!torture_close_connection(cli2)) {
		correct = False;
	}
	return correct;
}

