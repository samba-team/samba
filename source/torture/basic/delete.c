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
#include "system/filesys.h"
#include "libcli/raw/libcliraw.h"

static BOOL check_delete_on_close(struct smbcli_state *cli, int fnum,
				  const char *fname, BOOL expect_it)
{
	TALLOC_CTX *mem_ctx = talloc_init("single_search");
	union smb_search_data data;
	NTSTATUS status;

	time_t c_time, a_time, m_time;
	size_t size;
	uint16_t mode;

	BOOL res = True;

	status = torture_single_search(cli, mem_ctx,
				       fname, RAW_SEARCH_FULL_DIRECTORY_INFO,
				       FILE_ATTRIBUTE_DIRECTORY,
				       &data);
	if (!NT_STATUS_IS_OK(status)) {
		printf("(%s) single_search failed (%s)\n", 
		       __location__, nt_errstr(status));
		res = False;
		goto done;
	}

	if (fnum != -1) {
		union smb_fileinfo io;
		int nlink = expect_it ? 0 : 1;

		io.all_info.level = RAW_FILEINFO_ALL_INFO;
		io.all_info.in.fnum = fnum;

		status = smb_raw_fileinfo(cli->tree, mem_ctx, &io);
		if (!NT_STATUS_IS_OK(status)) {
			printf("(%s) qpathinfo failed (%s)\n", __location__,
			       nt_errstr(status));
			res = False;
			goto done;
		}

		if (expect_it != io.all_info.out.delete_pending) {
			printf("Expected del_on_close flag %d, qfileinfo gave %d\n",
			       expect_it, io.all_info.out.delete_pending);
			res = False;
			goto done;
		}

		if (nlink != io.all_info.out.nlink) {
			printf("Expected nlink %d, qfileinfo gave %d\n",
			       nlink, io.all_info.out.nlink);
			res = False;
			goto done;
		}

		io.standard_info.level = RAW_FILEINFO_STANDARD_INFO;
		io.standard_info.in.fnum = fnum;

		status = smb_raw_fileinfo(cli->tree, mem_ctx, &io);
		if (!NT_STATUS_IS_OK(status)) {
			printf("(%s) qpathinfo failed (%s)\n", __location__,
			       nt_errstr(status));
			res = False;
			goto done;
		}

		if (expect_it != io.standard_info.out.delete_pending) {
			printf("Expected del_on_close flag %d, qfileinfo gave %d\n",
			       expect_it, io.standard_info.out.delete_pending);
			res = False;
			goto done;
		}

		if (nlink != io.standard_info.out.nlink) {
			printf("Expected nlink %d, qfileinfo gave %d\n",
			       nlink, io.all_info.out.nlink);
			res = False;
			goto done;
		}

	}

	status = smbcli_qpathinfo(cli->tree, fname,
				  &c_time, &a_time, &m_time,
				  &size, &mode);

	if (expect_it) {
		if (!NT_STATUS_EQUAL(status, NT_STATUS_DELETE_PENDING)) {
			printf("(%s) qpathinfo did not give correct error "
			       "code (%s) -- NT_STATUS_DELETE_PENDING "
			       "expected\n", __location__,
			       nt_errstr(status));
			res = False;
			goto done;
		}
	} else {
		if (!NT_STATUS_IS_OK(status)) {
			printf("(%s) qpathinfo failed (%s)\n", __location__,
			       nt_errstr(status));
			res = False;
			goto done;
		}
	}

 done:
	talloc_free(mem_ctx);
	return res;
}

#define CHECK_STATUS(_cli, _expected) do { \
	if (!NT_STATUS_EQUAL(_cli->tree->session->transport->error.e.nt_status, _expected)) { \
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(_cli->tree->session->transport->error.e.nt_status), nt_errstr(_expected)); \
		correct = False; \
		goto fail; \
	}} while (0)

/*
  Test delete on close semantics.
 */
BOOL torture_test_delete(void)
{
	struct smbcli_state *cli1;
	struct smbcli_state *cli2 = NULL;
	const char *fname = "\\delete.file";
	const char *fname_new = "\\delete.new";
	const char *dirname = "\\delete.dir";
	int fnum1 = -1;
	int fnum2 = -1;
	int dnum1 = -1;
	BOOL correct = True;
	NTSTATUS status;
	
	printf("starting delete test\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}

	smbcli_deltree(cli1->tree, dirname);

	/* Test 1 - this should delete the file on close. */
	
	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      SEC_RIGHTS_FILE_ALL,
				      FILE_ATTRIBUTE_NORMAL,
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
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      SEC_RIGHTS_FILE_ALL,
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
				      SEC_RIGHTS_FILE_ALL,
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
				      SEC_RIGHTS_FILE_READ, 
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

	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      SEC_RIGHTS_FILE_READ, 
				      FILE_ATTRIBUTE_NORMAL,
				      NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE, 
				      NTCREATEX_DISP_OPEN, 0, 0);

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
				      SEC_FILE_READ_DATA  | 
				      SEC_FILE_WRITE_DATA |
				      SEC_STD_DELETE,
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
	fnum2 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      SEC_RIGHTS_FILE_READ,
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
				      SEC_RIGHTS_FILE_READ,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OPEN, 0, 0);
	if (fnum2 != -1) {
		printf("(%s) open  - 3 of %s succeeded ! Should have failed.\n",
		       __location__, fname );
		correct = False;
		goto fail;
	}
	CHECK_STATUS(cli1, NT_STATUS_DELETE_PENDING);

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
				   SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA,
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
				      SEC_FILE_READ_DATA  | 
				      SEC_FILE_WRITE_DATA |
				      SEC_STD_DELETE,
				      FILE_ATTRIBUTE_NORMAL, 0, 
				      NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
								
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

	correct &= check_delete_on_close(cli1, fnum1, fname, True);
	
	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1, False))) {
		printf("(%s) unsetting delete_on_close on file failed !\n",
		       __location__);
		correct = False;
		goto fail;
	}

	correct &= check_delete_on_close(cli1, fnum1, fname, False);
	
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

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      SEC_FILE_READ_DATA|
				      SEC_FILE_WRITE_DATA|
				      SEC_STD_DELETE,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OVERWRITE_IF, 0, 0);
	
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, 
				      SEC_FILE_READ_DATA|
				      SEC_FILE_WRITE_DATA|
				      SEC_STD_DELETE,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_WRITE|NTCREATEX_SHARE_ACCESS_DELETE,
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

	correct &= check_delete_on_close(cli1, fnum1, fname, True);
	correct &= check_delete_on_close(cli2, fnum2, fname, True);

	if (NT_STATUS_IS_ERR(smbcli_close(cli1->tree, fnum1))) {
		printf("(%s) close - 1 failed (%s)\n", 
		       __location__, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	correct &= check_delete_on_close(cli1, -1, fname, True);
	correct &= check_delete_on_close(cli2, fnum2, fname, True);
	
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
				      SEC_FILE_READ_DATA|SEC_FILE_WRITE_DATA,
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
				      SEC_FILE_READ_DATA|
				      SEC_FILE_WRITE_DATA|
				      SEC_STD_DELETE,
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
				      SEC_RIGHTS_FILE_ALL,
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

	if (!NT_STATUS_EQUAL(status, NT_STATUS_CANNOT_DELETE)) {
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

	/* test 12 - does having read only attribute still allow delete on
	 * close at time of open. */

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      SEC_RIGHTS_FILE_ALL,
				      FILE_ATTRIBUTE_READONLY,
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OVERWRITE_IF, 
				      NTCREATEX_OPTIONS_DELETE_ON_CLOSE, 0);
	
	if (fnum1 != -1) {
		printf("(%s) open of %s succeeded. Should fail with "
		       "NT_STATUS_CANNOT_DELETE.\n", __location__, fname);
		smbcli_close(cli1->tree, fnum1);
		correct = False;
		goto fail;
	} else {
		status = smbcli_nt_error(cli1->tree);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_CANNOT_DELETE)) {
			printf("(%s) setting delete_on_close on open should "
			       "fail with NT_STATUS_CANNOT_DELETE. Got %s "
			       "instead)\n", 
			       __location__, smbcli_errstr(cli1->tree));
			correct = False;
			goto fail;
		}
	}
	
        printf("twelvth delete on close test succeeded.\n");

	/* Test 13: Does resetting the delete on close flag affect a second
	 * fd? */

	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      SEC_FILE_READ_DATA|
				      SEC_FILE_WRITE_DATA|
				      SEC_STD_DELETE,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE|
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OVERWRITE_IF,
				      0, 0);
	
	if (fnum1 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, 
				      SEC_FILE_READ_DATA|
				      SEC_FILE_WRITE_DATA|
				      SEC_STD_DELETE,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE|
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OPEN, 0, 0);
	
	if (fnum2 == -1) {
		printf("(%s) open of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli2->tree));
		correct = False;
		goto fail;
	}

	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, fnum1,
						       True))) {
		printf("(%s) setting delete_on_close on file failed !\n",
		       __location__);
		correct = False;
		goto fail;
	}

	correct &= check_delete_on_close(cli1, fnum1, fname, True);
	correct &= check_delete_on_close(cli2, fnum2, fname, True);

	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli2->tree, fnum2,
						       False))) {
		printf("(%s) setting delete_on_close on file failed !\n",
		       __location__);
		correct = False;
		goto fail;
	}

	correct &= check_delete_on_close(cli1, fnum1, fname, False);
	correct &= check_delete_on_close(cli2, fnum2, fname, False);
	
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

	fnum1 = smbcli_open(cli1->tree, fname, O_RDONLY, DENY_NONE);

	if (fnum1 == -1) {
		printf("(%s) open of %s failed!\n", 
		       __location__, fname);
		correct = False;
		goto fail;
	}

	smbcli_close(cli1->tree, fnum1);
	smbcli_unlink(cli1->tree, fname);

	printf("thirteenth delete on close test succeeded.\n");

	/* Test 14 -- directory */

	dnum1 = smbcli_nt_create_full(cli1->tree, dirname, 0,
				      SEC_FILE_READ_DATA|
				      SEC_FILE_WRITE_DATA|
				      SEC_STD_DELETE,
				      FILE_ATTRIBUTE_DIRECTORY, 
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE|
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_CREATE, 0, 0);
	if (dnum1 == -1) {
		printf("(%s) open of %s failed: %s!\n", 
		       __location__, dirname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	check_delete_on_close(cli1, dnum1, dirname, False);
	if (NT_STATUS_IS_ERR(smbcli_nt_delete_on_close(cli1->tree, dnum1, True))) {
		printf("(%s) setting delete_on_close on file failed !\n",
		       __location__);
		correct = False;
		goto fail;
	}
	check_delete_on_close(cli1, dnum1, dirname, True);
	smbcli_close(cli1->tree, dnum1);

	/* Now it should be gone... */

	dnum1 = smbcli_nt_create_full(cli1->tree, dirname, 0,
				      SEC_FILE_READ_DATA|
				      SEC_FILE_WRITE_DATA|
				      SEC_STD_DELETE,
				      FILE_ATTRIBUTE_DIRECTORY, 
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE|
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OPEN, 0, 0);
	if (dnum1 != -1) {
		printf("(%s) setting delete_on_close on file succeeded !\n",
		       __location__);
		correct = False;
		goto fail;
	}

	printf("fourteenth delete on close test succeeded.\n");

	/* Test 15 -- non-empty directory */

	dnum1 = smbcli_nt_create_full(cli1->tree, dirname, 0,
				      SEC_FILE_READ_DATA|
				      SEC_FILE_WRITE_DATA|
				      SEC_STD_DELETE,
				      FILE_ATTRIBUTE_DIRECTORY, 
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE|
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_CREATE, 
				      NTCREATEX_OPTIONS_DIRECTORY, 0);
	if (dnum1 == -1) {
		printf("(%s) open of %s failed: %s!\n", 
		       __location__, dirname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	check_delete_on_close(cli1, dnum1, dirname, False);
	status = smbcli_nt_delete_on_close(cli1->tree, dnum1, True);

	{
		char *fullname;
		asprintf(&fullname, "\\%s%s", dirname, fname);
		fnum1 = smbcli_open(cli1->tree, fullname, O_CREAT|O_RDWR,
				    DENY_NONE);
		if (fnum1 != -1) {
			printf("(%s) smbcli_open succeeded, should have "
			       "failed: %s\n",
			       __location__, smbcli_errstr(cli1->tree));
			correct = False;
			goto fail;
		}

		if (!NT_STATUS_EQUAL(smbcli_nt_error(cli1->tree),
				     NT_STATUS_DELETE_PENDING)) {
			printf("(%s) smbcli_open returned %s, expected "
			       "NT_STATUS_DELETE_PENDING\n",
			       __location__, smbcli_errstr(cli1->tree));
			correct = False;
			goto fail;
		}
	}

	status = smbcli_nt_delete_on_close(cli1->tree, dnum1, False);
	if (!NT_STATUS_IS_OK(status)) {
		printf("(%s) setting delete_on_close on file failed !\n",
		       __location__);
		correct = False;
		goto fail;
	}
		
	{
		char *fullname;
		asprintf(&fullname, "\\%s%s", dirname, fname);
		fnum1 = smbcli_open(cli1->tree, fullname, O_CREAT|O_RDWR,
				    DENY_NONE);
		if (fnum1 == -1) {
			printf("(%s) smbcli_open failed: %s\n",
			       __location__, smbcli_errstr(cli1->tree));
			correct = False;
			goto fail;
		}
		smbcli_close(cli1->tree, fnum1);
	}

	status = smbcli_nt_delete_on_close(cli1->tree, dnum1, True);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_DIRECTORY_NOT_EMPTY)) {
		printf("(%s) setting delete_on_close returned %s, expected "
		       "NT_STATUS_DIRECTORY_NOT_EMPTY\n", __location__,
		       smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	smbcli_close(cli1->tree, dnum1);

	/* Now it should be gone... */

	printf("fifteenth delete on close test succeeded.\n");

	/* Test 16: delete on close under rename */

	smbcli_setatr(cli1->tree, fname, 0, 0);
	smbcli_unlink(cli1->tree, fname);
	smbcli_unlink(cli1->tree, fname_new);
	
	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      SEC_FILE_READ_DATA,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE|
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OVERWRITE_IF,
				      0, 0);

	if (fnum1 == -1) {
		printf("(%s) open - 1 of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	status = smbcli_rename(cli2->tree, fname, fname_new);

	if (!NT_STATUS_IS_OK(status)) {
		printf("(%s) renaming failed: %s !\n",
		       __location__, nt_errstr(status));
		correct = False;
		goto fail;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname_new, 0, 
				      SEC_GENERIC_ALL,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE|
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OVERWRITE_IF,
				      0, 0);

	if (fnum2 == -1) {
		printf("(%s) open - 1 of %s failed (%s)\n", 
		       __location__, fname_new, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	status = smbcli_nt_delete_on_close(cli2->tree, fnum2, True);

	if (!NT_STATUS_IS_OK(status)) {
		printf("(%s) setting delete_on_close on file failed !\n",
		       __location__);
		correct = False;
		goto fail;
	}

	smbcli_close(cli2->tree, fnum2);

	/* The file should be around under the new name, there's a second
	 * handle open */

	if (!check_delete_on_close(cli1, fnum1, fname_new, True)) {
		printf("(%s) checking delete on close on file %s failed!\n",
		       __location__, fname_new);
		correct = False;
		goto fail;
	}

	fnum2 = smbcli_nt_create_full(cli2->tree, fname, 0, 
				      SEC_GENERIC_ALL,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE|
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OVERWRITE_IF,
				      0, 0);

	if (fnum2 == -1) {
		printf("(%s) open - 1 of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	smbcli_close(cli2->tree, fnum2);
	smbcli_close(cli1->tree, fnum1);

	fnum1 = smbcli_nt_create_full(cli1->tree, fname, 0, 
				      SEC_FILE_READ_EA,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE|
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OPEN,
				      0, 0);

	if (fnum1 == -1) {
		printf("(%s) open - 1 of %s failed (%s)\n", 
		       __location__, fname, smbcli_errstr(cli1->tree));
		correct = False;
		goto fail;
	}

	smbcli_close(cli1->tree, fnum1);

	fnum1 = smbcli_nt_create_full(cli1->tree, fname_new, 0, 
				      SEC_FILE_READ_EA,
				      FILE_ATTRIBUTE_NORMAL, 
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE|
				      NTCREATEX_SHARE_ACCESS_DELETE,
				      NTCREATEX_DISP_OPEN,
				      0, 0);

	if (fnum1 != -1) {
		printf("(%s) smbcli_open succeeded, should have "
		       "failed\n", __location__);
		smbcli_close(cli1->tree, fnum1);
		correct = False;
		goto fail;
	}

	printf("sixteenth delete on close test succeeded.\n");

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

