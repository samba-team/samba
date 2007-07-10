/* 
   Unix SMB/CIFS implementation.
   chkpath individual test suite
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
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "torture/util.h"

#define BASEDIR "\\rawchkpath"

#define CHECK_STATUS(status, correct, dos_correct) do { \
	if (!NT_STATUS_EQUAL(status, correct) && !NT_STATUS_EQUAL(status, dos_correct)) { \
		printf("(%d) Incorrect status %s - should be %s\n", \
		       __LINE__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


static NTSTATUS single_search(struct smbcli_state *cli,
                              TALLOC_CTX *mem_ctx, const char *pattern)
{
	union smb_search_first io;
	NTSTATUS status;

	io.t2ffirst.level = RAW_SEARCH_TRANS2;
	io.t2ffirst.data_level = RAW_SEARCH_DATA_STANDARD;
	io.t2ffirst.in.search_attrib = 0;
	io.t2ffirst.in.max_count = 1;
	io.t2ffirst.in.flags = FLAG_TRANS2_FIND_CLOSE;
	io.t2ffirst.in.storage_type = 0;
	io.t2ffirst.in.pattern = pattern;

	status = smb_raw_search_first(cli->tree, mem_ctx,
				      &io, NULL, NULL);

	return status;
}

static BOOL test_path(struct smbcli_state *cli, const char *path, NTSTATUS expected, NTSTATUS dos_expected)
{
	union smb_chkpath io;
	NTSTATUS status;
	io.chkpath.in.path = path;
	status = smb_raw_chkpath(cli->tree, &io);
	if (!NT_STATUS_EQUAL(status, expected) && !NT_STATUS_EQUAL(status, dos_expected)) {
		printf("%-40s FAILED %s should be %s or %s\n", 
		       path, nt_errstr(status), nt_errstr(expected), nt_errstr(dos_expected));
		return False;
	} else {
		printf("%-40s correct (%s)\n", path, nt_errstr(status));

	}
	return True;
}

static BOOL test_chkpath(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	union smb_chkpath io;
	NTSTATUS status;
	BOOL ret = True;
	int fnum = -1;
	int fnum1 = -1;

	io.chkpath.in.path = BASEDIR;

	status = smb_raw_chkpath(cli->tree, &io);
	CHECK_STATUS(status, NT_STATUS_OK, NT_STATUS_OK);

	ret &= test_path(cli, BASEDIR "\\nodir", NT_STATUS_OBJECT_NAME_NOT_FOUND, NT_STATUS_DOS(ERRDOS,ERRbadpath));

	fnum = create_complex_file(cli, mem_ctx, BASEDIR "\\test.txt..");
	if (fnum == -1) {
		printf("failed to open test.txt - %s\n", smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	ret &= test_path(cli, BASEDIR "\\test.txt..", NT_STATUS_NOT_A_DIRECTORY, NT_STATUS_DOS(ERRDOS,ERRbadpath));
	
	if (!torture_set_file_attribute(cli->tree, BASEDIR, FILE_ATTRIBUTE_HIDDEN)) {
		printf("failed to set basedir hidden\n");
		ret = False;
		goto done;
	}

	ret &= test_path(cli, BASEDIR, NT_STATUS_OK, NT_STATUS_OK);
	ret &= test_path(cli, BASEDIR "\\foo\\..\\test.txt..", NT_STATUS_NOT_A_DIRECTORY, NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, "", NT_STATUS_OK, NT_STATUS_OK);
	ret &= test_path(cli, ".", NT_STATUS_OBJECT_NAME_INVALID, NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, ".\\", NT_STATUS_OBJECT_NAME_INVALID, NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, "\\\\\\.\\", NT_STATUS_OBJECT_NAME_INVALID, NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, ".\\.", NT_STATUS_OBJECT_PATH_NOT_FOUND, NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, "." BASEDIR, NT_STATUS_OBJECT_PATH_NOT_FOUND, NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR "\\.", NT_STATUS_OBJECT_NAME_INVALID, NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR "\\.\\test.txt..", NT_STATUS_OBJECT_PATH_NOT_FOUND, NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, ".\\.\\", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, ".\\.\\.", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, ".\\.\\.aaaaa", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, "\\.\\", NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, "\\.\\\\", NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, "\\.\\\\\\\\\\\\", NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRbadpath));

	/* Note that the two following paths are identical but
	  give different NT status returns for chkpth and findfirst. */

	printf("testing findfirst on %s\n", "\\.\\\\\\\\\\\\.");
	status = single_search(cli, mem_ctx, "\\.\\\\\\\\\\\\.");
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRinvalidname));

	ret &= test_path(cli, "\\.\\\\\\\\\\\\.", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));

	/* We expect this open to fail with the same error code as the chkpath below. */
	printf("testing Open on %s\n", "\\.\\\\\\\\\\\\.");
	/* findfirst seems to fail with a different error. */
	fnum1 = smbcli_nt_create_full(cli->tree, "\\.\\\\\\\\\\\\.",
				      0, SEC_RIGHTS_FILE_ALL,
				      FILE_ATTRIBUTE_NORMAL,
				      NTCREATEX_SHARE_ACCESS_DELETE|
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE,
				      NTCREATEX_DISP_OVERWRITE_IF,
				      0, 0);
	status = smbcli_nt_error(cli->tree);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));


	ret &= test_path(cli, "\\.\\\\xxx", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, "..\\..\\..", NT_STATUS_OBJECT_PATH_SYNTAX_BAD,NT_STATUS_DOS(ERRDOS,ERRinvalidpath));
	ret &= test_path(cli, "\\..", NT_STATUS_OBJECT_PATH_SYNTAX_BAD,NT_STATUS_DOS(ERRDOS,ERRinvalidpath));
	ret &= test_path(cli, "\\.\\\\\\\\\\\\xxx", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR"\\.\\", NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR"\\.\\\\", NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR"\\.\\nt", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR"\\.\\.\\nt", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR"\\nt", NT_STATUS_OK, NT_STATUS_OK);
	ret &= test_path(cli, BASEDIR".\\foo", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR"xx\\foo", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, ".\\", NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, ".\\.", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, ".\\.\\.\\.\\foo\\.\\.\\", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR".\\.\\.\\.\\foo\\.\\.\\", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR".\\.\\.\\.\\foo\\..\\.\\", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR".", NT_STATUS_OBJECT_NAME_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, "\\", NT_STATUS_OK,NT_STATUS_OK);
	ret &= test_path(cli, "\\.", NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, "\\..\\", NT_STATUS_OBJECT_PATH_SYNTAX_BAD,NT_STATUS_DOS(ERRDOS,ERRinvalidpath));
	ret &= test_path(cli, "\\..", NT_STATUS_OBJECT_PATH_SYNTAX_BAD,NT_STATUS_DOS(ERRDOS,ERRinvalidpath));
	ret &= test_path(cli, BASEDIR "\\.", NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR "\\..", NT_STATUS_OK,NT_STATUS_OK);
	ret &= test_path(cli, BASEDIR "\\nt\\V S\\VB98\\vb600", NT_STATUS_OBJECT_NAME_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR "\\nt\\V S\\VB98\\vb6.exe", NT_STATUS_NOT_A_DIRECTORY,NT_STATUS_DOS(ERRDOS,ERRbadpath));

	/* We expect this open to fail with the same error code as the chkpath below. */
	printf("testing Open on %s\n", BASEDIR".\\.\\.\\.\\foo\\..\\.\\");
	/* findfirst seems to fail with a different error. */
	fnum1 = smbcli_nt_create_full(cli->tree, BASEDIR".\\.\\.\\.\\foo\\..\\.\\",
				      0, SEC_RIGHTS_FILE_ALL,
				      FILE_ATTRIBUTE_NORMAL,
				      NTCREATEX_SHARE_ACCESS_DELETE|
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE,
				      NTCREATEX_DISP_OVERWRITE_IF,
				      0, 0);
	status = smbcli_nt_error(cli->tree);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));

	printf("testing findfirst on %s\n", BASEDIR".\\.\\.\\.\\foo\\..\\.\\");
	status = single_search(cli, mem_ctx, BASEDIR".\\.\\.\\.\\foo\\..\\.\\");
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));

	/* We expect this open to fail with the same error code as the chkpath below. */
	/* findfirst seems to fail with a different error. */
	printf("testing Open on %s\n", BASEDIR "\\nt\\V S\\VB98\\vb6.exe\\3");
	fnum1 = smbcli_nt_create_full(cli->tree, BASEDIR "\\nt\\V S\\VB98\\vb6.exe\\3",
				      0, SEC_RIGHTS_FILE_ALL,
				      FILE_ATTRIBUTE_NORMAL,
				      NTCREATEX_SHARE_ACCESS_DELETE|
				      NTCREATEX_SHARE_ACCESS_READ|
				      NTCREATEX_SHARE_ACCESS_WRITE,
				      NTCREATEX_DISP_OVERWRITE_IF,
				      0, 0);
	status = smbcli_nt_error(cli->tree);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));

	ret &= test_path(cli, BASEDIR "\\nt\\V S\\VB98\\vb6.exe\\3", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR "\\nt\\V S\\VB98\\vb6.exe\\3\\foo", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR "\\nt\\3\\foo", NT_STATUS_OBJECT_PATH_NOT_FOUND,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR "\\nt\\V S\\*\\vb6.exe\\3", NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRbadpath));
	ret &= test_path(cli, BASEDIR "\\nt\\V S\\*\\*\\vb6.exe\\3", NT_STATUS_OBJECT_NAME_INVALID,NT_STATUS_DOS(ERRDOS,ERRbadpath));

done:
	smbcli_close(cli->tree, fnum);
	return ret;
}

/* 
   basic testing of chkpath calls 
*/
BOOL torture_raw_chkpath(struct torture_context *torture)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	int fnum;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_chkpath");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR "\\nt"))) {
		printf("Failed to create " BASEDIR " - %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR "\\nt\\V S"))) {
		printf("Failed to create " BASEDIR " - %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_mkdir(cli->tree, BASEDIR "\\nt\\V S\\VB98"))) {
		printf("Failed to create " BASEDIR " - %s\n", smbcli_errstr(cli->tree));
		return False;
	}

	fnum = create_complex_file(cli, mem_ctx, BASEDIR "\\nt\\V S\\VB98\\vb6.exe");
	if (fnum == -1) {
		printf("failed to open \\nt\\V S\\VB98\\vb6.exe - %s\n", smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	if (!test_chkpath(cli, mem_ctx)) {
		ret = False;
	}

 done:

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	torture_close_connection(cli);
	talloc_free(mem_ctx);
	return ret;
}
