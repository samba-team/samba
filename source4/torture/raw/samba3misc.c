/* 
   Unix SMB/CIFS implementation.
   Test some misc Samba3 code paths
   Copyright (C) Volker Lendecke 2006
   
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
#include "libcli/raw/libcliraw.h"
#include "system/time.h"
#include "system/filesys.h"
#include "libcli/libcli.h"
#include "torture/util.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
	} \
} while (0)

BOOL torture_samba3_checkfsp(struct torture_context *torture)
{
	struct smbcli_state *cli;
	const char *fname = "test.txt";
	const char *dirname = "testdir";
	int fnum;
	NTSTATUS status;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;
	ssize_t nread;
	char buf[16];
	struct smbcli_tree *tree2;

	if ((mem_ctx = talloc_init("torture_samba3_checkfsp")) == NULL) {
		d_printf("talloc_init failed\n");
		return False;
	}

	if (!torture_open_connection_share(
		    torture, &cli, lp_parm_string(-1, "torture", "host"),
		    lp_parm_string(-1, "torture", "share"), NULL)) {
		d_printf("torture_open_connection_share failed\n");
		ret = False;
		goto done;
	}

	smbcli_deltree(cli->tree, dirname);

	status = torture_second_tcon(torture, cli->session,
				     lp_parm_string(-1, "torture", "share"),
				     &tree2);
	CHECK_STATUS(status, NT_STATUS_OK);
	if (!NT_STATUS_IS_OK(status))
		goto done;

	/* Try a read on an invalid FID */

	nread = smbcli_read(cli->tree, 4711, buf, 0, sizeof(buf));
	CHECK_STATUS(smbcli_nt_error(cli->tree), NT_STATUS_INVALID_HANDLE);

	/* Try a read on a directory handle */

	status = smbcli_mkdir(cli->tree, dirname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_mkdir failed: %s\n", nt_errstr(status));
		ret = False;
		goto done;
	}

	/* Open the directory */
	{
		union smb_open io;
		io.generic.level = RAW_OPEN_NTCREATEX;
		io.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED;
		io.ntcreatex.in.root_fid = 0;
		io.ntcreatex.in.security_flags = 0;
		io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
		io.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
		io.ntcreatex.in.alloc_size = 0;
		io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_DIRECTORY;
		io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
		io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
		io.ntcreatex.in.create_options = 0;
		io.ntcreatex.in.fname = dirname;
		status = smb_raw_open(cli->tree, mem_ctx, &io);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("smb_open on the directory failed: %s\n",
				 nt_errstr(status));
			ret = False;
			goto done;
		}
		fnum = io.ntcreatex.out.file.fnum;
	}

	/* Try a read on the directory */

	nread = smbcli_read(cli->tree, fnum, buf, 0, sizeof(buf));
	if (nread >= 0) {
		d_printf("smbcli_read on a directory succeeded, expected "
			 "failure\n");
		ret = False;
	}

	CHECK_STATUS(smbcli_nt_error(cli->tree),
		     NT_STATUS_INVALID_DEVICE_REQUEST);

	/* Same test on the second tcon */

	nread = smbcli_read(tree2, fnum, buf, 0, sizeof(buf));
	if (nread >= 0) {
		d_printf("smbcli_read on a directory succeeded, expected "
			 "failure\n");
		ret = False;
	}

	CHECK_STATUS(smbcli_nt_error(tree2), NT_STATUS_INVALID_HANDLE);

	smbcli_close(cli->tree, fnum);

	/* Try a normal file read on a second tcon */

	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		d_printf("Failed to create %s - %s\n", fname,
			 smbcli_errstr(cli->tree));
		ret = False;
		goto done;
	}

	nread = smbcli_read(tree2, fnum, buf, 0, sizeof(buf));
	CHECK_STATUS(smbcli_nt_error(tree2), NT_STATUS_INVALID_HANDLE);

	smbcli_close(cli->tree, fnum);

 done:
	smbcli_deltree(cli->tree, dirname);
	torture_close_connection(cli);
	talloc_free(mem_ctx);

	return ret;
}

BOOL torture_samba3_badpath(struct torture_context *torture)
{
	struct smbcli_state *cli_nt;
	struct smbcli_state *cli_dos;
	const char *fname = "test.txt";
	const char *dirname = "testdir";
	char *fpath;
	int fnum;
	NTSTATUS status;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;
	ssize_t nread;
	char buf[16];
	struct smbcli_tree *tree2;
	BOOL nt_status_support;

	if (!(mem_ctx = talloc_init("torture_samba3_badpath"))) {
		d_printf("talloc_init failed\n");
		return False;
	}

	nt_status_support = lp_nt_status_support();

	if (!lp_set_cmdline("nt status support", "yes")) {
		printf("Could not set 'nt status support = yes'\n");
		goto fail;
	}

	if (!torture_open_connection(&cli_nt)) {
		goto fail;
	}

	if (!lp_set_cmdline("nt status support", "no")) {
		printf("Could not set 'nt status support = yes'\n");
		goto fail;
	}

	if (!torture_open_connection(&cli_dos)) {
		goto fail;
	}

	if (!lp_set_cmdline("nt status support",
			    nt_status_support ? "yes":"no")) {
		printf("Could not reset 'nt status support = yes'");
		goto fail;
	}

	smbcli_deltree(cli_nt->tree, dirname);

	status = smbcli_mkdir(cli_nt->tree, dirname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_mkdir failed: %s\n", nt_errstr(status));
		ret = False;
		goto done;
	}

	status = smbcli_chkpath(cli_nt->tree, dirname);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smbcli_chkpath(cli_nt->tree,
				talloc_asprintf(mem_ctx, "%s\\bla", dirname));
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	status = smbcli_chkpath(cli_dos->tree,
				talloc_asprintf(mem_ctx, "%s\\bla", dirname));
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_chkpath(cli_nt->tree,
				talloc_asprintf(mem_ctx, "%s\\bla\\blub",
						dirname));
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
	status = smbcli_chkpath(cli_dos->tree,
				talloc_asprintf(mem_ctx, "%s\\bla\\blub",
						dirname));
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	if (!(fpath = talloc_asprintf(mem_ctx, "%s\\%s", dirname, fname))) {
		goto fail;
	}
	fnum = smbcli_open(cli_nt->tree, fpath, O_RDWR | O_CREAT, DENY_NONE);
	if (fnum == -1) {
		d_printf("Could not create file %s: %s\n", fpath,
			 smbcli_errstr(cli_nt->tree));
		goto fail;
	}
	smbcli_close(cli_nt->tree, fnum);

	status = smbcli_chkpath(cli_nt->tree, fpath);
	CHECK_STATUS(status, NT_STATUS_NOT_A_DIRECTORY);
	status = smbcli_chkpath(cli_dos->tree, fpath);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_chkpath(cli_nt->tree, "..");
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);
	status = smbcli_chkpath(cli_dos->tree, "..");
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidpath));

	status = smbcli_chkpath(cli_nt->tree, "\t");
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_chkpath(cli_dos->tree, "\t");
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_chkpath(cli_nt->tree, "\t\\bla");
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_chkpath(cli_dos->tree, "\t\\bla");
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_chkpath(cli_nt->tree, "<");
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_chkpath(cli_dos->tree, "<");
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_chkpath(cli_nt->tree, "<\\bla");
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_chkpath(cli_dos->tree, "<\\bla");
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	goto done;

 fail:
	ret = False;

 done:
	if (cli_nt != NULL) {
		smbcli_deltree(cli_nt->tree, dirname);
		torture_close_connection(cli_nt);
	}
	if (cli_dos != NULL) {
		torture_close_connection(cli_dos);
	}
	talloc_free(mem_ctx);

	return ret;
}
