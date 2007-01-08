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
#include "torture/raw/proto.h"

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
		    torture, &cli, torture_setting_string(torture, "host", NULL),
		    torture_setting_string(torture, "share", NULL), NULL)) {
		d_printf("torture_open_connection_share failed\n");
		ret = False;
		goto done;
	}

	smbcli_deltree(cli->tree, dirname);

	status = torture_second_tcon(torture, cli->session,
				     torture_setting_string(torture, "share", NULL),
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

static NTSTATUS raw_smbcli_open(struct smbcli_tree *tree, const char *fname, int flags, int share_mode, int *fnum)
{
        union smb_open open_parms;
        uint_t openfn=0;
        uint_t accessmode=0;
        TALLOC_CTX *mem_ctx;
        NTSTATUS status;

        mem_ctx = talloc_init("raw_open");
        if (!mem_ctx) return NT_STATUS_NO_MEMORY;

        if (flags & O_CREAT) {
                openfn |= OPENX_OPEN_FUNC_CREATE;
        }
        if (!(flags & O_EXCL)) {
                if (flags & O_TRUNC) {
                        openfn |= OPENX_OPEN_FUNC_TRUNC;
                } else {
                        openfn |= OPENX_OPEN_FUNC_OPEN;
                }
        }

        accessmode = (share_mode<<OPENX_MODE_DENY_SHIFT);

        if ((flags & O_ACCMODE) == O_RDWR) {
                accessmode |= OPENX_MODE_ACCESS_RDWR;
        } else if ((flags & O_ACCMODE) == O_WRONLY) {
                accessmode |= OPENX_MODE_ACCESS_WRITE;
        }

#if defined(O_SYNC)
        if ((flags & O_SYNC) == O_SYNC) {
                accessmode |= OPENX_MODE_WRITE_THRU;
        }
#endif

        if (share_mode == DENY_FCB) {
                accessmode = OPENX_MODE_ACCESS_FCB | OPENX_MODE_DENY_FCB;
        }

        open_parms.openx.level = RAW_OPEN_OPENX;
        open_parms.openx.in.flags = 0;
        open_parms.openx.in.open_mode = accessmode;
        open_parms.openx.in.search_attrs = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
        open_parms.openx.in.file_attrs = 0;
        open_parms.openx.in.write_time = 0;
        open_parms.openx.in.open_func = openfn;
        open_parms.openx.in.size = 0;
        open_parms.openx.in.timeout = 0;
        open_parms.openx.in.fname = fname;

        status = smb_raw_open(tree, mem_ctx, &open_parms);
        talloc_free(mem_ctx);

        if (fnum && NT_STATUS_IS_OK(status)) {
                *fnum = open_parms.openx.out.file.fnum;
        }

        return status;
}

BOOL torture_samba3_badpath(struct torture_context *torture)
{
	struct smbcli_state *cli_nt = NULL;
	struct smbcli_state *cli_dos = NULL;
	const char *fname = "test.txt";
	const char *dirname = "testdir";
	const char *invname = "testdir\\notthere.txt";
	const char *invpath = "test.txt\\test.txt";
	char *fpath;
	int fnum;
	NTSTATUS status;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;
	BOOL nt_status_support;
	uint16_t attr;


	if (!(mem_ctx = talloc_init("torture_samba3_badpath"))) {
		d_printf("talloc_init failed\n");
		return False;
	}

	nt_status_support = lp_nt_status_support();

	if (!lp_set_cmdline("nt status support", "yes")) {
		printf("Could not set 'nt status support = yes'\n");
		goto fail;
	}

	if (!torture_open_connection(&cli_nt, 0)) {
		goto fail;
	}

	if (!lp_set_cmdline("nt status support", "no")) {
		printf("Could not set 'nt status support = yes'\n");
		goto fail;
	}

	if (!torture_open_connection(&cli_dos, 1)) {
		goto fail;
	}

	if (!lp_set_cmdline("nt status support",
			    nt_status_support ? "yes":"no")) {
		printf("Could not reset 'nt status support = yes'");
		goto fail;
	}

	smbcli_unlink(cli_nt->tree, fname);
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

	fnum = smbcli_open(cli_nt->tree, fname, O_RDWR | O_CREAT, DENY_NONE);
	if (fnum == -1) {
		d_printf("Could not create file %s: %s\n", fname,
			 smbcli_errstr(cli_nt->tree));
		goto fail;
	}
	smbcli_close(cli_nt->tree, fnum);

	/*
	 * Do a whole bunch of error code checks on chkpath
	 */

	status = smbcli_chkpath(cli_nt->tree, fpath);
	CHECK_STATUS(status, NT_STATUS_NOT_A_DIRECTORY);
	status = smbcli_chkpath(cli_dos->tree, fpath);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_chkpath(cli_nt->tree, "..");
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);
	status = smbcli_chkpath(cli_dos->tree, "..");
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidpath));

	status = smbcli_chkpath(cli_nt->tree, ".");
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_chkpath(cli_dos->tree, ".");
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

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

	status = smbcli_chkpath(cli_nt->tree, "");
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smbcli_chkpath(cli_dos->tree, "");
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * .... And the same gang against getatr. Note that the DOS error codes
	 * differ....
	 */

	status = smbcli_getatr(cli_nt->tree, fpath, NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smbcli_getatr(cli_dos->tree, fpath, NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smbcli_getatr(cli_nt->tree, "..", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);
	status = smbcli_getatr(cli_dos->tree, "..", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidpath));

	status = smbcli_getatr(cli_nt->tree, ".", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_getatr(cli_dos->tree, ".", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	status = smbcli_getatr(cli_nt->tree, "\t", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_getatr(cli_dos->tree, "\t", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	status = smbcli_getatr(cli_nt->tree, "\t\\bla", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_getatr(cli_dos->tree, "\t\\bla", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	status = smbcli_getatr(cli_nt->tree, "<", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_getatr(cli_dos->tree, "<", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	status = smbcli_getatr(cli_nt->tree, "<\\bla", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_getatr(cli_dos->tree, "<\\bla", NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	if (lp_parm_bool(-1, "torture", "w2k3", False) ||
	    lp_parm_bool(-1, "torture", "samba3", False)) {

		/*
		 * XP and w2k don't show this behaviour, but I think
		 * Samba3 should follow W2k3
		 */

		status = smbcli_getatr(cli_nt->tree, "", &attr, NULL, NULL);
		CHECK_STATUS(status, NT_STATUS_OK);
		if (attr != (FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_DIRECTORY)) {
			d_printf("(%s) getatr(\"\") returned 0x%x, expected "
				 "0x%x\n", __location__, attr,
				 FILE_ATTRIBUTE_HIDDEN
				 |FILE_ATTRIBUTE_DIRECTORY);
			ret = False;
		}
	}

	status = smbcli_setatr(cli_nt->tree, "",
			       FILE_ATTRIBUTE_DIRECTORY, -1);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	status = smbcli_setatr(cli_dos->tree, "",
			       FILE_ATTRIBUTE_DIRECTORY, -1);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRnoaccess));
	
	status = smbcli_setatr(cli_nt->tree, ".",
			       FILE_ATTRIBUTE_DIRECTORY, -1);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = smbcli_setatr(cli_dos->tree, ".",
			       FILE_ATTRIBUTE_DIRECTORY, -1);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	/* Try the same set with openX. */

	status = raw_smbcli_open(cli_nt->tree, "..", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);
	status = raw_smbcli_open(cli_dos->tree, "..", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidpath));

	status = raw_smbcli_open(cli_nt->tree, ".", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = raw_smbcli_open(cli_dos->tree, ".", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	status = raw_smbcli_open(cli_nt->tree, "\t", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = raw_smbcli_open(cli_dos->tree, "\t", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	status = raw_smbcli_open(cli_nt->tree, "\t\\bla", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = raw_smbcli_open(cli_dos->tree, "\t\\bla", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	status = raw_smbcli_open(cli_nt->tree, "<", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = raw_smbcli_open(cli_dos->tree, "<", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	status = raw_smbcli_open(cli_nt->tree, "<\\bla", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_INVALID);
	status = raw_smbcli_open(cli_dos->tree, "<\\bla", O_RDONLY, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidname));

	/*
	 * Walk the Samba3 unix_convert bad_path handling. Some interesting
	 * error paths around...
	 */

	status = smbcli_chkpath(cli_nt->tree, invpath);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
	status = smbcli_chkpath(cli_dos->tree, invpath);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_getatr(cli_nt->tree, invpath, NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
	status = smbcli_getatr(cli_dos->tree, invpath, NULL, NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_setatr(cli_nt->tree, invpath, 0, 0);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
	status = smbcli_setatr(cli_dos->tree, invpath, 0, 0);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_setatr(cli_nt->tree, invpath, FILE_ATTRIBUTE_NORMAL,
			       0);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
	status = smbcli_setatr(cli_dos->tree, invpath, FILE_ATTRIBUTE_NORMAL,
			       0);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_setatr(cli_nt->tree, invname, 0, 0);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	status = smbcli_setatr(cli_dos->tree, invname, 0, 0);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadfile));

	/*
	 * reply_search returns STATUS_NO_MORE_FILES on invalid path
	 */

	goto done; 		/* We're not yet fully there, but keep it
				 * in */

	status = torture_single_search(cli_nt, mem_ctx, invpath,
				       RAW_SEARCH_SEARCH,
				       RAW_SEARCH_DATA_SEARCH, 0, NULL);
	CHECK_STATUS(status, STATUS_NO_MORE_FILES);
	status = torture_single_search(cli_dos, mem_ctx, invpath,
				       RAW_SEARCH_SEARCH,
				       RAW_SEARCH_DATA_SEARCH, 0, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRnofiles));

	/*
	 * ... whereas t2search gets you NT_STATUS_INVALID_PARAMETER
	 */

	status = torture_single_search(cli_nt, mem_ctx, dirname,
				       RAW_SEARCH_TRANS2,
				       RAW_SEARCH_DATA_STANDARD, 0xf, NULL);
	CHECK_STATUS(status, STATUS_NO_MORE_FILES);
	status = torture_single_search(cli_dos, mem_ctx, dirname,
				       RAW_SEARCH_TRANS2,
				       RAW_SEARCH_DATA_STANDARD, 0xf, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRnofiles));

	status = torture_single_search(cli_nt, mem_ctx, invpath,
				       RAW_SEARCH_TRANS2,
				       RAW_SEARCH_DATA_STANDARD, 0xf, NULL);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);
	status = torture_single_search(cli_dos, mem_ctx, invpath,
				       RAW_SEARCH_TRANS2,
				       RAW_SEARCH_DATA_STANDARD, 0xf, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidparam));

	{
		union smb_open o;
		o.openold.level = RAW_OPEN_OPEN;
		o.openold.in.open_mode = 0;
		o.openold.in.search_attrs = 0;
		o.openold.in.fname = invpath;

		status = smb_raw_open(cli_nt->tree, mem_ctx, &o);
		CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
		status = smb_raw_open(cli_dos->tree, mem_ctx, &o);
		CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

		ZERO_STRUCT(o);
		o.openx.level = RAW_OPEN_OPENX;
		o.openx.in.fname = invpath;
		o.openx.in.open_func = OPENX_OPEN_FUNC_OPEN;

		status = smb_raw_open(cli_nt->tree, mem_ctx, &o);
		CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
		status = smb_raw_open(cli_dos->tree, mem_ctx, &o);
		CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

		ZERO_STRUCT(o);
		o.mknew.level = RAW_OPEN_MKNEW;
		o.mknew.in.fname = invpath;

		status = smb_raw_open(cli_nt->tree, mem_ctx, &o);
		CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
		status = smb_raw_open(cli_dos->tree, mem_ctx, &o);
		CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

		ZERO_STRUCT(o);
		o.ntcreatex.level = RAW_OPEN_NTCREATEX;
		o.ntcreatex.in.fname = invpath;

		status = smb_raw_open(cli_nt->tree, mem_ctx, &o);
		CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
		status = smb_raw_open(cli_dos->tree, mem_ctx, &o);
		CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

		ZERO_STRUCT(o);
		o.nttrans.level = RAW_OPEN_NTTRANS_CREATE;
		o.nttrans.in.fname = invpath;

		status = smb_raw_open(cli_nt->tree, mem_ctx, &o);
		CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
		status = smb_raw_open(cli_dos->tree, mem_ctx, &o);
		CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

		/*
		 * TODO: Check t2open
		 */

#if 0
		/*
		 * This call seems completely broken on W2k3. It gives back a
		 * fid, and when you later want to close it the server returns
		 * INVALID_HANDLE....
		 */

		/*
		 * W2k3 puts the ctemp files into the root of the share, it
		 * seems to ignore the directory given. And, the file name
		 * given back seems to be bogus. The real file name is
		 * prepended with a "t"...
		 */

		ZERO_STRUCT(o);
		o.ctemp.level = RAW_OPEN_CTEMP;
		o.ctemp.in.directory = invpath;

		status = smb_raw_open(cli_nt->tree, mem_ctx, &o);
		if (NT_STATUS_IS_OK(status)) {
			smbcli_nt_delete_on_close(
				cli_nt->tree, o.ctemp.out.file.fnum, True);
			smbcli_close(cli_nt->tree, o.ctemp.out.file.fnum);
		}
		CHECK_STATUS(status, NT_STATUS_OK);
		status = smb_raw_open(cli_dos->tree, mem_ctx, &o);
		if (NT_STATUS_IS_OK(status)) {
			smbcli_nt_delete_on_close(
				cli_nt->tree, o.ctemp.out.file.fnum, True);
			smbcli_close(cli_nt->tree, o.ctemp.out.file.fnum);
		}
		CHECK_STATUS(status, NT_STATUS_OK);
#endif
	}

	status = smbcli_unlink(cli_nt->tree, invpath);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
	status = smbcli_unlink(cli_dos->tree, invpath);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_mkdir(cli_nt->tree, invpath);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
	status = smbcli_mkdir(cli_dos->tree, invpath);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_rmdir(cli_nt->tree, invpath);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
	status = smbcli_rmdir(cli_dos->tree, invpath);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_rename(cli_nt->tree, invpath, "");
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);
	status = smbcli_rename(cli_dos->tree, invpath, "");
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidpath));

	status = smbcli_rename(cli_nt->tree, "", invpath);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);
	status = smbcli_rename(cli_dos->tree, "", invpath);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRinvalidpath));

	status = smbcli_rename(cli_nt->tree, invpath, invpath);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
	status = smbcli_rename(cli_dos->tree, invpath, invpath);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	status = smbcli_qpathinfo(cli_nt->tree, invpath, NULL, NULL, NULL,
				  NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_PATH_NOT_FOUND);
	status = smbcli_qpathinfo(cli_dos->tree, invpath, NULL, NULL, NULL,
				  NULL, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS, ERRbadpath));

	goto done;

 fail:
	ret = False;

 done:
	if (cli_nt != NULL) {
		smbcli_deltree(cli_nt->tree, dirname);
		smbcli_unlink(cli_nt->tree, fname);
		torture_close_connection(cli_nt);
	}
	if (cli_dos != NULL) {
		torture_close_connection(cli_dos);
	}
	talloc_free(mem_ctx);

	return ret;
}
