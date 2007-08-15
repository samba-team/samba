/* 
   Unix SMB/CIFS implementation.
   Test some misc Samba3 code paths
   Copyright (C) Volker Lendecke 2006
   
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
        } else if ((flags & O_ACCMODE) == O_RDONLY) {
                accessmode |= OPENX_MODE_ACCESS_READ;
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

static NTSTATUS raw_smbcli_t2open(struct smbcli_tree *tree, const char *fname, int flags, int share_mode, int *fnum)
{
        union smb_open io;
        uint_t openfn=0;
        uint_t accessmode=0;
        TALLOC_CTX *mem_ctx;
        NTSTATUS status;

        mem_ctx = talloc_init("raw_t2open");
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
        } else if ((flags & O_ACCMODE) == O_RDONLY) {
                accessmode |= OPENX_MODE_ACCESS_READ;
	}

#if defined(O_SYNC)
        if ((flags & O_SYNC) == O_SYNC) {
                accessmode |= OPENX_MODE_WRITE_THRU;
        }
#endif

        if (share_mode == DENY_FCB) {
                accessmode = OPENX_MODE_ACCESS_FCB | OPENX_MODE_DENY_FCB;
        }

	memset(&io, '\0', sizeof(io));
        io.t2open.level = RAW_OPEN_T2OPEN;
        io.t2open.in.flags = 0;
        io.t2open.in.open_mode = accessmode;
        io.t2open.in.search_attrs = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
        io.t2open.in.file_attrs = 0;
        io.t2open.in.write_time = 0;
        io.t2open.in.open_func = openfn;
        io.t2open.in.size = 0;
        io.t2open.in.timeout = 0;
        io.t2open.in.fname = fname;

        io.t2open.in.num_eas = 1;
	io.t2open.in.eas = talloc_array(mem_ctx, struct ea_struct, io.t2open.in.num_eas);
	io.t2open.in.eas[0].flags = 0;
	io.t2open.in.eas[0].name.s = ".CLASSINFO";
	io.t2open.in.eas[0].value = data_blob_talloc(mem_ctx, "first value", 11);

        status = smb_raw_open(tree, mem_ctx, &io);
        talloc_free(mem_ctx);

        if (fnum && NT_STATUS_IS_OK(status)) {
                *fnum = io.openx.out.file.fnum;
        }

        return status;
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

	/* Let's test EEXIST error code mapping. */
	status = raw_smbcli_open(cli_nt->tree, fpath, O_RDONLY | O_CREAT| O_EXCL, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_COLLISION);
	status = raw_smbcli_open(cli_dos->tree, fpath, O_RDONLY | O_CREAT| O_EXCL, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS,ERRfilexists));

	status = raw_smbcli_t2open(cli_nt->tree, fpath, O_RDONLY | O_CREAT| O_EXCL, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_COLLISION);
	status = raw_smbcli_t2open(cli_dos->tree, fpath, O_RDONLY | O_CREAT| O_EXCL, DENY_NONE, NULL);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRDOS,ERRfilexists));

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
