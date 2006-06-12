/* 
   Unix SMB/CIFS implementation.
   Test samba3 hide unreadable/unwriteable
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

static void init_unixinfo_nochange(union smb_setfileinfo *info)
{
	ZERO_STRUCTP(info);
	info->unix_basic.level = RAW_SFILEINFO_UNIX_BASIC;
	info->unix_basic.in.mode = SMB_MODE_NO_CHANGE;

	info->unix_basic.in.end_of_file = SMB_SIZE_NO_CHANGE_HI;
	info->unix_basic.in.end_of_file <<= 32;
	info->unix_basic.in.end_of_file |= SMB_SIZE_NO_CHANGE_LO;
	
	info->unix_basic.in.num_bytes = SMB_SIZE_NO_CHANGE_HI;
	info->unix_basic.in.num_bytes <<= 32;
	info->unix_basic.in.num_bytes |= SMB_SIZE_NO_CHANGE_LO;
	
	info->unix_basic.in.status_change_time = SMB_TIME_NO_CHANGE_HI;
	info->unix_basic.in.status_change_time <<= 32;
	info->unix_basic.in.status_change_time = SMB_TIME_NO_CHANGE_LO;

	info->unix_basic.in.access_time = SMB_TIME_NO_CHANGE_HI;
	info->unix_basic.in.access_time <<= 32;
	info->unix_basic.in.access_time |= SMB_TIME_NO_CHANGE_LO;

	info->unix_basic.in.change_time = SMB_TIME_NO_CHANGE_HI;
	info->unix_basic.in.change_time <<= 32;
	info->unix_basic.in.change_time |= SMB_TIME_NO_CHANGE_LO;

	info->unix_basic.in.uid = SMB_UID_NO_CHANGE;
	info->unix_basic.in.gid = SMB_GID_NO_CHANGE;
}

struct list_state {
	const char *fname;
	BOOL visible;
};

static void set_visible(struct clilist_file_info *i, const char *mask,
			void *priv)
{
	struct list_state *state = priv;

	if (strcasecmp_m(state->fname, i->name) == 0)
		state->visible = True;
}

static BOOL is_visible(struct smbcli_tree *tree, const char *fname)
{
	struct list_state state;

	state.visible = False;
	state.fname = fname;

	if (smbcli_list(tree, "*.*", 0, set_visible, &state) < 0) {
		return False;
	}
	return state.visible;
}

static BOOL is_readable(struct smbcli_tree *tree, const char *fname)
{
	int fnum;
	fnum = smbcli_open(tree, fname, O_RDONLY, DENY_NONE);
	if (fnum < 0) {
		return False;
	}
	smbcli_close(tree, fnum);
	return True;
}

static BOOL is_writeable(TALLOC_CTX *mem_ctx, struct smbcli_tree *tree,
			 const char *fname)
{
	int fnum;
	fnum = smbcli_open(tree, fname, O_WRONLY, DENY_NONE);
	if (fnum < 0) {
		return False;
	}
	smbcli_close(tree, fnum);
	return True;
}

/*
 * This is not an exact method because there's a ton of reasons why a getatr
 * might fail. But for our purposes it's sufficient.
 */

static BOOL smbcli_file_exists(struct smbcli_tree *tree, const char *fname)
{
	return NT_STATUS_IS_OK(smbcli_getatr(tree, fname, NULL, NULL, NULL));
}

static NTSTATUS smbcli_chmod(struct smbcli_tree *tree, const char *fname,
			     uint64_t permissions)
{
	union smb_setfileinfo sfinfo;
	init_unixinfo_nochange(&sfinfo);
	sfinfo.unix_basic.in.file.path = fname;
	sfinfo.unix_basic.in.permissions = permissions;
	return smb_raw_setpathinfo(tree, &sfinfo);
}

static NTSTATUS second_tcon(TALLOC_CTX *mem_ctx,
			    struct smbcli_session *session,
			    const char *sharename,
			    struct smbcli_tree **res)
{
	union smb_tcon tcon;
	struct smbcli_tree *result;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;

	if ((tmp_ctx = talloc_new(mem_ctx)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result = smbcli_tree_init(session, tmp_ctx, False);
	if (result == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = 0;

	/* Ignore share mode security here */
	tcon.tconx.in.password = data_blob(NULL, 0);
	tcon.tconx.in.path = sharename;
	tcon.tconx.in.device = "????";

	status = smb_raw_tcon(result, tmp_ctx, &tcon);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	result->tid = tcon.tconx.out.tid;
	*res = talloc_steal(mem_ctx, result);
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

BOOL torture_samba3_hide(struct torture_context *torture)
{
	struct smbcli_state *cli;
	BOOL ret = False;
	TALLOC_CTX *mem_ctx;
	const char *fname = "test.txt";
	int fnum;
	NTSTATUS status;
	struct smbcli_tree *hideunread;
	struct smbcli_tree *hideunwrite;

	mem_ctx = talloc_init("torture_samba3_unixinfo");
	if (mem_ctx == NULL) {
		d_printf("talloc_init failed\n");
		return False;
	}

	if (!torture_open_connection_share(
		    mem_ctx, &cli, lp_parm_string(-1, "torture", "host"),
		    lp_parm_string(-1, "torture", "share"), NULL)) {
		d_printf("torture_open_connection_share failed\n");
		goto done;
	}

	status = second_tcon(mem_ctx, cli->session, "hideunread",
			     &hideunread);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("second_tcon(hideunread) failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	status = second_tcon(mem_ctx, cli->session, "hideunwrite",
			     &hideunwrite);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("second_tcon(hideunwrite) failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	status = smbcli_unlink(cli->tree, fname);
	if (NT_STATUS_EQUAL(status, NT_STATUS_CANNOT_DELETE)) {
		smbcli_setatr(cli->tree, fname, 0, -1);
		smbcli_unlink(cli->tree, fname);
	}

	fnum = smbcli_open(cli->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	if (fnum == -1) {
		d_printf("Failed to create %s - %s\n", fname,
			 smbcli_errstr(cli->tree));
		goto done;
	}

	smbcli_close(cli->tree, fnum);

	if (!smbcli_file_exists(cli->tree, fname)) {
		d_printf("%s does not exist\n", fname);
		goto done;
	}

	/* R/W file should be visible everywhere */

	status = smbcli_chmod(cli->tree, fname, UNIX_R_USR|UNIX_W_USR);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_chmod failed: %s\n", nt_errstr(status));
		goto done;
	}
	if (!is_writeable(mem_ctx, cli->tree, fname)) {
		d_printf("File not writable\n");
		goto done;
	}
	if (!is_readable(cli->tree, fname)) {
		d_printf("File not readable\n");
		goto done;
	}
	if (!is_visible(cli->tree, fname)) {
		d_printf("r/w file not visible via normal share\n");
		goto done;
	}
	if (!is_visible(hideunread, fname)) {
		d_printf("r/w file not visible via hide unreadable\n");
		goto done;
	}
	if (!is_visible(hideunwrite, fname)) {
		d_printf("r/w file not visible via hide unwriteable\n");
		goto done;
	}

	/* R/O file should not be visible via hide unwriteable files */

	status = smbcli_chmod(cli->tree, fname, UNIX_R_USR);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_chmod failed: %s\n", nt_errstr(status));
		goto done;
	}
	if (is_writeable(mem_ctx, cli->tree, fname)) {
		d_printf("r/o is writable\n");
		goto done;
	}
	if (!is_readable(cli->tree, fname)) {
		d_printf("r/o not readable\n");
		goto done;
	}
	if (!is_visible(cli->tree, fname)) {
		d_printf("r/o file not visible via normal share\n");
		goto done;
	}
	if (!is_visible(hideunread, fname)) {
		d_printf("r/o file not visible via hide unreadable\n");
		goto done;
	}
	if (is_visible(hideunwrite, fname)) {
		d_printf("r/o file visible via hide unwriteable\n");
		goto done;
	}

	/* inaccessible file should be only visible on normal share */

	status = smbcli_chmod(cli->tree, fname, 0);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_chmod failed: %s\n", nt_errstr(status));
		goto done;
	}
	if (is_writeable(mem_ctx, cli->tree, fname)) {
		d_printf("inaccessible file is writable\n");
		goto done;
	}
	if (is_readable(cli->tree, fname)) {
		d_printf("inaccessible file is readable\n");
		goto done;
	}
	if (!is_visible(cli->tree, fname)) {
		d_printf("inaccessible file not visible via normal share\n");
		goto done;
	}
	if (is_visible(hideunread, fname)) {
		d_printf("inaccessible file visible via hide unreadable\n");
		goto done;
	}
	if (is_visible(hideunwrite, fname)) {
		d_printf("inaccessible file visible via hide unwriteable\n");
		goto done;
	}


	ret = True;

 done:
	talloc_free(mem_ctx);
	return ret;
}

