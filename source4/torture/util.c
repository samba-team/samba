/* 
   Unix SMB/CIFS implementation.
   SMB torture tester utility functions
   Copyright (C) Jelmer Vernooij 2006
   
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
#include "system/filesys.h"
#include "system/wait.h"
#include "torture/torture.h"
#include "libcli/raw/interfaces.h"
#include "libcli/raw/libcliraw.h"

/**
 create a temporary directory.
*/
_PUBLIC_ NTSTATUS torture_temp_dir(TALLOC_CTX *mem_ctx, const char *prefix, 
								   char **tempdir)
{
	const char *basedir = lp_parm_string(-1, "torture", "basedir");
	if (basedir == NULL) basedir = ".";
	*tempdir = talloc_asprintf(mem_ctx, "%s/%s.XXXXXX", 
							   basedir, prefix);

	if (mkdtemp(*tempdir) == NULL)
		return NT_STATUS_UNSUCCESSFUL;

	return NT_STATUS_OK;
}

/**
  check if 2 NTTIMEs are equal.
*/
BOOL nt_time_equal(NTTIME *t1, NTTIME *t2)
{
	return *t1 == *t2;
}

NTSTATUS torture_second_tcon(TALLOC_CTX *mem_ctx,
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
	tcon.tconx.in.device = "?????";

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
