/*
   Unix SMB/CIFS implementation.
   Test cleanup behaviour
   Copyright (C) Volker Lendecke 2011

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
#include "torture/proto.h"
#include "system/filesys.h"
#include "libsmb/libsmb.h"
#include "libcli/smb/smbXcli_base.h"

bool run_cleanup1(int dummy)
{
	struct cli_state *cli;
	const char *fname = "\\cleanup1";
	uint16_t fnum;
	NTSTATUS status;

	printf("Starting cleanup1 test\n");

	if (!torture_open_connection(&cli, 0)) {
		return false;
	}
	status = cli_openx(cli, fname, O_RDWR|O_CREAT, DENY_ALL, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}
	status = smbXcli_conn_samba_suicide(cli->conn, 1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_conn_samba_suicide failed: %s\n",
		       nt_errstr(status));
		return false;
	}

	if (!torture_open_connection(&cli, 1)) {
		return false;
	}
	status = cli_openx(cli, fname, O_RDWR|O_CREAT, DENY_ALL, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("2nd open of %s failed (%s)\n", fname,
		       nt_errstr(status));
		return false;
	}
	cli_close(cli, fnum);

	status = cli_unlink(cli, fname, 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_unlink failed: %s\n", nt_errstr(status));
		goto done;
	}
done:
	torture_close_connection(cli);
	return NT_STATUS_IS_OK(status);
}
