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
#include "libcli/security/security.h"

bool run_cleanup1(int dummy)
{
	struct cli_state *cli;
	const char *fname = "\\cleanup1";
	uint16_t fnum;
	NTSTATUS status;

	printf("CLEANUP1: Checking that a conflicting share mode is cleaned "
	       "up\n");

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
	status = cli_ntcreate(
		cli, fname, 0,
		FILE_GENERIC_READ|FILE_GENERIC_WRITE|DELETE_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN, FILE_DELETE_ON_CLOSE, 0, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("2nd open of %s failed (%s)\n", fname,
		       nt_errstr(status));
		return false;
	}
	cli_close(cli, fnum);

	torture_close_connection(cli);
	return NT_STATUS_IS_OK(status);
}

bool run_cleanup2(int dummy)
{
	struct cli_state *cli1, *cli2;
	const char *fname = "\\cleanup2";
	uint16_t fnum1, fnum2;
	NTSTATUS status;
	char buf;

	printf("CLEANUP2: Checking that a conflicting brlock is cleaned up\n");

	if (!torture_open_connection(&cli1, 0)) {
		return false;
	}
	status = cli_ntcreate(
		cli1, fname, 0, FILE_GENERIC_READ|FILE_GENERIC_WRITE,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OVERWRITE_IF, 0, 0, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}
	status = cli_lock32(cli1, fnum1, 0, 1, 0, WRITE_LOCK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("lock failed (%s)\n", nt_errstr(status));
		return false;
	}

	/*
	 * Check the file is indeed locked
	 */
	if (!torture_open_connection(&cli2, 0)) {
		return false;
	}
	status = cli_ntcreate(
		cli2, fname, 0, FILE_GENERIC_READ|FILE_GENERIC_WRITE,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN, 0, 0, &fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}
	buf = 'x';
	status = cli_smbwrite(cli2, fnum2, &buf, 0, 1, NULL);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_LOCK_CONFLICT)) {
		printf("write succeeded\n");
		return false;
	}

	/*
	 * Kill the lock holder
	 */
	status = smbXcli_conn_samba_suicide(cli1->conn, 1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_conn_samba_suicide failed: %s\n",
		       nt_errstr(status));
		return false;
	}

	/*
	 * Right now we don't clean up immediately. Re-open the 2nd connection.
	 */
#if 1
	cli_shutdown(cli2);
	if (!torture_open_connection(&cli2, 0)) {
		return false;
	}
	status = cli_ntcreate(
		cli2, fname, 0, FILE_GENERIC_READ|FILE_GENERIC_WRITE,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN, 0, 0, &fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}
#endif
	status = cli_smbwrite(cli2, fnum2, &buf, 0, 1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("write failed: %s\n", nt_errstr(status));
		return false;
	}
	return true;
}
