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
#include "locking/proto.h"
#include "torture/proto.h"
#include "system/filesys.h"
#include "system/select.h"
#include "libsmb/libsmb.h"
#include "libcli/smb/smbXcli_base.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/open_files.h"

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

static bool create_stale_share_mode_entry(const char *fname,
					  struct file_id *p_id)
{
	struct cli_state *cli;
	uint16_t fnum;
	NTSTATUS status;
	SMB_STRUCT_STAT sbuf;
	struct file_id id;

	if (!torture_open_connection(&cli, 0)) {
		return false;
	}

	status = torture_setup_unix_extensions(cli);
	if (!NT_STATUS_IS_OK(status)) {
		printf("torture_setup_unix_extensions failed: %s\n",
		       nt_errstr(status));
		return false;
	}
	status = cli_openx(cli, fname, O_RDWR|O_CREAT, DENY_ALL, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("open of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}
	status = cli_posix_stat(cli, fname, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_stat failed: %s\n", nt_errstr(status));
		return false;
	}
	status = smbXcli_conn_samba_suicide(cli->conn, 1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_conn_samba_suicide failed: %s\n",
		       nt_errstr(status));
		return false;
	}

	id.devid = sbuf.st_ex_rdev;
	id.inode = sbuf.st_ex_ino;
	id.extid = 0;

	poll(NULL, 0, 1000);

	*p_id = id;
	return true;
}

static bool corrupt_dummy(struct share_mode_data *d)
{
	return true;
}

static bool invalidate_sharemode(struct share_mode_data *d)
{
	d->share_modes[0].op_type =
		OPLOCK_EXCLUSIVE|OPLOCK_BATCH|OPLOCK_LEVEL_II;
	d->modified = true;
	return true;
}

static bool duplicate_entry(struct share_mode_data *d, int i)
{
	struct share_mode_entry *tmp;

	if (i >= d->num_share_modes) {
		return false;
	}

	tmp = talloc_realloc(d, d->share_modes, struct share_mode_entry,
			     d->num_share_modes + 1);
	if (tmp == NULL) {
		return false;
	}
	d->share_modes = tmp;
	d->num_share_modes += 1;
	d->share_modes[d->num_share_modes-1] = d->share_modes[i];
	d->modified = true;
	return true;
}

static bool create_duplicate_batch(struct share_mode_data *d)
{
	if (d->num_share_modes != 1) {
		return false;
	}
	d->share_modes[0].op_type = OPLOCK_BATCH;
	if (!duplicate_entry(d, 0)) {
		return false;
	}
	return true;
}

struct corruption_fns {
	bool (*fn)(struct share_mode_data *d);
	const char *descr;
};

bool run_cleanup3(int dummy)
{
	struct cli_state *cli;
	const char *fname = "cleanup3";
	uint16_t fnum;
	NTSTATUS status;
	struct share_mode_lock *lck;
	struct file_id id;
	size_t i;

	struct corruption_fns fns[] = {
		{ corrupt_dummy, "no corruption" },
		{ invalidate_sharemode, "invalidate_sharemode" },
		{ create_duplicate_batch, "create_duplicate_batch" },
	};

	printf("CLEANUP3: Checking that a share mode is cleaned up on "
	       "conflict\n");

	for (i=0; i<ARRAY_SIZE(fns); i++) {

		printf("testing %s\n", fns[i].descr);

		if (!create_stale_share_mode_entry(fname, &id)) {
			printf("create_stale_entry failed\n");
			return false;
		}

		printf("%d %d %d\n", (int)id.devid, (int)id.inode,
		       (int)id.extid);

		if (!locking_init()) {
			printf("locking_init failed\n");
			return false;
		}
		lck = get_existing_share_mode_lock(talloc_tos(), id);
		if (lck == NULL) {
			printf("get_existing_share_mode_lock failed\n");
			return false;
		}
		if (lck->data->num_share_modes != 1) {
			printf("get_existing_share_mode_lock did clean up\n");
			return false;
		}

		fns[i].fn(lck->data);

		TALLOC_FREE(lck);

		if (!torture_open_connection(&cli, 0)) {
			return false;
		}
		status = cli_openx(cli, fname, O_RDWR|O_CREAT, DENY_ALL,
				   &fnum);
		if (!NT_STATUS_IS_OK(status)) {
			printf("open of %s failed (%s)\n", fname,
			       nt_errstr(status));
			return false;
		}
		lck = get_existing_share_mode_lock(talloc_tos(), id);
		if (lck == NULL) {
			printf("get_existing_share_mode_lock failed\n");
			return false;
		}
		if (lck->data->num_share_modes != 1) {
			printf("conflicting open did not clean up\n");
			return false;
		}
		TALLOC_FREE(lck);

		torture_close_connection(cli);
	}

	return true;
}

bool run_cleanup4(int dummy)
{
	struct cli_state *cli1, *cli2;
	const char *fname = "\\cleanup4";
	uint16_t fnum1, fnum2;
	NTSTATUS status;

	printf("CLEANUP4: Checking that a conflicting share mode is cleaned "
	       "up\n");

	if (!torture_open_connection(&cli1, 0)) {
		return false;
	}
	if (!torture_open_connection(&cli2, 0)) {
		return false;
	}

	status = cli_ntcreate(
		cli1, fname, 0,
		FILE_GENERIC_READ|DELETE_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_DELETE,
		FILE_OVERWRITE_IF, 0, 0, &fnum1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("creating file failed: %s\n",
		       nt_errstr(status));
		return false;
	}

	status = cli_ntcreate(
		cli2, fname, 0,
		FILE_GENERIC_READ|DELETE_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_DELETE,
		FILE_OPEN, 0, 0, &fnum2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("opening file 1st time failed: %s\n",
		       nt_errstr(status));
		return false;
	}

	status = smbXcli_conn_samba_suicide(cli1->conn, 1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_conn_samba_suicide failed: %s\n",
		       nt_errstr(status));
		return false;
	}

	/*
	 * The next open will conflict with both opens above. The first open
	 * above will be correctly cleaned up. A bug in smbd iterating over
	 * the share mode array made it skip the share conflict check for the
	 * second open. Trigger this bug.
	 */

	status = cli_ntcreate(
		cli2, fname, 0,
		FILE_GENERIC_WRITE|DELETE_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN, 0, 0, &fnum2);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
		printf("opening file 2nd time returned: %s\n",
		       nt_errstr(status));
		return false;
	}

	return true;
}
