/*
 * Unix SMB/CIFS implementation.
 * Test pthreadpool_tevent
 * Copyright (C) Volker Lendecke 2018
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "torture/proto.h"
#include "libsmb/libsmb.h"
#include "libcli/security/security.h"

static NTSTATUS servertime(
	struct cli_state *cli, const char *fname, struct timeval *tv)
{
	struct smb_create_returns cr;
	NTSTATUS status;
	uint16_t fnum;

	status = cli_ntcreate(
		cli,
		fname,
		0,
		FILE_GENERIC_WRITE|DELETE_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_CREATE,
		FILE_DELETE_ON_CLOSE,
		0,
		&fnum,
		&cr);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_ntcreate failed: %s\n", nt_errstr(status));
		return status;
	}

	status = cli_close(cli, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_close failed: %s\n", nt_errstr(status));
		return status;
	}

	nttime_to_timeval(tv, cr.creation_time);

	return NT_STATUS_OK;
}

struct have_file_state {
	bool found;
	const char *fname;
};

static NTSTATUS have_file_fn(const char *mntpoint,
			     struct file_info *f,
			     const char *mask,
			     void *private_data)
{
	struct have_file_state *state = private_data;
	state->found |= strequal(f->name, state->fname);
	return NT_STATUS_OK;
}

static bool have_file(struct cli_state *cli, const char *fname)
{
	struct have_file_state state = { .fname = fname };
	NTSTATUS status;

	status = cli_list(
		cli,
		"*.*",
		FILE_ATTRIBUTE_DIRECTORY|
		FILE_ATTRIBUTE_SYSTEM|
		FILE_ATTRIBUTE_HIDDEN,
		have_file_fn,
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_list failed: %s\n", nt_errstr(status));
		return false;
	}

	return state.found;
}

bool run_hidenewfiles(int dummy)
{
	const char *tsname = "timestamp.txt";
	const char *fname = "new_hidden.txt";
	struct cli_state *cli;
	struct smb_create_returns cr;
	struct timeval create_time;
	uint16_t fnum;
	NTSTATUS status;
	bool ret = false;
	bool gotit = false;
	bool ok;

	/* what is configure in smb.conf */
	unsigned hideunreadable_seconds = 5;

	ok = torture_open_connection(&cli, 0);
	if (!ok) {
		return false;
	}

	cli_unlink(cli, tsname, FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN);
	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(
		cli,
		fname,
		0,
		FILE_GENERIC_WRITE|DELETE_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_CREATE,
		0,
		0,
		&fnum,
		&cr);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_ntcreate failed: %s\n", nt_errstr(status));
		return false;
	}
	nttime_to_timeval(&create_time, cr.last_write_time);

	while (!gotit) {
		struct timeval now;
		double age;

		gotit = have_file(cli, fname);

		status = servertime(cli, tsname, &now);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("servertime failed: %s\n",
				 nt_errstr(status));
			goto fail;
		}
		age = timeval_elapsed2(&create_time, &now);

		if ((age < hideunreadable_seconds) && gotit) {
			d_printf("Found file at age of %f\n", age);
			goto fail;
		}
		if ((age > (hideunreadable_seconds*10)) && !gotit) {
			d_printf("Did not find file after %f seconds\n", age);
			goto fail;
		}
		if (gotit) {
			break;
		}

		smb_msleep(1000);
	}

	ret = true;
fail:
	cli_nt_delete_on_close(cli, fnum, true);
	cli_close(cli, fnum);

	return ret;
}
