/*
   Unix SMB/CIFS implementation.
   Copyright (C) Ralph Boehme 2020

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
#include "libcli/security/security.h"
#include "libsmb/clirap.h"
#include "libsmb/proto.h"
#include "../libcli/smb/smbXcli_base.h"
#include "util_sd.h"
#include "trans2.h"

extern struct cli_credentials *torture_creds;
extern fstring host, workgroup, share, password, username, myname;

struct posix_test_entry {
	const char *name;
	const char *target;
	const char *expected;
	uint32_t attr_win;
	uint32_t attr_lin;
	uint64_t returned_size;
	bool ok;
};

enum client_flavour { WINDOWS, POSIX };

struct posix_test_state {
	enum client_flavour flavour;
	struct posix_test_entry *entries;
};

static NTSTATUS posix_ls_fn(struct file_info *finfo,
			    const char *name,
			    void *_state)
{
	struct posix_test_state *state =
		(struct posix_test_state *)_state;
	struct posix_test_entry *e = state->entries;

	for (; e->name != NULL; e++) {
		uint32_t attr;
		if (!strequal(finfo->name, e->expected)) {
			continue;
		}
		if (state->flavour == WINDOWS) {
			attr = e->attr_win;
		} else {
			attr = e->attr_lin;
		}
		if (attr != finfo->attr) {
			break;
		}
		e->ok = true;
		e->returned_size = finfo->size;
		break;
	}

	return NT_STATUS_OK;
}

static void posix_test_entries_reset(struct posix_test_state *state)
{
	struct posix_test_entry *e = state->entries;

	for (; e->name != NULL; e++) {
		e->ok = false;
		e->returned_size = 0;
	}
}

static bool posix_test_entry_check(struct posix_test_state *state,
				   const char *name,
				   bool expected,
				   uint64_t expected_size)
{
	struct posix_test_entry *e = state->entries;
	bool result = false;

	for (; e->name != NULL; e++) {
		if (strequal(name, e->name)) {
			result = e->ok;
			break;
		}
	}
	if (e->name == NULL) {
		printf("test failed, unknown name: %s\n", name);
		return false;
	}

	if (expected == result) {
		return true;
	}

	printf("test failed, %s: %s\n",
	       expected ? "missing" : "unexpected",
	       name);

	return false;
}

/*
  Test non-POSIX vs POSIX ls * of symlinks
 */
bool run_posix_ls_wildcard_test(int dummy)
{
	TALLOC_CTX *frame = NULL;
	struct cli_state *cli_unix = NULL;
	struct cli_state *cli_win = NULL;
	uint16_t fnum = (uint16_t)-1;
	NTSTATUS status;
	const char *file = "file";
	const char *symlnk_dangling = "dangling";
	const char *symlnk_dst_dangling = "xxxxxxx";
	const char *symlnk_in_share = "symlnk_in_share";
	const char *symlnk_dst_in_share = file;
	const char *symlnk_outside_share = "symlnk_outside_share";
	const char *symlnk_dst_outside_share = "/etc/passwd";
	struct posix_test_entry entries[] = {
		{
			.name = file,
			.target = NULL,
			.expected = file,
			.attr_win = FILE_ATTRIBUTE_ARCHIVE,
			.attr_lin = FILE_ATTRIBUTE_ARCHIVE,
		}, {
			.name = symlnk_dangling,
			.target = symlnk_dst_dangling,
			.expected = symlnk_dangling,
			.attr_win = FILE_ATTRIBUTE_INVALID,
			.attr_lin = FILE_ATTRIBUTE_NORMAL,
		}, {
			.name = symlnk_in_share,
			.target = symlnk_dst_in_share,
			.expected = symlnk_in_share,
			.attr_win = FILE_ATTRIBUTE_ARCHIVE,
			.attr_lin = FILE_ATTRIBUTE_NORMAL,
		}, {
			.name = symlnk_outside_share,
			.target = symlnk_dst_outside_share,
			.expected = symlnk_outside_share,
			.attr_win = FILE_ATTRIBUTE_INVALID,
			.attr_lin = FILE_ATTRIBUTE_NORMAL,
		}, {
			.name = NULL,
		}
	};
	struct posix_test_state _state = {
		.entries = entries,
	};
	struct posix_test_state *state = &_state;
	int i;
	bool correct = false;

	frame = talloc_stackframe();

	printf("Starting POSIX-LS-WILDCARD test\n");

	if (!torture_open_connection(&cli_unix, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	if (!torture_open_connection(&cli_win, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	torture_conn_set_sockopt(cli_unix);
	torture_conn_set_sockopt(cli_win);

	status = torture_setup_unix_extensions(cli_unix);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	cli_posix_unlink(cli_unix, file);
	cli_posix_unlink(cli_unix, symlnk_dangling);
	cli_posix_unlink(cli_unix, symlnk_in_share);
	cli_posix_unlink(cli_unix, symlnk_outside_share);

	status = cli_posix_open(cli_unix,
				file,
				O_RDWR|O_CREAT,
				0666,
				&fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_open of %s failed error %s\n",
		       file,
		       nt_errstr(status));
		goto out;
	}

	status = cli_close(cli_unix, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_close failed %s\n", nt_errstr(status));
		goto out;
	}
	fnum = (uint16_t)-1;

	for (i = 0; entries[i].name != NULL; i++) {
		if (entries[i].target == NULL) {
			continue;
		}
		status = cli_posix_symlink(cli_unix,
					   entries[i].target,
					   entries[i].name);
		if (!NT_STATUS_IS_OK(status)) {
			printf("POSIX symlink of %s failed (%s)\n",
			       entries[i].name, nt_errstr(status));
			goto out;
		}
	}

	printf("Doing Windows ls *\n");
	state->flavour = WINDOWS;

	status = cli_list(cli_win, "*", 0, posix_ls_fn, state);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_list failed %s\n", nt_errstr(status));
		goto out;
	}

	if (!posix_test_entry_check(state, file, true, 0)) {
		goto out;
	}
	if (!posix_test_entry_check(state, symlnk_dangling, false, 0)) {
		goto out;
	}
	if (!posix_test_entry_check(state, symlnk_outside_share, false, 0)) {
		goto out;
	}
	if (!posix_test_entry_check(state, symlnk_in_share, true, 0)) {
		goto out;
	}

	posix_test_entries_reset(state);

	printf("Doing POSIX ls *\n");
	state->flavour = POSIX;

	status = cli_list(cli_unix, "*", 0, posix_ls_fn, state);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_close failed %s\n", nt_errstr(status));
		goto out;
	}

	if (!posix_test_entry_check(state, file, true, 0)) {
		goto out;
	}
	if (!posix_test_entry_check(state,
				    symlnk_dangling,
				    true,
				    strlen(symlnk_dst_dangling)))
	{
		goto out;
	}
	if (!posix_test_entry_check(state,
				    symlnk_outside_share,
				    true,
				    strlen(symlnk_dst_outside_share)))
	{
		goto out;
	}
	if (!posix_test_entry_check(state,
				    symlnk_in_share,
				    true,
				    strlen(symlnk_dst_in_share))) {
		goto out;
	}

	printf("POSIX-LS-WILDCARD test passed\n");
	correct = true;

out:
	cli_posix_unlink(cli_unix, file);
	cli_posix_unlink(cli_unix, symlnk_dangling);
	cli_posix_unlink(cli_unix, symlnk_in_share);
	cli_posix_unlink(cli_unix, symlnk_outside_share);

	if (!torture_close_connection(cli_unix)) {
		correct = false;
	}
	if (!torture_close_connection(cli_win)) {
		correct = false;
	}

	TALLOC_FREE(frame);
	return correct;
}

/*
  Test non-POSIX vs POSIX ls single of symlinks
 */
bool run_posix_ls_single_test(int dummy)
{
	TALLOC_CTX *frame = NULL;
	struct cli_state *cli_unix = NULL;
	struct cli_state *cli_win = NULL;
	uint16_t fnum = (uint16_t)-1;
	NTSTATUS status;
	const char *file = "file";
	const char *symlnk_dangling = "dangling";
	const char *symlnk_dst_dangling = "xxxxxxx";
	const char *symlnk_in_share = "symlnk_in_share";
	const char *symlnk_dst_in_share = file;
	const char *symlnk_outside_share = "symlnk_outside_share";
	const char *symlnk_dst_outside_share = "/etc/passwd";
	struct posix_test_entry entries[] = {
		{
			.name = file,
			.target = NULL,
			.expected = file,
			.attr_win = FILE_ATTRIBUTE_ARCHIVE,
			.attr_lin = FILE_ATTRIBUTE_ARCHIVE,
		}, {
			.name = symlnk_dangling,
			.target = symlnk_dst_dangling,
			.expected = symlnk_dangling,
			.attr_win = FILE_ATTRIBUTE_INVALID,
			.attr_lin = FILE_ATTRIBUTE_NORMAL,
		}, {
			.name = symlnk_in_share,
			.target = symlnk_dst_in_share,
			.expected = symlnk_in_share,
			.attr_win = FILE_ATTRIBUTE_ARCHIVE,
			.attr_lin = FILE_ATTRIBUTE_NORMAL,
		}, {
			.name = symlnk_outside_share,
			.target = symlnk_dst_outside_share,
			.expected = symlnk_outside_share,
			.attr_win = FILE_ATTRIBUTE_INVALID,
			.attr_lin = FILE_ATTRIBUTE_NORMAL,
		}, {
			.name = NULL,
		}
	};
	struct posix_test_state _state = {
		.entries = &entries[0],
	};
	struct posix_test_state *state = &_state;
	int i;
	bool correct = false;

	frame = talloc_stackframe();

	printf("Starting POSIX-LS-SINGLE test\n");

	if (!torture_open_connection(&cli_unix, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	if (!torture_init_connection(&cli_win)) {
		TALLOC_FREE(frame);
		return false;
	}

	status = smbXcli_negprot(cli_win->conn,
				 cli_win->timeout,
				 lp_client_min_protocol(),
				 lp_client_max_protocol(),
				 NULL,
				 NULL,
				 NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		TALLOC_FREE(frame);
		return false;
	}

	status = cli_session_setup_creds(cli_win, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_sesssetup returned %s\n", nt_errstr(status));
		TALLOC_FREE(frame);
		return false;
	}

	status = cli_tree_connect(cli_win, share, "?????", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		TALLOC_FREE(frame);
		return false;
	}
	torture_conn_set_sockopt(cli_unix);
	torture_conn_set_sockopt(cli_win);

	status = torture_setup_unix_extensions(cli_unix);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	cli_posix_unlink(cli_unix, file);
	cli_posix_unlink(cli_unix, symlnk_dangling);
	cli_posix_unlink(cli_unix, symlnk_in_share);
	cli_posix_unlink(cli_unix, symlnk_outside_share);

	status = cli_posix_open(cli_unix,
				file,
				O_RDWR|O_CREAT,
				0666,
				&fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_open of %s failed error %s\n",
		       file,
		       nt_errstr(status));
		goto out;
	}

	status = cli_close(cli_unix, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_close failed %s\n", nt_errstr(status));
		goto out;
	}
	fnum = (uint16_t)-1;

	for (i = 0; entries[i].name != NULL; i++) {
		if (entries[i].target == NULL) {
			continue;
		}
		status = cli_posix_symlink(cli_unix,
					   entries[i].target,
					   entries[i].name);
		if (!NT_STATUS_IS_OK(status)) {
			printf("POSIX symlink of %s failed (%s)\n",
			       symlnk_dangling, nt_errstr(status));
			goto out;
		}
	}

	printf("Doing Windows ls single\n");
	state->flavour = WINDOWS;

	cli_list(cli_win, file, 0, posix_ls_fn, state);
	cli_list(cli_win, symlnk_dangling, 0, posix_ls_fn, state);
	cli_list(cli_win, symlnk_outside_share, 0, posix_ls_fn, state);
	cli_list(cli_win, symlnk_in_share, 0, posix_ls_fn, state);

	if (!posix_test_entry_check(state, file, true, 0)) {
		goto out;
	}
	if (!posix_test_entry_check(state, symlnk_dangling, false, 0)) {
		goto out;
	}
	if (!posix_test_entry_check(state, symlnk_outside_share, false, 0)) {
		goto out;
	}
	if (!posix_test_entry_check(state, symlnk_in_share, true, 0)) {
		goto out;
	}

	posix_test_entries_reset(state);

	printf("Doing POSIX ls single\n");
	state->flavour = POSIX;

	cli_list(cli_unix, file, 0, posix_ls_fn, state);
	cli_list(cli_unix, symlnk_dangling, 0, posix_ls_fn, state);
	cli_list(cli_unix, symlnk_outside_share, 0, posix_ls_fn, state);
	cli_list(cli_unix, symlnk_in_share, 0, posix_ls_fn, state);

	if (!posix_test_entry_check(state, file, true, 0)) {
		goto out;
	}
	if (!posix_test_entry_check(state,
				    symlnk_dangling,
				    true,
				    strlen(symlnk_dst_dangling)))
	{
		goto out;
	}
	if (!posix_test_entry_check(state,
				    symlnk_outside_share,
				    true,
				    strlen(symlnk_dst_outside_share)))
	{
		goto out;
	}
	if (!posix_test_entry_check(state,
				    symlnk_in_share,
				    true,
				    strlen(symlnk_dst_in_share))) {
		goto out;
	}

	printf("POSIX-LS-SINGLE test passed\n");
	correct = true;

out:
	cli_posix_unlink(cli_unix, file);
	cli_posix_unlink(cli_unix, symlnk_dangling);
	cli_posix_unlink(cli_unix, symlnk_in_share);
	cli_posix_unlink(cli_unix, symlnk_outside_share);

	if (!torture_close_connection(cli_unix)) {
		correct = false;
	}
	if (!torture_close_connection(cli_win)) {
		correct = false;
	}

	TALLOC_FREE(frame);
	return correct;
}

/*
  Test POSIX readlink of symlinks
 */
bool run_posix_readlink_test(int dummy)
{
	TALLOC_CTX *frame = NULL;
	struct cli_state *cli_unix = NULL;
	uint16_t fnum = (uint16_t)-1;
	NTSTATUS status;
	const char *file = "file";
	const char *symlnk_dangling = "dangling";
	const char *symlnk_dst_dangling = "xxxxxxx";
	const char *symlnk_in_share = "symlnk_in_share";
	const char *symlnk_dst_in_share = file;
	const char *symlnk_outside_share = "symlnk_outside_share";
	const char *symlnk_dst_outside_share = "/etc/passwd";
	struct posix_test_entry entries[] = {
		{
			.name = symlnk_dangling,
			.target = symlnk_dst_dangling,
			.expected = symlnk_dangling,
		}, {
			.name = symlnk_in_share,
			.target = symlnk_dst_in_share,
			.expected = symlnk_in_share,
		}, {
			.name = symlnk_outside_share,
			.target = symlnk_dst_outside_share,
			.expected = symlnk_outside_share,
		}, {
			.name = NULL,
		}
	};
	struct posix_test_state _state = {
		.entries = &entries[0],
	};
	struct posix_test_state *state = &_state;
	int i;
	bool correct = false;

	frame = talloc_stackframe();

	printf("Starting POSIX-READLINK test\n");
	state->flavour = POSIX;

	if (!torture_open_connection(&cli_unix, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	torture_conn_set_sockopt(cli_unix);

	status = torture_setup_unix_extensions(cli_unix);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	cli_posix_unlink(cli_unix, file);
	cli_posix_unlink(cli_unix, symlnk_dangling);
	cli_posix_unlink(cli_unix, symlnk_in_share);
	cli_posix_unlink(cli_unix, symlnk_outside_share);

	status = cli_posix_open(cli_unix,
				file,
				O_RDWR|O_CREAT,
				0666,
				&fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_open of %s failed error %s\n",
		       file,
		       nt_errstr(status));
		goto out;
	}

	status = cli_close(cli_unix, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_close failed %s\n", nt_errstr(status));
		goto out;
	}
	fnum = (uint16_t)-1;

	for (i = 0; entries[i].name != NULL; i++) {
		status = cli_posix_symlink(cli_unix,
					   entries[i].target,
					   entries[i].name);
		if (!NT_STATUS_IS_OK(status)) {
			printf("POSIX symlink of %s failed (%s)\n",
			       symlnk_dangling, nt_errstr(status));
			goto out;
		}
	}

	for (i = 0; entries[i].name != NULL; i++) {
		char *target = NULL;

		status = cli_readlink(
			cli_unix,
			entries[i].name,
			talloc_tos(),
			&target,
			NULL,
			NULL);
		if (!NT_STATUS_IS_OK(status)) {
			printf("POSIX readlink on %s failed (%s)\n",
			       entries[i].name, nt_errstr(status));
			goto out;
		}
		if (strequal(target, entries[i].target)) {
			entries[i].ok = true;
			entries[i].returned_size = strlen(target);
		}
	}

	if (!posix_test_entry_check(state,
				    symlnk_dangling,
				    true,
				    strlen(symlnk_dst_dangling)))
	{
		goto out;
	}
	if (!posix_test_entry_check(state,
				    symlnk_outside_share,
				    true,
				    strlen(symlnk_dst_outside_share)))
	{
		goto out;
	}
	if (!posix_test_entry_check(state,
				    symlnk_in_share,
				    true,
				    strlen(symlnk_dst_in_share))) {
		goto out;
	}

	printf("POSIX-READLINK test passed\n");
	correct = true;

out:
	cli_posix_unlink(cli_unix, file);
	cli_posix_unlink(cli_unix, symlnk_dangling);
	cli_posix_unlink(cli_unix, symlnk_in_share);
	cli_posix_unlink(cli_unix, symlnk_outside_share);

	if (!torture_close_connection(cli_unix)) {
		correct = false;
	}

	TALLOC_FREE(frame);
	return correct;
}

/*
  Test POSIX stat of symlinks
 */
bool run_posix_stat_test(int dummy)
{
	TALLOC_CTX *frame = NULL;
	struct cli_state *cli_unix = NULL;
	uint16_t fnum = (uint16_t)-1;
	NTSTATUS status;
	const char *file = "file";
	const char *symlnk_dangling = "dangling";
	const char *symlnk_dst_dangling = "xxxxxxx";
	const char *symlnk_in_share = "symlnk_in_share";
	const char *symlnk_dst_in_share = file;
	const char *symlnk_outside_share = "symlnk_outside_share";
	const char *symlnk_dst_outside_share = "/etc/passwd";
	struct posix_test_entry entries[] = {
		{
			.name = symlnk_dangling,
			.target = symlnk_dst_dangling,
			.expected = symlnk_dangling,
		}, {
			.name = symlnk_in_share,
			.target = symlnk_dst_in_share,
			.expected = symlnk_in_share,
		}, {
			.name = symlnk_outside_share,
			.target = symlnk_dst_outside_share,
			.expected = symlnk_outside_share,
		}, {
			.name = NULL,
		}
	};
	struct posix_test_state _state = {
		.entries = &entries[0],
	};
	struct posix_test_state *state = &_state;
	int i;
	bool correct = false;

	frame = talloc_stackframe();

	printf("Starting POSIX-STAT test\n");
	state->flavour = POSIX;

	if (!torture_open_connection(&cli_unix, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	torture_conn_set_sockopt(cli_unix);

	status = torture_setup_unix_extensions(cli_unix);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	cli_posix_unlink(cli_unix, file);
	cli_posix_unlink(cli_unix, symlnk_dangling);
	cli_posix_unlink(cli_unix, symlnk_in_share);
	cli_posix_unlink(cli_unix, symlnk_outside_share);

	status = cli_posix_open(cli_unix,
				file,
				O_RDWR|O_CREAT,
				0666,
				&fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_open of %s failed error %s\n",
		       file,
		       nt_errstr(status));
		goto out;
	}

	status = cli_close(cli_unix, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_close failed %s\n", nt_errstr(status));
		goto out;
	}
	fnum = (uint16_t)-1;

	for (i = 0; entries[i].name != NULL; i++) {
		status = cli_posix_symlink(cli_unix,
					   entries[i].target,
					   entries[i].name);
		if (!NT_STATUS_IS_OK(status)) {
			printf("POSIX symlink of %s failed (%s)\n",
			       symlnk_dangling, nt_errstr(status));
			goto out;
		}
	}

	for (i = 0; entries[i].name != NULL; i++) {
		SMB_STRUCT_STAT sbuf;

		status = cli_posix_stat(cli_unix,
					entries[i].name,
					&sbuf);
		if (!NT_STATUS_IS_OK(status)) {
			printf("POSIX stat on %s failed (%s)\n",
			       entries[i].name, nt_errstr(status));
			continue;
		}
		entries[i].ok = true;
		entries[i].returned_size = sbuf.st_ex_size;
	}

	if (!posix_test_entry_check(state,
				    symlnk_dangling,
				    true,
				    strlen(symlnk_dst_dangling)))
	{
		goto out;
	}
	if (!posix_test_entry_check(state,
				    symlnk_outside_share,
				    true,
				    strlen(symlnk_dst_outside_share)))
	{
		goto out;
	}
	if (!posix_test_entry_check(state,
				    symlnk_in_share,
				    true,
				    strlen(symlnk_dst_in_share))) {
		goto out;
	}

	printf("POSIX-STAT test passed\n");
	correct = true;

out:
	cli_posix_unlink(cli_unix, file);
	cli_posix_unlink(cli_unix, symlnk_dangling);
	cli_posix_unlink(cli_unix, symlnk_in_share);
	cli_posix_unlink(cli_unix, symlnk_outside_share);

	if (!torture_close_connection(cli_unix)) {
		correct = false;
	}

	TALLOC_FREE(frame);
	return correct;
}

/*
  Test Creating files and directories directly
  under a symlink.
 */
bool run_posix_symlink_parent_test(int dummy)
{
	TALLOC_CTX *frame = NULL;
	struct cli_state *cli_unix = NULL;
	uint16_t fnum = (uint16_t)-1;
	NTSTATUS status;
	const char *parent_dir = "target_dir";
	const char *parent_symlink = "symlink_to_target_dir";
	const char *fname_real = "target_dir/file";
	const char *dname_real = "target_dir/dir";
	const char *fname_link = "symlink_to_target_dir/file";
	const char *dname_link = "symlink_to_target_dir/dir";
	const char *sname_link = "symlink_to_target_dir/symlink";
	const char *hname_link = "symlink_to_target_dir/hardlink";
	bool correct = false;

	frame = talloc_stackframe();

	printf("Starting POSIX-SYMLINK-PARENT test\n");

	if (!torture_open_connection(&cli_unix, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	torture_conn_set_sockopt(cli_unix);

	status = torture_setup_unix_extensions(cli_unix);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	/* Start with a clean slate. */
	cli_posix_unlink(cli_unix, fname_real);
	cli_posix_rmdir(cli_unix, dname_real);
	cli_posix_unlink(cli_unix, fname_link);
	cli_posix_rmdir(cli_unix, dname_link);
	cli_posix_unlink(cli_unix, sname_link);
	cli_posix_unlink(cli_unix, hname_link);
	cli_posix_unlink(cli_unix, parent_symlink);
	cli_posix_rmdir(cli_unix, parent_dir);

	/* Create parent_dir. */
	status = cli_posix_mkdir(cli_unix, parent_dir, 0777);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_mkdir of %s failed error %s\n",
		       parent_dir,
		       nt_errstr(status));
		goto out;
	}
	/* Create symlink to parent_dir. */
	status = cli_posix_symlink(cli_unix,
				   parent_dir,
				   parent_symlink);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_symlink of %s -> %s failed error %s\n",
		       parent_symlink,
		       parent_dir,
		       nt_errstr(status));
		goto out;
	}
	/* Try and create a directory under the symlink. */
	status = cli_posix_mkdir(cli_unix, dname_link, 0777);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_mkdir of %s failed error %s\n",
		       dname_link,
		       nt_errstr(status));
		goto out;
	}
	/* Try and create a file under the symlink. */
	status = cli_posix_open(cli_unix,
				fname_link,
				O_RDWR|O_CREAT,
				0666,
				&fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_open of %s failed error %s\n",
		       fname_link,
		       nt_errstr(status));
		goto out;
	}
	status = cli_close(cli_unix, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_close failed %s\n", nt_errstr(status));
		goto out;
	}
	fnum = (uint16_t)-1;

	/* Try and create a symlink to the file under the symlink. */
	status = cli_posix_symlink(cli_unix,
				   fname_link,
				   sname_link);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_symlink of %s -> %s failed error %s\n",
			sname_link,
			fname_link,
			nt_errstr(status));
		goto out;
	}

	/* Try and create a hardlink to the file under the symlink. */
	status = cli_posix_hardlink(cli_unix,
				   fname_link,
				   hname_link);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_hardlink of %s -> %s failed error %s\n",
			hname_link,
			fname_link,
			nt_errstr(status));
		goto out;
	}

	/* Ensure we can delete the symlink via the parent symlink */
	status = cli_posix_unlink(cli_unix, sname_link);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_unlink of %s failed error %s\n",
		       sname_link,
		       nt_errstr(status));
		goto out;
	}

	/* Ensure we can delete the hardlink via the parent symlink */
	status = cli_posix_unlink(cli_unix, hname_link);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_unlink of %s failed error %s\n",
		       hname_link,
		       nt_errstr(status));
		goto out;
	}

	/* Ensure we can delete the directory via the parent symlink */
	status = cli_posix_rmdir(cli_unix, dname_link);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_rmdir of %s failed error %s\n",
		       dname_link,
		       nt_errstr(status));
		goto out;
	}
	/* Ensure we can delete the file via the parent symlink */
	status = cli_posix_unlink(cli_unix, fname_link);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_unlink of %s failed error %s\n",
		       fname_link,
		       nt_errstr(status));
		goto out;
	}

	printf("POSIX-SYMLINK-PARENT test passed\n");
	correct = true;

out:
	if (fnum != (uint16_t)-1) {
		cli_close(cli_unix, fnum);
	}
	cli_posix_unlink(cli_unix, fname_real);
	cli_posix_rmdir(cli_unix, dname_real);
	cli_posix_unlink(cli_unix, fname_link);
	cli_posix_rmdir(cli_unix, dname_link);
	cli_posix_unlink(cli_unix, sname_link);
	cli_posix_unlink(cli_unix, hname_link);
	cli_posix_unlink(cli_unix, parent_symlink);
	cli_posix_rmdir(cli_unix, parent_dir);

	if (!torture_close_connection(cli_unix)) {
		correct = false;
	}

	TALLOC_FREE(frame);
	return correct;
}

/*
  Ensure we get an error when doing chmod on a symlink,
  whether it is pointing to a real object or dangling.
 */
bool run_posix_symlink_chmod_test(int dummy)
{
	TALLOC_CTX *frame = NULL;
	struct cli_state *cli_unix = NULL;
	NTSTATUS status;
	uint16_t fnum = (uint16_t)-1;
	const char *fname_real = "file_real";
	const char *fname_real_symlink = "file_real_symlink";
	const char *nonexist = "nonexist";
	const char *nonexist_symlink = "dangling_symlink";
	bool correct = false;

	frame = talloc_stackframe();

	printf("Starting POSIX-SYMLINK-CHMOD test\n");

	if (!torture_open_connection(&cli_unix, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	torture_conn_set_sockopt(cli_unix);

	status = torture_setup_unix_extensions(cli_unix);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	/* Start with a clean slate. */
	cli_posix_unlink(cli_unix, fname_real);
	cli_posix_unlink(cli_unix, fname_real_symlink);
	cli_posix_unlink(cli_unix, nonexist);
	cli_posix_unlink(cli_unix, nonexist_symlink);

	/* Create a real file. */
	status = cli_posix_open(cli_unix,
				fname_real,
				O_RDWR|O_CREAT,
				0644,
				&fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_open of %s failed error %s\n",
		       fname_real,
		       nt_errstr(status));
		goto out;
	}
	status = cli_close(cli_unix, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_close failed %s\n", nt_errstr(status));
		goto out;
	}
	fnum = (uint16_t)-1;

	/* Create symlink to real target. */
	status = cli_posix_symlink(cli_unix,
				   fname_real,
				   fname_real_symlink);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_symlink of %s -> %s failed error %s\n",
		       fname_real_symlink,
		       fname_real,
		       nt_errstr(status));
		goto out;
	}

	/* We should not be able to chmod symlinks that point to something. */
	status = cli_chmod(cli_unix, fname_real_symlink, 0777);

	/* This should fail with something other than server crashed. */
	if (NT_STATUS_IS_OK(status)) {
		printf("cli_chmod of %s succeeded (should have failed)\n",
		       fname_real_symlink);
		goto out;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_DISCONNECTED)) {
		/* Oops. Server crashed. */
		printf("cli_chmod of %s failed error %s\n",
		       fname_real_symlink,
		       nt_errstr(status));
		goto out;
	}
	/* Any other failure is ok. */

	/* Now create symlink to non-existing target. */
	status = cli_posix_symlink(cli_unix,
				   nonexist,
				   nonexist_symlink);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_symlink of %s -> %s failed error %s\n",
		       nonexist_symlink,
		       nonexist,
		       nt_errstr(status));
		goto out;
	}

	/* We should not be able to chmod symlinks that point to nothing. */
	status = cli_chmod(cli_unix, nonexist_symlink, 0777);

	/* This should fail with something other than server crashed. */
	if (NT_STATUS_IS_OK(status)) {
		printf("cli_chmod of %s succeeded (should have failed)\n",
		       nonexist_symlink);
		goto out;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_DISCONNECTED)) {
		/* Oops. Server crashed. */
		printf("cli_chmod of %s failed error %s\n",
		       nonexist_symlink,
		       nt_errstr(status));
		goto out;
	}

	/* Any other failure is ok. */
	printf("POSIX-SYMLINK-CHMOD test passed (expected failure was %s)\n",
			nt_errstr(status));
	correct = true;

out:
	if (fnum != (uint16_t)-1) {
		cli_close(cli_unix, fnum);
	}
	cli_posix_unlink(cli_unix, fname_real);
	cli_posix_unlink(cli_unix, fname_real_symlink);
	cli_posix_unlink(cli_unix, nonexist);
	cli_posix_unlink(cli_unix, nonexist_symlink);

	if (!torture_close_connection(cli_unix)) {
		correct = false;
	}

	TALLOC_FREE(frame);
	return correct;
}

/*
  Ensure we get an ACL containing OI|IO ACE entries
  after we add a default POSIX ACL to a directory.
  This will only ever be an SMB1 test as it depends
  on POSIX ACL semantics.
 */
bool run_posix_dir_default_acl_test(int dummy)
{
	TALLOC_CTX *frame = NULL;
	struct cli_state *cli_unix = NULL;
	NTSTATUS status;
	uint16_t fnum = (uint16_t)-1;
	const char *dname = "dir_with_default_acl";
	bool correct = false;
	SMB_STRUCT_STAT sbuf;
	size_t acl_size = 0;
	char *aclbuf = NULL;
	size_t num_file_acls = 0;
	size_t num_dir_acls = 0;
	size_t expected_buflen;
	uint8_t def_acl[SMB_POSIX_ACL_HEADER_SIZE +
			5*SMB_POSIX_ACL_ENTRY_SIZE] = {0};
	uint8_t *p = NULL;
	uint32_t i = 0;
	struct security_descriptor *sd = NULL;
	bool got_inherit = false;

	frame = talloc_stackframe();

	printf("Starting POSIX-DIR-DEFAULT-ACL test\n");

	if (!torture_open_connection(&cli_unix, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	torture_conn_set_sockopt(cli_unix);

	status = torture_setup_unix_extensions(cli_unix);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	/* Start with a clean slate. */
	cli_posix_unlink(cli_unix, dname);
	cli_posix_rmdir(cli_unix, dname);

	status = cli_posix_mkdir(cli_unix, dname, 0777);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_mkdir of %s failed error %s\n",
		       dname,
		       nt_errstr(status));
		goto out;
	}

	/* Do a posix stat to get the owner. */
	status = cli_posix_stat(cli_unix, dname, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_stat of %s failed %s\n",
			dname,
			nt_errstr(status));
		goto out;
	}

	/* Get the ACL on the directory. */
	status = cli_posix_getacl(cli_unix, dname, frame, &acl_size, &aclbuf);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_getacl on %s failed %s\n",
			dname,
			nt_errstr(status));
		goto out;
	}

	if (acl_size < 6 || SVAL(aclbuf,0) != SMB_POSIX_ACL_VERSION) {
		printf("%s, unknown POSIX acl version %u.\n",
			dname,
			(unsigned int)CVAL(aclbuf,0) );
		goto out;
	}

	num_file_acls = SVAL(aclbuf,2);
	num_dir_acls = SVAL(aclbuf,4);

	/*
	 * No overflow check, num_*_acls comes from a 16-bit value,
	 * and we expect expected_buflen (size_t) to be of at least 32
	 * bit.
	 */
	expected_buflen = SMB_POSIX_ACL_HEADER_SIZE +
			  SMB_POSIX_ACL_ENTRY_SIZE*(num_file_acls+num_dir_acls);

        if (acl_size != expected_buflen) {
		printf("%s, incorrect POSIX acl buffer size "
			"(should be %zu, was %zu).\n",
			dname,
			expected_buflen,
			acl_size);
		goto out;
	}

	if (num_dir_acls != 0) {
		printf("%s, POSIX default acl already exists"
			"(should be 0, was %zu).\n",
			dname,
			num_dir_acls);
		goto out;
	}

	/*
	 * Get the Windows ACL on the directory.
	 * Make sure there are no inheritable entries.
	 */
	status = cli_ntcreate(cli_unix,
				dname,
				0,
				SEC_STD_READ_CONTROL,
				0,
				FILE_SHARE_READ|
					FILE_SHARE_WRITE|
					FILE_SHARE_DELETE,
				FILE_OPEN,
				FILE_DIRECTORY_FILE,
				0x0,
				&fnum,
				NULL);
        if (!NT_STATUS_IS_OK(status)) {
                printf("Failed to open directory %s: %s\n",
			dname,
			nt_errstr(status));
		goto out;
        }

        status = cli_query_security_descriptor(cli_unix,
						fnum,
						SECINFO_DACL,
						frame,
						&sd);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to get security descriptor on directory %s: %s\n",
			dname,
			nt_errstr(status));
		goto out;
        }

	for (i = 0; sd->dacl && i < sd->dacl->num_aces; i++) {
		struct security_ace *ace = &sd->dacl->aces[i];
		if (ace->flags & (SEC_ACE_FLAG_OBJECT_INHERIT|
				  SEC_ACE_FLAG_CONTAINER_INHERIT)) {
			printf("security descriptor on directory %s already "
				"contains inheritance flags\n",
				dname);
			sec_desc_print(NULL, stdout, sd, true);
			goto out;
		}
	}

	TALLOC_FREE(sd);

	/* Construct a new default ACL. */
	SSVAL(def_acl,0,SMB_POSIX_ACL_VERSION);
	SSVAL(def_acl,2,SMB_POSIX_IGNORE_ACE_ENTRIES);
	SSVAL(def_acl,4,5); /* num_dir_acls. */

	p = def_acl + SMB_POSIX_ACL_HEADER_SIZE;

	/* USER_OBJ. */
	SCVAL(p,0,SMB_POSIX_ACL_USER_OBJ); /* tagtype. */
	SCVAL(p,1,SMB_POSIX_ACL_READ|SMB_POSIX_ACL_WRITE|SMB_POSIX_ACL_EXECUTE);
	p += SMB_POSIX_ACL_ENTRY_SIZE;

	/* GROUP_OBJ. */
	SCVAL(p,0,SMB_POSIX_ACL_GROUP_OBJ); /* tagtype. */
	SCVAL(p,1,SMB_POSIX_ACL_READ|SMB_POSIX_ACL_WRITE|SMB_POSIX_ACL_EXECUTE);
	p += SMB_POSIX_ACL_ENTRY_SIZE;

	/* OTHER. */
	SCVAL(p,0,SMB_POSIX_ACL_OTHER); /* tagtype. */
	SCVAL(p,1,SMB_POSIX_ACL_READ|SMB_POSIX_ACL_WRITE|SMB_POSIX_ACL_EXECUTE);
	p += SMB_POSIX_ACL_ENTRY_SIZE;

	/* Explicit user. */
	SCVAL(p,0,SMB_POSIX_ACL_USER); /* tagtype. */
	SCVAL(p,1,SMB_POSIX_ACL_READ|SMB_POSIX_ACL_WRITE|SMB_POSIX_ACL_EXECUTE);
	SIVAL(p,2,sbuf.st_ex_uid);
	p += SMB_POSIX_ACL_ENTRY_SIZE;

	/* MASK. */
	SCVAL(p,0,SMB_POSIX_ACL_MASK); /* tagtype. */
	SCVAL(p,1,SMB_POSIX_ACL_READ|SMB_POSIX_ACL_WRITE|SMB_POSIX_ACL_EXECUTE);
	p += SMB_POSIX_ACL_ENTRY_SIZE;

	/* Set the POSIX default ACL. */
	status = cli_posix_setacl(cli_unix, dname, def_acl, sizeof(def_acl));
        if (!NT_STATUS_IS_OK(status)) {
                printf("cli_posix_setacl on %s failed %s\n",
			dname,
			nt_errstr(status));
		goto out;
        }

	/*
	 * Get the Windows ACL on the directory again.
	 * Now there should be inheritable entries.
	 */

        status = cli_query_security_descriptor(cli_unix,
						fnum,
						SECINFO_DACL,
						frame,
						&sd);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed (2) to get security descriptor "
			"on directory %s: %s\n",
			dname,
			nt_errstr(status));
		goto out;
        }

	for (i = 0; sd->dacl && i < sd->dacl->num_aces; i++) {
		struct security_ace *ace = &sd->dacl->aces[i];
		if (ace->flags & (SEC_ACE_FLAG_OBJECT_INHERIT|
				  SEC_ACE_FLAG_CONTAINER_INHERIT)) {
			got_inherit = true;
			break;
		}
	}

	if (!got_inherit) {
		printf("security descriptor on directory %s does not "
			"contain inheritance flags\n",
			dname);
		sec_desc_print(NULL, stdout, sd, true);
		goto out;
	}

	cli_close(cli_unix, fnum);
	fnum = (uint16_t)-1;
	printf("POSIX-DIR-DEFAULT-ACL test passed\n");
	correct = true;

out:

	TALLOC_FREE(sd);

	if (fnum != (uint16_t)-1) {
		cli_close(cli_unix, fnum);
	}
	cli_posix_unlink(cli_unix, dname);
	cli_posix_rmdir(cli_unix, dname);

	if (!torture_close_connection(cli_unix)) {
		correct = false;
	}

	TALLOC_FREE(frame);
	return correct;
}

/*
  Ensure we can rename a symlink whether it is
  pointing to a real object or dangling.
 */
bool run_posix_symlink_rename_test(int dummy)
{
	TALLOC_CTX *frame = NULL;
	struct cli_state *cli_unix = NULL;
	NTSTATUS status;
	uint16_t fnum = (uint16_t)-1;
	const char *fname_real = "file_real";
	const char *fname_real_symlink = "file_real_symlink";
	const char *fname_real_symlink_newname = "rename_file_real_symlink";
	const char *nonexist = "nonexist";
	const char *nonexist_symlink = "dangling_symlink";
	const char *nonexist_symlink_newname = "dangling_symlink_rename";
	bool correct = false;

	frame = talloc_stackframe();

	printf("Starting POSIX-SYMLINK-RENAME test\n");

	if (!torture_open_connection(&cli_unix, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	torture_conn_set_sockopt(cli_unix);

	status = torture_setup_unix_extensions(cli_unix);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	/* Start with a clean slate. */
	cli_posix_unlink(cli_unix, fname_real);
	cli_posix_unlink(cli_unix, fname_real_symlink);
	cli_posix_unlink(cli_unix, fname_real_symlink_newname);
	cli_posix_unlink(cli_unix, nonexist);
	cli_posix_unlink(cli_unix, nonexist_symlink);
	cli_posix_unlink(cli_unix, nonexist_symlink_newname);

	/* Create a real file. */
	status = cli_posix_open(cli_unix,
				fname_real,
				O_RDWR|O_CREAT,
				0644,
				&fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_open of %s failed error %s\n",
		       fname_real,
		       nt_errstr(status));
		goto out;
	}
	status = cli_close(cli_unix, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_close failed %s\n", nt_errstr(status));
		goto out;
	}
	fnum = (uint16_t)-1;

	/* Create symlink to real target. */
	status = cli_posix_symlink(cli_unix,
				   fname_real,
				   fname_real_symlink);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_symlink of %s -> %s failed error %s\n",
		       fname_real_symlink,
		       fname_real,
		       nt_errstr(status));
		goto out;
	}

	/* Ensure we can rename the symlink to the real file. */
	status = cli_rename(cli_unix,
				fname_real_symlink,
				fname_real_symlink_newname,
				false);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_rename of %s -> %s failed %s\n",
			fname_real_symlink,
			fname_real_symlink_newname,
			nt_errstr(status));
		goto out;
	}

	/* Now create symlink to non-existing target. */
	status = cli_posix_symlink(cli_unix,
				   nonexist,
				   nonexist_symlink);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_symlink of %s -> %s failed error %s\n",
		       nonexist_symlink,
		       nonexist,
		       nt_errstr(status));
		goto out;
	}

	/* Ensure we can rename the dangling symlink. */
	status = cli_rename(cli_unix,
				nonexist_symlink,
				nonexist_symlink_newname,
				false);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_rename of %s -> %s failed %s\n",
			nonexist_symlink,
			nonexist_symlink_newname,
			nt_errstr(status));
		goto out;
	}

	printf("POSIX-SYMLINK-RENAME test passed\n");
	correct = true;

out:
	if (fnum != (uint16_t)-1) {
		cli_close(cli_unix, fnum);
	}
	cli_posix_unlink(cli_unix, fname_real);
	cli_posix_unlink(cli_unix, fname_real_symlink);
	cli_posix_unlink(cli_unix, fname_real_symlink_newname);
	cli_posix_unlink(cli_unix, nonexist);
	cli_posix_unlink(cli_unix, nonexist_symlink);
	cli_posix_unlink(cli_unix, nonexist_symlink_newname);

	if (!torture_close_connection(cli_unix)) {
		correct = false;
	}

	TALLOC_FREE(frame);
	return correct;
}

/* List of info levels to try with a POSIX symlink path. */

static struct {
	uint32_t level;
	const char *name;
} posix_smb1_qpath_array[] = {
  { SMB_INFO_STANDARD,			"SMB_INFO_STANDARD"},
  { SMB_INFO_QUERY_EA_SIZE,		"SMB_INFO_QUERY_EA_SIZE"},
  { SMB_INFO_IS_NAME_VALID,		"SMB_INFO_IS_NAME_VALID"},
  { SMB_INFO_QUERY_EAS_FROM_LIST,	"SMB_INFO_QUERY_EAS_FROM_LIST"},
  { SMB_INFO_QUERY_ALL_EAS,		"SMB_INFO_QUERY_ALL_EAS"},
  { SMB_FILE_BASIC_INFORMATION,		"SMB_FILE_BASIC_INFORMATION"},
  { SMB_FILE_STANDARD_INFORMATION,	"SMB_FILE_STANDARD_INFORMATION"},
  { SMB_FILE_EA_INFORMATION,		"SMB_FILE_EA_INFORMATION"},
  { SMB_FILE_ALTERNATE_NAME_INFORMATION,"SMB_FILE_ALTERNATE_NAME_INFORMATION"},
  { SMB_QUERY_FILE_NAME_INFO,		"SMB_QUERY_FILE_NAME_INFO"},
  { SMB_FILE_NORMALIZED_NAME_INFORMATION,"SMB_FILE_NORMALIZED_NAME_INFORMATION"},
  { SMB_FILE_ALLOCATION_INFORMATION,	"SMB_FILE_ALLOCATION_INFORMATION"},
  { SMB_FILE_END_OF_FILE_INFORMATION,	"SMB_FILE_END_OF_FILE_INFORMATION"},
  { SMB_FILE_ALL_INFORMATION,		"SMB_FILE_ALL_INFORMATION"},
  { SMB_FILE_INTERNAL_INFORMATION,	"SMB_FILE_INTERNAL_INFORMATION"},
  { SMB_FILE_ACCESS_INFORMATION,	"SMB_FILE_ACCESS_INFORMATION"},
  { SMB_FILE_NAME_INFORMATION,		"SMB_FILE_NAME_INFORMATION"},
  { SMB_FILE_DISPOSITION_INFORMATION,	"SMB_FILE_DISPOSITION_INFORMATION"},
  { SMB_FILE_POSITION_INFORMATION,	"SMB_FILE_POSITION_INFORMATION"},
  { SMB_FILE_MODE_INFORMATION,		"SMB_FILE_MODE_INFORMATION"},
  { SMB_FILE_ALIGNMENT_INFORMATION,	"SMB_FILE_ALIGNMENT_INFORMATION"},
  { SMB_FILE_STREAM_INFORMATION,	"SMB_FILE_STREAM_INFORMATION"},
  { SMB_FILE_COMPRESSION_INFORMATION,	"SMB_FILE_COMPRESSION_INFORMATION"},
  { SMB_FILE_NETWORK_OPEN_INFORMATION,	"SMB_FILE_NETWORK_OPEN_INFORMATION"},
  { SMB_FILE_ATTRIBUTE_TAG_INFORMATION, "SMB_FILE_ATTRIBUTE_TAG_INFORMATION"},
  { SMB_QUERY_FILE_UNIX_BASIC,		"SMB_QUERY_FILE_UNIX_BASIC"},
  { SMB_QUERY_FILE_UNIX_INFO2,		"SMB_QUERY_FILE_UNIX_INFO2"},
  { SMB_QUERY_FILE_UNIX_LINK,		"SMB_QUERY_FILE_UNIX_LINK"},
  { SMB_QUERY_POSIX_ACL,		"SMB_QUERY_POSIX_ACL"},
  { SMB_QUERY_POSIX_LOCK,		"SMB_QUERY_POSIX_LOCK"},
};

static NTSTATUS do_qpath(TALLOC_CTX *ctx,
			 struct cli_state *cli_unix,
			 const char *fname,
			 size_t i)
{
	NTSTATUS status;

	if (posix_smb1_qpath_array[i].level ==
			SMB_INFO_QUERY_EAS_FROM_LIST) {
		uint16_t setup;
		uint8_t *param;
		uint8_t data[8];
		uint8_t *rparam = NULL;
		uint8_t *rdata = NULL;
		uint32_t rbytes = 0;

		/* Set up an EA list with 'a' as the single name. */
		SIVAL(data,0, 8);
		SCVAL(data,4, 2); /* namelen. */
		SCVAL(data,5, 'a');
		SCVAL(data,6, '\0'); /* name. */
		SCVAL(data,7, '\0'); /* padding. */

		SSVAL(&setup, 0, TRANSACT2_QPATHINFO);

		param = talloc_zero_array(ctx, uint8_t, 6);
		if (param == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		SSVAL(param, 0, SMB_INFO_QUERY_EAS_FROM_LIST);
		param = trans2_bytes_push_str(param,
				smbXcli_conn_use_unicode(cli_unix->conn),
				fname,
				strlen(fname)+1,
				NULL);
		if (param == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = cli_trans(ctx,
				cli_unix,
				SMBtrans2,
				NULL,
				-1,
				0,
				0,
				&setup, 1, 0,
				param, talloc_get_size(param), talloc_get_size(param),
				data, 8, 0,
				NULL,
				NULL, 0, NULL,
				&rparam, 0, &rbytes,
				&rdata, 0, &rbytes);
		TALLOC_FREE(rparam);
		TALLOC_FREE(rdata);
	} else {
		uint8_t *rdata = NULL;
		uint32_t num_rdata = 0;

		status = cli_qpathinfo(ctx,
				cli_unix,
				fname,
				posix_smb1_qpath_array[i].level,
				0, /* min_rdata */
				65534, /* max_rdata */
				&rdata,
				&num_rdata);
		TALLOC_FREE(rdata);
	}
	/*
	 * We don't care what came back, so long as the
	 * server didn't crash.
	 */
	if (NT_STATUS_EQUAL(status,
			NT_STATUS_CONNECTION_DISCONNECTED)) {
		printf("cli_qpathinfo of %s failed error "
			"NT_STATUS_CONNECTION_DISCONNECTED\n",
			fname);
		return status;
	}

	printf("cli_qpathinfo info %x (%s) of %s got %s "
		"(this is not an error)\n",
		(unsigned int)posix_smb1_qpath_array[i].level,
		posix_smb1_qpath_array[i].name,
		fname,
		nt_errstr(status));

	return NT_STATUS_OK;
}

/*
  Ensure we can call SMB1 getpathinfo in a symlink,
  pointing to a real object or dangling. We mostly
  expect errors, but the server must not crash.
 */
bool run_posix_symlink_getpathinfo_test(int dummy)
{
	TALLOC_CTX *frame = NULL;
	struct cli_state *cli_unix = NULL;
	NTSTATUS status;
	uint16_t fnum = (uint16_t)-1;
	const char *fname_real = "file_getpath_real";
	const char *fname_real_symlink = "file_real_getpath_symlink";
	const char *nonexist = "nonexist_getpath";
	const char *nonexist_symlink = "dangling_getpath_symlink";
	bool correct = false;
	size_t i;

	frame = talloc_stackframe();

	printf("Starting POSIX-SYMLINK-GETPATHINFO test\n");

	if (!torture_open_connection(&cli_unix, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	torture_conn_set_sockopt(cli_unix);

	status = torture_setup_unix_extensions(cli_unix);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	/* Start with a clean slate. */
	cli_posix_unlink(cli_unix, fname_real);
	cli_posix_unlink(cli_unix, fname_real_symlink);
	cli_posix_unlink(cli_unix, nonexist);
	cli_posix_unlink(cli_unix, nonexist_symlink);

	/* Create a real file. */
	status = cli_posix_open(cli_unix,
				fname_real,
				O_RDWR|O_CREAT,
				0644,
				&fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_open of %s failed error %s\n",
		       fname_real,
		       nt_errstr(status));
		goto out;
	}
	status = cli_close(cli_unix, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_close failed %s\n", nt_errstr(status));
		goto out;
	}
	fnum = (uint16_t)-1;

	/* Create symlink to real target. */
	status = cli_posix_symlink(cli_unix,
				   fname_real,
				   fname_real_symlink);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_symlink of %s -> %s failed error %s\n",
		       fname_real_symlink,
		       fname_real,
		       nt_errstr(status));
		goto out;
	}

	/* Now create symlink to non-existing target. */
	status = cli_posix_symlink(cli_unix,
				   nonexist,
				   nonexist_symlink);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_symlink of %s -> %s failed error %s\n",
		       nonexist_symlink,
		       nonexist,
		       nt_errstr(status));
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(posix_smb1_qpath_array); i++) {
		status = do_qpath(frame,
				  cli_unix,
				  fname_real_symlink,
				  i);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
		status = do_qpath(frame,
				  cli_unix,
				  nonexist_symlink,
				  i);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	printf("POSIX-SYMLINK-GETPATHINFO test passed\n");
	correct = true;

out:
	if (fnum != (uint16_t)-1) {
		cli_close(cli_unix, fnum);
	}
	cli_posix_unlink(cli_unix, fname_real);
	cli_posix_unlink(cli_unix, fname_real_symlink);
	cli_posix_unlink(cli_unix, nonexist);
	cli_posix_unlink(cli_unix, nonexist_symlink);

	if (!torture_close_connection(cli_unix)) {
		correct = false;
	}

	TALLOC_FREE(frame);
	return correct;
}

/* List of info levels to try with a POSIX symlink path. */

static struct {
	uint32_t level;
	const char *name;
	uint32_t data_len;
} posix_smb1_setpath_array[] = {
  { SMB_SET_FILE_UNIX_BASIC,	"SMB_SET_FILE_UNIX_BASIC",	100},
  { SMB_SET_FILE_UNIX_INFO2,	"SMB_SET_FILE_UNIX_INFO2",	116},
  { SMB_SET_FILE_UNIX_LINK,	"SMB_SET_FILE_UNIX_LINK",	8},
  { SMB_SET_FILE_UNIX_HLINK,	"SMB_SET_FILE_UNIX_HLINK",	8},
  { SMB_SET_POSIX_ACL,		"SMB_SET_POSIX_ACL",		6},
  { SMB_SET_POSIX_LOCK,		"SMB_SET_POSIX_LOCK",		24},
  { SMB_INFO_STANDARD,		"SMB_INFO_STANDARD",		12},
  { SMB_INFO_SET_EA,		"SMB_INFO_SET_EA",		10},
  { SMB_FILE_BASIC_INFORMATION, "SMB_FILE_BASIC_INFORMATION",	36},
  { SMB_SET_FILE_ALLOCATION_INFO, "SMB_SET_FILE_ALLOCATION_INFO", 8},
  { SMB_SET_FILE_END_OF_FILE_INFO,"SMB_SET_FILE_END_OF_FILE_INFO",8},
  { SMB_SET_FILE_DISPOSITION_INFO,"SMB_SET_FILE_DISPOSITION_INFO",1},
  { SMB_FILE_POSITION_INFORMATION,"SMB_FILE_POSITION_INFORMATION",8},
  { SMB_FILE_FULL_EA_INFORMATION, "SMB_FILE_FULL_EA_INFORMATION",10},
  { SMB_FILE_MODE_INFORMATION,	"SMB_FILE_MODE_INFORMATION",	4},
  { SMB_FILE_SHORT_NAME_INFORMATION,"SMB_FILE_SHORT_NAME_INFORMATION",12},
  { SMB_FILE_RENAME_INFORMATION,"SMB_FILE_RENAME_INFORMATION",	20},
  { SMB_FILE_LINK_INFORMATION,	"SMB_FILE_LINK_INFORMATION",	20},
};

static NTSTATUS do_setpath(TALLOC_CTX *ctx,
			   struct cli_state *cli_unix,
			   const char *fname,
			   size_t i)
{
	NTSTATUS status;
	uint8_t *data = NULL;

	data = talloc_zero_array(ctx,
				 uint8_t,
				 posix_smb1_setpath_array[i].data_len);
	if (data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = cli_setpathinfo(cli_unix,
			posix_smb1_setpath_array[i].level,
			fname,
			data,
			posix_smb1_setpath_array[i].data_len);
	TALLOC_FREE(data);

	/*
	 * We don't care what came back, so long as the
	 * server didn't crash.
	 */
	if (NT_STATUS_EQUAL(status,
			NT_STATUS_CONNECTION_DISCONNECTED)) {
		printf("cli_setpathinfo info %x (%s) of %s failed"
			"error NT_STATUS_CONNECTION_DISCONNECTED\n",
			(unsigned int)posix_smb1_setpath_array[i].level,
			posix_smb1_setpath_array[i].name,
			fname);
		return status;
	}

	printf("cli_setpathinfo info %x (%s) of %s got %s "
		"(this is not an error)\n",
		(unsigned int)posix_smb1_setpath_array[i].level,
		posix_smb1_setpath_array[i].name,
		fname,
		nt_errstr(status));

	return NT_STATUS_OK;
}

/*
  Ensure we can call SMB1 setpathinfo in a symlink,
  pointing to a real object or dangling. We mostly
  expect errors, but the server must not crash.
 */
bool run_posix_symlink_setpathinfo_test(int dummy)
{
	TALLOC_CTX *frame = NULL;
	struct cli_state *cli_unix = NULL;
	NTSTATUS status;
	uint16_t fnum = (uint16_t)-1;
	const char *fname_real = "file_setpath_real";
	const char *fname_real_symlink = "file_real_setpath_symlink";
	const char *nonexist = "nonexist_setpath";
	const char *nonexist_symlink = "dangling_setpath_symlink";
	bool correct = false;
	size_t i;

	frame = talloc_stackframe();

	printf("Starting POSIX-SYMLINK-SETPATHINFO test\n");

	if (!torture_open_connection(&cli_unix, 0)) {
		TALLOC_FREE(frame);
		return false;
	}

	torture_conn_set_sockopt(cli_unix);

	status = torture_setup_unix_extensions(cli_unix);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	/* Start with a clean slate. */
	cli_posix_unlink(cli_unix, fname_real);
	cli_posix_unlink(cli_unix, fname_real_symlink);
	cli_posix_unlink(cli_unix, nonexist);
	cli_posix_unlink(cli_unix, nonexist_symlink);

	/* Create a real file. */
	status = cli_posix_open(cli_unix,
				fname_real,
				O_RDWR|O_CREAT,
				0644,
				&fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_open of %s failed error %s\n",
		       fname_real,
		       nt_errstr(status));
		goto out;
	}
	status = cli_close(cli_unix, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_close failed %s\n", nt_errstr(status));
		goto out;
	}
	fnum = (uint16_t)-1;

	/* Create symlink to real target. */
	status = cli_posix_symlink(cli_unix,
				   fname_real,
				   fname_real_symlink);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_symlink of %s -> %s failed error %s\n",
		       fname_real_symlink,
		       fname_real,
		       nt_errstr(status));
		goto out;
	}

	/* Now create symlink to non-existing target. */
	status = cli_posix_symlink(cli_unix,
				   nonexist,
				   nonexist_symlink);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_posix_symlink of %s -> %s failed error %s\n",
		       nonexist_symlink,
		       nonexist,
		       nt_errstr(status));
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(posix_smb1_setpath_array); i++) {
		status = do_setpath(frame,
				  cli_unix,
				  fname_real_symlink,
				  i);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
		status = do_setpath(frame,
				  cli_unix,
				  nonexist_symlink,
				  i);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	printf("POSIX-SYMLINK-SETPATHINFO test passed\n");
	correct = true;

out:
	if (fnum != (uint16_t)-1) {
		cli_close(cli_unix, fnum);
	}
	cli_posix_unlink(cli_unix, fname_real);
	cli_posix_unlink(cli_unix, fname_real_symlink);
	cli_posix_unlink(cli_unix, nonexist);
	cli_posix_unlink(cli_unix, nonexist_symlink);

	if (!torture_close_connection(cli_unix)) {
		correct = false;
	}

	TALLOC_FREE(frame);
	return correct;
}
