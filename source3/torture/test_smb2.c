/*
   Unix SMB/CIFS implementation.
   Initial test for the smb2 client lib
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
#include "client.h"
#include "libsmb/smb2cli.h"
#include "libcli/security/security.h"

extern fstring host, workgroup, share, password, username, myname;

bool run_smb2_basic(int dummy)
{
	struct cli_state *cli;
	NTSTATUS status;
	uint64_t fid_persistent, fid_volatile;
	const char *hello = "Hello, world\n";
	uint8_t *result;
	uint32_t nread;
	uint8_t *dir_data;
	uint32_t dir_data_length;

	printf("Starting SMB2-BASIC\n");

	if (!torture_init_connection(&cli)) {
		return false;
	}
	cli->smb2.pid = 0xFEFF;

	status = smb2cli_negprot(cli);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_sesssetup(cli, username, workgroup, password);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_sesssetup returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_tcon(cli, share);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_tcon returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(
		cli, "test.txt", SMB2_OPLOCK_LEVEL_NONE, 0,
		MAXIMUM_ALLOWED_ACCESS, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OVERWRITE_IF, FILE_DELETE_ON_CLOSE, NULL,
		&fid_persistent, &fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_write returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_read(cli, 0x10000, 0, fid_persistent,
			       fid_volatile, 2, 0,
			       talloc_tos(), &result, &nread);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_read returned %s\n", nt_errstr(status));
		return false;
	}

	if (nread != strlen(hello)) {
		printf("smb2cli_read returned %d bytes, expected %d\n",
		       (int)nread, (int)strlen(hello));
		return false;
	}

	if (memcmp(hello, result, nread) != 0) {
		printf("smb2cli_read returned '%s', expected '%s'\n",
		       result, hello);
		return false;
	}

	status = smb2cli_close(cli, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(
		cli, "", SMB2_OPLOCK_LEVEL_NONE, 0,
		MAXIMUM_ALLOWED_ACCESS, FILE_ATTRIBUTE_DIRECTORY, 0,
		FILE_OPEN, 0, NULL, &fid_persistent, &fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_query_directory(
		cli, 1, 0, 0, fid_persistent, fid_volatile, "*", 0xffff,
		talloc_tos(), &dir_data, &dir_data_length);

	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_query_directory returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_close(cli, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	return true;
}
