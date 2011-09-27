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
#include "../libcli/smb/smbXcli_base.h"
#include "libsmb/smb2cli.h"
#include "libcli/security/security.h"
#include "libsmb/proto.h"

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

	status = smbXcli_negprot(cli->conn, cli->timeout,
				 PROTOCOL_SMB2_02, PROTOCOL_SMB2_02);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_session_setup(cli, username,
				   password, strlen(password),
				   password, strlen(password),
				   workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_tcon(cli, share);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_tcon returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli, "smb2-basic.txt",
			SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
			SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
			SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
			FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
			FILE_CREATE, /* create_disposition, */
			FILE_DELETE_ON_CLOSE, /* create_options, */
			NULL, /* smb2_create_blobs *blobs */
			&fid_persistent,
			&fid_volatile);
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

	status = smb2cli_flush(cli, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
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

	status = smb2cli_create(cli, "",
			SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
			SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
			SEC_STD_SYNCHRONIZE|
			SEC_DIR_LIST|
			SEC_DIR_READ_ATTRIBUTE, /* desired_access, */
			0, /* file_attributes, */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
			FILE_OPEN, /* create_disposition, */
			FILE_SYNCHRONOUS_IO_NONALERT|FILE_DIRECTORY_FILE, /* create_options, */
			NULL, /* smb2_create_blobs *blobs */
			&fid_persistent,
			&fid_volatile);
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

bool run_smb2_negprot(int dummy)
{
	struct cli_state *cli;
	NTSTATUS status;
	enum protocol_types protocol;
	const char *name = NULL;

	printf("Starting SMB2-NEGPROT\n");

	if (!torture_init_connection(&cli)) {
		return false;
	}
	cli->smb2.pid = 0xFEFF;

	status = smbXcli_negprot(cli->conn, cli->timeout,
				 PROTOCOL_CORE, PROTOCOL_SMB2_22);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	protocol = smbXcli_conn_protocol(cli->conn);

	switch (protocol) {
	case PROTOCOL_SMB2_02:
		name = "SMB2_02";
		break;
	case PROTOCOL_SMB2_10:
		name = "SMB2_10";
		break;
	case PROTOCOL_SMB2_22:
		name = "SMB2_22";
		break;
	default:
		break;
	}

	if (name) {
		printf("Server supports %s\n", name);
	} else {
		printf("Server DOES NOT support SMB2\n");
		return false;
	}

	status = smbXcli_negprot(cli->conn, cli->timeout,
				 protocol, protocol);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_RESET) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_DISCONNECTED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_ABORTED)) {
		printf("2nd smbXcli_negprot should disconnect - returned %s\n",
			nt_errstr(status));
		return false;
	}

	if (smbXcli_conn_is_connected(cli->conn)) {
		printf("2nd smbXcli_negprot should disconnect "
		       "- still connected\n");
		return false;
	}

	return true;
}
