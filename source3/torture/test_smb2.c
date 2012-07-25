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
#include "trans2.h"
#include "../libcli/smb/smbXcli_base.h"
#include "libsmb/smb2cli.h"
#include "libcli/security/security.h"
#include "libsmb/proto.h"
#include "auth/gensec/gensec.h"
#include "auth_generic.h"

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
	uint32_t saved_tid = 0;
	struct smbXcli_tcon *saved_tcon = NULL;
	uint64_t saved_uid = 0;

	printf("Starting SMB2-BASIC\n");

	if (!torture_init_connection(&cli)) {
		return false;
	}

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

	status = cli_tree_connect(cli, share, "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, "smb2-basic.txt",
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

	status = smb2cli_write(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_write returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_read(cli->conn, cli->timeout, cli->smb2.session,
			      cli->smb2.tcon, 0x10000, 0, fid_persistent,
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

	status = smb2cli_close(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, "",
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
		cli->conn, cli->timeout, cli->smb2.session, cli->smb2.tcon,
		1, 0, 0, fid_persistent, fid_volatile, "*", 0xffff,
		talloc_tos(), &dir_data, &dir_data_length);

	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_query_directory returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_close(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	saved_tid = smb2cli_tcon_current_id(cli->smb2.tcon);
	saved_tcon = cli->smb2.tcon;
	cli->smb2.tcon = smbXcli_tcon_create(cli);
	smb2cli_tcon_set_values(cli->smb2.tcon,
				NULL, /* session */
				saved_tid,
				0, /* type */
				0, /* flags */
				0, /* capabilities */
				0  /* maximal_access */);
	status = smb2cli_tdis(cli);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_tdis returned %s\n", nt_errstr(status));
		return false;
	}
	talloc_free(cli->smb2.tcon);
	cli->smb2.tcon = saved_tcon;

	status = smb2cli_tdis(cli);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED)) {
		printf("2nd smb2cli_tdis returned %s\n", nt_errstr(status));
		return false;
	}

	saved_uid = smb2cli_session_current_id(cli->smb2.session);
	status = smb2cli_logoff(cli->conn, cli->timeout, cli->smb2.session);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_logoff returned %s\n", nt_errstr(status));
		return false;
	}

	cli->smb2.session = smbXcli_session_create(cli, cli->conn);
	if (cli->smb2.session == NULL) {
		printf("smbXcli_session_create() returned NULL\n");
		return false;
	}

	smb2cli_session_set_id_and_flags(cli->smb2.session, saved_uid, 0);

	status = smb2cli_logoff(cli->conn, cli->timeout, cli->smb2.session);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_USER_SESSION_DELETED)) {
		printf("2nd smb2cli_logoff returned %s\n", nt_errstr(status));
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

	status = smbXcli_negprot(cli->conn, cli->timeout,
				 PROTOCOL_CORE, PROTOCOL_LATEST);
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
	case PROTOCOL_SMB2_24:
		name = "SMB2_24";
		break;
	case PROTOCOL_SMB3_00:
		name = "SMB3_00";
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

bool run_smb2_session_reconnect(int dummy)
{
	struct cli_state *cli1;
	struct cli_state *cli2;
	NTSTATUS status;
	bool ok;
	uint64_t fid_persistent, fid_volatile;
	struct tevent_context *ev;
	struct tevent_req *subreq;
	DATA_BLOB in_blob = data_blob_null;
	DATA_BLOB out_blob;
	DATA_BLOB session_key;
	struct auth_generic_state *auth_generic_state;
	struct iovec *recv_iov;
	const char *hello = "Hello, world\n";
	uint8_t *result;
	uint32_t nread;

	printf("Starting SMB2-SESSION-RECONNECT\n");

	if (!torture_init_connection(&cli1)) {
		return false;
	}

	status = smbXcli_negprot(cli1->conn, cli1->timeout,
				 PROTOCOL_SMB2_02, PROTOCOL_LATEST);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_session_setup(cli1, username,
				   password, strlen(password),
				   password, strlen(password),
				   workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli1, share, "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli1->conn, cli1->timeout, cli1->smb2.session,
			cli1->smb2.tcon, "session-reconnect.txt",
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
		printf("smb2cli_create on cli1 %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli1->conn, cli1->timeout, cli1->smb2.session,
			       cli1->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_write returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli1->conn, cli1->timeout, cli1->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_read(cli1->conn, cli1->timeout, cli1->smb2.session,
			      cli1->smb2.tcon, 0x10000, 0, fid_persistent,
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

	/* prepare second session */

	if (!torture_init_connection(&cli2)) {
		return false;
	}

	status = smbXcli_negprot(cli2->conn, cli2->timeout,
				 PROTOCOL_SMB2_02, PROTOCOL_LATEST);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_prepare(talloc_tos(), &auth_generic_state);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_prepare returned %s\n", nt_errstr(status));
		return false;
	}

	gensec_want_feature(auth_generic_state->gensec_security,
			    GENSEC_FEATURE_SESSION_KEY);
	status = auth_generic_set_username(auth_generic_state, username);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_username returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_set_domain(auth_generic_state, workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_domain returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_set_password(auth_generic_state, password);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_password returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_start(auth_generic_state, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_start returned %s\n", nt_errstr(status));
		return false;
	}

	ev = event_context_init(talloc_tos());
	if (ev == NULL) {
		printf("event_context_init() returned NULL\n");
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security, talloc_tos(), ev, data_blob_null, &in_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		printf("gensec_update returned %s\n", nt_errstr(status));
		return false;
	}

	cli2->smb2.session = smbXcli_session_create(cli2, cli2->conn);

	subreq = smb2cli_session_setup_send(talloc_tos(), ev,
					    cli2->conn,
					    cli2->timeout,
					    cli2->smb2.session,
					    0x0, /* in_flags */
					    SMB2_CAP_DFS, /* in_capabilities */
					    0, /* in_channel */
					    /* in_previous_session_id: */
					    smb2cli_session_current_id(cli1->smb2.session),
					    &in_blob); /* in_security_buffer */
	if (subreq == NULL) {
		printf("smb2cli_session_setup_send() returned NULL\n");
		return false;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		printf("tevent_req_poll() returned false\n");
		return false;
	}

	status = smb2cli_session_setup_recv(subreq, talloc_tos(),
					    NULL, &out_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		printf("smb2cli_session_setup_recv returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security, talloc_tos(), ev, out_blob, &in_blob);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_update returned %s\n", nt_errstr(status));
		return false;
	}

	subreq = smb2cli_session_setup_send(talloc_tos(), ev,
					    cli2->conn,
					    cli2->timeout,
					    cli2->smb2.session,
					    0x0, /* in_flags */
					    SMB2_CAP_DFS, /* in_capabilities */
					    0, /* in_channel */
					    /* in_previous_session_id: */
					    smb2cli_session_current_id(cli1->smb2.session),
					    &in_blob); /* in_security_buffer */
	if (subreq == NULL) {
		printf("smb2cli_session_setup_send() returned NULL\n");
		return false;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		printf("tevent_req_poll() returned false\n");
		return false;
	}

	status = smb2cli_session_setup_recv(subreq, talloc_tos(),
					    &recv_iov, &out_blob);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_session_setup_recv returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = gensec_session_key(auth_generic_state->gensec_security, talloc_tos(),
				    &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("gensec_session_key returned %s\n",
			nt_errstr(status));
		return false;
	}

	/* check file operation on the old client */

	status = smb2cli_flush(cli1->conn, cli1->timeout, cli1->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_USER_SESSION_DELETED)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli1, share, "?????", "", 0);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_USER_SESSION_DELETED)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	/*
	 * checking file operations without signing.
	 * on w2k8r2 at least, flush, read and write also work the same way,
	 * while create gives ACCESS_DENIED without signing
	 */
	status = smb2cli_flush(cli2->conn, cli2->timeout, cli2->smb2.session,
			       cli2->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED))
	{
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli2->conn, cli2->timeout, cli2->smb2.session,
			       cli2->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED))
	{
		printf("smb2cli_write returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_read(cli2->conn, cli2->timeout, cli2->smb2.session,
			      cli2->smb2.tcon, 0x10000, 0, fid_persistent,
			      fid_volatile, 2, 0,
			      talloc_tos(), &result, &nread);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED))
	{
		printf("smb2cli_read returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli2->conn, cli2->timeout, cli2->smb2.session,
			cli2->smb2.tcon, "session-reconnect.txt",
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
	if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED)) {
		printf("smb2cli_create on cli2 %s\n", nt_errstr(status));
		return false;
	}

	/* now grab the session key and try with signing */

	status = smb2cli_session_set_session_key(cli2->smb2.session,
						 session_key,
						 recv_iov);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_session_set_session_key %s\n", nt_errstr(status));
		return false;
	}

	/* the tid seems to be irrelevant at this stage */

	status = smb2cli_flush(cli2->conn, cli2->timeout, cli2->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED))
	{
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli2->conn, cli2->timeout, cli2->smb2.session,
			       cli1->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED))
	{
		printf("smb2cli_write returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_read(cli2->conn, cli2->timeout, cli2->smb2.session,
			      cli1->smb2.tcon, 0x10000, 0, fid_persistent,
			      fid_volatile, 2, 0,
			      talloc_tos(), &result, &nread);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED))
	{
		printf("smb2cli_read returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli2->conn, cli2->timeout, cli2->smb2.session,
			cli1->smb2.tcon, "session-reconnect.txt",
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
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED))
	{
		printf("smb2cli_create on cli2 %s\n", nt_errstr(status));
		return false;
	}

	/* now do a new tcon and test file calls again */

	status = cli_tree_connect(cli2, share, "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli2->conn, cli2->timeout, cli2->smb2.session,
			cli2->smb2.tcon, "session-reconnect.txt",
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
		printf("smb2cli_create on cli2 %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli2->conn, cli2->timeout, cli2->smb2.session,
			       cli2->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_write returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli2->conn, cli2->timeout, cli2->smb2.session,
			       cli2->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_read(cli2->conn, cli2->timeout, cli2->smb2.session,
			      cli2->smb2.tcon, 0x10000, 0, fid_persistent,
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

	return true;
}

bool run_smb2_tcon_dependence(int dummy)
{
	struct cli_state *cli;
	NTSTATUS status;
	uint64_t fid_persistent, fid_volatile;
	const char *hello = "Hello, world\n";
	uint8_t *result;
	uint32_t nread;
	struct smbXcli_tcon *tcon2;
	uint32_t tcon2_id;

	printf("Starting SMB2-TCON-DEPENDENCE\n");

	if (!torture_init_connection(&cli)) {
		return false;
	}

	status = smbXcli_negprot(cli->conn, cli->timeout,
				 PROTOCOL_SMB2_02, PROTOCOL_LATEST);
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

	status = cli_tree_connect(cli, share, "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, "tcon_depedence.txt",
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
		printf("smb2cli_create on cli %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_write returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_read(cli->conn, cli->timeout, cli->smb2.session,
			      cli->smb2.tcon, 0x10000, 0, fid_persistent,
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

	/* check behaviour with wrong tid... */

	tcon2 = smbXcli_tcon_create(cli);
	tcon2_id = smb2cli_tcon_current_id(cli->smb2.tcon);
	tcon2_id++;
	smb2cli_tcon_set_values(tcon2,
				NULL, /* session */
				tcon2_id,
				0, /* type */
				0, /* flags */
				0, /* capabilities */
				0  /* maximal_access */);

	status = smb2cli_read(cli->conn, cli->timeout, cli->smb2.session,
			      tcon2, 0x10000, 0, fid_persistent,
			      fid_volatile, 2, 0,
			      talloc_tos(), &result, &nread);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED)) {
		printf("smb2cli_read returned %s\n", nt_errstr(status));
		return false;
	}

	talloc_free(tcon2);

	return true;
}

bool run_smb2_multi_channel(int dummy)
{
	struct cli_state *cli1;
	struct cli_state *cli2;
	struct cli_state *cli3;
	NTSTATUS status;
	bool ok;
	uint64_t fid_persistent, fid_volatile;
	struct tevent_context *ev;
	struct tevent_req *subreq;
	DATA_BLOB in_blob = data_blob_null;
	DATA_BLOB out_blob;
	DATA_BLOB channel_session_key;
	struct auth_generic_state *auth_generic_state;
	struct iovec *recv_iov;
	const char *hello = "Hello, world\n";
	uint8_t *result;
	uint32_t nread;

	printf("Starting SMB2-MULTI-CHANNEL\n");

	if (!torture_init_connection(&cli1)) {
		return false;
	}

	if (!torture_init_connection(&cli2)) {
		return false;
	}

	if (!torture_init_connection(&cli3)) {
		return false;
	}

	status = smbXcli_negprot(cli1->conn, cli1->timeout,
				 PROTOCOL_SMB2_22, PROTOCOL_LATEST);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = smbXcli_negprot(cli2->conn, cli2->timeout,
				 PROTOCOL_SMB2_22, PROTOCOL_LATEST);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = smbXcli_negprot(cli3->conn, cli3->timeout,
				 PROTOCOL_SMB2_22, PROTOCOL_LATEST);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_session_setup(cli1, username,
				   password, strlen(password),
				   password, strlen(password),
				   workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_sesssetup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli1, share, "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_session_create_channel(cli2,
						cli1->smb2.session,
						cli2->conn,
						&cli2->smb2.session);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_session_create_channel returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = auth_generic_client_prepare(talloc_tos(), &auth_generic_state);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_prepare returned %s\n", nt_errstr(status));
		return false;
	}

	gensec_want_feature(auth_generic_state->gensec_security,
			    GENSEC_FEATURE_SESSION_KEY);
	status = auth_generic_set_username(auth_generic_state, username);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_username returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_set_domain(auth_generic_state, workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_domain returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_set_password(auth_generic_state, password);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_password returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_start(auth_generic_state, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_start returned %s\n", nt_errstr(status));
		return false;
	}

	ev = event_context_init(talloc_tos());
	if (ev == NULL) {
		printf("event_context_init() returned NULL\n");
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security, talloc_tos(), ev, data_blob_null, &in_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		printf("gensec_update returned %s\n", nt_errstr(status));
		return false;
	}

	subreq = smb2cli_session_setup_send(talloc_tos(), ev,
					    cli2->conn,
					    cli2->timeout,
					    cli2->smb2.session,
					    0x01, /* in_flags */
					    SMB2_CAP_DFS, /* in_capabilities */
					    0, /* in_channel */
					    0, /* in_previous_session_id */
					    &in_blob); /* in_security_buffer */
	if (subreq == NULL) {
		printf("smb2cli_session_setup_send() returned NULL\n");
		return false;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		printf("tevent_req_poll() returned false\n");
		return false;
	}

	status = smb2cli_session_setup_recv(subreq, talloc_tos(),
					    NULL, &out_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		printf("smb2cli_session_setup_recv returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security, talloc_tos(), ev, out_blob, &in_blob);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_update returned %s\n", nt_errstr(status));
		return false;
	}

	subreq = smb2cli_session_setup_send(talloc_tos(), ev,
					    cli2->conn,
					    cli2->timeout,
					    cli2->smb2.session,
					    0x01, /* in_flags */
					    SMB2_CAP_DFS, /* in_capabilities */
					    0, /* in_channel */
					    0, /* in_previous_session_id */
					    &in_blob); /* in_security_buffer */
	if (subreq == NULL) {
		printf("smb2cli_session_setup_send() returned NULL\n");
		return false;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		printf("tevent_req_poll() returned false\n");
		return false;
	}

	status = smb2cli_session_setup_recv(subreq, talloc_tos(),
					    &recv_iov, &out_blob);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_session_setup_recv returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = gensec_session_key(auth_generic_state->gensec_security, talloc_tos(),
				    &channel_session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("gensec_session_key returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = smb2cli_session_set_channel_key(cli2->smb2.session,
						 channel_session_key,
						 recv_iov);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_session_set_channel_key %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_session_create_channel(cli3,
						cli1->smb2.session,
						cli3->conn,
						&cli3->smb2.session);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_session_create_channel returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = auth_generic_client_prepare(talloc_tos(), &auth_generic_state);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_prepare returned %s\n", nt_errstr(status));
		return false;
	}

	gensec_want_feature(auth_generic_state->gensec_security,
			    GENSEC_FEATURE_SESSION_KEY);
	status = auth_generic_set_username(auth_generic_state, username);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_username returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_set_domain(auth_generic_state, workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_domain returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_set_password(auth_generic_state, password);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_password returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_start(auth_generic_state, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_start returned %s\n", nt_errstr(status));
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security, talloc_tos(), ev, data_blob_null, &in_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		printf("gensec_update returned %s\n", nt_errstr(status));
		return false;
	}

	subreq = smb2cli_session_setup_send(talloc_tos(), ev,
					    cli3->conn,
					    cli3->timeout,
					    cli3->smb2.session,
					    0x01, /* in_flags */
					    SMB2_CAP_DFS, /* in_capabilities */
					    0, /* in_channel */
					    0, /* in_previous_session_id */
					    &in_blob); /* in_security_buffer */
	if (subreq == NULL) {
		printf("smb2cli_session_setup_send() returned NULL\n");
		return false;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		printf("tevent_req_poll() returned false\n");
		return false;
	}

	status = smb2cli_session_setup_recv(subreq, talloc_tos(),
					    NULL, &out_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		printf("smb2cli_session_setup_recv returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security, talloc_tos(), ev, out_blob, &in_blob);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_update returned %s\n", nt_errstr(status));
		return false;
	}

	subreq = smb2cli_session_setup_send(talloc_tos(), ev,
					    cli3->conn,
					    cli3->timeout,
					    cli3->smb2.session,
					    0x01, /* in_flags */
					    SMB2_CAP_DFS, /* in_capabilities */
					    0, /* in_channel */
					    0, /* in_previous_session_id */
					    &in_blob); /* in_security_buffer */
	if (subreq == NULL) {
		printf("smb2cli_session_setup_send() returned NULL\n");
		return false;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		printf("tevent_req_poll() returned false\n");
		return false;
	}

	status = smb2cli_session_setup_recv(subreq, talloc_tos(),
					    &recv_iov, &out_blob);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_session_setup_recv returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = gensec_session_key(auth_generic_state->gensec_security, talloc_tos(),
				    &channel_session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("gensec_session_key returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = smb2cli_session_set_channel_key(cli3->smb2.session,
						 channel_session_key,
						 recv_iov);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_session_set_channel_key %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli2->conn, cli2->timeout, cli2->smb2.session,
			cli1->smb2.tcon, "multi-channel.txt",
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
		printf("smb2cli_create on cli2 %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli1->conn, cli1->timeout, cli1->smb2.session,
			       cli1->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_write returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli2->conn, cli2->timeout, cli2->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli1->conn, cli1->timeout, cli1->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli3->conn, cli3->timeout, cli3->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_read(cli2->conn, cli2->timeout, cli2->smb2.session,
			      cli1->smb2.tcon, 0x10000, 0, fid_persistent,
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

	status = auth_generic_client_prepare(talloc_tos(), &auth_generic_state);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_prepare returned %s\n", nt_errstr(status));
		return false;
	}

	gensec_want_feature(auth_generic_state->gensec_security,
			    GENSEC_FEATURE_SESSION_KEY);
	status = auth_generic_set_username(auth_generic_state, username);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_username returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_set_domain(auth_generic_state, workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_domain returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_set_password(auth_generic_state, password);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_password returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_start(auth_generic_state, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_start returned %s\n", nt_errstr(status));
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security, talloc_tos(), ev, data_blob_null, &in_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		printf("gensec_update returned %s\n", nt_errstr(status));
		return false;
	}

	subreq = smb2cli_session_setup_send(talloc_tos(), ev,
					    cli3->conn,
					    cli3->timeout,
					    cli3->smb2.session,
					    0x0, /* in_flags */
					    SMB2_CAP_DFS, /* in_capabilities */
					    0, /* in_channel */
					    0, /* in_previous_session_id */
					    &in_blob); /* in_security_buffer */
	if (subreq == NULL) {
		printf("smb2cli_session_setup_send() returned NULL\n");
		return false;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		printf("tevent_req_poll() returned false\n");
		return false;
	}

	status = smb2cli_session_setup_recv(subreq, talloc_tos(),
					    NULL, &out_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		printf("smb2cli_session_setup_recv returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security, talloc_tos(), ev, out_blob, &in_blob);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_update returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli1->conn, cli1->timeout, cli1->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli2->conn, cli2->timeout, cli2->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli3->conn, cli3->timeout, cli3->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli1->conn, cli1->timeout, cli1->smb2.session,
			cli1->smb2.tcon, "multi-channel-invalid.txt",
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
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_create %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli2->conn, cli2->timeout, cli2->smb2.session,
			cli1->smb2.tcon, "multi-channel-invalid.txt",
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
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_create %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli3->conn, cli3->timeout, cli3->smb2.session,
			cli1->smb2.tcon, "multi-channel-invalid.txt",
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
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_create %s\n", nt_errstr(status));
		return false;
	}

	subreq = smb2cli_session_setup_send(talloc_tos(), ev,
					    cli2->conn,
					    cli2->timeout,
					    cli2->smb2.session,
					    0x0, /* in_flags */
					    SMB2_CAP_DFS, /* in_capabilities */
					    0, /* in_channel */
					    0, /* in_previous_session_id */
					    &in_blob); /* in_security_buffer */
	if (subreq == NULL) {
		printf("smb2cli_session_setup_send() returned NULL\n");
		return false;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		printf("tevent_req_poll() returned false\n");
		return false;
	}

	status = smb2cli_session_setup_recv(subreq, talloc_tos(),
					    &recv_iov, &out_blob);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_session_setup_recv returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = smb2cli_close(cli3->conn, cli3->timeout, cli3->smb2.session,
			       cli1->smb2.tcon, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli3->conn, cli3->timeout, cli3->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli2->conn, cli2->timeout, cli2->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli1->conn, cli1->timeout, cli1->smb2.session,
			       cli1->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	return true;
}

bool run_smb2_session_reauth(int dummy)
{
	struct cli_state *cli;
	NTSTATUS status;
	bool ok;
	uint64_t fid_persistent, fid_volatile;
	uint64_t dir_persistent, dir_volatile;
	uint8_t *dir_data;
	uint32_t dir_data_length;
	struct tevent_context *ev;
	struct tevent_req *subreq;
	DATA_BLOB in_blob = data_blob_null;
	DATA_BLOB out_blob;
	DATA_BLOB in_input_buffer;
	DATA_BLOB out_output_buffer;
	uint8_t in_file_info_class;
	struct auth_generic_state *auth_generic_state;
	struct iovec *recv_iov;
	uint32_t saved_tid;
	struct smbXcli_tcon *saved_tcon;

	printf("Starting SMB2-SESSION_REAUTH\n");

	if (!torture_init_connection(&cli)) {
		return false;
	}

	/*
	 * PROTOCOL_SMB2_22 has a bug in win8pre0
	 * it behaves like PROTOCOL_SMB2_02
	 * and returns NT_STATUS_REQUEST_NOT_ACCEPTED,
	 * while it allows it on PROTOCOL_SMB2_02.
	 */
	status = smbXcli_negprot(cli->conn, cli->timeout,
				 PROTOCOL_SMB2_10, PROTOCOL_SMB2_10);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_session_setup(cli, username,
				   password, strlen(password),
				   password, strlen(password),
				   workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_sesssetup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli, share, "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, "session-reauth.txt",
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
		printf("smb2cli_create %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, "",
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
			&dir_persistent,
			&dir_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_query_directory(
		cli->conn, cli->timeout, cli->smb2.session, cli->smb2.tcon,
		1, 0x3, 0, dir_persistent, dir_volatile,
		"session-reauth.txt", 0xffff,
		talloc_tos(), &dir_data, &dir_data_length);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_query_directory returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_prepare(talloc_tos(), &auth_generic_state);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_prepare returned %s\n", nt_errstr(status));
		return false;
	}

	gensec_want_feature(auth_generic_state->gensec_security,
			    GENSEC_FEATURE_SESSION_KEY);
	status = auth_generic_set_username(auth_generic_state, username);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_username returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_set_domain(auth_generic_state, workgroup);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_domain returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_set_password(auth_generic_state, password);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_password returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_start(auth_generic_state, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_start returned %s\n", nt_errstr(status));
		return false;
	}

	ev = event_context_init(talloc_tos());
	if (ev == NULL) {
		printf("event_context_init() returned NULL\n");
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security, talloc_tos(), ev, data_blob_null, &in_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		printf("gensec_update returned %s\n", nt_errstr(status));
		return false;
	}

	subreq = smb2cli_session_setup_send(talloc_tos(), ev,
					    cli->conn,
					    cli->timeout,
					    cli->smb2.session,
					    0x0, /* in_flags */
					    SMB2_CAP_DFS, /* in_capabilities */
					    0, /* in_channel */
					    0, /* in_previous_session_id */
					    &in_blob); /* in_security_buffer */
	if (subreq == NULL) {
		printf("smb2cli_session_setup_send() returned NULL\n");
		return false;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		printf("tevent_req_poll() returned false\n");
		return false;
	}

	status = smb2cli_session_setup_recv(subreq, talloc_tos(),
					    NULL, &out_blob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		printf("smb2cli_session_setup_recv returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security, talloc_tos(), ev, out_blob, &in_blob);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_update returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_query_directory(
		cli->conn, cli->timeout, cli->smb2.session, cli->smb2.tcon,
		1, 0x3, 0, dir_persistent, dir_volatile,
		"session-reauth.txt", 0xffff,
		talloc_tos(), &dir_data, &dir_data_length);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_query_directory returned %s\n", nt_errstr(status));
		return false;
	}

	/*
	 * query_info seems to be a path based operation on Windows...
	 */
	status = smb2cli_query_info(cli->conn,
				    cli->timeout,
				    cli->smb2.session,
				    cli->smb2.tcon,
				    SMB2_GETINFO_SECURITY,
				    0, /* in_file_info_class */
				    1024, /* in_max_output_length */
				    NULL, /* in_input_buffer */
				    SECINFO_OWNER, /* in_additional_info */
				    0, /* in_flags */
				    fid_persistent,
				    fid_volatile,
				    talloc_tos(),
				    &out_output_buffer);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_query_info (security) returned %s\n", nt_errstr(status));
		return false;
	}

	in_file_info_class = SMB_FILE_POSITION_INFORMATION - 1000;
	status = smb2cli_query_info(cli->conn,
				    cli->timeout,
				    cli->smb2.session,
				    cli->smb2.tcon,
				    SMB2_GETINFO_FILE,
				    in_file_info_class,
				    1024, /* in_max_output_length */
				    NULL, /* in_input_buffer */
				    0, /* in_additional_info */
				    0, /* in_flags */
				    fid_persistent,
				    fid_volatile,
				    talloc_tos(),
				    &out_output_buffer);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_query_info (position) returned %s\n", nt_errstr(status));
		return false;
	}

	in_input_buffer = data_blob_talloc(talloc_tos(), NULL, 8);
	SBVAL(in_input_buffer.data, 0, 512);

	in_file_info_class = SMB_FILE_POSITION_INFORMATION - 1000;
	status = smb2cli_set_info(cli->conn,
				  cli->timeout,
				  cli->smb2.session,
				  cli->smb2.tcon,
				  SMB2_GETINFO_FILE,
				  in_file_info_class,
				  &in_input_buffer,
				  0, /* in_additional_info */
				  fid_persistent,
				  fid_volatile);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_set_info (position) returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, "session-reauth-invalid.txt",
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
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_create %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, "",
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
			&dir_persistent,
			&dir_volatile);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_create returned %s\n", nt_errstr(status));
		return false;
	}

	saved_tid = smb2cli_tcon_current_id(cli->smb2.tcon);
	saved_tcon = cli->smb2.tcon;
	cli->smb2.tcon = smbXcli_tcon_create(cli);
	smb2cli_tcon_set_values(cli->smb2.tcon,
				NULL, /* session */
				saved_tid,
				0, /* type */
				0, /* flags */
				0, /* capabilities */
				0  /* maximal_access */);
	status = cli_tree_connect(cli, share, "?????", "", 0);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}
	talloc_free(cli->smb2.tcon);
	cli->smb2.tcon = saved_tcon;

	subreq = smb2cli_session_setup_send(talloc_tos(), ev,
					    cli->conn,
					    cli->timeout,
					    cli->smb2.session,
					    0x0, /* in_flags */
					    SMB2_CAP_DFS, /* in_capabilities */
					    0, /* in_channel */
					    0, /* in_previous_session_id */
					    &in_blob); /* in_security_buffer */
	if (subreq == NULL) {
		printf("smb2cli_session_setup_send() returned NULL\n");
		return false;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		printf("tevent_req_poll() returned false\n");
		return false;
	}

	status = smb2cli_session_setup_recv(subreq, talloc_tos(),
					    &recv_iov, &out_blob);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_session_setup_recv returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = smb2cli_flush(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_query_info(cli->conn,
				    cli->timeout,
				    cli->smb2.session,
				    cli->smb2.tcon,
				    SMB2_GETINFO_SECURITY,
				    0, /* in_file_info_class */
				    1024, /* in_max_output_length */
				    NULL, /* in_input_buffer */
				    SECINFO_OWNER, /* in_additional_info */
				    0, /* in_flags */
				    fid_persistent,
				    fid_volatile,
				    talloc_tos(),
				    &out_output_buffer);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_query_info (security) returned %s\n", nt_errstr(status));
		return false;
	}

	in_file_info_class = SMB_FILE_POSITION_INFORMATION - 1000;
	status = smb2cli_query_info(cli->conn,
				    cli->timeout,
				    cli->smb2.session,
				    cli->smb2.tcon,
				    SMB2_GETINFO_FILE,
				    in_file_info_class,
				    1024, /* in_max_output_length */
				    NULL, /* in_input_buffer */
				    0, /* in_additional_info */
				    0, /* in_flags */
				    fid_persistent,
				    fid_volatile,
				    talloc_tos(),
				    &out_output_buffer);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_query_info (position) returned %s\n", nt_errstr(status));
		return false;
	}

	in_input_buffer = data_blob_talloc(talloc_tos(), NULL, 8);
	SBVAL(in_input_buffer.data, 0, 512);

	in_file_info_class = SMB_FILE_POSITION_INFORMATION - 1000;
	status = smb2cli_set_info(cli->conn,
				  cli->timeout,
				  cli->smb2.session,
				  cli->smb2.tcon,
				  SMB2_GETINFO_FILE,
				  in_file_info_class,
				  &in_input_buffer,
				  0, /* in_additional_info */
				  fid_persistent,
				  fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_set_info (position) returned %s\n", nt_errstr(status));
		return false;
	}

	in_file_info_class = SMB_FILE_POSITION_INFORMATION - 1000;
	status = smb2cli_query_info(cli->conn,
				    cli->timeout,
				    cli->smb2.session,
				    cli->smb2.tcon,
				    SMB2_GETINFO_FILE,
				    in_file_info_class,
				    1024, /* in_max_output_length */
				    NULL, /* in_input_buffer */
				    0, /* in_additional_info */
				    0, /* in_flags */
				    fid_persistent,
				    fid_volatile,
				    talloc_tos(),
				    &out_output_buffer);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_query_info (position) returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_close(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, "session-reauth.txt",
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
		printf("smb2cli_create %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_query_directory(
		cli->conn, cli->timeout, cli->smb2.session, cli->smb2.tcon,
		1, 0x3, 0, dir_persistent, dir_volatile,
		"session-reauth.txt", 0xffff,
		talloc_tos(), &dir_data, &dir_data_length);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_query_directory returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_close(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, 0, dir_persistent, dir_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_close(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	saved_tid = smb2cli_tcon_current_id(cli->smb2.tcon);
	saved_tcon = cli->smb2.tcon;
	cli->smb2.tcon = smbXcli_tcon_create(cli);
	smb2cli_tcon_set_values(cli->smb2.tcon,
				NULL, /* session */
				saved_tid,
				0, /* type */
				0, /* flags */
				0, /* capabilities */
				0  /* maximal_access */);
	status = cli_tree_connect(cli, share, "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}
	talloc_free(cli->smb2.tcon);
	cli->smb2.tcon = saved_tcon;

	return true;
}
