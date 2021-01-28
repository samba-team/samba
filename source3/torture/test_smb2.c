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
#include "libcli/security/security.h"
#include "libsmb/proto.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth_generic.h"
#include "../librpc/ndr/libndr.h"
#include "libsmb/clirap.h"
#include "libsmb/cli_smb2_fnum.h"

extern fstring host, workgroup, share, password, username, myname;
extern struct cli_credentials *torture_creds;

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

	status = cli_session_setup_creds(cli, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli, share, "?????", NULL);
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
			&fid_volatile,
			NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello, NULL);
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
			&fid_volatile,
			NULL, NULL, NULL);
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
	saved_tcon = cli_state_save_tcon(cli);
	if (saved_tcon == NULL) {
		return false;
	}
	cli->smb2.tcon = smbXcli_tcon_create(cli);
	smb2cli_tcon_set_values(cli->smb2.tcon,
				NULL, /* session */
				saved_tid,
				0, /* type */
				0, /* flags */
				0, /* capabilities */
				0  /* maximal_access */);
	status = smb2cli_tdis(cli->conn,
			      cli->timeout,
			      cli->smb2.session,
			      cli->smb2.tcon);
	cli_state_restore_tcon(cli, saved_tcon);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_tdis returned %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_tdis(cli->conn,
			      cli->timeout,
			      cli->smb2.session,
			      cli->smb2.tcon);
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
	name = smb_protocol_types_string(protocol);

	if (protocol >= PROTOCOL_SMB2_02) {
		printf("Server supports %s\n", name);
	} else {
		printf("Server DOES NOT support SMB2, only %s\n", name);
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

bool run_smb2_anonymous(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	struct cli_credentials *anon_creds = NULL;
	bool guest = false;

	printf("Starting SMB2-ANONYMOUS\n");

	if (!torture_init_connection(&cli)) {
		return false;
	}

	status = smbXcli_negprot(cli->conn, cli->timeout,
				 PROTOCOL_SMB2_02, PROTOCOL_LATEST);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	anon_creds = cli_credentials_init_anon(talloc_tos());
	if (anon_creds == NULL) {
		printf("cli_credentials_init_anon failed\n");
		return false;
	}

	status = cli_session_setup_creds(cli, anon_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		return false;
	}

	guest = smbXcli_session_is_guest(cli->smb2.session);
	if (guest) {
		printf("anonymous session should not have guest authentication\n");
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

	status = cli_session_setup_creds(cli1, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli1, share, "?????", NULL);
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
			&fid_volatile,
			NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create on cli1 %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli1->conn, cli1->timeout, cli1->smb2.session,
			       cli1->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello, NULL);
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

	status = auth_generic_set_creds(auth_generic_state, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_creds returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_start(auth_generic_state, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_start returned %s\n", nt_errstr(status));
		return false;
	}

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		printf("samba_tevent_context_init() returned NULL\n");
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), data_blob_null, &in_blob);
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

	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), out_blob, &in_blob);
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

	status = cli_tree_connect(cli1, share, "?????", NULL);
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
			       fid_volatile, 0, 0, (const uint8_t *)hello, NULL);
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
			&fid_volatile,
			NULL, NULL, NULL);
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
			       fid_volatile, 0, 0, (const uint8_t *)hello, NULL);
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
			&fid_volatile,
			NULL, NULL, NULL);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED))
	{
		printf("smb2cli_create on cli2 %s\n", nt_errstr(status));
		return false;
	}

	/* now do a new tcon and test file calls again */

	status = cli_tree_connect(cli2, share, "?????", NULL);
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
			&fid_volatile,
			NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create on cli2 %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli2->conn, cli2->timeout, cli2->smb2.session,
			       cli2->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello, NULL);
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

	status = cli_session_setup_creds(cli, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli, share, "?????", NULL);
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
			&fid_volatile,
			NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create on cli %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello, NULL);
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
	struct GUID saved_guid = cli_state_client_guid;

	printf("Starting SMB2-MULTI-CHANNEL\n");

	cli_state_client_guid = GUID_random();

	if (!torture_init_connection(&cli1)) {
		return false;
	}

	if (!torture_init_connection(&cli2)) {
		return false;
	}

	if (!torture_init_connection(&cli3)) {
		return false;
	}

	cli_state_client_guid = saved_guid;

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

	status = cli_session_setup_creds(cli1, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_sesssetup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli1, share, "?????", NULL);
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

	status = auth_generic_set_creds(auth_generic_state, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_creds returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_start(auth_generic_state, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_start returned %s\n", nt_errstr(status));
		return false;
	}

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		printf("samba_tevent_context_init() returned NULL\n");
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), data_blob_null, &in_blob);
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

	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), out_blob, &in_blob);
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

	status = auth_generic_set_creds(auth_generic_state, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_creds returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_start(auth_generic_state, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_start returned %s\n", nt_errstr(status));
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), data_blob_null, &in_blob);
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

	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), out_blob, &in_blob);
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
			&fid_volatile,
			NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create on cli2 %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_write(cli1->conn, cli1->timeout, cli1->smb2.session,
			       cli1->smb2.tcon, strlen(hello), 0, fid_persistent,
			       fid_volatile, 0, 0, (const uint8_t *)hello, NULL);
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

	status = auth_generic_set_creds(auth_generic_state, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_creds returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_start(auth_generic_state, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_start returned %s\n", nt_errstr(status));
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), data_blob_null, &in_blob);
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

	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), out_blob, &in_blob);
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
			&fid_volatile,
			NULL, NULL, NULL);
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
			&fid_volatile,
			NULL, NULL, NULL);
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
			&fid_volatile,
			NULL, NULL, NULL);
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

	status = cli_session_setup_creds(cli, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_sesssetup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli, share, "?????", NULL);
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
			&fid_volatile,
			NULL, NULL, NULL);
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
			&dir_volatile,
			NULL, NULL, NULL);
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

	status = auth_generic_set_creds(auth_generic_state, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_set_creds returned %s\n", nt_errstr(status));
		return false;
	}

	status = auth_generic_client_start(auth_generic_state, GENSEC_OID_NTLMSSP);
	if (!NT_STATUS_IS_OK(status)) {
		printf("auth_generic_client_start returned %s\n", nt_errstr(status));
		return false;
	}

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		printf("samba_tevent_context_init() returned NULL\n");
		return false;
	}

	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), data_blob_null, &in_blob);
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

	status = gensec_update(auth_generic_state->gensec_security,
			       talloc_tos(), out_blob, &in_blob);
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
				    SMB2_0_INFO_SECURITY,
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
				    SMB2_0_INFO_FILE,
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
				  SMB2_0_INFO_FILE,
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
			&fid_volatile,
			NULL, NULL, NULL);
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
			&dir_volatile,
			NULL, NULL, NULL);
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
	status = cli_tree_connect(cli, share, "?????", NULL);
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
				    SMB2_0_INFO_SECURITY,
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
				    SMB2_0_INFO_FILE,
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
				  SMB2_0_INFO_FILE,
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
				    SMB2_0_INFO_FILE,
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
			&fid_volatile,
			NULL, NULL, NULL);
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
	status = cli_tree_connect(cli, share, "?????", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}
	talloc_free(cli->smb2.tcon);
	cli->smb2.tcon = saved_tcon;

	return true;
}

static NTSTATUS check_size(struct cli_state *cli,
				uint16_t fnum,
				const char *fname,
				size_t size)
{
	off_t size_read = 0;

	NTSTATUS status = cli_qfileinfo_basic(cli,
				fnum,
				NULL,
				&size_read,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL);

	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_qfileinfo_basic of %s failed (%s)\n",
			fname,
			nt_errstr(status));
		return status;
	}

	if (size != size_read) {
		printf("size (%u) != size_read(%u) for %s\n",
			(unsigned int)size,
			(unsigned int)size_read,
			fname);
		/* Use EOF to mean bad size. */
		return NT_STATUS_END_OF_FILE;
	}
	return NT_STATUS_OK;
}

/* Ensure cli_ftruncate() works for SMB2. */

bool run_smb2_ftruncate(int dummy)
{
	struct cli_state *cli = NULL;
	const char *fname = "smb2_ftruncate.txt";
	uint16_t fnum = (uint16_t)-1;
	bool correct = false;
	size_t buflen = 1024*1024;
	uint8_t *buf = NULL;
	unsigned int i;
	NTSTATUS status;

	printf("Starting SMB2-FTRUNCATE\n");

	if (!torture_init_connection(&cli)) {
		goto fail;
	}

	status = smbXcli_negprot(cli->conn, cli->timeout,
				 PROTOCOL_SMB2_02, PROTOCOL_SMB2_02);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		goto fail;
	}

	status = cli_session_setup_creds(cli, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		goto fail;
	}

	status = cli_tree_connect(cli, share, "?????", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		goto fail;
	}

	cli_setatr(cli, fname, 0, 0);
	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	status = cli_ntcreate(cli,
				fname,
				0,
				GENERIC_ALL_ACCESS,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_NONE,
				FILE_CREATE,
				0,
				0,
				&fnum,
				NULL);

        if (!NT_STATUS_IS_OK(status)) {
                printf("open of %s failed (%s)\n", fname, nt_errstr(status));
                goto fail;
        }

	buf = talloc_zero_array(cli, uint8_t, buflen);
	if (buf == NULL) {
		goto fail;
	}

	/* Write 1MB. */
	status = cli_writeall(cli,
				fnum,
				0,
				buf,
				0,
				buflen,
				NULL);

	if (!NT_STATUS_IS_OK(status)) {
		printf("write of %u to %s failed (%s)\n",
			(unsigned int)buflen,
			fname,
			nt_errstr(status));
		goto fail;
	}

	status = check_size(cli, fnum, fname, buflen);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* Now ftruncate. */
	for ( i = 0; i < 10; i++) {
		status = cli_ftruncate(cli, fnum, i*1024);
		if (!NT_STATUS_IS_OK(status)) {
			printf("cli_ftruncate %u of %s failed (%s)\n",
				(unsigned int)i*1024,
				fname,
				nt_errstr(status));
			goto fail;
		}
		status = check_size(cli, fnum, fname, i*1024);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	correct = true;

  fail:

	if (cli == NULL) {
		return false;
	}

	if (fnum != (uint16_t)-1) {
		cli_close(cli, fnum);
	}
	cli_setatr(cli, fname, 0, 0);
	cli_unlink(cli, fname, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	if (!torture_close_connection(cli)) {
		correct = false;
	}
	return correct;
}

/* Ensure SMB2 flush on directories behaves correctly. */

static bool test_dir_fsync(struct cli_state *cli, const char *path)
{
	NTSTATUS status;
	uint64_t fid_persistent, fid_volatile;
	uint8_t *dir_data = NULL;
	uint32_t dir_data_length = 0;

	/* Open directory - no write abilities. */
	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, path,
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
			&fid_volatile,
			NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create '%s' (readonly) returned %s\n",
			path,
			nt_errstr(status));
		return false;
	}

	status = smb2cli_query_directory(
		cli->conn, cli->timeout, cli->smb2.session, cli->smb2.tcon,
		1, 0, 0, fid_persistent, fid_volatile, "*", 0xffff,
		talloc_tos(), &dir_data, &dir_data_length);

	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_query_directory returned %s\n",
			nt_errstr(status));
		return false;
	}

	/* Open directory no write access. Flush should fail. */

	status = smb2cli_flush(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("smb2cli_flush on a read-only directory returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = smb2cli_close(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	/* Open directory write-attributes only. Flush should still fail. */

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, path,
			SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
			SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
			SEC_STD_SYNCHRONIZE|
			SEC_DIR_LIST|
			SEC_DIR_WRITE_ATTRIBUTE|
			SEC_DIR_READ_ATTRIBUTE, /* desired_access, */
			0, /* file_attributes, */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
			FILE_OPEN, /* create_disposition, */
			FILE_SYNCHRONOUS_IO_NONALERT|FILE_DIRECTORY_FILE, /* create_options, */
			NULL, /* smb2_create_blobs *blobs */
			&fid_persistent,
			&fid_volatile,
			NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create '%s' (write attr) returned %s\n",
			path,
			nt_errstr(status));
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

	status = smb2cli_flush(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("smb2cli_flush on a write-attributes directory "
			"returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = smb2cli_close(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	/* Open directory with SEC_DIR_ADD_FILE access. Flush should now succeed. */

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, path,
			SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
			SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
			SEC_STD_SYNCHRONIZE|
			SEC_DIR_LIST|
			SEC_DIR_ADD_FILE, /* desired_access, */
			0, /* file_attributes, */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
			FILE_OPEN, /* create_disposition, */
			FILE_SYNCHRONOUS_IO_NONALERT|FILE_DIRECTORY_FILE, /* create_options, */
			NULL, /* smb2_create_blobs *blobs */
			&fid_persistent,
			&fid_volatile,
			NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create '%s' (write FILE access) returned %s\n",
			path,
			nt_errstr(status));
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

	status = smb2cli_flush(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush on a directory returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = smb2cli_close(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	/* Open directory with SEC_DIR_ADD_FILE access. Flush should now succeed. */

	status = smb2cli_create(cli->conn, cli->timeout, cli->smb2.session,
			cli->smb2.tcon, path,
			SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
			SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
			SEC_STD_SYNCHRONIZE|
			SEC_DIR_LIST|
			SEC_DIR_ADD_SUBDIR, /* desired_access, */
			0, /* file_attributes, */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
			FILE_OPEN, /* create_disposition, */
			FILE_SYNCHRONOUS_IO_NONALERT|FILE_DIRECTORY_FILE, /* create_options, */
			NULL, /* smb2_create_blobs *blobs */
			&fid_persistent,
			&fid_volatile,
			NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create '%s' (write DIR access) returned %s\n",
			path,
			nt_errstr(status));
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

	status = smb2cli_flush(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_flush on a directory returned %s\n",
			nt_errstr(status));
		return false;
	}

	status = smb2cli_close(cli->conn, cli->timeout, cli->smb2.session,
			       cli->smb2.tcon, 0, fid_persistent, fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}


	return true;
}

bool run_smb2_dir_fsync(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	bool bret = false;
	const char *dname = "fsync_test_dir";

	printf("Starting SMB2-DIR-FSYNC\n");

	if (!torture_init_connection(&cli)) {
		return false;
	}

	status = smbXcli_negprot(cli->conn, cli->timeout,
				 PROTOCOL_SMB2_02, PROTOCOL_SMB2_02);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_session_setup_creds(cli, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli, share, "?????", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	(void)cli_rmdir(cli, dname);
	status = cli_mkdir(cli, dname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_mkdir(%s) returned %s\n",
			dname,
			nt_errstr(status));
		return false;
	}

	/* Test on a subdirectory. */
	bret = test_dir_fsync(cli, dname);
	if (bret == false) {
		(void)cli_rmdir(cli, dname);
		return false;
	}
	(void)cli_rmdir(cli, dname);

	/* Test on the root handle of a share. */
	bret = test_dir_fsync(cli, "");
	if (bret == false) {
		return false;
	}
	return true;
}

bool run_smb2_path_slash(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	uint64_t fid_persistent;
	uint64_t fid_volatile;
	const char *dname_noslash = "smb2_dir_slash";
	const char *dname_backslash = "smb2_dir_slash\\";
	const char *dname_slash = "smb2_dir_slash/";
	const char *fname_noslash = "smb2_file_slash";
	const char *fname_backslash = "smb2_file_slash\\";
	const char *fname_slash = "smb2_file_slash/";

	printf("Starting SMB2-PATH-SLASH\n");

	if (!torture_init_connection(&cli)) {
		return false;
	}

	status = smbXcli_negprot(cli->conn, cli->timeout,
				 PROTOCOL_SMB2_02, PROTOCOL_SMB2_02);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_session_setup_creds(cli, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli, share, "?????", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	(void)cli_unlink(cli, dname_noslash, 0);
	(void)cli_rmdir(cli, dname_noslash);
	(void)cli_unlink(cli, fname_noslash, 0);
	(void)cli_rmdir(cli, fname_noslash);

	/* Try to create a directory with the backslash name. */
	status = smb2cli_create(cli->conn,
			cli->timeout,
			cli->smb2.session,
			cli->smb2.tcon,
			dname_backslash,
			SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
			SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
			FILE_READ_DATA|FILE_READ_ATTRIBUTES, /* desired_access, */
			0, /* file_attributes, */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
			FILE_CREATE, /* create_disposition, */
			FILE_DIRECTORY_FILE, /* create_options, */
			NULL, /* smb2_create_blobs *blobs */
			&fid_persistent,
			&fid_volatile,
			NULL, NULL, NULL);

	/* directory ending in '\\' should be success. */

	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create '%s' returned %s - "
			"should be NT_STATUS_OK\n",
			dname_backslash,
			nt_errstr(status));
		return false;
	}
	status = smb2cli_close(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				0,
				fid_persistent,
				fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_close returned %s\n", nt_errstr(status));
		return false;
	}

	(void)cli_rmdir(cli, dname_noslash);

	/* Try to create a directory with the slash name. */
	status = smb2cli_create(cli->conn,
			cli->timeout,
			cli->smb2.session,
			cli->smb2.tcon,
			dname_slash,
			SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
			SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
			FILE_READ_DATA|FILE_READ_ATTRIBUTES, /* desired_access, */
			0, /* file_attributes, */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
			FILE_CREATE, /* create_disposition, */
			FILE_DIRECTORY_FILE, /* create_options, */
			NULL, /* smb2_create_blobs *blobs */
			&fid_persistent,
			&fid_volatile,
			NULL, NULL, NULL);

	/* directory ending in '/' is an error. */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_INVALID)) {
		printf("smb2cli_create '%s' returned %s - "
			"should be NT_STATUS_OBJECT_NAME_INVALID\n",
			dname_slash,
			nt_errstr(status));
		if (NT_STATUS_IS_OK(status)) {
			(void)smb2cli_close(cli->conn,
					cli->timeout,
					cli->smb2.session,
					cli->smb2.tcon,
					0,
					fid_persistent,
					fid_volatile);
		}
		(void)cli_rmdir(cli, dname_noslash);
		return false;
	}

	(void)cli_rmdir(cli, dname_noslash);

	/* Try to create a file with the backslash name. */
	status = smb2cli_create(cli->conn,
			cli->timeout,
			cli->smb2.session,
			cli->smb2.tcon,
			fname_backslash,
			SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
			SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
			FILE_READ_DATA|FILE_READ_ATTRIBUTES, /* desired_access, */
			0, /* file_attributes, */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
			FILE_CREATE, /* create_disposition, */
			FILE_NON_DIRECTORY_FILE, /* create_options, */
			NULL, /* smb2_create_blobs *blobs */
			&fid_persistent,
			&fid_volatile,
			NULL, NULL, NULL);

	/* file ending in '\\' should be error. */

	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_INVALID)) {
		printf("smb2cli_create '%s' returned %s - "
			"should be NT_STATUS_OBJECT_NAME_INVALID\n",
			fname_backslash,
			nt_errstr(status));
		if (NT_STATUS_IS_OK(status)) {
			(void)smb2cli_close(cli->conn,
					cli->timeout,
					cli->smb2.session,
					cli->smb2.tcon,
					0,
					fid_persistent,
					fid_volatile);
		}
		(void)cli_unlink(cli, fname_noslash, 0);
		return false;
	}

	(void)cli_unlink(cli, fname_noslash, 0);

	/* Try to create a file with the slash name. */
	status = smb2cli_create(cli->conn,
			cli->timeout,
			cli->smb2.session,
			cli->smb2.tcon,
			fname_slash,
			SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
			SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
			FILE_READ_DATA|FILE_READ_ATTRIBUTES, /* desired_access, */
			0, /* file_attributes, */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
			FILE_CREATE, /* create_disposition, */
			FILE_NON_DIRECTORY_FILE, /* create_options, */
			NULL, /* smb2_create_blobs *blobs */
			&fid_persistent,
			&fid_volatile,
			NULL, NULL, NULL);

	/* file ending in '/' should be error. */

	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_INVALID)) {
		printf("smb2cli_create '%s' returned %s - "
			"should be NT_STATUS_OBJECT_NAME_INVALID\n",
			fname_slash,
			nt_errstr(status));
		if (NT_STATUS_IS_OK(status)) {
			(void)smb2cli_close(cli->conn,
					cli->timeout,
					cli->smb2.session,
					cli->smb2.tcon,
					0,
					fid_persistent,
					fid_volatile);
		}
		(void)cli_unlink(cli, fname_noslash, 0);
		return false;
	}

	(void)cli_unlink(cli, fname_noslash, 0);
	return true;
}

/*
 * NB. This can only work against a server where
 * the connecting user has been granted SeSecurityPrivilege.
 *
 *  1). Create a test file.
 *  2). Open with SEC_FLAG_SYSTEM_SECURITY *only*. ACCESS_DENIED -
 *             NB. SMB2-only behavior.
 *  3). Open with SEC_FLAG_SYSTEM_SECURITY|FILE_WRITE_ATTRIBUTES.
 *  4). Write SACL. Should fail with ACCESS_DENIED (seems to need WRITE_DAC).
 *  5). Close (3).
 *  6). Open with SEC_FLAG_SYSTEM_SECURITY|SEC_STD_WRITE_DAC.
 *  7). Write SACL. Success.
 *  8). Close (4).
 *  9). Open with SEC_FLAG_SYSTEM_SECURITY|READ_ATTRIBUTES.
 *  10). Read SACL. Success.
 *  11). Read DACL. Should fail with ACCESS_DENIED (no READ_CONTROL).
 *  12). Close (9).
 */

bool run_smb2_sacl(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	struct security_descriptor *sd_dacl = NULL;
	struct security_descriptor *sd_sacl = NULL;
	const char *fname = "sacl_test_file";
	uint16_t fnum = (uint16_t)-1;

	printf("Starting SMB2-SACL\n");

	if (!torture_init_connection(&cli)) {
		return false;
	}

	status = smbXcli_negprot(cli->conn,
				cli->timeout,
				PROTOCOL_SMB2_02,
				PROTOCOL_SMB3_11);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_session_setup_creds(cli, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli, share, "?????", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	(void)cli_unlink(cli, fname, 0);

	/* First create a file. */
	status = cli_ntcreate(cli,
				fname,
				0,
				GENERIC_ALL_ACCESS,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_NONE,
				FILE_CREATE,
				0,
				0,
				&fnum,
				NULL);

        if (!NT_STATUS_IS_OK(status)) {
		printf("Create of %s failed (%s)\n",
			fname,
			nt_errstr(status));
                goto fail;
        }

	cli_close(cli, fnum);
	fnum = (uint16_t)-1;

	/*
	 * Now try to open with *only* SEC_FLAG_SYSTEM_SECURITY.
	 * This should fail with NT_STATUS_ACCESS_DENIED - but
	 * only against an SMB2 server. SMB1 allows this as tested
	 * in SMB1-SYSTEM-SECURITY.
	 */

	status = cli_smb2_create_fnum(cli,
			fname,
			SMB2_OPLOCK_LEVEL_NONE,
			SMB2_IMPERSONATION_IMPERSONATION,
			SEC_FLAG_SYSTEM_SECURITY, /* desired access */
			0, /* file_attributes, */
			FILE_SHARE_READ|
				FILE_SHARE_WRITE|
				FILE_SHARE_DELETE, /* share_access, */
			FILE_OPEN, /* create_disposition, */
			FILE_NON_DIRECTORY_FILE, /* create_options, */
			NULL, /* in_cblobs. */
			&fnum, /* fnum */
			NULL, /* smb_create_returns  */
			talloc_tos(), /* mem_ctx */
			NULL); /* out_cblobs */

	if (NT_STATUS_EQUAL(status, NT_STATUS_PRIVILEGE_NOT_HELD)) {
		printf("SMB2-SACL-TEST can only work with a user "
			"who has been granted SeSecurityPrivilege.\n"
			"This is the "
			"\"Manage auditing and security log\""
			"privilege setting on Windows\n");
		goto fail;
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("open file %s with SEC_FLAG_SYSTEM_SECURITY only: "
			"got %s - should fail with ACCESS_DENIED\n",
			fname,
			nt_errstr(status));
		goto fail;
	}

	/*
	 * Open with SEC_FLAG_SYSTEM_SECURITY|FILE_WRITE_ATTRIBUTES.
	 */

	status = cli_smb2_create_fnum(cli,
			fname,
			SMB2_OPLOCK_LEVEL_NONE,
			SMB2_IMPERSONATION_IMPERSONATION,
			SEC_FLAG_SYSTEM_SECURITY|
				FILE_WRITE_ATTRIBUTES, /* desired access */
			0, /* file_attributes, */
			FILE_SHARE_READ|
				FILE_SHARE_WRITE|
				FILE_SHARE_DELETE, /* share_access, */
			FILE_OPEN, /* create_disposition, */
			FILE_NON_DIRECTORY_FILE, /* create_options, */
			NULL, /* in_cblobs. */
			&fnum, /* fnum */
			NULL, /* smb_create_returns  */
			talloc_tos(), /* mem_ctx */
			NULL); /* out_cblobs */

        if (!NT_STATUS_IS_OK(status)) {
		printf("Open of %s with (SEC_FLAG_SYSTEM_SECURITY|"
			"FILE_WRITE_ATTRIBUTES) failed (%s)\n",
			fname,
			nt_errstr(status));
		goto fail;
        }

	/* Create an SD with a SACL. */
	sd_sacl = security_descriptor_sacl_create(talloc_tos(),
				0,
				NULL, /* owner. */
				NULL, /* group. */
				/* first ACE. */
				SID_WORLD,
				SEC_ACE_TYPE_SYSTEM_AUDIT,
				SEC_GENERIC_ALL,
				SEC_ACE_FLAG_FAILED_ACCESS,
				NULL);

	if (sd_sacl == NULL) {
		printf("Out of memory creating SACL\n");
		goto fail;
	}

	/*
	 * Write the SACL SD. This should fail
	 * even though we have SEC_FLAG_SYSTEM_SECURITY,
	 * as it seems to also need WRITE_DAC access.
	 */
	status = cli_smb2_set_security_descriptor(cli,
				fnum,
				SECINFO_DACL|SECINFO_SACL,
				sd_sacl);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("Writing SACL on file %s got (%s) "
			"should have failed with ACCESS_DENIED.\n",
			fname,
			nt_errstr(status));
		goto fail;
        }

	/* And close. */
	cli_smb2_close_fnum(cli, fnum);
	fnum = (uint16_t)-1;

	/*
	 * Open with SEC_FLAG_SYSTEM_SECURITY|SEC_STD_WRITE_DAC.
	 */

	status = cli_smb2_create_fnum(cli,
			fname,
			SMB2_OPLOCK_LEVEL_NONE,
			SMB2_IMPERSONATION_IMPERSONATION,
			SEC_FLAG_SYSTEM_SECURITY|
				SEC_STD_WRITE_DAC, /* desired access */
			0, /* file_attributes, */
			FILE_SHARE_READ|
				FILE_SHARE_WRITE|
				FILE_SHARE_DELETE, /* share_access, */
			FILE_OPEN, /* create_disposition, */
			FILE_NON_DIRECTORY_FILE, /* create_options, */
			NULL, /* in_cblobs. */
			&fnum, /* fnum */
			NULL, /* smb_create_returns  */
			talloc_tos(), /* mem_ctx */
			NULL); /* out_cblobs */

        if (!NT_STATUS_IS_OK(status)) {
		printf("Open of %s with (SEC_FLAG_SYSTEM_SECURITY|"
			"FILE_WRITE_ATTRIBUTES) failed (%s)\n",
			fname,
			nt_errstr(status));
		goto fail;
        }

	/*
	 * Write the SACL SD. This should now succeed
	 * as we have both SEC_FLAG_SYSTEM_SECURITY
	 * and WRITE_DAC access.
	 */
	status = cli_smb2_set_security_descriptor(cli,
				fnum,
				SECINFO_DACL|SECINFO_SACL,
				sd_sacl);

        if (!NT_STATUS_IS_OK(status)) {
		printf("cli_smb2_set_security_descriptor SACL "
			"on file %s failed (%s)\n",
			fname,
			nt_errstr(status));
		goto fail;
        }

	/* And close. */
	cli_smb2_close_fnum(cli, fnum);
	fnum = (uint16_t)-1;

	/* We're done with the sacl we made. */
	TALLOC_FREE(sd_sacl);

	/*
	 * Now try to open with SEC_FLAG_SYSTEM_SECURITY|READ_ATTRIBUTES.
	 * This gives us access to the SACL.
	 */

	status = cli_smb2_create_fnum(cli,
			fname,
			SMB2_OPLOCK_LEVEL_NONE,
			SMB2_IMPERSONATION_IMPERSONATION,
			SEC_FLAG_SYSTEM_SECURITY|
				FILE_READ_ATTRIBUTES, /* desired access */
			0, /* file_attributes, */
			FILE_SHARE_READ|
				FILE_SHARE_WRITE|
				FILE_SHARE_DELETE, /* share_access, */
			FILE_OPEN, /* create_disposition, */
			FILE_NON_DIRECTORY_FILE, /* create_options, */
			NULL, /* in_cblobs. */
			&fnum, /* fnum */
			NULL, /* smb_create_returns  */
			talloc_tos(), /* mem_ctx */
			NULL); /* out_cblobs */

        if (!NT_STATUS_IS_OK(status)) {
		printf("Open of %s with (SEC_FLAG_SYSTEM_SECURITY|"
			"FILE_READ_ATTRIBUTES) failed (%s)\n",
			fname,
			nt_errstr(status));
		goto fail;
        }

	/* Try and read the SACL - should succeed. */
	status = cli_smb2_query_security_descriptor(cli,
				fnum,
				SECINFO_SACL,
				talloc_tos(),
				&sd_sacl);

        if (!NT_STATUS_IS_OK(status)) {
		printf("Read SACL from file %s failed (%s)\n",
			fname,
			nt_errstr(status));
		goto fail;
        }

	TALLOC_FREE(sd_sacl);

	/*
	 * Try and read the DACL - should fail as we have
	 * no READ_DAC access.
	 */
	status = cli_smb2_query_security_descriptor(cli,
				fnum,
				SECINFO_DACL,
				talloc_tos(),
				&sd_sacl);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("Reading DACL on file %s got (%s) "
			"should have failed with ACCESS_DENIED.\n",
			fname,
			nt_errstr(status));
		goto fail;
        }

	if (fnum != (uint16_t)-1) {
		cli_smb2_close_fnum(cli, fnum);
		fnum = (uint16_t)-1;
	}

	TALLOC_FREE(sd_dacl);
	TALLOC_FREE(sd_sacl);

	(void)cli_unlink(cli, fname, 0);
	return true;

  fail:

	TALLOC_FREE(sd_dacl);
	TALLOC_FREE(sd_sacl);

	if (fnum != (uint16_t)-1) {
		cli_smb2_close_fnum(cli, fnum);
		fnum = (uint16_t)-1;
	}

	(void)cli_unlink(cli, fname, 0);
	return false;
}

bool run_smb2_quota1(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	uint16_t fnum = (uint16_t)-1;
	SMB_NTQUOTA_STRUCT qt = {0};

	printf("Starting SMB2-SACL\n");

	if (!torture_init_connection(&cli)) {
		return false;
	}

	status = smbXcli_negprot(cli->conn,
				cli->timeout,
				PROTOCOL_SMB2_02,
				PROTOCOL_SMB3_11);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_session_setup_creds(cli, torture_creds);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_session_setup returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_tree_connect(cli, share, "?????", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_tree_connect returned %s\n", nt_errstr(status));
		return false;
	}

	status = cli_smb2_create_fnum(
		cli,
		"\\",
		SMB2_OPLOCK_LEVEL_NONE,
		SMB2_IMPERSONATION_IMPERSONATION,
		SEC_GENERIC_READ, /* desired access */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_OPEN, /* create_disposition, */
		FILE_DIRECTORY_FILE, /* create_options, */
		NULL, /* in_cblobs. */
		&fnum, /* fnum */
		NULL, /* smb_create_returns  */
		NULL, /* mem_ctx */
		NULL); /* out_cblobs */
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_smb2_create_fnum failed: %s\n", nt_errstr(status));
		return false;
	}

	status = cli_smb2_get_user_quota(cli, fnum, &qt);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("cli_smb2_get_user_quota returned %s, expected "
		       "NT_STATUS_INVALID_HANDLE\n",
		       nt_errstr(status));
		return false;
	}

	return true;
}
