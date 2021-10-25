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
	char *saved_share = NULL;
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

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		"smb2-basic.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		"",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_SYNCHRONIZE|
		SEC_DIR_LIST|
		SEC_DIR_READ_ATTRIBUTE, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_OPEN, /* create_disposition, */
		FILE_SYNCHRONOUS_IO_NONALERT|
		FILE_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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
	cli_state_save_tcon_share(cli, &saved_tcon, &saved_share);
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
	cli_state_restore_tcon_share(cli, saved_tcon, saved_share);
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

	status = smb2cli_create(
		cli1->conn,
		cli1->timeout,
		cli1->smb2.session,
		cli1->smb2.tcon,
		"session-reconnect.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli2->conn,
		cli2->timeout,
		cli2->smb2.session,
		cli2->smb2.tcon,
		"session-reconnect.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli2->conn,
		cli2->timeout,
		cli2->smb2.session,
		cli1->smb2.tcon,
		"session-reconnect.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli2->conn,
		cli2->timeout,
		cli2->smb2.session,
		cli2->smb2.tcon,
		"session-reconnect.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		"tcon_depedence.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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
				 PROTOCOL_SMB3_00, PROTOCOL_LATEST);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = smbXcli_negprot(cli2->conn, cli2->timeout,
				 PROTOCOL_SMB3_00, PROTOCOL_LATEST);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smbXcli_negprot returned %s\n", nt_errstr(status));
		return false;
	}

	status = smbXcli_negprot(cli3->conn, cli3->timeout,
				 PROTOCOL_SMB3_00, PROTOCOL_LATEST);
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

	status = smb2cli_create(
		cli2->conn,
		cli2->timeout,
		cli2->smb2.session,
		cli1->smb2.tcon,
		"multi-channel.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli1->conn,
		cli1->timeout,
		cli1->smb2.session,
		cli1->smb2.tcon,
		"multi-channel-invalid.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_create %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(
		cli2->conn,
		cli2->timeout,
		cli2->smb2.session,
		cli1->smb2.tcon,
		"multi-channel-invalid.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_create %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(
		cli3->conn,
		cli3->timeout,
		cli3->smb2.session,
		cli1->smb2.tcon,
		"multi-channel-invalid.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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
	 * while it allows it on PROTOCOL_SMB2_10.
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

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		"session-reauth.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("smb2cli_create %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		"",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_SYNCHRONIZE|
		SEC_DIR_LIST|
		SEC_DIR_READ_ATTRIBUTE, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_OPEN, /* create_disposition, */
		FILE_SYNCHRONOUS_IO_NONALERT|
		FILE_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&dir_persistent,
		&dir_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		"session-reauth-invalid.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("smb2cli_create %s\n", nt_errstr(status));
		return false;
	}

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		"",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_SYNCHRONIZE|
		SEC_DIR_LIST|
		SEC_DIR_READ_ATTRIBUTE, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_OPEN, /* create_disposition, */
		FILE_SYNCHRONOUS_IO_NONALERT|
		FILE_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&dir_persistent,
		&dir_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		"session-reauth.txt",
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_ALL | SEC_FILE_ALL, /* desired_access, */
		FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DELETE_ON_CLOSE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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
	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		path,
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_SYNCHRONIZE|
		SEC_DIR_LIST|
		SEC_DIR_READ_ATTRIBUTE, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_OPEN, /* create_disposition, */
		FILE_SYNCHRONOUS_IO_NONALERT|
		FILE_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		path,
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_SYNCHRONIZE|
		SEC_DIR_LIST|
		SEC_DIR_WRITE_ATTRIBUTE|
		SEC_DIR_READ_ATTRIBUTE, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_OPEN, /* create_disposition, */
		FILE_SYNCHRONOUS_IO_NONALERT|
		FILE_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		path,
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_SYNCHRONIZE|
		SEC_DIR_LIST|
		SEC_DIR_ADD_FILE, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_OPEN, /* create_disposition, */
		FILE_SYNCHRONOUS_IO_NONALERT|
		FILE_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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

	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		path,
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		SEC_STD_SYNCHRONIZE|
		SEC_DIR_LIST|
		SEC_DIR_ADD_SUBDIR, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_OPEN, /* create_disposition, */
		FILE_SYNCHRONOUS_IO_NONALERT|
		FILE_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);
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
	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		dname_backslash,
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);

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
	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		dname_slash,
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);

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
	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		fname_backslash,
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_NON_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);

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
	status = smb2cli_create(
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		fname_slash,
		SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
		SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, /* desired_access, */
		0, /* file_attributes, */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access, */
		FILE_CREATE, /* create_disposition, */
		FILE_NON_DIRECTORY_FILE, /* create_options, */
		NULL, /* smb2_create_blobs *blobs */
		&fid_persistent,
		&fid_volatile,
		NULL,
		NULL,
		NULL,
		NULL);

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
	status = cli_set_security_descriptor(cli,
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
	status = cli_set_security_descriptor(cli,
				fnum,
				SECINFO_DACL|SECINFO_SACL,
				sd_sacl);

        if (!NT_STATUS_IS_OK(status)) {
		printf("cli_set_security_descriptor SACL "
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
	status = cli_query_security_descriptor(
		cli, fnum, SECINFO_SACL, talloc_tos(), &sd_sacl);

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
	status = cli_query_security_descriptor(
		cli, fnum, SECINFO_DACL, talloc_tos(), &sd_sacl);

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

	printf("Starting SMB2-QUOTA1\n");

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

bool run_smb2_stream_acl(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	uint16_t fnum = (uint16_t)-1;
	const char *fname = "stream_acl_test_file";
	const char *sname = "stream_acl_test_file:streamname";
	struct security_descriptor *sd_dacl = NULL;
	bool ret = false;

	printf("SMB2 stream acl\n");

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

	/* Ensure file doesn't exist. */
	(void)cli_unlink(cli, fname, 0);

	/* Create the file. */
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

	/* Close the handle. */
	cli_smb2_close_fnum(cli, fnum);
	fnum = (uint16_t)-1;

	/* Create the stream. */
	status = cli_ntcreate(cli,
				sname,
				0,
				FILE_READ_DATA|
					SEC_STD_READ_CONTROL|
					SEC_STD_WRITE_DAC,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_NONE,
				FILE_CREATE,
				0,
				0,
				&fnum,
				NULL);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Create of %s failed (%s)\n",
			sname,
			nt_errstr(status));
		goto fail;
	}

	/* Close the handle. */
	cli_smb2_close_fnum(cli, fnum);
	fnum = (uint16_t)-1;

	/*
	 * Open the stream - for Samba this ensures
	 * we prove we have a pathref fsp.
	 */
	status = cli_ntcreate(cli,
				sname,
				0,
				FILE_READ_DATA|
					SEC_STD_READ_CONTROL|
					SEC_STD_WRITE_DAC,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_NONE,
				FILE_OPEN,
				0,
				0,
				&fnum,
				NULL);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Open of %s failed (%s)\n",
			sname,
			nt_errstr(status));
                goto fail;
	}

	/* Read the security descriptor off the stream handle. */
	status = cli_query_security_descriptor(cli,
				fnum,
				SECINFO_DACL,
				talloc_tos(),
				&sd_dacl);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Reading DACL on stream %s got (%s)\n",
			sname,
			nt_errstr(status));
		goto fail;
	}

	if (sd_dacl == NULL || sd_dacl->dacl == NULL ||
			sd_dacl->dacl->num_aces < 1) {
		printf("Invalid DACL returned on stream %s "
			"(this should not happen)\n",
			sname);
		goto fail;
	}

	/*
	 * Ensure it allows FILE_READ_DATA in the first ace.
	 * It always should.
	 */
	if ((sd_dacl->dacl->aces[0].access_mask & FILE_READ_DATA) == 0) {
		printf("DACL->ace[0] returned on stream %s "
			"doesn't have read access (should not happen)\n",
			sname);
		goto fail;
	}

	/* Remove FILE_READ_DATA from the first ace and set. */
	sd_dacl->dacl->aces[0].access_mask &= ~FILE_READ_DATA;

	status = cli_set_security_descriptor(cli,
				fnum,
				SECINFO_DACL,
				sd_dacl);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Setting DACL on stream %s got (%s)\n",
			sname,
			nt_errstr(status));
		goto fail;
	}

	TALLOC_FREE(sd_dacl);

	/* Read again and check it changed. */
	status = cli_query_security_descriptor(cli,
				fnum,
				SECINFO_DACL,
				talloc_tos(),
				&sd_dacl);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Reading DACL on stream %s got (%s)\n",
			sname,
			nt_errstr(status));
		goto fail;
	}

	if (sd_dacl == NULL || sd_dacl->dacl == NULL ||
			sd_dacl->dacl->num_aces < 1) {
		printf("Invalid DACL (1) returned on stream %s "
			"(this should not happen)\n",
			sname);
		goto fail;
	}

	/* FILE_READ_DATA should be gone from the first ace. */
	if ((sd_dacl->dacl->aces[0].access_mask & FILE_READ_DATA) != 0) {
		printf("DACL on stream %s did not change\n",
			sname);
		goto fail;
	}

	ret = true;

  fail:

	if (fnum != (uint16_t)-1) {
		cli_smb2_close_fnum(cli, fnum);
		fnum = (uint16_t)-1;
	}

	(void)cli_unlink(cli, fname, 0);
	return ret;
}

static NTSTATUS list_fn(struct file_info *finfo,
			const char *name,
			void *state)
{
	bool *matched = (bool *)state;
	if (finfo->attr & FILE_ATTRIBUTE_DIRECTORY) {
		*matched = true;
	}
	return NT_STATUS_OK;
}

/*
 * Must be run against a share with "smbd async dosmode = yes".
 * Checks we can return DOS attriutes other than "N".
 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=14758
 */

bool run_list_dir_async_test(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	const char *dname = "ASYNC_DIR";
	bool ret = false;
	bool matched = false;

	printf("SMB2 list dir async\n");

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

	/* Ensure directory doesn't exist. */
	(void)cli_rmdir(cli, dname);

	status = cli_mkdir(cli, dname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_mkdir %s returned %s\n", dname, nt_errstr(status));
		return false;
	}

	status = cli_list(cli,
			  dname,
			  FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_DIRECTORY,
			  list_fn,
			  &matched);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_list %s returned %s\n", dname, nt_errstr(status));
		goto fail;
	}

	if (!matched) {
		printf("Failed to find %s\n", dname);
		goto fail;
	}

	ret = true;

  fail:

	(void)cli_rmdir(cli, dname);
	return ret;
}

/*
 * Test delete a directory fails if a file is created
 * in a directory after the delete on close is set.
 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=14892
 */

bool run_delete_on_close_non_empty(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	const char *dname = "DEL_ON_CLOSE_DIR";
	const char *fname = "DEL_ON_CLOSE_DIR\\testfile";
	uint16_t fnum = (uint16_t)-1;
	uint16_t fnum1 = (uint16_t)-1;
	bool ret = false;

	printf("SMB2 delete on close nonempty\n");

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

	/* Ensure directory doesn't exist. */
	(void)cli_unlink(cli,
			 fname,
			 FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	(void)cli_rmdir(cli, dname);

	/* Create target directory. */
	status = cli_ntcreate(cli,
				dname,
				0,
				DELETE_ACCESS|FILE_READ_DATA,
				FILE_ATTRIBUTE_DIRECTORY,
				FILE_SHARE_READ|
					FILE_SHARE_WRITE|
					FILE_SHARE_DELETE,
				FILE_CREATE,
				FILE_DIRECTORY_FILE,
				0,
				&fnum,
				NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_ntcreate for directory %s returned %s\n",
				dname,
				nt_errstr(status));
		goto out;
	}

	/* Now set the delete on close bit. */
	status = cli_nt_delete_on_close(cli, fnum, 1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_cli_nt_delete_on_close set for directory "
			"%s returned %s\n",
			dname,
			nt_errstr(status));
		goto out;
	}

	/* Create file inside target directory. */
	/*
	 * NB. On Windows this will return NT_STATUS_DELETE_PENDING.  Only on
	 * Samba will this succeed by default (the option "check parent
	 * directory delete on close" configures behaviour), but we're using
	 * this to test a race condition.
	 */
	status = cli_ntcreate(cli,
				fname,
				0,
				FILE_READ_DATA,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ|
					FILE_SHARE_WRITE|
					FILE_SHARE_DELETE,
				FILE_CREATE,
				0,
				0,
				&fnum1,
				NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_ntcreate for file %s returned %s\n",
				fname,
				nt_errstr(status));
		goto out;
	}
	cli_close(cli, fnum1);
	fnum1 = (uint16_t)-1;

	/* Now the close should fail. */
	status = cli_close(cli, fnum);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_DIRECTORY_NOT_EMPTY)) {
		printf("cli_close for directory %s returned %s\n",
				dname,
				nt_errstr(status));
		goto out;
	}

	ret = true;

  out:

	if (fnum1 != (uint16_t)-1) {
		cli_close(cli, fnum1);
	}
	if (fnum != (uint16_t)-1) {
		cli_nt_delete_on_close(cli, fnum, 0);
		cli_close(cli, fnum);
	}
	(void)cli_unlink(cli,
			 fname,
			 FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	(void)cli_rmdir(cli, dname);
	return ret;
}

static NTSTATUS check_empty_fn(struct file_info *finfo,
				const char *mask,
				void *private_data)
{
	unsigned int *pcount = (unsigned int *)private_data;

	if (ISDOT(finfo->name) || ISDOTDOT(finfo->name)) {
		(*pcount)++;
		return NT_STATUS_OK;
	}
	return NT_STATUS_DIRECTORY_NOT_EMPTY;
}

/*
 * Test setting the delete on close bit on a directory
 * containing an unwritable file fails or succeeds
 * an a share set with "hide unwritable = yes"
 * depending on the setting of "delete veto files".
 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=15023
 *
 * First version. With "delete veto files = yes"
 * setting the delete on close should succeed.
 */

bool run_delete_on_close_nonwrite_delete_yes_test(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	const char *dname = "delete_veto_yes";
	const char *list_dname = "delete_veto_yes\\*";
	uint16_t fnum = (uint16_t)-1;
	bool ret = false;
	unsigned int list_count = 0;

	printf("SMB2 delete on close nonwrite - delete veto yes\n");

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

	/* Ensure target directory is seen as empty. */
	status = cli_list(cli,
			list_dname,
			FILE_ATTRIBUTE_DIRECTORY |
				FILE_ATTRIBUTE_HIDDEN |
				FILE_ATTRIBUTE_SYSTEM,
			check_empty_fn,
			&list_count);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_list of %s returned %s\n",
			dname,
			nt_errstr(status));
		return false;
	}
	if (list_count != 2) {
		printf("cli_list of %s returned a count of %u\n",
			dname,
			list_count);
		return false;
	}

	/* Open target directory. */
	status = cli_ntcreate(cli,
				dname,
				0,
				DELETE_ACCESS|FILE_READ_DATA,
				FILE_ATTRIBUTE_DIRECTORY,
				FILE_SHARE_READ|
					FILE_SHARE_WRITE|
					FILE_SHARE_DELETE,
				FILE_OPEN,
				FILE_DIRECTORY_FILE,
				0,
				&fnum,
				NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_ntcreate for directory %s returned %s\n",
				dname,
				nt_errstr(status));
		goto out;
	}

	/* Now set the delete on close bit. */
	status = cli_nt_delete_on_close(cli, fnum, 1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_cli_nt_delete_on_close set for directory "
			"%s returned %s (should have succeeded)\n",
			dname,
			nt_errstr(status));
		goto out;
	}

	ret = true;

  out:

	if (fnum != (uint16_t)-1) {
		(void)cli_nt_delete_on_close(cli, fnum, 0);
		(void)cli_close(cli, fnum);
	}
	return ret;
}

/*
 * Test setting the delete on close bit on a directory
 * containing an unwritable file fails or succeeds
 * an a share set with "hide unwritable = yes"
 * depending on the setting of "delete veto files".
 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=15023
 *
 * Second version. With "delete veto files = no"
 * setting the delete on close should fail.
 */

bool run_delete_on_close_nonwrite_delete_no_test(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	const char *dname = "delete_veto_no";
	const char *list_dname = "delete_veto_no\\*";
	uint16_t fnum = (uint16_t)-1;
	bool ret = false;
	unsigned int list_count = 0;

	printf("SMB2 delete on close nonwrite - delete veto yes\n");

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

	/* Ensure target directory is seen as empty. */
	status = cli_list(cli,
			list_dname,
			FILE_ATTRIBUTE_DIRECTORY |
				FILE_ATTRIBUTE_HIDDEN |
				FILE_ATTRIBUTE_SYSTEM,
			check_empty_fn,
			&list_count);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_list of %s returned %s\n",
			dname,
			nt_errstr(status));
		return false;
	}
	if (list_count != 2) {
		printf("cli_list of %s returned a count of %u\n",
			dname,
			list_count);
		return false;
	}

	/* Open target directory. */
	status = cli_ntcreate(cli,
				dname,
				0,
				DELETE_ACCESS|FILE_READ_DATA,
				FILE_ATTRIBUTE_DIRECTORY,
				FILE_SHARE_READ|
					FILE_SHARE_WRITE|
					FILE_SHARE_DELETE,
				FILE_OPEN,
				FILE_DIRECTORY_FILE,
				0,
				&fnum,
				NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_ntcreate for directory %s returned %s\n",
				dname,
				nt_errstr(status));
		goto out;
	}

	/* Now set the delete on close bit. */
	status = cli_nt_delete_on_close(cli, fnum, 1);
	if (NT_STATUS_IS_OK(status)) {
		printf("cli_cli_nt_delete_on_close set for directory "
			"%s returned NT_STATUS_OK "
			"(should have failed)\n",
			dname);
		goto out;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_DIRECTORY_NOT_EMPTY)) {
		printf("cli_cli_nt_delete_on_close set for directory "
			"%s returned %s "
			"(should have returned "
			"NT_STATUS_DIRECTORY_NOT_EMPTY)\n",
			dname,
			nt_errstr(status));
		goto out;
	}

	ret = true;

  out:

	if (fnum != (uint16_t)-1) {
		(void)cli_nt_delete_on_close(cli, fnum, 0);
		(void)cli_close(cli, fnum);
	}
	return ret;
}

/*
 * Open an SMB2 file readonly and return the inode number.
 */
static NTSTATUS get_smb2_inode(struct cli_state *cli,
				const char *pathname,
				uint64_t *ino_ret)
{
	NTSTATUS status;
	uint64_t fid_persistent = 0;
	uint64_t fid_volatile = 0;
	DATA_BLOB outbuf = data_blob_null;
	/*
	 * Open the file.
	 */
	status = smb2cli_create(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				pathname,
				SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
				SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
				SEC_STD_SYNCHRONIZE|
					SEC_FILE_READ_DATA|
					SEC_FILE_READ_ATTRIBUTE, /* desired_access, */
				FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
				FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
				FILE_OPEN, /* create_disposition, */
				0, /* create_options, */
				NULL, /* smb2_create_blobs *blobs */
				&fid_persistent,
				&fid_volatile,
				NULL, /* struct smb_create_returns * */
				talloc_tos(), /* mem_ctx. */
				NULL, /* struct smb2_create_blobs * */
				NULL); /* struct symlink_reparse_struct */
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Get the inode.
	 */
	status = smb2cli_query_info(cli->conn,
				    cli->timeout,
				    cli->smb2.session,
				    cli->smb2.tcon,
				    SMB2_0_INFO_FILE,
				    (SMB_FILE_ALL_INFORMATION - 1000), /* in_file_info_class */
				    1024, /* in_max_output_length */
				    NULL, /* in_input_buffer */
				    0, /* in_additional_info */
				    0, /* in_flags */
				    fid_persistent,
				    fid_volatile,
				    talloc_tos(),
				    &outbuf);

	if (NT_STATUS_IS_OK(status)) {
		*ino_ret = PULL_LE_U64(outbuf.data, 0x40);
	}

	(void)smb2cli_close(cli->conn,
			    cli->timeout,
			    cli->smb2.session,
			    cli->smb2.tcon,
			    0,
			    fid_persistent,
			    fid_volatile);
	return status;
}

/*
 * Check an inode matches a given SMB2 path.
 */
static bool smb2_inode_matches(struct cli_state *cli,
				const char *match_pathname,
				uint64_t ino_tomatch,
				const char *test_pathname)
{
	uint64_t test_ino = 0;
	NTSTATUS status;

	status = get_smb2_inode(cli,
				test_pathname,
				&test_ino);
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s: Failed to get ino "
			"number for %s, (%s)\n",
			__func__,
			test_pathname,
			nt_errstr(status));
		return false;
	}
	if (test_ino != ino_tomatch) {
		printf("%s: Inode missmatch, ino_tomatch (%s) "
			"ino=%"PRIu64" test (%s) "
			"ino=%"PRIu64"\n",
			__func__,
			match_pathname,
			ino_tomatch,
			test_pathname,
			test_ino);
		return false;
	}
	return true;
}

/*
 * Delete an SMB2 file on a DFS share.
 */
static NTSTATUS smb2_dfs_delete(struct cli_state *cli,
				const char *pathname)
{
	NTSTATUS status;
	uint64_t fid_persistent = 0;
	uint64_t fid_volatile = 0;
	uint8_t data[1];
	DATA_BLOB inbuf;

	/*
	 * Open the file.
	 */
	status = smb2cli_create(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				pathname,
				SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
				SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
				SEC_STD_SYNCHRONIZE|
					SEC_STD_DELETE, /* desired_access, */
				FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
				FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
				FILE_OPEN, /* create_disposition, */
				0, /* create_options, */
				NULL, /* smb2_create_blobs *blobs */
				&fid_persistent,
				&fid_volatile,
				NULL, /* struct smb_create_returns * */
				talloc_tos(), /* mem_ctx. */
				NULL, /* struct smb2_create_blobs * */
				NULL); /* struct symlink_reparse_struct */
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Set delete on close.
	 */
	PUSH_LE_U8(&data[0], 0, 1);
	inbuf.data = &data[0];
	inbuf.length = 1;

	status = smb2cli_set_info(cli->conn,
				  cli->timeout,
				  cli->smb2.session,
				  cli->smb2.tcon,
				  SMB2_0_INFO_FILE, /* info_type. */
				  SMB_FILE_DISPOSITION_INFORMATION - 1000, /* info_class */
				  &inbuf,
				  0, /* additional_info. */
				  fid_persistent,
				  fid_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = smb2cli_close(cli->conn,
			       cli->timeout,
			       cli->smb2.session,
			       cli->smb2.tcon,
			       0,
			       fid_persistent,
			       fid_volatile);
	return status;
}

/*
 * Rename or hardlink an SMB2 file on a DFS share.
 */
static NTSTATUS smb2_dfs_setinfo_name(struct cli_state *cli,
				      uint64_t fid_persistent,
				      uint64_t fid_volatile,
				      const char *newname,
				      bool do_rename)
{
	NTSTATUS status;
	DATA_BLOB inbuf;
	smb_ucs2_t *converted_str = NULL;
	size_t converted_size_bytes = 0;
	size_t inbuf_size;
	uint8_t info_class = 0;
	bool ok;

	ok = push_ucs2_talloc(talloc_tos(),
			      &converted_str,
			      newname,
			      &converted_size_bytes);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	/*
	 * W2K8 insists the dest name is not null terminated. Remove
	 * the last 2 zero bytes and reduce the name length.
	 */
	if (converted_size_bytes < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	converted_size_bytes -= 2;
	inbuf_size = 20 + converted_size_bytes;
	if (inbuf_size < 20) {
		/* Integer wrap check. */
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * The Windows 10 SMB2 server has a minimum length
	 * for a SMB2_FILE_RENAME_INFORMATION buffer of
	 * 24 bytes. It returns NT_STATUS_INFO_LENGTH_MISMATCH
	 * if the length is less.
	 */
	inbuf_size = MAX(inbuf_size, 24);
	inbuf = data_blob_talloc_zero(talloc_tos(), inbuf_size);
	if (inbuf.data == NULL) {
		return NT_STATUS_NO_MEMORY;
        }
	PUSH_LE_U32(inbuf.data, 16, converted_size_bytes);
	memcpy(inbuf.data + 20, converted_str, converted_size_bytes);
	TALLOC_FREE(converted_str);

	if (do_rename == true) {
		info_class = SMB_FILE_RENAME_INFORMATION - 1000;
	} else {
		/* Hardlink. */
		info_class = SMB_FILE_LINK_INFORMATION - 1000;
	}

	status = smb2cli_set_info(cli->conn,
				  cli->timeout,
				  cli->smb2.session,
				  cli->smb2.tcon,
				  SMB2_0_INFO_FILE, /* info_type. */
				  info_class, /* info_class */
				  &inbuf,
				  0, /* additional_info. */
				  fid_persistent,
				  fid_volatile);
	return status;
}

static NTSTATUS smb2_dfs_rename(struct cli_state *cli,
				      uint64_t fid_persistent,
				      uint64_t fid_volatile,
				      const char *newname)
{
	return smb2_dfs_setinfo_name(cli,
				     fid_persistent,
				     fid_volatile,
				     newname,
				     true); /* do_rename */
}

static NTSTATUS smb2_dfs_hlink(struct cli_state *cli,
			       uint64_t fid_persistent,
			       uint64_t fid_volatile,
			       const char *newname)
{
	return smb2_dfs_setinfo_name(cli,
				     fid_persistent,
				     fid_volatile,
				     newname,
				     false); /* do_rename */
}

/*
 * According to:

 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/dc9978d7-6299-4c5a-a22d-a039cdc716ea
 *
 *  (Characters " \ / [ ] : | < > + = ; , * ?,
 *  and control characters in range 0x00 through
 *  0x1F, inclusive, are illegal in a share name)
 *
 * But Windows server only checks in DFS sharenames ':'. All other
 * share names are allowed.
 */

static bool test_smb2_dfs_sharenames(struct cli_state *cli,
				     const char *dfs_root_share_name,
				     uint64_t root_ino)
{
	char test_path[9];
	const char *test_str = "/[]:|<>+=;,*?";
	const char *p;
	unsigned int i;
	bool ino_matched = false;

	/* Setup template pathname. */
	memcpy(test_path, "SERVER\\X", 9);

	/* Test invalid control characters. */
	for (i = 1; i < 0x20; i++) {
		test_path[7] = i;
		ino_matched = smb2_inode_matches(cli,
					 dfs_root_share_name,
					 root_ino,
					 test_path);
		if (!ino_matched) {
			return false;
		}
	}

	/* Test explicit invalid characters. */
	for (p = test_str; *p != '\0'; p++) {
		test_path[7] = *p;
		if (*p == ':') {
			/*
			 * Only ':' is treated as an INVALID sharename
			 * for a DFS SERVER\\SHARE path.
			 */
			uint64_t test_ino = 0;
			NTSTATUS status = get_smb2_inode(cli,
							 test_path,
							 &test_ino);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_INVALID)) {
				printf("%s:%d Open of %s should get "
					"NT_STATUS_OBJECT_NAME_INVALID, got %s\n",
					__FILE__,
					__LINE__,
					test_path,
					nt_errstr(status));
				return false;
			}
		} else {
			ino_matched = smb2_inode_matches(cli,
						 dfs_root_share_name,
						 root_ino,
						 test_path);
			if (!ino_matched) {
				return false;
			}
		}
	}
	return true;
}

/*
 * "Raw" test of SMB2 paths to a DFS share.
 * We must use the lower level smb2cli_XXXX() interfaces,
 * not the cli_XXX() ones here as the ultimate goal is to fix our
 * cli_XXX() interfaces to work transparently over DFS.
 *
 * So here, we're testing the server code, not the client code.
 *
 * Passes cleanly against Windows.
 */

bool run_smb2_dfs_paths(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	bool dfs_supported = false;
	char *dfs_root_share_name = NULL;
	uint64_t root_ino = 0;
	uint64_t test_ino = 0;
	bool ino_matched = false;
	uint64_t fid_persistent = 0;
	uint64_t fid_volatile = 0;
	bool retval = false;
	bool ok = false;

	printf("Starting SMB2-DFS-PATHS\n");

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

	/* Ensure this is a DFS share. */
	dfs_supported = smbXcli_conn_dfs_supported(cli->conn);
	if (!dfs_supported) {
		printf("Server %s does not support DFS\n",
			smbXcli_conn_remote_name(cli->conn));
		return false;
	}
	dfs_supported = smbXcli_tcon_is_dfs_share(cli->smb2.tcon);
	if (!dfs_supported) {
		printf("Share %s does not support DFS\n",
			cli->share);
		return false;
	}
	/*
	 * Create the "official" DFS share root name.
	 * No SMB2 paths can start with '\\'.
	 */
	dfs_root_share_name = talloc_asprintf(talloc_tos(),
					"%s\\%s",
					smbXcli_conn_remote_name(cli->conn),
					cli->share);
	if (dfs_root_share_name == NULL) {
		printf("Out of memory\n");
		return false;
	}

	/* Get the share root inode number. */
	status = get_smb2_inode(cli,
				dfs_root_share_name,
				&root_ino);
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d Failed to get ino number for share root %s, (%s)\n",
			__FILE__,
			__LINE__,
			dfs_root_share_name,
			nt_errstr(status));
		return false;
	}

	/*
	 * Test the Windows algorithm for parsing DFS names.
	 */
	/*
	 * A single "SERVER" element should open and match the share root.
	 */
	ino_matched = smb2_inode_matches(cli,
					 dfs_root_share_name,
					 root_ino,
					 smbXcli_conn_remote_name(cli->conn));
	if (!ino_matched) {
		printf("%s:%d Failed to match ino number for %s\n",
			__FILE__,
			__LINE__,
			smbXcli_conn_remote_name(cli->conn));
		return false;
	}

	/*
	 * An "" DFS empty server name should open and match the share root on
	 * Windows 2008. Windows 2022 returns NT_STATUS_INVALID_PARAMETER
	 * for a DFS empty server name.
	 */
	status = get_smb2_inode(cli,
				"",
				&test_ino);
	if (NT_STATUS_IS_OK(status)) {
		/*
		 * Windows 2008 - open succeeded. Proceed to
		 * check ino number.
		 */
		ino_matched = smb2_inode_matches(cli,
						 dfs_root_share_name,
						 root_ino,
						 "");
		if (!ino_matched) {
			printf("%s:%d Failed to match ino number for %s\n",
				__FILE__,
				__LINE__,
				"");
			return false;
		}
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		/*
		 * For Windows 2022 we expect to fail with
		 * NT_STATUS_INVALID_PARAMETER. Anything else is
		 * unexpected.
		 */
		printf("%s:%d Unexpected error (%s) getting ino number for %s\n",
			__FILE__,
			__LINE__,
			nt_errstr(status),
			"");
		return false;
	}
	/* A "BAD" server name should open and match the share root. */
	ino_matched = smb2_inode_matches(cli,
					 dfs_root_share_name,
					 root_ino,
					 "BAD");
	if (!ino_matched) {
		printf("%s:%d Failed to match ino number for %s\n",
			__FILE__,
			__LINE__,
			"BAD");
		return false;
	}
	/*
	 * A "BAD\\BAD" server and share name should open
	 * and match the share root.
	 */
	ino_matched = smb2_inode_matches(cli,
					 dfs_root_share_name,
					 root_ino,
					 "BAD\\BAD");
	if (!ino_matched) {
		printf("%s:%d Failed to match ino number for %s\n",
			__FILE__,
			__LINE__,
			"BAD\\BAD");
		return false;
	}
	/*
	 * Trying to open "BAD\\BAD\\BAD" should get
	 * NT_STATUS_OBJECT_NAME_NOT_FOUND.
	 */
	status = get_smb2_inode(cli,
				"BAD\\BAD\\BAD",
				&test_ino);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		printf("%s:%d Open of %s should get "
			"STATUS_OBJECT_NAME_NOT_FOUND, got %s\n",
			__FILE__,
			__LINE__,
			"BAD\\BAD\\BAD",
			nt_errstr(status));
		return false;
	}
	/*
	 * Trying to open "BAD\\BAD\\BAD\\BAD" should get
	 * NT_STATUS_OBJECT_PATH_NOT_FOUND.
	 */
	status = get_smb2_inode(cli,
				"BAD\\BAD\\BAD\\BAD",
				&test_ino);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_PATH_NOT_FOUND)) {
		printf("%s:%d Open of %s should get "
			"STATUS_OBJECT_NAME_NOT_FOUND, got %s\n",
			__FILE__,
			__LINE__,
			"BAD\\BAD\\BAD\\BAD",
			nt_errstr(status));
		return false;
	}
	/*
	 * Test for invalid pathname characters in the servername.
	 * They are ignored, and it still opens the share root.
	 */
	ino_matched = smb2_inode_matches(cli,
					 dfs_root_share_name,
					 root_ino,
					 "::::");
	if (!ino_matched) {
		printf("%s:%d Failed to match ino number for %s\n",
			__FILE__,
			__LINE__,
			"::::");
		return false;
	}

	/*
	 * Test for invalid pathname characters in the sharename.
	 * Invalid sharename characters should still be flagged as
	 * NT_STATUS_OBJECT_NAME_INVALID. It turns out only ':'
	 * is considered an invalid sharename character.
	 */
	ok = test_smb2_dfs_sharenames(cli,
				      dfs_root_share_name,
				      root_ino);
	if (!ok) {
		return false;
	}

	/* Now create a file called "file". */
	status = smb2cli_create(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				"BAD\\BAD\\file",
				SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
				SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
				SEC_STD_SYNCHRONIZE|
					SEC_STD_DELETE |
					SEC_FILE_READ_DATA|
					SEC_FILE_READ_ATTRIBUTE, /* desired_access, */
				FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
				FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
				FILE_CREATE, /* create_disposition, */
				0, /* create_options, */
				NULL, /* smb2_create_blobs *blobs */
				&fid_persistent,
				&fid_volatile,
				NULL, /* struct smb_create_returns * */
				talloc_tos(), /* mem_ctx. */
				NULL, /* struct smb2_create_blobs * */
				NULL); /* struct symlink_reparse_struct */
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d smb2cli_create on %s returned %s\n",
			__FILE__,
			__LINE__,
			"BAD\\BAD\\file",
			nt_errstr(status));
		return false;
	}

	/*
	 * Trying to open "BAD\\BAD\\file" should now get
	 * a valid inode.
	 */
	status = get_smb2_inode(cli,
				"BAD\\BAD\\file",
				&test_ino);
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d Open of %s should succeed "
			"got %s\n",
			__FILE__,
			__LINE__,
			"BAD\\BAD\\file",
			nt_errstr(status));
		goto err;
	}

	/*
	 * Now show that renames use relative,
	 * not full DFS paths.
	 */

	/* Full DFS path should fail. */
	status = smb2_dfs_rename(cli,
				 fid_persistent,
				 fid_volatile,
				 "ANY\\NAME\\renamed_file");
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_PATH_NOT_FOUND)) {
		printf("%s:%d Rename of %s -> %s should fail "
			"with NT_STATUS_OBJECT_PATH_NOT_FOUND. Got %s\n",
			__FILE__,
			__LINE__,
			"BAD\\BAD\\file",
			"ANY\\NAME\\renamed_file",
			nt_errstr(status));
		goto err;
	}
	/* Relative DFS path should succeed. */
	status = smb2_dfs_rename(cli,
				 fid_persistent,
				 fid_volatile,
				 "renamed_file");
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d: Rename of %s -> %s should succeed. "
			"Got %s\n",
			__FILE__,
			__LINE__,
			"BAD\\BAD\\file",
			"renamed_file",
			nt_errstr(status));
		goto err;
	}

	/*
	 * Trying to open "BAD\\BAD\\renamed_file" should now get
	 * a valid inode.
	 */
	status = get_smb2_inode(cli,
				"BAD\\BAD\\renamed_file",
				&test_ino);
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d: Open of %s should succeed "
			"got %s\n",
			__FILE__,
			__LINE__,
			"BAD\\BAD\\renamed_file",
			nt_errstr(status));
		goto err;
	}

	/*
	 * Now show that hard links use relative,
	 * not full DFS paths.
	 */

	/* Full DFS path should fail. */
	status = smb2_dfs_hlink(cli,
				 fid_persistent,
				 fid_volatile,
				 "ANY\\NAME\\hlink");
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_PATH_NOT_FOUND)) {
		printf("%s:%d Hlink of %s -> %s should fail "
			"with NT_STATUS_OBJECT_PATH_NOT_FOUND. Got %s\n",
			__FILE__,
			__LINE__,
			"ANY\\NAME\\renamed_file",
			"ANY\\NAME\\hlink",
			nt_errstr(status));
		goto err;
	}
	/* Relative DFS path should succeed. */
	status = smb2_dfs_hlink(cli,
				 fid_persistent,
				 fid_volatile,
				 "hlink");
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d: Hlink of %s -> %s should succeed. "
			"Got %s\n",
			__FILE__,
			__LINE__,
			"ANY\\NAME\\renamed_file",
			"hlink",
			nt_errstr(status));
		goto err;
	}

	/*
	 * Trying to open "BAD\\BAD\\hlink" should now get
	 * a valid inode.
	 */
	status = get_smb2_inode(cli,
				"BAD\\BAD\\hlink",
				&test_ino);
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d Open of %s should succeed "
			"got %s\n",
			__FILE__,
			__LINE__,
			"BAD\\BAD\\hlink",
			nt_errstr(status));
		goto err;
	}

	retval = true;

  err:

	if (fid_persistent != 0 || fid_volatile != 0) {
		smb2cli_close(cli->conn,
			      cli->timeout,
			      cli->smb2.session,
			      cli->smb2.tcon,
			      0, /* flags */
			      fid_persistent,
			      fid_volatile);
	}
	/* Delete anything we made. */
	(void)smb2_dfs_delete(cli, "BAD\\BAD\\BAD");
	(void)smb2_dfs_delete(cli, "BAD\\BAD\\file");
	(void)smb2_dfs_delete(cli, "BAD\\BAD\\renamed_file");
	(void)smb2_dfs_delete(cli, "BAD\\BAD\\hlink");
	return retval;
}

/*
 * Add a test that sends DFS paths and sets the
 * SMB2 flag FLAGS2_DFS_PATHNAMES, but to a non-DFS
 * share. Windows passes this (it just treats the
 * pathnames as non-DFS and ignores the FLAGS2_DFS_PATHNAMES
 * bit).
 */

bool run_smb2_non_dfs_share(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	bool dfs_supported = false;
	uint64_t fid_persistent = 0;
	uint64_t fid_volatile = 0;
	bool retval = false;
	char *dfs_filename = NULL;

	printf("Starting SMB2-DFS-NON-DFS-SHARE\n");

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

	dfs_supported = smbXcli_conn_dfs_supported(cli->conn);
	if (!dfs_supported) {
		printf("Server %s does not support DFS\n",
			smbXcli_conn_remote_name(cli->conn));
		return false;
	}
	/* Ensure this is *NOT* a DFS share. */
	dfs_supported = smbXcli_tcon_is_dfs_share(cli->smb2.tcon);
	if (dfs_supported) {
		printf("Share %s is a DFS share.\n",
			cli->share);
		return false;
	}
	/*
	 * Force the share to be DFS, as far as the client
	 * is concerned.
	 */
	smb2cli_tcon_set_values(cli->smb2.tcon,
				cli->smb2.session,
				smb2cli_tcon_current_id(cli->smb2.tcon),
				0,
				smb2cli_tcon_flags(cli->smb2.tcon),
				smb2cli_tcon_capabilities(cli->smb2.tcon) |
					SMB2_SHARE_CAP_DFS,
				0);

	/* Come up with a "valid" SMB2 DFS name. */
	dfs_filename = talloc_asprintf(talloc_tos(),
				       "%s\\%s\\file",
				       smbXcli_conn_remote_name(cli->conn),
				       cli->share);
	if (dfs_filename == NULL) {
		printf("Out of memory\n");
		return false;
	}

	/* Now try create dfs_filename. */
	status = smb2cli_create(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				dfs_filename,
				SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
				SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
				SEC_STD_SYNCHRONIZE|
					SEC_STD_DELETE |
					SEC_FILE_READ_DATA|
					SEC_FILE_READ_ATTRIBUTE, /* desired_access, */
				FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
				FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
				FILE_CREATE, /* create_disposition, */
				0, /* create_options, */
				NULL, /* smb2_create_blobs *blobs */
				&fid_persistent,
				&fid_volatile,
				NULL, /* struct smb_create_returns * */
				talloc_tos(), /* mem_ctx. */
				NULL, /* struct smb2_create_blobs */
				NULL); /* struct symlink_reparse_struct */
	/*
	 * Should fail with NT_STATUS_OBJECT_PATH_NOT_FOUND, as
	 * even though we set the FLAGS2_DFS_PATHNAMES the server
	 * knows this isn't a DFS share and so treats BAD\\BAD as
	 * part of the filename.
	 */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_PATH_NOT_FOUND)) {
		printf("%s:%d create of %s should fail "
			"with NT_STATUS_OBJECT_PATH_NOT_FOUND. Got %s\n",
			__FILE__,
			__LINE__,
			dfs_filename,
			nt_errstr(status));
		goto err;
	}
	/*
	 * Prove we can still use non-DFS pathnames, even though
	 * we are setting the FLAGS2_DFS_PATHNAMES in the SMB2
	 * request.
	 */
	status = smb2cli_create(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				"file",
				SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
				SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
				SEC_STD_SYNCHRONIZE|
					SEC_STD_DELETE |
					SEC_FILE_READ_DATA|
					SEC_FILE_READ_ATTRIBUTE, /* desired_access, */
				FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
				FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
				FILE_CREATE, /* create_disposition, */
				0, /* create_options, */
				NULL, /* smb2_create_blobs *blobs */
				&fid_persistent,
				&fid_volatile,
				NULL, /* struct smb_create_returns * */
				talloc_tos(), /* mem_ctx. */
				NULL, /* struct smb2_create_blobs * */
				NULL); /* struct symlink_reparse_struct */
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d smb2cli_create on %s returned %s\n",
			__FILE__,
			__LINE__,
			"file",
			nt_errstr(status));
		return false;
	}

	retval = true;

  err:

	(void)smb2_dfs_delete(cli, dfs_filename);
	(void)smb2_dfs_delete(cli, "file");
	return retval;
}

/*
 * Add a test that sends a non-DFS path and does not set the
 * SMB2 flag FLAGS2_DFS_PATHNAMES to a DFS
 * share. Windows passes this (it just treats the
 * pathnames as non-DFS).
 */

bool run_smb2_dfs_share_non_dfs_path(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	bool dfs_supported = false;
	uint64_t fid_persistent = 0;
	uint64_t fid_volatile = 0;
	bool retval = false;
	char *dfs_filename = NULL;
	uint64_t root_ino = (uint64_t)-1;
	bool ino_matched = false;

	printf("Starting SMB2-DFS-SHARE-NON-DFS-PATH\n");

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

	dfs_supported = smbXcli_conn_dfs_supported(cli->conn);
	if (!dfs_supported) {
		printf("Server %s does not support DFS\n",
			smbXcli_conn_remote_name(cli->conn));
		return false;
	}
	/* Ensure this is a DFS share. */
	dfs_supported = smbXcli_tcon_is_dfs_share(cli->smb2.tcon);
	if (!dfs_supported) {
		printf("Share %s is not a DFS share.\n",
			cli->share);
		return false;
	}
	/* Come up with a "valid" SMB2 DFS name. */
	dfs_filename = talloc_asprintf(talloc_tos(),
				       "%s\\%s\\file",
				       smbXcli_conn_remote_name(cli->conn),
				       cli->share);
	if (dfs_filename == NULL) {
		printf("Out of memory\n");
		return false;
	}

	/* Get the root of the share ino. */
	status = get_smb2_inode(cli,
				"SERVER\\SHARE",
				&root_ino);
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d get_smb2_inode on %s returned %s\n",
			__FILE__,
			__LINE__,
			"SERVER\\SHARE",
			nt_errstr(status));
		goto err;
	}

	/* Create a dfs_filename. */
	status = smb2cli_create(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				dfs_filename,
				SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
				SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
				SEC_STD_SYNCHRONIZE|
					SEC_STD_DELETE |
					SEC_FILE_READ_DATA|
					SEC_FILE_READ_ATTRIBUTE, /* desired_access, */
				FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
				FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
				FILE_CREATE, /* create_disposition, */
				0, /* create_options, */
				NULL, /* smb2_create_blobs *blobs */
				&fid_persistent,
				&fid_volatile,
				NULL, /* struct smb_create_returns * */
				talloc_tos(), /* mem_ctx. */
				NULL, /* struct smb2_create_blobs * */
				NULL); /* psymlink */
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d smb2cli_create on %s returned %s\n",
			__FILE__,
			__LINE__,
			dfs_filename,
			nt_errstr(status));
		goto err;
	}

	/* Close the handle we just opened. */
	smb2cli_close(cli->conn,
		      cli->timeout,
		      cli->smb2.session,
		      cli->smb2.tcon,
		      0, /* flags */
		      fid_persistent,
		      fid_volatile);

	fid_persistent = 0;
	fid_volatile = 0;

	/*
	 * Force the share to be non-DFS, as far as the client
	 * is concerned.
	 */
	smb2cli_tcon_set_values(cli->smb2.tcon,
			cli->smb2.session,
			smb2cli_tcon_current_id(cli->smb2.tcon),
			0,
			smb2cli_tcon_flags(cli->smb2.tcon),
			smb2cli_tcon_capabilities(cli->smb2.tcon) &
				~SMB2_SHARE_CAP_DFS,
			0);

	/*
	 * Prove we can still use non-DFS pathnames on a DFS
	 * share so long as we don't set the FLAGS2_DFS_PATHNAMES
	 * in the SMB2 request.
	 */
	status = smb2cli_create(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				"file",
				SMB2_OPLOCK_LEVEL_NONE, /* oplock_level, */
				SMB2_IMPERSONATION_IMPERSONATION, /* impersonation_level, */
				SEC_STD_SYNCHRONIZE|
					SEC_STD_DELETE |
					SEC_FILE_READ_DATA|
					SEC_FILE_READ_ATTRIBUTE, /* desired_access, */
				FILE_ATTRIBUTE_NORMAL, /* file_attributes, */
				FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access, */
				FILE_OPEN, /* create_disposition, */
				0, /* create_options, */
				NULL, /* smb2_create_blobs *blobs */
				&fid_persistent,
				&fid_volatile,
				NULL, /* struct smb_create_returns * */
				talloc_tos(), /* mem_ctx. */
				NULL, /* struct smb2_create_blobs * */
				NULL); /* psymlink */
	if (!NT_STATUS_IS_OK(status)) {
		printf("%s:%d smb2cli_create on %s returned %s\n",
			__FILE__,
			__LINE__,
			"file",
			nt_errstr(status));
		goto err;
	}

	/*
	 * Show that now we're using non-DFS pathnames
	 * on a DFS share, "" opens the root of the share.
	 */
	ino_matched = smb2_inode_matches(cli,
					 "SERVER\\SHARE",
					 root_ino,
					 "");
	if (!ino_matched) {
		printf("%s:%d Failed to match ino number for %s\n",
			__FILE__,
			__LINE__,
			"");
		goto err;
	}

	retval = true;

  err:

	if (fid_volatile != 0) {
		smb2cli_close(cli->conn,
			      cli->timeout,
			      cli->smb2.session,
			      cli->smb2.tcon,
			      0, /* flags */
			      fid_persistent,
			      fid_volatile);
	}
	(void)smb2_dfs_delete(cli, "file");
	(void)smb2_dfs_delete(cli, dfs_filename);
	return retval;
}
