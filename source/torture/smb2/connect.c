/* 
   Unix SMB/CIFS implementation.

   test suite for SMB2 connection operations

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"
#include "auth/gensec/gensec.h"

#define BASEDIR "\\testsmb2"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


/*
  send a negotiate
 */
static struct smb2_transport *torture_smb2_negprot(TALLOC_CTX *mem_ctx, const char *host)
{
	struct smbcli_socket *socket;
	struct smb2_transport *transport;
	NTSTATUS status;
	struct smb2_negprot io;

	socket = smbcli_sock_connect_byname(host, 445, mem_ctx, NULL);
	if (socket == NULL) {
		printf("Failed to connect to %s\n", host);
		return False;
	}

	transport = smb2_transport_init(socket, mem_ctx);
	if (transport == NULL) {
		printf("Failed to setup smb2 transport\n");
		return False;
	}

	ZERO_STRUCT(io);
	io.in.unknown1 = 0x010024;

	/* send a negprot */
	status = smb2_negprot(transport, mem_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("negprot failed - %s\n", nt_errstr(status));
		return NULL;
	}

	printf("Negprot reply:\n");
	printf("current_time  = %s\n", nt_time_string(mem_ctx, io.out.current_time));
	printf("boot_time     = %s\n", nt_time_string(mem_ctx, io.out.boot_time));

	return transport;
}

/*
  send a session setup
*/
static struct smb2_session *torture_smb2_session(struct smb2_transport *transport, 
						 struct cli_credentials *credentials)
{
	struct smb2_session *session;
	struct smb2_session_setup io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(transport);

	ZERO_STRUCT(io);
	io.in.unknown1 = 0x11;
	io.in.unknown2 = 0xF;
	io.in.unknown3 = 0x00;
	io.in.unknown4 = 0x50;

	session = smb2_session_init(transport, transport, True);

	status = gensec_set_credentials(session->gensec, credentials);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client credentails: %s\n", 
			  nt_errstr(status)));
		return NULL;
	}

	status = gensec_set_target_hostname(session->gensec, transport->socket->hostname);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target hostname: %s\n", 
			  nt_errstr(status)));
		return NULL;
	}

	status = gensec_set_target_service(session->gensec, "cifs");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target service: %s\n", 
			  nt_errstr(status)));
		return NULL;
	}

	status = gensec_start_mech_by_oid(session->gensec, GENSEC_OID_SPNEGO);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client - %s\n",
			  nt_errstr(status)));
		return NULL;
	}

	status = gensec_update(session->gensec, tmp_ctx,
			       session->transport->negotiate.secblob,
			       &io.in.secblob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) && 
	    !NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed initial gensec_update : %s\n", nt_errstr(status)));
		return NULL;
	}

	status = smb2_session_setup(session, tmp_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("session setup failed - %s\n", nt_errstr(status));
		return NULL;
	}

	return session;
}

/* 
   basic testing of SMB2 connection calls
*/
BOOL torture_smb2_connect(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_transport *transport;
	struct smb2_session *session;
	const char *host = lp_parm_string(-1, "torture", "host");
	struct cli_credentials *credentials = cmdline_credentials;

	transport = torture_smb2_negprot(mem_ctx, host);
	session = torture_smb2_session(transport, credentials);

	talloc_free(mem_ctx);

	return True;
}
