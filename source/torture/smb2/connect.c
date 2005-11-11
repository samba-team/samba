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
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"

#define BASEDIR "\\testsmb2"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

/* 
   basic testing of SMB2 connection calls
*/
BOOL torture_smb2_connect(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smbcli_socket *socket;
	struct smb2_transport *transport;
	const char *host = lp_parm_string(-1, "torture", "host");
	BOOL ret = True;
	NTSTATUS status;

	socket = smbcli_sock_connect_byname(host, 445, mem_ctx, NULL);
	if (socket == NULL) {
		printf("Failed to connect to %s\n", host);
		return False;
	}

	transport = smb2_transport_init(socket, mem_ctx);
	if (socket == NULL) {
		printf("Failed to setup smb2 transport\n");
		return False;
	}

	/* send a negprot */
	status = smb2_negprot(transport);
	if (!NT_STATUS_IS_OK(status)) {
		printf("negprot failed - %s\n", nt_errstr(status));
		return False;
	}

	talloc_free(mem_ctx);

	return ret;
}
