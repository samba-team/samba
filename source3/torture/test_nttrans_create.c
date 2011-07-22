/*
   Unix SMB/CIFS implementation.
   Basic test for share secdescs vs nttrans_create
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
#include "libsmb/libsmb.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/secdesc.h"
#include "libcli/security/security.h"

bool run_nttrans_create(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status, status2;
	bool ret = false;
	struct security_ace ace;
	struct security_acl acl;
	struct security_descriptor *sd;
	const char *fname = "transtest";
	uint16_t fnum, fnum2;
	struct dom_sid owner;

	printf("Starting NTTRANS_CREATE\n");

	if (!torture_open_connection(&cli, 0)) {
		printf("torture_open_connection failed\n");
		goto fail;
	}

	ZERO_STRUCT(ace);
	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.access_mask = SEC_RIGHTS_FILE_ALL & ~SEC_STD_WRITE_DAC;
	sid_copy(&ace.trustee, &global_sid_World);

	acl.revision = SECURITY_ACL_REVISION_NT4;
	acl.size = 0;
	acl.num_aces = 1;
	acl.aces = &ace;

	dom_sid_parse("S-1-22-1-1000", &owner);

	sd = make_sec_desc(talloc_tos(),
			   SECURITY_DESCRIPTOR_REVISION_1,
			   SEC_DESC_SELF_RELATIVE|
			   SEC_DESC_DACL_PRESENT|SEC_DESC_OWNER_DEFAULTED|
			   SEC_DESC_GROUP_DEFAULTED,
			   NULL, NULL, NULL, &acl, NULL);
	if (sd == NULL) {
		d_fprintf(stderr, "make_sec_desc failed\n");
		goto fail;
	}

	status = cli_nttrans_create(
		cli, fname, 0, FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS|
		READ_CONTROL_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE| FILE_SHARE_DELETE,
		FILE_CREATE, 0, 0, sd, NULL, 0, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_nttrans_create returned %s\n",
			  nt_errstr(status));
		goto fail;
	}

	cli_query_secdesc(cli, fnum, talloc_tos(), NULL);

	status2 = cli_ntcreate(cli, fname, 0, WRITE_DAC_ACCESS,
			       FILE_ATTRIBUTE_NORMAL,
			       FILE_SHARE_READ|FILE_SHARE_WRITE|
			       FILE_SHARE_DELETE,
			       FILE_OPEN, 0, 0, &fnum2);

	status = cli_nt_delete_on_close(cli, fnum, true);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_nt_delete_on_close returned %s\n",
			  nt_errstr(status));
		goto fail;
	}

	if (!NT_STATUS_EQUAL(status2, NT_STATUS_ACCESS_DENIED)) {
		d_fprintf(stderr, "cli_ntcreate returned %s\n",
			  nt_errstr(status));
		goto fail;
	}

	ret = true;
fail:
	if (cli != NULL) {
		torture_close_connection(cli);
	}
	return ret;
}
