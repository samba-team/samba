/* 
   Unix SMB/CIFS implementation.

   find security related memory leaks

   Copyright (C) Andrew Tridgell 2004
   
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
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "torture/util.h"
#include "system/time.h"
#include "libcli/smb_composite/smb_composite.h"
#include "auth/credentials/credentials.h"

static BOOL try_failed_login(struct smbcli_state *cli)
{
	NTSTATUS status;
	struct smb_composite_sesssetup setup;
	struct smbcli_session *session;

	session = smbcli_session_init(cli->transport, cli, False);
	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities;
	setup.in.workgroup = lp_workgroup();

	setup.in.credentials = cli_credentials_init(session);
	cli_credentials_set_conf(setup.in.credentials);
	cli_credentials_set_domain(setup.in.credentials, "INVALID-DOMAIN", CRED_SPECIFIED);
	cli_credentials_set_username(setup.in.credentials, "INVALID-USERNAME", CRED_SPECIFIED);
	cli_credentials_set_password(setup.in.credentials, "INVALID-PASSWORD", CRED_SPECIFIED);

	status = smb_composite_sesssetup(session, &setup);
	talloc_free(session);
	if (NT_STATUS_IS_OK(status)) {
		printf("Allowed session setup with invalid credentials?!\n");
		return False;
	}

	return True;
}

BOOL torture_sec_leak(struct torture_context *tctx, struct smbcli_state *cli)
{
	time_t t1 = time(NULL);
	int timelimit = torture_setting_int(tctx, "timelimit", 20);

	while (time(NULL) < t1+timelimit) {
		if (!try_failed_login(cli)) {
			return False;
		}
		talloc_report(NULL, stdout);
	}

	return True;
}
