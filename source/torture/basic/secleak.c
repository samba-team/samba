/* 
   Unix SMB/CIFS implementation.

   find security related memory leaks

   Copyright (C) Andrew Tridgell 2004
   
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

static BOOL try_failed_login(struct smbcli_state *cli)
{
	NTSTATUS status;
	union smb_sesssetup setup;
	struct smbcli_session *session;

	session = smbcli_session_init(cli->transport);
	setup.generic.level = RAW_SESSSETUP_GENERIC;
	setup.generic.in.sesskey = cli->transport->negotiate.sesskey;
	setup.generic.in.capabilities = cli->transport->negotiate.capabilities;
	setup.generic.in.password = "INVALID-PASSWORD";
	setup.generic.in.user = "INVALID-USERNAME";
	setup.generic.in.domain = "INVALID-DOMAIN";

	status = smb_raw_session_setup(session, session, &setup);
	talloc_free(session);
	if (NT_STATUS_IS_OK(status)) {
		printf("Allowed session setup with invalid credentials?!\n");
		return False;
	}

	return True;
}

BOOL torture_sec_leak(void)
{
	struct smbcli_state *cli;
	time_t t1 = time(NULL);

	if (!torture_open_connection(&cli)) {
		return False;
	}

	while (time(NULL) < t1+20) {
		if (!try_failed_login(cli)) {
			return False;
		}
	}

	return True;
}
