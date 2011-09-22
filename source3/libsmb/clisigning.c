/*
   Unix SMB/CIFS implementation.
   SMB Signing Code
   Copyright (C) Jeremy Allison 2003.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003
   Copyright (C) Stefan Metzmacher 2009

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
#include "libsmb/libsmb.h"
#include "../libcli/smb/smbXcli_base.h"

bool cli_simple_set_signing(struct cli_state *cli,
			    const DATA_BLOB user_session_key,
			    const DATA_BLOB response)
{
	return smb1cli_conn_activate_signing(cli->conn,
					user_session_key,
					response);
}

bool cli_check_sign_mac(struct cli_state *cli, const char *buf, uint32_t seqnum)
{
	return smb1cli_conn_check_signing(cli->conn,
					  (const uint8_t *)buf,
					  seqnum);
}

bool client_is_signing_on(struct cli_state *cli)
{
	return smb1cli_conn_signing_is_active(cli->conn);
}
