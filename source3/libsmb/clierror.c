/* 
   Unix SMB/CIFS implementation.
   client error handling routines
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jelmer Vernooij 2003
   Copyright (C) Jeremy Allison 2006

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

/****************************************************************************
 Return the 32-bit NT status code from the last packet.
****************************************************************************/

NTSTATUS cli_nt_error(struct cli_state *cli)
{
	/* Deal with socket errors first. */
	if (!cli_state_is_connected(cli)) {
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	if (NT_STATUS_IS_DOS(cli->raw_status)) {
		int e_class = NT_STATUS_DOS_CLASS(cli->raw_status);
		int code = NT_STATUS_DOS_CODE(cli->raw_status);
		return dos_to_ntstatus(e_class, code);
	}

	return cli->raw_status;
}

int cli_status_to_errno(NTSTATUS status)
{
	int err;

	if (NT_STATUS_IS_DOS(status)) {
                uint8_t eclass = NT_STATUS_DOS_CLASS(status);
                uint32_t ecode = NT_STATUS_DOS_CODE(status);
		status = dos_to_ntstatus(eclass, ecode);
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK)) {
		/*
		 * Legacy code from cli_errno, see Samba up to 4.13: A
		 * special case for this Vista error. Since its
		 * high-order byte isn't 0xc0, it won't match
		 * correctly in map_errno_from_nt_status().
		 */
		err = EACCES;
	} else {
		err = map_errno_from_nt_status(status);
	}

	DBG_NOTICE("0x%"PRIx32" -> %d\n", NT_STATUS_V(status), err);

	return err;
}

/* Return a UNIX errno appropriate for the error received in the last
   packet. */

int cli_errno(struct cli_state *cli)
{
	bool connected;
	int err;

	connected = cli_state_is_connected(cli);
	if (!connected) {
		return EPIPE;
	}

	err = cli_status_to_errno(cli->raw_status);
	return err;
}

/* Return true if the last packet was in error */

bool cli_is_error(struct cli_state *cli)
{
	/* A socket error is always an error. */
	if (!cli_state_is_connected(cli)) {
		return true;
	}

	if (NT_STATUS_IS_DOS(cli->raw_status)) {
		/* Return error if error class in non-zero */
		uint8_t rcls = NT_STATUS_DOS_CLASS(cli->raw_status);
		return rcls != 0;
	}

	return NT_STATUS_IS_ERR(cli->raw_status);
}

bool cli_state_is_connected(struct cli_state *cli)
{
	if (cli == NULL) {
		return false;
	}

	if (!cli->initialised) {
		return false;
	}

	return smbXcli_conn_is_connected(cli->conn);
}
