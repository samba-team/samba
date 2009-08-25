/*
   Unix SMB/CIFS implementation.
   Copyright (C) Guenther Deschner    2009

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
#include "../libcli/auth/libcli_auth.h"
#include "../libcli/auth/schannel_state.h"

/******************************************************************************
 Wrapper around schannel_fetch_session_key_tdb()
 Note we must be root here.
*******************************************************************************/

NTSTATUS schannel_fetch_session_key(TALLOC_CTX *mem_ctx,
				    const char *computer_name,
				    struct netlogon_creds_CredentialState **pcreds)
{
	struct tdb_context *tdb;
	NTSTATUS status;

	tdb = open_schannel_session_store(mem_ctx);
	if (!tdb) {
		return NT_STATUS_ACCESS_DENIED;
	}

	status = schannel_fetch_session_key_tdb(tdb, mem_ctx, computer_name, pcreds);

	tdb_close(tdb);

	return status;
}

/******************************************************************************
 Wrapper around schannel_store_session_key_tdb()
 Note we must be root here.
*******************************************************************************/

NTSTATUS schannel_store_session_key(TALLOC_CTX *mem_ctx,
				    struct netlogon_creds_CredentialState *creds)
{
	struct tdb_context *tdb;
	NTSTATUS status;

	tdb = open_schannel_session_store(mem_ctx);
	if (!tdb) {
		return NT_STATUS_ACCESS_DENIED;
	}

	status = schannel_store_session_key_tdb(tdb, mem_ctx, creds);

	tdb_close(tdb);

	return status;
}
