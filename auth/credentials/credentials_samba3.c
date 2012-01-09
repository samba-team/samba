/*
   Unix SMB/CIFS implementation.

   Handle user credentials (shim to allow samba3 to build)

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2011

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
#include "auth/credentials/credentials.h"

/* These dummy functions are required only to allow the rest of the
 * code to compile when we are in the s3 autoconf build system */

_PUBLIC_ void cli_credentials_invalidate_ccache(struct cli_credentials *cred,
				       enum credentials_obtained obtained)
{
	return;
}

_PUBLIC_ int cli_credentials_set_ccache(struct cli_credentials *cred,
					struct loadparm_context *lp_ctx,
					const char *name,
					enum credentials_obtained obtained,
					const char **error_string)
{
	DEBUG(0, ("cli_credentials_set_ccache is unimplemented in the autoconf build\n"));
	return EINVAL;
}

_PUBLIC_ NTSTATUS cli_credentials_set_machine_account(struct cli_credentials *cred,
						      struct loadparm_context *lp_ctx)
{
	DEBUG(0, ("cli_credentials_set_machine_account is unimplemented in the autoconf build\n"));
	return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
}
