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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/smb/smb_signing.h"
#include "lib/param/param.h"
#include "smb2_signing.h"

bool smb2_srv_init_signing(struct loadparm_context *lp_ctx,
			   struct smbXsrv_connection *conn)
{
	/*
	 * For SMB2 all we need to know is if signing is mandatory.
	 * It is always allowed and desired, whatever the smb.conf says.
	 */
	(void)lpcfg_server_signing_allowed(lp_ctx, &conn->smb2.signing_mandatory);
	return true;
}

bool srv_init_signing(struct smbXsrv_connection *conn)
{
	struct loadparm_context *lp_ctx = NULL;
	bool ok;

	lp_ctx = loadparm_init_s3(conn, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		DBG_DEBUG("loadparm_init_s3 failed\n");
		return false;
	}

#if defined(WITH_SMB1SERVER)
	if (conn->protocol >= PROTOCOL_SMB2_02) {
#endif
		ok = smb2_srv_init_signing(lp_ctx, conn);
#if defined(WITH_SMB1SERVER)
	} else {
		ok = smb1_srv_init_signing(lp_ctx, conn);
	}
#endif
	talloc_unlink(conn, lp_ctx);
	return ok;
}
