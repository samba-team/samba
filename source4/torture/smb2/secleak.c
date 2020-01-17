/*
   Unix SMB/CIFS implementation.

   find security related memory leaks

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) David Mulder 2020

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
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/libcli.h"
#include "torture/util.h"
#include "system/time.h"
#include "libcli/smb_composite/smb_composite.h"
#include "auth/credentials/credentials.h"
#include "param/param.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/smb2/proto.h"
#include "../libcli/smb/smbXcli_base.h"

static bool try_failed_login(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	struct cli_credentials *credentials = NULL;
	uint32_t sessid = 0;
	struct smb2_session *session = NULL;
	bool result = true;

	session = smb2_session_init(tree->session->transport,
				    lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				    tctx);
	torture_assert(tctx, session, "Session initialization failed");

	sessid = smb2cli_session_current_id(tree->session->smbXcli);
	credentials = cli_credentials_init(session);
	torture_assert_goto(tctx, credentials, result, done,
			    "Credential allocation failed");

	cli_credentials_set_conf(credentials, tctx->lp_ctx);
	cli_credentials_set_domain(credentials, "INVALID-DOMAIN", CRED_SPECIFIED);
	cli_credentials_set_username(credentials, "INVALID-USERNAME", CRED_SPECIFIED);
	cli_credentials_set_password(credentials, "INVALID-PASSWORD", CRED_SPECIFIED);

	status = smb2_session_setup_spnego(session, credentials, sessid);
	torture_assert_ntstatus_equal_goto(tctx, status,
		NT_STATUS_LOGON_FAILURE, result, done,
		"Allowed session setup with invalid credentials?!\n");

done:
	/* smb2_session_init() steals the transport, and if we don't steal it
	 * back before freeing session, then we segfault on the next iteration
	 * because the transport pointer in the tree is now invalid.
	 */
	tree->session->transport = talloc_steal(tree->session, session->transport);
	talloc_free(session);

	return result;
}

bool torture_smb2_sec_leak(struct torture_context *tctx, struct smb2_tree *tree)
{
	time_t t1 = time_mono(NULL);
	int timelimit = torture_setting_int(tctx, "timelimit", 20);
	bool result;

	while (time_mono(NULL) < t1+timelimit) {
		result = try_failed_login(tctx, tree);
		torture_assert(tctx, result,
			       "Invalid credentials should have failed");

		talloc_report(NULL, stdout);
	}

	return true;
}
