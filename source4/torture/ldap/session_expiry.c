/*
 * Unix SMB/CIFS implementation.
 *
 * Test LDB attribute functions
 *
 * Copyright (C) Andrew Bartlet <abartlet@samba.org> 2008-2009
 * Copyright (C) Matthieu Patou <mat@matws.net> 2009
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.	If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "lib/events/events.h"
#include <ldb.h>
#include <ldb_errors.h>
#include "ldb_wrap.h"
#include "param/param.h"
#include "lib/cmdline/popt_common.h"
#include "auth/credentials/credentials.h"
#include "libcli/ldap/ldap_client.h"
#include "torture/smbtorture.h"
#include "torture/ldap/proto.h"

bool torture_ldap_session_expiry(struct torture_context *torture)
{
	const char *host = torture_setting_string(torture, "host", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	struct ldb_context *ldb = NULL;
	const char *url = NULL;
	bool ret = false;
	bool ok;
	struct ldb_dn *rootdn = NULL;
	struct ldb_result *result = NULL;
	int rc = LDB_SUCCESS;

	/*
	 * Further down we request a ticket lifetime of 4
	 * seconds. Give the server 10 seconds for this to kick in
	 */
	const struct timeval endtime = timeval_current_ofs(10, 0);

	url = talloc_asprintf(torture, "ldap://%s/", host);
	torture_assert_goto(
		torture, url!=NULL, ret, fail, "talloc_asprintf failed");

	cli_credentials_set_kerberos_state(
		credentials, CRED_MUST_USE_KERBEROS);

	ok = lpcfg_set_option(
		torture->lp_ctx, "gensec_gssapi:requested_life_time=4");
	torture_assert_goto(
		torture, ok, ret, fail, "lpcfg_set_option failed");

	ldb = ldb_wrap_connect(
		torture,
		torture->ev,
		torture->lp_ctx,
		url,
		NULL,
		credentials,
		0);
	torture_assert_goto(
		torture, ldb!=NULL, ret, fail, "ldb_wrap_connect failed");

	rootdn = ldb_dn_new(ldb, ldb, NULL);
	torture_assert_goto(
		torture, rootdn!=NULL, ret, fail, "ldb_dn_new failed");

	rc = ldb_search(
		ldb,		    /* ldb */
		ldb,		    /* mem_ctx */
		&result,	    /* result */
		rootdn,		    /* base */
		LDB_SCOPE_BASE,	    /* scope */
		NULL,		    /* attrs */
		"(objectclass=*)"); /* exp_fmt */
	torture_assert_goto(
		torture, rc==LDB_SUCCESS, ret, fail, "1st ldb_search failed");

	do {
		smb_msleep(1000);

		rc = ldb_search(
			ldb,		/* ldb */
			ldb,		/* mem_ctx */
			&result,	/* result */
			rootdn,		/* base */
			LDB_SCOPE_BASE, /* scope */
			NULL,		/* attrs */
			"(objectclass=*)"); /* exp_fmt */
		printf("ldb_search returned %s\n", ldb_strerror(rc));
		TALLOC_FREE(result);

		if (rc != LDB_SUCCESS) {
			break;
		}
	} while (!timeval_expired(&endtime));

	torture_assert_goto(
		torture,
		rc==LDB_ERR_PROTOCOL_ERROR,
		ret,
		fail,
		"expected LDB_ERR_PROTOCOL_ERROR after 4 seconds");

	ret = true;
fail:
	TALLOC_FREE(ldb);
	return ret;
}
