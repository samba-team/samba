/*
   Unix SMB/CIFS implementation.
   SMB torture tester - winbind struct based protocol
   Copyright (C) Stefan Metzmacher 2007

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
#include "pstring.h"
#include "torture/torture.h"
#include "torture/winbind/proto.h"
#include "nsswitch/winbind_client.h"
#include "param/param.h"

#define DO_STRUCT_REQ_REP(op,req,rep) do { \
	NSS_STATUS _result; \
	_result = winbindd_request_response(op, req, rep); \
	torture_assert_int_equal(torture, _result, NSS_STATUS_SUCCESS, \
				 __STRING(op) "(struct based)"); \
} while (0)

static bool torture_winbind_struct_ping(struct torture_context *torture)
{
	struct timeval tv = timeval_current();
	int timelimit = torture_setting_int(torture, "timelimit", 5);
	uint32_t total = 0;

	torture_comment(torture,
			"Running WINBINDD_PING (struct based) for %d seconds\n",
			timelimit);

	while (timeval_elapsed(&tv) < timelimit) {
		DO_STRUCT_REQ_REP(WINBINDD_PING, NULL, NULL);
		total++;
	}

	torture_comment(torture,
			"%u (%.1f/s) WINBINDD_PING (struct based)\n",
			total, total / timeval_elapsed(&tv));

	return true;
}

static bool torture_winbind_struct_getdcname(struct torture_context *torture)
{
	struct winbindd_request req;
	struct winbindd_response rep;

	ZERO_STRUCT(req);
	ZERO_STRUCT(rep);

	fstrcpy(req.domain_name, lp_workgroup());

	DO_STRUCT_REQ_REP(WINBINDD_GETDCNAME, &req, &rep);

	/*
	 * TODO: test all trusted domains
	 */

	return true;
}

struct torture_suite *torture_winbind_struct_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "STRUCT");

	torture_suite_add_simple_test(suite, "PING", torture_winbind_struct_ping);
	torture_suite_add_simple_test(suite, "GETDCNAME", torture_winbind_struct_getdcname);

	suite->description = talloc_strdup(suite, "WINBIND - struct based protocol tests");

	return suite;
}
