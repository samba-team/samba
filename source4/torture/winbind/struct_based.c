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
#include "torture/torture.h"
#include "torture/winbind/proto.h"
#include "nsswitch/winbind_client.h"

static bool torture_winbind_struct_ping(struct torture_context *torture)
{
	NSS_STATUS result;

	torture_comment(torture, "Testing WINBINDD_PING (struct based protocol)\n");

	result = winbindd_request_response(WINBINDD_PING, NULL, NULL);
	torture_assert_int_equal(torture,result,NSS_STATUS_SUCCESS,
				 "WINBINDD_PING (struct based protocol)");

	return true;
}

struct torture_suite *torture_winbind_struct_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "STRUCT");

	torture_suite_add_simple_test(suite, "PING", torture_winbind_struct_ping);

	suite->description = talloc_strdup(suite, "WINBIND - struct based protocol tests");

	return suite;
}
