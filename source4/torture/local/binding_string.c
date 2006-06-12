/* 
   Unix SMB/CIFS implementation.

   local testing of RPC binding string parsing 

   Copyright (C) Jelmer Vernooij 2004
   
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
#include "librpc/gen_ndr/epmapper.h"
#include "librpc/rpc/dcerpc.h"
#include "torture/torture.h"
#include "torture/ui.h"

static BOOL test_BindingString(struct torture_context *torture, const char *binding)
{
	struct dcerpc_binding *b, *b2;
	const char *s, *s2;
	struct epm_tower tower;
	NTSTATUS status;
	struct torture_test *test = torture_test(torture, binding, binding);

	/* Parse */
	torture_assert_ntstatus_ok(test, 
		dcerpc_parse_binding(test, binding, &b),
		"Error parsing binding string");

	s = dcerpc_binding_string(test, b);
	if (!s) {
		torture_fail(test, "Error converting binding back to string");
		talloc_free(test);
		return False;
	}

	torture_assert_casestr_equal(test, binding, s, 
		"Mismatch while comparing original and regenerated binding strings");

	/* Generate protocol towers */
	torture_assert_ntstatus_ok(test, 
		dcerpc_binding_build_tower(test, b, &tower),
		"Error generating protocol tower");

	/* Convert back to binding and then back to string and compare */

	torture_assert_ntstatus_ok(test,
				dcerpc_binding_from_tower(test, &tower, &b2),
			    "Error generating binding from tower for original binding");

	/* Compare to a stripped down version of the binding string because 
	 * the protocol tower doesn't contain the extra option data */
	b->options = NULL;

	b->flags = 0;
	
	s = dcerpc_binding_string(test, b);
	if (!s) {
		torture_fail(test, "Error converting binding back to string for (stripped down)"); 
		talloc_free(test);
		return False;
	}


	s2 = dcerpc_binding_string(test, b2);
	if (!s) {
		torture_fail(test, "Error converting binding back to string"); 
		talloc_free(test);
		return False;
	}

	if (is_ipaddress(b->host) && strcasecmp(s, s2) != 0) {
		torture_fail(test, "Mismatch while comparing original and from protocol tower generated binding strings: '%s' <> '%s'\n", s, s2);
		talloc_free(test);
		return False;
	}

	torture_ok(test);
	talloc_free(test);
	return True;
}

static const char *test_strings[] = {
	"ncacn_np:", 
	"ncalrpc:", 
	"ncalrpc:[,Security=Sane]", 
	"ncacn_np:[rpcecho]",
	"ncacn_np:127.0.0.1[rpcecho]",
	"ncacn_ip_tcp:127.0.0.1",
	"ncacn_ip_tcp:127.0.0.1[20]",
	"ncacn_ip_tcp:127.0.0.1[20,sign]",
	"ncacn_ip_tcp:127.0.0.1[20,Security=Foobar,sign]",
	"ncacn_http:127.0.0.1",
	"ncacn_http:127.0.0.1[78]",
	"ncacn_http:127.0.0.1[78,ProxyServer=myproxy:3128]",
	"ncacn_np:localhost[rpcecho]",
	"ncacn_np:[/pipe/rpcecho]",
	"ncacn_np:localhost[/pipe/rpcecho,sign,seal]",
	"ncacn_np:[,sign]",
	"ncadg_ip_udp:",
	"308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_np:localhost",
	"308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_ip_tcp:127.0.0.1",
	"ncacn_unix_stream:[/tmp/epmapper]",
	"ncalrpc:[IDENTIFIER]",
	"ncacn_unix_stream:[/tmp/epmapper,sign]",
};

BOOL torture_local_binding_string(struct torture_context *torture) 
{
	BOOL ret = True;
	int i;

	for (i = 0; i < ARRAY_SIZE(test_strings); i++) {
		ret &= test_BindingString(torture, test_strings[i]);
	}

	return ret;
}
