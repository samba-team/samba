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

static BOOL test_BindingString(TALLOC_CTX *mem_ctx, const char *binding)
{
	struct dcerpc_binding b, b2;
	const char *s, *s2;
	struct epm_tower tower;
	NTSTATUS status;

	/* Parse */
	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Error parsing binding string '%s': %s\n", binding, nt_errstr(status)));
		return False;
	}

	s = dcerpc_binding_string(mem_ctx, &b);
	if (!s) {
		DEBUG(0, ("Error converting binding back to string for '%s'\n", binding)); 
		return False;
	}

	if (strcasecmp(binding, s) != 0) {
		DEBUG(0, ("Mismatch while comparing original and regenerated binding strings: '%s' <> '%s'\n", binding, s));
		return False;
	}

	/* Generate protocol towers */
	status = dcerpc_binding_build_tower(mem_ctx, &b, &tower);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Error generating protocol tower from '%s': %s\n", binding, nt_errstr(status)));
		return False;
	}

	/* Convert back to binding and then back to string and compare */

	status = dcerpc_binding_from_tower(mem_ctx, &tower, &b2);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Error generating binding from tower for original binding '%s': %s\n", binding, nt_errstr(status)));
		return False;
	}

	/* Compare to a stripped down version of the binding string because 
	 * the protocol tower doesn't contain the extra option data */
	if (b.options && b.options[0]) {
		b.options[1] = NULL; 
	}

	b.flags = 0;
	
	s = dcerpc_binding_string(mem_ctx, &b);
	if (!s) {
		DEBUG(0, ("Error converting binding back to string for (stripped down) '%s'\n", binding)); 
		return False;
	}


	s2 = dcerpc_binding_string(mem_ctx, &b2);
	if (!s) {
		DEBUG(0, ("Error converting binding back to string for '%s'\n", binding)); 
		return False;
	}

	if (strcasecmp(s, s2) != 0) {
		DEBUG(0, ("Mismatch while comparing original and from protocol tower generated binding strings: '%s' <> '%s'\n", s, s2));
		return False;
	}

	return True;
}

static const char *test_strings[] = {
	"ncacn_np:", 
	"ncalrpc:", 
	"ncalrpc:[Security=Sane]", 
	"ncacn_np:[rpcecho]",
	"ncacn_np:127.0.0.1[rpcecho]",
	"ncacn_ip_tcp:127.0.0.1",
	"ncacn_np:localhost[rpcecho]",
	"ncacn_np:[/pipe/rpcecho]",
	"ncacn_np:localhost[/pipe/rpcecho,sign,seal]",
	"ncacn_np:[,sign]",
	"ncadg_ip_udp:",
	"308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_np:localhost",
	"308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_ip_tcp:127.0.0.1",
};

BOOL torture_local_binding_string(int dummy) 
{
	BOOL ret = True;
	TALLOC_CTX *mem_ctx = talloc_init("test_BindingString");
	int i;

	for (i = 0; i < ARRAY_SIZE(test_strings); i++) {
		ret &= test_BindingString(mem_ctx, test_strings[i]);
	}

	talloc_destroy(mem_ctx);

	return ret;
}
