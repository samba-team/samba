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

static BOOL test_BindingString(const char *binding)
{
	TALLOC_CTX *mem_ctx = talloc_init("test_BindingString");
	struct dcerpc_binding b;
	const char *s;
	struct epm_tower *tower;
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

	/* FIXME: Convert back to binding and then back to string and compare */

	return True;
}

BOOL torture_local_binding_string(int dummy) 
{
	BOOL ret = True;

	ret &= test_BindingString("ncacn_np:");
	ret &= test_BindingString("ncalrpc:");
	ret &= test_BindingString("ncalrpc:");
	ret &= test_BindingString("ncacn_np:[rpcecho]");
	ret &= test_BindingString("ncacn_np:127.0.0.1[rpcecho]");
	ret &= test_BindingString("ncacn_np:localhost[rpcecho]");
	ret &= test_BindingString("ncacn_np:[/pipe/rpcecho]");
	ret &= test_BindingString("ncacn_np:localhost[/pipe/rpcecho,sign,seal]");
	ret &= test_BindingString("ncacn_np:[,sign]");
	ret &= test_BindingString("ncadg_ip_udp:");
	ret &= test_BindingString("308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_np:localhost");
	ret &= test_BindingString("308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_ip_tcp:localhost");

	return ret;
}
