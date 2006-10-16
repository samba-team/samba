/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Jelmer Vernooij 2006
   
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
#include "torture/torture.h"
#include "torture/nbt/proto.h"
#include "torture/ui.h"
#include "libcli/resolve/resolve.h"

bool torture_nbt_get_name(struct torture_context *tctx, 
								 struct nbt_name *name, 
								 const char **address)
{
	make_nbt_name_server(name, strupper_talloc(tctx, 
						 torture_setting_string(tctx, "host", NULL)));

	/* do an initial name resolution to find its IP */
	torture_assert_ntstatus_ok(tctx, 
							   resolve_name(name, tctx, address, NULL), 
							   talloc_asprintf(tctx, 
							   "Failed to resolve %s", name->name));

	return true;
}

NTSTATUS torture_nbt_init(void)
{
	struct torture_suite *suite = torture_suite_create(
											talloc_autofree_context(),
											"NBT");
	/* nbt tests */
	torture_suite_add_suite(suite, torture_nbt_register());
	torture_suite_add_suite(suite, torture_nbt_wins());
	torture_suite_add_suite(suite, torture_nbt_dgram());
	torture_suite_add_suite(suite, torture_nbt_winsreplication());
	torture_suite_add_suite(suite, torture_bench_nbt());
	torture_suite_add_suite(suite, torture_bench_wins());

	suite->description = talloc_strdup(suite, 
							"NetBIOS over TCP/IP and WINS tests");

	torture_register_suite(suite);

	return NT_STATUS_OK;
}
