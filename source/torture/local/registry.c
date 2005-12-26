/* 
   Unix SMB/CIFS implementation.

   local testing of registry library

   Copyright (C) Jelmer Vernooij 2005
   
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
#include "librpc/gen_ndr/security.h"
#include "librpc/gen_ndr/ndr_epmapper.h"

static BOOL test_hive(TALLOC_CTX *mem_ctx, const char *backend, const char *location)
{
	WERROR error;
	struct registry_key *root, *subkey;
	uint32_t count;
	
	if (!reg_has_backend(backend)) {
		printf("Backend '%s' support not compiled in, ignoring\n", backend);
		return True;
	}

	error = reg_open_hive(mem_ctx, backend, location, NULL, &root);
	if (!W_ERROR_IS_OK(error)) {
		printf("reg_open_hive() failed\n"); 
		return False;
	}

	/* This is a new backend. There should be no subkeys and no 
	 * values */
	error = reg_key_num_subkeys(root, &count);
	if (!W_ERROR_IS_OK(error)) {
		printf("reg_key_num_subkeys failed\n");
		return False;
	}

	if (count != 0) {
		printf("New key has non-zero subkey count\n");
		return False;
	}

	error = reg_key_num_values(root, &count);
	if (!W_ERROR_IS_OK(error)) {
		printf("reg_key_num_values failed\n");
		return False;
	}

	if (count != 0) {
		printf("New key has non-zero value count\n");
		return False;
	}

	error = reg_key_add_name(mem_ctx, root, "Nested\\Key", SEC_MASK_GENERIC, NULL, &subkey);
	if (!W_ERROR_IS_OK(error)) {
		return False;
	}

	error = reg_key_del(root, "Nested\\Key");
	if (!W_ERROR_IS_OK(error)) {
		return False;
	}

	talloc_free(root);

	return True;
}

BOOL torture_registry(void) 
{
	BOOL ret = True;
	TALLOC_CTX *mem_ctx = talloc_init("torture_registry");

	registry_init();

	ret &= test_hive(mem_ctx, "nt4", "TEST.DAT");
	ret &= test_hive(mem_ctx, "ldb", "test.ldb");
	ret &= test_hive(mem_ctx, "gconf", ".");
	ret &= test_hive(mem_ctx, "dir", ".");

	talloc_free(mem_ctx);

	return ret;
}
