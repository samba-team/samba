/* 
   Unix SMB/CIFS implementation.
   Registry interface
   Copyright (C) Jelmer Vernooij					  2004.
   
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
#include "lib/registry/common/registry.h"

/* 
 * Saves the dn as private_data for every key/val
 */

static BOOL ldb_open_registry(REG_HANDLE *handle, const char *location, BOOL try_full_load)
{
	struct ldb_context *c;
	c = ldb_connect(location, 0, NULL);

	if(!c) return False;

	handle->backend_data = c;
	
	return True;
}

static BOOL ldb_close_registry(REG_HANDLE *h) 
{
	ldb_close(h);
	return True;
}

static REG_KEY *ldb_open_key(REG_HANDLE *h, const char *name)
{
	/* FIXME */
}

static REG_OPS reg_backend_ldb = {
	.name = "ldb",
	.open_registry = ldb_open_registry,
	.close_registry = ldb_close_registry,
	.open_key = ldb_open_key,
};

NTSTATUS reg_ldb_init(void)
{
	return register_backend("registry", &reg_backend_ldb);
}
