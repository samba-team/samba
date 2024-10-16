/*
   Unix SMB/CIFS implementation.

   Winbind daemon - miscellaneous other functions

   Copyright (C) Tim Potter      2000
   Copyright (C) Andrew Bartlett 2002

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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND


static struct winbindd_child *static_locator_child = NULL;

struct winbindd_child *locator_child(void)
{
	return static_locator_child;
}

bool is_locator_child(const struct winbindd_child *child)
{
	if (child == static_locator_child) {
		return true;
	}

	return false;
}

struct dcerpc_binding_handle *locator_child_handle(void)
{
	return static_locator_child->binding_handle;
}

NTSTATUS init_locator_child(TALLOC_CTX *mem_ctx)
{
	if (static_locator_child != NULL) {
		DBG_ERR("locator child already allocated\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	static_locator_child = talloc_zero(mem_ctx, struct winbindd_child);
	if (static_locator_child == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	setup_child(NULL, static_locator_child, "log.winbindd", "locator");
	return NT_STATUS_OK;
}
