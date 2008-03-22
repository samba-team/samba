/*
 * Unix SMB/CIFS implementation.
 * Registry helper routines
 * Copyright (C) Michael Adam 2008
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

bool registry_init_basic(void)
{
	int saved_errno = 0;

	DEBUG(10, ("registry_init_basic called\n"));

	if (!regdb_init()) {
		saved_errno = errno;
		DEBUG(1, ("Can't open the registry"));
		if (saved_errno) {
			DEBUGADD(1, (": %s", strerror(saved_errno)));
		}
		DEBUGADD(1, (".\n"));
		return false;
	}
	regdb_close();

	reghook_cache_init();

	return true;
}
