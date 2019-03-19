/*
 * Copyright (c) 2019      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "talloc_keep_secret.h"

static int talloc_keep_secret_destructor(void *ptr)
{
	size_t size = talloc_get_size(ptr);

	if (unlikely(size == 0)) {
		return 0;
	}

	memset_s(ptr, size, 0, size);

	return 0;
}

void _talloc_keep_secret(void *ptr, const char *name)
{
	size_t size;

	if (unlikely(ptr == NULL)) {
#ifdef DEVELOPER
		smb_panic("Invalid talloc pointer");
#endif
		return;
	}

	size = talloc_get_size(ptr);
	if (unlikely(size == 0)) {
		return;
	}

	talloc_set_name_const(ptr, name);
	talloc_set_destructor(ptr, talloc_keep_secret_destructor);
}
