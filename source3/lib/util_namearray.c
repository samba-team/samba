/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Ralph Boehme 2024

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
#include "lib/util/strv.h"

/*******************************************************************
 Strip a '/' separated list into an array of
 name_compare_enties structures suitable for
 passing to is_in_path(). We do this for
 speed so we can pre-parse all the names in the list
 and don't do it for each call to is_in_path().
 We also check if the entry contains a wildcard to
 remove a potentially expensive call to mask_match
 if possible.
********************************************************************/

void set_namearray(TALLOC_CTX *mem_ctx,
		   const char *namelist_in,
		   struct name_compare_entry **_name_array)
{
	struct name_compare_entry *name_array = NULL;
	struct name_compare_entry *e = NULL;
	char *namelist = NULL;
	const char *p = NULL;
	size_t num_entries;

	*_name_array = NULL;

	if ((namelist_in == NULL) || (namelist_in[0] == '\0')) {
		return;
	}

	namelist = path_to_strv(mem_ctx, namelist_in);
	if (namelist == NULL) {
		DBG_ERR("path_to_strv failed\n");
		return;
	}

	num_entries = strv_count(namelist);

	name_array = talloc_zero_array(mem_ctx,
				       struct name_compare_entry,
				       num_entries + 1);
	if (name_array == NULL) {
		DBG_ERR("talloc failed\n");
		TALLOC_FREE(namelist);
		return;
	}

	namelist = talloc_reparent(mem_ctx, name_array, namelist);

	e = &name_array[0];

	while ((p = strv_next(namelist, p)) != NULL) {
		if (*p == '\0') {
			/* cope with multiple (useless) /s) */
			continue;
		}

		e->name = p;
		e->is_wild = ms_has_wild(e->name);
		e++;
	}

	*_name_array = name_array;
	return;
}
