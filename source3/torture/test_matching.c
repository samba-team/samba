/*
   Unix SMB/CIFS implementation.
   Samba utility tests
   Copyright (C) Stefan Metzmacher 2021

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
#include "proto.h"

bool run_str_match_mswild(int dummy)
{
	const char *namelist = "/abc*.txt/xyz*.dat/a0123456789Z/";
	name_compare_entry *name_entries = NULL;
	const struct test_name {
		const char *name;
		ssize_t case_sensitive_idx;
		ssize_t case_insensitive_idx;
	} names[] = {{
		.name = "/dir/abc123.txt",
		.case_sensitive_idx = 0,
		.case_insensitive_idx = 0,
	},{
		.name = "/dir/AbC123.TxT",
		.case_sensitive_idx = -1,
		.case_insensitive_idx = 0,
	},{
		.name = "/dir/xyz123.dat",
		.case_sensitive_idx = 1,
		.case_insensitive_idx = 1,
	},{
		.name = "/dir/XyZ123.DaT",
		.case_sensitive_idx = -1,
		.case_insensitive_idx = 1,
	},{
		.name = "/dir/aaa123.jpg",
		.case_sensitive_idx = -1,
		.case_insensitive_idx = -1,
	},{
		.name = "/dir/a0123456789Z",
		.case_sensitive_idx = 2,
		.case_insensitive_idx = 2,
	},{
		.name = "/dir/A0123456789z",
		.case_sensitive_idx = -1,
		.case_insensitive_idx = 2,
	}};
	size_t i;
	bool ret = true;

	d_fprintf(stderr, "namelist: %s\n", namelist);

	set_namearray(&name_entries, namelist);
	SMB_ASSERT(name_entries != NULL);

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		const struct test_name *n = &names[i];
		bool case_sensitive_match;
		bool case_insensitive_match;
		bool ok = true;

		case_sensitive_match = is_in_path(n->name,
						  name_entries,
						  true);
		if (n->case_sensitive_idx != -1) {
			ok &= case_sensitive_match;
		} else {
			ok &= !case_sensitive_match;
		}
		case_insensitive_match = is_in_path(n->name,
						    name_entries,
						    false);
		if (n->case_insensitive_idx != -1) {
			ok &= case_insensitive_match;
		} else {
			ok &= !case_insensitive_match;
		}

		d_fprintf(stderr, "name[%s] "
			  "case_sensitive[TIDX=%zd;MATCH=%u] "
			  "case_insensitive[TIDX=%zd;MATCH=%u] "
			  "%s\n",
			  n->name,
			  n->case_sensitive_idx,
			  case_sensitive_match,
			  n->case_insensitive_idx,
			  case_insensitive_match,
			  ok ? "OK" : "FAIL");

		ret &= ok;
	}

	return ret;
}
