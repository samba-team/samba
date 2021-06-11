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
#include "lib/util_matching.h"
#include "proto.h"

bool run_str_match_mswild(int dummy)
{
	const char *namelist = "/abc*.txt/xyz*.dat/a0123456789Z/";
	name_compare_entry *name_entries = NULL;
	struct samba_path_matching *pmcs = NULL;
	struct samba_path_matching *pmci = NULL;
	const struct str_match_mswild_name {
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
	NTSTATUS status;
	size_t i;
	bool ret = true;

	d_fprintf(stderr, "namelist: %s\n", namelist);

	set_namearray(&name_entries, namelist);
	SMB_ASSERT(name_entries != NULL);

	status = samba_path_matching_mswild_create(talloc_tos(),
						   true, /* case_sensitive */
						   namelist,
						   &pmcs);
	SMB_ASSERT(NT_STATUS_IS_OK(status));
	status = samba_path_matching_mswild_create(talloc_tos(),
						   false, /* case_sensitive */
						   namelist,
						   &pmci);
	SMB_ASSERT(NT_STATUS_IS_OK(status));


	for (i = 0; i < ARRAY_SIZE(names); i++) {
		const struct str_match_mswild_name *n = &names[i];
		bool case_sensitive_match;
		bool case_insensitive_match;
		ssize_t cs_match_idx = -1;
		ssize_t ci_match_idx = -1;
		ssize_t replace_start = -1;
		ssize_t replace_end = -1;
		bool ok = true;

		case_sensitive_match = is_in_path(n->name,
						  name_entries,
						  true);
		if (n->case_sensitive_idx != -1) {
			ok &= case_sensitive_match;
		} else {
			ok &= !case_sensitive_match;
		}
		status = samba_path_matching_check_last_component(pmcs,
								  n->name,
								  &cs_match_idx,
								  &replace_start,
								  &replace_end);
		SMB_ASSERT(NT_STATUS_IS_OK(status));
		SMB_ASSERT(replace_start == -1);
		SMB_ASSERT(replace_end == -1);
		if (n->case_sensitive_idx != cs_match_idx) {
			ok = false;
		}
		case_insensitive_match = is_in_path(n->name,
						    name_entries,
						    false);
		if (n->case_insensitive_idx != -1) {
			ok &= case_insensitive_match;
		} else {
			ok &= !case_insensitive_match;
		}
		status = samba_path_matching_check_last_component(pmci,
								  n->name,
								  &ci_match_idx,
								  &replace_start,
								  &replace_end);
		SMB_ASSERT(NT_STATUS_IS_OK(status));
		SMB_ASSERT(replace_start == -1);
		SMB_ASSERT(replace_end == -1);
		if (n->case_insensitive_idx != ci_match_idx) {
			ok = false;
		}

		d_fprintf(stderr, "name[%s] "
			  "case_sensitive[TIDX=%zd;MATCH=%u;MIDX=%zd] "
			  "case_insensitive[TIDX=%zd;MATCH=%u;MIDX=%zd] "
			  "%s\n",
			  n->name,
			  n->case_sensitive_idx,
			  case_sensitive_match,
			  cs_match_idx,
			  n->case_insensitive_idx,
			  case_insensitive_match,
			  ci_match_idx,
			  ok ? "OK" : "FAIL");

		ret &= ok;
	}

	return ret;
}

bool run_str_match_regex_sub1(int dummy)
{
	const char *invalidlist1 = "/Re7599Ex[0-9].*\\.txt/";
	const char *invalidlist2 = "/Re7599Ex\\([0-9]\\).*\\.\\(txt\\)/";
	const char *invalidlist3 = "/Re7599Ex\\([0-9]).*\\.txt/";
	const char *invalidlist4 = "/Re7599Ex[0-9.*\\.txt/";
	const char *namelist = "/Re7599Ex\\([0-9]\\).*\\.txt/test\\(.*\\).txt/^test\\([0-9]*\\).dat/";
	struct samba_path_matching *pm = NULL;
	const struct str_match_regex_sub1 {
		const char *name;
		ssize_t match_idx;
		ssize_t sub_start;
		ssize_t sub_end;
	} names[] = {{
		.name = "/dir/Re7599Ex567.txt",
		.match_idx = 0,
		.sub_start = 13,
		.sub_end = 14,
	},{
		.name = "/dir/rE7599eX567.txt",
		.match_idx = -1,
		.sub_start = -1,
		.sub_end = -1,
	},{
		.name = "/dir/Re7599Ex.txt",
		.match_idx = -1,
		.sub_start = -1,
		.sub_end = -1,
	},{
		.name = "/dir/testabc123.txt",
		.match_idx = 1,
		.sub_start = 9,
		.sub_end = 15,
	},{
		.name = "/dir/testabc123.tXt",
		.match_idx = -1,
		.sub_start = -1,
		.sub_end = -1,
	},{
		.name = "/dir/test123.dat",
		.match_idx = 2,
		.sub_start = 9,
		.sub_end = 12,
	},{
		.name = "/dir/tEst123.dat",
		.match_idx = -1,
		.sub_start = -1,
		.sub_end = -1,
	}};
	NTSTATUS status;
	size_t i;
	bool ret = true;

	d_fprintf(stderr, "invalidlist1: %s\n", invalidlist1);
	status = samba_path_matching_regex_sub1_create(talloc_tos(),
						       invalidlist1,
						       &pm);
	SMB_ASSERT(NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER));
	d_fprintf(stderr, "invalidlist2: %s\n", invalidlist2);
	status = samba_path_matching_regex_sub1_create(talloc_tos(),
						       invalidlist2,
						       &pm);
	SMB_ASSERT(NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER));
	d_fprintf(stderr, "invalidlist3: %s\n", invalidlist3);
	status = samba_path_matching_regex_sub1_create(talloc_tos(),
						       invalidlist3,
						       &pm);
	SMB_ASSERT(NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER));
	d_fprintf(stderr, "invalidlist4: %s\n", invalidlist4);
	status = samba_path_matching_regex_sub1_create(talloc_tos(),
						       invalidlist4,
						       &pm);
	SMB_ASSERT(NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER));

	d_fprintf(stderr, "namelist: %s\n", namelist);
	status = samba_path_matching_regex_sub1_create(talloc_tos(),
						       namelist,
						       &pm);
	SMB_ASSERT(NT_STATUS_IS_OK(status));

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		const struct str_match_regex_sub1 *n = &names[i];
		ssize_t match_idx = -1;
		ssize_t replace_start = -1;
		ssize_t replace_end = -1;
		bool ok = true;

		status = samba_path_matching_check_last_component(pm,
								  n->name,
								  &match_idx,
								  &replace_start,
								  &replace_end);
		SMB_ASSERT(NT_STATUS_IS_OK(status));
		if (match_idx == -1) {
			SMB_ASSERT(replace_start == -1);
			SMB_ASSERT(replace_end == -1);
		}
		if (n->match_idx != match_idx) {
			ok = false;
		}
		if (n->sub_start != replace_start) {
			ok = false;
		}
		if (n->sub_end != replace_end) {
			ok = false;
		}

		d_fprintf(stderr, "name[%s] "
			  "T[IDX=%zd;START=%zd;END=%zd] "
			  "M[[IDX=%zd;START=%zd;END=%zd] "
			  "%s\n",
			  n->name,
			  n->match_idx,
			  n->sub_start,
			  n->sub_end,
			  match_idx,
			  replace_start,
			  replace_end,
			  ok ? "OK" : "FAIL");

		ret &= ok;
	}

	return ret;
}
