/*
   Unix SMB/CIFS implementation.
   Samba utility functions
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
#include "lib/util/string_wrappers.h"

struct samba_path_matching_entry {
	const char *name;
	bool is_wild;
	regex_t re;
};

struct samba_path_matching_result {
	ssize_t replace_start;
	ssize_t replace_end;
	bool match;
};

struct samba_path_matching {
	bool case_sensitive;
	NTSTATUS (*matching_fn)(const struct samba_path_matching *pm,
				const struct samba_path_matching_entry *e,
				const char *namecomponent,
				struct samba_path_matching_result *result);
	size_t num_entries;
	struct samba_path_matching_entry *entries;
};

static NTSTATUS samba_path_matching_split(TALLOC_CTX *mem_ctx,
					  const char *namelist_in,
					  struct samba_path_matching **ppm)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *name_end = NULL;
	char *namelist = NULL;
	char *namelist_end = NULL;
	char *nameptr = NULL;
	struct samba_path_matching *pm = NULL;
	size_t num_entries = 0;
	struct samba_path_matching_entry *entries = NULL;

	*ppm = NULL;

	pm = talloc_zero(mem_ctx, struct samba_path_matching);
	if (pm == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_reparent(mem_ctx, frame, pm);

	namelist = talloc_strdup(frame, namelist_in);
	if (namelist == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	nameptr = namelist;

	namelist_end = &namelist[strlen(namelist)];

	/*
	 * We need to make two passes over the string. The
	 * first to count the number of elements, the second
	 * to split it.
	 *
	 * The 1st time entries is NULL.
	 * the 2nd time entries is allocated.
	 */
again:
	while (nameptr <= namelist_end) {
		/* anything left? */
		if (*nameptr == '\0') {
			break;
		}

		if (*nameptr == '/') {
			/* cope with multiple (useless) /s) */
			nameptr++;
			continue;
		}

		/* find the next '/' or consume remaining */
		name_end = strchr_m(nameptr, '/');
		if (entries != NULL) {
			if (name_end != NULL) {
				*name_end = '\0';
			}
			entries[num_entries].name = talloc_strdup(entries,
								  nameptr);
			if (entries[num_entries].name == NULL) {
				TALLOC_FREE(frame);
				return NT_STATUS_NO_MEMORY;
			}
		}
		num_entries++;
		if (name_end != NULL) {
			/* next segment please */
			nameptr = name_end + 1;
			continue;
		}

		/* no entries remaining */
		break;
	}

	if (num_entries == 0) {
		/*
		 * No entries in the first round => we're done
		 */
		goto done;
	}

	if (entries != NULL) {
		/*
		 * We finished the 2nd round => we're done
		 */
		goto done;
	}

	/*
	 * Now allocate the array and loop again
	 * in order to split the names.
	 */
	entries = talloc_zero_array(pm,
				    struct samba_path_matching_entry,
				    num_entries);
	if (entries == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	num_entries = 0;
	nameptr = namelist;
	goto again;

done:
	pm->num_entries = num_entries;
	pm->entries = entries;
	*ppm = talloc_move(mem_ctx, &pm);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
};

static NTSTATUS samba_path_create_mswild_fn(const struct samba_path_matching *pm,
					    const struct samba_path_matching_entry *e,
					    const char *namecomponent,
					    struct samba_path_matching_result *result)
{
	bool match = false;

	if (e->is_wild) {
		match = mask_match(namecomponent, e->name, pm->case_sensitive);
	} else if (pm->case_sensitive) {
		match = (strcmp(namecomponent, e->name) == 0);
	} else {
		match = (strcasecmp_m(namecomponent, e->name) == 0);
	}

	*result = (struct samba_path_matching_result) {
		.match = match,
		.replace_start = -1,
		.replace_end = -1,
	};

	return NT_STATUS_OK;
}

NTSTATUS samba_path_matching_mswild_create(TALLOC_CTX *mem_ctx,
					   bool case_sensitive,
					   const char *namelist_in,
					   struct samba_path_matching **ppm)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	struct samba_path_matching *pm = NULL;
	size_t i;

	*ppm = NULL;

	status = samba_path_matching_split(mem_ctx, namelist_in, &pm);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}
	talloc_reparent(mem_ctx, frame, pm);

	for (i = 0; i < pm->num_entries; i++) {
		struct samba_path_matching_entry *e = &pm->entries[i];

		e->is_wild = ms_has_wild(e->name);
	}

	pm->case_sensitive = case_sensitive;
	pm->matching_fn = samba_path_create_mswild_fn;
	*ppm = talloc_move(mem_ctx, &pm);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
};

static int samba_path_matching_regex_sub1_destructor(struct samba_path_matching *pm)
{
	ssize_t i;

	for (i = 0; i < pm->num_entries; i++) {
		struct samba_path_matching_entry *e = &pm->entries[i];

		regfree(&e->re);
	}

	pm->num_entries = 0;

	return 0;
}

static NTSTATUS samba_path_create_regex_sub1_fn(const struct samba_path_matching *pm,
						const struct samba_path_matching_entry *e,
						const char *namecomponent,
						struct samba_path_matching_result *result)
{
	if (e->re.re_nsub == 1) {
		regmatch_t matches[2] = { };
		int ret;

		ret = regexec(&e->re, namecomponent, 2, matches, 0);
		if (ret == 0) {
			*result = (struct samba_path_matching_result) {
				.match = true,
				.replace_start = matches[1].rm_so,
				.replace_end = matches[1].rm_eo,
			};

			return NT_STATUS_OK;
		}
	}

	*result = (struct samba_path_matching_result) {
		.match = false,
		.replace_start = -1,
		.replace_end = -1,
	};

	return NT_STATUS_OK;
}

NTSTATUS samba_path_matching_regex_sub1_create(TALLOC_CTX *mem_ctx,
					       const char *namelist_in,
					       struct samba_path_matching **ppm)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	struct samba_path_matching *pm = NULL;
	ssize_t i;

	*ppm = NULL;

	status = samba_path_matching_split(mem_ctx, namelist_in, &pm);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}
	talloc_reparent(mem_ctx, frame, pm);

	for (i = 0; i < pm->num_entries; i++) {
		struct samba_path_matching_entry *e = &pm->entries[i];
		int ret;

		ret = regcomp(&e->re, e->name, 0);
		if (ret != 0) {
			fstring buf = { 0,};

			regerror(ret, &e->re, buf, sizeof(buf));

			DBG_ERR("idx[%zu] regcomp: /%s/ - %d - %s\n",
				i, e->name, ret, buf);

			status = NT_STATUS_INVALID_PARAMETER;
			i--;
			goto cleanup;
		}

		if (e->re.re_nsub != 1) {
			DBG_ERR("idx[%zu] regcomp: /%s/ - re_nsub[%zu] != 1\n",
				i, e->name, e->re.re_nsub);
			status = NT_STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
	}

	talloc_set_destructor(pm, samba_path_matching_regex_sub1_destructor);

	pm->case_sensitive = true;
	pm->matching_fn = samba_path_create_regex_sub1_fn;
	*ppm = talloc_move(mem_ctx, &pm);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;

cleanup:
	for (; i >= 0; i--) {
		struct samba_path_matching_entry *e = &pm->entries[i];

		regfree(&e->re);
	}

	TALLOC_FREE(frame);
	return status;
};

NTSTATUS samba_path_matching_check_last_component(struct samba_path_matching *pm,
						  const char *name,
						  ssize_t *p_match_idx,
						  ssize_t *p_replace_start,
						  ssize_t *p_replace_end)
{
	struct samba_path_matching_result result = {
		.match = false,
		.replace_start = -1,
		.replace_end = -1,
	};
	ssize_t match_idx = -1;
	NTSTATUS status = NT_STATUS_OK;
	const char *last_component = NULL;
	size_t i;

	if (pm->num_entries == 0) {
		goto finish;
	}

	/* Get the last component of the unix name. */
	last_component = strrchr_m(name, '/');
	if (last_component == NULL) {
		last_component = name;
	} else {
		last_component++; /* Go past '/' */
	}

	for (i = 0; i < pm->num_entries; i++) {
		struct samba_path_matching_entry *e = &pm->entries[i];

		status = pm->matching_fn(pm, e, last_component, &result);
		if (!NT_STATUS_IS_OK(status)) {
			result = (struct samba_path_matching_result) {
				.match = false,
				.replace_start = -1,
				.replace_end = -1,
			};
			goto finish;
		}

		if (result.match) {
			match_idx = i;
			goto finish;
		}
	}

finish:
	*p_match_idx = match_idx;
	if (p_replace_start != NULL) {
		size_t last_ofs = 0;

		if (result.replace_start >= 0) {
			last_ofs = PTR_DIFF(last_component, name);
		}

		*p_replace_start = last_ofs + result.replace_start;
	}
	if (p_replace_end != NULL) {
		size_t last_ofs = 0;

		if (result.replace_end >= 0) {
			last_ofs = PTR_DIFF(last_component, name);
		}

		*p_replace_end = last_ofs + result.replace_end;
	}
	return status;
}
