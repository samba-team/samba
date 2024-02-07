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
#include "libcli/security/security.h"
#include "source3/lib/substitute.h"
#include "passdb/lookup_sid.h"
#include "auth.h"

/*
 * No prefix means direct username
 * @name means netgroup first, then unix group
 * &name means netgroup
 * +name means unix group
 * + and & may be combined
 */

static bool do_group_checks(const char **name, const char **pattern)
{
	if ((*name)[0] == '@') {
		*pattern = "&+";
		*name += 1;
		return True;
	}

	if (((*name)[0] == '+') && ((*name)[1] == '&')) {
		*pattern = "+&";
		*name += 2;
		return True;
	}

	if ((*name)[0] == '+') {
		*pattern = "+";
		*name += 1;
		return True;
	}

	if (((*name)[0] == '&') && ((*name)[1] == '+')) {
		*pattern = "&+";
		*name += 2;
		return True;
	}

	if ((*name)[0] == '&') {
		*pattern = "&";
		*name += 1;
		return True;
	}

	return False;
}

bool token_contains_name(TALLOC_CTX *mem_ctx,
			 const char *username,
			 const char *domain,
			 const char *sharename,
			 const struct security_token *token,
			 const char *name,
			 bool *match)
{
	const char *prefix;
	struct dom_sid sid;
	enum lsa_SidType type;
	NTSTATUS status;

	*match = false;

	if (username != NULL) {
		size_t domain_len = domain != NULL ? strlen(domain) : 0;

		/* Check if username starts with domain name */
		if (domain_len > 0) {
			const char *sep = lp_winbind_separator();
			int cmp = strncasecmp_m(username, domain, domain_len);
			if (cmp == 0 && sep[0] == username[domain_len]) {
				/* Move after the winbind separator */
				domain_len += 1;
			} else {
				domain_len = 0;
			}
		}
		name = talloc_sub_basic(mem_ctx,
					username + domain_len,
					domain,
					name);
	}
	if (sharename != NULL) {
		name = talloc_string_sub(mem_ctx, name, "%S", sharename);
	}

	if (name == NULL) {
		return false;
	}

	if ( string_to_sid( &sid, name ) ) {
		DEBUG(5,("token_contains_name: Checking for SID [%s] in token\n", name));
		*match = nt_token_check_sid( &sid, token );
		return true;
	}

	if (!do_group_checks(&name, &prefix)) {
		status = lookup_name_smbconf_ex(mem_ctx,
						name,
						LOOKUP_NAME_ALL,
						NULL,
						NULL,
						&sid,
						&type);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("lookup_name '%s' failed %s\n",
				name, nt_errstr(status));
			return false;
		}
		if (type != SID_NAME_USER) {
			DBG_WARNING("%s is a %s, expected a user\n",
				    name, sid_type_lookup(type));
			return true;
		}
		*match = nt_token_check_sid(&sid, token);
		return true;
	}

	for (/* initialized above */ ; *prefix != '\0'; prefix++) {
		if (*prefix == '+') {
			status = lookup_name_smbconf_ex(
					mem_ctx,
					name,
					LOOKUP_NAME_ALL|LOOKUP_NAME_GROUP,
					NULL,
					NULL,
					&sid,
					&type);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("lookup_name '%s' failed %s\n",
					name, nt_errstr(status));
				return false;
			}
			if ((type != SID_NAME_DOM_GRP) &&
			    (type != SID_NAME_ALIAS) &&
			    (type != SID_NAME_WKN_GRP)) {
				DBG_WARNING("%s is a %s, expected a group\n",
					    name, sid_type_lookup(type));
				return true;
			}
			if (nt_token_check_sid(&sid, token)) {
				*match = true;
				return True;
			}
			continue;
		}
		if (*prefix == '&') {
			if (username) {
				if (user_in_netgroup(mem_ctx, username, name)) {
					*match = true;
					return True;
				}
			}
			continue;
		}
		smb_panic("got invalid prefix from do_groups_check");
	}
	return true;
}

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

bool set_namearray(TALLOC_CTX *mem_ctx,
		   const char *namelist_in,
		   const struct security_token *token,
		   struct name_compare_entry **_name_array)
{
	struct name_compare_entry *name_array = NULL;
	struct name_compare_entry *e = NULL;
	char *namelist = NULL;
	const char *p = NULL;
	size_t num_entries;
	bool ok;

	*_name_array = NULL;

	if ((namelist_in == NULL) || (namelist_in[0] == '\0')) {
		return true;
	}

	namelist = path_to_strv(mem_ctx, namelist_in);
	if (namelist == NULL) {
		DBG_ERR("path_to_strv failed\n");
		return false;
	}

	num_entries = strv_count(namelist);

	name_array = talloc_zero_array(mem_ctx,
				       struct name_compare_entry,
				       num_entries + 1);
	if (name_array == NULL) {
		DBG_ERR("talloc failed\n");
		TALLOC_FREE(namelist);
		return false;
	}

	namelist = talloc_reparent(mem_ctx, name_array, namelist);

	e = &name_array[0];

	while ((p = strv_next(namelist, p)) != NULL) {
		if (*p == '\0') {
			/* cope with multiple (useless) /s) */
			continue;
		}

		if (ISDOTDOT(p) && token != NULL) {
			const char *username = NULL;
			bool match;

			/* Get the username */
			p = strv_next(namelist, p);
			if (p == NULL) {
				DBG_ERR("Missing username\n");
				TALLOC_FREE(namelist);
				return false;
			}
			username = p;

			/* Get the filename */
			p = strv_next(namelist, p);
			if (p == NULL) {
				DBG_ERR("Missing filename after username '%s'\n",
					username);
				TALLOC_FREE(namelist);
				return false;
			}

			ok = token_contains_name(talloc_tos(),
						 NULL,
						 NULL,
						 NULL,
						 token,
						 username,
						 &match);
			if (!ok) {
				TALLOC_FREE(namelist);
				return false;
			}
			if (!match) {
				continue;
			}
		}

		e->name = p;
		e->is_wild = ms_has_wild(e->name);
		e++;
	}

	*_name_array = name_array;
	return true;
}
