/*
 * Samba Unix/Linux SMB client library
 * Json output
 * Copyright (C) Jule Anger 2022
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include "smbprofile.h"
#include "status_json.h"
#include "../libcli/security/security.h"
#include "status.h"

#include <jansson.h>
#include "audit_logging.h" /* various JSON helpers */
#include "auth/common_auth.h"

int add_general_information_to_json(struct traverse_state *state)
{
	int result;

	result = json_add_timestamp(&state->root_json);
	if (result < 0) {
		return -1;
	}

	result = json_add_string(&state->root_json, "version", samba_version_string());
	if (result < 0) {
		return -1;
	}

	result = json_add_string(&state->root_json, "smb_conf", get_dyn_CONFIGFILE());
	if (result < 0) {
		return -1;
	}

	return 0;
}

int add_section_to_json(struct traverse_state *state,
			const char *key)
{
	struct json_object empty_json;
	int result;

	empty_json = json_new_object();
	if (json_is_invalid(&empty_json)) {
		return -1;
	}

	result = json_add_object(&state->root_json, key, &empty_json);
	if (result < 0) {
		return -1;
	}

	return result;
}
