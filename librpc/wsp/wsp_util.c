/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c) Noel Power
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "includes.h"
#include "librpc/wsp/wsp_util.h"
#include "librpc/gen_ndr/wsp.h"
#include "ndr.h"
const struct full_propset_info *get_propset_info_with_guid(
						const char *prop_name,
						struct GUID *propset_guid)
{
	size_t i;
	const struct full_guid_propset *guid_propset = NULL;
	const struct full_propset_info *result = NULL;
	for (i = 0; full_propertyset[i].prop_info != NULL; i++) {
		const struct full_propset_info *item = NULL;
		guid_propset = &full_propertyset[i];
		item = guid_propset->prop_info;
		while (item->id) {
			if (strequal(prop_name, item->name)) {
				*propset_guid = guid_propset->guid;
				result = item;
				break;
			}
			item++;
		}
		if (result) {
			break;
		}
	}
	return result;
}

const struct full_propset_info *get_prop_info(const char *prop_name)
{
	const struct full_propset_info *result = NULL;
	struct GUID guid;
	result = get_propset_info_with_guid(prop_name, &guid);
	return result;
}

char *prop_from_fullprop(TALLOC_CTX *ctx, struct wsp_cfullpropspec *fullprop)
{
	size_t i;
	char *result = NULL;
	const struct full_propset_info *item = NULL;
	bool search_by_id = (fullprop->ulkind == PRSPEC_PROPID);

	for (i = 0; full_propertyset[i].prop_info != NULL; i++) {
		/* find propset */
		if (GUID_equal(&fullprop->guidpropset,
			       &full_propertyset[i].guid)) {
			item = full_propertyset[i].prop_info;
			break;
		}
	}
	if (item) {
		while (item->id) {
			if (search_by_id) {
				if( fullprop->name_or_id.prspec == item->id) {
					result = talloc_strdup(ctx, item->name);
					break;
				}
			} else if (strcmp(item->name,
					fullprop->name_or_id.propname.vstring)
					== 0) {
				result = talloc_strdup(ctx, item->name);
				break;
			}
			item++;
		}
	}

	if (!result) {
		result = GUID_string(ctx, &fullprop->guidpropset);

		if (search_by_id) {
			result = talloc_asprintf(result, "%s/%d", result,
						 fullprop->name_or_id.prspec);
		} else {
			result = talloc_asprintf(result, "%s/%s", result,
					fullprop->name_or_id.propname.vstring);
		}
	}
	return result;
}

struct wsp_cfullpropspec *get_full_prop(struct wsp_crestriction *restriction)
{
	struct wsp_cfullpropspec *result;
	switch (restriction->ultype) {
		case RTPROPERTY:
			result = &restriction->restriction.cpropertyrestriction.property;
			break;
		case RTCONTENT:
			result = &restriction->restriction.ccontentrestriction.property;
			break;
		case RTNATLANGUAGE:
			result = &restriction->restriction.cnatlanguagerestriction.property;
			break;
		default:
			result = NULL;
			break;
	}
	return result;
}
