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
#include "librpc/gen_ndr/ndr_wsp.h"
#include "lib/util/strv_util.h"
#include "lib/util/strv.h"
#include "lib/util/util_str_hex.h"
#include "source3/param/param_proto.h"
#include "lib/util/dlinklist.h"

#define BUFFER_SIZE  1024000
struct guidtopropmap_holder
{
	struct guidtopropmap *guidtopropmaploc;
};

struct full_propset_info_list {
	struct full_propset_info_list *prev, *next;
	struct full_propset_info info;
};

struct guidtopropmap {
	struct guidtopropmap *prev, *next;
	struct GUID guid;
	struct full_propset_info_list *propset;
};

static struct guidtopropmap *find_guid_props(
		struct guidtopropmap_holder *holder,
		const struct GUID *guid)
{
	struct guidtopropmap *mapitem;
	for (mapitem = holder->guidtopropmaploc; mapitem; mapitem = mapitem->next) {
		if (GUID_equal(guid, &mapitem->guid)) {
			return mapitem;
		}
	}
	return NULL;
}

static bool getbool(char *str)
{
	char *cpy = talloc_strdup(NULL, str);
	bool result;

	trim_string(cpy, " ", " ");
	if (strequal("TRUE", cpy)) {
		result = true;
	} else {
		result = false;
	}
	TALLOC_FREE(cpy);
	return result;
}

struct {
	const char* typename;
	uint16_t type;
} vtype_map[]  = {
	{"GUID", VT_CLSID},
	{"String", VT_LPWSTR},
	{"BString", VT_BSTR},
	{"Double", VT_R8},
	{"Buffer", VT_BLOB_OBJECT},
	{"Byte", VT_UI1},
	{"UInt64", VT_UI8},
	{"Int64", VT_I8},
	{"UInt32", VT_UI4},
	{"Int32", VT_I4},
	{"UInt16", VT_UI2},
	{"Int16", VT_I2},
	{"DateTime", VT_FILETIME},
	{"Boolean", VT_BOOL}
};

static uint16_t getvtype(char *str, bool isvec)
{
	uint16_t result = UINT16_MAX;
	int i;
	for (i = 0; i < ARRAY_SIZE(vtype_map); i++) {
		if (strequal(vtype_map[i].typename, str)) {
			result = vtype_map[i].type;
			if (isvec) {
				result |= VT_VECTOR;
			}
			break;
		}
	}
	return result;
}

static bool parse_csv_line(TALLOC_CTX *ctx,
		char **csvs, size_t num_values,
		struct guidtopropmap_holder *propmap_holder)
{
	struct guidtopropmap *mapitem = NULL;
	struct full_propset_info_list *item = NULL;

	char *guid_str = NULL;
	struct GUID guid;
	bool ok;

	item = talloc_zero(ctx,
			struct full_propset_info_list);
	if (!item) {
		return false;
	}

	item->info.in_inverted_index = false;
	item->info.is_column = true;
	item->info.can_col_be_indexed = true;

	if (strlen(csvs[1])) {
		guid_str = talloc_strdup(ctx, csvs[1]);
	}

	if (!guid_str) {
		DBG_ERR("out of memory\n");
		return false;
	}

	if (!trim_string(guid_str, "{", "}")) {
		return false;
	}

	if (strlen(csvs[0])) {
		char *tmp = talloc_strdup(item, csvs[0]);
		trim_string(tmp, " ", " ");
		item->info.name = tmp;
	}

	if (strlen(csvs[2])) {
		item->info.id = atoi(csvs[2]);
	}

	if (strlen(csvs[3])) {
		item->info.in_inverted_index = getbool(csvs[3]);
	}

	if (strlen(csvs[4])) {
		item->info.is_column = getbool(csvs[4]);
	}

	if (strlen(csvs[5])) {
		item->info.can_col_be_indexed = getbool(csvs[5]);
	}

	if (strlen(csvs[6])) {
		bool isvec = false;
		uint16_t type;
		if (strlen(csvs[0])) {
			isvec = getbool(csvs[8]);
		}
		type = getvtype(csvs[6], isvec);
		if (type == UINT16_MAX) {
			DBG_ERR("failed to parse type\n");
			return false;
		}
		item->info.vtype = type;
	}

	ok = parse_guid_string(guid_str, &guid);
	if (!ok) {
		return false;
	}

	mapitem = find_guid_props(propmap_holder, &guid);
	if (!mapitem) {
		mapitem = talloc_zero(propmap_holder,
			struct guidtopropmap);
		if (!mapitem) {
			return false;
		}
		mapitem->guid = guid;
		DLIST_ADD_END(propmap_holder->guidtopropmaploc, mapitem);
	}

	talloc_steal(mapitem, item);
	DLIST_ADD_END(mapitem->propset, item);
	return true;
}

static bool parse_properties_line(TALLOC_CTX *ctx,
		const char* line,
		struct guidtopropmap_holder *propmap_holder)
{
	int ret;
	int pos;
	char* strv = NULL;
	char** csv_line = NULL;
	char* t = NULL;
	size_t len;

	ret = strv_split(ctx,
			&strv,
			line,
			",");

	if (ret != 0) {
		DBG_ERR("failed to split line\n");
		return false;
	}

	len = strv_count(strv);

	if (len < 9) {
		DBG_WARNING("skipping line as it doesn't have "
			    "enough fields\n");
		return true;
	}

	csv_line = talloc_zero_array(ctx,
			char *,
			len);

	if (!csv_line) {
		DBG_ERR("out of memory\n");
		return false;
	}
	for (pos = 0; pos < talloc_array_length(csv_line); pos++) {
		t = strv_next(strv, t);
		/* the scraped property file can have a non ascii char */
		if (strlen(t) == 1 && *t == 0xa0) {
			csv_line[pos] = talloc_strdup(csv_line,
					"");
		} else {
			csv_line[pos] = talloc_strdup(csv_line,
						t);
		}
		trim_string(csv_line[pos], " ", " ");
	}

	if (!parse_csv_line(csv_line, csv_line, len, propmap_holder)) {
		DBG_ERR("failed to parse line\n");
		TALLOC_FREE(csv_line);
		return false;
	}
	TALLOC_FREE(csv_line);
	return true;
}

static bool parse_properties_csvfile(TALLOC_CTX *ctx,
		struct guidtopropmap_holder *propmap_holder,
		const char* filename)
{
	char **lines = NULL;
	int numlines;
	int i;

	if (filename == NULL || strlen(filename) == 0) {
		return false;
	}

	lines = file_lines_load(filename,
			&numlines,
			BUFFER_SIZE,
			ctx);
	if (!lines) {
		DBG_ERR("Failed to load %s\n", filename);
		return false;
	}
	DBG_ERR("parsed %d lines\n", numlines);

	for (i = 0; i < numlines; i++) {
		TALLOC_CTX *line_ctx = talloc_init("line context");
		if (!line_ctx) {
			DBG_ERR("out of memory\n");
			return false;
		}

		trim_string(lines[i], " ", " ");
		if (lines[i][0] == '#') {
			DBG_WARNING("skipping comment at line %d.\n)", i);
			TALLOC_FREE(line_ctx);
			continue;
		}

		if (!parse_properties_line(line_ctx,
					lines[i],
					propmap_holder)) {
			DBG_ERR("Failed to parse line %d\n", i);
		}
		TALLOC_FREE(line_ctx);
	}
	return true;
}

static bool populate_map(struct guidtopropmap_holder *propmap_holder)
{
	const char * path = NULL;
	path = lp_wsp_property_file();

	/* first populate the map from property file */
	if (path) {
		parse_properties_csvfile(propmap_holder, propmap_holder, path);
	}

	return true;
}

static struct guidtopropmap_holder *propmap(void)
{
	static struct guidtopropmap_holder *holder = NULL;

	if (!holder) {
		holder = talloc_zero(NULL, struct guidtopropmap_holder);
		if (holder) {
			populate_map(holder);
		}
	}

	return holder;
}

const struct full_propset_info *get_propset_info_with_guid(
						const char *prop_name,
						struct GUID *propset_guid)
{
	const struct full_propset_info *result = NULL;
	struct guidtopropmap_holder *holder = NULL;
	struct guidtopropmap *mapitem = NULL;

	size_t i;
	const struct full_guid_propset *guid_propset = NULL;

	/* search builtin props first */
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

	if (result) {
		return result;
	}

	/* if we didn't find a match in builtin props try the extra props */
	holder = propmap();
	for (mapitem = holder->guidtopropmaploc; mapitem;
			mapitem = mapitem->next) {
		struct full_propset_info_list *propitem;
		for (propitem = mapitem->propset; propitem;
				propitem = propitem->next) {
			if (strequal(prop_name, propitem->info.name)) {
				*propset_guid = mapitem->guid;
				result = &propitem->info;
				break;
			}
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
	const struct full_propset_info_list *prop_item = NULL;
	bool search_by_id = (fullprop->ulkind == PRSPEC_PROPID);
	struct guidtopropmap_holder *holder = NULL;
	struct guidtopropmap *mapitem = NULL;

	/* check builtin properties */
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

	/* not found, search the extra props */
	if (!result) {
		holder = propmap();

		for (mapitem = holder->guidtopropmaploc; mapitem;
				mapitem = mapitem->next) {
			if (GUID_equal(&fullprop->guidpropset,
				       &mapitem->guid)) {
				prop_item = mapitem->propset;
				break;
			}
		}

		for (;prop_item; prop_item = prop_item->next) {
			if (search_by_id) {
				if(fullprop->name_or_id.prspec ==
						prop_item->info.id) {
					result = talloc_strdup(ctx,
							prop_item->info.name);
					break;
				}
			} else if (strcmp(prop_item->info.name,
				fullprop->name_or_id.propname.vstring) == 0) {
					result = talloc_strdup(ctx,
							prop_item->info.name);
					break;
			}
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
