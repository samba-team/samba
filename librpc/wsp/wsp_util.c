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
#include "lib/util/util_file.h"
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
		if (strlen(t) == 1 && *(unsigned char *)t == 0xa0) {
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

const char *genmeth_to_string(uint32_t genmethod)
{
	const char *result = NULL;
	switch (genmethod) {
		case 0:
			result = "equals";
			break;
		case 1:
			result = "starts with";
			break;
		case 2:
			result = "matches inflection";
			break;
		default:
			result = NULL;
			break;
	}
	return result;
}

bool is_operator(struct wsp_crestriction *restriction) {
	bool result;
	switch(restriction->ultype) {
		case RTAND:
		case RTOR:
		case RTNOT:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

const char *op_as_string(struct wsp_crestriction *restriction)
{
	const char *op = NULL;
	if (is_operator(restriction)) {
		switch(restriction->ultype) {
			case RTAND:
				op = " && ";
				break;
			case RTOR:
				op = " || ";
				break;
			case RTNOT:
				op = "!";
				break;
		}
	} else if (restriction->ultype == RTPROPERTY) {
		struct wsp_cpropertyrestriction *prop_restr =
			&restriction->restriction.cpropertyrestriction;
		switch (prop_restr->relop & 0XF) {
			case PREQ:
				op = "=";
				break;
			case PRNE:
				op = "!=";
				break;
			case PRGE:
				op = ">=";
				break;
			case PRLE:
				op = "<=";
				break;
			case PRLT:
				op = "<";
				break;
			case PRGT:
				op = ">";
				break;
			default:
				break;
		}
	} else if (restriction->ultype == RTCONTENT) {
		struct wsp_ccontentrestriction *content = NULL;
		content = &restriction->restriction.ccontentrestriction;
		op = genmeth_to_string(content->ulgeneratemethod);
	} else if (restriction->ultype == RTNATLANGUAGE) {
		op = "=";
	}
	return op;
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

const char *variant_as_string(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *value, bool quote)
{
	const char* result = NULL;
	switch(value->vtype) {
		case VT_UI1:
			result = talloc_asprintf(ctx, "%u",
						 value->vvalue.vt_ui1);
			break;
		case VT_INT:
		case VT_I4:
			result = talloc_asprintf(ctx, "%d",
						 value->vvalue.vt_i4);
			break;
		case VT_ERROR:
		case VT_UINT:
		case VT_UI4:
			result = talloc_asprintf(ctx, "%u",
						 value->vvalue.vt_ui4);
			break;
		case VT_UI2:
		case VT_I2:
			result = talloc_asprintf(ctx, "%u",
						 value->vvalue.vt_ui2);
			break;
		case VT_BOOL:
			result = talloc_asprintf(ctx, "%s",
					value->vvalue.vt_ui2 == 0xFFFF ?
						"true" : "false");
			break;
		case VT_DATE:
		case VT_FILETIME: {
			NTTIME filetime = value->vvalue.vt_ui8;
			time_t unixtime;
			struct tm *tm = NULL;
			char datestring[256];
			unixtime = nt_time_to_unix(filetime);
			tm = gmtime(&unixtime);
			strftime(datestring, sizeof(datestring), "%FT%TZ", tm);
			result = talloc_strdup(ctx, datestring);
			break;
		}
		case VT_R4: {
			float f;
			if (sizeof(f) != sizeof(value->vvalue.vt_ui4)) {
				DBG_ERR("can't convert float\n");
				break;
			}
			memcpy((void*)&f,
				(void*)&value->vvalue.vt_ui4,
				sizeof(value->vvalue.vt_ui4));
			result = talloc_asprintf(ctx, "%f",
						 f);
			break;
		}
		case VT_R8: {
			/* should this really be unsigned ? */
			double dval;
			if (sizeof(dval) != sizeof(value->vvalue.vt_i8)) {
				DBG_ERR("can't convert double\n");
				break;
			}
			memcpy((void*)&dval,
				(void*)&value->vvalue.vt_i8,
				sizeof(dval));
			result = talloc_asprintf(ctx, "%f",
						 dval);
			break;
		}
		case VT_I8: {
			result = talloc_asprintf(ctx, "%" PRIi64,
						 value->vvalue.vt_i8);
			break;
		}
		case VT_UI8: {
			result = talloc_asprintf(ctx, "%" PRIu64,
						 value->vvalue.vt_ui8);
			break;
		}
		case VT_LPWSTR:
			result = talloc_asprintf(ctx, "%s%s%s",
						quote ? "\'" : "",
						value->vvalue.vt_lpwstr.value,
						quote ? "\'" : "");
			break;
		case VT_LPWSTR | VT_VECTOR: {
			int num_elems =
			value->vvalue.vt_lpwstr_v.vvector_elements;
			int i;
			for(i = 0; i < num_elems; i++) {
				struct vt_lpwstr_vec *vec;
				const char *val;
				vec = &value->vvalue.vt_lpwstr_v;
				val = vec->vvector_data[i].value;
				result =
					talloc_asprintf(ctx,
							"%s%s%s%s%s",
							result ? result : "",
							i ? "," : "",
							quote ? "\'" : "",
							val,
							quote ? "\'" : "");
			}
			break;
		}
		default:
			DBG_INFO("can't represent unsupported vtype 0x%x as string\n",
				value->vtype);
			break;
	}
	return result;
}

static const struct {
	uint32_t id;
	const char *name;
} typename_map[] = {
	{VT_EMPTY, "Empty"},
	{VT_NULL, "Null"},
	{VT_I2, "VT_I2"},
	{VT_I4, "VT_I4"},
	{VT_I4, "VT_I4"},
	{VT_R4, "VT_R4"},
	{VT_R8, "VT_R8"},
	{VT_CY, "VT_CY"},
	{VT_DATE, "VT_DATE"},
	{VT_BSTR, "VT_BSTR"},
	{VT_I1, "VT_I1"},
	{VT_UI1, "VT_UI1"},
	{VT_UI2, "VT_UI2"},
	{VT_UI4, "VT_UI4"},
	{VT_I8, "VT_I8"},
	{VT_UI8, "VT_UI8"},
	{VT_INT, "VT_INT"},
	{VT_UINT, "VT_UINT"},
	{VT_ERROR, "VT_ERROR"},
	{VT_BOOL, "VT_BOOL"},
	{VT_VARIANT, "VT_VARIANT"},
	{VT_DECIMAL, "VT_DECIMAL"},
	{VT_FILETIME, "VT_FILETIME"},
	{VT_BLOB, "VT_BLOB"},
	{VT_BLOB_OBJECT, "VT_BLOB_OBJECT"},
	{VT_CLSID, "VT_CLSID"},
	{VT_LPSTR, "VT_LPSTR"},
	{VT_LPWSTR, "VT_LPWSTR"},
	{VT_COMPRESSED_LPWSTR, "VT_COMPRESSED_LPWSTR"},
};

const char *get_vtype_name(uint32_t type)
{
	const char *type_name = NULL;
	static char result_buf[255];
	int i;
	uint32_t temp = type & ~(VT_VECTOR | VT_ARRAY);
	for (i = 0; i < ARRAY_SIZE(typename_map); i++) {
		if (temp == typename_map[i].id) {
			type_name = typename_map[i].name;
			break;
		}
	}
	if (type & VT_VECTOR) {
		snprintf(result_buf, sizeof(result_buf), "Vector | %s", type_name);
	} else if (type & VT_ARRAY) {
		snprintf(result_buf, sizeof(result_buf), "Array | %s", type_name);
	} else {
		snprintf(result_buf, sizeof(result_buf), "%s", type_name);
	}
	return result_buf;
}

bool is_variable_size(uint16_t vtype)
{
	bool result;
	switch(vtype) {
		case VT_LPWSTR:
		case VT_COMPRESSED_LPWSTR:
		case VT_BSTR:
		case VT_BLOB:
		case VT_BLOB_OBJECT:
		case VT_VARIANT:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

const char *get_store_status(uint8_t status_byte)
{
	const char *result;
	switch(status_byte) {
		case 0:
			result = "StoreStatusOk";
			break;
		case 1:
			result = "StoreStatusDeferred";
			break;
		case 2:
			result = "StoreStatusNull";
			break;
		default:
			result = "Unknown Status";
			break;
	}
	return result;
}

void set_variant_lpwstr(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *vvalue,
			const char *string_val)
{
	vvalue->vtype = VT_LPWSTR;
	vvalue->vvalue.vt_lpwstr.value = talloc_strdup(ctx, string_val);
}

void set_variant_i4(TALLOC_CTX *ctx,
		    struct wsp_cbasestoragevariant *vvalue,
		    uint32_t val)
{
	vvalue->vtype = VT_I4;
	vvalue->vvalue.vt_i4 = val;
}

void set_variant_vt_bool(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *variant,
			bool bval)
{
	variant->vtype = VT_BOOL;
	variant->vvalue.vt_bool = bval;
}

static void fill_int32_vec(TALLOC_CTX* ctx,
			    int32_t **pdest,
			    int32_t* ivector, uint32_t elems)
{
	int i;
	int32_t *dest = talloc_zero_array(ctx, int32_t, elems);
	for ( i = 0; i < elems; i++ ) {
		dest[ i ] = ivector[ i ];
	}
	*pdest = dest;
}

void set_variant_i4_vector(TALLOC_CTX *ctx,
			   struct wsp_cbasestoragevariant *variant,
			   int32_t* ivector, uint32_t elems)
{
	variant->vtype = VT_VECTOR | VT_I4;
	variant->vvalue.vt_i4_vec.vvector_elements = elems;
	fill_int32_vec(ctx, &variant->vvalue.vt_i4_vec.vvector_data, ivector, elems);
}

static void fill_string_vec(TALLOC_CTX* ctx,
				struct wsp_cbasestoragevariant *variant,
				const char **strings, uint16_t elems)
{
	int i;
	variant->vvalue.vt_lpwstr_v.vvector_elements = elems;
	variant->vvalue.vt_lpwstr_v.vvector_data = talloc_zero_array(ctx,
							struct vt_lpwstr,
							elems);

	for( i = 0; i < elems; i++ ) {
		variant->vvalue.vt_lpwstr_v.vvector_data[ i ].value = talloc_strdup(ctx, strings[ i ]);
	}
}

static void fill_bstr_vec(TALLOC_CTX *ctx,
		  struct vt_bstr **pvector,
		  const char **strings, uint16_t elems)
{
	int i;
	struct vt_bstr *vdata = talloc_zero_array(ctx, struct vt_bstr, elems);

	for( i = 0; i < elems; i++ ) {
		vdata [ i ].value = talloc_strdup(ctx, strings[ i ]);
	}
	*pvector = vdata;
}

void set_variant_bstr(TALLOC_CTX *ctx, struct wsp_cbasestoragevariant *variant,
			const char *string_val)
{
	variant->vtype = VT_BSTR;
	variant->vvalue.vt_bstr.value = talloc_strdup(ctx, string_val);
}

void set_variant_lpwstr_vector(TALLOC_CTX *ctx,
                              struct wsp_cbasestoragevariant *variant,
                              const char **string_vals, uint32_t elems)
{
        variant->vtype = VT_LPWSTR | VT_VECTOR;
        fill_string_vec(ctx, variant, string_vals, elems);
}

void set_variant_array_bstr(TALLOC_CTX *ctx,
			   struct wsp_cbasestoragevariant *variant,
			   const char **string_vals, uint16_t elems)
{
	variant->vtype = VT_BSTR | VT_ARRAY;
	variant->vvalue.vt_bstr_array.cdims = 1;
	variant->vvalue.vt_bstr_array.ffeatures = 0;

	variant->vvalue.vt_bstr_array.rgsabound =
		talloc_zero_array(ctx, struct safearraybound, 1);

	variant->vvalue.vt_bstr_array.rgsabound[0].celements = elems;
	variant->vvalue.vt_bstr_array.rgsabound[0].ilbound = 0;
	variant->vvalue.vt_bstr_array.cbelements = 0;
	fill_bstr_vec(ctx, &variant->vvalue.vt_bstr_array.vdata,
		      string_vals, elems);
	/*
	 * if cbelements is the num bytes per elem it kindof means each
	 * string in the array must be the same size ?
	 */

	if (elems >0) {
		variant->vvalue.vt_bstr_array.cbelements =
			strlen_m_term(variant->vvalue.vt_bstr_array.vdata[0].value)*2;
	}
}

/* create single dim array of vt_i4 */
void set_variant_array_i4(TALLOC_CTX *ctx,
			 struct wsp_cbasestoragevariant *variant,
			 int32_t *vals, uint16_t elems)
{
	/* #TODO see if we can combine with other set_variant_array methods */
	variant->vtype = VT_I4 | VT_ARRAY;
	variant->vvalue.vt_i4_array.cdims = 1;
	variant->vvalue.vt_i4_array.ffeatures = 0;

	variant->vvalue.vt_i4_array.rgsabound =
		talloc_zero_array(ctx, struct safearraybound, 1);

	variant->vvalue.vt_i4_array.rgsabound[0].celements = elems;
	variant->vvalue.vt_i4_array.rgsabound[0].ilbound = 0;
	variant->vvalue.vt_i4_array.cbelements = sizeof(uint32_t);
	fill_int32_vec(ctx, &variant->vvalue.vt_i4_array.vdata, vals, elems);
}
