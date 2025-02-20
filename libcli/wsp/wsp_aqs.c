/*
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
#include "libcli/wsp/wsp_aqs.h"
#include "libcli/wsp/wsp_aqs_parser.tab.h"
#include "libcli/wsp/wsp_aqs_lexer.h"
#include "librpc/wsp/wsp_util.h"
#include "librpc/gen_ndr/ndr_wsp.h"
#include <stdio.h>
#include <stdbool.h>

int yyparse(t_select_stmt **select, yyscan_t scanner);

static void reverse_cols(t_select_stmt *select)
{
	int num_elems, fwd, rev;
	char **cols;


	if (!select->cols) {
		return;
	}
	num_elems = select->cols->num_cols;
	cols =  select->cols->cols;

	for(fwd = 0, rev = num_elems - 1; fwd <= rev; fwd++, rev--) {
		char * tmp = cols[rev];
		cols[rev] = cols[fwd];
		cols[fwd] = tmp;
	}

}

t_select_stmt *get_wsp_sql_tree(const char *expr)
{
	t_select_stmt *select = NULL;
	yyscan_t scanner;
	YY_BUFFER_STATE state;

	if (yylex_init(&scanner)) {
		DBG_ERR("couldn't initialize\n");
		return NULL;
	}

	state = yy_scan_string(expr, scanner);

	if (yyparse(&select, scanner)) {
		DBG_ERR("some parse error\n");
		return NULL;
	}
	/*
	 * parsed columns are in reverse order to how they are specified
	 * in the AQS like statement, reverse them again to correct this.
	 */
	reverse_cols(select);

	yy_delete_buffer(state, scanner);

	yylex_destroy(scanner);

	return select;
}


t_col_list *create_cols(TALLOC_CTX *ctx, const char *col, t_col_list *append_list)
{
	t_col_list *cols = append_list;
	if (!get_prop_info(col)) {
		DBG_ERR("Unknown property %s\n", col);
		return NULL;
	}
	if (cols == NULL) {
		cols = talloc_zero(ctx, t_col_list);
		if (cols == NULL) {
			DBG_ERR("out of memory\n");
			return NULL;
		}
		cols->num_cols = 0;
		cols->cols = NULL;
		DBG_INFO("returning new cols %p with item %s\n", cols, col);
	}
	if (col) {
		int old_index = cols->num_cols;
		if (old_index == 0) {
			cols->cols = talloc_array(cols, char*, 1);
		} else {
			cols->cols = (char **)talloc_realloc(cols, cols->cols, char*, old_index + 1);
		}
		if (!cols->cols) {
			return NULL; /* can we create a parser error here */
		}
		cols->num_cols++;
		cols->cols[old_index] = talloc_strdup(cols, col);
		if (cols->cols[old_index] == NULL) {
			DBG_ERR("out of memory\n");
			return NULL;
		}

	}
	return cols;
}

t_select_stmt *create_select(TALLOC_CTX *ctx, t_col_list *cols, t_query *where)
{
	t_select_stmt *result = talloc_zero(ctx, t_select_stmt);
	if (result == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}
	result->cols = cols;
	result->where = where;
	return result;
}

t_basic_restr *create_basic_restr(TALLOC_CTX *ctx,
			uint32_t prop_type,
			t_optype op,
			t_value_holder *values)
{
	t_basic_restr *result = talloc_zero(ctx, t_basic_restr);
	if (result == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}
	result->prop_type = prop_type;
	result->op = op;
	if (values->type == VALUE_RANGE) {
		t_restr *left_node;
		t_restr *right_node;
		t_basic_restr *left_val;
		t_basic_restr *right_val;
		if (op != eEQ) {
			DBG_ERR("Unsupported operation %d\n", op);
			TALLOC_FREE(result);
			goto out;
		}

		if (values->value.value_range->lower == NULL) {
			DBG_ERR("range lower limit doesn't exist\n");
			TALLOC_FREE(result);
			goto out;
		}
		/*
		 * detect special case where upper range doesn't exist
		 * and convert to a property value. (this won't happen from
		 * the cmdline directly but only as a result of a range
		 * created 'specially' in code, e.g. special gigantic size
		 * range.
		 */
		if (values->value.value_range->upper == NULL) {
			result->op = eGE;
			result->values = values->value.value_range->lower;
			goto out;
		}
		result->values = talloc_zero(result, t_value_holder);
		if (result->values == NULL) {
			DBG_ERR("out of memory\n");
			TALLOC_FREE(result);
			goto out;
		}
		/*
		 * try create a restriction tree (>=lower AND <upper) to
		 * represent the range
		 */
		left_val = create_basic_restr(result->values,
					prop_type,
					eGE,
					values->value.value_range->lower);

		right_val = create_basic_restr(result->values,
					prop_type,
					eLT,
					values->value.value_range->upper);

		if (!left_val || !right_val) {
			DBG_ERR("Failed creating basic_restriction values "
				"for range\n");
			TALLOC_FREE(result);
			goto out;
		}

		left_node = create_restr(result->values, eVALUE, NULL, NULL, left_val);
		right_node = create_restr(result->values, eVALUE, NULL, NULL, right_val);


		if (!left_node || !right_node) {
			DBG_ERR("Failed creating restr nodes for range\n");
			TALLOC_FREE(result);
			goto out;
		}
		result->values->type = RESTR;
		result->values->value.restr_tree = create_restr(result->values,
							eAND,
							left_node,
							right_node,
							NULL);
		if (!result->values->value.restr_tree) {
			DBG_ERR("Failed creating restr tree for range\n");
			TALLOC_FREE(result);
			goto out;
		}
	} else {
		result->values = values;
	}
out:
	return result;
}

/*
 * The parser reads numbers as VT_UI8, booleans as VT_BOOL and strings as
 * VT_LPWSTR
 */
typedef bool (*conv_func) (TALLOC_CTX *ctx, t_value_holder *src,
			   struct wsp_cbasestoragevariant *dest,
			   uint16_t dest_type);

/*
 * default converter #TODO probably should cater for detecting over/underrun
 * depending on the dest_type we are narrowing to
 */
static bool default_convertor(TALLOC_CTX *ctx,
			t_value_holder *src,
			struct wsp_cbasestoragevariant *dest,
			uint16_t dest_type)
{
	if (src->type != NUMBER) {
		return false;
	}
	dest->vvalue.vt_ui8 = src->value.number;
	dest->vtype = dest_type;
	return true;
}

static bool convert_string_to_lpwstr_v(TALLOC_CTX *ctx,
			t_value_holder *src,
			struct wsp_cbasestoragevariant *dest,
			uint16_t dest_type)
{
	const char *str = src->value.string;
	set_variant_lpwstr_vector(ctx, dest, &str, 1);
	return true;
}

static bool convert_string_to_lpwstr(TALLOC_CTX *ctx,
			t_value_holder *src,
			struct wsp_cbasestoragevariant *dest,
			uint16_t dest_type)
{
	const char *str = src->value.string;
	set_variant_lpwstr(ctx, dest, str);
	return true;
}

static bool convert_bool_to_lpwstr(TALLOC_CTX *ctx,
			t_value_holder *src,
			struct wsp_cbasestoragevariant *dest,
			uint16_t dest_type)
{
	set_variant_lpwstr(
			ctx,
			dest,
			src->value.boolean ? "true": "false");
	return true;
}

static bool convert_string_to_filetime(TALLOC_CTX *ctx,
			t_value_holder *src,
			struct wsp_cbasestoragevariant *dest,
			uint16_t dest_type)
{

	static const char *fmts[] = {
		"%FT%TZ",
		"%FT%T",
		"%F %T",
		"%F %R",
		"%F",
	};
	struct tm tm;
	time_t timeval = 0;
	int i;
	ZERO_STRUCT(tm);

	for (i = 0; i < ARRAY_SIZE(fmts); i++) {
		if (strptime(src->value.string, fmts[i], &tm)) {
			timeval = timegm(&tm);
			break;
		}
	}

	if (timeval) {
		NTTIME nt;
		unix_to_nt_time(&nt, timeval);
		dest->vtype = VT_FILETIME;
		dest->vvalue.vt_filetime = nt;
		return true;
	}
	return false;
}

const struct {
	uint16_t src_vtype;
	uint16_t dest_vtype;
	conv_func convert_type;
} type_conv_map[] = {
	{NUMBER, VT_I8, default_convertor},
	{NUMBER, VT_UI8, default_convertor},
	{NUMBER, VT_INT, default_convertor},
	{NUMBER, VT_UINT, default_convertor},
	{NUMBER, VT_I4, default_convertor},
	{NUMBER, VT_UI4, default_convertor},
	{NUMBER, VT_I2, default_convertor},
	{NUMBER, VT_UI2, default_convertor},
	{NUMBER, VT_BOOL, default_convertor},
	{NUMBER, VT_FILETIME, default_convertor},
	{NUMBER, VT_BOOL, default_convertor},
	{BOOL, VT_LPWSTR, convert_bool_to_lpwstr},
	{STRING, VT_LPWSTR, convert_string_to_lpwstr},
	{STRING, VT_LPWSTR | VT_VECTOR, convert_string_to_lpwstr_v},
	{STRING, VT_FILETIME, convert_string_to_filetime},
};

static bool process_prop_value(TALLOC_CTX *ctx,
			const struct full_propset_info *prop_info,
			t_value_holder *node_value,
			struct wsp_cbasestoragevariant *prop_value)
{
	int i;

	/* coerce type as required */
	for (i = 0; i < ARRAY_SIZE(type_conv_map); i++ ) {
		if (type_conv_map[i].src_vtype == node_value->type &&
		    type_conv_map[i].dest_vtype == prop_info->vtype) {
			type_conv_map[i].convert_type(ctx,
						      node_value,
						      prop_value,
						      prop_info->vtype);
			return true;
		}
	}
	return false;
}

t_basic_query *create_basic_query(TALLOC_CTX *ctx, const char *propname, t_basic_restr *restr)
{
	t_basic_query *result = talloc_zero(ctx, t_basic_query);
	if (result == NULL) {
		DBG_ERR("out of memory\n");
		goto out;
	}
	result->prop = talloc_strdup(result, propname);
	result->prop_info = get_propset_info_with_guid(propname, &result->guid);

	if (!result->prop_info) {
		DBG_ERR("Unknown property %s\n",propname);
		TALLOC_FREE(result);
		goto out;
	}
	result->basic_restriction = restr;
out:
	return result;
}

static struct wsp_crestriction *create_restriction(TALLOC_CTX *ctx,
						   t_basic_query *query)
{
	struct wsp_crestriction *crestriction = NULL;
	struct wsp_cfullpropspec *prop = NULL;
	t_basic_restr *restr = NULL;
	t_value_holder *src = NULL;
	crestriction = talloc_zero(ctx, struct wsp_crestriction);
	if (crestriction == NULL) {
		DBG_ERR("out of memory\n");
		goto done;
	}

	restr = query->basic_restriction;
	src = restr->values;

	if (restr->prop_type == RTNONE) {
		/* shouldn't end up here */
		DBG_ERR("Unexpected t_basic_restr type\n");
		TALLOC_FREE(crestriction);
		goto done;
	}

	crestriction->weight = 1000;

	if (restr->prop_type == RTCONTENT) {
		struct wsp_ccontentrestriction *content = NULL;
		crestriction->ultype = RTCONTENT;
		if (src->type != STRING) {
			DBG_ERR("expected string value for %s\n",
				query->prop);
			TALLOC_FREE(crestriction);
			goto done;
		}
		content = &crestriction->restriction.ccontentrestriction;
		content->pwcsphrase = src->value.string;
		content->cc = strlen(src->value.string);
		/*
		 * In the future we might generate the lcid from
		 * environ (or config)
		 */
		content->lcid = WSP_DEFAULT_LCID;
		if (restr->op == eEQUALS) {
			content->ulgeneratemethod = 0;
		} else {
			content->ulgeneratemethod = 1;
		}

		prop = &content->property;
	} else if (restr->prop_type == RTPROPERTY) {
		struct wsp_cbasestoragevariant *dest =
			&crestriction->restriction.cpropertyrestriction.prval;
		crestriction->ultype = RTPROPERTY;
		if (!process_prop_value(ctx, query->prop_info, src, dest)) {
			DBG_ERR("Failed to process value for property %s\n",
				query->prop);
			TALLOC_FREE(crestriction);
			goto done;
		}
		crestriction->restriction.cpropertyrestriction.relop =
								restr->op;
		prop = &crestriction->restriction.cpropertyrestriction.property;
	} else {
		TALLOC_FREE(crestriction);
		goto done;
	}
	prop->guidpropset = query->guid;
	prop->ulkind = PRSPEC_PROPID;
	prop->name_or_id.prspec = query->prop_info->id;
done:
	return crestriction;
}

/* expands restr_node into a tree of t_query nodes */
static void build_query(TALLOC_CTX *ctx, t_query *node, t_restr *restr_node,
			    const char* prop)
{
	if (!node) {
		return;
	}
	if (!restr_node) {
		return;
	}

	node->type = restr_node->type;

	if (restr_node->left) {
		node->left = talloc_zero(ctx, t_query);
		SMB_ASSERT(node->left != NULL);
		build_query(ctx, node->left, restr_node->left, prop);
	}

	if (restr_node->right) {
		node->right = talloc_zero(ctx, t_query);
		SMB_ASSERT(node->right != NULL);
		build_query(ctx, node->right, restr_node->right, prop);
	}

	if (restr_node->type == eVALUE) {
		node->restriction =
			create_restriction(ctx,
				create_basic_query(ctx,
						   prop,
						   restr_node->basic_restr));
	}
}

t_query *create_query_node(TALLOC_CTX *ctx, t_nodetype op, t_query *left, t_query *right, t_basic_query *value)
{
	t_query *result = talloc_zero(ctx, t_query);
	if (result == NULL) {
		return result;
	}
	result->type = op;
	result->left = left;
	result->right = right;
	if (op == eVALUE) {
		t_basic_restr *restr = value->basic_restriction;
		/* expand restr node */
		if (restr->values->type == RESTR) {
			build_query(ctx,
				    result,
				    restr->values->value.restr_tree,
				    value->prop);
		} else {
			result->restriction =
				create_restriction(ctx, value);
			if (!result->restriction) {
				TALLOC_FREE(result);
			}
		}
	}
	return result;
}

t_restr *create_restr(TALLOC_CTX *ctx, t_nodetype op, t_restr *left, t_restr *right, t_basic_restr *value)
{
	t_restr *result = talloc_zero(ctx, t_restr);
	if (result == NULL) {
		return result;
	}
	result->type = op;
	result->right = right;
	result->left = left;
	result->basic_restr = value;
	return result;
}

t_value_holder *create_string_val(TALLOC_CTX* ctx, const char *text)
{
	t_value_holder *result =
		talloc_zero(ctx, t_value_holder);
	if (result == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}
	result->value.string = text;
	result->type = STRING;
	return result;
}

t_value_holder *create_num_val(TALLOC_CTX* ctx, int64_t val)
{
	t_value_holder *result =
		talloc_zero(ctx, t_value_holder);

	if (result == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	result->type = NUMBER;
	result->value.number = val;
	return result;
}

t_value_holder *create_bool_val(TALLOC_CTX* ctx, bool val)
{
	t_value_holder *result =
		talloc_zero(ctx, t_value_holder);

	if (result == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	result->type = BOOL;
	result->value.boolean = val;
	return result;
}

t_value_holder *create_value_range(TALLOC_CTX* ctx,
				   t_value_holder *left,
				   t_value_holder *right)
{
	t_value_holder *result =
		talloc_zero(ctx, t_value_holder);

	if (result == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	result->type = VALUE_RANGE;
	result->value.value_range = talloc_zero(result, struct value_range);
	if (!result->value.value_range) {
		TALLOC_FREE(result);
		goto out;
	}
	result->value.value_range->lower = left;
	result->value.value_range->upper = right;
out:
	return result;
}

static void zero_time(struct tm *tm)
{
	tm->tm_hour = 0;
	tm->tm_min = 0;
	tm->tm_sec = 0;
}

typedef bool (*daterange_func) (TALLOC_CTX *ctx, uint64_t *date1,
				uint64_t *date2);


static bool create_date_range(TALLOC_CTX *ctx, uint64_t *date1,
				uint64_t *date2,
				int32_t lower_mday_adj,
				int32_t lower_mon_adj,
				int32_t upper_mday_adj,
				int32_t upper_mon_adj)
{
	struct tm tm_now;
	time_t now;

	struct tm tm_tmp;
	time_t lower;
	time_t upper;

	time(&now);
	gmtime_r(&now, &tm_now);

	tm_tmp = tm_now;
	zero_time(&tm_tmp);
	tm_tmp.tm_mday += lower_mday_adj;
	tm_tmp.tm_mon += lower_mon_adj;
	lower = mktime(&tm_tmp);
	tm_tmp = tm_now;
	zero_time(&tm_tmp);
	tm_tmp.tm_mday += upper_mday_adj;
	tm_tmp.tm_mon += upper_mon_adj;
	upper = mktime(&tm_tmp);
	unix_to_nt_time(date1, lower);
	unix_to_nt_time(date2, upper);
	return true;
}

static void get_now_tm(struct tm *tm_now)
{
	time_t now;
	time(&now);
	gmtime_r(&now, tm_now);
}

static bool create_thismonth_range(TALLOC_CTX *ctx, uint64_t *date1,
				uint64_t *date2)
{
	struct tm tm_now;
	int32_t firstofmonth_adj;

	get_now_tm(&tm_now);
	firstofmonth_adj =  1 - tm_now.tm_mday;
	return create_date_range(ctx, date1,
				date2, firstofmonth_adj,
				0, firstofmonth_adj, 1);
}

static bool create_lastyear_range(TALLOC_CTX *ctx, uint64_t *date1,
				uint64_t *date2)
{
	struct tm tm_now;
	int32_t firstofmonth_adj;
	int32_t january_adj;
	get_now_tm(&tm_now);

	firstofmonth_adj =  1 - tm_now.tm_mday;
	january_adj = -tm_now.tm_mon;
	return create_date_range(ctx, date1,
				date2, firstofmonth_adj,
				january_adj - 12, firstofmonth_adj, january_adj);
}

static bool create_thisyear_range(TALLOC_CTX *ctx, uint64_t *date1,
				uint64_t *date2)
{
	struct tm tm_now;
	int32_t firstofmonth_adj;
	int32_t january_adj;

	get_now_tm(&tm_now);

	firstofmonth_adj =  1 - tm_now.tm_mday;
	january_adj = -tm_now.tm_mon;
	return create_date_range(ctx, date1,
				date2, firstofmonth_adj,
				january_adj, firstofmonth_adj, january_adj + 12);
}

static bool create_lastmonth_range(TALLOC_CTX *ctx, uint64_t *date1,
				uint64_t *date2)
{
	struct tm tm_now;
	int32_t firstofmonth_adj;
	get_now_tm(&tm_now);

	firstofmonth_adj =  1 - tm_now.tm_mday;
	return create_date_range(ctx, date1,
				date2, firstofmonth_adj,
				-1, firstofmonth_adj, 0);
}

static bool create_today_range(TALLOC_CTX *ctx, uint64_t *date1,
				uint64_t *date2)
{
	return create_date_range(ctx, date1,
				date2, 0, 0, 1, 0);
}

static bool create_yesterday_range(TALLOC_CTX *ctx, uint64_t *date1,
				uint64_t *date2)
{
	return create_date_range(ctx, date1,
				date2, -1, 0, 0, 0);
}

static bool create_thisweek_range(TALLOC_CTX *ctx, uint64_t *date1,
				uint64_t *date2)
{
	struct tm tm_now;
	time_t now;
	int32_t startofweek_adj;
	time(&now);
	gmtime_r(&now, &tm_now);
	if (tm_now.tm_wday) {
		startofweek_adj = 1 - tm_now.tm_wday;
	} else {
		startofweek_adj = -6;
	}
	/* lower will be the start of this week */
	return create_date_range(ctx, date1,
				date2, startofweek_adj,
				0, startofweek_adj + 7, 0);
}

static bool create_lastweek_range(TALLOC_CTX *ctx, uint64_t *date1,
				uint64_t *date2)
{
	struct tm tm_now;
	time_t now;
	int32_t startofweek_adj;
	time(&now);
	gmtime_r(&now, &tm_now);
	if (tm_now.tm_wday) {
		startofweek_adj = 1 - tm_now.tm_wday;
	} else {
		startofweek_adj = -6;
	}
	/* upper will be the start of this week */
	return create_date_range(ctx, date1,
				date2, startofweek_adj - 7,
				0,startofweek_adj, 0);
}

t_value_holder *create_date_range_shortcut(TALLOC_CTX *ctx,
			      daterange_type daterange)
{
	int i;
	static const struct {
		daterange_type range;
		daterange_func create_fn;
	} date_conv_map[] = {
		{eYESTERDAY, create_yesterday_range},
		{eTODAY, create_today_range},
		{eTHISMONTH, create_thismonth_range},
		{eLASTMONTH, create_lastmonth_range},
		{eTHISWEEK, create_thisweek_range},
		{eLASTWEEK, create_lastweek_range},
		{eTHISYEAR, create_thisyear_range},
		{eLASTYEAR, create_lastyear_range},
	};
	t_value_holder *result = NULL;
	t_value_holder *lower = NULL;
	t_value_holder *upper = NULL;

	lower = talloc_zero(ctx, t_value_holder);
	if (lower == NULL) {
		DBG_ERR("out of memory\n");
		goto out;
	}

	upper = talloc_zero(ctx, t_value_holder);
	if (upper == NULL) {
		DBG_ERR("out of memory\n");
		goto out;
	}

	result = create_value_range(result, lower, upper);

	if (result == NULL) {
		TALLOC_FREE(result);
		goto out;
	}

	lower->type = NUMBER;
	upper->type = NUMBER;

	result->value.value_range->lower = lower;
	result->value.value_range->upper = upper;

	for (i = 0; i < ARRAY_SIZE(date_conv_map); i++) {
		if (date_conv_map[i].range == daterange) {
			if (!date_conv_map[i].create_fn(result,
						&lower->value.number,
						&upper->value.number)) {
				TALLOC_FREE(result);
				break;
			}
			break;
		}
	}
out:
	return result;
}

t_value_holder *create_size_range_shortcut(TALLOC_CTX *ctx,
			      sizerange_type sizerange)
{
	static const struct {
		sizerange_type range;
		uint32_t lower;
		uint32_t upper;
	} sizes[] = {
		{eEMPTY, 0x0, 0x1},
		{eTINY, 0x1, 0x2801},
		{eSMALL, 0x2801, 0x19001},
		{eMEDIUM, 0x19001, 0x100001},
		{eLARGE, 0x100001, 0x10000001},
		{eHUGE, 0x10000001, 0x80000001},
		{eGIGANTIC, 0x80000001, 0} /* special case not a range */
	};
	int i;
	t_value_holder *result = NULL;
	uint32_t lower_size = 0;
	uint32_t upper_size = 0;
	bool rangefound = false;
	t_value_holder *left = NULL;
	t_value_holder *right = NULL;
	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		if (sizes[i].range == sizerange) {
			result = talloc_zero(ctx, t_value_holder);
			if (result == NULL) {
				DBG_ERR("out of memory\n");
				return NULL;
			}
			lower_size = sizes[i].lower;
			upper_size = sizes[i].upper;
			rangefound = true;
			break;
		}
	}

	if (!rangefound) {
		return NULL;
	}

	left = talloc_zero(ctx, t_value_holder);

	if (left == NULL) {
		return NULL;
	}

	left->type = NUMBER;
	left->value.number = lower_size;

	if (upper_size) {
		right = talloc_zero(ctx, t_value_holder);
		if (right == NULL) {
			return NULL;
		}
		right->type = NUMBER;
		right->value.number = upper_size;
	}

	result = create_value_range(ctx, left, right);
	return result;
}
