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

#ifndef __WSP_AQS_H__
#define __WSP_AQS_H__
#include "librpc/gen_ndr/wsp.h"

typedef enum nodetype
{
	eAND,
	eOR,
	eNOT,
	eVALUE,
} t_nodetype;

typedef enum op
{
	eLT = PRLT,
	eLE = PRLE,
	eGT = PRGT,
	eGE = PRGE,
	eEQ = PREQ,
	eNE = PRNE,
	eSTARTSWITH,
	eEQUALS,
	/*
	 * eMATCHES,
	 *
	 * not sure we can express the above in the grammar without
	 * some custom operator :/
	 */
} t_optype;

struct restr;

typedef enum {
	NUMBER,
	STRING,
	BOOL,
	RESTR,
	VALUE_RANGE,
} value_type;

typedef enum {
	eTODAY,
	eYESTERDAY,
	eLASTWEEK,
	eTHISWEEK,
	eTHISMONTH,
	eLASTMONTH,
	eTHISYEAR,
	eLASTYEAR,
} daterange_type;

typedef enum {
	eEMPTY,
	eTINY,
	eSMALL,
	eMEDIUM,
	eLARGE,
	eHUGE,
	eGIGANTIC,
} sizerange_type;

struct value_range;

typedef struct {
	value_type type;
	union {
		bool boolean;
		const char *string;
		uint64_t number;
		struct restr *restr_tree;
		struct value_range *value_range;
	} value;
} t_value_holder;

struct value_range
{
	t_value_holder *lower;
	t_value_holder *upper;
};
typedef struct basic_restr
{
	uint32_t prop_type;
	t_optype op;
	t_value_holder *values;
} t_basic_restr;

typedef struct basic_query
{
	struct GUID guid;
	const struct full_propset_info *prop_info;
	char *prop;
	t_basic_restr *basic_restriction;
} t_basic_query;

t_basic_query *create_basic_query(TALLOC_CTX *ctx, const char *prop, t_basic_restr *restr);

typedef struct restr
{
	t_nodetype type;
	struct restr *left;
	struct restr *right;
	t_basic_restr *basic_restr;
} t_restr;

t_restr *create_restr(TALLOC_CTX *ctx, t_nodetype op, t_restr *left, t_restr *right, t_basic_restr *value);

t_basic_restr *create_basic_restr(TALLOC_CTX *ctx,
				uint32_t prop_type,
				t_optype op,
				t_value_holder *values);

typedef struct query
{
	t_nodetype type;
	struct query *left;
	struct query *right;
	struct wsp_crestriction *restriction;
} t_query;

t_query *create_query_node(TALLOC_CTX *ctx, t_nodetype op, t_query *left, t_query *right, t_basic_query *value);


typedef struct col_list {
	int num_cols;
	char **cols;
} t_col_list;

typedef struct select_stmt {
	t_col_list *cols;
	t_query *where;
} t_select_stmt;

t_col_list *create_cols(TALLOC_CTX *ctx, const char *col, t_col_list *append_list);
t_select_stmt *create_select(TALLOC_CTX *ctx, t_col_list *cols, t_query *where);

t_select_stmt *get_wsp_sql_tree(const char *expr);
t_value_holder *create_string_val(TALLOC_CTX*, const char *text);
t_value_holder *create_num_val(TALLOC_CTX*, int64_t val);
t_value_holder *create_bool_val(TALLOC_CTX*, bool val);
t_value_holder *create_value_range(TALLOC_CTX*,
				   t_value_holder *left,
				   t_value_holder *right);
t_value_holder *create_date_range_shortcut(TALLOC_CTX *ctx,
			      daterange_type daterange);
t_value_holder *create_size_range_shortcut(TALLOC_CTX *ctx,
			      sizerange_type size);
#endif /* __WSP_AQS_H__ */
