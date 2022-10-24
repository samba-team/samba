/*
 *  Unix SMB/CIFS implementation.
 *  Copyright (C) Noel Power
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
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include <setjmp.h>
#include <cmocka.h>
#include <talloc.h>
#include "lib/cmdline/cmdline.h"
#include "libcli/util/ntstatus.h"
#include "lib/util/samba_util.h"
#include "lib/torture/torture.h"
#include "lib/param/param.h"
#include "libcli/wsp/wsp_aqs.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"
#include "librpc/wsp/wsp_util.h"

/*
 * some routines to help stringify the parsed AQS
 * query so we can test parsing
 */

static bool is_operator_node(t_query *node)
{
	if (node->type == eVALUE) {
		return false;
	}
	return true;
}

static const char *nodetype_as_string(t_nodetype node)
{
	const char *result = NULL;
	switch (node) {
		case eNOT:
			result = "NOT";
			break;
		case eAND:
			result = "AND";
			break;
		case eOR:
			result = "OR";
			break;
		case eVALUE:
		default:
			break;
	}
	return result;
}

static const char *restriction_as_string(TALLOC_CTX *ctx,
				    struct wsp_crestriction *crestriction )
{
	const char *result = NULL;
	if (crestriction->ultype == RTPROPERTY) {
		struct wsp_cpropertyrestriction *prop_restr =
			&crestriction->restriction.cpropertyrestriction;
		struct wsp_cbasestoragevariant *value = &prop_restr->prval;
		result = variant_as_string(ctx, value, true);
	} else {
		struct wsp_ccontentrestriction *cont_restr = NULL;
		cont_restr = &crestriction->restriction.ccontentrestriction;
		result = talloc_strdup(ctx, cont_restr->pwcsphrase);
	}
	return result;
}

static const char *prop_name_from_restriction(
		TALLOC_CTX *ctx,
		struct wsp_crestriction *restriction)
{
	const char *result = NULL;
	struct wsp_cfullpropspec *prop;
	if (restriction->ultype == RTCONTENT) {
		prop = &restriction->restriction.ccontentrestriction.property;
	} else {
		prop = &restriction->restriction.cpropertyrestriction.property;
	}
	result = prop_from_fullprop(ctx, prop);
	return result;
}

static char *print_basic_query(TALLOC_CTX *ctx,
		struct wsp_crestriction *restriction)
{
	const char *op_str = op_as_string(restriction);
	const char *val_str = restriction_as_string(ctx, restriction);
	const char *prop_name = prop_name_from_restriction(ctx, restriction);
	char *res = talloc_asprintf(ctx,
			"%s %s %s", prop_name, op_str ? op_str : "", val_str);
	return res;
}

static char *print_node(TALLOC_CTX *ctx, t_query *node, bool is_rpn)
{
	switch(node->type) {
		case eAND:
		case eOR:
		case eNOT:
			return talloc_asprintf(ctx,
				" %s ", nodetype_as_string(node->type));
			break;
		case eVALUE:
		default:
			return print_basic_query(ctx, node->restriction);
			break;
	}
}

/*
 * Algorithm infix (tree)
 * Print the infix expression for an expression tree.
 *  Pre : tree is a pointer to an expression tree
 *  Post: the infix expression has been printed
 * start infix
 *  if (tree not empty)
 *     if (tree token is operator)
 *        print (open parenthesis)
 *     end if
 *     infix (tree left subtree)
 *     print (tree token)
 *     infix (tree right subtree)
 *     if (tree token is operator)
 *        print (close parenthesis)
 *     end if
 *  end if
 * end infix
 */

static char *infix(TALLOC_CTX *ctx, t_query *tree)
{
	char *sresult = NULL;
	char *stree = NULL;
	char *sleft = NULL;
	char *sright = NULL;
	if (tree == NULL) {
		return NULL;
	}

	if (is_operator_node(tree)) {
		sresult = talloc_strdup(ctx, "(");
		SMB_ASSERT(sresult != NULL);
	}
	sleft = infix(ctx, tree->left);
	stree = print_node(ctx, tree, false);
	sright = infix(ctx, tree->right);
	sresult = talloc_asprintf(ctx, "%s%s%s%s",
			sresult ? sresult : "",
			sleft ? sleft : "",
			stree? stree : "",
			sright ? sright : "");

	if (is_operator_node(tree)) {
		sresult = talloc_asprintf(ctx, "%s)", sresult);
		SMB_ASSERT(sresult != NULL);
	}
	return sresult;
}

static struct {
	const char *aqs;
	const char *stringified;
} no_col_map_queries [] = {

	/* equals (numeric) */
	{
		"System.Size:10241",
		"System.Size = 10241"
	},
	{
		"System.Size := 10241",
		"System.Size = 10241"
	},
	/* not equals */
	{
		"System.Size:!=10241",
		"System.Size != 10241"
	},
	/* equals (string property) */
	{
		"ALL:(somestring)",
		"All = 'somestring'"
	},
	{
		"ALL:=somestring",
		"All = 'somestring'"
	},
	{
		"ALL:somestring",
		"All = 'somestring'"
	},
	/* not equals (string) */
	{
		"ALL:!=somestring",
		"All != 'somestring'"
	},
	/* Greater than */
	{
		"System.Size:(>10241)",
		"System.Size > 10241"
	},
	{
		"System.Size:>10241",
		"System.Size > 10241"
	},
	/* Less than */
	{
		"System.Size:(<10241)",
		"System.Size < 10241"
	},
	/* Greater than or equals */
	{
		"System.Size:(>=10241)",
		"System.Size >= 10241"
	},
	{
		"System.Size:>=10241",
		"System.Size >= 10241"
	},
	/* Less than or equals */
	{
		"System.Size:(<=10241)",
		"System.Size <= 10241"
	},
	{
		"System.Size:<=10241",
		"System.Size <= 10241"
	},
	/* equals (in the sense of matches) */
	{
		"ALL:($=somestring)",
		"All equals somestring"
	},
	/* starts with */
	{
		"ALL:($<somestring)",
		"All starts with somestring"
	},
	/* range */
	{
		"System.Size:10241-102401",
		"(System.Size >= 10241 AND System.Size < 102401)"
	},
	{
		"System.Size:small",
		"(System.Size >= 10241 AND System.Size < 102401)"
	},
	/* NOT */
	{
		"NOT System.Size:10241",
		"( NOT System.Size = 10241)"
	},
	/* AND */
	{
		"System.Size:(>=10241) AND System.Size:(<102401)",
		"(System.Size >= 10241 AND System.Size < 102401)"
	},
	/* OR */
	{
		"System.Kind:picture OR System.Kind:video",
		"(System.Kind = 'picture' OR System.Kind = 'video')"
	},
	/* MULTIPLE LOGICAL */
	{
		"System.Kind:picture AND NOT System.Kind:video OR "
		"System.Kind:movie",
		"(System.Kind = 'picture' AND (( NOT System.Kind = 'video') OR "
		"System.Kind = 'movie'))"
	},
	/* parenthesized MULTIPLE LOGICAL */
	{
		"(System.Kind:picture AND NOT System.Kind:video) OR "
		"System.Kind:movie",
		"((System.Kind = 'picture' AND ( NOT System.Kind = 'video')) "
		"OR System.Kind = 'movie')"
	},
};

static char *dump_cols(TALLOC_CTX *ctx, t_select_stmt *select)
{
	t_col_list *cols = select->cols;
	char *res = NULL;
	if (cols) {
		int i;
		for (i = 0; i < cols->num_cols; i++) {
			if (i == 0) {
				res = talloc_strdup(ctx,
						cols->cols[i]);
			} else {
				res = talloc_asprintf(ctx,
						"%s, %s",
						res, cols->cols[i]);
			}
		}
	}
	return res;
}

static void test_wsp_parser(void **state)
{
	int i;
	t_select_stmt *select_stmt = NULL;
	const char *col_query =
		"SELECT System.ItemName, System.ItemURL, System.Size WHERE "
		"System.Kind:picture";
	char *res = NULL;

	TALLOC_CTX *frame = talloc_stackframe();
	for (i = 0; i < ARRAY_SIZE(no_col_map_queries); i++) {
		select_stmt = get_wsp_sql_tree(no_col_map_queries[i].aqs);
		assert_non_null(select_stmt);
		assert_null(select_stmt->cols);
		res = infix(frame, select_stmt->where);
		DBG_DEBUG("reading query => %s parsed => %s\n",
			no_col_map_queries[i].aqs,
			res);
		assert_string_equal(res, no_col_map_queries[i].stringified);
	}
	select_stmt = get_wsp_sql_tree(col_query);
	res = infix(frame, select_stmt->where);
	assert_string_equal(res, "System.Kind = 'picture'");
	assert_non_null(select_stmt->cols);
	res = dump_cols(frame, select_stmt);
	assert_string_equal(res,
		"System.ItemName, System.ItemURL, System.Size");
	TALLOC_FREE(frame);
}

int main(int argc, const char *argv[])
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wsp_parser),
	};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	poptContext pc;
	int opt;
	bool ok;
	struct loadparm_context *lp_ctx = NULL;

	TALLOC_CTX *frame = talloc_stackframe();

	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	lp_ctx = samba_cmdline_get_lp_ctx();
	if (!lp_ctx) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	lpcfg_set_cmdline(lp_ctx, "log level", "1");

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt) {
		    default:
			    fprintf(stderr, "Unknown Option: %c\n", opt);
			    exit(1);
		}
	}

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
