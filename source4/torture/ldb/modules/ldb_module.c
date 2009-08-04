/* 
	 Unix SMB/CIFS implementation.

	 Test LDB attribute functions

	 Copyright (C) Andrew Bartlet <abartlet@samba.org> 2008
	 Copyright (C) Matthieu Patou <mat@matws.net> 2009
	 
	 This program is free software; you can redistribute it and/or modify
	 it under the terms of the GNU General Public License as published by
	 the Free Software Foundation; either version 3 of the License, or
	 (at your option) any later version.
	 
	 This program is distributed in the hope that it will be useful,
	 but WITHOUT ANY WARRANTY; without even the implied warranty of
	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
	 GNU General Public License for more details.
	 
	 You should have received a copy of the GNU General Public License
	 along with this program.	If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/events/events.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "ldb_wrap.h"
#include "param/param.h"
#include "lib/cmdline/popt_common.h" 
#include "torture/smbtorture.h"
#include "torture/local/proto.h"

static bool torture_ldb_mod_sort(struct torture_context *torture)
{

	struct ldb_context *ldb;

	bool ret = false;
	const char *host = torture_setting_string(torture, "host", NULL);
	char *url;
	char *basedn;
	int i;
	int j;
	struct ldb_message_element *elem;
	struct ldb_message *msg;
	struct dsdb_schema *schema = NULL;
	struct ldb_control **ctrl;

	struct ldb_server_sort_control ** control;
	struct ldb_request *req;
	struct ldb_result *ctx;
	struct ldb_val* prev = NULL;
	char *prev_txt = NULL;
	int prev_len = 0;
	struct ldb_val* cur = NULL;
	char *cur_txt = NULL;
	int cur_len = 0;
	struct ldb_dn* dn;
	char* user_cn = "Users";
		 
		 
	/* TALLOC_CTX* ctx;*/

	url = talloc_asprintf(torture, "ldap://%s/", host);

	ldb = ldb_wrap_connect(torture, torture->ev, torture->lp_ctx, url,
						 NULL,
						 cmdline_credentials,
						 0, NULL);
	if (!ldb) goto failed;
	ret = false;
	fprintf(stderr,"Ici \n");

	ctx = talloc_zero(ldb, struct ldb_result);

	ctrl = talloc_array(ctx, struct ldb_control *, 2);
	ctrl[0] = talloc(ctrl, struct ldb_control);
	ctrl[0]->oid = LDB_CONTROL_SERVER_SORT_OID;
	ctrl[0]->critical = true;

	control = talloc_array(ctrl[0], struct ldb_server_sort_control *, 2);
	control[0] = talloc(control, struct ldb_server_sort_control);
	control[0]->attributeName = talloc_strdup(control, "cn");
	control[0]->orderingRule = NULL;
	control[0]->reverse = 0;
	control[1] = NULL;
	ctrl[0]->data = control;
	ctrl[1] = NULL;

	dn = ldb_get_root_basedn(ldb);
	ldb_dn_add_child_fmt(dn, "cn=%s", user_cn);
	ret = ldb_build_search_req(&req, ldb, ctx,
					 dn,
					 LDB_SCOPE_SUBTREE,
					 "(objectClass=*)", NULL,
					 ctrl,
					 ctx, ldb_search_default_callback, NULL);

	ret = ldb_request(ldb, req);
	if (ret != LDB_SUCCESS) {
		d_printf("search failed - %s\n", ldb_errstring(ldb));
		talloc_free(req);
		return false;
	}

	ret = ldb_wait(req->handle, LDB_WAIT_ALL);

	if (ret != LDB_SUCCESS) {
		d_printf("search error - %s\n", ldb_errstring(ldb));
		talloc_free(req);
		return false;
	}
	ret = 1;
	if (ctx->count > 1) {
		for (i=0;i<ctx->count;i++) {
			msg = ctx->msgs[i];
			elem = ldb_msg_find_element(msg,"cn");
			cur = elem->values;
			d_printf("cn: %s\n",cur->data);
			if (prev != NULL)
			{
				/* Do only the ascii case right now ... */
				cur_txt=cur->data;
				cur_len=cur->length;
				prev_txt=prev->data;
				prev_len=prev->length;
				/* Remove leading whitespace as the sort function do so ... */
				while ( cur_txt[0] == cur_txt[1] ) { cur_txt++; cur_len--;}
				while ( prev_txt[0] == prev_txt[1] ) { prev_txt++; prev_len--;}
				while( *(cur_txt) && *(prev_txt) && cur_len && prev_len ) {
					j = (int)toupper(*(prev_txt))-(int)toupper(*(cur_txt));
					if ( j > 0 ) {
						/* Just check that is not due to trailling white space in prev_txt 
						 * That is to say *cur_txt = 0 and prev_txt = 20 */
						/* Remove trailling whitespace */
						while ( *prev_txt == ' ' ) { prev_txt++; prev_len--;}
						while ( *cur_txt == ' ' ) { cur_txt++; cur_len--;}
						/* Now that potential whitespace are removed if we are at the end 
						 * of the cur_txt then it means that in fact strings were identical
						 */
						if ( *cur_txt || *prev_txt ) {
							ret = 0;
							torture->last_reason = talloc_strdup(torture, "Data wrongly sorted");
						}
						break;
					}
					else
					{
						if ( j == 0 )
						{
							if ( *(cur_txt) == ' ') {
								while ( cur_txt[0] == cur_txt[1] ) { cur_txt++; cur_len--;}
								while ( prev_txt[0] == prev_txt[1] ) { prev_txt++; prev_len--;}
							}
							cur_txt++;
							prev_txt++;
							prev_len--;
							cur_len--;
						}
						else
						{
							break;
						} 
					}
				}
				if ( ret != 1 ) {
					break;
				}
			}
			prev = cur; 
		}

	}

failed:
	return ret;
}


NTSTATUS torture_ldb_module_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "LDB_MODULE");
	torture_suite_add_simple_test(suite, "SORT", torture_ldb_mod_sort);
	suite->description = talloc_strdup(suite, "LDB MODULES (samba-specific behaviour) tests");

	torture_register_suite(suite);

	return NT_STATUS_OK;
}

