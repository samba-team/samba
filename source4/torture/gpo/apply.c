/*
   Unix SMB/CIFS implementation.

   Copyright (C) David Mulder 2017

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
#include "param/param.h"
#include "param/loadparm.h"
#include "torture/smbtorture.h"
#include "lib/util/mkdir_p.h"
#include "dsdb/samdb/samdb.h"
#include "auth/session.h"
#include "lib/ldb/include/ldb.h"
#include "torture/gpo/proto.h"
#include <unistd.h>
#include "lib/util/samba_util.h"
#include "util/tevent_ntstatus.h"

struct torture_suite *gpo_apply_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "apply");

	torture_suite_add_simple_test(suite, "gpo_param_from_gpo",
				      torture_gpo_system_access_policies);

	suite->description = talloc_strdup(suite, "Group Policy apply tests");

	return suite;
}

static int exec_wait(struct torture_context *tctx, const char **gpo_update_cmd)
{
	NTSTATUS status;
	int ret = 0;
	struct tevent_req *req;

	req = samba_runcmd_send(tctx,
				tctx->ev,
				timeval_current_ofs(100, 0),
				2, 0,
				gpo_update_cmd,
				"gpo_reload_cmd", NULL);
	if (req == NULL) {
		return -1;
	}

	if (!tevent_req_poll_ntstatus(req, tctx->ev, &status)) {
		return -1;
	}
	if (samba_runcmd_recv(req, &ret) != 0) {
		return -1;
	}
	return ret;
}

static int unix2nttime(const char *sval)
{
	return (strtoll(sval, NULL, 10) * -1 / 60 / 60 / 24 / 10000000);
}

#define GPODIR "addom.samba.example.com/Policies/"\
	       "{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/"\
	       "Windows NT/SecEdit"
#define GPOFILE "GptTmpl.inf"
#define GPTTMPL "[System Access]\n\
MinimumPasswordAge = %d\n\
MaximumPasswordAge = %d\n\
MinimumPasswordLength = %d\n\
PasswordComplexity = %d\n\
"
#define GPTINI "addom.samba.example.com/Policies/"\
	       "{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI"

bool torture_gpo_system_access_policies(struct torture_context *tctx)
{
	TALLOC_CTX *ctx = talloc_new(tctx);
	int ret, vers = 0, i;
	const char *sysvol_path = NULL, *gpo_dir = NULL;
	const char *gpo_file = NULL, *gpt_file = NULL;
	struct ldb_context *samdb = NULL;
	struct ldb_result *result;
	const char *attrs[] = {
		"minPwdAge",
		"maxPwdAge",
		"minPwdLength",
		"pwdProperties",
		NULL
	};
	FILE *fp = NULL;
	const char **gpo_update_cmd;
	const char **gpo_unapply_cmd;
	const char **gpo_update_force_cmd;
	int minpwdcases[] = { 0, 1, 998 };
	int maxpwdcases[] = { 0, 1, 999 };
	int pwdlencases[] = { 0, 1, 14 };
	int pwdpropcases[] = { 0, 1, 1 };
	struct ldb_message *old_message = NULL;
	const char **itr;
	int gpo_update_len = 0;

	sysvol_path = lpcfg_path(lpcfg_service(tctx->lp_ctx, "sysvol"),
				 lpcfg_default_service(tctx->lp_ctx), tctx);
	torture_assert(tctx, sysvol_path, "Failed to fetch the sysvol path");

	/* Ensure the sysvol path exists */
	gpo_dir = talloc_asprintf(ctx, "%s/%s", sysvol_path, GPODIR);
	mkdir_p(gpo_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	gpo_file = talloc_asprintf(ctx, "%s/%s", gpo_dir, GPOFILE);

	/* Get the gpo update command */
	gpo_update_cmd = lpcfg_gpo_update_command(tctx->lp_ctx);
	torture_assert(tctx, gpo_update_cmd && gpo_update_cmd[0],
		       "Failed to fetch the gpo update command");

	/* Open and read the samba db and store the initial password settings */
	samdb = samdb_connect(ctx,
			      tctx->ev,
			      tctx->lp_ctx,
			      system_session(tctx->lp_ctx),
			      NULL,
			      0);
	torture_assert(tctx, samdb, "Failed to connect to the samdb");

	ret = ldb_search(samdb, ctx, &result, ldb_get_default_basedn(samdb),
			 LDB_SCOPE_BASE, attrs, NULL);
	torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1,
		       "Searching the samdb failed");

	old_message = result->msgs[0];

	for (i = 0; i < 3; i++) {
		/* Write out the sysvol */
		if ( (fp = fopen(gpo_file, "w")) ) {
			fputs(talloc_asprintf(ctx, GPTTMPL, minpwdcases[i],
					      maxpwdcases[i], pwdlencases[i],
					      pwdpropcases[i]), fp);
			fclose(fp);
		}

		/* Update the version in the GPT.INI */
		gpt_file = talloc_asprintf(ctx, "%s/%s", sysvol_path, GPTINI);
		if ( (fp = fopen(gpt_file, "r")) ) {
			char line[256];
			while (fgets(line, 256, fp)) {
				if (strncasecmp(line, "Version=", 8) == 0) {
					vers = atoi(line+8);
					break;
				}
			}
			fclose(fp);
		}
		if ( (fp = fopen(gpt_file, "w")) ) {
			char *data = talloc_asprintf(ctx,
						     "[General]\nVersion=%d\n",
						     ++vers);
			fputs(data, fp);
			fclose(fp);
		}

		/* Run the gpo update command */
		ret = exec_wait(tctx, gpo_update_cmd);

		torture_assert(tctx, ret == 0,
			       "Failed to execute the gpo update command");
		ret = ldb_search(samdb, ctx, &result,
				 ldb_get_default_basedn(samdb),
				 LDB_SCOPE_BASE, attrs, NULL);
		torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1,
			       "Searching the samdb failed");

		/* minPwdAge */
		torture_assert_int_equal(tctx, unix2nttime(
						ldb_msg_find_attr_as_string(
							result->msgs[0],
							attrs[0],
							"")), minpwdcases[i],
			       "The minPwdAge was not applied");

		/* maxPwdAge */
		torture_assert_int_equal(tctx, unix2nttime(
						ldb_msg_find_attr_as_string(
							result->msgs[0],
							attrs[1],
							"")), maxpwdcases[i],
			       "The maxPwdAge was not applied");

		/* minPwdLength */
		torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
							result->msgs[0],
							attrs[2],
							-1),
					       pwdlencases[i],
				"The minPwdLength was not applied");

		/* pwdProperties */
		torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
							result->msgs[0],
							attrs[3],
							-1),
					       pwdpropcases[i],
			       "The pwdProperties were not applied");
	}

	/* Reset settings, then verify a reapply doesn't force them back */
	for (i = 0; i < old_message->num_elements; i++) {
		old_message->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}
	ret = ldb_modify(samdb, old_message);
	torture_assert(tctx, ret == 0, "Failed to reset password settings.");

	ret = exec_wait(tctx, gpo_update_cmd);
	torture_assert(tctx, ret == 0,
		       "Failed to execute the gpo update command");

	/* Validate that the apply did nothing (without --force param) */
	ret = ldb_search(samdb, ctx, &result, ldb_get_default_basedn(samdb),
			 LDB_SCOPE_BASE, attrs, NULL);
	torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1,
		       "Searching the samdb failed");
	/* minPwdAge */
	torture_assert_int_equal(tctx, unix2nttime(ldb_msg_find_attr_as_string(
						result->msgs[0],
						attrs[0],
						"")),
		       unix2nttime(ldb_msg_find_attr_as_string(old_message,
							       attrs[0],
							       "")
				  ),
		       "The minPwdAge was re-applied");
	/* maxPwdAge */
	torture_assert_int_equal(tctx, unix2nttime(ldb_msg_find_attr_as_string(
						result->msgs[0],
						attrs[1],
						"")),
		       unix2nttime(ldb_msg_find_attr_as_string(old_message,
							       attrs[1],
							       "")
				  ),
		       "The maxPwdAge was re-applied");
	/* minPwdLength */
	torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
						result->msgs[0],
						attrs[2],
						-1),
				       ldb_msg_find_attr_as_int(
						old_message,
						attrs[2],
						-2),
			"The minPwdLength was re-applied");
	/* pwdProperties */
	torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
						result->msgs[0],
						attrs[3],
						-1),
					ldb_msg_find_attr_as_int(
						old_message,
						attrs[3],
						-2),
			"The pwdProperties were re-applied");

	for (itr = gpo_update_cmd; *itr != NULL; itr++) {
		gpo_update_len++;
	}

	/* Run gpupdate --force and verify settings are re-applied */
	gpo_update_force_cmd = talloc_array(ctx, const char*, gpo_update_len+2);
	for (i = 0; i < gpo_update_len; i++) {
		gpo_update_force_cmd[i] = talloc_strdup(gpo_update_force_cmd,
							gpo_update_cmd[i]);
	}
	gpo_update_force_cmd[i] = talloc_asprintf(gpo_update_force_cmd,
						  "--force");
	gpo_update_force_cmd[i+1] = NULL;
	ret = exec_wait(tctx, gpo_update_force_cmd);
	torture_assert(tctx, ret == 0,
		       "Failed to execute the gpupdate --force command");

	ret = ldb_search(samdb, ctx, &result,
			 ldb_get_default_basedn(samdb),
			 LDB_SCOPE_BASE, attrs, NULL);
	torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1,
		       "Searching the samdb failed");

	/* minPwdAge */
	torture_assert_int_equal(tctx, unix2nttime(
					ldb_msg_find_attr_as_string(
						result->msgs[0],
						attrs[0],
						"")), minpwdcases[2],
		       "The minPwdAge was not applied");

	/* maxPwdAge */
	torture_assert_int_equal(tctx, unix2nttime(
					ldb_msg_find_attr_as_string(
						result->msgs[0],
						attrs[1],
						"")), maxpwdcases[2],
		       "The maxPwdAge was not applied");

	/* minPwdLength */
	torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
						result->msgs[0],
						attrs[2],
						-1),
				       pwdlencases[2],
			"The minPwdLength was not applied");

	/* pwdProperties */
	torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
						result->msgs[0],
						attrs[3],
						-1),
				       pwdpropcases[2],
		       "The pwdProperties were not applied");

	/* Unapply the settings and verify they are removed */
	gpo_unapply_cmd = talloc_array(ctx, const char*, gpo_update_len+2);
	for (i = 0; i < gpo_update_len; i++) {
		gpo_unapply_cmd[i] = talloc_strdup(gpo_unapply_cmd,
						   gpo_update_cmd[i]);
	}
	gpo_unapply_cmd[i] = talloc_asprintf(gpo_unapply_cmd, "--unapply");
	gpo_unapply_cmd[i+1] = NULL;
	ret = exec_wait(tctx, gpo_unapply_cmd);
	torture_assert(tctx, ret == 0,
		       "Failed to execute the gpo unapply command");
	ret = ldb_search(samdb, ctx, &result, ldb_get_default_basedn(samdb),
			 LDB_SCOPE_BASE, attrs, NULL);
	torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1,
		       "Searching the samdb failed");
	/* minPwdAge */
	torture_assert_int_equal(tctx, unix2nttime(ldb_msg_find_attr_as_string(
						result->msgs[0],
						attrs[0],
						"")),
		       unix2nttime(ldb_msg_find_attr_as_string(old_message,
							       attrs[0],
							       "")
				  ),
		       "The minPwdAge was not unapplied");
	/* maxPwdAge */
	torture_assert_int_equal(tctx, unix2nttime(ldb_msg_find_attr_as_string(
						result->msgs[0],
						attrs[1],
						"")),
		       unix2nttime(ldb_msg_find_attr_as_string(old_message,
							       attrs[1],
							       "")
				  ),
		       "The maxPwdAge was not unapplied");
	/* minPwdLength */
	torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
						result->msgs[0],
						attrs[2],
						-1),
				       ldb_msg_find_attr_as_int(
						old_message,
						attrs[2],
						-2),
			"The minPwdLength was not unapplied");
	/* pwdProperties */
	torture_assert_int_equal(tctx, ldb_msg_find_attr_as_int(
						result->msgs[0],
						attrs[3],
						-1),
					ldb_msg_find_attr_as_int(
						old_message,
						attrs[3],
						-2),
			"The pwdProperties were not unapplied");

	talloc_free(ctx);
	return true;
}
