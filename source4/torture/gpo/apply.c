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

struct torture_suite *gpo_apply_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "apply");

	torture_suite_add_simple_test(suite, "gpo_param_from_gpo", torture_gpo_system_access_policies);

	suite->description = talloc_strdup(suite, "Group Policy apply tests");

	return suite;
}

static int exec_wait(const char **cmd)
{
	int ret;
	pid_t pid = fork();
	switch (pid) {
		case 0:
			execv(cmd[0], discard_const_p(char *, &(cmd[1])));
			ret = -1;
			break;
		case -1:
			ret = errno;
			break;
		default:
			if (waitpid(pid, &ret, 0) < 0)
				ret = errno;
			break;
	}
	return ret;
}

static int unix2nttime(char *sval)
{
	return (strtoll(sval, NULL, 10) * -1 / 60 / 60 / 24 / 10000000);
}

#define GPODIR "addom.samba.example.com/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit"
#define GPOFILE "GptTmpl.inf"
#define GPTTMPL "[System Access]\n\
MinimumPasswordAge = %d\n\
MaximumPasswordAge = %d\n\
MinimumPasswordLength = %d\n\
PasswordComplexity = %d\n\
"
#define GPTINI "addom.samba.example.com/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI"

bool torture_gpo_system_access_policies(struct torture_context *tctx)
{
	int ret, vers = 0, i;
	const char *sysvol_path = NULL, *gpo_dir = NULL, *gpo_file = NULL, *gpt_file = NULL;
	struct ldb_context *samdb = NULL;
	struct ldb_result *result;
	const char *attrs[] = {
		"minPwdAge",
		"maxPwdAge",
		"minPwdLength",
		"pwdProperties",
		NULL
	};
	const struct ldb_val *val;
	FILE *fp = NULL;
	const char **gpo_update_cmd;
	int minpwdcases[] = { 0, 1, 998 };
	int maxpwdcases[] = { 0, 1, 999 };
	int pwdlencases[] = { 0, 1, 14 };
	int pwdpropcases[] = { 0, 1, 1 };
	struct ldb_message *old_message = NULL;

	sysvol_path = lpcfg_path(lpcfg_service(tctx->lp_ctx, "sysvol"), lpcfg_default_service(tctx->lp_ctx), tctx);
	torture_assert(tctx, sysvol_path, "Failed to fetch the sysvol path");

	/* Ensure the sysvol path exists */
	gpo_dir = talloc_asprintf(tctx, "%s/%s", sysvol_path, GPODIR);
	mkdir_p(gpo_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	gpo_file = talloc_asprintf(tctx, "%s/%s", gpo_dir, GPOFILE);

	/* Get the gpo update command */
	gpo_update_cmd = lpcfg_gpo_update_command(tctx->lp_ctx);
	torture_assert(tctx, gpo_update_cmd && gpo_update_cmd[0], "Failed to fetch the gpo update command");

	/* Open and read the samba db and store the initial password settings */
	samdb = samdb_connect(tctx, tctx->ev, tctx->lp_ctx, system_session(tctx->lp_ctx), 0);
	torture_assert(tctx, samdb, "Failed to connect to the samdb");

	ret = ldb_search(samdb, tctx, &result, ldb_get_default_basedn(samdb), LDB_SCOPE_BASE, attrs, NULL);
	torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1, "Searching the samdb failed");

	old_message = result->msgs[0];

	for (i = 0; i < 3; i++) {
		/* Write out the sysvol */
		if ( (fp = fopen(gpo_file, "w")) ) {
			fputs(talloc_asprintf(tctx, GPTTMPL, minpwdcases[i], maxpwdcases[i], pwdlencases[i], pwdpropcases[i]), fp);
			fclose(fp);
		}

		/* Update the version in the GPT.INI */
		gpt_file = talloc_asprintf(tctx, "%s/%s", sysvol_path, GPTINI);
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
			char *data = talloc_asprintf(tctx, "[General]\nVersion=%d\n", ++vers);
			fputs(data, fp);
			fclose(fp);
		}

		/* Run the gpo update command */
		ret = exec_wait(gpo_update_cmd);
		torture_assert(tctx, ret == 0, "Failed to execute the gpo update command");

		ret = ldb_search(samdb, tctx, &result, ldb_get_default_basedn(samdb), LDB_SCOPE_BASE, attrs, NULL);
		torture_assert(tctx, ret == LDB_SUCCESS && result->count == 1, "Searching the samdb failed");

		/* minPwdAge */
		val = ldb_msg_find_ldb_val(result->msgs[0], attrs[0]);
		torture_assert(tctx, unix2nttime((char*)val->data) == minpwdcases[i], "The minPwdAge was not applied");

		/* maxPwdAge */
		val = ldb_msg_find_ldb_val(result->msgs[0], attrs[1]);
		torture_assert(tctx, unix2nttime((char*)val->data) == maxpwdcases[i], "The maxPwdAge was not applied");

		/* minPwdLength */
		val = ldb_msg_find_ldb_val(result->msgs[0], attrs[2]);
		torture_assert(tctx, atoi((char*)val->data) == pwdlencases[i], "The minPwdLength was not applied");

		/* pwdProperties */
		val = ldb_msg_find_ldb_val(result->msgs[0], attrs[3]);
		torture_assert(tctx, atoi((char*)val->data) == pwdpropcases[i], "The pwdProperties were not applied");
	}

	for (i = 0; i < old_message->num_elements; i++) {
		old_message->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	ret = ldb_modify(samdb, old_message);
	torture_assert(tctx, ret == 0, "Failed to reset password settings.");

	return true;
}
