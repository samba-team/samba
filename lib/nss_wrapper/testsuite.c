/*
   Unix SMB/CIFS implementation.

   local testing of the nss wrapper

   Copyright (C) Guenther Deschner 2009

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
#include "torture/torture.h"
#include "lib/replace/system/passwd.h"
#include "lib/nss_wrapper/nss_wrapper.h"

static void print_passwd(struct passwd *pwd)
{
	printf("%s:%s:%lu:%lu:%s:%s:%s\n",
	       pwd->pw_name,
	       pwd->pw_passwd,
	       (unsigned long)pwd->pw_uid,
	       (unsigned long)pwd->pw_gid,
	       pwd->pw_gecos,
	       pwd->pw_dir,
	       pwd->pw_shell);
}


static bool test_nwrap_getpwnam(struct torture_context *tctx,
				const char *name)
{
	struct passwd *pwd;

	torture_comment(tctx, "Testing getpwnam: %s\n", name);

	pwd = getpwnam(name);
	if (pwd) {
		print_passwd(pwd);
	}

	return pwd ? true : false;
}

static bool test_nwrap_getpwuid(struct torture_context *tctx,
				uid_t uid)
{
	struct passwd *pwd;

	torture_comment(tctx, "Testing getpwuid: %lu\n", (unsigned long)uid);

	pwd = getpwuid(uid);
	if (pwd) {
		print_passwd(pwd);
	}

	return pwd ? true : false;
}

static void print_group(struct group *grp)
{
	int i;
	printf("%s:%s:%lu:",
	       grp->gr_name,
	       grp->gr_passwd,
	       (unsigned long)grp->gr_gid);

	if (!grp->gr_mem[0]) {
		printf("\n");
		return;
	}

	for (i=0; grp->gr_mem[i+1]; i++) {
		printf("%s,", grp->gr_mem[i]);
	}
	printf("%s\n", grp->gr_mem[i]);
}

static bool test_nwrap_getgrnam(struct torture_context *tctx,
				const char *name)
{
	struct group *grp;

	torture_comment(tctx, "Testing getgrnam: %s\n", name);

	grp = getgrnam(name);
	if (grp) {
		print_group(grp);
	}

	return grp ? true : false;
}

static bool test_nwrap_getgrgid(struct torture_context *tctx,
				gid_t gid)
{
	struct group *grp;

	torture_comment(tctx, "Testing getgrgid: %lu\n", (unsigned long)gid);

	grp = getgrgid(gid);
	if (grp) {
		print_group(grp);
	}

	return grp ? true : false;
}


static bool test_nwrap_passwd(struct torture_context *tctx)
{
	struct passwd *pwd;
	const char **names = NULL;
	uid_t *uids = NULL;
	int num_names = 0;
	size_t num_uids = 0;
	int i;

	torture_comment(tctx, "Testing setpwent\n");
	setpwent();

	while ((pwd = getpwent())) {
		torture_comment(tctx, "Testing getpwent\n");

		if (pwd) {
			print_passwd(pwd);
			add_string_to_array(tctx, pwd->pw_name, &names, &num_names);
			add_uid_to_array_unique(tctx, pwd->pw_uid, &uids, &num_uids);
		}
	}

	torture_comment(tctx, "Testing endpwent\n");
	endpwent();

	torture_assert_int_equal(tctx, num_names, num_uids, "invalid results");

	for (i=0; i < num_names; i++) {
		torture_assert(tctx, test_nwrap_getpwnam(tctx, names[i]),
			"failed to call getpwnam for enumerated user");
		torture_assert(tctx, test_nwrap_getpwuid(tctx, uids[i]),
			"failed to call getpwuid for enumerated user");
	}

	return true;
}

static bool test_nwrap_group(struct torture_context *tctx)
{
	struct group *grp;
	const char **names = NULL;
	gid_t *gids = NULL;
	int num_names = 0;
	size_t num_gids = 0;
	int i;

	torture_comment(tctx, "Testing setgrent\n");
	setgrent();

	do {
		torture_comment(tctx, "Testing getgrent\n");
		grp = getgrent();
		if (grp) {
			print_group(grp);
			add_string_to_array(tctx, grp->gr_name, &names, &num_names);
			add_gid_to_array_unique(tctx, grp->gr_gid, &gids, &num_gids);
		}
	} while (grp);

	torture_comment(tctx, "Testing endgrent\n");
	endgrent();

	torture_assert_int_equal(tctx, num_names, num_gids, "invalid results");

	for (i=0; i < num_names; i++) {
		torture_assert(tctx, test_nwrap_getgrnam(tctx, names[i]),
			"failed to call getgrnam for enumerated user");
		torture_assert(tctx, test_nwrap_getgrgid(tctx, gids[i]),
			"failed to call getgrgid for enumerated user");
	}

	return true;
}

static bool test_nwrap_env(struct torture_context *tctx)
{
	const char *old_pwd = getenv("NSS_WRAPPER_PASSWD");
	const char *old_group = getenv("NSS_WRAPPER_GROUP");

	if (!old_pwd || !old_group) {
		torture_skip(tctx, "nothing to test\n");
		return true;
	}

	torture_assert(tctx, test_nwrap_passwd(tctx),
			"failed to test users");
	torture_assert(tctx, test_nwrap_group(tctx),
			"failed to test groups");

	return true;
}

struct torture_suite *torture_local_nss_wrapper(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "NSS-WRAPPER");

	torture_suite_add_simple_test(suite, "env", test_nwrap_env);

	return suite;
}
