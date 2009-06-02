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

static bool copy_passwd(struct torture_context *tctx,
			const struct passwd *pwd,
			struct passwd *p)
{
	p->pw_name	= talloc_strdup(tctx, pwd->pw_name);
	p->pw_passwd	= talloc_strdup(tctx, pwd->pw_passwd);
	p->pw_uid	= pwd->pw_uid;
	p->pw_gid	= pwd->pw_gid;
	p->pw_gecos	= talloc_strdup(tctx, pwd->pw_gecos);
	p->pw_dir	= talloc_strdup(tctx, pwd->pw_dir);
	p->pw_shell	= talloc_strdup(tctx, pwd->pw_shell);

	return true;
}

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

static bool copy_group(struct torture_context *tctx,
		       const struct group *grp,
		       struct group *g)
{
	int i;

	g->gr_name	= talloc_strdup(tctx, grp->gr_name);
	g->gr_passwd	= talloc_strdup(tctx, grp->gr_passwd);
	g->gr_gid	= grp->gr_gid;
	g->gr_mem	= NULL;

	for (i=0; grp->gr_mem && grp->gr_mem[i]; i++) {
		g->gr_mem = talloc_realloc(tctx, g->gr_mem, char *, i + 2);
		g->gr_mem[i] = talloc_strdup(g->gr_mem, grp->gr_mem[i]);
		g->gr_mem[i+1] = NULL;
	}

	return true;
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

static bool test_nwrap_enum_passwd(struct torture_context *tctx,
				   struct passwd **pwd_array_p,
				   size_t *num_pwd_p)
{
	struct passwd *pwd;
	struct passwd *pwd_array = NULL;
	size_t num_pwd = 0;

	torture_comment(tctx, "Testing setpwent\n");
	setpwent();

	while ((pwd = getpwent()) != NULL) {
		torture_comment(tctx, "Testing getpwent\n");

		print_passwd(pwd);
		if (pwd_array_p && num_pwd_p) {
			pwd_array = talloc_realloc(tctx, pwd_array, struct passwd, num_pwd+1);
			torture_assert(tctx, pwd_array, "out of memory");
			copy_passwd(tctx, pwd, &pwd_array[num_pwd]);
			num_pwd++;
		}
	}

	torture_comment(tctx, "Testing endpwent\n");
	endpwent();

	if (pwd_array_p) {
		*pwd_array_p = pwd_array;
	}
	if (num_pwd_p) {
		*num_pwd_p = num_pwd;
	}

	return true;
}

static bool test_nwrap_passwd(struct torture_context *tctx)
{
	int i;
	struct passwd *pwd;
	size_t num_pwd;

	torture_assert(tctx, test_nwrap_enum_passwd(tctx, &pwd, &num_pwd),
						    "failed to enumerate passwd");

	for (i=0; i < num_pwd; i++) {
		torture_assert(tctx, test_nwrap_getpwnam(tctx, pwd[i].pw_name),
			"failed to call getpwnam for enumerated user");
		torture_assert(tctx, test_nwrap_getpwuid(tctx, pwd[i].pw_uid),
			"failed to call getpwuid for enumerated user");
	}

	return true;
}

static bool test_nwrap_enum_group(struct torture_context *tctx,
				  struct group **grp_array_p,
				  size_t *num_grp_p)
{
	struct group *grp;
	struct group *grp_array = NULL;
	size_t num_grp = 0;

	torture_comment(tctx, "Testing setgrent\n");
	setgrent();

	while ((grp = getgrent()) != NULL) {
		torture_comment(tctx, "Testing getgrent\n");

		print_group(grp);
		if (grp_array_p && num_grp_p) {
			grp_array = talloc_realloc(tctx, grp_array, struct group, num_grp+1);
			torture_assert(tctx, grp_array, "out of memory");
			copy_group(tctx, grp, &grp_array[num_grp]);
			num_grp++;
		}
	}

	torture_comment(tctx, "Testing endgrent\n");
	endgrent();

	if (grp_array_p) {
		*grp_array_p = grp_array;
	}
	if (num_grp_p) {
		*num_grp_p = num_grp;
	}


	return true;
}

static bool test_nwrap_group(struct torture_context *tctx)
{
	int i;
	struct group *grp;
	size_t num_grp;

	torture_assert(tctx, test_nwrap_enum_group(tctx, &grp, &num_grp),
						   "failed to enumerate group");

	for (i=0; i < num_grp; i++) {
		torture_assert(tctx, test_nwrap_getgrnam(tctx, grp[i].gr_name),
			"failed to call getgrnam for enumerated user");
		torture_assert(tctx, test_nwrap_getgrgid(tctx, grp[i].gr_gid),
			"failed to call getgrgid for enumerated user");
	}

	return true;
}

static bool test_nwrap_getgrouplist(struct torture_context *tctx,
				    const char *user,
				    gid_t gid,
				    gid_t **gids_p,
				    int *num_gids_p)
{
	int ret;
	int num_groups = 0;
	gid_t *groups = NULL;

	torture_comment(tctx, "Testing getgrouplist: %s\n", user);

	ret = getgrouplist(user, gid, NULL, &num_groups);
	if (ret == -1 || num_groups != 0) {

		groups = talloc_array(tctx, gid_t, num_groups);
		torture_assert(tctx, groups, "out of memory\n");

		ret = getgrouplist(user, gid, groups, &num_groups);
	}

	torture_assert(tctx, (ret != -1), "failed to call getgrouplist");

	torture_comment(tctx, "%s is member in %d groups\n", user, num_groups);

	if (gids_p) {
		*gids_p = groups;
	}
	if (num_gids_p) {
		*num_gids_p = num_groups;
	}

	return true;
}

static bool test_nwrap_membership(struct torture_context *tctx)
{
	const char *old_pwd = getenv("NSS_WRAPPER_PASSWD");
	const char *old_group = getenv("NSS_WRAPPER_GROUP");
	struct passwd *pwd;
	size_t num_pwd;
	int i;

	if (!old_pwd || !old_group) {
		torture_skip(tctx, "nothing to test\n");
		return true;
	}

	torture_assert(tctx, test_nwrap_enum_passwd(tctx, &pwd, &num_pwd),
						    "failed to enumerate passwd");

	for (i=0; i < num_pwd; i++) {

		int num_user_groups = 0;
		gid_t *user_groups = NULL;
		int g;

		torture_assert(tctx, test_nwrap_getgrouplist(tctx,
							     pwd[i].pw_name,
							     pwd[i].pw_gid,
							     &user_groups,
							     &num_user_groups),
							     "failed to test getgrouplist");

		for (g=0; g < num_user_groups; g++) {
			torture_assert(tctx, test_nwrap_getgrgid(tctx, user_groups[g]),
				"failed to find the group the user is a member of");
		}
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
	torture_suite_add_simple_test(suite, "membership", test_nwrap_membership);

	return suite;
}
