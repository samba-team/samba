/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   nss tester for winbindd
   Copyright (C) Andrew Tridgell 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

static char *so_path = "/lib/libnss_winbind.so";
static int nss_errno;

static void *find_fn(const char *name)
{
	static void *h;
	void *res;
	if (!h) {
		h = dlopen(so_path, RTLD_LAZY);
	}
	if (!h) {
		printf("Can't open shared library %s\n", so_path);
		exit(1);
	}
	res = dlsym(h, name);
	if (!res) {
		printf("Can't find function %s\n", name);
		exit(1);
	}
	return res;
}

static void report_nss_error(NSS_STATUS status)
{
	if (status >= NSS_STATUS_SUCCESS) return;
	printf("NSS_STATUS=%d  %d\n", status, NSS_STATUS_SUCCESS);
}

static struct passwd *nss_getpwent(void)
{
	NSS_STATUS (*_nss_getpwent_r)(struct passwd *, char *, 
				      size_t , int *) = find_fn("_nss_winbind_getpwent_r");
	static struct passwd pwd;
	static char buf[1000];
	NSS_STATUS status;
	
	status = _nss_getpwent_r(&pwd, buf, sizeof(buf), &nss_errno);
	if (status == NSS_STATUS_NOTFOUND) {
		return NULL;
	}
	if (status == NSS_STATUS_RETURN) {
		report_nss_error(status);
		return NULL;
	}
	return &pwd;
}

static struct passwd *nss_getpwnam(const char *name)
{
	NSS_STATUS (*_nss_getpwnam_r)(const char *, struct passwd *, char *, 
				      size_t , int *) = find_fn("_nss_winbind_getpwnam_r");
	static struct passwd pwd;
	static char buf[1000];
	NSS_STATUS status;
	
	status = _nss_getpwnam_r(name, &pwd, buf, sizeof(buf), &nss_errno);
	if (status == NSS_STATUS_NOTFOUND) {
		return NULL;
	}
	if (status == NSS_STATUS_RETURN) {
		report_nss_error(status);
		return NULL;
	}
	return &pwd;
}

static struct passwd *nss_getpwuid(uid_t uid)
{
	NSS_STATUS (*_nss_getpwuid_r)(uid_t , struct passwd *, char *, 
				      size_t , int *) = find_fn("_nss_winbind_getpwuid_r");
	static struct passwd pwd;
	static char buf[1000];
	NSS_STATUS status;
	
	status = _nss_getpwuid_r(uid, &pwd, buf, sizeof(buf), &nss_errno);
	if (status == NSS_STATUS_NOTFOUND) {
		return NULL;
	}
	if (status == NSS_STATUS_RETURN) {
		report_nss_error(status);
		return NULL;
	}
	return &pwd;
}

static void nss_setpwent(void)
{
	NSS_STATUS (*_nss_setpwent)(void) = find_fn("_nss_winbind_setpwent");

	report_nss_error(_nss_setpwent());
}

static void nss_endpwent(void)
{
	NSS_STATUS (*_nss_endpwent)(void) = find_fn("_nss_winbind_endpwent");

	report_nss_error(_nss_endpwent());
}


static struct group *nss_getgrent(void)
{
	NSS_STATUS (*_nss_getgrent_r)(struct group *, char *, 
				      size_t , int *) = find_fn("_nss_winbind_getgrent_r");
	static struct group grp;
	static char buf[1000];
	NSS_STATUS status;
	
	status = _nss_getgrent_r(&grp, buf, sizeof(buf), &nss_errno);
	if (status == NSS_STATUS_NOTFOUND) {
		return NULL;
	}
	if (status == NSS_STATUS_RETURN) {
		report_nss_error(status);
		return NULL;
	}
	return &grp;
}

static struct group *nss_getgrnam(const char *name)
{
	NSS_STATUS (*_nss_getgrnam_r)(const char *, struct group *, char *, 
				      size_t , int *) = find_fn("_nss_winbind_getgrnam_r");
	static struct group grp;
	static char buf[1000];
	NSS_STATUS status;
	
	status = _nss_getgrnam_r(name, &grp, buf, sizeof(buf), &nss_errno);
	if (status == NSS_STATUS_NOTFOUND) {
		return NULL;
	}
	if (status == NSS_STATUS_RETURN) {
		report_nss_error(status);
		return NULL;
	}
	return &grp;
}

static struct group *nss_getgrgid(gid_t gid)
{
	NSS_STATUS (*_nss_getgrgid_r)(gid_t , struct group *, char *, 
				      size_t , int *) = find_fn("_nss_winbind_getgrgid_r");
	static struct group grp;
	static char buf[1000];
	NSS_STATUS status;
	
	status = _nss_getgrgid_r(gid, &grp, buf, sizeof(buf), &nss_errno);
	if (status == NSS_STATUS_NOTFOUND) {
		return NULL;
	}
	if (status == NSS_STATUS_RETURN) {
		report_nss_error(status);
		return NULL;
	}
	return &grp;
}

static void nss_setgrent(void)
{
	NSS_STATUS (*_nss_setgrent)(void) = find_fn("_nss_winbind_setgrent");

	report_nss_error(_nss_setgrent());
}

static void nss_endgrent(void)
{
	NSS_STATUS (*_nss_endgrent)(void) = find_fn("_nss_winbind_endgrent");

	report_nss_error(_nss_endgrent());
}

static int nss_initgroups(char *user, gid_t group, gid_t **groups, long int *start, long int *size)
{
	NSS_STATUS (*_nss_initgroups)(char *, gid_t , long int *,
				      long int *, gid_t **, long int , int *) = 
		find_fn("_nss_winbind_initgroups_dyn");
	NSS_STATUS status;

	status = _nss_initgroups(user, group, start, size, groups, 0, &nss_errno);
	report_nss_error(status);
	return status;
}

static void print_passwd(struct passwd *pwd)
{
	printf("%s:%s:%d:%d:%s:%s:%s\n", 
	       pwd->pw_name,
	       pwd->pw_passwd,
	       pwd->pw_uid,
	       pwd->pw_gid,
	       pwd->pw_gecos,
	       pwd->pw_dir,
	       pwd->pw_shell);
}

static void print_group(struct group *grp)
{
	int i;
	printf("%s:%s:%d: ", 
	       grp->gr_name,
	       grp->gr_passwd,
	       grp->gr_gid);
	
	if (!grp->gr_mem[0]) {
		printf("\n");
		return;
	}
	
	for (i=0; grp->gr_mem[i+1]; i++) {
		printf("%s, ", grp->gr_mem[i]);
	}
	printf("%s\n", grp->gr_mem[i]);
}

static void nss_test_initgroups(char *name, gid_t gid)
{
	long int size = 16;
	long int start = 1;
	gid_t *groups = NULL;
	int i;

	groups = (gid_t *)malloc(size * sizeof(gid_t));
	groups[0] = gid;

	nss_initgroups(name, gid, &groups, &start, &size);
	for (i=0; i<start-1; i++) {
		printf("%d, ", groups[i]);
	}
	printf("%d\n", groups[i]);
}


static void nss_test_users(void)
{
	struct passwd *pwd;

	nss_setpwent();
	/* loop over all users */
	while ((pwd = nss_getpwent())) {
		printf("Testing user %s\n", pwd->pw_name);
		printf("getpwent:   "); print_passwd(pwd);
		pwd = nss_getpwnam(pwd->pw_name);
		printf("getpwnam:   "); print_passwd(pwd);
		pwd = nss_getpwuid(pwd->pw_uid);
		printf("getpwuid:   "); print_passwd(pwd);
		printf("initgroups: "); nss_test_initgroups(pwd->pw_name, pwd->pw_gid);
		printf("\n");
	}
	nss_endpwent();
}

static void nss_test_groups(void)
{
	struct group *grp;

	nss_setgrent();
	/* loop over all groups */
	while ((grp = nss_getgrent())) {
		printf("Testing group %s\n", grp->gr_name);
		printf("getgrent: "); print_group(grp);
		grp = nss_getgrnam(grp->gr_name);
		printf("getgrnam: "); print_group(grp);
		grp = nss_getgrgid(grp->gr_gid);
		printf("getgrgid: "); print_group(grp);
		printf("\n");
	}
	nss_endgrent();
}


 int main(int argc, char *argv[])
{	
	if (argc > 1) so_path = argv[1];

	nss_test_users();
	nss_test_groups();

	return 0;
}
