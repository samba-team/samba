/* 
   nss sample code for extended winbindd functionality

   Copyright (C) Andrew Tridgell (tridge@samba.org)   

   you are free to use this code in any way you see fit, including
   without restriction, using this code in your own products. You do
   not need to give any attribution.
*/

/*
   compile like this:

      cc -o wbtest wbtest.c -ldl

   and run like this:

      ./wbtest /lib/libnss_winbind.so
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <nss.h>
#include <dlfcn.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

typedef enum nss_status NSS_STATUS;

struct nss_state {
	void *dl_handle;
	char *nss_name;
	char pwnam_buf[512];
};

/*
  find a function in the nss library
*/
static void *find_fn(struct nss_state *nss, const char *name)
{
	void *res;
	char *s = NULL;

	asprintf(&s, "_nss_%s_%s", nss->nss_name, name);
	if (!s) {
		errno = ENOMEM;
		return NULL;
	}
	res = dlsym(nss->dl_handle, s);
	free(s);
	if (!res) {
		errno = ENOENT;
		return NULL;
	}
	return res;
}

/*
  establish a link to the nss library
  Return 0 on success and -1 on error
*/
int nss_open(struct nss_state *nss, const char *nss_path)
{
	char *p;
	p = strrchr(nss_path, '_');
	if (!p) {
		errno = EINVAL;
		return -1;
	}

	nss->nss_name = strdup(p+1);
	p = strchr(nss->nss_name, '.');
	if (p) *p = 0;

	nss->dl_handle = dlopen(nss_path, RTLD_LAZY);
	if (!nss->dl_handle) {
		free(nss->nss_name);
		return -1;
	}

	return 0;
}

/*
  close and cleanup a nss state
*/
void nss_close(struct nss_state *nss)
{
	free(nss->nss_name);
	dlclose(nss->dl_handle);
}

/*
  make a getpwnam call. 
  Return 0 on success and -1 on error
*/
int nss_getpwent(struct nss_state *nss, struct passwd *pwd)
{
	NSS_STATUS (*_nss_getpwent_r)(struct passwd *, char *, 
				      size_t , int *) = find_fn(nss, "getpwent_r");
	NSS_STATUS status;
	int nss_errno = 0;

	if (!_nss_getpwent_r) {
		return -1;
	}

	status = _nss_getpwent_r(pwd, nss->pwnam_buf, sizeof(nss->pwnam_buf), &nss_errno);
	if (status == NSS_STATUS_NOTFOUND) {
		errno = ENOENT;
		return -1;
	}
	if (status != NSS_STATUS_SUCCESS) {
		errno = nss_errno;
		return -1;
	}

	return 0;
}

/*
  make a setpwent call. 
  Return 0 on success and -1 on error
*/
int nss_setpwent(struct nss_state *nss)
{
	NSS_STATUS (*_nss_setpwent)(void) = find_fn(nss, "setpwent");
	NSS_STATUS status;
	if (!_nss_setpwent) {
		return -1;
	}
	status = _nss_setpwent();
	if (status != NSS_STATUS_SUCCESS) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

/*
  make a endpwent call. 
  Return 0 on success and -1 on error
*/
int nss_endpwent(struct nss_state *nss)
{
	NSS_STATUS (*_nss_endpwent)(void) = find_fn(nss, "endpwent");
	NSS_STATUS status;
	if (!_nss_endpwent) {
		return -1;
	}
	status = _nss_endpwent();
	if (status != NSS_STATUS_SUCCESS) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}


/*
  convert a name to a SID
  caller frees
  Return 0 on success and -1 on error
*/
int nss_nametosid(struct nss_state *nss, const char *name, char **sid)
{
	NSS_STATUS (*_nss_nametosid)(const char *, char **, char *, size_t, int *) = 
		find_fn(nss, "nametosid");
	NSS_STATUS status;
	int nss_errno = 0;
	char buf[200];

	if (!_nss_nametosid) {
		return -1;
	}

	status = _nss_nametosid(name, sid, buf, sizeof(buf), &nss_errno);
	if (status == NSS_STATUS_NOTFOUND) {
		errno = ENOENT;
		return -1;
	}
	if (status != NSS_STATUS_SUCCESS) {
		errno = nss_errno;
		return -1;
	}

	*sid = strdup(*sid);

	return 0;
}

/*
  convert a SID to a name
  caller frees
  Return 0 on success and -1 on error
*/
int nss_sidtoname(struct nss_state *nss, char *sid, char **name)
{
	NSS_STATUS (*_nss_sidtoname)(const char *, char **, char *, size_t, int *) = 
		find_fn(nss, "sidtoname");
	NSS_STATUS status;
	int nss_errno = 0;
	char buf[200];

	if (!_nss_sidtoname) {
		return -1;
	}

	status = _nss_sidtoname(sid, name, buf, sizeof(buf), &nss_errno);
	if (status == NSS_STATUS_NOTFOUND) {
		errno = ENOENT;
		return -1;
	}
	if (status != NSS_STATUS_SUCCESS) {
		errno = nss_errno;
		return -1;
	}

	*name = strdup(*name);

	return 0;
}

/*
  return a list of group SIDs for a user SID
  the returned list is NULL terminated
  Return 0 on success and -1 on error
*/
int nss_getusersids(struct nss_state *nss, const char *user_sid, char ***sids)
{
	NSS_STATUS (*_nss_getusersids)(const char *, char **, int *, char *, size_t, int *) = 
		find_fn(nss, "getusersids");
	NSS_STATUS status;
	int nss_errno = 0;
	char *s;
	int i, num_groups = 0;
	unsigned bufsize = 10;
	char *buf;

	if (!_nss_getusersids) {
		return -1;
	}

again:
	buf = malloc(bufsize);
	if (!buf) {
		errno = ENOMEM;
		return -1;
	}

	status = _nss_getusersids(user_sid, &s, &num_groups, buf, bufsize, &nss_errno);
	if (status == NSS_STATUS_NOTFOUND) {
		errno = ENOENT;
		free(buf);
		return -1;
	}
	
	if (status == NSS_STATUS_TRYAGAIN) {
		bufsize *= 2;
		free(buf);
		goto again;
	}

	if (status != NSS_STATUS_SUCCESS) {
		free(buf);
		errno = nss_errno;
		return -1;
	}

	if (num_groups == 0) {
		free(buf);
		return 0;
	}

	*sids = (char **)malloc(sizeof(char *) * (num_groups+1));
	if (! *sids) {
		errno = ENOMEM;
		free(buf);
		return -1;
	}

	for (i=0;i<num_groups;i++) {
		(*sids)[i] = strdup(s);
		s += strlen(s) + 1;
	}
	(*sids)[i] = NULL;

	free(buf);

	return 0;
}


static int nss_test_users(struct nss_state *nss)
{
	struct passwd pwd;

	if (nss_setpwent(nss) != 0) {
		perror("setpwent");
		return -1;
	}

	/* loop over all users */
	while ((nss_getpwent(nss, &pwd) == 0)) {
		char *sid, **group_sids, *name2;
		int i;

		printf("User %s\n", pwd.pw_name);
		if (nss_nametosid(nss, pwd.pw_name, &sid) != 0) {
			perror("nametosid");
			return -1;
		}
		printf("\tSID %s\n", sid);

		if (nss_sidtoname(nss, sid, &name2) != 0) {
			perror("sidtoname");
			return -1;
		}
		printf("\tSID->name %s\n", name2);

		if (nss_getusersids(nss, sid, &group_sids) != 0) {
			perror("getusersids");
			return -1;
		}

		printf("\tGroups:\n");
		for (i=0; group_sids[i]; i++) {
			printf("\t\t%s\n", group_sids[i]);
			free(group_sids[i]);
		}

		free(sid);
		free(name2);
		free(group_sids);
	}


	if (nss_endpwent(nss) != 0) {
		perror("endpwent");
		return -1;
	}

	return 0;
}


/*
  main program. It lists all users, listing user SIDs for each user
 */
int main(int argc, char *argv[])
{	
	struct nss_state nss;
	const char *so_path = "/lib/libnss_winbind.so";
	int ret;

	if (argc > 1) {
		so_path = argv[1];
	}

	if (nss_open(&nss, so_path) != 0) {
		perror("nss_open");
		exit(1);
	}

	ret = nss_test_users(&nss);

	nss_close(&nss);

	return ret;
}
