/* 
   Unix SMB/CIFS implementation.

   AIX loadable authentication module, providing identification 
   routines against Samba winbind/Windows NT Domain

   Copyright (C) Tim Potter 2003
   Copyright (C) Steve Roylance 2003
   Copyright (C) Andrew Tridgell 2003
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

/*
  see 
  http://publib16.boulder.ibm.com/doc_link/en_US/a_doc_lib/aixprggd/kernextc/sec_load_mod.htm
  for information in the interface that this module implements
*/

#include <stdlib.h>
#include <string.h>
#include <usersec.h>
#include <errno.h>
#include <stdarg.h>

#include "winbind_client.h"

/*
  the documentation doesn't say so, but experimentation shows that all
  of the functions need to return static data, and the area can be
  freed only when the same function is called again, or the close
  method is called on the module. Note that this matches the standard
  behaviour of functions like getpwnam().

  The most puzzling thing about this AIX interface is that it seems to
  offer no way of providing a user or group enumeration method. You
  can find out any amount of detail about a user or group once you
  know the name, but you can't obtain a list of those names. If anyone
  does find out how to do this then please let me know (yes, I should
  be able to find out as I work for IBM, and this is an IBM interface,
  but finding the right person to ask is a mammoth task!)

  tridge@samba.org October 2003
*/


/* 
   each function uses one of the following lists of memory, declared 
   static in each backend method. This allows the function to destroy
   the memory when that backend is called next time
*/
struct mem_list {
	struct mem_list *next, *prev;
	void *p;
};


/* allocate some memory on a mem_list */
static void *list_alloc(struct mem_list **list, size_t size)
{
	struct mem_list *m;
	m = malloc(sizeof(*m));
	if (!m) {
		errno = ENOMEM;
		return NULL;
	}
	m->p = malloc(size);
	if (!m->p) {
		errno = ENOMEM;
		free(m);
		return NULL;
	}
	m->next = *list;
	m->prev = NULL;
	if (*list) {
		(*list)->prev = m;
	}
	(*list) = m;
	return m->p;
}

/* duplicate a string using list_alloc() */
static char *list_strdup(struct mem_list **list, const char *s)
{
	char *ret = list_alloc(list, strlen(s)+1);
	if (!ret) return NULL;
	strcpy(ret, s);
	return ret;
}

/* destroy a mem_list */
static void list_destory(struct mem_list **list)
{
	struct mem_list *m, *next;
	for (m=*list; m; m=next) {
		next = m->next;
		free(m->p);
		free(m);
	}
	(*list) = NULL;
}


#define HANDLE_ERRORS(ret) do { \
	if ((ret) == NSS_STATUS_NOTFOUND) { \
		errno = ENOENT; \
		return NULL; \
	} else if ((ret) != NSS_STATUS_SUCCESS) { \
		errno = EIO; \
		return NULL; \
	} \
} while (0)

/*
  fill a struct passwd from a winbindd_pw struct, using memory from a mem_list
*/
static struct passwd *fill_pwent(struct mem_list **list, struct winbindd_pw *pw)
{
	struct passwd *result;

	if (!(result = list_alloc(list, sizeof(struct passwd)))) {
		return NULL;
	}

	ZERO_STRUCTP(result);

	result->pw_uid = pw->pw_uid;
	result->pw_gid = pw->pw_gid;

	/* strings */
	if ((result->pw_name =   list_strdup(list, pw->pw_name)) == NULL ||
	    (result->pw_passwd = list_strdup(list, pw->pw_passwd)) == NULL ||
	    (result->pw_gecos =  list_strdup(list, pw->pw_gecos)) == NULL ||
	    (result->pw_dir =    list_strdup(list, pw->pw_dir)) == NULL ||
	    (result->pw_shell =  list_strdup(list, pw->pw_shell)) == NULL) {
		return NULL;
	}
	
	return result;
}


/*
  fill a struct group from a winbindd_pw struct, using memory from a mem_list
*/
static struct group *fill_grent(struct mem_list **list, struct winbindd_gr *gr, char *gr_mem)
{
	int i;
	char *tst;
	struct group *result;
	char *name, *p;

	if (!(result = list_alloc(list, sizeof(struct group)))) {
		return NULL;
	}

	ZERO_STRUCTP(result);

	result->gr_gid = gr->gr_gid;

	/* Group name */
	if ((result->gr_name = list_strdup(list, gr->gr_name)) == NULL ||
	    (result->gr_passwd = list_strdup(list, gr->gr_passwd)) == NULL) {
		return NULL;
	}

	/* Group membership */
	if ((gr->num_gr_mem < 0) || !gr_mem) {
		gr->num_gr_mem = 0;
	}
	
	if (gr->num_gr_mem == 0) {
		/* Group is empty */		
		return result;
	}
	
	tst = list_alloc(list, (gr->num_gr_mem + 1) * sizeof(char *));
	if (!tst) {
		return NULL;
	}
		
	result->gr_mem = (char **)tst;

	/* Start looking at extra data */
	i=0;
	for (name = strtok_r(gr_mem, ",", &p); 
	     name; 
	     name = strtok_r(NULL, ",", &p)) {
		if (i >= gr->num_gr_mem) {
			return NULL;
		}
		(result->gr_mem)[i] = list_strdup(list, name);
		if ((result->gr_mem)[i] == NULL) {
			return NULL;
		}
		i++;
	}

	/* Terminate list */
	(result->gr_mem)[i] = NULL;

	return result;
}



/* take a group id and return a filled struct group */	
static struct group *wb_aix_getgrgid(gid_t gid)
{
	static struct mem_list *list;
	struct winbindd_response response;
	struct winbindd_request request;
	struct group *grp;
	NSS_STATUS ret;

	list_destory(&list);

	ZERO_STRUCT(response);
	ZERO_STRUCT(request);
	
	request.data.gid = gid;

	ret = winbindd_request(WINBINDD_GETGRGID, &request, &response);

	HANDLE_ERRORS(ret);

	grp = fill_grent(&list, &response.data.gr, response.extra_data);

	free_response(&response);

	return grp;
}

/* take a group name and return a filled struct group */
static struct group *wb_aix_getgrnam(const char *name)
{
	static struct mem_list *list;
	struct winbindd_response response;
	struct winbindd_request request;
	NSS_STATUS ret;
	struct group *grp;

	list_destory(&list);

	ZERO_STRUCT(response);
	ZERO_STRUCT(request);

	if (strlen(name)+1 > sizeof(request.data.groupname)) {
		errno = EINVAL;
		return NULL;
	}
	strcpy(request.data.groupname, name);

	ret = winbindd_request(WINBINDD_GETGRNAM, &request, &response);
	
	HANDLE_ERRORS(ret);

	grp = fill_grent(&list, &response.data.gr, response.extra_data);

	free_response(&response);

	return grp;
}


/* take a username and return a string containing a comma-separated
   list of group id numbers to which the user belongs */
static char *wb_aix_getgrset(char *user)
{
	static struct mem_list *list;
	struct winbindd_response response;
	struct winbindd_request request;
	NSS_STATUS ret;
	int i, idx;
	char *tmpbuf;
	int num_gids;
	gid_t *gid_list;

	list_destory(&list);

	if (strlen(user)+1 > sizeof(request.data.username)) {
		errno = EINVAL;
		return NULL;
	}
	strcpy(request.data.username, user);

	ret = winbindd_request(WINBINDD_GETGROUPS, &request, &response);

	HANDLE_ERRORS(ret);

	num_gids = response.data.num_entries;
	gid_list = (gid_t *)response.extra_data;
		
	/* allocate a space large enough to contruct the string */
	tmpbuf = list_alloc(&list, num_gids*12);
	if (!tmpbuf) {
		return NULL;
	}

	for (idx=i=0; i < num_gids-1; i++) {
		idx += sprintf(tmpbuf+idx, "%u,", gid_list[i]);	
	}
	idx += sprintf(tmpbuf+idx, "%u", gid_list[i]);	

	free_response(&response);

	return tmpbuf;
}


/* take a uid and return a filled struct passwd */	
static struct passwd *wb_aix_getpwuid(uid_t uid)
{
	static struct mem_list *list;
	struct winbindd_response response;
	struct winbindd_request request;
	NSS_STATUS ret;

	list_destory(&list);
	
	ZERO_STRUCT(response);
	ZERO_STRUCT(request);
		
	request.data.uid = uid;
	
	ret = winbindd_request(WINBINDD_GETPWUID, &request, &response);

	HANDLE_ERRORS(ret);

	return fill_pwent(&list, &response.data.pw);
}


/* take a username and return a filled struct passwd */
static struct passwd *wb_aix_getpwnam(const char *name)
{
	static struct mem_list *list;
	struct winbindd_response response;
	struct winbindd_request request;
	NSS_STATUS ret;

	list_destory(&list);
	
	ZERO_STRUCT(response);
	ZERO_STRUCT(request);

	if (strlen(name)+1 > sizeof(request.data.username)) {
		errno = EINVAL;
		return NULL;
	}

	strcpy(request.data.username, name);

	ret = winbindd_request(WINBINDD_GETPWNAM, &request, &response);

	HANDLE_ERRORS(ret);
	
	return fill_pwent(&list, &response.data.pw);
}

int wb_aix_init(struct secmethod_table *methods)
{
	ZERO_STRUCTP(methods);

	/* identification methods, this is the minimum requried for a
	   working module */
    
	methods->method_getgrgid = wb_aix_getgrgid;
	methods->method_getgrnam = wb_aix_getgrnam;
	methods->method_getgrset = wb_aix_getgrset;
	methods->method_getpwnam = wb_aix_getpwnam;
	methods->method_getpwuid = wb_aix_getpwuid;

	return AUTH_SUCCESS;
}

