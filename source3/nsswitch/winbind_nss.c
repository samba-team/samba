/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Windows NT Domain nsswitch module

   Copyright (C) Tim Potter 2000
   
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

#include "winbind_nss_config.h"
#include "winbindd_nss.h"

/* Prototypes from common.c */

void init_request(struct winbindd_request *req,int rq_type);
NSS_STATUS winbindd_request(int req_type, 
				 struct winbindd_request *request,
				 struct winbindd_response *response);
int write_sock(void *buffer, int count);
int read_reply(struct winbindd_response *response);
void free_response(struct winbindd_response *response);

/* Allocate some space from the nss static buffer.  The buffer and buflen
   are the pointers passed in by the C library to the _nss_ntdom_*
   functions. */

static char *get_static(char **buffer, int *buflen, int len)
{
	char *result;

	/* Error check.  We return false if things aren't set up right, or
	   there isn't enough buffer space left. */
	
	if ((buffer == NULL) || (buflen == NULL) || (*buflen < len)) {
		return NULL;
	}

	/* Some architectures, like Sparc, need pointers aligned on 
	   boundaries */
#if _ALIGNMENT_REQUIRED
	{
		int mod = len % _MAX_ALIGNMENT;
		if(mod != 0)
			len += _MAX_ALIGNMENT - mod;
	}
#endif

	/* Return an index into the static buffer */

	result = *buffer;
	*buffer += len;
	*buflen -= len;

	return result;
}

/* I've copied the strtok() replacement function next_token() from
   lib/util_str.c as I really don't want to have to link in any other
   objects if I can possibly avoid it. */

BOOL next_token(char **ptr,char *buff,char *sep, size_t bufsize)
{
	char *s;
	BOOL quoted;
	size_t len=1;

	if (!ptr) return(False);

	s = *ptr;

	/* default to simple separators */
	if (!sep) sep = " \t\n\r";

	/* find the first non sep char */
	while (*s && strchr(sep,*s)) s++;
	
	/* nothing left? */
	if (! *s) return(False);
	
	/* copy over the token */
	for (quoted = False; len < bufsize && *s && (quoted || !strchr(sep,*s)); s++) {
		if (*s == '\"') {
			quoted = !quoted;
		} else {
			len++;
			*buff++ = *s;
		}
	}
	
	*ptr = (*s) ? s+1 : s;  
	*buff = 0;
	
	return(True);
}


/* Fill a pwent structure from a winbindd_response structure.  We use
   the static data passed to us by libc to put strings and stuff in.
   Return NSS_STATUS_TRYAGAIN if we run out of memory. */

static NSS_STATUS fill_pwent(struct passwd *result,
				  struct winbindd_pw *pw,
				  char **buffer, int *buflen)
{
	/* User name */

	if ((result->pw_name = 
	     get_static(buffer, buflen, strlen(pw->pw_name) + 1)) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}

	strcpy(result->pw_name, pw->pw_name);

	/* Password */

	if ((result->pw_passwd = 
	     get_static(buffer, buflen, strlen(pw->pw_passwd) + 1)) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}

	strcpy(result->pw_passwd, pw->pw_passwd);
        
	/* [ug]id */

	result->pw_uid = pw->pw_uid;
	result->pw_gid = pw->pw_gid;

	/* GECOS */

	if ((result->pw_gecos = 
	     get_static(buffer, buflen, strlen(pw->pw_gecos) + 1)) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}

	strcpy(result->pw_gecos, pw->pw_gecos);
	
	/* Home directory */
	
	if ((result->pw_dir = 
	     get_static(buffer, buflen, strlen(pw->pw_dir) + 1)) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}

	strcpy(result->pw_dir, pw->pw_dir);

	/* Logon shell */
	
	if ((result->pw_shell = 
	     get_static(buffer, buflen, strlen(pw->pw_shell) + 1)) == NULL) {
		
		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}

	strcpy(result->pw_shell, pw->pw_shell);

	return NSS_STATUS_SUCCESS;
}

/* Fill a grent structure from a winbindd_response structure.  We use
   the static data passed to us by libc to put strings and stuff in.
   Return NSS_STATUS_TRYAGAIN if we run out of memory. */

static int fill_grent(struct group *result, struct winbindd_gr *gr,
		      char *gr_mem, char **buffer, int *buflen)
{
	fstring name;
	int i;

	/* Group name */

	if ((result->gr_name =
	     get_static(buffer, buflen, strlen(gr->gr_name) + 1)) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}

	strcpy(result->gr_name, gr->gr_name);

	/* Password */

	if ((result->gr_passwd =
	     get_static(buffer, buflen, strlen(gr->gr_passwd) + 1)) == NULL) {

		/* Out of memory */
		
		return NSS_STATUS_TRYAGAIN;
	}

	strcpy(result->gr_passwd, gr->gr_passwd);

	/* gid */

	result->gr_gid = gr->gr_gid;

	/* Group membership */

	if ((gr->num_gr_mem < 0) || !gr_mem) {
		gr->num_gr_mem = 0;
	}

	if ((result->gr_mem = 
	     (char **)get_static(buffer, buflen, (gr->num_gr_mem + 1) * 
				 sizeof(char *))) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}

	if (gr->num_gr_mem == 0) {

		/* Group is empty */

		*(result->gr_mem) = NULL;
		return NSS_STATUS_SUCCESS;
	}

	/* Start looking at extra data */

	i = 0;

	while(next_token((char **)&gr_mem, name, ",", sizeof(fstring))) {
        
		/* Allocate space for member */
        
		if (((result->gr_mem)[i] = 
		     get_static(buffer, buflen, strlen(name) + 1)) == NULL) {
            
			/* Out of memory */
            
			return NSS_STATUS_TRYAGAIN;
		}        
        
		strcpy((result->gr_mem)[i], name);
		i++;
	}

	/* Terminate list */

	(result->gr_mem)[i] = NULL;

	return NSS_STATUS_SUCCESS;
}

/*
 * NSS user functions
 */

static struct winbindd_response getpwent_response;

static int ndx_pw_cache;                 /* Current index into pwd cache */
static int num_pw_cache;                 /* Current size of pwd cache */

/* Rewind "file pointer" to start of ntdom password database */

NSS_STATUS
_nss_winbind_setpwent(void)
{
#ifdef DEBUG_NSS
	fprintf(stderr, "[%5d]: setpwent\n", getpid());
#endif

	if (num_pw_cache > 0) {
		ndx_pw_cache = num_pw_cache = 0;
		free_response(&getpwent_response);
	}

	return winbindd_request(WINBINDD_SETPWENT, NULL, NULL);
}

/* Close ntdom password database "file pointer" */

NSS_STATUS
_nss_winbind_endpwent(void)
{
#ifdef DEBUG_NSS
	fprintf(stderr, "[%5d]: endpwent\n", getpid());
#endif

	if (num_pw_cache > 0) {
		ndx_pw_cache = num_pw_cache = 0;
		free_response(&getpwent_response);
	}

	return winbindd_request(WINBINDD_ENDPWENT, NULL, NULL);
}

/* Fetch the next password entry from ntdom password database */

#define MAX_GETPWENT_USERS 250

NSS_STATUS
_nss_winbind_getpwent_r(struct passwd *result, char *buffer, 
			size_t buflen, int *errnop)
{
	NSS_STATUS ret;
	struct winbindd_request request;
	static int called_again;

#ifdef DEBUG_NSS
	fprintf(stderr, "[%5d]: getpwent\n", getpid());
#endif

	/* Return an entry from the cache if we have one, or if we are
	   called again because we exceeded our static buffer.  */

	if ((ndx_pw_cache < num_pw_cache) || called_again) {
		goto return_result;
	}

	/* Else call winbindd to get a bunch of entries */
	
	if (num_pw_cache > 0) {
		free_response(&getpwent_response);
	}

	ZERO_STRUCT(request);
	ZERO_STRUCT(getpwent_response);

	request.data.num_entries = MAX_GETPWENT_USERS;

	ret = winbindd_request(WINBINDD_GETPWENT, &request, 
			       &getpwent_response);

	if (ret == NSS_STATUS_SUCCESS) {
		struct winbindd_pw *pw_cache;

		/* Fill cache */

		ndx_pw_cache = 0;
		num_pw_cache = getpwent_response.data.num_entries;

		/* Return a result */

	return_result:

		pw_cache = getpwent_response.extra_data;

		/* Check data is valid */

		if (pw_cache == NULL) {
			return NSS_STATUS_NOTFOUND;
		}

		ret = fill_pwent(result, &pw_cache[ndx_pw_cache],
				 &buffer, &buflen);
		
		/* Out of memory - try again */

		if (ret == NSS_STATUS_TRYAGAIN) {
			called_again = True;
			*errnop = errno = ERANGE;
			return ret;
		}

		*errnop = errno = 0;
		called_again = False;
		ndx_pw_cache++;

		/* If we've finished with this lot of results free cache */

		if (ndx_pw_cache == num_pw_cache) {
			ndx_pw_cache = num_pw_cache = 0;
			free_response(&getpwent_response);
		}
	}

	return ret;
}

/* Return passwd struct from uid */

NSS_STATUS
_nss_winbind_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
			size_t buflen, int *errnop)
{
	NSS_STATUS ret;
	static struct winbindd_response response;
	struct winbindd_request request;
	static int keep_response=0;

	/* If our static buffer needs to be expanded we are called again */
	if (!keep_response) {

		/* Call for the first time */

		ZERO_STRUCT(response);
		ZERO_STRUCT(request);

		request.data.uid = uid;

		ret = winbindd_request(WINBINDD_GETPWNAM_FROM_UID, &request, 
				       &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_pwent(result, &response.data.pw, 
					 &buffer, &buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = errno = ERANGE;
				return ret;
			}
		}

	} else {

		/* We've been called again */

		ret = fill_pwent(result, &response.data.pw, &buffer, &buflen);

		if (ret == NSS_STATUS_TRYAGAIN) {
			keep_response = True;
			*errnop = errno = ERANGE;
			return ret;
		}

		keep_response = False;
		*errnop = errno = 0;
	}

	free_response(&response);
	return ret;
}

/* Return passwd struct from username */

NSS_STATUS
_nss_winbind_getpwnam_r(const char *name, struct passwd *result, char *buffer,
			size_t buflen, int *errnop)
{
	NSS_STATUS ret;
	static struct winbindd_response response;
	struct winbindd_request request;
	static int keep_response;

#ifdef DEBUG_NSS
	fprintf(stderr, "[%5d]: getpwnam %s\n", getpid(), name);
#endif

	/* If our static buffer needs to be expanded we are called again */

	if (!keep_response) {

		/* Call for the first time */

		ZERO_STRUCT(response);
		ZERO_STRUCT(request);

		strncpy(request.data.username, name, 
			sizeof(request.data.username) - 1);
		request.data.username
			[sizeof(request.data.username) - 1] = '\0';

		ret = winbindd_request(WINBINDD_GETPWNAM_FROM_USER, &request, 
				       &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_pwent(result, &response.data.pw, &buffer,
					 &buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = errno = ERANGE;
				return ret;
			}
		}

	} else {

		/* We've been called again */

		ret = fill_pwent(result, &response.data.pw, &buffer, &buflen);

		if (ret == NSS_STATUS_TRYAGAIN) {
			keep_response = True;
			*errnop = errno = ERANGE;
			return ret;
		}

		keep_response = False;
		*errnop = errno = 0;
	}

	free_response(&response);
	return ret;
}

/*
 * NSS group functions
 */

static struct winbindd_response getgrent_response;

static int ndx_gr_cache;                 /* Current index into grp cache */
static int num_gr_cache;                 /* Current size of grp cache */

/* Rewind "file pointer" to start of ntdom group database */

NSS_STATUS
_nss_winbind_setgrent(void)
{
#ifdef DEBUG_NSS
	fprintf(stderr, "[%5d]: setgrent\n", getpid());
#endif

	if (num_gr_cache > 0) {
		ndx_gr_cache = num_gr_cache = 0;
		free_response(&getgrent_response);
	}

	return winbindd_request(WINBINDD_SETGRENT, NULL, NULL);
}

/* Close "file pointer" for ntdom group database */

NSS_STATUS
_nss_winbind_endgrent(void)
{
#ifdef DEBUG_NSS
	fprintf(stderr, "[%5d]: endgrent\n", getpid());
#endif

	if (num_gr_cache > 0) {
		ndx_gr_cache = num_gr_cache = 0;
		free_response(&getgrent_response);
	}

	return winbindd_request(WINBINDD_ENDGRENT, NULL, NULL);
}

/* Get next entry from ntdom group database */

#define MAX_GETGRENT_USERS 250

NSS_STATUS
_nss_winbind_getgrent_r(struct group *result,
			char *buffer, size_t buflen, int *errnop)
{
	NSS_STATUS ret;
	static struct winbindd_request request;
	static int called_again;

#ifdef DEBUG_NSS
	fprintf(stderr, "[%5d]: getgrent\n", getpid());
#endif

	/* Return an entry from the cache if we have one, or if we are
	   called again because we exceeded our static buffer.  */

	if ((ndx_gr_cache < num_gr_cache) || called_again) {
		goto return_result;
	}

	/* Else call winbindd to get a bunch of entries */
	
	if (num_gr_cache > 0) {
		free_response(&getgrent_response);
	}

	ZERO_STRUCT(request);
	ZERO_STRUCT(getgrent_response);

	request.data.num_entries = MAX_GETGRENT_USERS;

	ret = winbindd_request(WINBINDD_GETGRENT, &request, 
			       &getgrent_response);

	if (ret == NSS_STATUS_SUCCESS) {
		struct winbindd_gr *gr_cache;
		int mem_ofs;

		/* Fill cache */

		ndx_gr_cache = 0;
		num_gr_cache = getgrent_response.data.num_entries;

		/* Return a result */

	return_result:

		gr_cache = getgrent_response.extra_data;

		/* Check data is valid */

		if (gr_cache == NULL) {
			return NSS_STATUS_NOTFOUND;
		}

		/* Fill group membership.  The offset into the extra data
		   for the group membership is the reported offset plus the
		   size of all the winbindd_gr records returned. */

		mem_ofs = gr_cache[ndx_gr_cache].gr_mem_ofs +
			num_gr_cache * sizeof(struct winbindd_gr);

		ret = fill_grent(result, &gr_cache[ndx_gr_cache],
				 ((char *)getgrent_response.extra_data)+mem_ofs,
				 &buffer, &buflen);
		
		/* Out of memory - try again */

		if (ret == NSS_STATUS_TRYAGAIN) {
			called_again = True;
			*errnop = errno = ERANGE;
			return ret;
		}

		*errnop = 0;
		called_again = False;
		ndx_gr_cache++;

		/* If we've finished with this lot of results free cache */

		if (ndx_gr_cache == num_gr_cache) {
			ndx_gr_cache = num_gr_cache = 0;
			free_response(&getgrent_response);
		}
	}

	return ret;
}

/* Return group struct from group name */

NSS_STATUS
_nss_winbind_getgrnam_r(const char *name,
			struct group *result, char *buffer,
			size_t buflen, int *errnop)
{
	NSS_STATUS ret;
	static struct winbindd_response response;
	struct winbindd_request request;
	static int keep_response;
	
#ifdef DEBUG_NSS
	fprintf(stderr, "[%5d]: getgrnam %s\n", getpid(), name);
#endif

	/* If our static buffer needs to be expanded we are called again */
	
	if (!keep_response) {

		/* Call for the first time */

		ZERO_STRUCT(request);
		ZERO_STRUCT(response);

		strncpy(request.data.groupname, name, 
			sizeof(request.data.groupname));
		request.data.groupname
			[sizeof(request.data.groupname) - 1] = '\0';

		ret = winbindd_request(WINBINDD_GETGRNAM_FROM_GROUP, 
				       &request, &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_grent(result, &response.data.gr, 
					 response.extra_data,
					 &buffer, &buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = errno = ERANGE;
				return ret;
			}
		}

	} else {
		
		/* We've been called again */
		
		ret = fill_grent(result, &response.data.gr, 
				 response.extra_data, &buffer, &buflen);
		
		if (ret == NSS_STATUS_TRYAGAIN) {
			keep_response = True;
			*errnop = errno = ERANGE;
			return ret;
		}

		keep_response = False;
		*errnop = 0;
	}

	free_response(&response);
	return ret;
}

/* Return group struct from gid */

NSS_STATUS
_nss_winbind_getgrgid_r(gid_t gid,
			struct group *result, char *buffer,
			size_t buflen, int *errnop)
{
	NSS_STATUS ret;
	static struct winbindd_response response;
	struct winbindd_request request;
	static int keep_response;

#ifdef DEBUG_NSS
	fprintf(stderr, "[%5d]: getgrgid %d\n", getpid(), gid);
#endif

	/* If our static buffer needs to be expanded we are called again */

	if (!keep_response) {

		/* Call for the first time */

		ZERO_STRUCT(request);
		ZERO_STRUCT(response);

		request.data.gid = gid;

		ret = winbindd_request(WINBINDD_GETGRNAM_FROM_GID, &request, 
				       &response);

		if (ret == NSS_STATUS_SUCCESS) {

			ret = fill_grent(result, &response.data.gr, 
					 response.extra_data, 
					 &buffer, &buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = errno = ERANGE;
				return ret;
			}
		}

	} else {

		/* We've been called again */

		ret = fill_grent(result, &response.data.gr, 
				 response.extra_data, &buffer, &buflen);

		if (ret == NSS_STATUS_TRYAGAIN) {
			keep_response = True;
			*errnop = errno = ERANGE;
			return ret;
		}

		keep_response = False;
		*errnop = 0;
	}

	free_response(&response);
	return ret;
}

/* Initialise supplementary groups */

NSS_STATUS
_nss_winbind_initgroups_dyn(char *user, gid_t group, long int *start,
			    long int *size, gid_t **groups, long int limit,
			    int *errnop)
{
	NSS_STATUS ret;
	struct winbindd_request request;
	struct winbindd_response response;
	int i;

#ifdef DEBUG_NSS
	fprintf(stderr, "[%5d]: initgroups %s (%d)\n", getpid(),
		user, group);
#endif

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	strncpy(request.data.username, user,
		sizeof(request.data.username) - 1);

	ret = winbindd_request(WINBINDD_GETGROUPS, &request, &response);

	if (ret == NSS_STATUS_SUCCESS) {
		int num_gids = response.data.num_entries;
		gid_t *gid_list = (gid_t *)response.extra_data;

		/* Copy group list to client */

		for (i = 0; i < num_gids; i++) {

			/* Skip primary group */

			if (gid_list[i] == group) continue;

			/* Add to buffer */

			if (*start == *size && limit <= 0) {
				(*groups) = realloc(
					(*groups), (2 * (*size) + 1) * sizeof(**groups));
				if (! *groups) goto done;
				*size = 2 * (*size) + 1;
			}

			if (*start == *size) goto done;

			(*groups)[*start] = gid_list[i];
			*start += 1;

			/* Filled buffer? */

			if (*start == limit) goto done;
		}
	}
	
	/* Back to your regularly scheduled programming */

 done:
	return ret;
}
