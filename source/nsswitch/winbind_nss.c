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
enum nss_status generic_request(int req_type, 
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

	/* Return an index into the static buffer */

	result = *buffer;
	*buffer += len;
	*buflen -= len;

	return result;
}

/* I've copied the strtok() replacement function next_token() from
   lib/util_str.c as I really don't want to have to link in any other
   objects if I can possibly avoid it. */

static char *last_ptr = NULL;

BOOL next_token(char **ptr, char *buff, char *sep, size_t bufsize)
{
	char *s;
	BOOL quoted;
	size_t len=1;
    
	if (!ptr) ptr = &last_ptr;
	if (!ptr) return(False);
    
	s = *ptr;
    
	/* default to simple separators */
	if (!sep) sep = " \t\n\r";
    
	/* find the first non sep char */
	while(*s && strchr(sep,*s)) s++;
    
	/* nothing left? */
	if (! *s) return(False);
    
	/* copy over the token */
	for (quoted = False; 
	     len < bufsize && *s && (quoted || !strchr(sep,*s)); 
	     s++) {

		if (*s == '\"') {
			quoted = !quoted;
		} else {
			len++;
			*buff++ = *s;
		}
	}
    
	*ptr = (*s) ? s+1 : s;  
	*buff = 0;
	last_ptr = *ptr;
  
	return(True);
}

/* Fill a pwent structure from a winbindd_response structure.  We use
   the static data passed to us by libc to put strings and stuff in.
   Return NSS_STATUS_TRYAGAIN if we run out of memory. */

static enum nss_status fill_pwent(struct passwd *result,
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

static int fill_grent(struct group *result, 
                      struct winbindd_response *response,
                      char **buffer, int *buflen)
{
	struct winbindd_gr *gr = &response->data.gr;
	char *tmp_data;
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

	if ((gr->num_gr_mem < 0) || !response->extra_data) {
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
	tmp_data = response->extra_data;

	while(next_token((char **)&tmp_data, name, ",", 
			 sizeof(fstring))) {
        
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

static int ndx_pw_cache;                 /* Current index into cache */
static int num_pw_cache;                 /* Current size of cache */

/* Rewind "file pointer" to start of ntdom password database */

enum nss_status
_nss_winbind_setpwent(void)
{
	if (num_pw_cache > 0) {
		free_response(&getpwent_response);
	}

	return generic_request(WINBINDD_SETPWENT, NULL, NULL);
}

/* Close ntdom password database "file pointer" */

enum nss_status
_nss_winbind_endpwent(void)
{
	if (num_pw_cache > 0) {
		free_response(&getpwent_response);
	}

	return generic_request(WINBINDD_ENDPWENT, NULL, NULL);
}

/* Fetch the next password entry from ntdom password database */

#define MAX_GETPWENT_USERS 250

enum nss_status
_nss_winbind_getpwent_r(struct passwd *result, char *buffer, 
                      size_t buflen, int *errnop)
{
	enum nss_status ret;
	struct winbindd_request request;
	static int called_again;

	/* Return an entry from the cache if we have one, or if we are
	   called again because we exceeded our static buffer.  */

	if ((ndx_pw_cache < num_pw_cache) || called_again) {
		goto return_result;
	}

	/* Else call winbind to get a bunch of entries */
	
	if (num_pw_cache > 0) {
		free_response(&getpwent_response);
	}

	ZERO_STRUCT(request);
	ZERO_STRUCT(getpwent_response);

	request.data.num_entries = MAX_GETPWENT_USERS;

	ret = generic_request(WINBINDD_GETPWENT, &request, &getpwent_response);

	if (ret == NSS_STATUS_SUCCESS) {
		struct winbindd_pw *pw_cache;

		/* Fill cache */

		ndx_pw_cache = 0;
		num_pw_cache = getpwent_response.data.num_entries;

		pw_cache = getpwent_response.extra_data;

		/* Return a result */

	return_result:

		ret = fill_pwent(result, &pw_cache[ndx_pw_cache],
				 &buffer, &buflen);
		
		/* Out of memory - try again */

		if (ret == NSS_STATUS_TRYAGAIN) {
			called_again = True;
			*errnop = ERANGE;
			return ret;
		}

		*errnop = 0;
		called_again = False;
		ndx_pw_cache++;

		/* We've finished with this lot of results so free cache */

		if (ndx_pw_cache == num_pw_cache) {
			free_response(&getpwent_response);
		}
	}

	return ret;
}

/* Return passwd struct from uid */

enum nss_status
_nss_winbind_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
                      size_t buflen, int *errnop)
{
	enum nss_status ret;
	static struct winbindd_response response;
	struct winbindd_request request;
	static int keep_response;

	/* If our static buffer needs to be expanded we are called again */

	if (!keep_response) {

		/* Call for the first time */

		ZERO_STRUCT(response);
		ZERO_STRUCT(request);

		request.data.uid = uid;

		ret = generic_request(WINBINDD_GETPWNAM_FROM_UID, &request, 
				      &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_pwent(result, &response.data.pw, 
					 &buffer, &buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = ERANGE;
				return ret;
			}
		}

	} else {

		/* We've been called again */

		ret = fill_pwent(result, &response.data.pw, &buffer, &buflen);

		if (ret == NSS_STATUS_TRYAGAIN) {
			keep_response = True;
			*errnop = ERANGE;
			return ret;
		}

		keep_response = False;
		*errnop = 0;
	}

	free_response(&response);
	return ret;
}

/* Return passwd struct from username */

enum nss_status
_nss_winbind_getpwnam_r(const char *name, struct passwd *result, char *buffer,
			size_t buflen, int *errnop)
{
	enum nss_status ret;
	static struct winbindd_response response;
	struct winbindd_request request;
	static int keep_response;

	/* If our static buffer needs to be expanded we are called again */

	if (!keep_response) {

		/* Call for the first time */

		ZERO_STRUCT(response);
		ZERO_STRUCT(request);

		strncpy(request.data.username, name, 
			sizeof(request.data.username) - 1);
		request.data.username
			[sizeof(request.data.username) - 1] = '\0';

		ret = generic_request(WINBINDD_GETPWNAM_FROM_USER, &request, 
				      &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_pwent(result, &response.data.pw, &buffer,
					 &buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = ERANGE;
				return ret;
			}
		}

	} else {

		/* We've been called again */

		ret = fill_pwent(result, &response.data.pw, &buffer, &buflen);

		if (ret == NSS_STATUS_TRYAGAIN) {
			keep_response = True;
			*errnop = ERANGE;
			return ret;
		}

		keep_response = False;
		*errnop = 0;
	}

	free_response(&response);
	return ret;
}

/*
 * NSS group functions
 */

/* Rewind "file pointer" to start of ntdom group database */

enum nss_status
_nss_winbind_setgrent(void)
{
	return generic_request(WINBINDD_SETGRENT, NULL, NULL);
}

/* Close "file pointer" for ntdom group database */

enum nss_status
_nss_winbind_endgrent(void)
{
	return generic_request(WINBINDD_ENDGRENT, NULL, NULL);
}

/* Get next entry from ntdom group database */

enum nss_status
_nss_winbind_getgrent_r(struct group *result,
			char *buffer, size_t buflen, int *errnop)
{
	enum nss_status ret;
	static struct winbindd_response response;
	static int keep_response;

	/* If our static buffer needs to be expanded we are called again */

	if (!keep_response) {

		/* Call for the first time */

		ZERO_STRUCT(response);
		
		ret = generic_request(WINBINDD_GETGRENT, NULL, &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_grent(result, &response, &buffer, &buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = ERANGE;
				return ret;
			}
		}

	} else {
		
		/* We've been called again */

		ret = fill_grent(result, &response, &buffer, &buflen);

		if (ret == NSS_STATUS_TRYAGAIN) {
			keep_response = True;
			*errnop = ERANGE;
			return ret;
		}

		keep_response = False;
		*errnop = 0;            
	}

	free_response(&response);
	return ret;
}

/* Return group struct from group name */

enum nss_status
_nss_winbind_getgrnam_r(const char *name,
                      struct group *result, char *buffer,
                      size_t buflen, int *errnop)
{
	enum nss_status ret;
	static struct winbindd_response response;
	struct winbindd_request request;
	static int keep_response;
	
	/* If our static buffer needs to be expanded we are called again */
	
	if (!keep_response) {

		/* Call for the first time */

		ZERO_STRUCT(request);
		ZERO_STRUCT(response);

		strncpy(request.data.groupname, name, 
			sizeof(request.data.groupname));
		request.data.groupname
			[sizeof(request.data.groupname) - 1] = '\0';

		ret = generic_request(WINBINDD_GETGRNAM_FROM_GROUP, 
				      &request, &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_grent(result, &response, &buffer, &buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = ERANGE;
				return ret;
			}
		}

	} else {
		
		/* We've been called again */
		
		ret = fill_grent(result, &response, &buffer, &buflen);
		
		if (ret == NSS_STATUS_TRYAGAIN) {
			keep_response = True;
			*errnop = ERANGE;
			return ret;
		}

		keep_response = False;
		*errnop = 0;
	}

	free_response(&response);
	return ret;
}

/* Return group struct from gid */

enum nss_status
_nss_winbind_getgrgid_r(gid_t gid,
                      struct group *result, char *buffer,
                      size_t buflen, int *errnop)
{
	enum nss_status ret;
	static struct winbindd_response response;
	struct winbindd_request request;
	static int keep_response;

	/* If our static buffer needs to be expanded we are called again */

	if (!keep_response) {

		/* Call for the first time */

		ZERO_STRUCT(request);
		ZERO_STRUCT(response);

		request.data.gid = gid;

		ret = generic_request(WINBINDD_GETGRNAM_FROM_GID, &request, 
				      &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_grent(result, &response, &buffer, &buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = ERANGE;
				return ret;
			}
		}

	} else {

		/* We've been called again */

		ret = fill_grent(result, &response, &buffer, &buflen);

		if (ret == NSS_STATUS_TRYAGAIN) {
			keep_response = True;
			*errnop = ERANGE;
			return ret;
		}

		keep_response = False;
		*errnop = 0;
	}

	free_response(&response);
	return ret;
}
