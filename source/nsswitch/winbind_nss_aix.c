
#include <stdlib.h>
#include <string.h>
#include <usersec.h>
#include <errno.h>

#include "winbind_client.h"

#define MAX_GETPWENT_USERS 250
#define MAX_GETGRENT_USERS 250

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

static struct passwd *fill_pwent(struct winbindd_pw *pw)
{
	struct passwd *result;

	if (!(result = malloc(sizeof(struct passwd)))) {
		return NULL; 
	}
	memset(result, 0, sizeof(struct passwd));

	/* User name */

	if ((result->pw_name = malloc(strlen(pw->pw_name) + 1)) == NULL) {

		/* Out of memory */
		
		return NULL;
	}
	
	strcpy(result->pw_name, pw->pw_name);

	/* Password */

	if ((result->pw_passwd = malloc(strlen(pw->pw_passwd) + 1)) == NULL) {

		/* Out of memory */

		return NULL;
	}
	
	strcpy(result->pw_passwd, pw->pw_passwd);
        
	/* [ug]id */

	result->pw_uid = pw->pw_uid;
	result->pw_gid = pw->pw_gid;

	/* GECOS */

	if ((result->pw_gecos = malloc(strlen(pw->pw_gecos) + 1)) == NULL) {

		/* Out of memory */

		return NULL;
	}

	strcpy(result->pw_gecos, pw->pw_gecos);
	
	/* Home directory */
	
	if ((result->pw_dir = malloc(strlen(pw->pw_dir) + 1)) == NULL) {

		/* Out of memory */

		return NULL;
	}

	strcpy(result->pw_dir, pw->pw_dir);

	/* Logon shell */
	
	if ((result->pw_shell = malloc(strlen(pw->pw_shell) + 1)) == NULL) {
		
		/* Out of memory */

		return NULL;
	}
	
	strcpy(result->pw_shell, pw->pw_shell);

	return result;
}

static struct group *fill_grent(struct winbindd_gr *gr, char *gr_mem)
{
	fstring name;
	int i;
	char *tst;
	struct group *result;
	
	if (!(result = malloc(sizeof(struct group)))) {
		return NULL; 
	}
	memset(result, 0, sizeof(struct group));

	/* Group name */

	if ((result->gr_name = malloc(strlen(gr->gr_name) + 1)) == NULL) {

		/* Out of memory */

		return NULL;
	}

	strcpy(result->gr_name, gr->gr_name);

	/* Password */

	if ((result->gr_passwd = malloc(strlen(gr->gr_passwd) + 1)) == NULL) {

		/* Out of memory */
		
		return NULL;
	}

	strcpy(result->gr_passwd, gr->gr_passwd);

	/* gid */

	result->gr_gid = gr->gr_gid;

	/* Group membership */

	if ((gr->num_gr_mem < 0) || !gr_mem) {
		gr->num_gr_mem = 0;
	}
	
	if (gr->num_gr_mem == 0) {

		/* Group is empty */
		
		*(result->gr_mem) = NULL;
		return result;
	}
	
	if ((tst = malloc(((gr->num_gr_mem + 1) * sizeof(char *)))) == NULL) {

		/* Out of memory */

		return NULL;
	}
	result->gr_mem = (char **)tst;

	/* Start looking at extra data */

	i = 0;

	while(next_token((char **)&gr_mem, name, ",", sizeof(fstring))) {
        
		/* Allocate space for member */
        
		if (((result->gr_mem)[i] = 
		     malloc(strlen(name) + 1)) == NULL) {
            
			/* Out of memory */
            
			return NULL;
		}        
        
		strcpy((result->gr_mem)[i], name);
		i++;
	}

	/* Terminate list */

	(result->gr_mem)[i] = NULL;

	return result;
}



static struct group *
wb_aix_getgrgid (gid_t gid)
{
/* take a group id and return a filled struct group */
	
	NSS_STATUS ret;
	struct winbindd_response response;
	struct winbindd_request request;

	ZERO_STRUCT(response);
	ZERO_STRUCT(request);
	
	request.data.gid = gid;

	ret = winbindd_request(WINBINDD_GETGRGID, &request, &response);

	if (ret == NSS_STATUS_SUCCESS) {
		return fill_grent(&response.data.gr, response.extra_data);
	}
	return NULL;
}

static struct group *
wb_aix_getgrnam (const char *name)
{
/* take a group name and return a filled struct group */

	NSS_STATUS ret;
	struct winbindd_response response;
	struct winbindd_request request;
	
	ZERO_STRUCT(response);
	ZERO_STRUCT(request);

	strncpy(request.data.groupname, name, 
		sizeof(request.data.groupname));
	request.data.groupname
		[sizeof(request.data.groupname) - 1] = '\0';

	ret = winbindd_request(WINBINDD_GETGRNAM, &request, &response);

	if (ret == NSS_STATUS_SUCCESS) {
		return fill_grent(&response.data.gr, response.extra_data);
	}
	return NULL;	
}

static char *
wb_aix_getgrset (const char *user)
{
/* 	take a username and return a string containing a comma-separated list of 
	group id numbers to which the user belongs */
	
	NSS_STATUS ret;
	struct winbindd_response response;
	struct winbindd_request request;
	
	char *tmpbuf, *result;
	int i, idx = 0;
	
	strncpy(request.data.username, user, 
		sizeof(request.data.username) - 1);
	request.data.username
		[sizeof(request.data.username) - 1] = '\0';

	ret = winbindd_request(WINBINDD_GETGROUPS, &request, &response);
	
	if (ret == NSS_STATUS_SUCCESS) {
		int num_gids = response.data.num_entries;
		gid_t *gid_list = (gid_t *)response.extra_data;
		
		/* allocate a space large enough to contruct the string */
		if (!(tmpbuf = malloc(num_gids*12))) {
			return NULL;
		}
		idx += sprintf(tmpbuf, "%d", gid_list[0]);
		for (i = 1; i < num_gids; i++) {
			tmpbuf[idx++] = ',';
			idx += sprintf(tmpbuf+idx, "%d", gid_list[i]);	
		}
		tmpbuf[idx] = '\0';
		if (!(result = malloc(idx+1))) {
			/* 	allocate a string the right size to return, but
				if that fails may as well return our working buffer
				because it contains the same thing */
			return tmpbuf;
		}
		strcpy(result, tmpbuf);
		free(tmpbuf);
		return result;
	}
	return NULL;
}

static struct passwd *
wb_aix_getpwuid (uid_t uid)
{
/* take a uid and return a filled struct passwd */
	
	NSS_STATUS ret;
	struct winbindd_response response;
	struct winbindd_request request;
	
	ZERO_STRUCT(response);
	ZERO_STRUCT(request);
		
	request.data.uid = uid;
	
	ret = winbindd_request(WINBINDD_GETPWUID, &request, &response);
	
	if (ret == NSS_STATUS_SUCCESS) {
		return fill_pwent(&response.data.pw);
	}
	return NULL;	
}

static struct passwd *
wb_aix_getpwnam (const char *name)
{
/* take a username and return a filled struct passwd */

	NSS_STATUS ret;
	struct winbindd_response response;
	struct winbindd_request request;
	
	ZERO_STRUCT(response);
	ZERO_STRUCT(request);

	strncpy(request.data.username, name, 
		sizeof(request.data.username) - 1);
	request.data.username
		[sizeof(request.data.username) - 1] = '\0';

	ret = winbindd_request(WINBINDD_GETPWNAM, &request, &response);

	if (ret == NSS_STATUS_SUCCESS) {
		return fill_pwent(&response.data.pw);
	}
	return NULL;
}

int
wb_aix_init (struct secmethod_table *methods)
{
	memset(methods, 0, sizeof(*methods));

	/* identification methods */
    
	methods->method_getgrgid = wb_aix_getgrgid;
	methods->method_getgrnam = wb_aix_getgrnam;
	methods->method_getgrset = wb_aix_getgrset;
	methods->method_getpwnam = wb_aix_getpwnam;
	methods->method_getpwuid = wb_aix_getpwuid;
    
	/* support methods 
	methods->method_open = wb_aix_open;
	methods->method_close = wb_aix_close;
	*/
	
	return AUTH_SUCCESS;
}


