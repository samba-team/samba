/* 
   Unix SMB/CIFS implementation.

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

#ifdef HAVE_NS_API_H
#undef VOLATILE

#include <ns_daemon.h>
#endif

#define MAX_GETPWENT_USERS 250
#define MAX_GETGRENT_USERS 250

/* Prototypes from wb_common.c */

extern int winbindd_fd;

void init_request(struct winbindd_request *req,int rq_type);
NSS_STATUS winbindd_send_request(int req_type,
				 struct winbindd_request *request);
NSS_STATUS winbindd_get_response(struct winbindd_response *response);
NSS_STATUS winbindd_request(int req_type, 
				 struct winbindd_request *request,
				 struct winbindd_response *response);
int winbind_open_pipe_sock(void);
int write_sock(void *buffer, int count);
int read_reply(struct winbindd_response *response);
void free_response(struct winbindd_response *response);

#ifdef HAVE_NS_API_H
/* IRIX version */

static int send_next_request(nsd_file_t *, struct winbindd_request *);
static int do_list(int state, nsd_file_t *rq);

static nsd_file_t *current_rq = NULL;
static int current_winbind_xid = 0;
static int next_winbind_xid = 0;

typedef struct winbind_xid {
	int			xid;
	nsd_file_t		*rq;
	struct winbindd_request *request;
	struct winbind_xid	*next;
} winbind_xid_t;

static winbind_xid_t *winbind_xids = (winbind_xid_t *)0;

static int
winbind_xid_new(int xid, nsd_file_t *rq, struct winbindd_request *request)
{
	winbind_xid_t *new;

	nsd_logprintf(NSD_LOG_LOW,
		"entering winbind_xid_new xid = %d rq = 0x%x, request = 0x%x\n",
		xid, rq, request);
	new = (winbind_xid_t *)nsd_calloc(1,sizeof(winbind_xid_t));
	if (!new) {
		nsd_logprintf(NSD_LOG_RESOURCE,"winbind_xid_new: failed malloc\n");
		return NSD_ERROR;
	}

	new->xid = xid;
	new->rq = rq;
	new->request = request;
	new->next = winbind_xids;
	winbind_xids = new;

	return NSD_CONTINUE;
}

/*
** This routine will look down the xid list and return the request
** associated with an xid.  We remove the record if it is found.
*/
nsd_file_t *
winbind_xid_lookup(int xid, struct winbindd_request **requestp)
{
        winbind_xid_t **last, *dx;
        nsd_file_t *result=0;

        for (last = &winbind_xids, dx = winbind_xids; dx && (dx->xid != xid);
            last = &dx->next, dx = dx->next);
        if (dx) {
                *last = dx->next;
                result = dx->rq;
		*requestp = dx->request;
                SAFE_FREE(dx);
        }
	nsd_logprintf(NSD_LOG_LOW,
		"entering winbind_xid_lookup xid = %d rq = 0x%x, request = 0x%x\n",
		xid, result, dx->request);

        return result;
}

static int
winbind_startnext_timeout(nsd_file_t **rqp, nsd_times_t *to)
{
	nsd_file_t *rq;
	struct winbindd_request *request;

	nsd_logprintf(NSD_LOG_MIN, "timeout (winbind startnext)\n");
	rq = to->t_file;
	*rqp = rq;
	nsd_timeout_remove(rq);
	request = to->t_clientdata;
	return(send_next_request(rq, request));
}

static void
dequeue_request()
{
	nsd_file_t *rq;
	struct winbindd_request *request;

	/*
	 * Check for queued requests
	 */
	if (winbind_xids) {
	    nsd_logprintf(NSD_LOG_MIN, "timeout (winbind) unqueue xid %d\n",
			current_winbind_xid);
	    rq = winbind_xid_lookup(current_winbind_xid++, &request);
	    /* cause a timeout on the queued request so we can send it */
	    nsd_timeout_new(rq,1,winbind_startnext_timeout,request);
	}
}

static int
do_request(nsd_file_t *rq, struct winbindd_request *request)
{
	if (winbind_xids == NULL) {
		/*
		 * No outstanding requests.
		 * Send off the request to winbindd
		 */
		nsd_logprintf(NSD_LOG_MIN, "lookup (winbind) sending request\n");
		return(send_next_request(rq, request));
	} else {
		/*
		 * Just queue it up for now - previous callout or timout
		 * will start it up
		 */
		nsd_logprintf(NSD_LOG_MIN,
			"lookup (winbind): queue request xid = %d\n",
			next_winbind_xid);
		return(winbind_xid_new(next_winbind_xid++, rq, request));
	}
}

static int 
winbind_callback(nsd_file_t **rqp, int fd)
{
	struct winbindd_response response;
	struct winbindd_pw *pw = &response.data.pw;
	struct winbindd_gr *gr = &response.data.gr;
	nsd_file_t *rq;
	NSS_STATUS status;
	fstring result;
	char *members;
	int i, maxlen;

	dequeue_request();

	nsd_logprintf(NSD_LOG_MIN, "entering callback (winbind)\n");

	rq = current_rq;
	*rqp = rq;

	nsd_timeout_remove(rq);
	nsd_callback_remove(fd);

	ZERO_STRUCT(response);
	status = winbindd_get_response(&response);

	if (status != NSS_STATUS_SUCCESS) {
		/* free any extra data area in response structure */
		free_response(&response);
		nsd_logprintf(NSD_LOG_MIN, 
			"callback (winbind) returning not found, status = %d\n",
			status);
		rq->f_status = NS_NOTFOUND;
		return NSD_NEXT;
	}

	maxlen = sizeof(result) - 1;

	switch ((int)rq->f_cmd_data) {
	    case WINBINDD_WINS_BYNAME:
	    case WINBINDD_WINS_BYIP:
		snprintf(result,maxlen,"%s\n",response.data.winsresp);
		break;
	    case WINBINDD_GETPWUID:
	    case WINBINDD_GETPWNAM:
		snprintf(result,maxlen,"%s:%s:%d:%d:%s:%s:%s\n",
			pw->pw_name,
			pw->pw_passwd,
			pw->pw_uid,
			pw->pw_gid,
			pw->pw_gecos,
			pw->pw_dir,
			pw->pw_shell);
		break;
	    case WINBINDD_GETGRNAM:
	    case WINBINDD_GETGRGID:
		if (gr->num_gr_mem && response.extra_data)
			members = response.extra_data;
		else
			members = "";
		snprintf(result,maxlen,"%s:%s:%d:%s\n",
			gr->gr_name, gr->gr_passwd, gr->gr_gid, members);
		break;
	    case WINBINDD_SETGRENT:
	    case WINBINDD_SETPWENT:
		nsd_logprintf(NSD_LOG_MIN, "callback (winbind) - SETPWENT/SETGRENT\n");
		free_response(&response);
		return(do_list(1,rq));
	    case WINBINDD_GETGRENT:
		nsd_logprintf(NSD_LOG_MIN, 
			"callback (winbind) - %d GETGRENT responses\n",
			response.data.num_entries);
		if (response.data.num_entries) {
		    gr = (struct winbindd_gr *)response.extra_data;
		    if (! gr ) {
			nsd_logprintf(NSD_LOG_MIN, "     no extra_data\n");
			free_response(&response);
			return NSD_ERROR;
		    }
		    members = (char *)response.extra_data + 
				(response.data.num_entries * sizeof(struct winbindd_gr));
		    for (i = 0; i < response.data.num_entries; i++) {
			snprintf(result,maxlen,"%s:%s:%d:%s\n",
				gr->gr_name, gr->gr_passwd, gr->gr_gid, 
				&members[gr->gr_mem_ofs]);
			nsd_logprintf(NSD_LOG_MIN, "     GETGRENT %s\n",result);
			nsd_append_element(rq,NS_SUCCESS,result,strlen(result));
			gr++;
		    }
		}
		i = response.data.num_entries;
		free_response(&response);
		if (i < MAX_GETPWENT_USERS)
		    return(do_list(2,rq));
		else
		    return(do_list(1,rq));
	    case WINBINDD_GETPWENT:
		nsd_logprintf(NSD_LOG_MIN, 
			"callback (winbind) - %d GETPWENT responses\n",
			response.data.num_entries);
		if (response.data.num_entries) {
		    pw = (struct winbindd_pw *)response.extra_data;
		    if (! pw ) {
			nsd_logprintf(NSD_LOG_MIN, "     no extra_data\n");
			free_response(&response);
			return NSD_ERROR;
		    }
		    for (i = 0; i < response.data.num_entries; i++) {
			snprintf(result,maxlen,"%s:%s:%d:%d:%s:%s:%s",
				pw->pw_name,
				pw->pw_passwd,
				pw->pw_uid,
				pw->pw_gid,
				pw->pw_gecos,
				pw->pw_dir,
				pw->pw_shell);
			nsd_logprintf(NSD_LOG_MIN, "     GETPWENT %s\n",result);
			nsd_append_element(rq,NS_SUCCESS,result,strlen(result));
			pw++;
		    }
		}
		i = response.data.num_entries;
		free_response(&response);
		if (i < MAX_GETPWENT_USERS)
		    return(do_list(2,rq));
		else
		    return(do_list(1,rq));
	    case WINBINDD_ENDGRENT:
	    case WINBINDD_ENDPWENT:
		nsd_logprintf(NSD_LOG_MIN, "callback (winbind) - ENDPWENT/ENDGRENT\n");
		nsd_append_element(rq,NS_SUCCESS,"\n",1);
		free_response(&response);
		return NSD_NEXT;
	    default:
		free_response(&response);
		nsd_logprintf(NSD_LOG_MIN, "callback (winbind) - no valid command\n");
		return NSD_NEXT;
	}
	nsd_logprintf(NSD_LOG_MIN, "callback (winbind) %s\n", result);
	/* free any extra data area in response structure */
	free_response(&response);
	nsd_set_result(rq,NS_SUCCESS,result,strlen(result),VOLATILE);
	return NSD_OK;
}

static int 
winbind_timeout(nsd_file_t **rqp, nsd_times_t *to)
{
	nsd_file_t *rq;

	dequeue_request();

	nsd_logprintf(NSD_LOG_MIN, "timeout (winbind)\n");

	rq = to->t_file;
	*rqp = rq;

	/* Remove the callback and timeout */
	nsd_callback_remove(winbindd_fd);
	nsd_timeout_remove(rq);

	rq->f_status = NS_NOTFOUND;
	return NSD_NEXT;
}

static int
send_next_request(nsd_file_t *rq, struct winbindd_request *request)
{
	NSS_STATUS status;
	long timeout;

	timeout = 1000;

	nsd_logprintf(NSD_LOG_MIN, "send_next_request (winbind) %d to = %d\n",
			rq->f_cmd_data, timeout);
	status = winbindd_send_request((int)rq->f_cmd_data,request);
	SAFE_FREE(request);

	if (status != NSS_STATUS_SUCCESS) {
		nsd_logprintf(NSD_LOG_MIN, 
			"send_next_request (winbind) error status = %d\n",status);
		rq->f_status = status;
		return NSD_NEXT;
	}

	current_rq = rq;

	/*
	 * Set up callback and timeouts
	 */
	nsd_logprintf(NSD_LOG_MIN, "send_next_request (winbind) fd = %d\n",winbindd_fd);
	nsd_callback_new(winbindd_fd,winbind_callback,NSD_READ);
	nsd_timeout_new(rq,timeout,winbind_timeout,(void *)0);
	return NSD_CONTINUE;
}

int init(void)
{
	nsd_logprintf(NSD_LOG_MIN, "entering init (winbind)\n");
	return(NSD_OK);
}

int lookup(nsd_file_t *rq)
{
	char *map;
	char *key;
	struct winbindd_request *request;

	nsd_logprintf(NSD_LOG_MIN, "entering lookup (winbind)\n");
	if (! rq)
		return NSD_ERROR;

	map = nsd_attr_fetch_string(rq->f_attrs, "table", (char*)0);
	key = nsd_attr_fetch_string(rq->f_attrs, "key", (char*)0);
	if (! map || ! key) {
		nsd_logprintf(NSD_LOG_MIN, "lookup (winbind) table or key not defined\n");
		rq->f_status = NS_BADREQ;
		return NSD_ERROR;
	}

	nsd_logprintf(NSD_LOG_MIN, "lookup (winbind %s)\n",map);

	request = (struct winbindd_request *)nsd_calloc(1,sizeof(struct winbindd_request));
	if (! request) {
		nsd_logprintf(NSD_LOG_RESOURCE,
			"lookup (winbind): failed malloc\n");
		return NSD_ERROR;
	}

	if (strcasecmp(map,"passwd.byuid") == 0) {
	    request->data.uid = atoi(key);
	    rq->f_cmd_data = (void *)WINBINDD_GETPWUID;
	} else if (strcasecmp(map,"passwd.byname") == 0) {
	    strncpy(request->data.username, key, 
		sizeof(request->data.username) - 1);
	    request->data.username[sizeof(request->data.username) - 1] = '\0';
	    rq->f_cmd_data = (void *)WINBINDD_GETPWNAM; 
	} else if (strcasecmp(map,"group.byname") == 0) {
	    strncpy(request->data.groupname, key, 
		sizeof(request->data.groupname) - 1);
	    request->data.groupname[sizeof(request->data.groupname) - 1] = '\0';
	    rq->f_cmd_data = (void *)WINBINDD_GETGRNAM; 
	} else if (strcasecmp(map,"group.bygid") == 0) {
	    request->data.gid = atoi(key);
	    rq->f_cmd_data = (void *)WINBINDD_GETGRGID;
	} else if (strcasecmp(map,"hosts.byname") == 0) {
	    strncpy(request->data.winsreq, key, sizeof(request->data.winsreq) - 1);
	    request->data.winsreq[sizeof(request->data.winsreq) - 1] = '\0';
	    rq->f_cmd_data = (void *)WINBINDD_WINS_BYNAME;
	} else if (strcasecmp(map,"hosts.byaddr") == 0) {
	    strncpy(request->data.winsreq, key, sizeof(request->data.winsreq) - 1);
	    request->data.winsreq[sizeof(request->data.winsreq) - 1] = '\0';
	    rq->f_cmd_data = (void *)WINBINDD_WINS_BYIP;
	} else {
		/*
		 * Don't understand this map - just return not found
		 */
		nsd_logprintf(NSD_LOG_MIN, "lookup (winbind) unknown table\n");
		SAFE_FREE(request);
		rq->f_status = NS_NOTFOUND;
		return NSD_NEXT;
	}

	return(do_request(rq, request));
}

int list(nsd_file_t *rq)
{
	char *map;

	nsd_logprintf(NSD_LOG_MIN, "entering list (winbind)\n");
	if (! rq)
		return NSD_ERROR;

	map = nsd_attr_fetch_string(rq->f_attrs, "table", (char*)0);
	if (! map ) {
		nsd_logprintf(NSD_LOG_MIN, "list (winbind) table not defined\n");
		rq->f_status = NS_BADREQ;
		return NSD_ERROR;
	}

	nsd_logprintf(NSD_LOG_MIN, "list (winbind %s)\n",map);

	return (do_list(0,rq));
}

static int
do_list(int state, nsd_file_t *rq)
{
	char *map;
	struct winbindd_request *request;

	nsd_logprintf(NSD_LOG_MIN, "entering do_list (winbind) state = %d\n",state);

	map = nsd_attr_fetch_string(rq->f_attrs, "table", (char*)0);
	request = (struct winbindd_request *)nsd_calloc(1,sizeof(struct winbindd_request));
	if (! request) {
		nsd_logprintf(NSD_LOG_RESOURCE,
			"do_list (winbind): failed malloc\n");
		return NSD_ERROR;
	}

	if (strcasecmp(map,"passwd.byname") == 0) {
	    switch (state) {
		case 0:
		    rq->f_cmd_data = (void *)WINBINDD_SETPWENT;
		    break;
		case 1:
		    request->data.num_entries = MAX_GETPWENT_USERS;
		    rq->f_cmd_data = (void *)WINBINDD_GETPWENT;
		    break;
		case 2:
		    rq->f_cmd_data = (void *)WINBINDD_ENDPWENT;
		    break;
		default:
		    nsd_logprintf(NSD_LOG_MIN, "do_list (winbind) unknown state\n");
		    SAFE_FREE(request);
		    rq->f_status = NS_NOTFOUND;
		    return NSD_NEXT;
	    }
	} else if (strcasecmp(map,"group.byname") == 0) {
	    switch (state) {
		case 0:
		    rq->f_cmd_data = (void *)WINBINDD_SETGRENT;
		    break;
		case 1:
		    request->data.num_entries = MAX_GETGRENT_USERS;
		    rq->f_cmd_data = (void *)WINBINDD_GETGRENT;
		    break;
		case 2:
		    rq->f_cmd_data = (void *)WINBINDD_ENDGRENT;
		    break;
		default:
		    nsd_logprintf(NSD_LOG_MIN, "do_list (winbind) unknown state\n");
		    SAFE_FREE(request);
		    rq->f_status = NS_NOTFOUND;
		    return NSD_NEXT;
	    }
	} else {
		/*
		 * Don't understand this map - just return not found
		 */
		nsd_logprintf(NSD_LOG_MIN, "do_list (winbind) unknown table\n");
		SAFE_FREE(request);
		rq->f_status = NS_NOTFOUND;
		return NSD_NEXT;
	}

	return(do_request(rq, request));
}

#else

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

BOOL next_token(const char **ptr,char *buff,const char *sep, size_t bufsize)
{
	const char *s;
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
				  char **buffer, size_t *buflen)
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

	/* The struct passwd for Solaris has some extra fields which must
	   be initialised or nscd crashes. */

#if HAVE_PASSWD_PW_COMMENT
	result->pw_comment = "";
#endif

#if HAVE_PASSWD_PW_AGE
	result->pw_age = "";
#endif

	return NSS_STATUS_SUCCESS;
}

/* Fill a grent structure from a winbindd_response structure.  We use
   the static data passed to us by libc to put strings and stuff in.
   Return NSS_STATUS_TRYAGAIN if we run out of memory. */

static int fill_grent(struct group *result, struct winbindd_gr *gr,
		      char *gr_mem, char **buffer, size_t *buflen)
{
	fstring name;
	int i;
	char *tst;

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

	/* this next value is a pointer to a pointer so let's align it */

	/* Calculate number of extra bytes needed to align on pointer size boundry */
	if ((i = (unsigned long)(*buffer) % sizeof(char*)) != 0)
		i = sizeof(char*) - i;
	
	if ((tst = get_static(buffer, buflen, ((gr->num_gr_mem + 1) * 
				 sizeof(char *)+i))) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}
	result->gr_mem = (char **)(tst + i);

	if (gr->num_gr_mem == 0) {

		/* Group is empty */

		*(result->gr_mem) = NULL;
		return NSS_STATUS_SUCCESS;
	}

	/* Start looking at extra data */

	i = 0;

	while(next_token((const char **)&gr_mem, name, ",", sizeof(fstring))) {
        
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
 &buffer, (int *)&buflen);
		
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

		ret = winbindd_request(WINBINDD_GETPWUID, &request, &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_pwent(result, &response.data.pw, 
					&buffer, (int *)&buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = errno = ERANGE;
				return ret;
			}
		}

	} else {

		/* We've been called again */

		ret = fill_pwent(result, &response.data.pw, &buffer, (int *)&buflen);

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

		ret = winbindd_request(WINBINDD_GETPWNAM, &request, &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_pwent(result, &response.data.pw, &buffer,
					(int *)&buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = errno = ERANGE;
				return ret;
			}
		}

	} else {

		/* We've been called again */

		ret = fill_pwent(result, &response.data.pw, &buffer, (int *)&buflen);

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
				&buffer, (int *)&buflen);
		
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

		ret = winbindd_request(WINBINDD_GETGRNAM, &request, &response);

		if (ret == NSS_STATUS_SUCCESS) {
			ret = fill_grent(result, &response.data.gr, 
					 response.extra_data,
					&buffer, (int *)&buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = errno = ERANGE;
				return ret;
			}
		}

	} else {
		
		/* We've been called again */
		
		ret = fill_grent(result, &response.data.gr, 
				response.extra_data, &buffer, (int *)&buflen);
		
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

		ret = winbindd_request(WINBINDD_GETGRGID, &request, &response);

		if (ret == NSS_STATUS_SUCCESS) {

			ret = fill_grent(result, &response.data.gr, 
					 response.extra_data, 
					&buffer, (int *)&buflen);

			if (ret == NSS_STATUS_TRYAGAIN) {
				keep_response = True;
				*errnop = errno = ERANGE;
				return ret;
			}
		}

	} else {

		/* We've been called again */

		ret = fill_grent(result, &response.data.gr, 
				response.extra_data, &buffer, (int *)&buflen);

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

#endif
