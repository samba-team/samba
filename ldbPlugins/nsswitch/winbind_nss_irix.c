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

#include "winbind_client.h"

#ifdef HAVE_NS_API_H
#undef VOLATILE
#include <ns_daemon.h>
#endif

/* Maximum number of users to pass back over the unix domain socket
   per call. This is not a static limit on the total number of users 
   or groups returned in total. */

#define MAX_GETPWENT_USERS 250
#define MAX_GETGRENT_USERS 250

/* Prototypes from wb_common.c */

extern int winbindd_fd;

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
	    case WINBINDD_GETGRLST:
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

#endif /* HAVE_NS_API_H */
