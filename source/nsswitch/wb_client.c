/* 
   Unix SMB/CIFS implementation.

   winbind client code

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Tridgell 2000
   
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

#include "includes.h"
#include "nsswitch/winbind_nss.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

extern DOM_SID global_sid_NULL;            		/* NULL sid */

NSS_STATUS winbindd_request(int req_type,
                                 struct winbindd_request *request,
                                 struct winbindd_response *response);

/* Call winbindd to convert a name to a sid */

BOOL winbind_lookup_name(const char *dom_name, const char *name, DOM_SID *sid, 
                         enum SID_NAME_USE *name_type)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	
	if (!sid || !name_type)
		return False;

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.name.dom_name, dom_name);
	fstrcpy(request.data.name.name, name);

	if ((result = winbindd_request(WINBINDD_LOOKUPNAME, &request, 
				       &response)) == NSS_STATUS_SUCCESS) {
		if (!string_to_sid(sid, response.data.sid.sid))
			return False;
		*name_type = (enum SID_NAME_USE)response.data.sid.type;
	}

	return result == NSS_STATUS_SUCCESS;
}

/* Call winbindd to convert sid to name */

BOOL winbind_lookup_sid(const DOM_SID *sid, 
			fstring dom_name, fstring name, 
                        enum SID_NAME_USE *name_type)
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	fstring sid_str;
	
	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	sid_to_string(sid_str, sid);
	fstrcpy(request.data.sid, sid_str);
	
	/* Make request */

	result = winbindd_request(WINBINDD_LOOKUPSID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		fstrcpy(dom_name, response.data.name.dom_name);
		fstrcpy(name, response.data.name.name);
		*name_type = (enum SID_NAME_USE)response.data.name.type;

		DEBUG(10, ("winbind_lookup_sid: SUCCESS: SID %s -> %s %s\n", 
                           sid_str, dom_name, name));
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert SID to uid */

BOOL winbind_sid_to_uid(uid_t *puid, const DOM_SID *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;
	fstring sid_str;

	if (!puid)
		return False;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	sid_to_string(sid_str, sid);
	fstrcpy(request.data.sid, sid_str);
	
	/* Make request */

	result = winbindd_request(WINBINDD_SID_TO_UID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		*puid = response.data.uid;
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert uid to sid */

BOOL winbind_uid_to_sid(DOM_SID *sid, uid_t uid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	if (!sid)
		return False;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.data.uid = uid;

	/* Make request */

	result = winbindd_request(WINBINDD_UID_TO_SID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		if (!string_to_sid(sid, response.data.sid.sid))
			return False;
	} else {
		sid_copy(sid, &global_sid_NULL);
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert SID to gid */

BOOL winbind_sid_to_gid(gid_t *pgid, const DOM_SID *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;
	fstring sid_str;

	if (!pgid)
		return False;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	sid_to_string(sid_str, sid);
	fstrcpy(request.data.sid, sid_str);
	
	/* Make request */

	result = winbindd_request(WINBINDD_SID_TO_GID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		*pgid = response.data.gid;
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert gid to sid */

BOOL winbind_gid_to_sid(DOM_SID *sid, gid_t gid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	if (!sid)
		return False;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.data.gid = gid;

	/* Make request */

	result = winbindd_request(WINBINDD_GID_TO_SID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		if (!string_to_sid(sid, response.data.sid.sid))
			return False;
	} else {
		sid_copy(sid, &global_sid_NULL);
	}

	return (result == NSS_STATUS_SUCCESS);
}

BOOL winbind_allocate_rid(uint32 *rid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	result = winbindd_request(WINBINDD_ALLOCATE_RID, &request, &response);

	if (result != NSS_STATUS_SUCCESS)
		return False;

	/* Copy out result */
	*rid = response.data.rid;

	return True;
}

/* Fetch the list of groups a user is a member of from winbindd.  This is
   used by winbind_getgroups. */

static int wb_getgroups(const char *user, gid_t **groups)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;

	/* Call winbindd */

	ZERO_STRUCT(request);
	fstrcpy(request.data.username, user);

	ZERO_STRUCT(response);

	result = winbindd_request(WINBINDD_GETGROUPS, &request, &response);

	if (result == NSS_STATUS_SUCCESS) {
		
		/* Return group list.  Don't forget to free the group list
		   when finished. */

		*groups = (gid_t *)response.extra_data;
		return response.data.num_entries;
	}

	return -1;
}

/* Call winbindd to initialise group membership.  This is necessary for
   some systems (i.e RH5.2) that do not have an initgroups function as part
   of the nss extension.  In RH5.2 this is implemented using getgrent()
   which can be amazingly inefficient as well as having problems with
   username case. */

int winbind_initgroups(char *user, gid_t gid)
{
	gid_t *tgr, *groups = NULL;
	int result;

	/* Call normal initgroups if we are a local user */

	if (!strchr(user, *lp_winbind_separator())) {
		return initgroups(user, gid);
	}

	result = wb_getgroups(user, &groups);

	DEBUG(10,("winbind_getgroups: %s: result = %s\n", user, 
		  result == -1 ? "FAIL" : "SUCCESS"));

	if (result != -1) {
		int ngroups = result, i;
		BOOL is_member = False;

		/* Check to see if the passed gid is already in the list */

		for (i = 0; i < ngroups; i++) {
			if (groups[i] == gid) {
				is_member = True;
			}
		}

		/* Add group to list if necessary */

		if (!is_member) {
			tgr = (gid_t *)Realloc(groups, sizeof(gid_t) * ngroups + 1);
			
			if (!tgr) {
				errno = ENOMEM;
				result = -1;
				goto done;
			}
			else groups = tgr;

			groups[ngroups] = gid;
			ngroups++;
		}

		/* Set the groups */

		if (sys_setgroups(ngroups, groups) == -1) {
			errno = EPERM;
			result = -1;
			goto done;
		}

	} else {
		
		/* The call failed.  Set errno to something so we don't get
		   a bogus value from the last failed system call. */

		errno = EIO;
	}

	/* Free response data if necessary */

 done:
	SAFE_FREE(groups);

	return result;
}

/* Return a list of groups the user is a member of.  This function is
   useful for large systems where inverting the group database would be too
   time consuming.  If size is zero, list is not modified and the total
   number of groups for the user is returned. */

int winbind_getgroups(const char *user, gid_t **list)
{
	/*
	 * Don't do the lookup if the name has no separator _and_ we are not in
	 * 'winbind use default domain' mode.
	 */

	if (!(strchr(user, *lp_winbind_separator()) || lp_winbind_use_default_domain()))
		return -1;

	/* Fetch list of groups */

	return wb_getgroups(user, list);
}

/**********************************************************************
 simple wrapper function to see if winbindd is alive
**********************************************************************/

BOOL winbind_ping( void )
{
	NSS_STATUS result;

	result = winbindd_request(WINBINDD_PING, NULL, NULL);

	return result == NSS_STATUS_SUCCESS;
}

/**********************************************************************
 Ask winbindd to create a local user
**********************************************************************/

BOOL winbind_create_user( const char *name, uint32 *rid )
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	
	if ( !lp_winbind_enable_local_accounts() )
		return False;
	
	if ( !name )
		return False;
		
	DEBUG(10,("winbind_create_user: %s\n", name));
	
	ZERO_STRUCT(request);
	ZERO_STRUCT(response);
	
	/* see if the caller wants a new RID returned */
	
	if ( rid ) 
		request.flags = WBFLAG_ALLOCATE_RID;

	fstrcpy( request.data.acct_mgt.username, name );
	fstrcpy( request.data.acct_mgt.groupname, "" );
	
	result = winbindd_request( WINBINDD_CREATE_USER, &request, &response);
	
	if ( rid )
		*rid = response.data.rid;
	
	return result == NSS_STATUS_SUCCESS;
}

/**********************************************************************
 Ask winbindd to create a local group
**********************************************************************/

BOOL winbind_create_group( const char *name, uint32 *rid )
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	
	if ( !lp_winbind_enable_local_accounts() )
		return False;
		
	if ( !name )
		return False;
		
	DEBUG(10,("winbind_create_group: %s\n", name));

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);
	
	/* see if the caller wants a new RID returned */
	
	if ( rid ) 
		request.flags = WBFLAG_ALLOCATE_RID;
		
	fstrcpy( request.data.acct_mgt.groupname, name );
	
	
	result = winbindd_request( WINBINDD_CREATE_GROUP, &request, &response);
	
	if ( rid )
		*rid = response.data.rid;
	
	return result == NSS_STATUS_SUCCESS;
}

/**********************************************************************
 Ask winbindd to add a user to a local group
**********************************************************************/

BOOL winbind_add_user_to_group( const char *user, const char *group )
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	
	if ( !lp_winbind_enable_local_accounts() )
		return False;
		
	if ( !user || !group )
		return False;
		
	ZERO_STRUCT(request);
	ZERO_STRUCT(response);
	
	DEBUG(10,("winbind_add_user_to_group: user(%s), group(%s) \n", 
		user, group));
		
	fstrcpy( request.data.acct_mgt.username, user );
	fstrcpy( request.data.acct_mgt.groupname, group );
	
	result = winbindd_request( WINBINDD_ADD_USER_TO_GROUP, &request, &response);
	
	return result == NSS_STATUS_SUCCESS;
}

/**********************************************************************
 Ask winbindd to remove a user to a local group
**********************************************************************/

BOOL winbind_remove_user_from_group( const char *user, const char *group )
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	
	if ( !lp_winbind_enable_local_accounts() )
		return False;
		
	if ( !user || !group )
		return False;
		
	ZERO_STRUCT(request);
	ZERO_STRUCT(response);
	
	DEBUG(10,("winbind_remove_user_from_group: user(%s), group(%s) \n", 
		user, group));
		
	ZERO_STRUCT(response);
	
	fstrcpy( request.data.acct_mgt.username, user );
	fstrcpy( request.data.acct_mgt.groupname, group );
	
	result = winbindd_request( WINBINDD_REMOVE_USER_FROM_GROUP, &request, &response);
	
	return result == NSS_STATUS_SUCCESS;
}

/**********************************************************************
 Ask winbindd to set the primary group for a user local user
**********************************************************************/

BOOL winbind_set_user_primary_group( const char *user, const char *group )
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	
	if ( !lp_winbind_enable_local_accounts() )
		return False;
		
	if ( !user || !group )
		return False;
		
	ZERO_STRUCT(request);
	ZERO_STRUCT(response);
	
	DEBUG(10,("winbind_set_user_primary_group: user(%s), group(%s) \n", 
		user, group));

	fstrcpy( request.data.acct_mgt.username, user );
	fstrcpy( request.data.acct_mgt.groupname, group );
	
	result = winbindd_request( WINBINDD_SET_USER_PRIMARY_GROUP, &request, &response);
	
	return result == NSS_STATUS_SUCCESS;
}


/**********************************************************************
 Ask winbindd to remove a user from its lists of accounts
**********************************************************************/

BOOL winbind_delete_user( const char *user )
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	
	if ( !lp_winbind_enable_local_accounts() )
		return False;
		
	if ( !user )
		return False;
		
	ZERO_STRUCT(request);
	ZERO_STRUCT(response);
	
	DEBUG(10,("winbind_delete_user: user (%s)\n", user));

	fstrcpy( request.data.acct_mgt.username, user );
	
	result = winbindd_request( WINBINDD_DELETE_USER, &request, &response);
	
	return result == NSS_STATUS_SUCCESS;
}

/**********************************************************************
 Ask winbindd to remove a group from its lists of accounts
**********************************************************************/

BOOL winbind_delete_group( const char *group )
{
	struct winbindd_request request;
	struct winbindd_response response;
	NSS_STATUS result;
	
	if ( !lp_winbind_enable_local_accounts() )
		return False;
		
	if ( !group )
		return False;
		
	ZERO_STRUCT(request);
	ZERO_STRUCT(response);
	
	DEBUG(10,("winbind_delete_group: group (%s)\n", group));

	fstrcpy( request.data.acct_mgt.groupname, group );
	
	result = winbindd_request( WINBINDD_DELETE_GROUP, &request, &response);
	
	return result == NSS_STATUS_SUCCESS;
}

/***********************************************************************/
#if 0	/* not needed currently since winbindd_acct was added -- jerry */

/* Call winbindd to convert SID to uid. Do not allocate */

BOOL winbind_sid_to_uid_query(uid_t *puid, const DOM_SID *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;
	fstring sid_str;

	if (!puid)
		return False;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	sid_to_string(sid_str, sid);
	fstrcpy(request.data.sid, sid_str);

	request.flags = WBFLAG_QUERY_ONLY;
	
	/* Make request */

	result = winbindd_request(WINBINDD_SID_TO_UID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		*puid = response.data.uid;
	}

	return (result == NSS_STATUS_SUCCESS);
}

/* Call winbindd to convert SID to gid.  Do not allocate */

BOOL winbind_sid_to_gid_query(gid_t *pgid, const DOM_SID *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result;
	fstring sid_str;

	if (!pgid)
		return False;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	sid_to_string(sid_str, sid);
	fstrcpy(request.data.sid, sid_str);
	
	request.flags = WBFLAG_QUERY_ONLY;

	/* Make request */

	result = winbindd_request(WINBINDD_SID_TO_GID, &request, &response);

	/* Copy out result */

	if (result == NSS_STATUS_SUCCESS) {
		*pgid = response.data.gid;
	}

	return (result == NSS_STATUS_SUCCESS);
}

#endif 	/* JERRY */

/***********************************************************************/

/* Write data to winbindd socket */

static int wb_write_sock(int fd, const void *buffer, int count)
{
	int result, nwritten;
	
 restart:
	
	/* Write data to socket */
	
	nwritten = 0;
	
	while(nwritten < count) {
		struct timeval tv;
		fd_set r_fds;
		
		/* Catch pipe close on other end by checking if a read()
		   call would not block by calling select(). */

		FD_ZERO(&r_fds);
		FD_SET(fd, &r_fds);
		ZERO_STRUCT(tv);
		
		if (select(fd + 1, &r_fds, NULL, NULL, &tv) == -1) {
			close(fd);
			return -1;                   /* Select error */
		}
		
		/* Write should be OK if fd not available for reading */
		
		if (!FD_ISSET(fd, &r_fds)) {
			
			/* Do the write */
			
			result = write(fd, (const char *)buffer + nwritten, 
				       count - nwritten);
			
			if ((result == -1) || (result == 0)) {
				
				/* Write failed */
				
				return -1;
			}

			nwritten += result;

		} else {

			/* Pipe has closed on remote end */

			close(fd);
			goto restart;
		}
	}

	return nwritten;
}

/* Read data from winbindd socket */

static int wb_read_sock(int fd, void *buffer, int count)
{
	int result = 0, nread = 0;
	int total_time = 0, selret;

	/* Read data from socket */
	while(nread < count) {
		struct timeval tv;
		fd_set r_fds;
		
		/* Catch pipe close on other end by checking if a read()
		   call would not block by calling select(). */

		FD_ZERO(&r_fds);
		FD_SET(fd, &r_fds);
		ZERO_STRUCT(tv);
		/* Wait for 5 seconds for a reply. May need to parameterise
		 * this... */
		tv.tv_sec = 5;

		if ((selret = select(fd + 1, &r_fds, NULL, NULL, &tv)) == -1) {
			return -1;                   /* Select error */
		}
		
		if (selret == 0) {
			/* Not ready for read yet... */
			if (total_time >= 30) {
				/* Timeout */
				return -1;
			}
			total_time += 5;
			continue;
		}

		if (FD_ISSET(fd, &r_fds)) {
			
			/* Do the Read */
			
			result = read(fd, (char *)buffer + nread, 
				      count - nread);
			
			if ((result == -1) || (result == 0)) {
				
				/* Read failed.  I think the only useful thing
				   we can do here is just return -1 and fail
				   since the transaction has failed half way
				   through. */
			
				return -1;
			}
			
			nread += result;
			
		}
	}
	
	return result;
}

static BOOL wb_single_request(int *fd, const char *name,
			      int max_attempts, const char *request,
			      char **response)
{
	fstring header;
	int response_len;

	int attempts = 0;

	/* If the DC a winbindd is connected to has shut down the connection,
	 * the normal behaviour of that winbindd is to die at that moment. The
	 * parent winbindd should restart that child. This routine should give
	 * the child some time to reconnect to the DC. */

 retry:
	if (attempts > 0)
		close(*fd);

	if (attempts > max_attempts)
		return False;

	if (*fd != -1) {
		struct timeval tv;
		fd_set r_fds;

		/* Catch pipe close on other end by checking if a read() call
		   would not block by calling select(). */

		FD_ZERO(&r_fds);
		FD_SET(*fd, &r_fds);
		ZERO_STRUCT(tv);
		
		if ( (select(*fd + 1, &r_fds, NULL, NULL, &tv) == -1) ||
		     FD_ISSET(*fd, &r_fds) ) {
			close(*fd);
			*fd = -1;
		}
	}

	if (*fd == -1) {
		if (attempts > 0)
			smb_msleep(attempts*100);
		
		*fd = winbind_named_pipe_sock(WINBINDD_SOCKET_DIR, name);
	}

	attempts += 1;

	if (*fd == -1)
		goto retry;

	if (wb_write_sock(*fd, request, strlen(request)) < 0)
		goto retry;

	if (wb_read_sock(*fd, header, 12) < 0)
		goto retry;

	if (strncmp(header, "OK ", strlen("OK ")) != 0)
		return False;

	response_len = strtol(&header[3], NULL, 10);

	*response = malloc(response_len+1);

	if (wb_read_sock(*fd, *response, response_len) < 0)
		goto retry;

	(*response)[response_len] = '\0';

	return True;
}

BOOL wb_fetchpid(const char *socket_name, pid_t *pid)
{
	char *response;
	int fd = -1;

	if (!wb_single_request(&fd, socket_name, 1, "pid\n", &response))
		return False;

	close(fd);

	*pid = strtol(response, NULL, 0);

	free(response);

	return True;
}

void wb_init_client_state(struct wb_client_state *state)
{
	state->lsa_socket = -1;
	state->idmap_socket = -1;
	state->num_sam_sockets = 0;
	state->sam_sockets = NULL;
	state->sam_socket_sids = NULL;
	state->num_users = 0;
	state->current_user = 0;
	state->user_sids = NULL;
	state->user_names = NULL;
}

void wb_destroy_client_state(struct wb_client_state *state)
{
	int i;

	if (state->lsa_socket > 0)
		close(state->lsa_socket);

	if (state->idmap_socket > 0)
		close(state->idmap_socket);

	for (i=0; i<state->num_sam_sockets; i++) {
		if (state->sam_sockets[i] != -1)
			close(state->sam_sockets[i]);
	}

	if (state->sam_sockets != NULL)
		free(state->sam_sockets);

	if (state->sam_socket_sids != NULL)
		free(state->sam_socket_sids);
}

static BOOL wb_lsa_request(struct wb_client_state *state, const char *request,
			   char **response)
{
	return wb_single_request(&state->lsa_socket, "lsa", 4,
				 request, response);
}

BOOL wb_sidtoname(struct wb_client_state *state, const char *sid,
		  char **domain, char **name, int *type)
{
	BOOL result = False;
	fstring request;
	char *response;
	char *p, *q;

	fstr_sprintf(request, "sidtoname %s\n", sid);

	if (!wb_lsa_request(state, request, &response))
		return False;

	p = strchr(response, '\\');
	if (p == NULL)
		goto done;

	*p = '\0';
	*domain = strdup(response);

	p += 1;
	q = strchr(p, '\\');
	if (q == NULL)
		goto done;

	*q = '\0';
	*name = strdup(p);

	q += 1;
	*type = strtol(q, NULL, 10);

	result = True;

 done:
	if (response != NULL)
		free(response);

	return result;
}

BOOL wb_nametosid(struct wb_client_state *state, const char *name, char **sid)
{
	BOOL result = False;
	fstring request;
	char *response, *p;

	fstr_sprintf(request, "nametosid %s\n", name);

	if (!wb_lsa_request(state, request, &response))
		return False;

	p = strchr(response, ' ');
	if (p == NULL)
		goto done;

	*p = 0;

	*sid = strdup(response);
	result = True;

 done:
	if (response != NULL)
		free(response);

	return result;
}

BOOL wb_enumtrust(struct wb_client_state *state,
		  int *num, char ***names, char ***sids)
{
	BOOL result = False;
	fstring request;
	char *p, *response;
	int i;

	fstr_sprintf(request, "enumtrust\n");

	if (!wb_lsa_request(state, request, &response))
		return False;

	*num = strtol(response, &p, 10);

	if (*num == 0) {
		*names = NULL;
		*sids = NULL;
		result = True;
		goto done;
	}

	if ( (p==NULL) || (*p != '\n') )
		goto done;

	p +=1;

	*names = malloc((*num) * sizeof(**names));
	*sids  = malloc((*num) * sizeof(**sids));

	for (i=0; i<(*num); i++) {
		char *q = strchr(p, '\\');

		if (q == NULL)
			goto done;
		*q++ = '\0';
		(*names)[i] = strdup(p);

		p = strchr(q, '\n');
		if (p == NULL)
			goto done;
		*p++ = '\0';
		(*sids)[i] = strdup(q);
	}

	result = True;

 done:
	if (response != NULL)
		free(response);

	return result;
}

BOOL wb_add_ourself(struct wb_client_state *state, int *num_domains,
		    char ***domain_names, char ***sids)
{
	char *my_name, *my_sid;

	if (!wb_dominfo(state, &my_name, &my_sid))
		return False;

	*domain_names = realloc((*domain_names),
				((*num_domains)+1) * sizeof(**domain_names));
	*sids =         realloc((*sids), ((*num_domains)+1) * sizeof(**sids));

	(*domain_names)[*num_domains] = my_name;
	(*sids)[*num_domains] = my_sid;
	*num_domains += 1;
	return True;
}

BOOL wb_dominfo(struct wb_client_state *state, char **name, char **sid)
{
	BOOL result = False;
	fstring request;
	char *response;
	char *p, *q;

	fstr_sprintf(request, "dominfo\n");

	if (!wb_lsa_request(state, request, &response))
		return False;

	p = strchr(response, '\\');
	if (p == NULL)
		goto done;

	*p++ = '\0';

	*name = strdup(response);

	q = strchr(p, '\n');
	if (q == NULL) {
		free(*name);
		goto done;
	}
	*q = '\0';

	*sid = strdup(p);
	result = True;

 done:
	if (response != NULL)
		free(response);

	return result;
}

static int sam_socket_num(struct wb_client_state *state, const char *sid)
{
	int i;

	for (i=0; i<state->num_sam_sockets; i++) {
		if (strcmp(state->sam_socket_sids[i], sid) == 0)
			return i;
	}

	state->sam_socket_sids = realloc(state->sam_socket_sids,
					 (state->num_sam_sockets+1) *
					 sizeof(*state->sam_socket_sids));
	state->sam_socket_sids[state->num_sam_sockets] = strdup(sid);

	state->sam_sockets = realloc(state->sam_sockets,
				     (state->num_sam_sockets+1) *
				     sizeof(*state->sam_sockets));

	state->sam_sockets[state->num_sam_sockets] = -1;

	state->num_sam_sockets += 1;

	return state->num_sam_sockets-1;
}

static BOOL wb_sam_request(struct wb_client_state *state, const char *sam_sid,
			   const char *request, char **response)
{
	fstring socket_name;
	int socket_index = sam_socket_num(state, sam_sid);

	fstr_sprintf(socket_name, "samr-%s", sam_sid);

	return wb_single_request(&state->sam_sockets[socket_index],
				 socket_name, 4, request, response);
}

static BOOL wb_enumusers(struct wb_client_state *state, const char *sam_sid,
			 uint32 *resume_key, char ***sids, char ***names,
			 int *num_users)
{
	BOOL result = False;
	fstring request;
	char *response, *p;
	int i;

	fstr_sprintf(request, "enumusers %d\n", *resume_key);

	if (!wb_sam_request(state, sam_sid, request, &response))
		return False;

	if (strncmp(response, "RESUME ", strlen("RESUME ")) == 0) {
		p = strchr(response, ' ');
		if (p == NULL)
			goto done;
		p += 1;
		*resume_key = strtol(p, NULL, 10);
		p = strchr(p, ' ');
	} else if (strncmp(response, "DONE ", strlen("DONE ")) == 0) {
		*resume_key = -1;
		p = strchr(response, ' ');
	} else {
		goto done;
	}

	if (p == NULL)
		goto done;

	p += 1;

	*num_users = strtol(p, NULL, 10);

	p = strchr(p, '\n');
	if (p == NULL)
		goto done;
	p += 1;

	*sids = malloc((*num_users) * sizeof(**sids));
	*names = malloc((*num_users) * sizeof(**names));

	for (i=0; i<*num_users; i++) {
		char *q;

		q = strchr(p, ' ');
		if (q == NULL)
			goto done;
		*q = '\0';
		q += 1;

		(*sids)[i] = strdup(p);

		p = strchr(q, '\n');
		if (p == NULL)
			goto done;
		*p = '\0';
		(*names)[i] = strdup(q);
		p += 1;
	}

	result = True;
 done:
	if (response != NULL)
		free(response);

	return result;
}

void wb_setpwent(struct wb_client_state *state)
{
	if ( (!wb_enumtrust(state, &state->num_domains, &state->domain_names,
			    &state->domain_sids)) ||
	     (!wb_add_ourself(state, &state->num_domains, &state->domain_names,
			      &state->domain_sids)) ) {
		state->num_domains = 0;
		state->current_domain = 0;
		return;
	}
	state->current_domain = -1;
	state->resume_key = -1;
}

BOOL wb_getpwent(struct wb_client_state *state,	char **domain, char **name,
		 char **sid)
{
	if (state->current_user >= state->num_users) {

		int i;

		if (state->resume_key == -1) {
			state->current_domain += 1;

			if (state->current_domain >= state->num_domains)
				return False;

			state->resume_key = 0;
		}

		for (i=0; i<state->num_users; i++) {
			free(state->user_sids[i]);
			free(state->user_names[i]);
		}
		SAFE_FREE(state->user_sids);
		SAFE_FREE(state->user_names);
		state->num_users = 0;

		if (!wb_enumusers(state,
				  state->domain_sids[state->current_domain],
				  &state->resume_key, &state->user_sids,
				  &state->user_names, &state->num_users))
			return False;

		state->current_user = 0;
	}

	*domain = strdup(state->domain_names[state->current_domain]);
	*name = strdup(state->user_names[state->current_user]);
	*sid = strdup(state->user_sids[state->current_user]);

	state->current_user += 1;

	return True;
}

void wb_endpwent(struct wb_client_state *state)
{
	int i;

	state->num_domains = 0;
	state->current_domain = 0;

	for (i=0; i<state->num_users; i++) {
		free(state->user_sids[i]);
		free(state->user_names[i]);
	}
	SAFE_FREE(state->user_sids);
	SAFE_FREE(state->user_names);

	state->num_users = 0;
	state->current_user = 0;

	for (i=0; i<state->num_domains; i++) {
		free(state->domain_sids[i]);
		free(state->domain_names[i]);
	}
	SAFE_FREE(state->domain_sids);
	SAFE_FREE(state->domain_names);
	
	state->num_domains = 0;
	state->current_domain = 0;

	return;
}
