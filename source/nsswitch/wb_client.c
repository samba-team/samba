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

static BOOL wb_single_request(TALLOC_CTX *mem_ctx, int *fd, const char *name,
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

	*response = talloc(mem_ctx, response_len+1);

	if (wb_read_sock(*fd, *response, response_len) < 0)
		goto retry;

	(*response)[response_len] = '\0';

	return True;
}

BOOL wb_fetchpid(const char *socket_name, pid_t *pid)
{
	TALLOC_CTX *mem_ctx = talloc_init("wb_fetchpid");
	char *response;
	int fd = -1;

	if (!wb_single_request(mem_ctx, &fd, socket_name, 1,
			       "pid\n", &response))
		return False;

	close(fd);

	*pid = strtol(response, NULL, 0);

	return True;
}

void wb_init_client_state(struct wb_client_state *state)
{
	state->lsa_socket = -1;
	state->idmap_socket = -1;
}

void wb_destroy_client_state(struct wb_client_state *state)
{
	if (state->lsa_socket > 0)
		close(state->lsa_socket);

	if (state->idmap_socket > 0)
		close(state->idmap_socket);
}

static BOOL wb_lsa_request(struct wb_client_state *state,
			   TALLOC_CTX *mem_ctx, const char *request,
			   char **response)
{
	return wb_single_request(mem_ctx, &state->lsa_socket, "lsa", 4,
				 request, response);
}

BOOL wb_sidtoname(struct wb_client_state *state, TALLOC_CTX *mem_ctx,
		  const DOM_SID *sid, char **domain, char **name,
		  enum SID_NAME_USE *type)
{
	fstring request;
	char *response;
	char *p, *q;

	fstr_sprintf(request, "sidtoname %s\n", sid_string_static(sid));

	if (!wb_lsa_request(state, mem_ctx, request, &response))
		return False;

	p = strchr(response, '\\');
	if (p == NULL)
		return False;

	*p = '\0';
	*domain = talloc_strdup(mem_ctx, response);

	p += 1;
	q = strchr(p, '\\');
	if (q == NULL)
		return False;

	*q = '\0';
	*name = talloc_strdup(mem_ctx, p);

	q += 1;
	*type = strtol(q, NULL, 10);

	return True;
}

BOOL wb_nametosid(struct wb_client_state *state, TALLOC_CTX *mem_ctx,
		  const char *name, DOM_SID *sid)
{
	fstring request;
	char *response;

	fstr_sprintf(request, "nametosid %s\n", name);

	if (!wb_lsa_request(state, mem_ctx, request, &response))
		return False;

	if (!string_to_sid(sid, response))
		return False;

	return True;
}

BOOL wb_enumtrust(struct wb_client_state *state, TALLOC_CTX *mem_ctx,
		  int *num, char ***names, DOM_SID **sids)
{
	fstring request;
	char *p, *response;
	int i;

	fstr_sprintf(request, "enumtrust\n");

	if (!wb_lsa_request(state, mem_ctx, request, &response))
		return False;

	*num = strtol(response, &p, 10);

	if (*num == 0) {
		*names = NULL;
		*sids = NULL;
		return True;
	}

	if ( (p==NULL) || (*p != '\n') )
		return False;

	p +=1;

	*names = talloc(mem_ctx, (*num) * sizeof(**names));
	*sids  = talloc(mem_ctx, (*num) * sizeof(**sids));

	for (i=0; i<(*num); i++) {
		char *q = strchr(p, '\\');

		if (q == NULL)
			return False;
		*q++ = '\0';
		(*names)[i] = talloc_strdup(mem_ctx, p);

		p = strchr(q, '\n');
		if (p == NULL)
			return False;
		*p++ = '\0';
		if (!string_to_sid(&(*sids)[i], q))
			return False;
	}
	return True;
}

BOOL wb_dominfo(struct wb_client_state *state,
		TALLOC_CTX *mem_ctx, char **name, DOM_SID *sid)
{
	fstring request;
	char *response;
	char *p;

	fstr_sprintf(request, "dominfo\n");

	if (!wb_lsa_request(state, mem_ctx, request, &response))
		return False;

	p = strchr(response, '\\');
	if (p == NULL)
		return False;

	*p++ = '\0';

	*name = talloc_strdup(mem_ctx, response);

	if (!string_to_sid(sid, p))
		return False;

	return True;
}
