/* 
   Unix SMB/CIFS implementation.

   Winbind daemon connection manager

   Copyright (C) Tim Potter 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
   We need to manage connections to domain controllers without having to
   mess up the main winbindd code with other issues.  The aim of the
   connection manager is to:
  
       - make connections to domain controllers and cache them
       - re-establish connections when networks or servers go down
       - centralise the policy on connection timeouts, domain controller
	 selection etc
       - manage re-entrancy for when winbindd becomes able to handle
	 multiple outstanding rpc requests
  
   Why not have connection management as part of the rpc layer like tng?
   Good question.  This code may morph into libsmb/rpc_cache.c or something
   like that but at the moment it's simply staying as part of winbind.	I
   think the TNG architecture of forcing every user of the rpc layer to use
   the connection caching system is a bad idea.	 It should be an optional
   method of using the routines.

   The TNG design is quite good but I disagree with some aspects of the
   implementation. -tpot

 */

/*
   TODO:

     - I'm pretty annoyed by all the make_nmb_name() stuff.  It should be
       moved down into another function.

     - Take care when destroying cli_structs as they can be shared between
       various sam handles.

 */

#include "winbindd.h"

/* Global list of connections.	Initially a DLIST but can become a hash
   table or whatever later. */

struct winbindd_cm_conn {
	struct winbindd_cm_conn *prev, *next;
	fstring domain;
	fstring controller;
	fstring pipe_name;
	size_t mutex_ref_count;
	struct cli_state *cli;
	POLICY_HND pol;
};

static struct winbindd_cm_conn *cm_conns = NULL;

/* Choose between anonymous or authenticated connections.  We need to use
   an authenticated connection if DCs have the RestrictAnonymous registry
   entry set > 0, or the "Additional restrictions for anonymous
   connections" set in the win2k Local Security Policy. 
   
   Caller to free() result in domain, username, password
*/

static void cm_get_ipc_userpass(char **username, char **domain, char **password)
{
	*username = secrets_fetch(SECRETS_AUTH_USER, NULL);
	*domain = secrets_fetch(SECRETS_AUTH_DOMAIN, NULL);
	*password = secrets_fetch(SECRETS_AUTH_PASSWORD, NULL);
	
	if (*username && **username) {

		if (!*domain || !**domain)
			*domain = smb_xstrdup(lp_workgroup_unix());
		
		if (!*password || !**password)
			*password = smb_xstrdup("");

		DEBUG(3, ("IPC$ connections done by user %s\\%s\n", 
			  *domain, *username));

	} else {
		DEBUG(3, ("IPC$ connections done anonymously\n"));
		*username = smb_xstrdup("");
		*domain = smb_xstrdup("");
		*password = smb_xstrdup("");
	}
}

/* Open a connction to the remote server, cache failures for 30 seconds */

static NTSTATUS cm_open_connection(const char *domain, const int pipe_index,
				   struct winbindd_cm_conn *new_conn, BOOL keep_mutex)
{
	NTSTATUS result;
	char *ipc_username, *ipc_domain, *ipc_password;
	struct in_addr dc_ip;
	int i;
	BOOL retry = True;
	BOOL got_mutex = False;
	ZERO_STRUCT(dc_ip);

	fstrcpy(new_conn->domain, domain);
	fstrcpy(new_conn->pipe_name, get_pipe_name_from_index(pipe_index));
	
	/* connection failure cache has been moved inside of get_dc_name
	   so we can deal with half dead DC's   --jerry */
	   
	if (!get_dc_name(domain, new_conn->controller, &dc_ip)) {
		result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		add_failed_connection_entry(domain, "", result);
		return result;
	}

	/* Initialise SMB connection */

	cm_get_ipc_userpass(&ipc_username, &ipc_domain, &ipc_password);

	DEBUG(5, ("connecting to %s from %s with username [%s]\\[%s]\n", 
	      new_conn->controller, global_myname_unix(), ipc_domain, ipc_username));

	for (i = 0; retry && (i < NUM_CLI_AUTH_CONNECT_RETRIES); i++) {

		if (!secrets_named_mutex(new_conn->controller, WINBIND_SERVER_MUTEX_WAIT_TIME, &new_conn->mutex_ref_count)) {
			DEBUG(0,("cm_open_connection: mutex grab failed for %s\n", new_conn->controller));
			result = NT_STATUS_POSSIBLE_DEADLOCK;
			continue;
		}

		got_mutex = True;

		result = cli_full_connection(&new_conn->cli, global_myname_unix(), new_conn->controller, 
			     &dc_ip, 0, CLI_AUTH_TIMEOUT, "IPC$", 
			     "IPC", ipc_username, ipc_domain, 
			     ipc_password, strlen(ipc_password), &retry);
		
		if (NT_STATUS_IS_OK(result))
			break;

		secrets_named_mutex_release(new_conn->controller, &new_conn->mutex_ref_count);
		got_mutex = False;
	}

	SAFE_FREE(ipc_username);
	SAFE_FREE(ipc_domain);
	SAFE_FREE(ipc_password);

	if (!NT_STATUS_IS_OK(result)) {
		if (got_mutex)
			secrets_named_mutex_release(new_conn->controller, &new_conn->mutex_ref_count);
		add_failed_connection_entry(domain, new_conn->controller, result);
		return result;
	}
	
	if ( !cli_nt_session_open (new_conn->cli, pipe_index) ) {
		result = NT_STATUS_PIPE_NOT_AVAILABLE;
		/* 
		 * only cache a failure if we are not trying to open the 
		 * **win2k** specific lsarpc UUID.  This could be an NT PDC 
		 * and therefore a failure is normal.  This should probably
		 * be abstracted to a check for 2k specific pipes and wondering
		 * if the PDC is an NT4 box.   but since there is only one 2k 
		 * specific UUID right now, i'm not going to bother.  --jerry
		 */
		if (got_mutex)
			secrets_named_mutex_release(new_conn->controller, &new_conn->mutex_ref_count);
		if ( !is_win2k_pipe(pipe_index) )
			add_failed_connection_entry(domain, new_conn->controller, result);
		cli_shutdown(new_conn->cli);
		return result;
	}

	if ((got_mutex) && !keep_mutex)
		secrets_named_mutex_release(new_conn->controller, &new_conn->mutex_ref_count);
	return NT_STATUS_OK;
}

/* Return true if a connection is still alive */

static BOOL connection_ok(struct winbindd_cm_conn *conn)
{
	if (!conn) {
		smb_panic("Invalid paramater passed to conneciton_ok():  conn was NULL!\n");
		return False;
	}

	if (!conn->cli) {
		DEBUG(0, ("Connection to %s for domain %s (pipe %s) has NULL conn->cli!\n", 
			  conn->controller, conn->domain, conn->pipe_name));
		smb_panic("connection_ok: conn->cli was null!");
		return False;
	}

	if (!conn->cli->initialised) {
		DEBUG(0, ("Connection to %s for domain %s (pipe %s) was never initialised!\n", 
			  conn->controller, conn->domain, conn->pipe_name));
		smb_panic("connection_ok: conn->cli->initialised is False!");
		return False;
	}

	if (conn->cli->fd == -1) {
		DEBUG(3, ("Connection to %s for domain %s (pipe %s) has died or was never started (fd == -1)\n", 
			  conn->controller, conn->domain, conn->pipe_name));
		return False;
	}
	
	return True;
}

/* Get a connection to the remote DC and open the pipe.  If there is already a connection, use that */

static NTSTATUS get_connection_from_cache(const char *domain, const char *pipe_name, struct winbindd_cm_conn **conn_out, BOOL keep_mutex) 
{
	struct winbindd_cm_conn *conn, conn_temp;
	NTSTATUS result;

	for (conn = cm_conns; conn; conn = conn->next) {
		if (strequal_unix(conn->domain, domain) && 
		    strequal_unix(conn->pipe_name, pipe_name)) {
			if (!connection_ok(conn)) {
				if (conn->cli) {
					cli_shutdown(conn->cli);
				}
				conn_temp.next = conn->next;
				DLIST_REMOVE(cm_conns, conn);
				SAFE_FREE(conn);
				conn = &conn_temp;  /* Just to keep the loop moving */
			} else {
				if (keep_mutex) {
					if (!secrets_named_mutex(conn->controller,
								WINBIND_SERVER_MUTEX_WAIT_TIME, &conn->mutex_ref_count))
		                	        DEBUG(0,("get_connection_from_cache: mutex grab failed for %s\n",
									conn->controller));
				}
				break;
			}
		}
	}

	if (!conn) {
		if (!(conn = (struct winbindd_cm_conn *) malloc(sizeof(struct winbindd_cm_conn))))
			return NT_STATUS_NO_MEMORY;
		
		ZERO_STRUCTP(conn);
		
		if (!NT_STATUS_IS_OK(result = cm_open_connection(domain, get_pipe_index(pipe_name), conn, keep_mutex))) {
			DEBUG(3, ("get_connection_from_cache: Could not open a connection to %s for %s (%s)\n", 
				  domain, pipe_name, nt_errstr(result)));
		        SAFE_FREE(conn);
			return result;
		}
		DLIST_ADD(cm_conns, conn);		
	}
	
	*conn_out = conn;
	return NT_STATUS_OK;
}

/**********************************************************************************
**********************************************************************************/

BOOL cm_check_for_native_mode_win2k( const char *domain )
{
	NTSTATUS 		result;
	struct winbindd_cm_conn	conn;
	DS_DOMINFO_CTR		ctr;
	BOOL			ret = False;
	
	ZERO_STRUCT( conn );
	ZERO_STRUCT( ctr );
	
	
	if ( !NT_STATUS_IS_OK(result = cm_open_connection(domain, PI_LSARPC_DS, &conn, False)) ) 
	{
		DEBUG(5, ("cm_check_for_native_mode_win2k: Could not open a connection to %s for PIPE_LSARPC (%s)\n", 
			  domain, nt_errstr(result)));
		return False;
	}
	
	if ( conn.cli ) {
		if ( !NT_STATUS_IS_OK(cli_ds_getprimarydominfo( conn.cli, 
			conn.cli->mem_ctx, DsRolePrimaryDomainInfoBasic, &ctr)) ) 
		{
			ret = False;
			goto done;
		}
	}
				
	if ( (ctr.basic->flags & DSROLE_PRIMARY_DS_RUNNING) 
		&& !(ctr.basic->flags & DSROLE_PRIMARY_DS_MIXED_MODE) )
	{
		ret = True;
	}

done:

#if 0
	/*
	 * I don't think we need to shutdown here ? JRA.
	 */
	if ( conn.cli )
		cli_shutdown( conn.cli );
#endif

	return ret;
}



/* Return a LSA policy handle on a domain */

NTSTATUS cm_get_lsa_handle(const char *domain, CLI_POLICY_HND **return_hnd)
{
	struct winbindd_cm_conn *conn;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	NTSTATUS result;
	static CLI_POLICY_HND hnd;

	/* Look for existing connections */

	if (!NT_STATUS_IS_OK(result = get_connection_from_cache(domain, PIPE_LSARPC, &conn, False)))
		return result;

	/* This *shitty* code needs scrapping ! JRA */

	if (policy_handle_is_valid(&conn->pol)) {
		hnd.pol = conn->pol;
		hnd.cli = conn->cli;
		*return_hnd = &hnd;

		return NT_STATUS_OK;
	}
	
	result = cli_lsa_open_policy(conn->cli, conn->cli->mem_ctx, False, 
				     des_access, &conn->pol);

	if (!NT_STATUS_IS_OK(result)) {
		/* Hit the cache code again.  This cleans out the old connection and gets a new one */
		if (conn->cli->fd == -1) { /* Try again, if the remote host disapeared */
			if (!NT_STATUS_IS_OK(result = get_connection_from_cache(domain, PIPE_LSARPC, &conn, False)))
				return result;

			result = cli_lsa_open_policy(conn->cli, conn->cli->mem_ctx, False, 
						     des_access, &conn->pol);
		}

		if (!NT_STATUS_IS_OK(result)) {
			cli_shutdown(conn->cli);
			DLIST_REMOVE(cm_conns, conn);
			SAFE_FREE(conn);

			return result;
		}
	}	

	hnd.pol = conn->pol;
	hnd.cli = conn->cli;

	*return_hnd = &hnd;

	return NT_STATUS_OK;
}

/* Return a SAM policy handle on a domain */

NTSTATUS cm_get_sam_handle(char *domain, CLI_POLICY_HND **return_hnd)
{ 
	struct winbindd_cm_conn *conn;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	NTSTATUS result;
	static CLI_POLICY_HND hnd;

	/* Look for existing connections */

	if (!NT_STATUS_IS_OK(result = get_connection_from_cache(domain, PIPE_SAMR, &conn, False)))
		return result;
	
	/* This *shitty* code needs scrapping ! JRA */

	if (policy_handle_is_valid(&conn->pol)) {
		hnd.pol = conn->pol;
		hnd.cli = conn->cli;

		*return_hnd = &hnd;

		return NT_STATUS_OK;
	}

	result = cli_samr_connect(conn->cli, conn->cli->mem_ctx,
				  des_access, &conn->pol);

	if (!NT_STATUS_IS_OK(result)) {
		/* Hit the cache code again.  This cleans out the old connection and gets a new one */
		if (conn->cli->fd == -1) { /* Try again, if the remote host disapeared */

			if (!NT_STATUS_IS_OK(result = get_connection_from_cache(domain, PIPE_SAMR, &conn, False)))
				return result;

			result = cli_samr_connect(conn->cli, conn->cli->mem_ctx,
						  des_access, &conn->pol);
		}

		if (!NT_STATUS_IS_OK(result)) {

			cli_shutdown(conn->cli);
			DLIST_REMOVE(cm_conns, conn);
			SAFE_FREE(conn);

			return result;
		}
	}	

	hnd.pol = conn->pol;
	hnd.cli = conn->cli;

	*return_hnd = &hnd;

	return NT_STATUS_OK;
}

/* Get a handle on a netlogon pipe.  This is a bit of a hack to re-use the
   netlogon pipe as no handle is returned. */

NTSTATUS cm_get_netlogon_cli(const char *domain, unsigned char *trust_passwd,
			     struct cli_state **cli)
{
	NTSTATUS result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	struct winbindd_cm_conn *conn;

	if (!cli)
		return NT_STATUS_INVALID_PARAMETER;

	/* Open an initial conection - keep the mutex. */

	if (!NT_STATUS_IS_OK(result = get_connection_from_cache(domain, PIPE_NETLOGON, &conn, True)))
		return result;
	
	result = new_cli_nt_setup_creds(conn->cli, (lp_server_role() == ROLE_DOMAIN_MEMBER) ?
					SEC_CHAN_WKSTA : SEC_CHAN_BDC, trust_passwd);

	if (conn->mutex_ref_count)
		secrets_named_mutex_release(conn->controller, &conn->mutex_ref_count);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("cm_get_netlogon_cli: error connecting to domain password server %s for domain %s: %s\n",
			conn->controller, domain, nt_errstr(result)));
		
		/* Hit the cache code again.  This cleans out the old connection and gets a new one */
		if (conn->cli->fd == -1) {
			if (!NT_STATUS_IS_OK(result = get_connection_from_cache(domain, PIPE_NETLOGON, &conn, True)))
				return result;
			
			/* Try again */
			result = new_cli_nt_setup_creds(conn->cli, (lp_server_role() == ROLE_DOMAIN_MEMBER) ?
							SEC_CHAN_WKSTA : SEC_CHAN_BDC, trust_passwd);
		}
		
		if (conn->mutex_ref_count)
			secrets_named_mutex_release(conn->controller, &conn->mutex_ref_count);

		if (!NT_STATUS_IS_OK(result)) {
			cli_shutdown(conn->cli);
			DLIST_REMOVE(cm_conns, conn);
			SAFE_FREE(conn);
			return result;
		}
	}

	*cli = conn->cli;

	return result;
}

/* Dump the current connection status */

static void dump_conn_list(void)
{
	struct winbindd_cm_conn *con;

	DEBUG(0, ("\tDomain	     Controller	     Pipe\n"));

	for(con = cm_conns; con; con = con->next) {
		char *msg;

		/* Display pipe info */
		
		if (asprintf(&msg, "\t%-15s %-15s %-16s", con->domain, con->controller, con->pipe_name) < 0) {
			DEBUG(0, ("Error: not enough memory!\n"));
		} else {
			DEBUG(0, ("%s\n", msg));
			SAFE_FREE(msg);
		}
	}
}

void winbindd_cm_status(void)
{
	/* List open connections */

	DEBUG(0, ("winbindd connection manager status:\n"));

	if (cm_conns)
		dump_conn_list();
	else
		DEBUG(0, ("\tNo active connections\n"));
}

/* Close all cached connections */

void winbindd_cm_flush(void)
{
	struct winbindd_cm_conn *conn, tmp;

	/* Flush connection cache */

	for (conn = cm_conns; conn; conn = conn->next) {

		if (!connection_ok(conn))
			continue;

		DEBUG(10, ("Closing connection to %s on %s\n",
			   conn->pipe_name, conn->controller));

		if (conn->cli)
			cli_shutdown(conn->cli);

		tmp.next = conn->next;

		DLIST_REMOVE(cm_conns, conn);
		SAFE_FREE(conn);
		conn = &tmp;
	}

	/* Flush failed connection cache */

	flush_negative_conn_cache();
}
