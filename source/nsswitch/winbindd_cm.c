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

     - There needs to be a utility function in libsmb/namequery.c that does
       cm_get_dc_name() 

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
	struct cli_state *cli;
	POLICY_HND pol;
};

static struct winbindd_cm_conn *cm_conns = NULL;

/* Get a domain controller name.  Cache positive and negative lookups so we
   don't go to the network too often when something is badly broken. */

#define GET_DC_NAME_CACHE_TIMEOUT 30 /* Seconds between dc lookups */

struct get_dc_name_cache {
	fstring domain_name;
	fstring srv_name;
	time_t lookup_time;
	struct get_dc_name_cache *prev, *next;
};

static BOOL cm_get_dc_name(char *domain, fstring srv_name)
{
	static struct get_dc_name_cache *get_dc_name_cache;
	struct get_dc_name_cache *dcc;
	struct in_addr *ip_list, dc_ip;
	int count, i;

	/* Check the cache for previous lookups */

	for (dcc = get_dc_name_cache; dcc; dcc = dcc->next) {

		if (!strequal(domain, dcc->domain_name))
			continue; /* Not our domain */

		if ((time(NULL) - dcc->lookup_time) > 
		    GET_DC_NAME_CACHE_TIMEOUT) {

			/* Cache entry has expired, delete it */

			DEBUG(10, ("get_dc_name_cache entry expired for %s\n", domain));

			DLIST_REMOVE(get_dc_name_cache, dcc);
			SAFE_FREE(dcc);

			break;
		}

		/* Return a positive or negative lookup for this domain */

		if (dcc->srv_name[0]) {
			DEBUG(10, ("returning positive get_dc_name_cache entry for %s\n", domain));
			fstrcpy(srv_name, dcc->srv_name);
			return True;
		} else {
			DEBUG(10, ("returning negative get_dc_name_cache entry for %s\n", domain));
			return False;
		}
	}

	/* Add cache entry for this lookup. */

	DEBUG(10, ("Creating get_dc_name_cache entry for %s\n", domain));

	if (!(dcc = (struct get_dc_name_cache *) 
	      malloc(sizeof(struct get_dc_name_cache))))
		return False;

	ZERO_STRUCTP(dcc);

	fstrcpy(dcc->domain_name, domain);
	dcc->lookup_time = time(NULL);

	DLIST_ADD(get_dc_name_cache, dcc);

	/* Lookup domain controller name */
		
	if (!get_dc_list(False, domain, &ip_list, &count)) {
		DEBUG(3, ("Could not look up dc's for domain %s\n", domain));
		return False;
	}

	/* Pick a nice close server */
	   
	if (strequal(lp_passwordserver(), "*")) {
		
		/* Look for DC on local net */

		for (i = 0; i < count; i++) {
			if (is_local_net(ip_list[i]) &&
			    name_status_find(domain, 0x1c, 0x20,
					     ip_list[i], srv_name)) {
				dc_ip = ip_list[i];
				goto done;
			}
			zero_ip(&ip_list[i]);
		}

		/* Look for other DCs */

		for (i = 0; i < count; i++) {
			if (!is_zero_ip(ip_list[i]) &&
			    name_status_find(domain, 0x1c, 0x20,
					     ip_list[i], srv_name)) {
				dc_ip = ip_list[i];
				goto done;
			}
		}

		/* No-one to talk to )-: */

		return False;
	}

	/* Return first DC that we can contact */

	for (i = 0; i < count; i++) {
		if (name_status_find(domain, 0x1c, 0x20, ip_list[i],
				     srv_name)) {
			dc_ip = ip_list[i];
			goto done;
		}
	}

	return False;		/* Boo-hoo */
	
 done:
	/* We have the netbios name and IP address of a domain controller.
	   Ideally we should sent a SAMLOGON request to determine whether
	   the DC is alive and kicking.  If we can catch a dead DC before
	   performing a cli_connect() we can avoid a 30-second timeout. */

	/* We have a name so make the cache entry positive now */

	fstrcpy(dcc->srv_name, srv_name);

	DEBUG(3, ("Returning DC %s (%s) for domain %s\n", srv_name,
		  inet_ntoa(dc_ip), domain));

	return True;
}

/* Choose between anonymous or authenticated connections.  We need to use
   an authenticated connection if DCs have the RestrictAnonymous registry
   entry set > 0, or the "Additional restrictions for anonymous
   connections" set in the win2k Local Security Policy. */

void cm_init_creds(struct ntuser_creds *creds)
{
	char *username, *password;

	ZERO_STRUCTP(creds);

	creds->pwd.null_pwd = True; /* anonymoose */

	username = secrets_fetch(SECRETS_AUTH_USER, NULL);
	password = secrets_fetch(SECRETS_AUTH_PASSWORD, NULL);

	if (username && *username) {
		pwd_set_cleartext(&creds->pwd, password);

		fstrcpy(creds->user_name, username);
		fstrcpy(creds->domain, lp_workgroup());

		DEBUG(3, ("IPC$ connections done %s\\%s\n", creds->domain,
			  creds->user_name));
	} else 
		DEBUG(3, ("IPC$ connections done anonymously\n"));
}

/* Open a new smb pipe connection to a DC on a given domain.  Cache
   negative creation attempts so we don't try and connect to broken
   machines too often. */

#define OPEN_CONNECTION_CACHE_TIMEOUT 30 /* Seconds between attempts */

struct open_connection_cache {
	fstring domain_name;
	fstring controller;
	time_t lookup_time;
	struct open_connection_cache *prev, *next;
};

static BOOL cm_open_connection(char *domain, char *pipe_name,
			       struct winbindd_cm_conn *new_conn)
{
	static struct open_connection_cache *open_connection_cache;
	struct open_connection_cache *occ;
	struct nmb_name calling, called;
	extern pstring global_myname;
	fstring dest_host;
	struct in_addr dest_ip;
	BOOL result = False;
	struct ntuser_creds creds;

	fstrcpy(new_conn->domain, domain);
	fstrcpy(new_conn->pipe_name, pipe_name);
	
	/* Look for a domain controller for this domain.  Negative results
	   are cached so don't bother applying the caching for this
	   function just yet.  */

	if (!cm_get_dc_name(domain, new_conn->controller))
		goto done;

	/* Return false if we have tried to look up this domain and netbios
	   name before and failed. */

	for (occ = open_connection_cache; occ; occ = occ->next) {
		
		if (!(strequal(domain, occ->domain_name) &&
		      strequal(new_conn->controller, occ->controller)))
			continue; /* Not our domain */

		if ((time(NULL) - occ->lookup_time) > 
		    OPEN_CONNECTION_CACHE_TIMEOUT) {

			/* Cache entry has expired, delete it */

			DEBUG(10, ("cm_open_connection cache entry expired for %s, %s\n", domain, new_conn->controller));

			DLIST_REMOVE(open_connection_cache, occ);
			free(occ);

			break;
		}

		/* The timeout hasn't expired yet so return false */

		DEBUG(10, ("returning negative open_connection_cache entry for %s, %s\n", domain, new_conn->controller));

		goto done;
	}

	/* Initialise SMB connection */

	if (!(new_conn->cli = cli_initialise(NULL)))
		goto done;

	if (!resolve_srv_name(new_conn->controller, dest_host, &dest_ip))
		goto done;

	make_nmb_name(&called, dns_to_netbios_name(new_conn->controller), 0x20);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0);

	cm_init_creds(&creds);

	cli_init_creds(new_conn->cli, &creds);

	if (!cli_establish_connection(new_conn->cli, new_conn->controller, 
				      &dest_ip, &calling, &called, "IPC$", 
				      "IPC", False, True))
		goto done;

	if (!cli_nt_session_open (new_conn->cli, pipe_name))
		goto done;

	result = True;

 done:

	/* Create negative lookup cache entry for this domain and controller */

	if (!result) {
		if (!(occ = (struct open_connection_cache *)
		      malloc(sizeof(struct open_connection_cache))))
			return False;

		ZERO_STRUCTP(occ);

		fstrcpy(occ->domain_name, domain);
		fstrcpy(occ->controller, new_conn->controller);
		occ->lookup_time = time(NULL);
		
		DLIST_ADD(open_connection_cache, occ);
	}

	if (!result && new_conn->cli)
		cli_shutdown(new_conn->cli);

	return result;
}

/* Return true if a connection is still alive */

static BOOL connection_ok(struct winbindd_cm_conn *conn)
{
	if (!conn->cli->initialised) {
		DEBUG(3, ("Connection to %s for domain %s (pipe %s) was never initialised!\n", 
			  conn->controller, conn->domain, conn->pipe_name));
		return False;
	}

	if (conn->cli->fd == -1) {
		DEBUG(3, ("Connection to %s for domain %s (pipe %s) has died or was never started (fd == -1)\n", 
			  conn->controller, conn->domain, conn->pipe_name));
		return False;
	}
	
	return True;
}

/* Return a LSA policy handle on a domain */

CLI_POLICY_HND *cm_get_lsa_handle(char *domain)
{
	struct winbindd_cm_conn *conn;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	NTSTATUS result;
	static CLI_POLICY_HND hnd;

	/* Look for existing connections */

	for (conn = cm_conns; conn; conn = conn->next) {
		if (strequal(conn->domain, domain) && 
		    strequal(conn->pipe_name, PIPE_LSARPC)) {

			if (!connection_ok(conn)) {
				cli_shutdown(conn->cli);
				DLIST_REMOVE(cm_conns, conn);
				SAFE_FREE(conn);
			}

			goto ok;
		}
	}

	/* Create a new one */

	if (!(conn = (struct winbindd_cm_conn *) malloc(sizeof(struct winbindd_cm_conn))))
		return NULL;

	ZERO_STRUCTP(conn);

	if (!cm_open_connection(domain, PIPE_LSARPC, conn)) {
		DEBUG(3, ("Could not connect to a dc for domain %s\n", domain));
		return NULL;
	}

	result = cli_lsa_open_policy(conn->cli, conn->cli->mem_ctx, False, 
				     des_access, &conn->pol);

	if (!NT_STATUS_IS_OK(result))
		return NULL;

	/* Add to list */

	DLIST_ADD(cm_conns, conn);

 ok:
	hnd.pol = conn->pol;
	hnd.cli = conn->cli;

	return &hnd;
}

/* Return a SAM policy handle on a domain */

CLI_POLICY_HND *cm_get_sam_handle(char *domain)
{ 
	struct winbindd_cm_conn *conn;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	NTSTATUS result;
	static CLI_POLICY_HND hnd;

	/* Look for existing connections */

	for (conn = cm_conns; conn; conn = conn->next) {
		if (strequal(conn->domain, domain) && strequal(conn->pipe_name, PIPE_SAMR)) {

			if (!connection_ok(conn)) {
				cli_shutdown(conn->cli);
				DLIST_REMOVE(cm_conns, conn);
				SAFE_FREE(conn);
			}

			goto ok;
		}
	}

	/* Create a new one */

	if (!(conn = (struct winbindd_cm_conn *) 
	      malloc(sizeof(struct winbindd_cm_conn))))
		return NULL;

	ZERO_STRUCTP(conn);

	if (!cm_open_connection(domain, PIPE_SAMR, conn)) {
		DEBUG(3, ("Could not connect to a dc for domain %s\n", domain));
		return NULL;
	}

	result = cli_samr_connect(conn->cli, conn->cli->mem_ctx,
				  des_access, &conn->pol);

	if (!NT_STATUS_IS_OK(result))
		return NULL;

	/* Add to list */

	DLIST_ADD(cm_conns, conn);

 ok:
	hnd.pol = conn->pol;
	hnd.cli = conn->cli;

	return &hnd;	    
}

#if 0

/* Return a SAM domain policy handle on a domain */

CLI_POLICY_HND *cm_get_sam_dom_handle(char *domain, DOM_SID *domain_sid)
{
	struct winbindd_cm_conn *conn, *basic_conn = NULL;
	static CLI_POLICY_HND hnd;
	NTSTATUS result;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;

	/* Look for existing connections */

	for (conn = cm_conns; conn; conn = conn->next) {
		if (strequal(conn->domain, domain) &&
		    strequal(conn->pipe_name, PIPE_SAMR) &&
		    conn->pipe_data.samr.pipe_type == SAM_PIPE_DOM) {

			if (!connection_ok(conn)) {
				/* Shutdown cli?  Free conn?  Allow retry of DC? */
				DLIST_REMOVE(cm_conns, conn);
				return NULL;
			}

			goto ok;
		}
	}

	/* Create a basic handle to open a domain handle from */

	if (!cm_get_sam_handle(domain))
		return False;

	for (conn = cm_conns; conn; conn = conn->next) {
		if (strequal(conn->domain, domain) &&
		    strequal(conn->pipe_name, PIPE_SAMR) &&
		    conn->pipe_data.samr.pipe_type == SAM_PIPE_BASIC)
			basic_conn = conn;
	}
	
	if (!(conn = (struct winbindd_cm_conn *)
	      malloc(sizeof(struct winbindd_cm_conn))))
		return NULL;
	
	ZERO_STRUCTP(conn);

	fstrcpy(conn->domain, basic_conn->domain);
	fstrcpy(conn->controller, basic_conn->controller);
	fstrcpy(conn->pipe_name, basic_conn->pipe_name);

	conn->pipe_data.samr.pipe_type = SAM_PIPE_DOM;
	conn->cli = basic_conn->cli;

	result = cli_samr_open_domain(conn->cli, conn->cli->mem_ctx,
				      &basic_conn->pol, des_access, 
				      domain_sid, &conn->pol);

	if (!NT_STATUS_IS_OK(result))
		return NULL;

	/* Add to list */

	DLIST_ADD(cm_conns, conn);

 ok:
	hnd.pol = conn->pol;
	hnd.cli = conn->cli;

	return &hnd;
}

/* Return a SAM policy handle on a domain user */

CLI_POLICY_HND *cm_get_sam_user_handle(char *domain, DOM_SID *domain_sid,
				       uint32 user_rid)
{
	struct winbindd_cm_conn *conn, *basic_conn = NULL;
	static CLI_POLICY_HND hnd;
	NTSTATUS result;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;

	/* Look for existing connections */

	for (conn = cm_conns; conn; conn = conn->next) {
		if (strequal(conn->domain, domain) &&
		    strequal(conn->pipe_name, PIPE_SAMR) &&
		    conn->pipe_data.samr.pipe_type == SAM_PIPE_USER &&
		    conn->pipe_data.samr.rid == user_rid) {

			if (!connection_ok(conn)) {
				/* Shutdown cli?  Free conn?  Allow retry of DC? */
				DLIST_REMOVE(cm_conns, conn);
				return NULL;
			}
		
			goto ok;
		}
	}

	/* Create a domain handle to open a user handle from */

	if (!cm_get_sam_dom_handle(domain, domain_sid))
		return NULL;

	for (conn = cm_conns; conn; conn = conn->next) {
		if (strequal(conn->domain, domain) &&
		    strequal(conn->pipe_name, PIPE_SAMR) &&
		    conn->pipe_data.samr.pipe_type == SAM_PIPE_DOM)
			basic_conn = conn;
	}
	
	if (!basic_conn) {
		DEBUG(0, ("No domain sam handle was created!\n"));
		return NULL;
	}

	if (!(conn = (struct winbindd_cm_conn *)
	      malloc(sizeof(struct winbindd_cm_conn))))
		return NULL;
	
	ZERO_STRUCTP(conn);

	fstrcpy(conn->domain, basic_conn->domain);
	fstrcpy(conn->controller, basic_conn->controller);
	fstrcpy(conn->pipe_name, basic_conn->pipe_name);
	
	conn->pipe_data.samr.pipe_type = SAM_PIPE_USER;
	conn->cli = basic_conn->cli;
	conn->pipe_data.samr.rid = user_rid;

	result = cli_samr_open_user(conn->cli, conn->cli->mem_ctx,
				    &basic_conn->pol, des_access, user_rid,
				    &conn->pol);

	if (!NT_STATUS_IS_OK(result))
		return NULL;

	/* Add to list */

	DLIST_ADD(cm_conns, conn);

 ok:
	hnd.pol = conn->pol;
	hnd.cli = conn->cli;

	return &hnd;
}

/* Return a SAM policy handle on a domain group */

CLI_POLICY_HND *cm_get_sam_group_handle(char *domain, DOM_SID *domain_sid,
					uint32 group_rid)
{
	struct winbindd_cm_conn *conn, *basic_conn = NULL;
	static CLI_POLICY_HND hnd;
	NTSTATUS result;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;

	/* Look for existing connections */

	for (conn = cm_conns; conn; conn = conn->next) {
		if (strequal(conn->domain, domain) &&
		    strequal(conn->pipe_name, PIPE_SAMR) &&
		    conn->pipe_data.samr.pipe_type == SAM_PIPE_GROUP &&
		    conn->pipe_data.samr.rid == group_rid) {

			if (!connection_ok(conn)) {
				/* Shutdown cli?  Free conn?  Allow retry of DC? */
				DLIST_REMOVE(cm_conns, conn);
				return NULL;
			}
		
			goto ok;
		}
	}

	/* Create a domain handle to open a user handle from */

	if (!cm_get_sam_dom_handle(domain, domain_sid))
		return NULL;

	for (conn = cm_conns; conn; conn = conn->next) {
		if (strequal(conn->domain, domain) &&
		    strequal(conn->pipe_name, PIPE_SAMR) &&
		    conn->pipe_data.samr.pipe_type == SAM_PIPE_DOM)
			basic_conn = conn;
	}
	
	if (!basic_conn) {
		DEBUG(0, ("No domain sam handle was created!\n"));
		return NULL;
	}

	if (!(conn = (struct winbindd_cm_conn *)
	      malloc(sizeof(struct winbindd_cm_conn))))
		return NULL;
	
	ZERO_STRUCTP(conn);

	fstrcpy(conn->domain, basic_conn->domain);
	fstrcpy(conn->controller, basic_conn->controller);
	fstrcpy(conn->pipe_name, basic_conn->pipe_name);
	
	conn->pipe_data.samr.pipe_type = SAM_PIPE_GROUP;
	conn->cli = basic_conn->cli;
	conn->pipe_data.samr.rid = group_rid;

	result = cli_samr_open_group(conn->cli, conn->cli->mem_ctx,
				    &basic_conn->pol, des_access, group_rid,
				    &conn->pol);

	if (!NT_STATUS_IS_OK(result))
		return NULL;

	/* Add to list */

	DLIST_ADD(cm_conns, conn);

 ok:
	hnd.pol = conn->pol;
	hnd.cli = conn->cli;

	return &hnd;
}

#endif

/* Get a handle on a netlogon pipe.  This is a bit of a hack to re-use the
   netlogon pipe as no handle is returned. */

NTSTATUS cm_get_netlogon_cli(char *domain, unsigned char *trust_passwd,
			     struct cli_state **cli)
{
	struct winbindd_cm_conn *conn;
	NTSTATUS result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	BOOL new_conn = False; /* Is this a new connection, to add to the list? */

	/* Open an initial conection */

	for (conn = cm_conns; conn; conn = conn->next) {
		if (strequal(conn->domain, domain) && 
		    strequal(conn->pipe_name, PIPE_NETLOGON)) {
			if (!connection_ok(conn)) {
				cli_shutdown(conn->cli);
				DLIST_REMOVE(cm_conns, conn);
				SAFE_FREE(conn);
			} else {
				break;
			}
		}
	}

	if (!conn) {
		if (!(conn = (struct winbindd_cm_conn *) malloc(sizeof(struct winbindd_cm_conn))))
			return NT_STATUS_NO_MEMORY;

		ZERO_STRUCTP(conn);
		
		if (!cm_open_connection(domain, PIPE_NETLOGON, conn)) {
			DEBUG(3, ("Could not open a connection to %s\n", domain));
			free(conn);
			return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		}
		
		new_conn = True;
	}
	
	result = new_cli_nt_setup_creds(conn->cli, trust_passwd);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("error connecting to domain password server: %s\n",
			get_nt_error_msg(result)));
			cli_shutdown(conn->cli);
			DLIST_REMOVE(cm_conns, conn);
			SAFE_FREE(conn);
			return result;
	}

	/* Add to list */

	if (new_conn) {
		DLIST_ADD(cm_conns, conn);
	}

	if (cli)
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
