/* 
   Unix SMB/Netbios implementation.
   Version 3.0

   Winbind daemon connection manager

   Copyright (C) Tim Potter 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
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
   like that but at the moment it's simply staying as part of winbind.  I
   think the TNG architecture of forcing every user of the rpc layer to use
   the connection caching system is a bad idea.  It should be an optional
   method of using the routines.  We actually cache policy handles - tng
   caches connections to pipes.

   The TNG design is quite good but I disagree with some aspects of the
   implementation. -tpot

 */

/*
   TODO:

     - I'm pretty annoyed by all the make_nmb_name() stuff.  It should be
       moved down into another function.

     - There needs to be a utility function in libsmb/namequery.c that does
       cm_get_dc_name() 

     - When closing down sam handles we need to close down user, group and
       domain handles.

     - Take care when destroying cli_structs as they can be shared between
       various sam handles.

 */

#include "winbindd.h"

/* We store lists of connections here */

enum sam_pipe_type {
        SAM_PIPE_BASIC,         /* A basic handle */
        SAM_PIPE_DOM,           /* A domain handle */
        SAM_PIPE_USER,          /* A handle on a user */
        SAM_PIPE_GROUP          /* A handle on a group */
};

struct winbindd_cm_conn {
        struct winbindd_cm_conn *prev, *next;
        fstring domain;
        fstring controller;
        fstring pipe_name;
        struct cli_state *cli;
        POLICY_HND pol;

        /* Specific pipe stuff - move into a union? */

        enum sam_pipe_type sam_pipe_type; /* Domain, user, group etc  */
        uint32 user_rid;
};

/* Global list of connections.  Initially a DLIST but can become a hash
   table or whatever later. */

struct winbindd_cm_conn *cm_conns = NULL;

/* Get a domain controller name */

BOOL cm_get_dc_name(char *domain, fstring srv_name)
{
	struct in_addr *ip_list, dc_ip;
	extern pstring global_myname;
	int count, i;

	/* Lookup domain controller name */
		
	if (!get_dc_list(False, domain, &ip_list, &count))
		return False;
		
	/* Firstly choose a PDC/BDC who has the same network address as any
	   of our interfaces. */
	
	for (i = 0; i < count; i++) {
		if(!is_local_net(ip_list[i]))
			goto got_ip;
	}
	
	i = (sys_random() % count);
	
 got_ip:
	dc_ip = ip_list[i];
	SAFE_FREE(ip_list);
		
	if (!lookup_pdc_name(global_myname, domain, &dc_ip, srv_name))
		return False;

	return True;
}

/* Open a new smb pipe connection to a DC on a given domain */

static BOOL cm_open_connection(char *domain, char *pipe_name,
                               struct winbindd_cm_conn *new_conn)
{
	struct nmb_name calling, called;
        extern pstring global_myname;
        fstring dest_host;
        struct in_addr dest_ip;
        BOOL result = False;
        struct ntuser_creds creds;

        fstrcpy(new_conn->domain, domain);
        fstrcpy(new_conn->pipe_name, pipe_name);
        
        /* Look for a domain controller for this domain */

        if (!cm_get_dc_name(domain, new_conn->controller))
                goto done;

        /* Initialise SMB connection */

        if (!(new_conn->cli = cli_initialise(NULL)))
                goto done;

	if (!resolve_srv_name(new_conn->controller, dest_host, &dest_ip))
		goto done;

	make_nmb_name(&called, dns_to_netbios_name(new_conn->controller), 
                      0x20);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0);

	ZERO_STRUCT(creds);
	creds.pwd.null_pwd = 1;

	cli_init_creds(new_conn->cli, &creds);

	if (!cli_establish_connection(new_conn->cli, new_conn->controller, 
                                      &dest_ip, &calling, &called, "IPC$", 
                                      "IPC", False, True))
		goto done;

	if (!cli_nt_session_open (new_conn->cli, pipe_name))
		goto done;

        result = True;

 done:
        if (!result && new_conn->cli)
                cli_shutdown(new_conn->cli);

        return result;
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
                    strequal(conn->pipe_name, PIPE_LSARPC))
                        goto ok;
        }

        /* Create a new one */

        if (!(conn = (struct winbindd_cm_conn *)
              malloc(sizeof(struct winbindd_cm_conn))))
                return NULL;

        ZERO_STRUCTP(conn);

        if (!cm_open_connection(domain, PIPE_LSARPC, conn)) {
                DEBUG(3, ("Could not connect to a dc for domain %s\n",
                          domain));
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
                if (strequal(conn->domain, domain) &&
                    strequal(conn->pipe_name, PIPE_SAMR) &&
                    conn->sam_pipe_type == SAM_PIPE_BASIC)
                        goto ok;
        }

        /* Create a new one */

        if (!(conn = (struct winbindd_cm_conn *)
              malloc(sizeof(struct winbindd_cm_conn))))
                return NULL;

        ZERO_STRUCTP(conn);

        if (!cm_open_connection(domain, PIPE_SAMR, conn)) {
                DEBUG(3, ("Could not connect to a dc for domain %s\n",
                          domain));
                return NULL;
        }

        result = cli_samr_connect(conn->cli, conn->cli->mem_ctx, des_access, 
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
                    conn->sam_pipe_type == SAM_PIPE_DOM)
                        goto ok;
        }

        /* Create a basic handle to open a domain handle from */

        if (!cm_get_sam_handle(domain))
                return False;

        for (conn = cm_conns; conn; conn = conn->next) {
                if (strequal(conn->domain, domain) &&
                    strequal(conn->pipe_name, PIPE_SAMR) &&
                    conn->sam_pipe_type == SAM_PIPE_BASIC)
                        basic_conn = conn;
        }
        
        if (!basic_conn) {
                DEBUG(0, ("No basic sam handle was created!\n"));
                return NULL;

                }
        if (!(conn = (struct winbindd_cm_conn *)
              malloc(sizeof(struct winbindd_cm_conn))))
                return NULL;
        
        ZERO_STRUCTP(conn);

        fstrcpy(conn->domain, basic_conn->domain);
        fstrcpy(conn->controller, basic_conn->controller);
        fstrcpy(conn->pipe_name, basic_conn->pipe_name);

        conn->sam_pipe_type = SAM_PIPE_DOM;
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
                    conn->sam_pipe_type == SAM_PIPE_USER &&
                    conn->user_rid == user_rid)
                        goto ok;
        }

        /* Create a domain handle to open a user handle from */

        if (!cm_get_sam_dom_handle(domain, domain_sid))
                return NULL;

        for (conn = cm_conns; conn; conn = conn->next) {
                if (strequal(conn->domain, domain) &&
                    strequal(conn->pipe_name, PIPE_SAMR) &&
                    conn->sam_pipe_type == SAM_PIPE_DOM)
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
        
        conn->sam_pipe_type = SAM_PIPE_USER;
        conn->cli = basic_conn->cli;
        conn->user_rid = user_rid;

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

CLI_POLICY_HND *cm_get_sam_group_handle(char *domain, char *group)
{
        DEBUG(0, ("get_sam_group_handle(): not implemented\n"));
        return NULL;
}
