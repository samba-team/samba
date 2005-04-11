/* 
   Unix SMB/CIFS implementation.

   Winbind daemon connection manager

   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett 2002
   
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

#include "includes.h"
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

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

static NTSTATUS get_connection_from_cache(struct winbindd_domain *domain,
					  const char *pipe_name,
					  struct winbindd_cm_conn **conn_out);

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
			*domain = smb_xstrdup(lp_workgroup());
		
		if (!*password || !**password)
			*password = smb_xstrdup("");

		DEBUG(3, ("cm_get_ipc_userpass: Retrieved auth-user from secrets.tdb [%s\\%s]\n", 
			  *domain, *username));

	} else {
		DEBUG(3, ("cm_get_ipc_userpass: No auth-user defined\n"));
		*username = smb_xstrdup("");
		*domain = smb_xstrdup("");
		*password = smb_xstrdup("");
	}
}

/*
  setup for schannel on any pipes opened on this connection
*/
static NTSTATUS setup_schannel( struct cli_state *cli, const char *domain )
{
	NTSTATUS ret;
	uchar trust_password[16];
	uint32 sec_channel_type;
	DOM_SID sid;
	time_t lct;

	/* use the domain trust password if we're on a DC 
	   and this is not our domain */
	
	if ( IS_DC && !strequal(domain, lp_workgroup()) ) {
		char *pass = NULL;
		
		if ( !secrets_fetch_trusted_domain_password( domain, 
			&pass, &sid, &lct) )
		{
			return NT_STATUS_UNSUCCESSFUL;
		}	

		sec_channel_type = SEC_CHAN_DOMAIN;
		E_md4hash(pass, trust_password);
		SAFE_FREE( pass );
		
	} else {
		if (!secrets_fetch_trust_account_password(lp_workgroup(),
			trust_password, NULL, &sec_channel_type)) 
		{
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	ret = cli_nt_setup_netsec(cli, sec_channel_type, 
		AUTH_PIPE_NETSEC | AUTH_PIPE_SIGN, trust_password);

	return ret;
}

static BOOL get_dc_name_via_netlogon(const struct winbindd_domain *domain,
				     fstring dcname, struct in_addr *dc_ip)
{
	struct winbindd_domain *our_domain;
	NTSTATUS result;
	struct winbindd_cm_conn *conn;
	TALLOC_CTX *mem_ctx;

	fstring tmp;
	char *p;

	if (IS_DC)
		return False;

	if (domain->primary)
		return False;

	if ((our_domain = find_our_domain()) == NULL)
		return False;

	result = get_connection_from_cache(our_domain, PIPE_NETLOGON, &conn);
	if (!NT_STATUS_IS_OK(result))
		return False;

	if ((mem_ctx = talloc_init("get_dc_name_via_netlogon")) == NULL)
		return False;

	result = cli_netlogon_getdcname(conn->cli, mem_ctx, domain->name, tmp);

	talloc_destroy(mem_ctx);

	if (!NT_STATUS_IS_OK(result))
		return False;

	/* cli_netlogon_getdcname gives us a name with \\ */
	p = tmp;
	if (*p == '\\') p+=1;
	if (*p == '\\') p+=1;

	fstrcpy(dcname, p);

	if (!resolve_name(dcname, dc_ip, 0x20))
		return False;

	return True;
}

/************************************************************************
 Given a fd with a just-connected TCP connection to a DC, open a connection
 to the pipe.
************************************************************************/

static NTSTATUS cm_prepare_connection(const struct winbindd_domain *domain,
				      const int sockfd,
				      const int pipe_index,
				      const char *controller,
				      struct cli_state **cli,
				      BOOL *retry)
{
	char *machine_password, *machine_krb5_principal;
	char *ipc_username, *ipc_domain, *ipc_password;

	BOOL got_mutex;
	BOOL add_failed_connection = True;

	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	struct sockaddr peeraddr;
	socklen_t peeraddr_len;

	struct sockaddr_in *peeraddr_in = (struct sockaddr_in *)&peeraddr;

	machine_password = secrets_fetch_machine_password(lp_workgroup(), NULL,
							  NULL);
	
	if (asprintf(&machine_krb5_principal, "%s$@%s", global_myname(),
		     lp_realm()) == -1) {
		SAFE_FREE(machine_password);
		return NT_STATUS_NO_MEMORY;
	}

	cm_get_ipc_userpass(&ipc_username, &ipc_domain, &ipc_password);

	*retry = True;

	got_mutex = secrets_named_mutex(controller,
					WINBIND_SERVER_MUTEX_WAIT_TIME);

	if (!got_mutex) {
		DEBUG(0,("cm_open_connection: mutex grab failed for %s\n",
			 controller));
		result = NT_STATUS_POSSIBLE_DEADLOCK;
		goto done;
	}

	if ((*cli = cli_initialise(NULL)) == NULL) {
		DEBUG(1, ("Could not cli_initialize\n"));
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	(*cli)->timeout = 10000; 	/* 10 seconds */
	(*cli)->fd = sockfd;
	fstrcpy((*cli)->desthost, controller);
	(*cli)->use_kerberos = True;

	peeraddr_len = sizeof(peeraddr);

	if ((getpeername((*cli)->fd, &peeraddr, &peeraddr_len) != 0) ||
	    (peeraddr_len != sizeof(struct sockaddr_in)) ||
	    (peeraddr_in->sin_family != PF_INET))
	{
		DEBUG(0,("cm_prepare_connection: %s\n", strerror(errno)));
		goto done;
	}

	if (ntohs(peeraddr_in->sin_port) == 139) {
		struct nmb_name calling;
		struct nmb_name called;

		make_nmb_name(&calling, global_myname(), 0x0);
		make_nmb_name(&called, "*SMBSERVER", 0x20);

		if (!cli_session_request(*cli, &calling, &called)) {
			DEBUG(8, ("cli_session_request failed for %s\n",
				  controller));
			goto done;
		}
	}

	cli_setup_signing_state(*cli, Undefined);

	if (!cli_negprot(*cli)) {
		DEBUG(1, ("cli_negprot failed\n"));
		cli_shutdown(*cli);
		goto done;
	}

	/* Krb5 session */
			
	if ((lp_security() == SEC_ADS) 
	    && ((*cli)->protocol >= PROTOCOL_NT1 &&
		(*cli)->capabilities & CAP_EXTENDED_SECURITY)) {

		ADS_STATUS ads_status;
		(*cli)->use_kerberos = True;
		DEBUG(5, ("connecting to %s from %s with kerberos principal "
			  "[%s]\n", controller, global_myname(),
			  machine_krb5_principal));

		ads_status = cli_session_setup_spnego(*cli,
						      machine_krb5_principal, 
						      machine_password, 
						      lp_workgroup());

		if (!ADS_ERR_OK(ads_status))
			DEBUG(4,("failed kerberos session setup with %s\n",
				 ads_errstr(ads_status)));

		result = ads_ntstatus(ads_status);
	}

	if (NT_STATUS_IS_OK(result))
		goto session_setup_done;

	/* Fall back to non-kerberos session setup */

	(*cli)->use_kerberos = False;

	if ((((*cli)->sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) != 0) &&
	    (strlen(ipc_username) > 0)) {

		/* Only try authenticated if we have a username */

		DEBUG(5, ("connecting to %s from %s with username "
			  "[%s]\\[%s]\n",  controller, global_myname(),
			  ipc_domain, ipc_username));

		if (cli_session_setup(*cli, ipc_username,
				      ipc_password, strlen(ipc_password)+1,
				      ipc_password, strlen(ipc_password)+1,
				      ipc_domain)) {
			DEBUG(5, ("authenticated session setup failed\n"));
			goto session_setup_done;
		}
	}

	/* Fall back to anonymous connection, this might fail later */

	if (cli_session_setup(*cli, "", NULL, 0, NULL, 0, "")) {
		DEBUG(5, ("Connected anonymously\n"));
		goto session_setup_done;
	}

	result = cli_nt_error(*cli);

	if (NT_STATUS_IS_OK(result))
		result = NT_STATUS_UNSUCCESSFUL;

	/* We can't session setup */

	goto done;

 session_setup_done:

	if (!cli_send_tconX(*cli, "IPC$", "IPC", "", 0)) {

		result = cli_nt_error(*cli);

		DEBUG(1,("failed tcon_X with %s\n", nt_errstr(result)));

		if (NT_STATUS_IS_OK(result))
			result = NT_STATUS_UNSUCCESSFUL;

		cli_shutdown(*cli);
		goto done;
	}

	secrets_named_mutex_release(controller);
	got_mutex = False;
	*retry = False;

	/* Windows 2003 SP1 does not lie LsaOpenPolicy() over schannel.
	   Returns RPC_NT_CANNOT_SUPPPORT (0xc0020041) for that call.
	   So just drop it on the lsarpc pipe */

	if ( (domain->primary || IS_DC) && (pipe_index!=PI_LSARPC) ) {
		NTSTATUS status = setup_schannel( *cli, domain->name );
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3,("schannel refused - continuing without "
				 "schannel (%s)\n", nt_errstr(status)));
		}
	}

	/* set the domain if empty; needed for schannel connections */
	if ( !*(*cli)->domain )
		fstrcpy( (*cli)->domain, domain->name );

	if ( !cli_nt_session_open (*cli, pipe_index) ) {

		result = NT_STATUS_PIPE_NOT_AVAILABLE;

		/* This might be a NT4 DC */
		if ( is_win2k_pipe(pipe_index) )
			add_failed_connection = False;

		cli_shutdown(*cli);
		goto done;
	}

	result = NT_STATUS_OK;
	add_failed_connection = False;

 done:
	if (got_mutex)
		secrets_named_mutex_release(controller);

	SAFE_FREE(machine_password);
	SAFE_FREE(machine_krb5_principal);
	SAFE_FREE(ipc_username);
	SAFE_FREE(ipc_domain);
	SAFE_FREE(ipc_password);

	if (add_failed_connection)
		add_failed_connection_entry(domain->name, controller, result);

	return result;
}

struct dc_name_ip {
	fstring name;
	struct in_addr ip;
};

static BOOL add_one_dc_unique(TALLOC_CTX *mem_ctx, const char *domain_name,
			      const char *dcname, struct in_addr ip,
			      struct dc_name_ip **dcs, int *num)
{
	if (!NT_STATUS_IS_OK(check_negative_conn_cache(domain_name, dcname)))
		return False;

	*dcs = TALLOC_REALLOC_ARRAY(mem_ctx, *dcs, struct dc_name_ip, (*num)+1);

	if (*dcs == NULL)
		return False;

	fstrcpy((*dcs)[*num].name, dcname);
	(*dcs)[*num].ip = ip;
	*num += 1;
	return True;
}

static BOOL add_sockaddr_to_array(TALLOC_CTX *mem_ctx,
				  struct in_addr ip, uint16 port,
				  struct sockaddr_in **addrs, int *num)
{
	*addrs = TALLOC_REALLOC_ARRAY(mem_ctx, *addrs, struct sockaddr_in, (*num)+1);

	if (*addrs == NULL)
		return False;

	(*addrs)[*num].sin_family = PF_INET;
	putip((char *)&((*addrs)[*num].sin_addr), (char *)&ip);
	(*addrs)[*num].sin_port = htons(port);

	*num += 1;
	return True;
}

/*******************************************************************
 convert an ip to a name
*******************************************************************/

static void dcip_to_name( const char *domainname, const char *realm, struct in_addr ip, fstring name )
{
	/* try node status request first */

	if ( name_status_find(domainname, 0x1c, 0x20, ip, name) )
		return;

	/* backup in case the ads stuff fails */

	fstrcpy( name, inet_ntoa(ip) );

#ifdef WITH_ADS
	/* for active directory servers, try to get the ldap server name.
	   None of these failure should be considered critical for now */

	if ( lp_security() == SEC_ADS ) 
	{
		ADS_STRUCT *ads;
		ADS_STATUS status;

		ads = ads_init( realm, domainname, NULL );
		ads->auth.flags |= ADS_AUTH_NO_BIND;

		if ( !ads_try_connect( ads, inet_ntoa(ip), LDAP_PORT ) )  {
			ads_destroy( &ads );
			return;
		}

		status = ads_server_info(ads);
		if ( !ADS_ERR_OK(status) ) {
			ads_destroy( &ads );
			return;
		}

		fstrcpy(name, ads->config.ldap_server_name);

		ads_destroy( &ads );
	}
#endif

	return;
}


/*******************************************************************
 Retreive a list of IP address for domain controllers.  Fill in 
 the dcs[]  with results.
*******************************************************************/

static BOOL get_dcs(TALLOC_CTX *mem_ctx, const struct winbindd_domain *domain,
		    struct dc_name_ip **dcs, int *num_dcs)
{
	fstring dcname;
	struct  in_addr ip;
	struct  ip_service *ip_list = NULL;
	int     iplist_size = 0;
	int     i;
	BOOL    is_our_domain;


	is_our_domain = strequal(domain->name, lp_workgroup());

	if ( !is_our_domain 
		&& get_dc_name_via_netlogon(domain, dcname, &ip) 
		&& add_one_dc_unique(mem_ctx, domain->name, dcname, ip, dcs, num_dcs) )
	{
		return True;
	}

	if ( is_our_domain 
		&& must_use_pdc(domain->name) 
		&& get_pdc_ip(domain->name, &ip)) 
	{
		if (add_one_dc_unique(mem_ctx, domain->name, inet_ntoa(ip), ip, dcs, num_dcs)) 
			return True;
	}

	/* try standard netbios queries first */

	get_sorted_dc_list(domain->name, &ip_list, &iplist_size, False);

	/* check for security = ads and use DNS if we can */

	if ( iplist_size==0 && lp_security() == SEC_ADS ) 
		get_sorted_dc_list(domain->alt_name, &ip_list, &iplist_size, True);

	/* now add to the dc array.  We'll wait until the last minute 
	   to look up the name of the DC.  But we fill in the char* for 
	   the ip now in to make the failed connection cache work */

	for ( i=0; i<iplist_size; i++ ) {
		add_one_dc_unique(mem_ctx, domain->name, inet_ntoa(ip_list[i].ip), 
			ip_list[i].ip, dcs, num_dcs);
	}

	SAFE_FREE( ip_list );

	return True;
}

static BOOL find_new_dc(TALLOC_CTX *mem_ctx,
			const struct winbindd_domain *domain,
			fstring dcname, struct sockaddr_in *addr, int *fd)
{
	struct dc_name_ip *dcs = NULL;
	int num_dcs = 0;

	const char **dcnames = NULL;
	int num_dcnames = 0;

	struct sockaddr_in *addrs = NULL;
	int num_addrs = 0;

	int i, fd_index;

	if (!get_dcs(mem_ctx, domain, &dcs, &num_dcs) || (num_dcs == 0))
		return False;

	for (i=0; i<num_dcs; i++) {

		add_string_to_array(mem_ctx, dcs[i].name,
				    &dcnames, &num_dcnames);
		add_sockaddr_to_array(mem_ctx, dcs[i].ip, 445,
				      &addrs, &num_addrs);

		add_string_to_array(mem_ctx, dcs[i].name,
				    &dcnames, &num_dcnames);
		add_sockaddr_to_array(mem_ctx, dcs[i].ip, 139,
				      &addrs, &num_addrs);
	}

	if ((num_dcnames == 0) || (num_dcnames != num_addrs))
		return False;

	if ( !open_any_socket_out(addrs, num_addrs, 10000, &fd_index, fd) ) 
	{
		for (i=0; i<num_dcs; i++) {
			add_failed_connection_entry(domain->name,
				dcs[i].name, NT_STATUS_UNSUCCESSFUL);
		}
		return False;
	}

	*addr = addrs[fd_index];

	/* if we have no name on the server or just an IP address for 
	   the name, now try to get the name */

	if ( is_ipaddress(dcnames[fd_index]) || *dcnames[fd_index] == '\0' )
		dcip_to_name( domain->name, domain->alt_name, addr->sin_addr, dcname );
	else
		fstrcpy(dcname, dcnames[fd_index]);

	return True;
}

static NTSTATUS cm_open_connection(struct winbindd_domain *domain,
				   const int pipe_index,
				   struct winbindd_cm_conn *new_conn)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS result;

	int retries;

	if ((mem_ctx = talloc_init("cm_open_connection")) == NULL)
		return NT_STATUS_NO_MEMORY;

	for (retries = 0; retries < 3; retries++) {

		int fd = -1;
		BOOL retry;

		result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;

		if ((strlen(domain->dcname) > 0) &&
		    NT_STATUS_IS_OK(check_negative_conn_cache(domain->name,
							      domain->dcname))) {
			int dummy;
			if (!open_any_socket_out(&domain->dcaddr, 1, 10000,
						 &dummy, &fd)) {
				fd = -1;
			}
		}

		if ((fd == -1) &&
		    !find_new_dc(mem_ctx, domain, domain->dcname,
				 &domain->dcaddr, &fd))
			break;

		new_conn->cli = NULL;

		result = cm_prepare_connection(domain, fd, pipe_index,
					       domain->dcname,
					       &new_conn->cli, &retry);

		if (NT_STATUS_IS_OK(result)) {
			fstrcpy(new_conn->domain, domain->name);
			/* Initialise SMB connection */
			fstrcpy(new_conn->pipe_name,
				get_pipe_name_from_index(pipe_index));
			break;
		}

		if (!retry)
			break;
	}

	talloc_destroy(mem_ctx);
	return result;
}

/************************************************************************
 Wrapper around statuc cm_open_connection to retreive a freshly
 setup cli_state struct
************************************************************************/

NTSTATUS cm_fresh_connection(struct winbindd_domain *domain, const int pipe_index,
			       struct cli_state **cli)
{
	NTSTATUS result;
	struct winbindd_cm_conn conn;
	
	result = cm_open_connection( domain, pipe_index, &conn );
	
	if ( NT_STATUS_IS_OK(result) ) 
		*cli = conn.cli;

	return result;
}

/* Return true if a connection is still alive */

static BOOL connection_ok(struct winbindd_cm_conn *conn)
{
	if (!conn) {
		smb_panic("Invalid parameter passed to connection_ok():  conn was NULL!\n");
		return False;
	}

	if (!conn->cli) {
		DEBUG(3, ("Connection to %s for domain %s (pipe %s) has NULL conn->cli!\n", 
			  conn->controller, conn->domain, conn->pipe_name));
		return False;
	}

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

/* Search the cache for a connection. If there is a broken one,
   shut it down properly and return NULL. */

static void find_cm_connection(struct winbindd_domain *domain, const char *pipe_name,
			       struct winbindd_cm_conn **conn_out) 
{
	struct winbindd_cm_conn *conn;

	for (conn = cm_conns; conn; ) {
		if (strequal(conn->domain, domain->name) && 
		    strequal(conn->pipe_name, pipe_name)) {
			if (!connection_ok(conn)) {
				/* Dead connection - remove it. */
				struct winbindd_cm_conn *conn_temp = conn->next;
				if (conn->cli)
					cli_shutdown(conn->cli);
				DLIST_REMOVE(cm_conns, conn);
				SAFE_FREE(conn);
				conn = conn_temp;  /* Keep the loop moving */
				continue;
			} else {
				break;
			}
		}
		conn = conn->next;
	}

	*conn_out = conn;
}

/* Initialize a new connection up to the RPC BIND. */

static NTSTATUS new_cm_connection(struct winbindd_domain *domain, const char *pipe_name,
				  struct winbindd_cm_conn **conn_out)
{
	struct winbindd_cm_conn *conn;
	NTSTATUS result;

	if (!(conn = SMB_MALLOC_P(struct winbindd_cm_conn)))
		return NT_STATUS_NO_MEMORY;
		
	ZERO_STRUCTP(conn);
		
	if (!NT_STATUS_IS_OK(result = cm_open_connection(domain, get_pipe_index(pipe_name), conn))) {
		DEBUG(3, ("Could not open a connection to %s for %s (%s)\n", 
			  domain->name, pipe_name, nt_errstr(result)));
		SAFE_FREE(conn);
		return result;
	}
	DLIST_ADD(cm_conns, conn);

	*conn_out = conn;
	return NT_STATUS_OK;
}

/* Get a connection to the remote DC and open the pipe.  If there is already a connection, use that */

static NTSTATUS get_connection_from_cache(struct winbindd_domain *domain, const char *pipe_name,
					  struct winbindd_cm_conn **conn_out)
{
	find_cm_connection(domain, pipe_name, conn_out);

	if (*conn_out != NULL)
		return NT_STATUS_OK;

	return new_cm_connection(domain, pipe_name, conn_out);
}

/**********************************************************************************
 We can 'sense' certain things about the DC by it's replies to certain questions.

 This tells us if this particular remote server is Active Directory, and if it is
 native mode.
**********************************************************************************/

void set_dc_type_and_flags( struct winbindd_domain *domain )
{
	NTSTATUS 		result;
	struct winbindd_cm_conn	conn;
	DS_DOMINFO_CTR		ctr;
	TALLOC_CTX              *mem_ctx = NULL;
	
	ZERO_STRUCT( conn );
	ZERO_STRUCT( ctr );
	
	domain->native_mode = False;
	domain->active_directory = False;

	if (domain->internal) {
		domain->initialized = True;
		return;
	}
	
	if ( !NT_STATUS_IS_OK(result = cm_open_connection(domain, PI_LSARPC_DS, &conn)) ) {
		DEBUG(5, ("set_dc_type_and_flags: Could not open a connection to %s for PIPE_LSARPC (%s)\n", 
			  domain->name, nt_errstr(result)));
		domain->initialized = True;
		return;
	}
	
	if ( conn.cli ) {
		if ( !NT_STATUS_IS_OK(cli_ds_getprimarydominfo( conn.cli, 
				conn.cli->mem_ctx, DsRolePrimaryDomainInfoBasic, &ctr)) ) {
			goto done;
		}
	}
				
	if ( (ctr.basic->flags & DSROLE_PRIMARY_DS_RUNNING) 
			&& !(ctr.basic->flags & DSROLE_PRIMARY_DS_MIXED_MODE) )
		domain->native_mode = True;

	/* Cheat - shut down the DS pipe, and open LSA */

	cli_nt_session_close(conn.cli);

	if ( cli_nt_session_open (conn.cli, PI_LSARPC) ) {
		char *domain_name = NULL;
		char *dns_name = NULL;
		DOM_SID *dom_sid = NULL;

		mem_ctx = talloc_init("set_dc_type_and_flags on domain %s\n", domain->name);
		if (!mem_ctx) {
			DEBUG(1, ("set_dc_type_and_flags: talloc_init() failed\n"));
			return;
		}

		result = cli_lsa_open_policy2(conn.cli, mem_ctx, True, 
					      SEC_RIGHTS_MAXIMUM_ALLOWED,
					      &conn.pol);
		
		if (NT_STATUS_IS_OK(result)) {
			/* This particular query is exactly what Win2k clients use 
			   to determine that the DC is active directory */
			result = cli_lsa_query_info_policy2(conn.cli, mem_ctx, 
							    &conn.pol,
							    12, &domain_name,
							    &dns_name, NULL,
							    NULL, &dom_sid);
		}

		if (NT_STATUS_IS_OK(result)) {
			if (domain_name)
				fstrcpy(domain->name, domain_name);
			
			if (dns_name)
				fstrcpy(domain->alt_name, dns_name);

			if (dom_sid) 
				sid_copy(&domain->sid, dom_sid);

			domain->active_directory = True;
		} else {
			
			result = cli_lsa_open_policy(conn.cli, mem_ctx, True, 
						     SEC_RIGHTS_MAXIMUM_ALLOWED,
						     &conn.pol);
			
			if (!NT_STATUS_IS_OK(result))
				goto done;
			
			result = cli_lsa_query_info_policy(conn.cli, mem_ctx, 
							   &conn.pol, 5, &domain_name, 
							   &dom_sid);
			
			if (NT_STATUS_IS_OK(result)) {
				if (domain_name)
					fstrcpy(domain->name, domain_name);
				
				if (dom_sid) 
					sid_copy(&domain->sid, dom_sid);
			}
		}
	}
	
done:
	
	DEBUG(3,("add_trusted_domain: %s is an %s %s domain\n", domain->name,
		domain->active_directory ? "ADS" : "NT4",
		domain->native_mode ? "native mode" :
		((domain->active_directory && !domain->native_mode) ? "mixed mode" : "")));

	/* close the connection;  no other calls use this pipe and it is called only
	   on reestablishing the domain list   --jerry */
	
	if ( conn.cli )
		cli_shutdown( conn.cli );
	
	talloc_destroy(mem_ctx);

	domain->initialized = True;
	
	return;
}



/* Return a LSA policy handle on a domain */

NTSTATUS cm_get_lsa_handle(struct winbindd_domain *domain, CLI_POLICY_HND **return_hnd)
{
	struct winbindd_cm_conn *conn;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	NTSTATUS result;
	static CLI_POLICY_HND hnd;

	/* Look for existing connections */

	if (!NT_STATUS_IS_OK(result = get_connection_from_cache(domain, PIPE_LSARPC, &conn)))
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
			if (!NT_STATUS_IS_OK(result = get_connection_from_cache(domain, PIPE_LSARPC, &conn)))
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

NTSTATUS cm_get_sam_handle(struct winbindd_domain *domain, CLI_POLICY_HND **return_hnd)
{ 
	struct winbindd_cm_conn *conn;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	NTSTATUS result;
	static CLI_POLICY_HND hnd;

	/* Look for existing connections */

	if (!NT_STATUS_IS_OK(result = get_connection_from_cache(domain, PIPE_SAMR, &conn)))
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
		
			if (!NT_STATUS_IS_OK(result = get_connection_from_cache(domain, PIPE_SAMR, &conn)))
				return result;

			result = cli_samr_connect(conn->cli, conn->cli->mem_ctx,
						  des_access, &conn->pol);
		}

		if (!NT_STATUS_IS_OK(result)) {
		
			cli_shutdown(conn->cli);
			DLIST_REMOVE(cm_conns, conn);
			SAFE_FREE(conn);

			/* log a message for possible Windows 2003 SP1 DC's */
			if ( NT_STATUS_EQUAL(result,NT_STATUS_ACCESS_DENIED) && (lp_security() == SEC_DOMAIN) ) {
				DEBUG(0,("samr_connect() received NT_STATUS_ACCESS_DENIED.  If you are connecting \n"));
				DEBUGADD(0,("to a Windows 2003 SP1 DC, this is a known issue.  There are two current \n"));
				DEBUGADD(0,("workarounds:\n"));
				DEBUGADD(0,("(a) Move your configuration to security = ads, or\n"));
				DEBUGADD(0,("(b) set 'client schannel = no' in smb.conf and use 'wbinfo --set-auth-user'\n"));
				DEBUGADD(0,("    to define the credentials when connecting to the DC\n"));
			}
			
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

NTSTATUS cm_get_netlogon_cli(struct winbindd_domain *domain, 
			     const unsigned char *trust_passwd, 
			     uint32 sec_channel_type,
			     BOOL fresh,
			     struct cli_state **cli)
{
	NTSTATUS result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	struct winbindd_cm_conn *conn;
	fstring lock_name;
	BOOL got_mutex;

	if (!cli)
		return NT_STATUS_INVALID_PARAMETER;

	/* Open an initial conection - keep the mutex. */

	find_cm_connection(domain, PIPE_NETLOGON, &conn);

	if ( fresh && (conn != NULL) ) {
		cli_shutdown(conn->cli);
		conn->cli = NULL;

		conn = NULL;

		/* purge connection from cache */
		find_cm_connection(domain, PIPE_NETLOGON, &conn);
		if (conn != NULL) {
			DEBUG(0,("Could not purge connection\n"));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	if (conn != NULL) {
		*cli = conn->cli;
		return NT_STATUS_OK;
	}

	result = new_cm_connection(domain, PIPE_NETLOGON, &conn);

	if (!NT_STATUS_IS_OK(result))
		return result;
	
	fstr_sprintf(lock_name, "NETLOGON\\%s", conn->controller);

	if (!(got_mutex = secrets_named_mutex(lock_name, WINBIND_SERVER_MUTEX_WAIT_TIME))) {
		DEBUG(0,("cm_get_netlogon_cli: mutex grab failed for %s\n", conn->controller));
	}
	
	if ( sec_channel_type == SEC_CHAN_DOMAIN )
		fstr_sprintf(conn->cli->mach_acct, "%s$", lp_workgroup());
			
	/* This must be the remote domain (not ours) for schannel */

	fstrcpy( conn->cli->domain, domain->name);
	
	result = cli_nt_establish_netlogon(conn->cli, sec_channel_type, trust_passwd);
	
	if (got_mutex)
		secrets_named_mutex_release(lock_name);
				
	if (!NT_STATUS_IS_OK(result)) {
		cli_shutdown(conn->cli);
		DLIST_REMOVE(cm_conns, conn);
		SAFE_FREE(conn);
		return result;
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
