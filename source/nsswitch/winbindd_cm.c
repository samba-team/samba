/* 
   Unix SMB/CIFS implementation.

   Winbind daemon connection manager

   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett 2002
   Copyright (C) Volker Lendecke 2004
   
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

		DEBUG(3, ("IPC$ connections done by user %s\\%s\n", 
			  *domain, *username));

	} else {
		DEBUG(3, ("IPC$ connections done anonymously\n"));
		*username = smb_xstrdup("");
		*domain = smb_xstrdup("");
		*password = smb_xstrdup("");
	}
}

static BOOL get_dc_name_via_netlogon(const struct winbindd_domain *domain,
				     fstring dcname, struct in_addr *dc_ip)
{
	struct winbindd_domain *our_domain;
	NTSTATUS result;
	struct rpc_pipe_client *cli;
	TALLOC_CTX *mem_ctx;

	fstring tmp;
	char *p;

	/* Hmmmm. We can only open one connection to the NETLOGON pipe at the
	 * moment.... */

	if (IS_DC)
		return False;

	if (domain->primary)
		return False;

	if ((our_domain = find_our_domain()) == NULL)
		return False;

	if ((mem_ctx = talloc_init("get_dc_name_via_netlogon")) == NULL)
		return False;

	{
		/* These var's can be ignored -- we're not requesting
		   anything in the credential chain here */
		unsigned char *session_key;
		DOM_CRED *creds;
		result = cm_connect_netlogon(our_domain, mem_ctx, &cli,
					     &session_key, &creds);
	}

	if (!NT_STATUS_IS_OK(result))
		return False;

	result = rpccli_netlogon_getdcname(cli, mem_ctx, domain->dcname,
					   domain->name, tmp);

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

	/* set the domain if empty; needed for schannel connections */
	if ( !*(*cli)->domain )
		fstrcpy( (*cli)->domain, domain->name );

	(*cli)->pipe_auth_flags = 0;

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

static void mailslot_name(struct in_addr dc_ip, fstring name)
{
	fstr_sprintf(name, "\\MAILSLOT\\NET\\GETDC%X", dc_ip.s_addr);
}

static BOOL send_getdc_request(struct in_addr dc_ip,
			       const char *domain_name,
			       const DOM_SID *sid)
{
	pstring outbuf;
	char *p;
	fstring my_acct_name;
	fstring my_mailslot;

	mailslot_name(dc_ip, my_mailslot);

	memset(outbuf, '\0', sizeof(outbuf));

	p = outbuf;

	SCVAL(p, 0, SAMLOGON);
	p++;

	SCVAL(p, 0, 0); /* Count pointer ... */
	p++;

	SIVAL(p, 0, 0); /* The sender's token ... */
	p += 2;

	p += dos_PutUniCode(p, global_myname(), sizeof(pstring), True);
	fstr_sprintf(my_acct_name, "%s$", global_myname());
	p += dos_PutUniCode(p, my_acct_name, sizeof(pstring), True);

	memcpy(p, my_mailslot, strlen(my_mailslot)+1);
	p += strlen(my_mailslot)+1;

	SIVAL(p, 0, 0x80);
	p+=4;

	SIVAL(p, 0, sid_size(sid));
	p+=4;

	p = ALIGN4(p, outbuf);

	sid_linearize(p, sid_size(sid), sid);
	p += sid_size(sid);

	SIVAL(p, 0, 1);
	SSVAL(p, 4, 0xffff);
	SSVAL(p, 6, 0xffff);
	p+=8;

	return cli_send_mailslot(False, "\\MAILSLOT\\NET\\NTLOGON", 0,
				 outbuf, PTR_DIFF(p, outbuf),
				 global_myname(), 0, domain_name, 0x1c,
				 dc_ip);
}

static BOOL receive_getdc_response(struct in_addr dc_ip,
				   const char *domain_name,
				   fstring dc_name)
{
	struct packet_struct *packet;
	fstring my_mailslot;
	char *buf, *p;
	fstring dcname, user, domain;
	int len;

	mailslot_name(dc_ip, my_mailslot);

	packet = receive_unexpected(DGRAM_PACKET, 0, my_mailslot);

	if (packet == NULL) {
		DEBUG(5, ("Did not receive packet for %s\n", my_mailslot));
		return False;
	}

	DEBUG(5, ("Received packet for %s\n", my_mailslot));

	buf = packet->packet.dgram.data;
	len = packet->packet.dgram.datasize;

	if (len < 70) {
		/* 70 is a completely arbitrary value to make sure
		   the SVAL below does not read uninitialized memory */
		DEBUG(3, ("GetDC got short response\n"));
		return False;
	}

	/* This should be (buf-4)+SVAL(buf-4, smb_vwv12)... */
	p = buf+SVAL(buf, smb_vwv10);

	if (CVAL(p,0) != SAMLOGON_R) {
		DEBUG(8, ("GetDC got invalid response type %d\n", CVAL(p, 0)));
		return False;
	}

	p+=2;
	pull_ucs2(buf, dcname, p, sizeof(dcname), PTR_DIFF(buf+len, p),
		  STR_TERMINATE|STR_NOALIGN);
	p = skip_unibuf(p, PTR_DIFF(buf+len, p));
	pull_ucs2(buf, user, p, sizeof(dcname), PTR_DIFF(buf+len, p),
		  STR_TERMINATE|STR_NOALIGN);
	p = skip_unibuf(p, PTR_DIFF(buf+len, p));
	pull_ucs2(buf, domain, p, sizeof(dcname), PTR_DIFF(buf+len, p),
		  STR_TERMINATE|STR_NOALIGN);
	p = skip_unibuf(p, PTR_DIFF(buf+len, p));

	if (!strequal(domain, domain_name)) {
		DEBUG(3, ("GetDC: Expected domain %s, got %s\n",
			  domain_name, domain));
		return False;
	}

	p = dcname;
	if (*p == '\\')	p += 1;
	if (*p == '\\')	p += 1;

	fstrcpy(dc_name, p);

	DEBUG(10, ("GetDC gave name %s for domain %s\n",
		   dc_name, domain));

	return True;
}

static BOOL get_dcs_1c(TALLOC_CTX *mem_ctx,
		       const struct winbindd_domain *domain,
		       struct dc_name_ip **dcs, int *num_dcs)
{
	struct ip_service *iplist = NULL;
	int i, num = 0;
	struct bitmap *replied;

	if (!internal_resolve_name(domain->name, 0x1c, &iplist, &num,
				   lp_name_resolve_order()))
		return False;

	replied = bitmap_talloc(mem_ctx, num);

	if (replied == NULL)
		return False;

	for (i=0; i<num; i++) {
		if (!send_getdc_request(iplist[i].ip, domain->name,
					&domain->sid)) {
			DEBUG(10, ("Defaulting to nbtstat method\n"));
			goto nbtstat;
		}
	}

	for (i=0; i<5; i++) {
		int j;
		BOOL retry = False;

		for (j = 0; j<num; j++) {

			fstring dcname;

			if (bitmap_query(replied, j))
				continue;

			if (receive_getdc_response(iplist[j].ip,
						   domain->name,
						   dcname)) {
				add_one_dc_unique(mem_ctx, domain->name,
						  dcname, iplist[j].ip,
						  dcs, num_dcs);
				bitmap_set(replied, j);
			} else {
				retry = True;
			}
		}

		if (!retry)
			break;

		smb_msleep(1000);
	}

	if (*num_dcs > 0)
		return True;

 nbtstat:

	/* Fall back to the old method with the name status request */

	for (i=0; i<num; i++) {

		fstring dcname;

		if (!name_status_find(domain->name, 0x1c, 0x20, iplist[i].ip,
				      dcname))
			continue;

		if (add_one_dc_unique(mem_ctx, domain->name, dcname,
				      iplist[i].ip, dcs, num_dcs)) {
			/* One DC responded, so we assume that he will also
			   work on 139/445 */
			break;
		}
	}

	SAFE_FREE(iplist);

	return True;
}

static BOOL get_one_dc_name(struct in_addr ip, const char *domain_name,
			    const DOM_SID *sid, fstring dcname)
{
	int i;

	send_getdc_request(ip, domain_name, sid);
	smb_msleep(100);

	for (i=0; i<5; i++) {
		if (receive_getdc_response(ip, domain_name, dcname))
			return True;
		smb_msleep(500);
	}

	return name_status_find(domain_name, 0x1c, 0x20, ip, dcname);
}

static BOOL get_dcs(TALLOC_CTX *mem_ctx, const struct winbindd_domain *domain,
		    struct dc_name_ip **dcs, int *num_dcs)
{
	fstring dcname;
	struct in_addr ip;
	BOOL is_our_domain;

	const char *p;

	is_our_domain = strequal(domain->name, lp_workgroup());

	DEBUG(5, ("get_dcs: %s %s our domain\n", domain->name,
		  is_our_domain ? "is" : "is not"));

	if (!is_our_domain && get_dc_name_via_netlogon(domain, dcname, &ip) &&
	    add_one_dc_unique(mem_ctx, domain->name, dcname, ip, dcs, num_dcs))
			return True;

	if (!is_our_domain) {
		/* NETLOGON to our own domain could not give us a DC name
		 * (which is an error), fall back to looking up domain#1c */
		return get_dcs_1c(mem_ctx, domain, dcs, num_dcs);
	}

	if (must_use_pdc(domain->name) && get_pdc_ip(domain->name, &ip)) {

		if (!name_status_find(domain->name, 0x1b, 0x20, ip, dcname))
			return False;

		if (add_one_dc_unique(mem_ctx, domain->name,
				      dcname, ip, dcs, num_dcs))
			return True;
	}

	p = lp_passwordserver();

	if (*p == 0)
		return get_dcs_1c(mem_ctx, domain, dcs, num_dcs);

	while (next_token(&p, dcname, LIST_SEP, sizeof(dcname))) {

		if (strequal(dcname, "*")) {
			get_dcs_1c(mem_ctx, domain, dcs, num_dcs);
			continue;
		}

		if (!resolve_name(dcname, &ip, 0x20))
			continue;

		/* Even if we got the dcname, double check the name to use for
		 * the netlogon auth2 */

		if (!get_one_dc_name(ip, domain->name, &domain->sid, dcname))
			continue;

		add_one_dc_unique(mem_ctx, domain->name, dcname, ip,
				  dcs, num_dcs);
	}

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

	if (!open_any_socket_out(addrs, num_addrs, 10000, &fd_index, fd)) {
		for (i=0; i<num_dcs; i++) {
			add_failed_connection_entry(domain->name,
						    dcs[i].name,
						    NT_STATUS_UNSUCCESSFUL);
		}
		return False;
	}

	fstrcpy(dcname, dcnames[fd_index]);
	*addr = addrs[fd_index];

	return True;
}

static NTSTATUS cm_open_connection(struct winbindd_domain *domain,
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

		result = cm_prepare_connection(domain, fd, domain->dcname,
					       &new_conn->cli, &retry);

		if (NT_STATUS_IS_OK(result))
			break;

		if (!retry)
			break;
	}

	talloc_destroy(mem_ctx);
	return result;
}

/* Return true if a connection is still alive */

void invalidate_cm_connection(struct winbindd_cm_conn *conn)
{
	if (conn->samr_pipe != NULL) {
		cli_rpc_close(conn->samr_pipe);
		conn->samr_pipe = NULL;
	}

	if (conn->lsa_pipe != NULL) {
		cli_rpc_close(conn->lsa_pipe);
		conn->lsa_pipe = NULL;
	}

	if (conn->netlogon_auth2_pipe != NULL) {
		cli_rpc_close(conn->netlogon_auth2_pipe);
		conn->netlogon_auth2_pipe = NULL;
	}

	if (conn->netlogon_pipe != NULL) {
		cli_rpc_close(conn->netlogon_pipe);
		conn->netlogon_pipe = NULL;
	}

	if (conn->cli)
		cli_shutdown(conn->cli);

	conn->cli = NULL;
}

static BOOL connection_ok(struct winbindd_domain *domain)
{
	if (domain->conn.cli == NULL) {
		DEBUG(8, ("Connection to %s for domain %s has NULL "
			  "cli!\n", domain->dcname, domain->name));
		return False;
	}

	if (!domain->conn.cli->initialised) {
		DEBUG(3, ("Connection to %s for domain %s was never "
			  "initialised!\n", domain->dcname, domain->name));
		return False;
	}

	if (domain->conn.cli->fd == -1) {
		DEBUG(3, ("Connection to %s for domain %s has died or was "
			  "never started (fd == -1)\n", 
			  domain->dcname, domain->name));
		return False;
	}

	return True;
}
	
/* Initialize a new connection up to the RPC BIND. */

static NTSTATUS init_dc_connection(struct winbindd_domain *domain)
{
	if (connection_ok(domain))
		return NT_STATUS_OK;

	invalidate_cm_connection(&domain->conn);

	return cm_open_connection(domain, &domain->conn);
}

/**********************************************************************************
 We can 'sense' certain things about the DC by it's replies to certain questions.

 This tells us if this particular remote server is Active Directory, and if it is
 native mode.
**********************************************************************************/

void set_dc_type_and_flags( struct winbindd_domain *domain )
{
	NTSTATUS 		result;
	DS_DOMINFO_CTR		ctr;
	TALLOC_CTX              *mem_ctx = NULL;
	struct rpc_pipe_client  *cli;
	POLICY_HND pol;
	
	char *domain_name = NULL;
	char *dns_name = NULL;
	DOM_SID *dom_sid = NULL;

	ZERO_STRUCT( ctr );
	
	domain->native_mode = False;
	domain->active_directory = False;

	if (domain->internal) {
		domain->initialized = True;
		return;
	}

	result = init_dc_connection(domain);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(5, ("set_dc_type_and_flags: Could not open a connection "
			  "to %s: (%s)\n", domain->name, nt_errstr(result)));
		domain->initialized = True;
		return;
	}

	cli = cli_rpc_open_noauth(domain->conn.cli, PI_LSARPC_DS);

	if (cli == NULL) {
		DEBUG(5, ("set_dc_type_and_flags: Could not bind to "
			  "PI_LSARPC_DS on domain %s: (%s)\n",
			  domain->name, nt_errstr(result)));
		domain->initialized = True;
		return;
	}

	result = rpccli_ds_getprimarydominfo(cli, cli->cli->mem_ctx,
					     DsRolePrimaryDomainInfoBasic,
					     &ctr);
	cli_rpc_close(cli);

	if (!NT_STATUS_IS_OK(result)) {
		domain->initialized = True;
		return;
	}
	
	if ((ctr.basic->flags & DSROLE_PRIMARY_DS_RUNNING) &&
	    !(ctr.basic->flags & DSROLE_PRIMARY_DS_MIXED_MODE) )
		domain->native_mode = True;

	cli = cli_rpc_open_noauth(domain->conn.cli, PI_LSARPC);

	if (cli == NULL) {
		domain->initialized = True;
		return;
	}

	mem_ctx = talloc_init("set_dc_type_and_flags on domain %s\n",
			      domain->name);
	if (!mem_ctx) {
		DEBUG(1, ("set_dc_type_and_flags: talloc_init() failed\n"));
		return;
	}

	result = rpccli_lsa_open_policy2(cli, mem_ctx, True, 
					 SEC_RIGHTS_MAXIMUM_ALLOWED, &pol);
		
	if (NT_STATUS_IS_OK(result)) {
		/* This particular query is exactly what Win2k clients use 
		   to determine that the DC is active directory */
		result = rpccli_lsa_query_info_policy2(cli, mem_ctx, &pol,
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
		
		result = rpccli_lsa_open_policy(cli, mem_ctx, True, 
						SEC_RIGHTS_MAXIMUM_ALLOWED,
						&pol);
			
		if (!NT_STATUS_IS_OK(result))
			goto done;
			
		result = rpccli_lsa_query_info_policy(cli, mem_ctx, 
						      &pol, 5, &domain_name, 
						      &dom_sid);
			
		if (NT_STATUS_IS_OK(result)) {
			if (domain_name)
				fstrcpy(domain->name, domain_name);

			if (dom_sid) 
				sid_copy(&domain->sid, dom_sid);
		}
	}
done:

	cli_rpc_close(cli);
	
	talloc_destroy(mem_ctx);

	domain->initialized = True;
	
	return;
}

NTSTATUS cm_connect_sam(struct winbindd_domain *domain, TALLOC_CTX *mem_ctx,
			struct rpc_pipe_client **cli, POLICY_HND *sam_handle)
{
	struct winbindd_cm_conn *conn;
	NTSTATUS result;

	result = init_dc_connection(domain);
	if (!NT_STATUS_IS_OK(result))
		return result;

	conn = &domain->conn;

	if (conn->samr_pipe == NULL) {
		conn->samr_pipe = cli_rpc_open_noauth(conn->cli, PI_SAMR);
		if (conn->samr_pipe == NULL) {
			result = NT_STATUS_PIPE_NOT_AVAILABLE;
			goto done;
		}

		result = rpccli_samr_connect(conn->samr_pipe, mem_ctx,
					     SEC_RIGHTS_MAXIMUM_ALLOWED,
					     &conn->sam_connect_handle);
		if (!NT_STATUS_IS_OK(result))
			goto done;

		result = rpccli_samr_open_domain(conn->samr_pipe,
						 mem_ctx,
						 &conn->sam_connect_handle,
						 SEC_RIGHTS_MAXIMUM_ALLOWED,
						 &domain->sid,
						 &conn->sam_domain_handle);
	}

 done:
	if (!NT_STATUS_IS_OK(result)) {
		invalidate_cm_connection(conn);
		return NT_STATUS_UNSUCCESSFUL;
	}

	*cli = conn->samr_pipe;
	*sam_handle = conn->sam_domain_handle;
	return result;
}

NTSTATUS cm_connect_lsa(struct winbindd_domain *domain, TALLOC_CTX *mem_ctx,
			struct rpc_pipe_client **cli, POLICY_HND *lsa_policy)
{
	struct winbindd_cm_conn *conn;
	NTSTATUS result;

	result = init_dc_connection(domain);
	if (!NT_STATUS_IS_OK(result))
		return result;

	conn = &domain->conn;

	if (conn->lsa_pipe == NULL) {
		conn->lsa_pipe = cli_rpc_open_noauth(conn->cli, PI_LSARPC);
		if (conn->lsa_pipe == NULL) {
			result = NT_STATUS_PIPE_NOT_AVAILABLE;
			goto done;
		}

		result = rpccli_lsa_open_policy(conn->lsa_pipe, mem_ctx, True,
						SEC_RIGHTS_MAXIMUM_ALLOWED,
						&conn->lsa_policy);
	}

 done:
	if (!NT_STATUS_IS_OK(result)) {
		invalidate_cm_connection(conn);
		return NT_STATUS_UNSUCCESSFUL;
	}

	*cli = conn->lsa_pipe;
	*lsa_policy = conn->lsa_policy;
	return result;
}

NTSTATUS cm_connect_netlogon(struct winbindd_domain *domain,
			     TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client **cli,
			     unsigned char **session_key,
			     DOM_CRED **credentials)
{
	struct winbindd_cm_conn *conn;
	NTSTATUS result;

	uint32 neg_flags = NETLOGON_NEG_AUTH2_FLAGS;
	uint8  mach_pwd[16];
	time_t last_change_time;
	uint32  sec_chan_type;
	DOM_CHAL clnt_chal, srv_chal, rcv_chal;
	const char *server_name;
	const char *account_name;
	UTIME zerotime;

	result = init_dc_connection(domain);
	if (!NT_STATUS_IS_OK(result))
		return result;

	conn = &domain->conn;

	if (conn->netlogon_pipe != NULL) {
		*cli = conn->netlogon_pipe;
		*session_key = (unsigned char *)&conn->sess_key;
		*credentials = &conn->clnt_cred;
		return NT_STATUS_OK;
	}

	if (!get_trust_pw(domain->name, mach_pwd, &last_change_time,
			  &sec_chan_type))
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;

	conn->netlogon_auth2_pipe = cli_rpc_open_noauth(conn->cli,
							PI_NETLOGON);
	if (conn->netlogon_auth2_pipe == NULL)
		return NT_STATUS_UNSUCCESSFUL;

	if (lp_client_schannel() != False)
		neg_flags |= NETLOGON_NEG_SCHANNEL;

	generate_random_buffer(clnt_chal.data, 8);

	server_name = talloc_asprintf(mem_ctx, "\\\\%s", domain->dcname);
	account_name = talloc_asprintf(mem_ctx, "%s$",
				       domain->primary ?
				       global_myname() : domain->name);

	if ((server_name == NULL) || (account_name == NULL))
		return NT_STATUS_NO_MEMORY;

	result = rpccli_net_req_chal(conn->netlogon_auth2_pipe, server_name,
				     global_myname(), &clnt_chal, &srv_chal);
	if (!NT_STATUS_IS_OK(result))
		return result;

	/**************** Long-term Session key **************/

	/* calculate the session key */
	cred_session_key(&clnt_chal, &srv_chal, mach_pwd, conn->sess_key);
	memset((char *)conn->sess_key+8, '\0', 8);

	/* calculate auth2 credentials */
	zerotime.time = 0;
	cred_create(conn->sess_key, &clnt_chal, zerotime,
		    &conn->clnt_cred.challenge);

	result = rpccli_net_auth2(conn->netlogon_auth2_pipe, server_name,
				  account_name, sec_chan_type, global_myname(),
				  &conn->clnt_cred.challenge, &neg_flags,
				  &rcv_chal);

	if (!NT_STATUS_IS_OK(result))
		return result;

	zerotime.time = 0;
	if (!cred_assert(&rcv_chal, conn->sess_key, &srv_chal, zerotime)) {
		DEBUG(0, ("Server replied with bad credential\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	if ((lp_client_schannel() == True) &&
	    ((neg_flags & NETLOGON_NEG_SCHANNEL) == 0)) {
		DEBUG(3, ("Server did not offer schannel\n"));
		cli_rpc_close(conn->netlogon_auth2_pipe);
		conn->netlogon_auth2_pipe = NULL;
		return NT_STATUS_ACCESS_DENIED;
	}

	if ((lp_client_schannel() == False) ||
	    ((neg_flags & NETLOGON_NEG_SCHANNEL) == 0)) {
		/* keep the existing connection to NETLOGON open */
		conn->netlogon_pipe = conn->netlogon_auth2_pipe;
		conn->netlogon_auth2_pipe = NULL;
		*cli = conn->netlogon_pipe;
		*session_key = (unsigned char *)&conn->sess_key;
		*credentials = &conn->clnt_cred;
		return NT_STATUS_OK;
	}

	conn->netlogon_pipe = cli_rpc_open_schannel(conn->cli, PI_NETLOGON,
						    conn->sess_key,
						    domain->name);

	if (conn->netlogon_pipe == NULL) {
		DEBUG(3, ("Could not open schannel'ed NETLOGON pipe\n"));
		cli_rpc_close(conn->netlogon_auth2_pipe);
		conn->netlogon_auth2_pipe = NULL;
		return NT_STATUS_ACCESS_DENIED;
	}

	*cli = conn->netlogon_pipe;
	*session_key = (unsigned char *)&conn->sess_key;
	*credentials = &conn->clnt_cred;
		
	return NT_STATUS_OK;
}
