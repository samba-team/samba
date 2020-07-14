/* 
   Unix SMB/CIFS implementation.
   ads (active directory) utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   Copyright (C) Guenther Deschner 2005
   Copyright (C) Gerald Carter 2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "ads.h"
#include "libads/sitename_cache.h"
#include "libads/cldap.h"
#include "../lib/addns/dnsquery.h"
#include "../libds/common/flags.h"
#include "smbldap.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "lib/param/loadparm.h"
#include "libsmb/namequery.h"

#ifdef HAVE_LDAP

/**
 * @file ldap.c
 * @brief basic ldap client-side routines for ads server communications
 *
 * The routines contained here should do the necessary ldap calls for
 * ads setups.
 * 
 * Important note: attribute names passed into ads_ routines must
 * already be in UTF-8 format.  We do not convert them because in almost
 * all cases, they are just ascii (which is represented with the same
 * codepoints in UTF-8).  This may have to change at some point
 **/


#define LDAP_SERVER_TREE_DELETE_OID	"1.2.840.113556.1.4.805"

static SIG_ATOMIC_T gotalarm;

/***************************************************************
 Signal function to tell us we timed out.
****************************************************************/

static void gotalarm_sig(int signum)
{
	gotalarm = 1;
}

 LDAP *ldap_open_with_timeout(const char *server,
			      struct sockaddr_storage *ss,
			      int port, unsigned int to)
{
	LDAP *ldp = NULL;
	int ldap_err;
	char *uri;

	DEBUG(10, ("Opening connection to LDAP server '%s:%d', timeout "
		   "%u seconds\n", server, port, to));

	if (to) {
		/* Setup timeout */
		gotalarm = 0;
		CatchSignal(SIGALRM, gotalarm_sig);
		alarm(to);
		/* End setup timeout. */
	}

	if ( strchr_m(server, ':') ) {
		/* IPv6 URI */
		uri = talloc_asprintf(talloc_tos(), "ldap://[%s]:%u", server, port);
	} else {
		/* IPv4 URI */
		uri = talloc_asprintf(talloc_tos(), "ldap://%s:%u", server, port);
	}
	if (uri == NULL) {
		return NULL;
	}

#ifdef HAVE_LDAP_INIT_FD
	{
		int fd = -1;
		NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
		unsigned timeout_ms = 1000 * to;

		status = open_socket_out(ss, port, timeout_ms, &fd);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("open_socket_out: failed to open socket\n"));
			return NULL;
		}

/* define LDAP_PROTO_TCP from openldap.h if required */
#ifndef LDAP_PROTO_TCP
#define LDAP_PROTO_TCP 1
#endif
		ldap_err = ldap_init_fd(fd, LDAP_PROTO_TCP, uri, &ldp);
	}
#elif defined(HAVE_LDAP_INITIALIZE)
	ldap_err = ldap_initialize(&ldp, uri);
#else
	ldp = ldap_open(server, port);
	if (ldp != NULL) {
		ldap_err = LDAP_SUCCESS;
	} else {
		ldap_err = LDAP_OTHER;
	}
#endif
	if (ldap_err != LDAP_SUCCESS) {
		DEBUG(2,("Could not initialize connection for LDAP server '%s': %s\n",
			 uri, ldap_err2string(ldap_err)));
	} else {
		DEBUG(10, ("Initialized connection for LDAP server '%s'\n", uri));
	}

	if (to) {
		/* Teardown timeout. */
		alarm(0);
		CatchSignal(SIGALRM, SIG_IGN);
	}

	return ldp;
}

static int ldap_search_with_timeout(LDAP *ld,
				    LDAP_CONST char *base,
				    int scope,
				    LDAP_CONST char *filter,
				    char **attrs,
				    int attrsonly,
				    LDAPControl **sctrls,
				    LDAPControl **cctrls,
				    int sizelimit,
				    LDAPMessage **res )
{
	int to = lp_ldap_timeout();
	struct timeval timeout;
	struct timeval *timeout_ptr = NULL;
	int result;

	/* Setup timeout for the ldap_search_ext_s call - local and remote. */
	gotalarm = 0;

	if (to) {
		timeout.tv_sec = to;
	 	timeout.tv_usec = 0;
		timeout_ptr = &timeout;

		/* Setup alarm timeout. */
		CatchSignal(SIGALRM, gotalarm_sig);
		/* Make the alarm time one second beyond
		   the timout we're setting for the
		   remote search timeout, to allow that
		   to fire in preference. */
		alarm(to+1);
		/* End setup timeout. */
	}


	result = ldap_search_ext_s(ld, base, scope, filter, attrs,
				   attrsonly, sctrls, cctrls, timeout_ptr,
				   sizelimit, res);

	if (to) {
		/* Teardown alarm timeout. */
		CatchSignal(SIGALRM, SIG_IGN);
		alarm(0);
	}

	if (gotalarm != 0)
		return LDAP_TIMELIMIT_EXCEEDED;

	/*
	 * A bug in OpenLDAP means ldap_search_ext_s can return
	 * LDAP_SUCCESS but with a NULL res pointer. Cope with
	 * this. See bug #6279 for details. JRA.
	 */

	if (*res == NULL) {
		return LDAP_TIMELIMIT_EXCEEDED;
	}

	return result;
}

/**********************************************
 Do client and server sitename match ?
**********************************************/

bool ads_sitename_match(ADS_STRUCT *ads)
{
	if (ads->config.server_site_name == NULL &&
	    ads->config.client_site_name == NULL ) {
		DEBUG(10,("ads_sitename_match: both null\n"));
		return True;
	}
	if (ads->config.server_site_name &&
	    ads->config.client_site_name &&
	    strequal(ads->config.server_site_name,
		     ads->config.client_site_name)) {
		DEBUG(10,("ads_sitename_match: name %s match\n", ads->config.server_site_name));
		return True;
	}
	DEBUG(10,("ads_sitename_match: no match between server: %s and client: %s\n",
		ads->config.server_site_name ? ads->config.server_site_name : "NULL",
		ads->config.client_site_name ? ads->config.client_site_name : "NULL"));
	return False;
}

/**********************************************
 Is this the closest DC ?
**********************************************/

bool ads_closest_dc(ADS_STRUCT *ads)
{
	if (ads->config.flags & NBT_SERVER_CLOSEST) {
		DEBUG(10,("ads_closest_dc: NBT_SERVER_CLOSEST flag set\n"));
		return True;
	}

	/* not sure if this can ever happen */
	if (ads_sitename_match(ads)) {
		DEBUG(10,("ads_closest_dc: NBT_SERVER_CLOSEST flag not set but sites match\n"));
		return True;
	}

	if (ads->config.client_site_name == NULL) {
		DEBUG(10,("ads_closest_dc: client belongs to no site\n"));
		return True;
	}

	DEBUG(10,("ads_closest_dc: %s is not the closest DC\n", 
		ads->config.ldap_server_name));

	return False;
}


/*
  try a connection to a given ldap server, returning True and setting the servers IP
  in the ads struct if successful
 */
static bool ads_try_connect(ADS_STRUCT *ads, bool gc,
			    struct sockaddr_storage *ss)
{
	struct NETLOGON_SAM_LOGON_RESPONSE_EX cldap_reply;
	TALLOC_CTX *frame = talloc_stackframe();
	bool ret = false;
	char addr[INET6_ADDRSTRLEN];

	if (ss == NULL) {
		TALLOC_FREE(frame);
		return False;
	}

	print_sockaddr(addr, sizeof(addr), ss);

	DEBUG(5,("ads_try_connect: sending CLDAP request to %s (realm: %s)\n", 
		addr, ads->server.realm));

	ZERO_STRUCT( cldap_reply );

	if ( !ads_cldap_netlogon_5(frame, ss, ads->server.realm, &cldap_reply ) ) {
		DEBUG(3,("ads_try_connect: CLDAP request %s failed.\n", addr));
		ret = false;
		goto out;
	}

	/* Check the CLDAP reply flags */

	if ( !(cldap_reply.server_type & NBT_SERVER_LDAP) ) {
		DEBUG(1,("ads_try_connect: %s's CLDAP reply says it is not an LDAP server!\n",
			addr));
		ret = false;
		goto out;
	}

	/* Fill in the ads->config values */

	SAFE_FREE(ads->config.realm);
	SAFE_FREE(ads->config.bind_path);
	SAFE_FREE(ads->config.ldap_server_name);
	SAFE_FREE(ads->config.server_site_name);
	SAFE_FREE(ads->config.client_site_name);
	SAFE_FREE(ads->server.workgroup);

	if (!check_cldap_reply_required_flags(cldap_reply.server_type,
					      ads->config.flags)) {
		ret = false;
		goto out;
	}

	ads->config.ldap_server_name   = SMB_STRDUP(cldap_reply.pdc_dns_name);
	ads->config.realm              = SMB_STRDUP(cldap_reply.dns_domain);
	if (!strupper_m(ads->config.realm)) {
		ret = false;
		goto out;
	}

	ads->config.bind_path          = ads_build_dn(ads->config.realm);
	if (*cldap_reply.server_site) {
		ads->config.server_site_name =
			SMB_STRDUP(cldap_reply.server_site);
	}
	if (*cldap_reply.client_site) {
		ads->config.client_site_name =
			SMB_STRDUP(cldap_reply.client_site);
	}
	ads->server.workgroup          = SMB_STRDUP(cldap_reply.domain_name);

	ads->ldap.port = gc ? LDAP_GC_PORT : LDAP_PORT;
	ads->ldap.ss = *ss;

	/* Store our site name. */
	sitename_store( cldap_reply.domain_name, cldap_reply.client_site);
	sitename_store( cldap_reply.dns_domain, cldap_reply.client_site);

	/* Leave this until last so that the flags are not clobbered */
	ads->config.flags	       = cldap_reply.server_type;

	ret = true;

 out:

	TALLOC_FREE(frame);
	return ret;
}

/**********************************************************************
 send a cldap ping to list of servers, one at a time, until one of
 them answers it's an ldap server. Record success in the ADS_STRUCT.
 Take note of and update negative connection cache.
**********************************************************************/

static NTSTATUS cldap_ping_list(ADS_STRUCT *ads,const char *domain,
				struct ip_service *ip_list, int count)
{
	int i;
	bool ok;

	for (i = 0; i < count; i++) {
		char server[INET6_ADDRSTRLEN];

		print_sockaddr(server, sizeof(server), &ip_list[i].ss);

		if (!NT_STATUS_IS_OK(
			check_negative_conn_cache(domain, server)))
			continue;

		/* Returns ok only if it matches the correct server type */
		ok = ads_try_connect(ads, false, &ip_list[i].ss);

		if (ok) {
			return NT_STATUS_OK;
		}

		/* keep track of failures */
		add_failed_connection_entry(domain, server,
					    NT_STATUS_UNSUCCESSFUL);
	}

	return NT_STATUS_NO_LOGON_SERVERS;
}

/***************************************************************************
 resolve a name and perform an "ldap ping" using NetBIOS and related methods
****************************************************************************/

static NTSTATUS resolve_and_ping_netbios(ADS_STRUCT *ads,
					 const char *domain, const char *realm)
{
	int count, i;
	struct ip_service *ip_list;
	NTSTATUS status;

	DEBUG(6, ("resolve_and_ping_netbios: (cldap) looking for domain '%s'\n",
		  domain));

	status = get_sorted_dc_list(domain, NULL, &ip_list, &count,
				    false);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* remove servers which are known to be dead based on
	   the corresponding DNS method */
	if (*realm) {
		for (i = 0; i < count; ++i) {
			char server[INET6_ADDRSTRLEN];

			print_sockaddr(server, sizeof(server), &ip_list[i].ss);

			if(!NT_STATUS_IS_OK(
				check_negative_conn_cache(realm, server))) {
				/* Ensure we add the workgroup name for this
				   IP address as negative too. */
				add_failed_connection_entry(
				    domain, server,
				    NT_STATUS_UNSUCCESSFUL);
			}
		}
	}

	status = cldap_ping_list(ads, domain, ip_list, count);

	SAFE_FREE(ip_list);

	return status;
}


/**********************************************************************
 resolve a name and perform an "ldap ping" using DNS
**********************************************************************/

static NTSTATUS resolve_and_ping_dns(ADS_STRUCT *ads, const char *sitename,
				     const char *realm)
{
	int count;
	struct ip_service *ip_list = NULL;
	NTSTATUS status;

	DEBUG(6, ("resolve_and_ping_dns: (cldap) looking for realm '%s'\n",
		  realm));

	status = get_sorted_dc_list(realm, sitename, &ip_list, &count,
				    true);
	if (!NT_STATUS_IS_OK(status)) {
		SAFE_FREE(ip_list);
		return status;
	}

	status = cldap_ping_list(ads, realm, ip_list, count);

	SAFE_FREE(ip_list);

	return status;
}

/**********************************************************************
 Try to find an AD dc using our internal name resolution routines
 Try the realm first and then then workgroup name if netbios is not
 disabled
**********************************************************************/

static NTSTATUS ads_find_dc(ADS_STRUCT *ads)
{
	const char *c_domain = "";
	const char *c_realm;
	bool use_own_domain = False;
	char *sitename = NULL;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	bool ok = false;

	/* if the realm and workgroup are both empty, assume they are ours */

	/* realm */
	c_realm = ads->server.realm;

	if (c_realm == NULL)
		c_realm = "";

	if (!*c_realm) {
		/* special case where no realm and no workgroup means our own */
		if ( !ads->server.workgroup || !*ads->server.workgroup ) {
			use_own_domain = True;
			c_realm = lp_realm();
		}
	}

	if (!lp_disable_netbios()) {
		if (use_own_domain) {
			c_domain = lp_workgroup();
		} else {
			c_domain = ads->server.workgroup;
			if (!*c_realm && (!c_domain || !*c_domain)) {
				c_domain = lp_workgroup();
			}
		}

		if (!c_domain) {
			c_domain = "";
		}
	}

	if (!*c_realm && !*c_domain) {
		DEBUG(0, ("ads_find_dc: no realm or workgroup!  Don't know "
			  "what to do\n"));
		return NT_STATUS_INVALID_PARAMETER; /* rather need MISSING_PARAMETER ... */
	}

	/*
	 * In case of LDAP we use get_dc_name() as that
	 * creates the custom krb5.conf file
	 */
	if (!(ads->auth.flags & ADS_AUTH_NO_BIND)) {
		fstring srv_name;
		struct sockaddr_storage ip_out;

		DEBUG(6, ("ads_find_dc: (ldap) looking for realm '%s'"
			  " and falling back to domain '%s'\n",
			  c_realm, c_domain));

		ok = get_dc_name(c_domain, c_realm, srv_name, &ip_out);
		if (ok) {
			/*
			 * we call ads_try_connect() to fill in the
			 * ads->config details
			 */
			ok = ads_try_connect(ads, false, &ip_out);
			if (ok) {
				return NT_STATUS_OK;
			}
		}

		return NT_STATUS_NO_LOGON_SERVERS;
	}

	if (*c_realm) {
		sitename = sitename_fetch(talloc_tos(), c_realm);
		status = resolve_and_ping_dns(ads, sitename, c_realm);

		if (NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(sitename);
			return status;
		}

		/* In case we failed to contact one of our closest DC on our
		 * site we
		 * need to try to find another DC, retry with a site-less SRV
		 * DNS query
		 * - Guenther */

		if (sitename) {
			DEBUG(3, ("ads_find_dc: failed to find a valid DC on "
				  "our site (%s), Trying to find another DC "
				  "for realm '%s' (domain '%s')\n",
				  sitename, c_realm, c_domain));
			namecache_delete(c_realm, 0x1C);
			status =
			    resolve_and_ping_dns(ads, NULL, c_realm);

			if (NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(sitename);
				return status;
			}
		}

		TALLOC_FREE(sitename);
	}

	/* try netbios as fallback - if permitted,
	   or if configuration specifically requests it */
	if (*c_domain) {
		if (*c_realm) {
			DEBUG(3, ("ads_find_dc: falling back to netbios "
				  "name resolution for domain '%s' (realm '%s')\n",
				  c_domain, c_realm));
		}

		status = resolve_and_ping_netbios(ads, c_domain, c_realm);
		if (NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	DEBUG(1, ("ads_find_dc: "
		  "name resolution for realm '%s' (domain '%s') failed: %s\n",
		  c_realm, c_domain, nt_errstr(status)));
	return status;
}
/**
 * Connect to the LDAP server
 * @param ads Pointer to an existing ADS_STRUCT
 * @return status of connection
 **/
ADS_STATUS ads_connect(ADS_STRUCT *ads)
{
	int version = LDAP_VERSION3;
	ADS_STATUS status;
	NTSTATUS ntstatus;
	char addr[INET6_ADDRSTRLEN];

	ZERO_STRUCT(ads->ldap);
	ZERO_STRUCT(ads->ldap_wrap_data);
	ads->ldap.last_attempt	= time_mono(NULL);
	ads->ldap_wrap_data.wrap_type	= ADS_SASLWRAP_TYPE_PLAIN;

	/* try with a user specified server */

	if (DEBUGLEVEL >= 11) {
		char *s = NDR_PRINT_STRUCT_STRING(talloc_tos(), ads_struct, ads);
		DEBUG(11,("ads_connect: entering\n"));
		DEBUGADD(11,("%s\n", s));
		TALLOC_FREE(s);
	}

	if (ads->server.ldap_server) {
		bool ok = false;
		struct sockaddr_storage ss;

		ok = resolve_name(ads->server.ldap_server, &ss, 0x20, true);
		if (!ok) {
			DEBUG(5,("ads_connect: unable to resolve name %s\n",
				 ads->server.ldap_server));
			status = ADS_ERROR_NT(NT_STATUS_NOT_FOUND);
			goto out;
		}
		ok = ads_try_connect(ads, ads->server.gc, &ss);
		if (ok) {
			goto got_connection;
		}

		/* The choice of which GC use is handled one level up in
		   ads_connect_gc().  If we continue on from here with
		   ads_find_dc() we will get GC searches on port 389 which
		   doesn't work.   --jerry */

		if (ads->server.gc == true) {
			return ADS_ERROR(LDAP_OPERATIONS_ERROR);
		}

		if (ads->server.no_fallback) {
			status = ADS_ERROR_NT(NT_STATUS_NOT_FOUND);
			goto out;
		}
	}

	ntstatus = ads_find_dc(ads);
	if (NT_STATUS_IS_OK(ntstatus)) {
		goto got_connection;
	}

	status = ADS_ERROR_NT(ntstatus);
	goto out;

got_connection:

	print_sockaddr(addr, sizeof(addr), &ads->ldap.ss);
	DEBUG(3,("Successfully contacted LDAP server %s\n", addr));

	if (!ads->auth.user_name) {
		/* Must use the userPrincipalName value here or sAMAccountName
		   and not servicePrincipalName; found by Guenther Deschner */

		if (asprintf(&ads->auth.user_name, "%s$", lp_netbios_name() ) == -1) {
			DEBUG(0,("ads_connect: asprintf fail.\n"));
			ads->auth.user_name = NULL;
		}
	}

	if (!ads->auth.realm) {
		ads->auth.realm = SMB_STRDUP(ads->config.realm);
	}

	if (!ads->auth.kdc_server) {
		print_sockaddr(addr, sizeof(addr), &ads->ldap.ss);
		ads->auth.kdc_server = SMB_STRDUP(addr);
	}

	/* If the caller() requested no LDAP bind, then we are done */

	if (ads->auth.flags & ADS_AUTH_NO_BIND) {
		status = ADS_SUCCESS;
		goto out;
	}

	ads->ldap_wrap_data.mem_ctx = talloc_init("ads LDAP connection memory");
	if (!ads->ldap_wrap_data.mem_ctx) {
		status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		goto out;
	}

	/* Otherwise setup the TCP LDAP session */

	ads->ldap.ld = ldap_open_with_timeout(ads->config.ldap_server_name,
					      &ads->ldap.ss,
					      ads->ldap.port, lp_ldap_timeout());
	if (ads->ldap.ld == NULL) {
		status = ADS_ERROR(LDAP_OPERATIONS_ERROR);
		goto out;
	}
	DEBUG(3,("Connected to LDAP server %s\n", ads->config.ldap_server_name));

	/* cache the successful connection for workgroup and realm */
	if (ads_closest_dc(ads)) {
		saf_store( ads->server.workgroup, ads->config.ldap_server_name);
		saf_store( ads->server.realm, ads->config.ldap_server_name);
	}

	ldap_set_option(ads->ldap.ld, LDAP_OPT_PROTOCOL_VERSION, &version);

	/* fill in the current time and offsets */

	status = ads_current_time( ads );
	if ( !ADS_ERR_OK(status) ) {
		goto out;
	}

	/* Now do the bind */

	if (ads->auth.flags & ADS_AUTH_ANON_BIND) {
		status = ADS_ERROR(ldap_simple_bind_s(ads->ldap.ld, NULL, NULL));
		goto out;
	}

	if (ads->auth.flags & ADS_AUTH_SIMPLE_BIND) {
		status = ADS_ERROR(ldap_simple_bind_s(ads->ldap.ld, ads->auth.user_name, ads->auth.password));
		goto out;
	}

	status = ads_sasl_bind(ads);

 out:
	if (DEBUGLEVEL >= 11) {
		char *s = NDR_PRINT_STRUCT_STRING(talloc_tos(), ads_struct, ads);
		DEBUG(11,("ads_connect: leaving with: %s\n",
			ads_errstr(status)));
		DEBUGADD(11,("%s\n", s));
		TALLOC_FREE(s);
	}

	return status;
}

/**
 * Connect to the LDAP server using given credentials
 * @param ads Pointer to an existing ADS_STRUCT
 * @return status of connection
 **/
ADS_STATUS ads_connect_user_creds(ADS_STRUCT *ads)
{
	ads->auth.flags |= ADS_AUTH_USER_CREDS;

	return ads_connect(ads);
}

/**
 * Disconnect the LDAP server
 * @param ads Pointer to an existing ADS_STRUCT
 **/
void ads_disconnect(ADS_STRUCT *ads)
{
	if (ads->ldap.ld) {
		ldap_unbind(ads->ldap.ld);
		ads->ldap.ld = NULL;
	}
	if (ads->ldap_wrap_data.wrap_ops &&
		ads->ldap_wrap_data.wrap_ops->disconnect) {
		ads->ldap_wrap_data.wrap_ops->disconnect(&ads->ldap_wrap_data);
	}
	if (ads->ldap_wrap_data.mem_ctx) {
		talloc_free(ads->ldap_wrap_data.mem_ctx);
	}
	ZERO_STRUCT(ads->ldap);
	ZERO_STRUCT(ads->ldap_wrap_data);
}

/*
  Duplicate a struct berval into talloc'ed memory
 */
static struct berval *dup_berval(TALLOC_CTX *ctx, const struct berval *in_val)
{
	struct berval *value;

	if (!in_val) return NULL;

	value = talloc_zero(ctx, struct berval);
	if (value == NULL)
		return NULL;
	if (in_val->bv_len == 0) return value;

	value->bv_len = in_val->bv_len;
	value->bv_val = (char *)talloc_memdup(ctx, in_val->bv_val,
					      in_val->bv_len);
	return value;
}

/*
  Make a values list out of an array of (struct berval *)
 */
static struct berval **ads_dup_values(TALLOC_CTX *ctx, 
				      const struct berval **in_vals)
{
	struct berval **values;
	int i;

	if (!in_vals) return NULL;
	for (i=0; in_vals[i]; i++)
		; /* count values */
	values = talloc_zero_array(ctx, struct berval *, i+1);
	if (!values) return NULL;

	for (i=0; in_vals[i]; i++) {
		values[i] = dup_berval(ctx, in_vals[i]);
	}
	return values;
}

/*
  UTF8-encode a values list out of an array of (char *)
 */
static char **ads_push_strvals(TALLOC_CTX *ctx, const char **in_vals)
{
	char **values;
	int i;
	size_t size;

	if (!in_vals) return NULL;
	for (i=0; in_vals[i]; i++)
		; /* count values */
	values = talloc_zero_array(ctx, char *, i+1);
	if (!values) return NULL;

	for (i=0; in_vals[i]; i++) {
		if (!push_utf8_talloc(ctx, &values[i], in_vals[i], &size)) {
			TALLOC_FREE(values);
			return NULL;
		}
	}
	return values;
}

/*
  Pull a (char *) array out of a UTF8-encoded values list
 */
static char **ads_pull_strvals(TALLOC_CTX *ctx, const char **in_vals)
{
	char **values;
	int i;
	size_t converted_size;

	if (!in_vals) return NULL;
	for (i=0; in_vals[i]; i++)
		; /* count values */
	values = talloc_zero_array(ctx, char *, i+1);
	if (!values) return NULL;

	for (i=0; in_vals[i]; i++) {
		if (!pull_utf8_talloc(ctx, &values[i], in_vals[i],
				      &converted_size)) {
			DEBUG(0,("ads_pull_strvals: pull_utf8_talloc failed: "
				 "%s", strerror(errno)));
		}
	}
	return values;
}

/**
 * Do a search with paged results.  cookie must be null on the first
 *  call, and then returned on each subsequent call.  It will be null
 *  again when the entire search is complete 
 * @param ads connection to ads server 
 * @param bind_path Base dn for the search
 * @param scope Scope of search (LDAP_SCOPE_BASE | LDAP_SCOPE_ONE | LDAP_SCOPE_SUBTREE)
 * @param expr Search expression - specified in local charset
 * @param attrs Attributes to retrieve - specified in utf8 or ascii
 * @param res ** which will contain results - free res* with ads_msgfree()
 * @param count Number of entries retrieved on this page
 * @param cookie The paged results cookie to be returned on subsequent calls
 * @return status of search
 **/
static ADS_STATUS ads_do_paged_search_args(ADS_STRUCT *ads,
					   const char *bind_path,
					   int scope, const char *expr,
					   const char **attrs, void *args,
					   LDAPMessage **res, 
					   int *count, struct berval **cookie)
{
	int rc, i, version;
	char *utf8_expr, *utf8_path, **search_attrs = NULL;
	size_t converted_size;
	LDAPControl PagedResults, NoReferrals, ExternalCtrl, *controls[4], **rcontrols;
	BerElement *cookie_be = NULL;
	struct berval *cookie_bv= NULL;
	BerElement *ext_be = NULL;
	struct berval *ext_bv= NULL;

	TALLOC_CTX *ctx;
	ads_control *external_control = (ads_control *) args;

	*res = NULL;

	if (!(ctx = talloc_init("ads_do_paged_search_args")))
		return ADS_ERROR(LDAP_NO_MEMORY);

	/* 0 means the conversion worked but the result was empty 
	   so we only fail if it's -1.  In any case, it always 
	   at least nulls out the dest */
	if (!push_utf8_talloc(ctx, &utf8_expr, expr, &converted_size) ||
	    !push_utf8_talloc(ctx, &utf8_path, bind_path, &converted_size))
	{
		rc = LDAP_NO_MEMORY;
		goto done;
	}

	if (!attrs || !(*attrs))
		search_attrs = NULL;
	else {
		/* This would be the utf8-encoded version...*/
		/* if (!(search_attrs = ads_push_strvals(ctx, attrs))) */
		if (!(search_attrs = str_list_copy(talloc_tos(), attrs))) {
			rc = LDAP_NO_MEMORY;
			goto done;
		}
	}

	/* Paged results only available on ldap v3 or later */
	ldap_get_option(ads->ldap.ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (version < LDAP_VERSION3) {
		rc =  LDAP_NOT_SUPPORTED;
		goto done;
	}

	cookie_be = ber_alloc_t(LBER_USE_DER);
	if (*cookie) {
		ber_printf(cookie_be, "{iO}", (ber_int_t) ads->config.ldap_page_size, *cookie);
		ber_bvfree(*cookie); /* don't need it from last time */
		*cookie = NULL;
	} else {
		ber_printf(cookie_be, "{io}", (ber_int_t) ads->config.ldap_page_size, "", 0);
	}
	ber_flatten(cookie_be, &cookie_bv);
	PagedResults.ldctl_oid = discard_const_p(char, ADS_PAGE_CTL_OID);
	PagedResults.ldctl_iscritical = (char) 1;
	PagedResults.ldctl_value.bv_len = cookie_bv->bv_len;
	PagedResults.ldctl_value.bv_val = cookie_bv->bv_val;

	NoReferrals.ldctl_oid = discard_const_p(char, ADS_NO_REFERRALS_OID);
	NoReferrals.ldctl_iscritical = (char) 0;
	NoReferrals.ldctl_value.bv_len = 0;
	NoReferrals.ldctl_value.bv_val = discard_const_p(char, "");

	if (external_control && 
	    (strequal(external_control->control, ADS_EXTENDED_DN_OID) || 
	     strequal(external_control->control, ADS_SD_FLAGS_OID))) {

		ExternalCtrl.ldctl_oid = discard_const_p(char, external_control->control);
		ExternalCtrl.ldctl_iscritical = (char) external_control->critical;

		/* win2k does not accept a ldctl_value beeing passed in */

		if (external_control->val != 0) {

			if ((ext_be = ber_alloc_t(LBER_USE_DER)) == NULL ) {
				rc = LDAP_NO_MEMORY;
				goto done;
			}

			if ((ber_printf(ext_be, "{i}", (ber_int_t) external_control->val)) == -1) {
				rc = LDAP_NO_MEMORY;
				goto done;
			}
			if ((ber_flatten(ext_be, &ext_bv)) == -1) {
				rc = LDAP_NO_MEMORY;
				goto done;
			}

			ExternalCtrl.ldctl_value.bv_len = ext_bv->bv_len;
			ExternalCtrl.ldctl_value.bv_val = ext_bv->bv_val;

		} else {
			ExternalCtrl.ldctl_value.bv_len = 0;
			ExternalCtrl.ldctl_value.bv_val = NULL;
		}

		controls[0] = &NoReferrals;
		controls[1] = &PagedResults;
		controls[2] = &ExternalCtrl;
		controls[3] = NULL;

	} else {
		controls[0] = &NoReferrals;
		controls[1] = &PagedResults;
		controls[2] = NULL;
	}

	/* we need to disable referrals as the openldap libs don't
	   handle them and paged results at the same time.  Using them
	   together results in the result record containing the server 
	   page control being removed from the result list (tridge/jmcd) 

	   leaving this in despite the control that says don't generate
	   referrals, in case the server doesn't support it (jmcd)
	*/
	ldap_set_option(ads->ldap.ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

	rc = ldap_search_with_timeout(ads->ldap.ld, utf8_path, scope, utf8_expr, 
				      search_attrs, 0, controls,
				      NULL, LDAP_NO_LIMIT,
				      (LDAPMessage **)res);

	ber_free(cookie_be, 1);
	ber_bvfree(cookie_bv);

	if (rc) {
		DEBUG(3,("ads_do_paged_search_args: ldap_search_with_timeout(%s) -> %s\n", expr,
			 ldap_err2string(rc)));
		if (rc == LDAP_OTHER) {
			char *ldap_errmsg;
			int ret;

			ret = ldap_parse_result(ads->ldap.ld,
						*res,
						NULL,
						NULL,
						&ldap_errmsg,
						NULL,
						NULL,
						0);
			if (ret == LDAP_SUCCESS) {
				DEBUG(3, ("ldap_search_with_timeout(%s) "
					  "error: %s\n", expr, ldap_errmsg));
				ldap_memfree(ldap_errmsg);
			}
		}
		goto done;
	}

	rc = ldap_parse_result(ads->ldap.ld, *res, NULL, NULL, NULL,
					NULL, &rcontrols,  0);

	if (!rcontrols) {
		goto done;
	}

	for (i=0; rcontrols[i]; i++) {
		if (strcmp(ADS_PAGE_CTL_OID, rcontrols[i]->ldctl_oid) == 0) {
			cookie_be = ber_init(&rcontrols[i]->ldctl_value);
			ber_scanf(cookie_be,"{iO}", (ber_int_t *) count,
				  &cookie_bv);
			/* the berval is the cookie, but must be freed when
			   it is all done */
			if (cookie_bv->bv_len) /* still more to do */
				*cookie=ber_bvdup(cookie_bv);
			else
				*cookie=NULL;
			ber_bvfree(cookie_bv);
			ber_free(cookie_be, 1);
			break;
		}
	}
	ldap_controls_free(rcontrols);

done:
	talloc_destroy(ctx);

	if (ext_be) {
		ber_free(ext_be, 1);
	}

	if (ext_bv) {
		ber_bvfree(ext_bv);
	}

	if (rc != LDAP_SUCCESS && *res != NULL) {
		ads_msgfree(ads, *res);
		*res = NULL;
	}

	/* if/when we decide to utf8-encode attrs, take out this next line */
	TALLOC_FREE(search_attrs);

	return ADS_ERROR(rc);
}

static ADS_STATUS ads_do_paged_search(ADS_STRUCT *ads, const char *bind_path,
				      int scope, const char *expr,
				      const char **attrs, LDAPMessage **res, 
				      int *count, struct berval **cookie)
{
	return ads_do_paged_search_args(ads, bind_path, scope, expr, attrs, NULL, res, count, cookie);
}


/**
 * Get all results for a search.  This uses ads_do_paged_search() to return 
 * all entries in a large search.
 * @param ads connection to ads server 
 * @param bind_path Base dn for the search
 * @param scope Scope of search (LDAP_SCOPE_BASE | LDAP_SCOPE_ONE | LDAP_SCOPE_SUBTREE)
 * @param expr Search expression
 * @param attrs Attributes to retrieve
 * @param res ** which will contain results - free res* with ads_msgfree()
 * @return status of search
 **/
 ADS_STATUS ads_do_search_all_args(ADS_STRUCT *ads, const char *bind_path,
				   int scope, const char *expr,
				   const char **attrs, void *args,
				   LDAPMessage **res)
{
	struct berval *cookie = NULL;
	int count = 0;
	ADS_STATUS status;

	*res = NULL;
	status = ads_do_paged_search_args(ads, bind_path, scope, expr, attrs, args, res,
				     &count, &cookie);

	if (!ADS_ERR_OK(status)) 
		return status;

#ifdef HAVE_LDAP_ADD_RESULT_ENTRY
	while (cookie) {
		LDAPMessage *res2 = NULL;
		LDAPMessage *msg, *next;

		status = ads_do_paged_search_args(ads, bind_path, scope, expr,
					      attrs, args, &res2, &count, &cookie);
		if (!ADS_ERR_OK(status)) {
			break;
		}

		/* this relies on the way that ldap_add_result_entry() works internally. I hope
		   that this works on all ldap libs, but I have only tested with openldap */
		for (msg = ads_first_message(ads, res2); msg; msg = next) {
			next = ads_next_message(ads, msg);
			ldap_add_result_entry((LDAPMessage **)res, msg);
		}
		/* note that we do not free res2, as the memory is now
                   part of the main returned list */
	}
#else
	DEBUG(0, ("no ldap_add_result_entry() support in LDAP libs!\n"));
	status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
#endif

	return status;
}

 ADS_STATUS ads_do_search_all(ADS_STRUCT *ads, const char *bind_path,
			      int scope, const char *expr,
			      const char **attrs, LDAPMessage **res)
{
	return ads_do_search_all_args(ads, bind_path, scope, expr, attrs, NULL, res);
}

 ADS_STATUS ads_do_search_all_sd_flags(ADS_STRUCT *ads, const char *bind_path,
				       int scope, const char *expr,
				       const char **attrs, uint32_t sd_flags, 
				       LDAPMessage **res)
{
	ads_control args;

	args.control = ADS_SD_FLAGS_OID;
	args.val = sd_flags;
	args.critical = True;

	return ads_do_search_all_args(ads, bind_path, scope, expr, attrs, &args, res);
}


/**
 * Run a function on all results for a search.  Uses ads_do_paged_search() and
 *  runs the function as each page is returned, using ads_process_results()
 * @param ads connection to ads server
 * @param bind_path Base dn for the search
 * @param scope Scope of search (LDAP_SCOPE_BASE | LDAP_SCOPE_ONE | LDAP_SCOPE_SUBTREE)
 * @param expr Search expression - specified in local charset
 * @param attrs Attributes to retrieve - specified in UTF-8 or ascii
 * @param fn Function which takes attr name, values list, and data_area
 * @param data_area Pointer which is passed to function on each call
 * @return status of search
 **/
ADS_STATUS ads_do_search_all_fn(ADS_STRUCT *ads, const char *bind_path,
				int scope, const char *expr, const char **attrs,
				bool (*fn)(ADS_STRUCT *, char *, void **, void *), 
				void *data_area)
{
	struct berval *cookie = NULL;
	int count = 0;
	ADS_STATUS status;
	LDAPMessage *res;

	status = ads_do_paged_search(ads, bind_path, scope, expr, attrs, &res,
				     &count, &cookie);

	if (!ADS_ERR_OK(status)) return status;

	ads_process_results(ads, res, fn, data_area);
	ads_msgfree(ads, res);

	while (cookie) {
		status = ads_do_paged_search(ads, bind_path, scope, expr, attrs,
					     &res, &count, &cookie);

		if (!ADS_ERR_OK(status)) break;

		ads_process_results(ads, res, fn, data_area);
		ads_msgfree(ads, res);
	}

	return status;
}

/**
 * Do a search with a timeout.
 * @param ads connection to ads server
 * @param bind_path Base dn for the search
 * @param scope Scope of search (LDAP_SCOPE_BASE | LDAP_SCOPE_ONE | LDAP_SCOPE_SUBTREE)
 * @param expr Search expression
 * @param attrs Attributes to retrieve
 * @param res ** which will contain results - free res* with ads_msgfree()
 * @return status of search
 **/
 ADS_STATUS ads_do_search(ADS_STRUCT *ads, const char *bind_path, int scope, 
			  const char *expr,
			  const char **attrs, LDAPMessage **res)
{
	int rc;
	char *utf8_expr, *utf8_path, **search_attrs = NULL;
	size_t converted_size;
	TALLOC_CTX *ctx;

	*res = NULL;
	if (!(ctx = talloc_init("ads_do_search"))) {
		DEBUG(1,("ads_do_search: talloc_init() failed!"));
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	/* 0 means the conversion worked but the result was empty 
	   so we only fail if it's negative.  In any case, it always 
	   at least nulls out the dest */
	if (!push_utf8_talloc(ctx, &utf8_expr, expr, &converted_size) ||
	    !push_utf8_talloc(ctx, &utf8_path, bind_path, &converted_size))
	{
		DEBUG(1,("ads_do_search: push_utf8_talloc() failed!"));
		rc = LDAP_NO_MEMORY;
		goto done;
	}

	if (!attrs || !(*attrs))
		search_attrs = NULL;
	else {
		/* This would be the utf8-encoded version...*/
		/* if (!(search_attrs = ads_push_strvals(ctx, attrs)))  */
		if (!(search_attrs = str_list_copy(talloc_tos(), attrs)))
		{
			DEBUG(1,("ads_do_search: str_list_copy() failed!"));
			rc = LDAP_NO_MEMORY;
			goto done;
		}
	}

	/* see the note in ads_do_paged_search - we *must* disable referrals */
	ldap_set_option(ads->ldap.ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

	rc = ldap_search_with_timeout(ads->ldap.ld, utf8_path, scope, utf8_expr,
				      search_attrs, 0, NULL, NULL, 
				      LDAP_NO_LIMIT,
				      (LDAPMessage **)res);

	if (rc == LDAP_SIZELIMIT_EXCEEDED) {
		DEBUG(3,("Warning! sizelimit exceeded in ldap. Truncating.\n"));
		rc = 0;
	}

 done:
	talloc_destroy(ctx);
	/* if/when we decide to utf8-encode attrs, take out this next line */
	TALLOC_FREE(search_attrs);
	return ADS_ERROR(rc);
}
/**
 * Do a general ADS search
 * @param ads connection to ads server
 * @param res ** which will contain results - free res* with ads_msgfree()
 * @param expr Search expression
 * @param attrs Attributes to retrieve
 * @return status of search
 **/
 ADS_STATUS ads_search(ADS_STRUCT *ads, LDAPMessage **res, 
		       const char *expr, const char **attrs)
{
	return ads_do_search(ads, ads->config.bind_path, LDAP_SCOPE_SUBTREE, 
			     expr, attrs, res);
}

/**
 * Do a search on a specific DistinguishedName
 * @param ads connection to ads server
 * @param res ** which will contain results - free res* with ads_msgfree()
 * @param dn DistinguishName to search
 * @param attrs Attributes to retrieve
 * @return status of search
 **/
 ADS_STATUS ads_search_dn(ADS_STRUCT *ads, LDAPMessage **res, 
			  const char *dn, const char **attrs)
{
	return ads_do_search(ads, dn, LDAP_SCOPE_BASE, "(objectclass=*)",
			     attrs, res);
}

/**
 * Free up memory from a ads_search
 * @param ads connection to ads server
 * @param msg Search results to free
 **/
 void ads_msgfree(ADS_STRUCT *ads, LDAPMessage *msg)
{
	if (!msg) return;
	ldap_msgfree(msg);
}

/**
 * Get a dn from search results
 * @param ads connection to ads server
 * @param msg Search result
 * @return dn string
 **/
 char *ads_get_dn(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, LDAPMessage *msg)
{
	char *utf8_dn, *unix_dn;
	size_t converted_size;

	utf8_dn = ldap_get_dn(ads->ldap.ld, msg);

	if (!utf8_dn) {
		DEBUG (5, ("ads_get_dn: ldap_get_dn failed\n"));
		return NULL;
	}

	if (!pull_utf8_talloc(mem_ctx, &unix_dn, utf8_dn, &converted_size)) {
		DEBUG(0,("ads_get_dn: string conversion failure utf8 [%s]\n",
			utf8_dn ));
		return NULL;
	}
	ldap_memfree(utf8_dn);
	return unix_dn;
}

/**
 * Get the parent from a dn
 * @param dn the dn to return the parent from
 * @return parent dn string
 **/
char *ads_parent_dn(const char *dn)
{
	char *p;

	if (dn == NULL) {
		return NULL;
	}

	p = strchr(dn, ',');

	if (p == NULL) {
		return NULL;
	}

	return p+1;
}

/**
 * Find a machine account given a hostname
 * @param ads connection to ads server
 * @param res ** which will contain results - free res* with ads_msgfree()
 * @param host Hostname to search for
 * @return status of search
 **/
 ADS_STATUS ads_find_machine_acct(ADS_STRUCT *ads, LDAPMessage **res,
				  const char *machine)
{
	ADS_STATUS status;
	char *expr;
	const char *attrs[] = {
		/* This is how Windows checks for machine accounts */
		"objectClass",
		"SamAccountName",
		"userAccountControl",
		"DnsHostName",
		"ServicePrincipalName",
		"userPrincipalName",
		"unicodePwd",

		/* Additional attributes Samba checks */
		"msDS-AdditionalDnsHostName",
		"msDS-SupportedEncryptionTypes",
		"nTSecurityDescriptor",

		NULL
	};
	TALLOC_CTX *frame = talloc_stackframe();

	*res = NULL;

	/* the easiest way to find a machine account anywhere in the tree
	   is to look for hostname$ */
	expr = talloc_asprintf(frame, "(samAccountName=%s$)", machine);
	if (expr == NULL) {
		status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		goto done;
	}

	status = ads_search(ads, res, expr, attrs);
	if (ADS_ERR_OK(status)) {
		if (ads_count_replies(ads, *res) != 1) {
			status = ADS_ERROR_LDAP(LDAP_NO_SUCH_OBJECT);
		}
	}

done:
	TALLOC_FREE(frame);
	return status;
}

/**
 * Initialize a list of mods to be used in a modify request
 * @param ctx An initialized TALLOC_CTX
 * @return allocated ADS_MODLIST
 **/
ADS_MODLIST ads_init_mods(TALLOC_CTX *ctx)
{
#define ADS_MODLIST_ALLOC_SIZE 10
	LDAPMod **mods;

	if ((mods = talloc_zero_array(ctx, LDAPMod *, ADS_MODLIST_ALLOC_SIZE + 1)))
		/* -1 is safety to make sure we don't go over the end.
		   need to reset it to NULL before doing ldap modify */
		mods[ADS_MODLIST_ALLOC_SIZE] = (LDAPMod *) -1;

	return (ADS_MODLIST)mods;
}


/*
  add an attribute to the list, with values list already constructed
*/
static ADS_STATUS ads_modlist_add(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
				  int mod_op, const char *name, 
				  const void *_invals)
{
	int curmod;
	LDAPMod **modlist = (LDAPMod **) *mods;
	struct berval **ber_values = NULL;
	char **char_values = NULL;

	if (!_invals) {
		mod_op = LDAP_MOD_DELETE;
	} else {
		if (mod_op & LDAP_MOD_BVALUES) {
			const struct berval **b;
			b = discard_const_p(const struct berval *, _invals);
			ber_values = ads_dup_values(ctx, b);
		} else {
			const char **c;
			c = discard_const_p(const char *, _invals);
			char_values = ads_push_strvals(ctx, c);
		}
	}

	/* find the first empty slot */
	for (curmod=0; modlist[curmod] && modlist[curmod] != (LDAPMod *) -1;
	     curmod++);
	if (modlist[curmod] == (LDAPMod *) -1) {
		if (!(modlist = talloc_realloc(ctx, modlist, LDAPMod *,
				curmod+ADS_MODLIST_ALLOC_SIZE+1)))
			return ADS_ERROR(LDAP_NO_MEMORY);
		memset(&modlist[curmod], 0, 
		       ADS_MODLIST_ALLOC_SIZE*sizeof(LDAPMod *));
		modlist[curmod+ADS_MODLIST_ALLOC_SIZE] = (LDAPMod *) -1;
		*mods = (ADS_MODLIST)modlist;
	}

	if (!(modlist[curmod] = talloc_zero(ctx, LDAPMod)))
		return ADS_ERROR(LDAP_NO_MEMORY);
	modlist[curmod]->mod_type = talloc_strdup(ctx, name);
	if (mod_op & LDAP_MOD_BVALUES) {
		modlist[curmod]->mod_bvalues = ber_values;
	} else if (mod_op & LDAP_MOD_DELETE) {
		modlist[curmod]->mod_values = NULL;
	} else {
		modlist[curmod]->mod_values = char_values;
	}

	modlist[curmod]->mod_op = mod_op;
	return ADS_ERROR(LDAP_SUCCESS);
}

/**
 * Add a single string value to a mod list
 * @param ctx An initialized TALLOC_CTX
 * @param mods An initialized ADS_MODLIST
 * @param name The attribute name to add
 * @param val The value to add - NULL means DELETE
 * @return ADS STATUS indicating success of add
 **/
ADS_STATUS ads_mod_str(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
		       const char *name, const char *val)
{
	const char *values[2];

	values[0] = val;
	values[1] = NULL;

	if (!val)
		return ads_modlist_add(ctx, mods, LDAP_MOD_DELETE, name, NULL);
	return ads_modlist_add(ctx, mods, LDAP_MOD_REPLACE, name, values);
}

/**
 * Add an array of string values to a mod list
 * @param ctx An initialized TALLOC_CTX
 * @param mods An initialized ADS_MODLIST
 * @param name The attribute name to add
 * @param vals The array of string values to add - NULL means DELETE
 * @return ADS STATUS indicating success of add
 **/
ADS_STATUS ads_mod_strlist(TALLOC_CTX *ctx, ADS_MODLIST *mods,
			   const char *name, const char **vals)
{
	if (!vals)
		return ads_modlist_add(ctx, mods, LDAP_MOD_DELETE, name, NULL);
	return ads_modlist_add(ctx, mods, LDAP_MOD_REPLACE, 
			       name, (const void **) vals);
}

/**
 * Add a single ber-encoded value to a mod list
 * @param ctx An initialized TALLOC_CTX
 * @param mods An initialized ADS_MODLIST
 * @param name The attribute name to add
 * @param val The value to add - NULL means DELETE
 * @return ADS STATUS indicating success of add
 **/
static ADS_STATUS ads_mod_ber(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
			      const char *name, const struct berval *val)
{
	const struct berval *values[2];

	values[0] = val;
	values[1] = NULL;
	if (!val)
		return ads_modlist_add(ctx, mods, LDAP_MOD_DELETE, name, NULL);
	return ads_modlist_add(ctx, mods, LDAP_MOD_REPLACE|LDAP_MOD_BVALUES,
			       name, (const void **) values);
}

static void ads_print_error(int ret, LDAP *ld)
{
	if (ret != 0) {
		char *ld_error = NULL;
		ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &ld_error);
		DBG_ERR("AD LDAP ERROR: %d (%s): %s\n",
			ret,
			ldap_err2string(ret),
			ld_error);
		SAFE_FREE(ld_error);
	}
}

/**
 * Perform an ldap modify
 * @param ads connection to ads server
 * @param mod_dn DistinguishedName to modify
 * @param mods list of modifications to perform
 * @return status of modify
 **/
ADS_STATUS ads_gen_mod(ADS_STRUCT *ads, const char *mod_dn, ADS_MODLIST mods)
{
	int ret,i;
	char *utf8_dn = NULL;
	size_t converted_size;
	/* 
	   this control is needed to modify that contains a currently 
	   non-existent attribute (but allowable for the object) to run
	*/
	LDAPControl PermitModify = {
                discard_const_p(char, ADS_PERMIT_MODIFY_OID),
		{0, NULL},
		(char) 1};
	LDAPControl *controls[2];

	DBG_INFO("AD LDAP: Modifying %s\n", mod_dn);

	controls[0] = &PermitModify;
	controls[1] = NULL;

	if (!push_utf8_talloc(talloc_tos(), &utf8_dn, mod_dn, &converted_size)) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	/* find the end of the list, marked by NULL or -1 */
	for(i=0;(mods[i]!=0)&&(mods[i]!=(LDAPMod *) -1);i++);
	/* make sure the end of the list is NULL */
	mods[i] = NULL;
	ret = ldap_modify_ext_s(ads->ldap.ld, utf8_dn,
				(LDAPMod **) mods, controls, NULL);
	ads_print_error(ret, ads->ldap.ld);
	TALLOC_FREE(utf8_dn);
	return ADS_ERROR(ret);
}

/**
 * Perform an ldap add
 * @param ads connection to ads server
 * @param new_dn DistinguishedName to add
 * @param mods list of attributes and values for DN
 * @return status of add
 **/
ADS_STATUS ads_gen_add(ADS_STRUCT *ads, const char *new_dn, ADS_MODLIST mods)
{
	int ret, i;
	char *utf8_dn = NULL;
	size_t converted_size;

	DBG_INFO("AD LDAP: Adding %s\n", new_dn);

	if (!push_utf8_talloc(talloc_tos(), &utf8_dn, new_dn, &converted_size)) {
		DEBUG(1, ("ads_gen_add: push_utf8_talloc failed!"));
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	/* find the end of the list, marked by NULL or -1 */
	for(i=0;(mods[i]!=0)&&(mods[i]!=(LDAPMod *) -1);i++);
	/* make sure the end of the list is NULL */
	mods[i] = NULL;

	ret = ldap_add_ext_s(ads->ldap.ld, utf8_dn, (LDAPMod**)mods, NULL, NULL);
	ads_print_error(ret, ads->ldap.ld);
	TALLOC_FREE(utf8_dn);
	return ADS_ERROR(ret);
}

/**
 * Delete a DistinguishedName
 * @param ads connection to ads server
 * @param new_dn DistinguishedName to delete
 * @return status of delete
 **/
ADS_STATUS ads_del_dn(ADS_STRUCT *ads, char *del_dn)
{
	int ret;
	char *utf8_dn = NULL;
	size_t converted_size;
	if (!push_utf8_talloc(talloc_tos(), &utf8_dn, del_dn, &converted_size)) {
		DEBUG(1, ("ads_del_dn: push_utf8_talloc failed!"));
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	DBG_INFO("AD LDAP: Deleting %s\n", del_dn);

	ret = ldap_delete_s(ads->ldap.ld, utf8_dn);
	ads_print_error(ret, ads->ldap.ld);
	TALLOC_FREE(utf8_dn);
	return ADS_ERROR(ret);
}

/**
 * Build an org unit string
 *  if org unit is Computers or blank then assume a container, otherwise
 *  assume a / separated list of organisational units.
 * jmcd: '\' is now used for escapes so certain chars can be in the ou (e.g. #)
 * @param ads connection to ads server
 * @param org_unit Organizational unit
 * @return org unit string - caller must free
 **/
char *ads_ou_string(ADS_STRUCT *ads, const char *org_unit)
{
	char *ret = NULL;

	if (!org_unit || !*org_unit) {

		ret = ads_default_ou_string(ads, DS_GUID_COMPUTERS_CONTAINER);

		/* samba4 might not yet respond to a wellknownobject-query */
		return ret ? ret : SMB_STRDUP("cn=Computers");
	}

	if (strequal(org_unit, "Computers")) {
		return SMB_STRDUP("cn=Computers");
	}

	/* jmcd: removed "\\" from the separation chars, because it is
	   needed as an escape for chars like '#' which are valid in an
	   OU name */
	return ads_build_path(org_unit, "/", "ou=", 1);
}

/**
 * Get a org unit string for a well-known GUID
 * @param ads connection to ads server
 * @param wknguid Well known GUID
 * @return org unit string - caller must free
 **/
char *ads_default_ou_string(ADS_STRUCT *ads, const char *wknguid)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	char *base, *wkn_dn = NULL, *ret = NULL, **wkn_dn_exp = NULL,
		**bind_dn_exp = NULL;
	const char *attrs[] = {"distinguishedName", NULL};
	int new_ln, wkn_ln, bind_ln, i;

	if (wknguid == NULL) {
		return NULL;
	}

	if (asprintf(&base, "<WKGUID=%s,%s>", wknguid, ads->config.bind_path ) == -1) {
		DEBUG(1, ("asprintf failed!\n"));
		return NULL;
	}

	status = ads_search_dn(ads, &res, base, attrs);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("Failed while searching for: %s\n", base));
		goto out;
	}

	if (ads_count_replies(ads, res) != 1) {
		goto out;
	}

	/* substitute the bind-path from the well-known-guid-search result */
	wkn_dn = ads_get_dn(ads, talloc_tos(), res);
	if (!wkn_dn) {
		goto out;
	}

	wkn_dn_exp = ldap_explode_dn(wkn_dn, 0);
	if (!wkn_dn_exp) {
		goto out;
	}

	bind_dn_exp = ldap_explode_dn(ads->config.bind_path, 0);
	if (!bind_dn_exp) {
		goto out;
	}

	for (wkn_ln=0; wkn_dn_exp[wkn_ln]; wkn_ln++)
		;
	for (bind_ln=0; bind_dn_exp[bind_ln]; bind_ln++)
		;

	new_ln = wkn_ln - bind_ln;

	ret = SMB_STRDUP(wkn_dn_exp[0]);
	if (!ret) {
		goto out;
	}

	for (i=1; i < new_ln; i++) {
		char *s = NULL;

		if (asprintf(&s, "%s,%s", ret, wkn_dn_exp[i]) == -1) {
			SAFE_FREE(ret);
			goto out;
		}

		SAFE_FREE(ret);
		ret = SMB_STRDUP(s);
		free(s);
		if (!ret) {
			goto out;
		}
	}

 out:
	SAFE_FREE(base);
	ads_msgfree(ads, res);
	TALLOC_FREE(wkn_dn);
	if (wkn_dn_exp) {
		ldap_value_free(wkn_dn_exp);
	}
	if (bind_dn_exp) {
		ldap_value_free(bind_dn_exp);
	}

	return ret;
}

/**
 * Adds (appends) an item to an attribute array, rather then
 * replacing the whole list
 * @param ctx An initialized TALLOC_CTX
 * @param mods An initialized ADS_MODLIST
 * @param name name of the ldap attribute to append to
 * @param vals an array of values to add
 * @return status of addition
 **/

ADS_STATUS ads_add_strlist(TALLOC_CTX *ctx, ADS_MODLIST *mods,
				const char *name, const char **vals)
{
	return ads_modlist_add(ctx, mods, LDAP_MOD_ADD, name,
			       (const void *) vals);
}

/**
 * Determines the an account's current KVNO via an LDAP lookup
 * @param ads An initialized ADS_STRUCT
 * @param account_name the NT samaccountname.
 * @return the kvno for the account, or -1 in case of a failure.
 **/

uint32_t ads_get_kvno(ADS_STRUCT *ads, const char *account_name)
{
	LDAPMessage *res = NULL;
	uint32_t kvno = (uint32_t)-1;      /* -1 indicates a failure */
	char *filter;
	const char *attrs[] = {"msDS-KeyVersionNumber", NULL};
	char *dn_string = NULL;
	ADS_STATUS ret;

	DEBUG(5,("ads_get_kvno: Searching for account %s\n", account_name));
	if (asprintf(&filter, "(samAccountName=%s)", account_name) == -1) {
		return kvno;
	}
	ret = ads_search(ads, &res, filter, attrs);
	SAFE_FREE(filter);
	if (!ADS_ERR_OK(ret) || (ads_count_replies(ads, res) != 1)) {
		DEBUG(1,("ads_get_kvno: Account for %s not found.\n", account_name));
		ads_msgfree(ads, res);
		return kvno;
	}

	dn_string = ads_get_dn(ads, talloc_tos(), res);
	if (!dn_string) {
		DEBUG(0,("ads_get_kvno: out of memory.\n"));
		ads_msgfree(ads, res);
		return kvno;
	}
	DEBUG(5,("ads_get_kvno: Using: %s\n", dn_string));
	TALLOC_FREE(dn_string);

	/* ---------------------------------------------------------
	 * 0 is returned as a default KVNO from this point on...
	 * This is done because Windows 2000 does not support key
	 * version numbers.  Chances are that a failure in the next
	 * step is simply due to Windows 2000 being used for a
	 * domain controller. */
	kvno = 0;

	if (!ads_pull_uint32(ads, res, "msDS-KeyVersionNumber", &kvno)) {
		DEBUG(3,("ads_get_kvno: Error Determining KVNO!\n"));
		DEBUG(3,("ads_get_kvno: Windows 2000 does not support KVNO's, so this may be normal.\n"));
		ads_msgfree(ads, res);
		return kvno;
	}

	/* Success */
	DEBUG(5,("ads_get_kvno: Looked Up KVNO of: %d\n", kvno));
	ads_msgfree(ads, res);
	return kvno;
}

/**
 * Determines the computer account's current KVNO via an LDAP lookup
 * @param ads An initialized ADS_STRUCT
 * @param machine_name the NetBIOS name of the computer, which is used to identify the computer account.
 * @return the kvno for the computer account, or -1 in case of a failure.
 **/

uint32_t ads_get_machine_kvno(ADS_STRUCT *ads, const char *machine_name)
{
	char *computer_account = NULL;
	uint32_t kvno = -1;

	if (asprintf(&computer_account, "%s$", machine_name) < 0) {
		return kvno;
	}

	kvno = ads_get_kvno(ads, computer_account);
	free(computer_account);

	return kvno;
}

/**
 * This clears out all registered spn's for a given hostname
 * @param ads An initilaized ADS_STRUCT
 * @param machine_name the NetBIOS name of the computer.
 * @return 0 upon success, non-zero otherwise.
 **/

ADS_STATUS ads_clear_service_principal_names(ADS_STRUCT *ads, const char *machine_name)
{
	TALLOC_CTX *ctx;
	LDAPMessage *res = NULL;
	ADS_MODLIST mods;
	const char *servicePrincipalName[1] = {NULL};
	ADS_STATUS ret;
	char *dn_string = NULL;

	ret = ads_find_machine_acct(ads, &res, machine_name);
	if (!ADS_ERR_OK(ret)) {
		DEBUG(5,("ads_clear_service_principal_names: WARNING: Host Account for %s not found... skipping operation.\n", machine_name));
		DEBUG(5,("ads_clear_service_principal_names: WARNING: Service Principals for %s have NOT been cleared.\n", machine_name));
		ads_msgfree(ads, res);
		return ret;
	}

	DEBUG(5,("ads_clear_service_principal_names: Host account for %s found\n", machine_name));
	ctx = talloc_init("ads_clear_service_principal_names");
	if (!ctx) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	if (!(mods = ads_init_mods(ctx))) {
		talloc_destroy(ctx);
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}
	ret = ads_mod_strlist(ctx, &mods, "servicePrincipalName", servicePrincipalName);
	if (!ADS_ERR_OK(ret)) {
		DEBUG(1,("ads_clear_service_principal_names: Error creating strlist.\n"));
		ads_msgfree(ads, res);
		talloc_destroy(ctx);
		return ret;
	}
	dn_string = ads_get_dn(ads, talloc_tos(), res);
	if (!dn_string) {
		talloc_destroy(ctx);
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}
	ret = ads_gen_mod(ads, dn_string, mods);
	TALLOC_FREE(dn_string);
	if (!ADS_ERR_OK(ret)) {
		DEBUG(1,("ads_clear_service_principal_names: Error: Updating Service Principals for machine %s in LDAP\n",
			machine_name));
		ads_msgfree(ads, res);
		talloc_destroy(ctx);
		return ret;
	}

	ads_msgfree(ads, res);
	talloc_destroy(ctx);
	return ret;
}

/**
 * @brief Search for an element in a string array.
 *
 * @param[in]  el_array  The string array to search.
 *
 * @param[in]  num_el    The number of elements in the string array.
 *
 * @param[in]  el        The string to search.
 *
 * @return               True if found, false if not.
 */
bool ads_element_in_array(const char **el_array, size_t num_el, const char *el)
{
	size_t i;

	if (el_array == NULL || num_el == 0 || el == NULL) {
		return false;
	}

	for (i = 0; i < num_el && el_array[i] != NULL; i++) {
		int cmp;

		cmp = strcasecmp_m(el_array[i], el);
		if (cmp == 0) {
			return true;
		}
	}

	return false;
}

/**
 * @brief This gets the service principal names of an existing computer account.
 *
 * @param[in]  mem_ctx      The memory context to use to allocate the spn array.
 *
 * @param[in]  ads          The ADS context to use.
 *
 * @param[in]  machine_name The NetBIOS name of the computer, which is used to
 *                          identify the computer account.
 *
 * @param[in]  spn_array    A pointer to store the array for SPNs.
 *
 * @param[in]  num_spns     The number of principals stored in the array.
 *
 * @return                  0 on success, or a ADS error if a failure occurred.
 */
ADS_STATUS ads_get_service_principal_names(TALLOC_CTX *mem_ctx,
					   ADS_STRUCT *ads,
					   const char *machine_name,
					   char ***spn_array,
					   size_t *num_spns)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	int count;

	status = ads_find_machine_acct(ads,
				       &res,
				       machine_name);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("Host Account for %s not found... skipping operation.\n",
			 machine_name));
		return status;
	}

	count = ads_count_replies(ads, res);
	if (count != 1) {
		status = ADS_ERROR(LDAP_NO_SUCH_OBJECT);
		goto done;
	}

	*spn_array = ads_pull_strings(ads,
				      mem_ctx,
				      res,
				      "servicePrincipalName",
				      num_spns);
	if (*spn_array == NULL) {
		DEBUG(1, ("Host account for %s does not have service principal "
			  "names.\n",
			  machine_name));
		status = ADS_ERROR(LDAP_NO_SUCH_OBJECT);
		goto done;
	}

done:
	ads_msgfree(ads, res);

	return status;
}

/**
 * This adds a service principal name to an existing computer account
 * (found by hostname) in AD.
 * @param ads An initialized ADS_STRUCT
 * @param machine_name the NetBIOS name of the computer, which is used to identify the computer account.
 * @param spns An array or strings for the service principals to add,
 *        i.e. 'cifs/machine_name', 'http/machine.full.domain.com' etc.
 * @return 0 upon sucess, or non-zero if a failure occurs
 **/

ADS_STATUS ads_add_service_principal_names(ADS_STRUCT *ads,
					   const char *machine_name,
                                           const char **spns)
{
	ADS_STATUS ret;
	TALLOC_CTX *ctx;
	LDAPMessage *res = NULL;
	ADS_MODLIST mods;
	char *dn_string = NULL;
	const char **servicePrincipalName = spns;

	ret = ads_find_machine_acct(ads, &res, machine_name);
	if (!ADS_ERR_OK(ret)) {
		DEBUG(1,("ads_add_service_principal_name: WARNING: Host Account for %s not found... skipping operation.\n",
			machine_name));
		DEBUG(1,("ads_add_service_principal_name: WARNING: Service Principals have NOT been added.\n"));
		ads_msgfree(ads, res);
		return ret;
	}

	DEBUG(1,("ads_add_service_principal_name: Host account for %s found\n", machine_name));
	if (!(ctx = talloc_init("ads_add_service_principal_name"))) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	DEBUG(5,("ads_add_service_principal_name: INFO: "
		"Adding %s to host %s\n",
		spns[0] ? "N/A" : spns[0], machine_name));


	DEBUG(5,("ads_add_service_principal_name: INFO: "
		"Adding %s to host %s\n",
		spns[1] ? "N/A" : spns[1], machine_name));

	if ( (mods = ads_init_mods(ctx)) == NULL ) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto out;
	}

	ret = ads_add_strlist(ctx,
			      &mods,
			      "servicePrincipalName",
			      servicePrincipalName);
	if (!ADS_ERR_OK(ret)) {
		DEBUG(1,("ads_add_service_principal_name: Error: Updating Service Principals in LDAP\n"));
		goto out;
	}

	if ( (dn_string = ads_get_dn(ads, ctx, res)) == NULL ) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto out;
	}

	ret = ads_gen_mod(ads, dn_string, mods);
	if (!ADS_ERR_OK(ret)) {
		DEBUG(1,("ads_add_service_principal_name: Error: Updating Service Principals in LDAP\n"));
		goto out;
	}

 out:
	TALLOC_FREE( ctx );
	ads_msgfree(ads, res);
	return ret;
}

static uint32_t ads_get_acct_ctrl(ADS_STRUCT *ads,
				  LDAPMessage *msg)
{
	uint32_t acct_ctrl = 0;
	bool ok;

	ok = ads_pull_uint32(ads, msg, "userAccountControl", &acct_ctrl);
	if (!ok) {
		return 0;
	}

	return acct_ctrl;
}

static ADS_STATUS ads_change_machine_acct(ADS_STRUCT *ads,
					  LDAPMessage *msg,
					  const struct berval *machine_pw_val)
{
	ADS_MODLIST mods;
	ADS_STATUS ret;
	TALLOC_CTX *frame = talloc_stackframe();
	uint32_t acct_control;
	char *control_str = NULL;
	const char *attrs[] = {
		"objectSid",
		NULL
	};
	LDAPMessage *res = NULL;
	char *dn = NULL;

	dn = ads_get_dn(ads, frame, msg);
	if (dn == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	acct_control = ads_get_acct_ctrl(ads, msg);
	if (acct_control == 0) {
		ret = ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
		goto done;
	}

	/*
	 * Changing the password, disables the account. So we need to change the
	 * userAccountControl flags to enable it again.
	 */
	mods = ads_init_mods(frame);
	if (mods == NULL) {
		ret = ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		goto done;
	}

	ads_mod_ber(frame, &mods, "unicodePwd", machine_pw_val);

	ret = ads_gen_mod(ads, dn, mods);
	if (!ADS_ERR_OK(ret)) {
		goto done;
	}
	TALLOC_FREE(mods);

	/*
	 * To activate the account, we need to disable and enable it.
	 */
	acct_control |= UF_ACCOUNTDISABLE;

	control_str = talloc_asprintf(frame, "%u", acct_control);
	if (control_str == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	mods = ads_init_mods(frame);
	if (mods == NULL) {
		ret = ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		goto done;
	}

	ads_mod_str(frame, &mods, "userAccountControl", control_str);

	ret = ads_gen_mod(ads, dn, mods);
	if (!ADS_ERR_OK(ret)) {
		goto done;
	}
	TALLOC_FREE(mods);
	TALLOC_FREE(control_str);

	/*
	 * Enable the account again.
	 */
	acct_control &= ~UF_ACCOUNTDISABLE;

	control_str = talloc_asprintf(frame, "%u", acct_control);
	if (control_str == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	mods = ads_init_mods(frame);
	if (mods == NULL) {
		ret = ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		goto done;
	}

	ads_mod_str(frame, &mods, "userAccountControl", control_str);

	ret = ads_gen_mod(ads, dn, mods);
	if (!ADS_ERR_OK(ret)) {
		goto done;
	}
	TALLOC_FREE(mods);
	TALLOC_FREE(control_str);

	ret = ads_search_dn(ads, &res, dn, attrs);
	ads_msgfree(ads, res);

done:
	talloc_free(frame);

	return ret;
}

/**
 * adds a machine account to the ADS server
 * @param ads An intialized ADS_STRUCT
 * @param machine_name - the NetBIOS machine name of this account.
 * @param account_type A number indicating the type of account to create
 * @param org_unit The LDAP path in which to place this account
 * @return 0 upon success, or non-zero otherwise
**/

ADS_STATUS ads_create_machine_acct(ADS_STRUCT *ads,
				   const char *machine_name,
				   const char *machine_password,
				   const char *org_unit,
				   uint32_t etype_list,
				   const char *dns_domain_name)
{
	ADS_STATUS ret;
	char *samAccountName = NULL;
	char *controlstr = NULL;
	TALLOC_CTX *ctx = NULL;
	ADS_MODLIST mods;
	char *machine_escaped = NULL;
	char *dns_hostname = NULL;
	char *new_dn = NULL;
	char *utf8_pw = NULL;
	size_t utf8_pw_len = 0;
	char *utf16_pw = NULL;
	size_t utf16_pw_len = 0;
	struct berval machine_pw_val;
	bool ok;
	const char **spn_array = NULL;
	size_t num_spns = 0;
	const char *spn_prefix[] = {
		"HOST",
		"RestrictedKrbHost",
	};
	size_t i;
	LDAPMessage *res = NULL;
	uint32_t acct_control = UF_WORKSTATION_TRUST_ACCOUNT;

	ctx = talloc_init("ads_add_machine_acct");
	if (ctx == NULL) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	machine_escaped = escape_rdn_val_string_alloc(machine_name);
	if (machine_escaped == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	utf8_pw = talloc_asprintf(ctx, "\"%s\"", machine_password);
	if (utf8_pw == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}
	utf8_pw_len = strlen(utf8_pw);

	ok = convert_string_talloc(ctx,
				   CH_UTF8, CH_UTF16MUNGED,
				   utf8_pw, utf8_pw_len,
				   (void *)&utf16_pw, &utf16_pw_len);
	if (!ok) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	machine_pw_val = (struct berval) {
		.bv_val = utf16_pw,
		.bv_len = utf16_pw_len,
	};

	/* Check if the machine account already exists. */
	ret = ads_find_machine_acct(ads, &res, machine_escaped);
	if (ADS_ERR_OK(ret)) {
		/* Change the machine account password */
		ret = ads_change_machine_acct(ads, res, &machine_pw_val);
		ads_msgfree(ads, res);

		goto done;
	}
	ads_msgfree(ads, res);

	new_dn = talloc_asprintf(ctx, "cn=%s,%s", machine_escaped, org_unit);
	if (new_dn == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	/* Create machine account */

	samAccountName = talloc_asprintf(ctx, "%s$", machine_name);
	if (samAccountName == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	dns_hostname = talloc_asprintf(ctx,
				       "%s.%s",
				       machine_name,
				       dns_domain_name);
	if (dns_hostname == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	/* Add dns_hostname SPNs */
	for (i = 0; i < ARRAY_SIZE(spn_prefix); i++) {
		char *spn = talloc_asprintf(ctx,
					    "%s/%s",
					    spn_prefix[i],
					    dns_hostname);
		if (spn == NULL) {
			ret = ADS_ERROR(LDAP_NO_MEMORY);
			goto done;
		}

		ok = add_string_to_array(spn_array,
					 spn,
					 &spn_array,
					 &num_spns);
		if (!ok) {
			ret = ADS_ERROR(LDAP_NO_MEMORY);
			goto done;
		}
	}

	/* Add machine_name SPNs */
	for (i = 0; i < ARRAY_SIZE(spn_prefix); i++) {
		char *spn = talloc_asprintf(ctx,
					    "%s/%s",
					    spn_prefix[i],
					    machine_name);
		if (spn == NULL) {
			ret = ADS_ERROR(LDAP_NO_MEMORY);
			goto done;
		}

		ok = add_string_to_array(spn_array,
					 spn,
					 &spn_array,
					 &num_spns);
		if (!ok) {
			ret = ADS_ERROR(LDAP_NO_MEMORY);
			goto done;
		}
	}

	/* Make sure to NULL terminate the array */
	spn_array = talloc_realloc(ctx, spn_array, const char *, num_spns + 1);
	if (spn_array == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}
	spn_array[num_spns] = NULL;

	controlstr = talloc_asprintf(ctx, "%u", acct_control);
	if (controlstr == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	mods = ads_init_mods(ctx);
	if (mods == NULL) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	ads_mod_str(ctx, &mods, "objectClass", "Computer");
	ads_mod_str(ctx, &mods, "SamAccountName", samAccountName);
	ads_mod_str(ctx, &mods, "userAccountControl", controlstr);
	ads_mod_str(ctx, &mods, "DnsHostName", dns_hostname);
	ads_mod_strlist(ctx, &mods, "ServicePrincipalName", spn_array);
	ads_mod_ber(ctx, &mods, "unicodePwd", &machine_pw_val);

	ret = ads_gen_add(ads, new_dn, mods);

done:
	SAFE_FREE(machine_escaped);
	talloc_destroy(ctx);

	return ret;
}

/**
 * move a machine account to another OU on the ADS server
 * @param ads - An intialized ADS_STRUCT
 * @param machine_name - the NetBIOS machine name of this account.
 * @param org_unit - The LDAP path in which to place this account
 * @param moved - whether we moved the machine account (optional)
 * @return 0 upon success, or non-zero otherwise
**/

ADS_STATUS ads_move_machine_acct(ADS_STRUCT *ads, const char *machine_name, 
                                 const char *org_unit, bool *moved)
{
	ADS_STATUS rc;
	int ldap_status;
	LDAPMessage *res = NULL;
	char *filter = NULL;
	char *computer_dn = NULL;
	char *parent_dn;
	char *computer_rdn = NULL;
	bool need_move = False;

	if (asprintf(&filter, "(samAccountName=%s$)", machine_name) == -1) {
		rc = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	/* Find pre-existing machine */
	rc = ads_search(ads, &res, filter, NULL);
	if (!ADS_ERR_OK(rc)) {
		goto done;
	}

	computer_dn = ads_get_dn(ads, talloc_tos(), res);
	if (!computer_dn) {
		rc = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	parent_dn = ads_parent_dn(computer_dn);
	if (strequal(parent_dn, org_unit)) {
		goto done;
	}

	need_move = True;

	if (asprintf(&computer_rdn, "CN=%s", machine_name) == -1) {
		rc = ADS_ERROR(LDAP_NO_MEMORY);
		goto done;
	}

	ldap_status = ldap_rename_s(ads->ldap.ld, computer_dn, computer_rdn, 
				    org_unit, 1, NULL, NULL);
	rc = ADS_ERROR(ldap_status);

done:
	ads_msgfree(ads, res);
	SAFE_FREE(filter);
	TALLOC_FREE(computer_dn);
	SAFE_FREE(computer_rdn);

	if (!ADS_ERR_OK(rc)) {
		need_move = False;
	}

	if (moved) {
		*moved = need_move;
	}

	return rc;
}

/*
  dump a binary result from ldap
*/
static void dump_binary(ADS_STRUCT *ads, const char *field, struct berval **values)
{
	size_t i;
	for (i=0; values[i]; i++) {
		ber_len_t j;
		printf("%s: ", field);
		for (j=0; j<values[i]->bv_len; j++) {
			printf("%02X", (unsigned char)values[i]->bv_val[j]);
		}
		printf("\n");
	}
}

static void dump_guid(ADS_STRUCT *ads, const char *field, struct berval **values)
{
	int i;
	for (i=0; values[i]; i++) {
		NTSTATUS status;
		DATA_BLOB in = data_blob_const(values[i]->bv_val, values[i]->bv_len);
		struct GUID guid;

		status = GUID_from_ndr_blob(&in, &guid);
		if (NT_STATUS_IS_OK(status)) {
			printf("%s: %s\n", field, GUID_string(talloc_tos(), &guid));
		} else {
			printf("%s: INVALID GUID\n", field);
		}
	}
}

/*
  dump a sid result from ldap
*/
static void dump_sid(ADS_STRUCT *ads, const char *field, struct berval **values)
{
	int i;
	for (i=0; values[i]; i++) {
		ssize_t ret;
		struct dom_sid sid;
		struct dom_sid_buf tmp;
		ret = sid_parse((const uint8_t *)values[i]->bv_val,
				values[i]->bv_len, &sid);
		if (ret == -1) {
			return;
		}
		printf("%s: %s\n", field, dom_sid_str_buf(&sid, &tmp));
	}
}

/*
  dump ntSecurityDescriptor
*/
static void dump_sd(ADS_STRUCT *ads, const char *filed, struct berval **values)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct security_descriptor *psd;
	NTSTATUS status;

	status = unmarshall_sec_desc(talloc_tos(), (uint8_t *)values[0]->bv_val,
				     values[0]->bv_len, &psd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("unmarshall_sec_desc failed: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(frame);
		return;
	}

	if (psd) {
		ads_disp_sd(ads, talloc_tos(), psd);
	}

	TALLOC_FREE(frame);
}

/*
  dump a string result from ldap
*/
static void dump_string(const char *field, char **values)
{
	int i;
	for (i=0; values[i]; i++) {
		printf("%s: %s\n", field, values[i]);
	}
}

/*
  dump a field from LDAP on stdout
  used for debugging
*/

static bool ads_dump_field(ADS_STRUCT *ads, char *field, void **values, void *data_area)
{
	const struct {
		const char *name;
		bool string;
		void (*handler)(ADS_STRUCT *, const char *, struct berval **);
	} handlers[] = {
		{"objectGUID", False, dump_guid},
		{"netbootGUID", False, dump_guid},
		{"nTSecurityDescriptor", False, dump_sd},
		{"dnsRecord", False, dump_binary},
		{"objectSid", False, dump_sid},
		{"tokenGroups", False, dump_sid},
		{"tokenGroupsNoGCAcceptable", False, dump_sid},
		{"tokengroupsGlobalandUniversal", False, dump_sid},
		{"mS-DS-CreatorSID", False, dump_sid},
		{"msExchMailboxGuid", False, dump_guid},
		{NULL, True, NULL}
	};
	int i;

	if (!field) { /* must be end of an entry */
		printf("\n");
		return False;
	}

	for (i=0; handlers[i].name; i++) {
		if (strcasecmp_m(handlers[i].name, field) == 0) {
			if (!values) /* first time, indicate string or not */
				return handlers[i].string;
			handlers[i].handler(ads, field, (struct berval **) values);
			break;
		}
	}
	if (!handlers[i].name) {
		if (!values) /* first time, indicate string conversion */
			return True;
		dump_string(field, (char **)values);
	}
	return False;
}

/**
 * Dump a result from LDAP on stdout
 *  used for debugging
 * @param ads connection to ads server
 * @param res Results to dump
 **/

 void ads_dump(ADS_STRUCT *ads, LDAPMessage *res)
{
	ads_process_results(ads, res, ads_dump_field, NULL);
}

/**
 * Walk through results, calling a function for each entry found.
 *  The function receives a field name, a berval * array of values,
 *  and a data area passed through from the start.  The function is
 *  called once with null for field and values at the end of each
 *  entry.
 * @param ads connection to ads server
 * @param res Results to process
 * @param fn Function for processing each result
 * @param data_area user-defined area to pass to function
 **/
 void ads_process_results(ADS_STRUCT *ads, LDAPMessage *res,
			  bool (*fn)(ADS_STRUCT *, char *, void **, void *),
			  void *data_area)
{
	LDAPMessage *msg;
	TALLOC_CTX *ctx;
	size_t converted_size;

	if (!(ctx = talloc_init("ads_process_results")))
		return;

	for (msg = ads_first_entry(ads, res); msg; 
	     msg = ads_next_entry(ads, msg)) {
		char *utf8_field;
		BerElement *b;

		for (utf8_field=ldap_first_attribute(ads->ldap.ld,
						     (LDAPMessage *)msg,&b); 
		     utf8_field;
		     utf8_field=ldap_next_attribute(ads->ldap.ld,
						    (LDAPMessage *)msg,b)) {
			struct berval **ber_vals;
			char **str_vals;
			char **utf8_vals;
			char *field;
			bool string; 

			if (!pull_utf8_talloc(ctx, &field, utf8_field,
					      &converted_size))
			{
				DEBUG(0,("ads_process_results: "
					 "pull_utf8_talloc failed: %s",
					 strerror(errno)));
			}

			string = fn(ads, field, NULL, data_area);

			if (string) {
				const char **p;

				utf8_vals = ldap_get_values(ads->ldap.ld,
					       	 (LDAPMessage *)msg, field);
				p = discard_const_p(const char *, utf8_vals);
				str_vals = ads_pull_strvals(ctx, p);
				fn(ads, field, (void **) str_vals, data_area);
				ldap_value_free(utf8_vals);
			} else {
				ber_vals = ldap_get_values_len(ads->ldap.ld, 
						 (LDAPMessage *)msg, field);
				fn(ads, field, (void **) ber_vals, data_area);

				ldap_value_free_len(ber_vals);
			}
			ldap_memfree(utf8_field);
		}
		ber_free(b, 0);
		talloc_free_children(ctx);
		fn(ads, NULL, NULL, data_area); /* completed an entry */

	}
	talloc_destroy(ctx);
}

/**
 * count how many replies are in a LDAPMessage
 * @param ads connection to ads server
 * @param res Results to count
 * @return number of replies
 **/
int ads_count_replies(ADS_STRUCT *ads, void *res)
{
	return ldap_count_entries(ads->ldap.ld, (LDAPMessage *)res);
}

/**
 * pull the first entry from a ADS result
 * @param ads connection to ads server
 * @param res Results of search
 * @return first entry from result
 **/
 LDAPMessage *ads_first_entry(ADS_STRUCT *ads, LDAPMessage *res)
{
	return ldap_first_entry(ads->ldap.ld, res);
}

/**
 * pull the next entry from a ADS result
 * @param ads connection to ads server
 * @param res Results of search
 * @return next entry from result
 **/
 LDAPMessage *ads_next_entry(ADS_STRUCT *ads, LDAPMessage *res)
{
	return ldap_next_entry(ads->ldap.ld, res);
}

/**
 * pull the first message from a ADS result
 * @param ads connection to ads server
 * @param res Results of search
 * @return first message from result
 **/
 LDAPMessage *ads_first_message(ADS_STRUCT *ads, LDAPMessage *res)
{
	return ldap_first_message(ads->ldap.ld, res);
}

/**
 * pull the next message from a ADS result
 * @param ads connection to ads server
 * @param res Results of search
 * @return next message from result
 **/
 LDAPMessage *ads_next_message(ADS_STRUCT *ads, LDAPMessage *res)
{
	return ldap_next_message(ads->ldap.ld, res);
}

/**
 * pull a single string from a ADS result
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX to use for allocating result string
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @return Result string in talloc context
 **/
 char *ads_pull_string(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, LDAPMessage *msg,
		       const char *field)
{
	char **values;
	char *ret = NULL;
	char *ux_string;
	size_t converted_size;

	values = ldap_get_values(ads->ldap.ld, msg, field);
	if (!values)
		return NULL;

	if (values[0] && pull_utf8_talloc(mem_ctx, &ux_string, values[0],
					  &converted_size))
	{
		ret = ux_string;
	}
	ldap_value_free(values);
	return ret;
}

/**
 * pull an array of strings from a ADS result
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX to use for allocating result string
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @return Result strings in talloc context
 **/
 char **ads_pull_strings(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
			 LDAPMessage *msg, const char *field,
			 size_t *num_values)
{
	char **values;
	char **ret = NULL;
	size_t i, converted_size;

	values = ldap_get_values(ads->ldap.ld, msg, field);
	if (!values)
		return NULL;

	*num_values = ldap_count_values(values);

	ret = talloc_array(mem_ctx, char *, *num_values + 1);
	if (!ret) {
		ldap_value_free(values);
		return NULL;
	}

	for (i=0;i<*num_values;i++) {
		if (!pull_utf8_talloc(mem_ctx, &ret[i], values[i],
				      &converted_size))
		{
			ldap_value_free(values);
			return NULL;
		}
	}
	ret[i] = NULL;

	ldap_value_free(values);
	return ret;
}

/**
 * pull an array of strings from a ADS result 
 *  (handle large multivalue attributes with range retrieval)
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX to use for allocating result string
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @param current_strings strings returned by a previous call to this function
 * @param next_attribute The next query should ask for this attribute
 * @param num_values How many values did we get this time?
 * @param more_values Are there more values to get?
 * @return Result strings in talloc context
 **/
 char **ads_pull_strings_range(ADS_STRUCT *ads, 
			       TALLOC_CTX *mem_ctx,
			       LDAPMessage *msg, const char *field,
			       char **current_strings,
			       const char **next_attribute,
			       size_t *num_strings,
			       bool *more_strings)
{
	char *attr;
	char *expected_range_attrib, *range_attr;
	BerElement *ptr = NULL;
	char **strings;
	char **new_strings;
	size_t num_new_strings;
	unsigned long int range_start;
	unsigned long int range_end;

	/* we might have been given the whole lot anyway */
	if ((strings = ads_pull_strings(ads, mem_ctx, msg, field, num_strings))) {
		*more_strings = False;
		return strings;
	}

	expected_range_attrib = talloc_asprintf(mem_ctx, "%s;Range=", field);

	/* look for Range result */
	for (attr = ldap_first_attribute(ads->ldap.ld, (LDAPMessage *)msg, &ptr); 
	     attr; 
	     attr = ldap_next_attribute(ads->ldap.ld, (LDAPMessage *)msg, ptr)) {
		/* we ignore the fact that this is utf8, as all attributes are ascii... */
		if (strnequal(attr, expected_range_attrib, strlen(expected_range_attrib))) {
			range_attr = attr;
			break;
		}
		ldap_memfree(attr);
	}
	if (!attr) {
		ber_free(ptr, 0);
		/* nothing here - this field is just empty */
		*more_strings = False;
		return NULL;
	}

	if (sscanf(&range_attr[strlen(expected_range_attrib)], "%lu-%lu", 
		   &range_start, &range_end) == 2) {
		*more_strings = True;
	} else {
		if (sscanf(&range_attr[strlen(expected_range_attrib)], "%lu-*", 
			   &range_start) == 1) {
			*more_strings = False;
		} else {
			DEBUG(1, ("ads_pull_strings_range:  Cannot parse Range attriubte (%s)\n", 
				  range_attr));
			ldap_memfree(range_attr);
			*more_strings = False;
			return NULL;
		}
	}

	if ((*num_strings) != range_start) {
		DEBUG(1, ("ads_pull_strings_range: Range attribute (%s) doesn't start at %u, but at %lu"
			  " - aborting range retreival\n",
			  range_attr, (unsigned int)(*num_strings) + 1, range_start));
		ldap_memfree(range_attr);
		*more_strings = False;
		return NULL;
	}

	new_strings = ads_pull_strings(ads, mem_ctx, msg, range_attr, &num_new_strings);

	if (*more_strings && ((*num_strings + num_new_strings) != (range_end + 1))) {
		DEBUG(1, ("ads_pull_strings_range: Range attribute (%s) tells us we have %lu "
			  "strings in this bunch, but we only got %lu - aborting range retreival\n",
			  range_attr, (unsigned long int)range_end - range_start + 1, 
			  (unsigned long int)num_new_strings));
		ldap_memfree(range_attr);
		*more_strings = False;
		return NULL;
	}

	strings = talloc_realloc(mem_ctx, current_strings, char *,
				 *num_strings + num_new_strings);

	if (strings == NULL) {
		ldap_memfree(range_attr);
		*more_strings = False;
		return NULL;
	}

	if (new_strings && num_new_strings) {
		memcpy(&strings[*num_strings], new_strings,
		       sizeof(*new_strings) * num_new_strings);
	}

	(*num_strings) += num_new_strings;

	if (*more_strings) {
		*next_attribute = talloc_asprintf(mem_ctx,
						  "%s;range=%d-*", 
						  field,
						  (int)*num_strings);

		if (!*next_attribute) {
			DEBUG(1, ("talloc_asprintf for next attribute failed!\n"));
			ldap_memfree(range_attr);
			*more_strings = False;
			return NULL;
		}
	}

	ldap_memfree(range_attr);

	return strings;
}

/**
 * pull a single uint32_t from a ADS result
 * @param ads connection to ads server
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @param v Pointer to int to store result
 * @return boolean inidicating success
*/
 bool ads_pull_uint32(ADS_STRUCT *ads, LDAPMessage *msg, const char *field,
		      uint32_t *v)
{
	char **values;

	values = ldap_get_values(ads->ldap.ld, msg, field);
	if (!values)
		return False;
	if (!values[0]) {
		ldap_value_free(values);
		return False;
	}

	*v = atoi(values[0]);
	ldap_value_free(values);
	return True;
}

/**
 * pull a single objectGUID from an ADS result
 * @param ads connection to ADS server
 * @param msg results of search
 * @param guid 37-byte area to receive text guid
 * @return boolean indicating success
 **/
 bool ads_pull_guid(ADS_STRUCT *ads, LDAPMessage *msg, struct GUID *guid)
{
	DATA_BLOB blob;
	NTSTATUS status;

	if (!smbldap_talloc_single_blob(talloc_tos(), ads->ldap.ld, msg, "objectGUID",
					&blob)) {
		return false;
	}

	status = GUID_from_ndr_blob(&blob, guid);
	talloc_free(blob.data);
	return NT_STATUS_IS_OK(status);
}


/**
 * pull a single struct dom_sid from a ADS result
 * @param ads connection to ads server
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @param sid Pointer to sid to store result
 * @return boolean inidicating success
*/
 bool ads_pull_sid(ADS_STRUCT *ads, LDAPMessage *msg, const char *field,
		   struct dom_sid *sid)
{
	return smbldap_pull_sid(ads->ldap.ld, msg, field, sid);
}

/**
 * pull an array of struct dom_sids from a ADS result
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX for allocating sid array
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @param sids pointer to sid array to allocate
 * @return the count of SIDs pulled
 **/
 int ads_pull_sids(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
		   LDAPMessage *msg, const char *field, struct dom_sid **sids)
{
	struct berval **values;
	int count, i;

	values = ldap_get_values_len(ads->ldap.ld, msg, field);

	if (!values)
		return 0;

	for (i=0; values[i]; i++)
		/* nop */ ;

	if (i) {
		(*sids) = talloc_array(mem_ctx, struct dom_sid, i);
		if (!(*sids)) {
			ldap_value_free_len(values);
			return 0;
		}
	} else {
		(*sids) = NULL;
	}

	count = 0;
	for (i=0; values[i]; i++) {
		ssize_t ret;
		ret = sid_parse((const uint8_t *)values[i]->bv_val,
				values[i]->bv_len, &(*sids)[count]);
		if (ret != -1) {
			struct dom_sid_buf buf;
			DBG_DEBUG("pulling SID: %s\n",
				  dom_sid_str_buf(&(*sids)[count], &buf));
			count++;
		}
	}

	ldap_value_free_len(values);
	return count;
}

/**
 * pull a struct security_descriptor from a ADS result
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX for allocating sid array
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @param sd Pointer to *struct security_descriptor to store result (talloc()ed)
 * @return boolean inidicating success
*/
 bool ads_pull_sd(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
		  LDAPMessage *msg, const char *field,
		  struct security_descriptor **sd)
{
	struct berval **values;
	bool ret = true;

	values = ldap_get_values_len(ads->ldap.ld, msg, field);

	if (!values) return false;

	if (values[0]) {
		NTSTATUS status;
		status = unmarshall_sec_desc(mem_ctx,
					     (uint8_t *)values[0]->bv_val,
					     values[0]->bv_len, sd);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("unmarshall_sec_desc failed: %s\n",
				  nt_errstr(status)));
			ret = false;
		}
	}

	ldap_value_free_len(values);
	return ret;
}

/* 
 * in order to support usernames longer than 21 characters we need to 
 * use both the sAMAccountName and the userPrincipalName attributes 
 * It seems that not all users have the userPrincipalName attribute set
 *
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX for allocating sid array
 * @param msg Results of search
 * @return the username
 */
 char *ads_pull_username(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
			 LDAPMessage *msg)
{
#if 0	/* JERRY */
	char *ret, *p;

	/* lookup_name() only works on the sAMAccountName to 
	   returning the username portion of userPrincipalName
	   breaks winbindd_getpwnam() */

	ret = ads_pull_string(ads, mem_ctx, msg, "userPrincipalName");
	if (ret && (p = strchr_m(ret, '@'))) {
		*p = 0;
		return ret;
	}
#endif
	return ads_pull_string(ads, mem_ctx, msg, "sAMAccountName");
}


/**
 * find the update serial number - this is the core of the ldap cache
 * @param ads connection to ads server
 * @param ads connection to ADS server
 * @param usn Pointer to retrieved update serial number
 * @return status of search
 **/
ADS_STATUS ads_USN(ADS_STRUCT *ads, uint32_t *usn)
{
	const char *attrs[] = {"highestCommittedUSN", NULL};
	ADS_STATUS status;
	LDAPMessage *res;

	status = ads_do_search_retry(ads, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) 
		return status;

	if (ads_count_replies(ads, res) != 1) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
	}

	if (!ads_pull_uint32(ads, res, "highestCommittedUSN", usn)) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_SUCH_ATTRIBUTE);
	}

	ads_msgfree(ads, res);
	return ADS_SUCCESS;
}

/* parse a ADS timestring - typical string is
   '20020917091222.0Z0' which means 09:12.22 17th September
   2002, timezone 0 */
static time_t ads_parse_time(const char *str)
{
	struct tm tm;

	ZERO_STRUCT(tm);

	if (sscanf(str, "%4d%2d%2d%2d%2d%2d", 
		   &tm.tm_year, &tm.tm_mon, &tm.tm_mday, 
		   &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
		return 0;
	}
	tm.tm_year -= 1900;
	tm.tm_mon -= 1;

	return timegm(&tm);
}

/********************************************************************
********************************************************************/

ADS_STATUS ads_current_time(ADS_STRUCT *ads)
{
	const char *attrs[] = {"currentTime", NULL};
	ADS_STATUS status;
	LDAPMessage *res;
	char *timestr;
	TALLOC_CTX *ctx;
	ADS_STRUCT *ads_s = ads;

	if (!(ctx = talloc_init("ads_current_time"))) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

        /* establish a new ldap tcp session if necessary */

	if ( !ads->ldap.ld ) {
		if ( (ads_s = ads_init( ads->server.realm, ads->server.workgroup, 
			ads->server.ldap_server, ADS_SASL_PLAIN )) == NULL )
		{
			status = ADS_ERROR(LDAP_NO_MEMORY);
			goto done;
		}
		ads_s->auth.flags = ADS_AUTH_ANON_BIND;
		status = ads_connect( ads_s );
		if ( !ADS_ERR_OK(status))
			goto done;
	}

	status = ads_do_search(ads_s, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) {
		goto done;
	}

	timestr = ads_pull_string(ads_s, ctx, res, "currentTime");
	if (!timestr) {
		ads_msgfree(ads_s, res);
		status = ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
		goto done;
	}

	/* but save the time and offset in the original ADS_STRUCT */	

	ads->config.current_time = ads_parse_time(timestr);

	if (ads->config.current_time != 0) {
		ads->auth.time_offset = ads->config.current_time - time(NULL);
		DEBUG(4,("KDC time offset is %d seconds\n", ads->auth.time_offset));
	}

	ads_msgfree(ads, res);

	status = ADS_SUCCESS;

done:
	/* free any temporary ads connections */
	if ( ads_s != ads ) {
		ads_destroy( &ads_s );
	}
	talloc_destroy(ctx);

	return status;
}

/********************************************************************
********************************************************************/

ADS_STATUS ads_domain_func_level(ADS_STRUCT *ads, uint32_t *val)
{
	const char *attrs[] = {"domainFunctionality", NULL};
	ADS_STATUS status;
	LDAPMessage *res;
	ADS_STRUCT *ads_s = ads;

	*val = DS_DOMAIN_FUNCTION_2000;

        /* establish a new ldap tcp session if necessary */

	if ( !ads->ldap.ld ) {
		if ( (ads_s = ads_init( ads->server.realm, ads->server.workgroup, 
			ads->server.ldap_server, ADS_SASL_PLAIN )) == NULL )
		{
			status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			goto done;
		}
		ads_s->auth.flags = ADS_AUTH_ANON_BIND;
		status = ads_connect( ads_s );
		if ( !ADS_ERR_OK(status))
			goto done;
	}

	/* If the attribute does not exist assume it is a Windows 2000 
	   functional domain */

	status = ads_do_search(ads_s, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) {
		if ( status.err.rc == LDAP_NO_SUCH_ATTRIBUTE ) {
			status = ADS_SUCCESS;
		}
		goto done;
	}

	if ( !ads_pull_uint32(ads_s, res, "domainFunctionality", val) ) {
		DEBUG(5,("ads_domain_func_level: Failed to pull the domainFunctionality attribute.\n"));
	}
	DEBUG(3,("ads_domain_func_level: %d\n", *val));


	ads_msgfree(ads, res);

done:
	/* free any temporary ads connections */
	if ( ads_s != ads ) {
		ads_destroy( &ads_s );
	}

	return status;
}

/**
 * find the domain sid for our domain
 * @param ads connection to ads server
 * @param sid Pointer to domain sid
 * @return status of search
 **/
ADS_STATUS ads_domain_sid(ADS_STRUCT *ads, struct dom_sid *sid)
{
	const char *attrs[] = {"objectSid", NULL};
	LDAPMessage *res;
	ADS_STATUS rc;

	rc = ads_do_search_retry(ads, ads->config.bind_path, LDAP_SCOPE_BASE, "(objectclass=*)", 
			   attrs, &res);
	if (!ADS_ERR_OK(rc)) return rc;
	if (!ads_pull_sid(ads, res, "objectSid", sid)) {
		ads_msgfree(ads, res);
		return ADS_ERROR_SYSTEM(ENOENT);
	}
	ads_msgfree(ads, res);

	return ADS_SUCCESS;
}

/**
 * find our site name 
 * @param ads connection to ads server
 * @param mem_ctx Pointer to talloc context
 * @param site_name Pointer to the sitename
 * @return status of search
 **/
ADS_STATUS ads_site_dn(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, const char **site_name)
{
	ADS_STATUS status;
	LDAPMessage *res;
	const char *dn, *service_name;
	const char *attrs[] = { "dsServiceName", NULL };

	status = ads_do_search(ads, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	service_name = ads_pull_string(ads, mem_ctx, res, "dsServiceName");
	if (service_name == NULL) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
	}

	ads_msgfree(ads, res);

	/* go up three levels */
	dn = ads_parent_dn(ads_parent_dn(ads_parent_dn(service_name)));
	if (dn == NULL) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	*site_name = talloc_strdup(mem_ctx, dn);
	if (*site_name == NULL) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	return status;
	/*
	dsServiceName: CN=NTDS Settings,CN=W2K3DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ber,DC=suse,DC=de
	*/						 
}

/**
 * find the site dn where a machine resides
 * @param ads connection to ads server
 * @param mem_ctx Pointer to talloc context
 * @param computer_name name of the machine
 * @param site_name Pointer to the sitename
 * @return status of search
 **/
ADS_STATUS ads_site_dn_for_machine(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, const char *computer_name, const char **site_dn)
{
	ADS_STATUS status;
	LDAPMessage *res;
	const char *parent, *filter;
	char *config_context = NULL;
	char *dn;

	/* shortcut a query */
	if (strequal(computer_name, ads->config.ldap_server_name)) {
		return ads_site_dn(ads, mem_ctx, site_dn);
	}

	status = ads_config_path(ads, mem_ctx, &config_context);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	filter = talloc_asprintf(mem_ctx, "(cn=%s)", computer_name);
	if (filter == NULL) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	status = ads_do_search(ads, config_context, LDAP_SCOPE_SUBTREE, 
			       filter, NULL, &res);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	if (ads_count_replies(ads, res) != 1) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_SUCH_OBJECT);
	}

	dn = ads_get_dn(ads, mem_ctx, res);
	if (dn == NULL) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	/* go up three levels */
	parent = ads_parent_dn(ads_parent_dn(ads_parent_dn(dn)));
	if (parent == NULL) {
		ads_msgfree(ads, res);
		TALLOC_FREE(dn);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	*site_dn = talloc_strdup(mem_ctx, parent);
	if (*site_dn == NULL) {
		ads_msgfree(ads, res);
		TALLOC_FREE(dn);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	TALLOC_FREE(dn);
	ads_msgfree(ads, res);

	return status;
}

/**
 * get the upn suffixes for a domain
 * @param ads connection to ads server
 * @param mem_ctx Pointer to talloc context
 * @param suffixes Pointer to an array of suffixes
 * @param num_suffixes Pointer to the number of suffixes
 * @return status of search
 **/
ADS_STATUS ads_upn_suffixes(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, char ***suffixes, size_t *num_suffixes)
{
	ADS_STATUS status;
	LDAPMessage *res;
	const char *base;
	char *config_context = NULL;
	const char *attrs[] = { "uPNSuffixes", NULL };

	status = ads_config_path(ads, mem_ctx, &config_context);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	base = talloc_asprintf(mem_ctx, "cn=Partitions,%s", config_context);
	if (base == NULL) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	status = ads_search_dn(ads, &res, base, attrs);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	if (ads_count_replies(ads, res) != 1) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_SUCH_OBJECT);
	}

	(*suffixes) = ads_pull_strings(ads, mem_ctx, res, "uPNSuffixes", num_suffixes);
	if ((*suffixes) == NULL) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	ads_msgfree(ads, res);

	return status;
}

/**
 * get the joinable ous for a domain
 * @param ads connection to ads server
 * @param mem_ctx Pointer to talloc context
 * @param ous Pointer to an array of ous
 * @param num_ous Pointer to the number of ous
 * @return status of search
 **/
ADS_STATUS ads_get_joinable_ous(ADS_STRUCT *ads,
				TALLOC_CTX *mem_ctx,
				char ***ous,
				size_t *num_ous)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	LDAPMessage *msg = NULL;
	const char *attrs[] = { "dn", NULL };
	int count = 0;

	status = ads_search(ads, &res,
			    "(|(objectClass=domain)(objectclass=organizationalUnit))",
			    attrs);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	count = ads_count_replies(ads, res);
	if (count < 1) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
	}

	for (msg = ads_first_entry(ads, res); msg;
	     msg = ads_next_entry(ads, msg)) {
		const char **p = discard_const_p(const char *, *ous);
		char *dn = NULL;

		dn = ads_get_dn(ads, talloc_tos(), msg);
		if (!dn) {
			ads_msgfree(ads, res);
			return ADS_ERROR(LDAP_NO_MEMORY);
		}

		if (!add_string_to_array(mem_ctx, dn, &p, num_ous)) {
			TALLOC_FREE(dn);
			ads_msgfree(ads, res);
			return ADS_ERROR(LDAP_NO_MEMORY);
		}

		TALLOC_FREE(dn);
		*ous = discard_const_p(char *, p);
	}

	ads_msgfree(ads, res);

	return status;
}


/**
 * pull a struct dom_sid from an extended dn string
 * @param mem_ctx TALLOC_CTX
 * @param extended_dn string
 * @param flags string type of extended_dn
 * @param sid pointer to a struct dom_sid
 * @return NT_STATUS_OK on success,
 *	   NT_INVALID_PARAMETER on error,
 *	   NT_STATUS_NOT_FOUND if no SID present
 **/
ADS_STATUS ads_get_sid_from_extended_dn(TALLOC_CTX *mem_ctx,
					const char *extended_dn,
					enum ads_extended_dn_flags flags,
					struct dom_sid *sid)
{
	char *p, *q, *dn;

	if (!extended_dn) {
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	/* otherwise extended_dn gets stripped off */
	if ((dn = talloc_strdup(mem_ctx, extended_dn)) == NULL) {
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}
	/*
	 * ADS_EXTENDED_DN_HEX_STRING:
	 * <GUID=238e1963cb390f4bb032ba0105525a29>;<SID=010500000000000515000000bb68c8fd6b61b427572eb04556040000>;CN=gd,OU=berlin,OU=suse,DC=ber,DC=suse,DC=de
	 *
	 * ADS_EXTENDED_DN_STRING (only with w2k3):
	 * <GUID=63198e23-39cb-4b0f-b032-ba0105525a29>;<SID=S-1-5-21-4257769659-666132843-1169174103-1110>;CN=gd,OU=berlin,OU=suse,DC=ber,DC=suse,DC=de
	 *
	 * Object with no SID, such as an Exchange Public Folder
	 * <GUID=28907fb4bdf6854993e7f0a10b504e7c>;CN=public,CN=Microsoft Exchange System Objects,DC=sd2k3ms,DC=west,DC=isilon,DC=com
	 */

	p = strchr(dn, ';');
	if (!p) {
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	if (strncmp(p, ";<SID=", strlen(";<SID=")) != 0) {
		DEBUG(5,("No SID present in extended dn\n"));
		return ADS_ERROR_NT(NT_STATUS_NOT_FOUND);
	}

	p += strlen(";<SID=");

	q = strchr(p, '>');
	if (!q) {
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	*q = '\0';

	DEBUG(100,("ads_get_sid_from_extended_dn: sid string is %s\n", p));

	switch (flags) {

	case ADS_EXTENDED_DN_STRING:
		if (!string_to_sid(sid, p)) {
			return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}
		break;
	case ADS_EXTENDED_DN_HEX_STRING: {
		ssize_t ret;
		fstring buf;
		size_t buf_len;

		buf_len = strhex_to_str(buf, sizeof(buf), p, strlen(p));
		if (buf_len == 0) {
			return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}

		ret = sid_parse((const uint8_t *)buf, buf_len, sid);
		if (ret == -1) {
			DEBUG(10,("failed to parse sid\n"));
			return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}
		break;
		}
	default:
		DEBUG(10,("unknown extended dn format\n"));
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	return ADS_ERROR_NT(NT_STATUS_OK);
}

/********************************************************************
********************************************************************/

char* ads_get_dnshostname( ADS_STRUCT *ads, TALLOC_CTX *ctx, const char *machine_name )
{
	LDAPMessage *res = NULL;
	ADS_STATUS status;
	int count = 0;
	char *name = NULL;

	status = ads_find_machine_acct(ads, &res, machine_name);
	if (!ADS_ERR_OK(status)) {
		DEBUG(0,("ads_get_dnshostname: Failed to find account for %s\n",
			lp_netbios_name()));
		goto out;
	}

	if ( (count = ads_count_replies(ads, res)) != 1 ) {
		DEBUG(1,("ads_get_dnshostname: %d entries returned!\n", count));
		goto out;
	}

	if ( (name = ads_pull_string(ads, ctx, res, "dNSHostName")) == NULL ) {
		DEBUG(0,("ads_get_dnshostname: No dNSHostName attribute!\n"));
	}

out:
	ads_msgfree(ads, res);

	return name;
}

/********************************************************************
********************************************************************/

static char **get_addl_hosts(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
			      LDAPMessage *msg, size_t *num_values)
{
	const char *field = "msDS-AdditionalDnsHostName";
	struct berval **values = NULL;
	char **ret = NULL;
	size_t i, converted_size;

	/*
	 * Windows DC implicitly adds a short name for each FQDN added to
	 * msDS-AdditionalDnsHostName, but it comes with a strage binary
	 * suffix "\0$" which we should ignore (see bug #14406).
	 */

	values = ldap_get_values_len(ads->ldap.ld, msg, field);
	if (values == NULL) {
		return NULL;
	}

	*num_values = ldap_count_values_len(values);

	ret = talloc_array(mem_ctx, char *, *num_values + 1);
	if (ret == NULL) {
		ldap_value_free_len(values);
		return NULL;
	}

	for (i = 0; i < *num_values; i++) {
		ret[i] = NULL;
		if (!convert_string_talloc(mem_ctx, CH_UTF8, CH_UNIX,
					   values[i]->bv_val,
					   strnlen(values[i]->bv_val,
						   values[i]->bv_len),
					   &ret[i], &converted_size)) {
			ldap_value_free_len(values);
			return NULL;
		}
	}
	ret[i] = NULL;

	ldap_value_free_len(values);
	return ret;
}

ADS_STATUS ads_get_additional_dns_hostnames(TALLOC_CTX *mem_ctx,
					    ADS_STRUCT *ads,
					    const char *machine_name,
					    char ***hostnames_array,
					    size_t *num_hostnames)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	int count;

	status = ads_find_machine_acct(ads,
				       &res,
				       machine_name);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("Host Account for %s not found... skipping operation.\n",
			 machine_name));
		return status;
	}

	count = ads_count_replies(ads, res);
	if (count != 1) {
		status = ADS_ERROR(LDAP_NO_SUCH_OBJECT);
		goto done;
	}

	*hostnames_array = get_addl_hosts(ads, mem_ctx, res, num_hostnames);
	if (*hostnames_array == NULL) {
		DEBUG(1, ("Host account for %s does not have msDS-AdditionalDnsHostName.\n",
			  machine_name));
		status = ADS_ERROR(LDAP_NO_SUCH_OBJECT);
		goto done;
	}

done:
	ads_msgfree(ads, res);

	return status;
}

/********************************************************************
********************************************************************/

char* ads_get_upn( ADS_STRUCT *ads, TALLOC_CTX *ctx, const char *machine_name )
{
	LDAPMessage *res = NULL;
	ADS_STATUS status;
	int count = 0;
	char *name = NULL;

	status = ads_find_machine_acct(ads, &res, machine_name);
	if (!ADS_ERR_OK(status)) {
		DEBUG(0,("ads_get_upn: Failed to find account for %s\n",
			lp_netbios_name()));
		goto out;
	}

	if ( (count = ads_count_replies(ads, res)) != 1 ) {
		DEBUG(1,("ads_get_upn: %d entries returned!\n", count));
		goto out;
	}

	if ( (name = ads_pull_string(ads, ctx, res, "userPrincipalName")) == NULL ) {
		DEBUG(2,("ads_get_upn: No userPrincipalName attribute!\n"));
	}

out:
	ads_msgfree(ads, res);

	return name;
}

/********************************************************************
********************************************************************/

bool ads_has_samaccountname( ADS_STRUCT *ads, TALLOC_CTX *ctx, const char *machine_name )
{
	LDAPMessage *res = NULL;
	ADS_STATUS status;
	int count = 0;
	char *name = NULL;
	bool ok = false;

	status = ads_find_machine_acct(ads, &res, machine_name);
	if (!ADS_ERR_OK(status)) {
		DEBUG(0,("ads_has_samaccountname: Failed to find account for %s\n",
			lp_netbios_name()));
		goto out;
	}

	if ( (count = ads_count_replies(ads, res)) != 1 ) {
		DEBUG(1,("ads_has_samaccountname: %d entries returned!\n", count));
		goto out;
	}

	if ( (name = ads_pull_string(ads, ctx, res, "sAMAccountName")) == NULL ) {
		DEBUG(0,("ads_has_samaccountname: No sAMAccountName attribute!\n"));
	}

out:
	ads_msgfree(ads, res);
	if (name != NULL) {
		ok = (strlen(name) > 0);
	}
	TALLOC_FREE(name);
	return ok;
}

#if 0

   SAVED CODE - we used to join via ldap - remember how we did this. JRA.

/**
 * Join a machine to a realm
 *  Creates the machine account and sets the machine password
 * @param ads connection to ads server
 * @param machine name of host to add
 * @param org_unit Organizational unit to place machine in
 * @return status of join
 **/
ADS_STATUS ads_join_realm(ADS_STRUCT *ads, const char *machine_name,
			uint32_t account_type, const char *org_unit)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	char *machine;

	/* machine name must be lowercase */
	machine = SMB_STRDUP(machine_name);
	strlower_m(machine);

	/*
	status = ads_find_machine_acct(ads, (void **)&res, machine);
	if (ADS_ERR_OK(status) && ads_count_replies(ads, res) == 1) {
		DEBUG(0, ("Host account for %s already exists - deleting old account\n", machine));
		status = ads_leave_realm(ads, machine);
		if (!ADS_ERR_OK(status)) {
			DEBUG(0, ("Failed to delete host '%s' from the '%s' realm.\n",
				machine, ads->config.realm));
			return status;
		}
	}
	*/
	status = ads_add_machine_acct(ads, machine, account_type, org_unit);
	if (!ADS_ERR_OK(status)) {
		DEBUG(0, ("ads_join_realm: ads_add_machine_acct failed (%s): %s\n", machine, ads_errstr(status)));
		SAFE_FREE(machine);
		return status;
	}

	status = ads_find_machine_acct(ads, (void **)(void *)&res, machine);
	if (!ADS_ERR_OK(status)) {
		DEBUG(0, ("ads_join_realm: Host account test failed for machine %s\n", machine));
		SAFE_FREE(machine);
		return status;
	}

	SAFE_FREE(machine);
	ads_msgfree(ads, res);

	return status;
}
#endif

/**
 * Delete a machine from the realm
 * @param ads connection to ads server
 * @param hostname Machine to remove
 * @return status of delete
 **/
ADS_STATUS ads_leave_realm(ADS_STRUCT *ads, const char *hostname)
{
	ADS_STATUS status;
	void *msg;
	LDAPMessage *res;
	char *hostnameDN, *host;
	int rc;
	LDAPControl ldap_control;
	LDAPControl  * pldap_control[2] = {NULL, NULL};

	pldap_control[0] = &ldap_control;
	memset(&ldap_control, 0, sizeof(LDAPControl));
	ldap_control.ldctl_oid = discard_const_p(char, LDAP_SERVER_TREE_DELETE_OID);

	/* hostname must be lowercase */
	host = SMB_STRDUP(hostname);
	if (!strlower_m(host)) {
		SAFE_FREE(host);
		return ADS_ERROR_SYSTEM(EINVAL);
	}

	status = ads_find_machine_acct(ads, &res, host);
	if (!ADS_ERR_OK(status)) {
		DEBUG(0, ("Host account for %s does not exist.\n", host));
		SAFE_FREE(host);
		return status;
	}

	msg = ads_first_entry(ads, res);
	if (!msg) {
		SAFE_FREE(host);
		return ADS_ERROR_SYSTEM(ENOENT);
	}

	hostnameDN = ads_get_dn(ads, talloc_tos(), (LDAPMessage *)msg);
	if (hostnameDN == NULL) {
		SAFE_FREE(host);
		return ADS_ERROR_SYSTEM(ENOENT);
	}

	rc = ldap_delete_ext_s(ads->ldap.ld, hostnameDN, pldap_control, NULL);
	if (rc) {
		DEBUG(3,("ldap_delete_ext_s failed with error code %d\n", rc));
	}else {
		DEBUG(3,("ldap_delete_ext_s succeeded with error code %d\n", rc));
	}

	if (rc != LDAP_SUCCESS) {
		const char *attrs[] = { "cn", NULL };
		LDAPMessage *msg_sub;

		/* we only search with scope ONE, we do not expect any further
		 * objects to be created deeper */

		status = ads_do_search_retry(ads, hostnameDN,
					     LDAP_SCOPE_ONELEVEL,
					     "(objectclass=*)", attrs, &res);

		if (!ADS_ERR_OK(status)) {
			SAFE_FREE(host);
			TALLOC_FREE(hostnameDN);
			return status;
		}

		for (msg_sub = ads_first_entry(ads, res); msg_sub;
			msg_sub = ads_next_entry(ads, msg_sub)) {

			char *dn = NULL;

			if ((dn = ads_get_dn(ads, talloc_tos(), msg_sub)) == NULL) {
				SAFE_FREE(host);
				TALLOC_FREE(hostnameDN);
				return ADS_ERROR(LDAP_NO_MEMORY);
			}

			status = ads_del_dn(ads, dn);
			if (!ADS_ERR_OK(status)) {
				DEBUG(3,("failed to delete dn %s: %s\n", dn, ads_errstr(status)));
				SAFE_FREE(host);
				TALLOC_FREE(dn);
				TALLOC_FREE(hostnameDN);
				return status;
			}

			TALLOC_FREE(dn);
		}

		/* there should be no subordinate objects anymore */
		status = ads_do_search_retry(ads, hostnameDN,
					     LDAP_SCOPE_ONELEVEL,
					     "(objectclass=*)", attrs, &res);

		if (!ADS_ERR_OK(status) || ( (ads_count_replies(ads, res)) > 0 ) ) {
			SAFE_FREE(host);
			TALLOC_FREE(hostnameDN);
			return status;
		}

		/* delete hostnameDN now */
		status = ads_del_dn(ads, hostnameDN);
		if (!ADS_ERR_OK(status)) {
			SAFE_FREE(host);
			DEBUG(3,("failed to delete dn %s: %s\n", hostnameDN, ads_errstr(status)));
			TALLOC_FREE(hostnameDN);
			return status;
		}
	}

	TALLOC_FREE(hostnameDN);

	status = ads_find_machine_acct(ads, &res, host);
	if ((status.error_type == ENUM_ADS_ERROR_LDAP) &&
	    (status.err.rc != LDAP_NO_SUCH_OBJECT)) {
		DEBUG(3, ("Failed to remove host account.\n"));
		SAFE_FREE(host);
		return status;
	}

	SAFE_FREE(host);
	return ADS_SUCCESS;
}

/**
 * pull all token-sids from an LDAP dn
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX for allocating sid array
 * @param dn of LDAP object
 * @param user_sid pointer to struct dom_sid (objectSid)
 * @param primary_group_sid pointer to struct dom_sid (self composed)
 * @param sids pointer to sid array to allocate
 * @param num_sids counter of SIDs pulled
 * @return status of token query
 **/
 ADS_STATUS ads_get_tokensids(ADS_STRUCT *ads,
			      TALLOC_CTX *mem_ctx,
			      const char *dn,
			      struct dom_sid *user_sid,
			      struct dom_sid *primary_group_sid,
			      struct dom_sid **sids,
			      size_t *num_sids)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	int count = 0;
	size_t tmp_num_sids;
	struct dom_sid *tmp_sids;
	struct dom_sid tmp_user_sid;
	struct dom_sid tmp_primary_group_sid;
	uint32_t pgid;
	const char *attrs[] = {
		"objectSid",
		"tokenGroups",
		"primaryGroupID",
		NULL
	};

	status = ads_search_retry_dn(ads, &res, dn, attrs);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	count = ads_count_replies(ads, res);
	if (count != 1) {
		ads_msgfree(ads, res);
		return ADS_ERROR_LDAP(LDAP_NO_SUCH_OBJECT);
	}

	if (!ads_pull_sid(ads, res, "objectSid", &tmp_user_sid)) {
		ads_msgfree(ads, res);
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	if (!ads_pull_uint32(ads, res, "primaryGroupID", &pgid)) {
		ads_msgfree(ads, res);
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	{
		/* hack to compose the primary group sid without knowing the
		 * domsid */

		struct dom_sid domsid;

		sid_copy(&domsid, &tmp_user_sid);

		if (!sid_split_rid(&domsid, NULL)) {
			ads_msgfree(ads, res);
			return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		}

		if (!sid_compose(&tmp_primary_group_sid, &domsid, pgid)) {
			ads_msgfree(ads, res);
			return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
		}
	}

	tmp_num_sids = ads_pull_sids(ads, mem_ctx, res, "tokenGroups", &tmp_sids);

	if (tmp_num_sids == 0 || !tmp_sids) {
		ads_msgfree(ads, res);
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	if (num_sids) {
		*num_sids = tmp_num_sids;
	}

	if (sids) {
		*sids = tmp_sids;
	}

	if (user_sid) {
		*user_sid = tmp_user_sid;
	}

	if (primary_group_sid) {
		*primary_group_sid = tmp_primary_group_sid;
	}

	DEBUG(10,("ads_get_tokensids: returned %d sids\n", (int)tmp_num_sids + 2));

	ads_msgfree(ads, res);
	return ADS_ERROR_LDAP(LDAP_SUCCESS);
}

/**
 * Find a sAMAccoutName in LDAP
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX for allocating sid array
 * @param samaccountname to search
 * @param uac_ret uint32_t pointer userAccountControl attribute value
 * @param dn_ret pointer to dn
 * @return status of token query
 **/
ADS_STATUS ads_find_samaccount(ADS_STRUCT *ads,
			       TALLOC_CTX *mem_ctx,
			       const char *samaccountname,
			       uint32_t *uac_ret,
			       const char **dn_ret)
{
	ADS_STATUS status;
	const char *attrs[] = { "userAccountControl", NULL };
	const char *filter;
	LDAPMessage *res = NULL;
	char *dn = NULL;
	uint32_t uac = 0;

	filter = talloc_asprintf(mem_ctx, "(&(objectclass=user)(sAMAccountName=%s))",
		samaccountname);
	if (filter == NULL) {
		status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
		goto out;
	}

	status = ads_do_search_all(ads, ads->config.bind_path,
				   LDAP_SCOPE_SUBTREE,
				   filter, attrs, &res);

	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (ads_count_replies(ads, res) != 1) {
		status = ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
		goto out;
	}

	dn = ads_get_dn(ads, talloc_tos(), res);
	if (dn == NULL) {
		status = ADS_ERROR(LDAP_NO_MEMORY);
		goto out;
	}

	if (!ads_pull_uint32(ads, res, "userAccountControl", &uac)) {
		status = ADS_ERROR(LDAP_NO_SUCH_ATTRIBUTE);
		goto out;
	}

	if (uac_ret) {
		*uac_ret = uac;
	}

	if (dn_ret) {
		*dn_ret = talloc_strdup(mem_ctx, dn);
		if (!*dn_ret) {
			status = ADS_ERROR(LDAP_NO_MEMORY);
			goto out;
		}
	}
 out:
	TALLOC_FREE(dn);
	ads_msgfree(ads, res);

	return status;
}

/**
 * find our configuration path 
 * @param ads connection to ads server
 * @param mem_ctx Pointer to talloc context
 * @param config_path Pointer to the config path
 * @return status of search
 **/
ADS_STATUS ads_config_path(ADS_STRUCT *ads, 
			   TALLOC_CTX *mem_ctx, 
			   char **config_path)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	const char *config_context = NULL;
	const char *attrs[] = { "configurationNamingContext", NULL };

	status = ads_do_search(ads, "", LDAP_SCOPE_BASE, 
			       "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	config_context = ads_pull_string(ads, mem_ctx, res, 
					 "configurationNamingContext");
	ads_msgfree(ads, res);
	if (!config_context) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	if (config_path) {
		*config_path = talloc_strdup(mem_ctx, config_context);
		if (!*config_path) {
			return ADS_ERROR(LDAP_NO_MEMORY);
		}
	}

	return ADS_ERROR(LDAP_SUCCESS);
}

/**
 * find the displayName of an extended right 
 * @param ads connection to ads server
 * @param config_path The config path
 * @param mem_ctx Pointer to talloc context
 * @param GUID struct of the rightsGUID
 * @return status of search
 **/
const char *ads_get_extended_right_name_by_guid(ADS_STRUCT *ads, 
						const char *config_path, 
						TALLOC_CTX *mem_ctx, 
						const struct GUID *rights_guid)
{
	ADS_STATUS rc;
	LDAPMessage *res = NULL;
	char *expr = NULL;
	const char *attrs[] = { "displayName", NULL };
	const char *result = NULL;
	const char *path;

	if (!ads || !mem_ctx || !rights_guid) {
		goto done;
	}

	expr = talloc_asprintf(mem_ctx, "(rightsGuid=%s)", 
			       GUID_string(mem_ctx, rights_guid));
	if (!expr) {
		goto done;
	}

	path = talloc_asprintf(mem_ctx, "cn=Extended-Rights,%s", config_path);
	if (!path) {
		goto done;
	}

	rc = ads_do_search_retry(ads, path, LDAP_SCOPE_SUBTREE, 
				 expr, attrs, &res);
	if (!ADS_ERR_OK(rc)) {
		goto done;
	}

	if (ads_count_replies(ads, res) != 1) {
		goto done;
	}

	result = ads_pull_string(ads, mem_ctx, res, "displayName");

 done:
	ads_msgfree(ads, res);
	return result;
}

/**
 * verify or build and verify an account ou
 * @param mem_ctx Pointer to talloc context
 * @param ads connection to ads server
 * @param account_ou
 * @return status of search
 **/

ADS_STATUS ads_check_ou_dn(TALLOC_CTX *mem_ctx,
			   ADS_STRUCT *ads,
			   const char **account_ou)
{
	char **exploded_dn;
	const char *name;
	char *ou_string;

	if (account_ou == NULL) {
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	if (*account_ou != NULL) {
		exploded_dn = ldap_explode_dn(*account_ou, 0);
		if (exploded_dn) {
			ldap_value_free(exploded_dn);
			return ADS_SUCCESS;
		}
	}

	ou_string = ads_ou_string(ads, *account_ou);
	if (!ou_string) {
		return ADS_ERROR_LDAP(LDAP_INVALID_DN_SYNTAX);
	}

	name = talloc_asprintf(mem_ctx, "%s,%s", ou_string,
			       ads->config.bind_path);
	SAFE_FREE(ou_string);

	if (!name) {
		return ADS_ERROR_LDAP(LDAP_NO_MEMORY);
	}

	exploded_dn = ldap_explode_dn(name, 0);
	if (!exploded_dn) {
		return ADS_ERROR_LDAP(LDAP_INVALID_DN_SYNTAX);
	}
	ldap_value_free(exploded_dn);

	*account_ou = name;
	return ADS_SUCCESS;
}

#endif
