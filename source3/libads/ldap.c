/* 
   Unix SMB/CIFS implementation.
   ads (active directory) utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   
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

#include "includes.h"

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


/*
  try a connection to a given ldap server, returning True and setting the servers IP
  in the ads struct if successful
  
  TODO : add a negative connection cache in here leveraged off of the one
  found in the rpc code.  --jerry
 */
static BOOL ads_try_connect(ADS_STRUCT *ads, const char *server, unsigned port)
{
	char *srv;

	if (!server || !*server) {
		return False;
	}

	DEBUG(5,("ads_try_connect: trying ldap server '%s' port %u\n", server, port));

	/* this copes with inet_ntoa brokenness */
	srv = strdup(server);

	ads->ld = ldap_open(srv, port);
	if (!ads->ld) {
		free(srv);
		return False;
	}
	ads->ldap_port = port;
	ads->ldap_ip = *interpret_addr2(srv);
	free(srv);

	return True;
}

/*
  try a connection to a given ldap server, based on URL, returning True if successful
 */
static BOOL ads_try_connect_uri(ADS_STRUCT *ads)
{
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
	DEBUG(5,("ads_try_connect: trying ldap server at URI '%s'\n", 
		 ads->server.ldap_uri));

	
	if (ldap_initialize((LDAP**)&(ads->ld), ads->server.ldap_uri) == LDAP_SUCCESS) {
		return True;
	}
	DEBUG(0, ("ldap_initialize: %s\n", strerror(errno)));
	
#else 

	DEBUG(1, ("no URL support in LDAP libs!\n"));
#endif

	return False;
}

/**********************************************************************
 Try to find an AD dc using our internal name resolution routines
 Try the realm first and then then workgroup name if netbios is not 
 disabled
**********************************************************************/

static BOOL ads_find_dc(ADS_STRUCT *ads)
{
	const char *c_realm;
	int count, i=0;
	struct ip_service *ip_list;
	pstring realm;
	BOOL got_realm = False;
	BOOL use_own_domain = False;

	/* if the realm and workgroup are both empty, assume they are ours */

	/* realm */
	c_realm = ads->server.realm;
	
	if ( !c_realm || !*c_realm ) {
		/* special case where no realm and no workgroup means our own */
		if ( !ads->server.workgroup || !*ads->server.workgroup ) {
			use_own_domain = True;
			c_realm = lp_realm();
		}
	}
	
	if (c_realm && *c_realm) 
		got_realm = True;
		   
again:
	/* we need to try once with the realm name and fallback to the 
	   netbios domain name if we fail (if netbios has not been disabled */
	   
	if ( !got_realm	&& !lp_disable_netbios() ) {
		c_realm = ads->server.workgroup;
		if (!c_realm || !*c_realm) {
			if ( use_own_domain )
				c_realm = lp_workgroup();
		}
		
		if ( !c_realm || !*c_realm ) {
			DEBUG(0,("ads_find_dc: no realm or workgroup!  Don't know what to do\n"));
			return False;
		}
	}
	
	pstrcpy( realm, c_realm );

	DEBUG(6,("ads_find_dc: looking for %s '%s'\n", 
		(got_realm ? "realm" : "domain"), realm));

	if ( !get_sorted_dc_list(realm, &ip_list, &count, got_realm) ) {
		/* fall back to netbios if we can */
		if ( got_realm && !lp_disable_netbios() ) {
			got_realm = False;
			goto again;
		}
		
		return False;
	}
			
	/* if we fail this loop, then giveup since all the IP addresses returned were dead */
	for ( i=0; i<count; i++ ) {
		/* since this is an ads conection request, default to LDAP_PORT is not set */
		int port = (ip_list[i].port!=PORT_NONE) ? ip_list[i].port : LDAP_PORT;
		fstring server;
		
		fstrcpy( server, inet_ntoa(ip_list[i].ip) );
		
		if ( !NT_STATUS_IS_OK(check_negative_conn_cache(realm, server)) )
			continue;
			
		if ( ads_try_connect(ads, server, port) ) {
			SAFE_FREE(ip_list);
			return True;
		}
		
		/* keep track of failures */
		add_failed_connection_entry( realm, server, NT_STATUS_UNSUCCESSFUL );
	}

	SAFE_FREE(ip_list);
	
	return False;
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

	ads->last_attempt = time(NULL);
	ads->ld = NULL;

	/* try with a URL based server */

	if (ads->server.ldap_uri &&
	    ads_try_connect_uri(ads)) {
		goto got_connection;
	}

	/* try with a user specified server */
	if (ads->server.ldap_server && 
	    ads_try_connect(ads, ads->server.ldap_server, LDAP_PORT)) {
		goto got_connection;
	}

	if (ads_find_dc(ads)) {
		goto got_connection;
	}

	return ADS_ERROR_SYSTEM(errno?errno:ENOENT);

got_connection:
	DEBUG(3,("Connected to LDAP server %s\n", inet_ntoa(ads->ldap_ip)));

	status = ads_server_info(ads);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("Failed to get ldap server info\n"));
		return status;
	}

	ldap_set_option(ads->ld, LDAP_OPT_PROTOCOL_VERSION, &version);

	if (!ads->auth.user_name) {
		/* by default use the machine account */
		fstring myname;
		fstrcpy(myname, global_myname());
		strlower_m(myname);
		asprintf(&ads->auth.user_name, "HOST/%s", myname);
	}

	if (!ads->auth.realm) {
		ads->auth.realm = strdup(ads->config.realm);
	}

	if (!ads->auth.kdc_server) {
		ads->auth.kdc_server = strdup(inet_ntoa(ads->ldap_ip));
	}

#if KRB5_DNS_HACK
	/* this is a really nasty hack to avoid ADS DNS problems. It needs a patch
	   to MIT kerberos to work (tridge) */
	{
		char *env;
		asprintf(&env, "KRB5_KDC_ADDRESS_%s", ads->config.realm);
		setenv(env, ads->auth.kdc_server, 1);
		free(env);
	}
#endif

	if (ads->auth.flags & ADS_AUTH_NO_BIND) {
		return ADS_SUCCESS;
	}

	if (ads->auth.flags & ADS_AUTH_ANON_BIND) {
		return ADS_ERROR(ldap_simple_bind_s( ads->ld, NULL, NULL));
	}

	if (ads->auth.flags & ADS_AUTH_SIMPLE_BIND) {
		return ADS_ERROR(ldap_simple_bind_s( ads->ld, ads->auth.user_name, ads->auth.password));
	}

	return ads_sasl_bind(ads);
}

/*
  Duplicate a struct berval into talloc'ed memory
 */
static struct berval *dup_berval(TALLOC_CTX *ctx, const struct berval *in_val)
{
	struct berval *value;

	if (!in_val) return NULL;

	value = talloc_zero(ctx, sizeof(struct berval));
	if (value == NULL)
		return NULL;
	if (in_val->bv_len == 0) return value;

	value->bv_len = in_val->bv_len;
	value->bv_val = talloc_memdup(ctx, in_val->bv_val, in_val->bv_len);
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
	for (i=0; in_vals[i]; i++); /* count values */
	values = (struct berval **) talloc_zero(ctx, 
						(i+1)*sizeof(struct berval *));
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
       
	if (!in_vals) return NULL;
	for (i=0; in_vals[i]; i++); /* count values */
	values = (char ** ) talloc_zero(ctx, (i+1)*sizeof(char *));
	if (!values) return NULL;

	for (i=0; in_vals[i]; i++) {
		push_utf8_talloc(ctx, &values[i], in_vals[i]);
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
       
	if (!in_vals) return NULL;
	for (i=0; in_vals[i]; i++); /* count values */
	values = (char **) talloc_zero(ctx, (i+1)*sizeof(char *));
	if (!values) return NULL;

	for (i=0; in_vals[i]; i++) {
		pull_utf8_talloc(ctx, &values[i], in_vals[i]);
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
ADS_STATUS ads_do_paged_search(ADS_STRUCT *ads, const char *bind_path,
			       int scope, const char *expr,
			       const char **attrs, void **res, 
			       int *count, void **cookie)
{
	int rc, i, version;
	char *utf8_expr, *utf8_path, **search_attrs;
	LDAPControl PagedResults, NoReferrals, *controls[3], **rcontrols; 
	BerElement *cookie_be = NULL;
	struct berval *cookie_bv= NULL;
	TALLOC_CTX *ctx;

	*res = NULL;

	if (!(ctx = talloc_init("ads_do_paged_search")))
		return ADS_ERROR(LDAP_NO_MEMORY);

	/* 0 means the conversion worked but the result was empty 
	   so we only fail if it's -1.  In any case, it always 
	   at least nulls out the dest */
	if ((push_utf8_talloc(ctx, &utf8_expr, expr) == (size_t)-1) ||
	    (push_utf8_talloc(ctx, &utf8_path, bind_path) == (size_t)-1)) {
		rc = LDAP_NO_MEMORY;
		goto done;
	}

	if (!attrs || !(*attrs))
		search_attrs = NULL;
	else {
		/* This would be the utf8-encoded version...*/
		/* if (!(search_attrs = ads_push_strvals(ctx, attrs))) */
		if (!(str_list_copy(&search_attrs, attrs))) {
			rc = LDAP_NO_MEMORY;
			goto done;
		}
	}
		
		
	/* Paged results only available on ldap v3 or later */
	ldap_get_option(ads->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (version < LDAP_VERSION3) {
		rc =  LDAP_NOT_SUPPORTED;
		goto done;
	}

	cookie_be = ber_alloc_t(LBER_USE_DER);
	if (cookie && *cookie) {
		ber_printf(cookie_be, "{iO}", (ber_int_t) 1000, *cookie);
		ber_bvfree(*cookie); /* don't need it from last time */
		*cookie = NULL;
	} else {
		ber_printf(cookie_be, "{io}", (ber_int_t) 1000, "", 0);
	}
	ber_flatten(cookie_be, &cookie_bv);
	PagedResults.ldctl_oid = ADS_PAGE_CTL_OID;
	PagedResults.ldctl_iscritical = (char) 1;
	PagedResults.ldctl_value.bv_len = cookie_bv->bv_len;
	PagedResults.ldctl_value.bv_val = cookie_bv->bv_val;

	NoReferrals.ldctl_oid = ADS_NO_REFERRALS_OID;
	NoReferrals.ldctl_iscritical = (char) 0;
	NoReferrals.ldctl_value.bv_len = 0;
	NoReferrals.ldctl_value.bv_val = "";


	controls[0] = &NoReferrals;
	controls[1] = &PagedResults;
	controls[2] = NULL;

	*res = NULL;

	/* we need to disable referrals as the openldap libs don't
	   handle them and paged results at the same time.  Using them
	   together results in the result record containing the server 
	   page control being removed from the result list (tridge/jmcd) 
	
	   leaving this in despite the control that says don't generate
	   referrals, in case the server doesn't support it (jmcd)
	*/
	ldap_set_option(ads->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

	rc = ldap_search_ext_s(ads->ld, utf8_path, scope, utf8_expr, 
			       search_attrs, 0, controls,
			       NULL, NULL, LDAP_NO_LIMIT, (LDAPMessage **)res);

	ber_free(cookie_be, 1);
	ber_bvfree(cookie_bv);

	if (rc) {
		DEBUG(3,("ldap_search_ext_s(%s) -> %s\n", expr, ldap_err2string(rc)));
		goto done;
	}

	rc = ldap_parse_result(ads->ld, *res, NULL, NULL, NULL,
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
	/* if/when we decide to utf8-encode attrs, take out this next line */
	str_list_free(&search_attrs);

	return ADS_ERROR(rc);
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
ADS_STATUS ads_do_search_all(ADS_STRUCT *ads, const char *bind_path,
			     int scope, const char *expr,
			     const char **attrs, void **res)
{
	void *cookie = NULL;
	int count = 0;
	ADS_STATUS status;

	status = ads_do_paged_search(ads, bind_path, scope, expr, attrs, res,
				     &count, &cookie);

	if (!ADS_ERR_OK(status)) return status;

	while (cookie) {
		void *res2 = NULL;
		ADS_STATUS status2;
		LDAPMessage *msg, *next;

		status2 = ads_do_paged_search(ads, bind_path, scope, expr, 
					      attrs, &res2, &count, &cookie);

		if (!ADS_ERR_OK(status2)) break;

		/* this relies on the way that ldap_add_result_entry() works internally. I hope
		   that this works on all ldap libs, but I have only tested with openldap */
		for (msg = ads_first_entry(ads, res2); msg; msg = next) {
			next = ads_next_entry(ads, msg);
			ldap_add_result_entry((LDAPMessage **)res, msg);
		}
		/* note that we do not free res2, as the memory is now
                   part of the main returned list */
	}

	return status;
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
				BOOL(*fn)(char *, void **, void *), 
				void *data_area)
{
	void *cookie = NULL;
	int count = 0;
	ADS_STATUS status;
	void *res;

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
			 const char **attrs, void **res)
{
	struct timeval timeout;
	int rc;
	char *utf8_expr, *utf8_path, **search_attrs = NULL;
	TALLOC_CTX *ctx;

	if (!(ctx = talloc_init("ads_do_search"))) {
		DEBUG(1,("ads_do_search: talloc_init() failed!"));
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	/* 0 means the conversion worked but the result was empty 
	   so we only fail if it's negative.  In any case, it always 
	   at least nulls out the dest */
	if ((push_utf8_talloc(ctx, &utf8_expr, expr) == (size_t)-1) ||
	    (push_utf8_talloc(ctx, &utf8_path, bind_path) == (size_t)-1)) {
		DEBUG(1,("ads_do_search: push_utf8_talloc() failed!"));
		rc = LDAP_NO_MEMORY;
		goto done;
	}

	if (!attrs || !(*attrs))
		search_attrs = NULL;
	else {
		/* This would be the utf8-encoded version...*/
		/* if (!(search_attrs = ads_push_strvals(ctx, attrs)))  */
		if (!(str_list_copy(&search_attrs, attrs)))
		{
			DEBUG(1,("ads_do_search: str_list_copy() failed!"));
			rc = LDAP_NO_MEMORY;
			goto done;
		}
	}

	timeout.tv_sec = ADS_SEARCH_TIMEOUT;
	timeout.tv_usec = 0;
	*res = NULL;

	/* see the note in ads_do_paged_search - we *must* disable referrals */
	ldap_set_option(ads->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

	rc = ldap_search_ext_s(ads->ld, utf8_path, scope, utf8_expr,
			       search_attrs, 0, NULL, NULL, 
			       &timeout, LDAP_NO_LIMIT, (LDAPMessage **)res);

	if (rc == LDAP_SIZELIMIT_EXCEEDED) {
		DEBUG(3,("Warning! sizelimit exceeded in ldap. Truncating.\n"));
		rc = 0;
	}

 done:
	talloc_destroy(ctx);
	/* if/when we decide to utf8-encode attrs, take out this next line */
	str_list_free(&search_attrs);
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
ADS_STATUS ads_search(ADS_STRUCT *ads, void **res, 
		      const char *expr, 
		      const char **attrs)
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
ADS_STATUS ads_search_dn(ADS_STRUCT *ads, void **res, 
			 const char *dn, 
			 const char **attrs)
{
	return ads_do_search(ads, dn, LDAP_SCOPE_BASE, "(objectclass=*)", attrs, res);
}

/**
 * Free up memory from a ads_search
 * @param ads connection to ads server
 * @param msg Search results to free
 **/
void ads_msgfree(ADS_STRUCT *ads, void *msg)
{
	if (!msg) return;
	ldap_msgfree(msg);
}

/**
 * Free up memory from various ads requests
 * @param ads connection to ads server
 * @param mem Area to free
 **/
void ads_memfree(ADS_STRUCT *ads, void *mem)
{
	SAFE_FREE(mem);
}

/**
 * Get a dn from search results
 * @param ads connection to ads server
 * @param msg Search result
 * @return dn string
 **/
char *ads_get_dn(ADS_STRUCT *ads, void *msg)
{
	char *utf8_dn, *unix_dn;

	utf8_dn = ldap_get_dn(ads->ld, msg);

	if (!utf8_dn) {
		DEBUG (5, ("ads_get_dn: ldap_get_dn failed\n"));
		return NULL;
	}

	if (pull_utf8_allocate(&unix_dn, utf8_dn) == (size_t)-1) {
		DEBUG(0,("ads_get_dn: string conversion failure utf8 [%s]\n",
			utf8_dn ));
		return NULL;
	}
	ldap_memfree(utf8_dn);
	return unix_dn;
}

/**
 * Find a machine account given a hostname
 * @param ads connection to ads server
 * @param res ** which will contain results - free res* with ads_msgfree()
 * @param host Hostname to search for
 * @return status of search
 **/
ADS_STATUS ads_find_machine_acct(ADS_STRUCT *ads, void **res, const char *host)
{
	ADS_STATUS status;
	char *expr;
	const char *attrs[] = {"*", "nTSecurityDescriptor", NULL};

	/* the easiest way to find a machine account anywhere in the tree
	   is to look for hostname$ */
	if (asprintf(&expr, "(samAccountName=%s$)", host) == -1) {
		DEBUG(1, ("asprintf failed!\n"));
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}
	
	status = ads_search(ads, res, expr, attrs);
	free(expr);
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
	
	if ((mods = (LDAPMod **) talloc_zero(ctx, sizeof(LDAPMod *) * 
					     (ADS_MODLIST_ALLOC_SIZE + 1))))
		/* -1 is safety to make sure we don't go over the end.
		   need to reset it to NULL before doing ldap modify */
		mods[ADS_MODLIST_ALLOC_SIZE] = (LDAPMod *) -1;
	
	return mods;
}


/*
  add an attribute to the list, with values list already constructed
*/
static ADS_STATUS ads_modlist_add(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
				  int mod_op, const char *name, 
				  const void **invals)
{
	int curmod;
	LDAPMod **modlist = (LDAPMod **) *mods;
	struct berval **ber_values = NULL;
	char **char_values = NULL;

	if (!invals) {
		mod_op = LDAP_MOD_DELETE;
	} else {
		if (mod_op & LDAP_MOD_BVALUES)
			ber_values = ads_dup_values(ctx, 
						(const struct berval **)invals);
		else
			char_values = ads_push_strvals(ctx, 
						  (const char **) invals);
	}

	/* find the first empty slot */
	for (curmod=0; modlist[curmod] && modlist[curmod] != (LDAPMod *) -1;
	     curmod++);
	if (modlist[curmod] == (LDAPMod *) -1) {
		if (!(modlist = talloc_realloc(ctx, modlist, 
			(curmod+ADS_MODLIST_ALLOC_SIZE+1)*sizeof(LDAPMod *))))
			return ADS_ERROR(LDAP_NO_MEMORY);
		memset(&modlist[curmod], 0, 
		       ADS_MODLIST_ALLOC_SIZE*sizeof(LDAPMod *));
		modlist[curmod+ADS_MODLIST_ALLOC_SIZE] = (LDAPMod *) -1;
		*mods = modlist;
	}
		
	if (!(modlist[curmod] = talloc_zero(ctx, sizeof(LDAPMod))))
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
	return ads_modlist_add(ctx, mods, LDAP_MOD_REPLACE, name, 
			       (const void **) values);
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
	/* 
	   this control is needed to modify that contains a currently 
	   non-existent attribute (but allowable for the object) to run
	*/
	LDAPControl PermitModify = {
		ADS_PERMIT_MODIFY_OID,
		{0, NULL},
		(char) 1};
	LDAPControl *controls[2];

	controls[0] = &PermitModify;
	controls[1] = NULL;

	if (push_utf8_allocate(&utf8_dn, mod_dn) == -1) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	/* find the end of the list, marked by NULL or -1 */
	for(i=0;(mods[i]!=0)&&(mods[i]!=(LDAPMod *) -1);i++);
	/* make sure the end of the list is NULL */
	mods[i] = NULL;
	ret = ldap_modify_ext_s(ads->ld, utf8_dn,
				(LDAPMod **) mods, controls, NULL);
	SAFE_FREE(utf8_dn);
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

	if (push_utf8_allocate(&utf8_dn, new_dn) == -1) {
		DEBUG(1, ("ads_gen_add: push_utf8_allocate failed!"));
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}
	
	/* find the end of the list, marked by NULL or -1 */
	for(i=0;(mods[i]!=0)&&(mods[i]!=(LDAPMod *) -1);i++);
	/* make sure the end of the list is NULL */
	mods[i] = NULL;

	ret = ldap_add_s(ads->ld, utf8_dn, mods);
	SAFE_FREE(utf8_dn);
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
	if (push_utf8_allocate(&utf8_dn, del_dn) == -1) {
		DEBUG(1, ("ads_del_dn: push_utf8_allocate failed!"));
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}
	
	ret = ldap_delete_s(ads->ld, utf8_dn);
	return ADS_ERROR(ret);
}

/**
 * Build an org unit string
 *  if org unit is Computers or blank then assume a container, otherwise
 *  assume a \ separated list of organisational units
 * @param org_unit Organizational unit
 * @return org unit string - caller must free
 **/
char *ads_ou_string(const char *org_unit)
{	
	if (!org_unit || !*org_unit || strequal(org_unit, "Computers")) {
		return strdup("cn=Computers");
	}

	return ads_build_path(org_unit, "\\/", "ou=", 1);
}



/*
  add a machine account to the ADS server
*/
static ADS_STATUS ads_add_machine_acct(ADS_STRUCT *ads, const char *hostname, 
				       uint32 account_type,
				       const char *org_unit)
{
	ADS_STATUS ret, status;
	char *host_spn, *host_upn, *new_dn, *samAccountName, *controlstr;
	char *ou_str;
	TALLOC_CTX *ctx;
	ADS_MODLIST mods;
	const char *objectClass[] = {"top", "person", "organizationalPerson",
				     "user", "computer", NULL};
	const char *servicePrincipalName[5] = {NULL, NULL, NULL, NULL, NULL};
	char *psp, *psp2;
	unsigned acct_control;
	unsigned exists=0;
	LDAPMessage *res;

	status = ads_find_machine_acct(ads, (void **)&res, hostname);
	if (ADS_ERR_OK(status) && ads_count_replies(ads, res) == 1) {
		DEBUG(0, ("Host account for %s already exists - modifying old account\n", hostname));
		exists=1;
	}

	if (!(ctx = talloc_init("machine_account")))
		return ADS_ERROR(LDAP_NO_MEMORY);

	ret = ADS_ERROR(LDAP_NO_MEMORY);

	if (!(host_spn = talloc_asprintf(ctx, "HOST/%s", hostname)))
		goto done;
	if (!(host_upn = talloc_asprintf(ctx, "%s@%s", host_spn, ads->config.realm)))
		goto done;
	ou_str = ads_ou_string(org_unit);
	if (!ou_str) {
		DEBUG(1, ("ads_ou_string returned NULL (malloc failure?)\n"));
		goto done;
	}
	new_dn = talloc_asprintf(ctx, "cn=%s,%s,%s", hostname, ou_str, 
				 ads->config.bind_path);
	servicePrincipalName[0] = talloc_asprintf(ctx, "HOST/%s", hostname);
	psp = talloc_asprintf(ctx, "HOST/%s.%s", 
			      hostname, 
			      ads->config.realm);
	strlower_m(&psp[5]);
	servicePrincipalName[1] = psp;
	servicePrincipalName[2] = talloc_asprintf(ctx, "CIFS/%s", hostname);
	psp2 = talloc_asprintf(ctx, "CIFS/%s.%s", 
			       hostname, 
			       ads->config.realm);
	strlower_m(&psp2[5]);
	servicePrincipalName[3] = psp2;

	free(ou_str);
	if (!new_dn)
		goto done;

	if (!(samAccountName = talloc_asprintf(ctx, "%s$", hostname)))
		goto done;

	acct_control = account_type | UF_DONT_EXPIRE_PASSWD;
#ifndef ENCTYPE_ARCFOUR_HMAC
	acct_control |= UF_USE_DES_KEY_ONLY;
#endif

	if (!(controlstr = talloc_asprintf(ctx, "%u", acct_control)))
		goto done;

	if (!(mods = ads_init_mods(ctx)))
		goto done;

	if (!exists) {
		ads_mod_str(ctx, &mods, "cn", hostname);
		ads_mod_str(ctx, &mods, "sAMAccountName", samAccountName);
		ads_mod_str(ctx, &mods, "userAccountControl", controlstr);
		ads_mod_strlist(ctx, &mods, "objectClass", objectClass);
	}
	ads_mod_str(ctx, &mods, "dNSHostName", hostname);
	ads_mod_str(ctx, &mods, "userPrincipalName", host_upn);
	ads_mod_strlist(ctx, &mods, "servicePrincipalName", servicePrincipalName);
	ads_mod_str(ctx, &mods, "operatingSystem", "Samba");
	ads_mod_str(ctx, &mods, "operatingSystemVersion", SAMBA_VERSION_STRING);

	if (!exists) 
		ret = ads_gen_add(ads, new_dn, mods);
	else
		ret = ads_gen_mod(ads, new_dn, mods);

	if (!ADS_ERR_OK(ret))
		goto done;

	/* Do not fail if we can't set security descriptor
	 * it shouldn't be mandatory and probably we just 
	 * don't have enough rights to do it.
	 */
	if (!exists) {
		status = ads_set_machine_sd(ads, hostname, new_dn);
	
		if (!ADS_ERR_OK(status)) {
			DEBUG(0, ("Warning: ads_set_machine_sd: %s\n",
					ads_errstr(status)));
		}
	}
done:
	talloc_destroy(ctx);
	return ret;
}

/*
  dump a binary result from ldap
*/
static void dump_binary(const char *field, struct berval **values)
{
	int i, j;
	for (i=0; values[i]; i++) {
		printf("%s: ", field);
		for (j=0; j<values[i]->bv_len; j++) {
			printf("%02X", (unsigned char)values[i]->bv_val[j]);
		}
		printf("\n");
	}
}

static void dump_guid(const char *field, struct berval **values)
{
	int i;
	UUID_FLAT guid;
	for (i=0; values[i]; i++) {
		memcpy(guid.info, values[i]->bv_val, sizeof(guid.info));
		printf("%s: %s\n", field, 
		       smb_uuid_string_static(smb_uuid_unpack_static(guid)));
	}
}

/*
  dump a sid result from ldap
*/
static void dump_sid(const char *field, struct berval **values)
{
	int i;
	for (i=0; values[i]; i++) {
		DOM_SID sid;
		sid_parse(values[i]->bv_val, values[i]->bv_len, &sid);
		printf("%s: %s\n", field, sid_string_static(&sid));
	}
}

/*
  dump ntSecurityDescriptor
*/
static void dump_sd(const char *filed, struct berval **values)
{
	prs_struct ps;
	
	SEC_DESC   *psd = 0;
	TALLOC_CTX *ctx = 0;

	if (!(ctx = talloc_init("sec_io_desc")))
		return;

	/* prepare data */
	prs_init(&ps, values[0]->bv_len, ctx, UNMARSHALL);
	prs_copy_data_in(&ps, values[0]->bv_val, values[0]->bv_len);
	prs_set_offset(&ps,0);

	/* parse secdesc */
	if (!sec_io_desc("sd", &psd, &ps, 1)) {
		prs_mem_free(&ps);
		talloc_destroy(ctx);
		return;
	}
	if (psd) ads_disp_sd(psd);

	prs_mem_free(&ps);
	talloc_destroy(ctx);
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

static BOOL ads_dump_field(char *field, void **values, void *data_area)
{
	const struct {
		const char *name;
		BOOL string;
		void (*handler)(const char *, struct berval **);
	} handlers[] = {
		{"objectGUID", False, dump_guid},
		{"nTSecurityDescriptor", False, dump_sd},
		{"dnsRecord", False, dump_binary},
		{"objectSid", False, dump_sid},
		{"tokenGroups", False, dump_sid},
		{NULL, True, NULL}
	};
	int i;

	if (!field) { /* must be end of an entry */
		printf("\n");
		return False;
	}

	for (i=0; handlers[i].name; i++) {
		if (StrCaseCmp(handlers[i].name, field) == 0) {
			if (!values) /* first time, indicate string or not */
				return handlers[i].string;
			handlers[i].handler(field, (struct berval **) values);
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

void ads_dump(ADS_STRUCT *ads, void *res)
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
void ads_process_results(ADS_STRUCT *ads, void *res,
			 BOOL(*fn)(char *, void **, void *),
			 void *data_area)
{
	void *msg;
	TALLOC_CTX *ctx;

	if (!(ctx = talloc_init("ads_process_results")))
		return;

	for (msg = ads_first_entry(ads, res); msg; 
	     msg = ads_next_entry(ads, msg)) {
		char *utf8_field;
		BerElement *b;
	
		for (utf8_field=ldap_first_attribute(ads->ld,
						     (LDAPMessage *)msg,&b); 
		     utf8_field;
		     utf8_field=ldap_next_attribute(ads->ld,
						    (LDAPMessage *)msg,b)) {
			struct berval **ber_vals;
			char **str_vals, **utf8_vals;
			char *field;
			BOOL string; 

			pull_utf8_talloc(ctx, &field, utf8_field);
			string = fn(field, NULL, data_area);

			if (string) {
				utf8_vals = ldap_get_values(ads->ld,
					       	 (LDAPMessage *)msg, field);
				str_vals = ads_pull_strvals(ctx, 
						  (const char **) utf8_vals);
				fn(field, (void **) str_vals, data_area);
				ldap_value_free(utf8_vals);
			} else {
				ber_vals = ldap_get_values_len(ads->ld, 
						 (LDAPMessage *)msg, field);
				fn(field, (void **) ber_vals, data_area);

				ldap_value_free_len(ber_vals);
			}
			ldap_memfree(utf8_field);
		}
		ber_free(b, 0);
		talloc_destroy_pool(ctx);
		fn(NULL, NULL, data_area); /* completed an entry */

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
	return ldap_count_entries(ads->ld, (LDAPMessage *)res);
}

/**
 * Join a machine to a realm
 *  Creates the machine account and sets the machine password
 * @param ads connection to ads server
 * @param hostname name of host to add
 * @param org_unit Organizational unit to place machine in
 * @return status of join
 **/
ADS_STATUS ads_join_realm(ADS_STRUCT *ads, const char *hostname, 
			  uint32 account_type, const char *org_unit)
{
	ADS_STATUS status;
	LDAPMessage *res;
	char *host;

	/* hostname must be lowercase */
	host = strdup(hostname);
	strlower_m(host);

	/*
	status = ads_find_machine_acct(ads, (void **)&res, host);
	if (ADS_ERR_OK(status) && ads_count_replies(ads, res) == 1) {
		DEBUG(0, ("Host account for %s already exists - deleting old account\n", host));
		status = ads_leave_realm(ads, host);
		if (!ADS_ERR_OK(status)) {
			DEBUG(0, ("Failed to delete host '%s' from the '%s' realm.\n", 
				  host, ads->config.realm));
			return status;
		}
	}
	*/

	status = ads_add_machine_acct(ads, host, account_type, org_unit);
	if (!ADS_ERR_OK(status)) {
		DEBUG(0, ("ads_add_machine_acct: %s\n", ads_errstr(status)));
		return status;
	}

	status = ads_find_machine_acct(ads, (void **)&res, host);
	if (!ADS_ERR_OK(status)) {
		DEBUG(0, ("Host account test failed\n"));
		return status;
	}

	free(host);

	return status;
}

/**
 * Delete a machine from the realm
 * @param ads connection to ads server
 * @param hostname Machine to remove
 * @return status of delete
 **/
ADS_STATUS ads_leave_realm(ADS_STRUCT *ads, const char *hostname)
{
	ADS_STATUS status;
	void *res, *msg;
	char *hostnameDN, *host; 
	int rc;

	/* hostname must be lowercase */
	host = strdup(hostname);
	strlower_m(host);

	status = ads_find_machine_acct(ads, &res, host);
	if (!ADS_ERR_OK(status)) {
	    DEBUG(0, ("Host account for %s does not exist.\n", host));
	    return status;
	}

	msg = ads_first_entry(ads, res);
	if (!msg) {
		return ADS_ERROR_SYSTEM(ENOENT);
	}

	hostnameDN = ads_get_dn(ads, (LDAPMessage *)msg);
	rc = ldap_delete_s(ads->ld, hostnameDN);
	ads_memfree(ads, hostnameDN);
	if (rc != LDAP_SUCCESS) {
		return ADS_ERROR(rc);
	}

	status = ads_find_machine_acct(ads, &res, host);
	if (ADS_ERR_OK(status) && ads_count_replies(ads, res) == 1) {
		DEBUG(0, ("Failed to remove host account.\n"));
		return status;
	}

	free(host);

	return status;
}

/**
 * add machine account to existing security descriptor 
 * @param ads connection to ads server
 * @param hostname machine to add
 * @param dn DN of security descriptor
 * @return status
 **/
ADS_STATUS ads_set_machine_sd(ADS_STRUCT *ads, const char *hostname, char *dn)
{
	const char     *attrs[] = {"nTSecurityDescriptor", "objectSid", 0};
	char           *expr     = 0;
	size_t          sd_size = 0;
	struct berval   bval = {0, NULL};
	prs_struct      ps_wire;
	char           *escaped_hostname = escape_ldap_string_alloc(hostname);

	LDAPMessage *res  = 0;
	LDAPMessage *msg  = 0;
	ADS_MODLIST  mods = 0;

	NTSTATUS    status;
	ADS_STATUS  ret;
	DOM_SID     sid;
	SEC_DESC   *psd = NULL;
	TALLOC_CTX *ctx = NULL;	

	/* Avoid segmentation fault in prs_mem_free if
	 * we have to bail out before prs_init */
	ps_wire.is_dynamic = False;

	if (!ads) return ADS_ERROR(LDAP_SERVER_DOWN);

	ret = ADS_ERROR(LDAP_SUCCESS);

	if (!escaped_hostname) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	if (asprintf(&expr, "(samAccountName=%s$)", escaped_hostname) == -1) {
		DEBUG(1, ("ads_set_machine_sd: asprintf failed!\n"));
		SAFE_FREE(escaped_hostname);
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	SAFE_FREE(escaped_hostname);

	ret = ads_search(ads, (void *) &res, expr, attrs);

	if (!ADS_ERR_OK(ret)) return ret;

	if ( !(msg = ads_first_entry(ads, res) )) {
		ret = ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
		goto ads_set_sd_error;
	}

	if (!ads_pull_sid(ads, msg, attrs[1], &sid)) {
		ret = ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		goto ads_set_sd_error;
	}

	if (!(ctx = talloc_init("sec_io_desc"))) {
		ret =  ADS_ERROR(LDAP_NO_MEMORY);
		goto ads_set_sd_error;
	}

	if (!ads_pull_sd(ads, ctx, msg, attrs[0], &psd)) {
		ret = ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		goto ads_set_sd_error;
	}

	status = sec_desc_add_sid(ctx, &psd, &sid, SEC_RIGHTS_FULL_CTRL, &sd_size);

	if (!NT_STATUS_IS_OK(status)) {
		ret = ADS_ERROR_NT(status);
		goto ads_set_sd_error;
	}

	if (!prs_init(&ps_wire, sd_size, ctx, MARSHALL)) {
		ret = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	if (!sec_io_desc("sd_wire", &psd, &ps_wire, 1)) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto ads_set_sd_error;
	}

#if 0
	file_save("/tmp/sec_desc.new", ps_wire.data_p, sd_size);
#endif
	if (!(mods = ads_init_mods(ctx))) return ADS_ERROR(LDAP_NO_MEMORY);

	bval.bv_len = prs_offset(&ps_wire);
	bval.bv_val = talloc(ctx, bval.bv_len);
	if (!bval.bv_val) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto ads_set_sd_error;
	}

	prs_set_offset(&ps_wire, 0);

	if (!prs_copy_data_out(bval.bv_val, &ps_wire, bval.bv_len)) {
		ret = ADS_ERROR(LDAP_NO_MEMORY);
		goto ads_set_sd_error;		
	}

	ret = ads_mod_ber(ctx, &mods, attrs[0], &bval);
	if (ADS_ERR_OK(ret)) {
		ret = ads_gen_mod(ads, dn, mods);
	}

ads_set_sd_error:
	ads_msgfree(ads, res);
	prs_mem_free(&ps_wire);
	talloc_destroy(ctx);
	return ret;
}

/**
 * pull the first entry from a ADS result
 * @param ads connection to ads server
 * @param res Results of search
 * @return first entry from result
 **/
void *ads_first_entry(ADS_STRUCT *ads, void *res)
{
	return (void *)ldap_first_entry(ads->ld, (LDAPMessage *)res);
}

/**
 * pull the next entry from a ADS result
 * @param ads connection to ads server
 * @param res Results of search
 * @return next entry from result
 **/
void *ads_next_entry(ADS_STRUCT *ads, void *res)
{
	return (void *)ldap_next_entry(ads->ld, (LDAPMessage *)res);
}

/**
 * pull a single string from a ADS result
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX to use for allocating result string
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @return Result string in talloc context
 **/
char *ads_pull_string(ADS_STRUCT *ads, 
		      TALLOC_CTX *mem_ctx, void *msg, const char *field)
{
	char **values;
	char *ret = NULL;
	char *ux_string;
	size_t rc;

	values = ldap_get_values(ads->ld, msg, field);
	if (!values)
		return NULL;
	
	if (values[0]) {
		rc = pull_utf8_talloc(mem_ctx, &ux_string, 
				      values[0]);
		if (rc != (size_t)-1)
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
char **ads_pull_strings(ADS_STRUCT *ads, 
			TALLOC_CTX *mem_ctx, void *msg, const char *field,
			size_t *num_values)
{
	char **values;
	char **ret = NULL;
	int i;

	values = ldap_get_values(ads->ld, msg, field);
	if (!values)
		return NULL;

	*num_values = ldap_count_values(values);

	ret = talloc(mem_ctx, sizeof(char *) * (*num_values+1));
	if (!ret) {
		ldap_value_free(values);
		return NULL;
	}

	for (i=0;i<*num_values;i++) {
		if (pull_utf8_talloc(mem_ctx, &ret[i], values[i]) == -1) {
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
			      void *msg, const char *field,
			      char **current_strings,
			      const char **next_attribute,
			      size_t *num_strings,
			      BOOL *more_strings)
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
	for (attr = ldap_first_attribute(ads->ld, (LDAPMessage *)msg, &ptr); 
	     attr; 
	     attr = ldap_next_attribute(ads->ld, (LDAPMessage *)msg, ptr)) {
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
			  range_attr, *num_strings + 1, range_start));
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

	strings = talloc_realloc(mem_ctx, current_strings,
				 sizeof(*current_strings) *
				 (*num_strings + num_new_strings));
	
	if (strings == NULL) {
		ldap_memfree(range_attr);
		*more_strings = False;
		return NULL;
	}
	
	memcpy(&strings[*num_strings], new_strings,
	       sizeof(*new_strings) * num_new_strings);

	(*num_strings) += num_new_strings;

	if (*more_strings) {
		*next_attribute = talloc_asprintf(mem_ctx,
						  "%s;range=%d-*", 
						  field,
						  *num_strings);
		
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
 * pull a single uint32 from a ADS result
 * @param ads connection to ads server
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @param v Pointer to int to store result
 * @return boolean inidicating success
*/
BOOL ads_pull_uint32(ADS_STRUCT *ads, 
		     void *msg, const char *field, uint32 *v)
{
	char **values;

	values = ldap_get_values(ads->ld, msg, field);
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
BOOL ads_pull_guid(ADS_STRUCT *ads,
		   void *msg, struct uuid *guid)
{
	char **values;
	UUID_FLAT flat_guid;

	values = ldap_get_values(ads->ld, msg, "objectGUID");
	if (!values)
		return False;
	
	if (values[0]) {
		memcpy(&flat_guid.info, values[0], sizeof(UUID_FLAT));
		smb_uuid_unpack(flat_guid, guid);
		ldap_value_free(values);
		return True;
	}
	ldap_value_free(values);
	return False;

}


/**
 * pull a single DOM_SID from a ADS result
 * @param ads connection to ads server
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @param sid Pointer to sid to store result
 * @return boolean inidicating success
*/
BOOL ads_pull_sid(ADS_STRUCT *ads, 
		  void *msg, const char *field, DOM_SID *sid)
{
	struct berval **values;
	BOOL ret = False;

	values = ldap_get_values_len(ads->ld, msg, field);

	if (!values)
		return False;

	if (values[0])
		ret = sid_parse(values[0]->bv_val, values[0]->bv_len, sid);
	
	ldap_value_free_len(values);
	return ret;
}

/**
 * pull an array of DOM_SIDs from a ADS result
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX for allocating sid array
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @param sids pointer to sid array to allocate
 * @return the count of SIDs pulled
 **/
int ads_pull_sids(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
		  void *msg, const char *field, DOM_SID **sids)
{
	struct berval **values;
	BOOL ret;
	int count, i;

	values = ldap_get_values_len(ads->ld, msg, field);

	if (!values)
		return 0;

	for (i=0; values[i]; i++)
		/* nop */ ;

	(*sids) = talloc(mem_ctx, sizeof(DOM_SID) * i);
	if (!(*sids)) {
		ldap_value_free_len(values);
		return 0;
	}

	count = 0;
	for (i=0; values[i]; i++) {
		ret = sid_parse(values[i]->bv_val, values[i]->bv_len, &(*sids)[count]);
		if (ret) {
			fstring sid;
			DEBUG(10, ("pulling SID: %s\n", sid_to_string(sid, &(*sids)[count])));
			count++;
		}
	}
	
	ldap_value_free_len(values);
	return count;
}

/**
 * pull a SEC_DESC from a ADS result
 * @param ads connection to ads server
 * @param mem_ctx TALLOC_CTX for allocating sid array
 * @param msg Results of search
 * @param field Attribute to retrieve
 * @param sd Pointer to *SEC_DESC to store result (talloc()ed)
 * @return boolean inidicating success
*/
BOOL ads_pull_sd(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
		  void *msg, const char *field, SEC_DESC **sd)
{
	struct berval **values;
	prs_struct      ps;
	BOOL ret = False;

	values = ldap_get_values_len(ads->ld, msg, field);

	if (!values) return False;

	if (values[0]) {
		prs_init(&ps, values[0]->bv_len, mem_ctx, UNMARSHALL);
		prs_copy_data_in(&ps, values[0]->bv_val, values[0]->bv_len);
		prs_set_offset(&ps,0);

		ret = sec_io_desc("sd", sd, &ps, 1);
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
char *ads_pull_username(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, void *msg)
{
	char *ret, *p;

	ret = ads_pull_string(ads, mem_ctx, msg, "userPrincipalName");
	if (ret && (p = strchr(ret, '@'))) {
		*p = 0;
		return ret;
	}
	return ads_pull_string(ads, mem_ctx, msg, "sAMAccountName");
}


/**
 * find the update serial number - this is the core of the ldap cache
 * @param ads connection to ads server
 * @param ads connection to ADS server
 * @param usn Pointer to retrieved update serial number
 * @return status of search
 **/
ADS_STATUS ads_USN(ADS_STRUCT *ads, uint32 *usn)
{
	const char *attrs[] = {"highestCommittedUSN", NULL};
	ADS_STATUS status;
	void *res;

	status = ads_do_search_retry(ads, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) 
		return status;

	if (ads_count_replies(ads, res) != 1) {
		return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
	}

	ads_pull_uint32(ads, res, "highestCommittedUSN", usn);
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


/**
 * Find the servers name and realm - this can be done before authentication 
 *  The ldapServiceName field on w2k  looks like this:
 *    vnet3.home.samba.org:win2000-vnet3$@VNET3.HOME.SAMBA.ORG
 * @param ads connection to ads server
 * @return status of search
 **/
ADS_STATUS ads_server_info(ADS_STRUCT *ads)
{
	const char *attrs[] = {"ldapServiceName", "currentTime", NULL};
	ADS_STATUS status;
	void *res;
	char *value;
	char *p;
	char *timestr;
	TALLOC_CTX *ctx;

	if (!(ctx = talloc_init("ads_server_info"))) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	status = ads_do_search(ads, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) return status;

	value = ads_pull_string(ads, ctx, res, "ldapServiceName");
	if (!value) {
		return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
	}

	timestr = ads_pull_string(ads, ctx, res, "currentTime");
	if (!timestr) {
		return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
	}

	ldap_msgfree(res);

	p = strchr(value, ':');
	if (!p) {
		talloc_destroy(ctx);
		DEBUG(1, ("ads_server_info: returned ldap server name did not contain a ':' "
			  "so was deemed invalid\n"));
		return ADS_ERROR(LDAP_DECODING_ERROR);
	}

	SAFE_FREE(ads->config.ldap_server_name);

	ads->config.ldap_server_name = strdup(p+1);
	p = strchr(ads->config.ldap_server_name, '$');
	if (!p || p[1] != '@') {
		talloc_destroy(ctx);
		DEBUG(1, ("ads_server_info: returned ldap server name (%s) does not contain '$@'"
			  " so was deemed invalid\n", ads->config.ldap_server_name));
		SAFE_FREE(ads->config.ldap_server_name);
		return ADS_ERROR(LDAP_DECODING_ERROR);
	}

	*p = 0;

	SAFE_FREE(ads->config.realm);
	SAFE_FREE(ads->config.bind_path);

	ads->config.realm = strdup(p+2);
	ads->config.bind_path = ads_build_dn(ads->config.realm);

	DEBUG(3,("got ldap server name %s@%s, using bind path: %s\n", 
		 ads->config.ldap_server_name, ads->config.realm,
		 ads->config.bind_path));

	ads->config.current_time = ads_parse_time(timestr);

	if (ads->config.current_time != 0) {
		ads->auth.time_offset = ads->config.current_time - time(NULL);
		DEBUG(4,("time offset is %d seconds\n", ads->auth.time_offset));
	}

	talloc_destroy(ctx);

	return ADS_SUCCESS;
}

/**
 * find the domain sid for our domain
 * @param ads connection to ads server
 * @param sid Pointer to domain sid
 * @return status of search
 **/
ADS_STATUS ads_domain_sid(ADS_STRUCT *ads, DOM_SID *sid)
{
	const char *attrs[] = {"objectSid", NULL};
	void *res;
	ADS_STATUS rc;

	rc = ads_do_search_retry(ads, ads->config.bind_path, LDAP_SCOPE_BASE, "(objectclass=*)", 
			   attrs, &res);
	if (!ADS_ERR_OK(rc)) return rc;
	if (!ads_pull_sid(ads, res, "objectSid", sid)) {
		return ADS_ERROR_SYSTEM(ENOENT);
	}
	ads_msgfree(ads, res);
	
	return ADS_SUCCESS;
}

/* this is rather complex - we need to find the allternate (netbios) name
   for the domain, but there isn't a simple query to do this. Instead
   we look for the principle names on the DCs account and find one that has 
   the right form, then extract the netbios name of the domain from that

   NOTE! better method is this:

bin/net -Uadministrator%XXXXX ads search '(&(objectclass=crossref)(dnsroot=VNET3.HOME.SAMBA.ORG))'  nETBIOSName 

but you need to force the bind path to match the configurationNamingContext from the rootDSE

*/
ADS_STATUS ads_workgroup_name(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, const char **workgroup)
{
	char *expr;
	ADS_STATUS rc;
	char **principles;
	char *prefix;
	int prefix_length;
	int i;
	void *res;
	const char *attrs[] = {"servicePrincipalName", NULL};
	int num_principals;

	(*workgroup) = NULL;

	asprintf(&expr, "(&(objectclass=computer)(dnshostname=%s.%s))", 
		 ads->config.ldap_server_name, ads->config.realm);
	rc = ads_search(ads, &res, expr, attrs);
	free(expr);

	if (!ADS_ERR_OK(rc)) {
		return rc;
	}

	principles = ads_pull_strings(ads, mem_ctx, res,
				      "servicePrincipalName", &num_principals);

	ads_msgfree(ads, res);

	if (!principles) {
		return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
	}

	asprintf(&prefix, "HOST/%s.%s/", 
		 ads->config.ldap_server_name, 
		 ads->config.realm);

	prefix_length = strlen(prefix);

	for (i=0;principles[i]; i++) {
		if (strnequal(principles[i], prefix, prefix_length) &&
		    !strequal(ads->config.realm, principles[i]+prefix_length) &&
		    !strchr(principles[i]+prefix_length, '.')) {
			/* found an alternate (short) name for the domain. */
			DEBUG(3,("Found alternate name '%s' for realm '%s'\n",
				 principles[i]+prefix_length, 
				 ads->config.realm));
			(*workgroup) = talloc_strdup(mem_ctx, principles[i]+prefix_length);
			break;
		}
	}
	free(prefix);

	if (!*workgroup) {
		return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
	}
	
	return ADS_SUCCESS;
}

#endif
