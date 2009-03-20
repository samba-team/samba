/* 
   Unix SMB/CIFS implementation.
   kerberos utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Nalin Dahyabhai <nalin@redhat.com> 2004.
   Copyright (C) Jeremy Allison 2004.
   Copyright (C) Gerald Carter 2006.

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

#ifdef HAVE_KRB5

#define DEFAULT_KRB5_PORT 88

#define LIBADS_CCACHE_NAME "MEMORY:libads"

/*
  we use a prompter to avoid a crash bug in the kerberos libs when 
  dealing with empty passwords
  this prompter is just a string copy ...
*/
static krb5_error_code 
kerb_prompter(krb5_context ctx, void *data,
	       const char *name,
	       const char *banner,
	       int num_prompts,
	       krb5_prompt prompts[])
{
	if (num_prompts == 0) return 0;

	memset(prompts[0].reply->data, '\0', prompts[0].reply->length);
	if (prompts[0].reply->length > 0) {
		if (data) {
			strncpy(prompts[0].reply->data, (const char *)data,
				prompts[0].reply->length-1);
			prompts[0].reply->length = strlen(prompts[0].reply->data);
		} else {
			prompts[0].reply->length = 0;
		}
	}
	return 0;
}

static bool smb_krb5_err_io_nstatus(TALLOC_CTX *mem_ctx, 
				    DATA_BLOB *edata_blob, 
				    KRB5_EDATA_NTSTATUS *edata)
{
	bool ret = False;
	prs_struct ps;

	if (!mem_ctx || !edata_blob || !edata) 
		return False;

	if (!prs_init(&ps, edata_blob->length, mem_ctx, UNMARSHALL))
		return False;

	if (!prs_copy_data_in(&ps, (char *)edata_blob->data, edata_blob->length))
		goto out;

	prs_set_offset(&ps, 0);

	if (!prs_ntstatus("ntstatus", &ps, 1, &edata->ntstatus))
		goto out;

	if (!prs_uint32("unknown1", &ps, 1, &edata->unknown1))
		goto out;

	if (!prs_uint32("unknown2", &ps, 1, &edata->unknown2)) /* only seen 00000001 here */
		goto out;

	ret = True;
 out:
	prs_mem_free(&ps);

	return ret;
}

 static bool smb_krb5_get_ntstatus_from_krb5_error(krb5_error *error,
						   NTSTATUS *nt_status)
{
	DATA_BLOB edata;
	DATA_BLOB unwrapped_edata;
	TALLOC_CTX *mem_ctx;
	KRB5_EDATA_NTSTATUS parsed_edata;

#ifdef HAVE_E_DATA_POINTER_IN_KRB5_ERROR
	edata = data_blob(error->e_data->data, error->e_data->length);
#else
	edata = data_blob(error->e_data.data, error->e_data.length);
#endif /* HAVE_E_DATA_POINTER_IN_KRB5_ERROR */

#ifdef DEVELOPER
	dump_data(10, edata.data, edata.length);
#endif /* DEVELOPER */

	mem_ctx = talloc_init("smb_krb5_get_ntstatus_from_krb5_error");
	if (mem_ctx == NULL) {
		data_blob_free(&edata);
		return False;
	}

	if (!unwrap_edata_ntstatus(mem_ctx, &edata, &unwrapped_edata)) {
		data_blob_free(&edata);
		TALLOC_FREE(mem_ctx);
		return False;
	}

	data_blob_free(&edata);

	if (!smb_krb5_err_io_nstatus(mem_ctx, &unwrapped_edata, &parsed_edata)) {
		data_blob_free(&unwrapped_edata);
		TALLOC_FREE(mem_ctx);
		return False;
	}

	data_blob_free(&unwrapped_edata);

	if (nt_status) {
		*nt_status = parsed_edata.ntstatus;
	}

	TALLOC_FREE(mem_ctx);

	return True;
}

 static bool smb_krb5_get_ntstatus_from_krb5_error_init_creds_opt(krb5_context ctx, 
 								  krb5_get_init_creds_opt *opt, 
								  NTSTATUS *nt_status)
{
	bool ret = False;
	krb5_error *error = NULL;

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_GET_ERROR
	ret = krb5_get_init_creds_opt_get_error(ctx, opt, &error);
	if (ret) {
		DEBUG(1,("krb5_get_init_creds_opt_get_error gave: %s\n", 
			error_message(ret)));
		return False;
	}
#endif /* HAVE_KRB5_GET_INIT_CREDS_OPT_GET_ERROR */

	if (!error) {
		DEBUG(1,("no krb5_error\n"));
		return False;
	}

#ifdef HAVE_E_DATA_POINTER_IN_KRB5_ERROR
	if (!error->e_data) {
#else
	if (error->e_data.data == NULL) {
#endif /* HAVE_E_DATA_POINTER_IN_KRB5_ERROR */
		DEBUG(1,("no edata in krb5_error\n")); 
		krb5_free_error(ctx, error);
		return False;
	}

	ret = smb_krb5_get_ntstatus_from_krb5_error(error, nt_status);

	krb5_free_error(ctx, error);

	return ret;
}

/*
  simulate a kinit, putting the tgt in the given cache location. If cache_name == NULL
  place in default cache location.
  remus@snapserver.com
*/
int kerberos_kinit_password_ext(const char *principal,
				const char *password,
				int time_offset,
				time_t *expire_time,
				time_t *renew_till_time,
				const char *cache_name,
				bool request_pac,
				bool add_netbios_addr,
				time_t renewable_time,
				NTSTATUS *ntstatus)
{
	krb5_context ctx = NULL;
	krb5_error_code code = 0;
	krb5_ccache cc = NULL;
	krb5_principal me = NULL;
	krb5_creds my_creds;
	krb5_get_init_creds_opt *opt = NULL;
	smb_krb5_addresses *addr = NULL;

	ZERO_STRUCT(my_creds);

	initialize_krb5_error_table();
	if ((code = krb5_init_context(&ctx)))
		goto out;

	if (time_offset != 0) {
		krb5_set_real_time(ctx, time(NULL) + time_offset, 0);
	}

	DEBUG(10,("kerberos_kinit_password: as %s using [%s] as ccache and config [%s]\n",
			principal,
			cache_name ? cache_name: krb5_cc_default_name(ctx),
			getenv("KRB5_CONFIG")));

	if ((code = krb5_cc_resolve(ctx, cache_name ? cache_name : krb5_cc_default_name(ctx), &cc))) {
		goto out;
	}
	
	if ((code = smb_krb5_parse_name(ctx, principal, &me))) {
		goto out;
	}

	if ((code = smb_krb5_get_init_creds_opt_alloc(ctx, &opt))) {
		goto out;
	}

	krb5_get_init_creds_opt_set_renew_life(opt, renewable_time);
	krb5_get_init_creds_opt_set_forwardable(opt, True);
#if 0
	/* insane testing */
	krb5_get_init_creds_opt_set_tkt_life(opt, 60);
#endif

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PAC_REQUEST
	if (request_pac) {
		if ((code = krb5_get_init_creds_opt_set_pac_request(ctx, opt, (krb5_boolean)request_pac))) {
			goto out;
		}
	}
#endif
	if (add_netbios_addr) {
		if ((code = smb_krb5_gen_netbios_krb5_address(&addr))) {
			goto out;
		}
		krb5_get_init_creds_opt_set_address_list(opt, addr->addrs);
	}

	if ((code = krb5_get_init_creds_password(ctx, &my_creds, me, CONST_DISCARD(char *,password), 
						 kerb_prompter, CONST_DISCARD(char *,password),
						 0, NULL, opt))) {
		goto out;
	}

	if ((code = krb5_cc_initialize(ctx, cc, me))) {
		goto out;
	}
	
	if ((code = krb5_cc_store_cred(ctx, cc, &my_creds))) {
		goto out;
	}

	if (expire_time) {
		*expire_time = (time_t) my_creds.times.endtime;
	}

	if (renew_till_time) {
		*renew_till_time = (time_t) my_creds.times.renew_till;
	}
 out:
	if (ntstatus) {

		NTSTATUS status;

		/* fast path */
		if (code == 0) {
			*ntstatus = NT_STATUS_OK;
			goto cleanup;
		}

		/* try to get ntstatus code out of krb5_error when we have it
		 * inside the krb5_get_init_creds_opt - gd */

		if (opt && smb_krb5_get_ntstatus_from_krb5_error_init_creds_opt(ctx, opt, &status)) {
			*ntstatus = status;
			goto cleanup;
		}

		/* fall back to self-made-mapping */
		*ntstatus = krb5_to_nt_status(code);
	}

 cleanup:
	krb5_free_cred_contents(ctx, &my_creds);
	if (me) {
		krb5_free_principal(ctx, me);
	}
	if (addr) {
		smb_krb5_free_addresses(ctx, addr);
	}
 	if (opt) {
		smb_krb5_get_init_creds_opt_free(ctx, opt);
	}
	if (cc) {
		krb5_cc_close(ctx, cc);
	}
	if (ctx) {
		krb5_free_context(ctx);
	}
	return code;
}



/* run kinit to setup our ccache */
int ads_kinit_password(ADS_STRUCT *ads)
{
	char *s;
	int ret;
	const char *account_name;
	fstring acct_name;

	if ( IS_DC ) {
		/* this will end up getting a ticket for DOMAIN@RUSTED.REA.LM */
		account_name = lp_workgroup();
	} else {
		/* always use the sAMAccountName for security = domain */
		/* global_myname()$@REA.LM */
		if ( lp_security() == SEC_DOMAIN ) {
			fstr_sprintf( acct_name, "%s$", global_myname() );
			account_name = acct_name;
		}
		else 
			/* This looks like host/global_myname()@REA.LM */
			account_name = ads->auth.user_name;
	}

	if (asprintf(&s, "%s@%s", account_name, ads->auth.realm) == -1) {
		return KRB5_CC_NOMEM;
	}

	if (!ads->auth.password) {
		SAFE_FREE(s);
		return KRB5_LIBOS_CANTREADPWD;
	}
	
	ret = kerberos_kinit_password_ext(s, ads->auth.password, ads->auth.time_offset,
			&ads->auth.tgt_expire, NULL, NULL, False, False, ads->auth.renewable, 
			NULL);

	if (ret) {
		DEBUG(0,("kerberos_kinit_password %s failed: %s\n", 
			 s, error_message(ret)));
	}
	SAFE_FREE(s);
	return ret;
}

int ads_kdestroy(const char *cc_name)
{
	krb5_error_code code;
	krb5_context ctx = NULL;
	krb5_ccache cc = NULL;

	initialize_krb5_error_table();
	if ((code = krb5_init_context (&ctx))) {
		DEBUG(3, ("ads_kdestroy: kdb5_init_context failed: %s\n", 
			error_message(code)));
		return code;
	}
  
	if (!cc_name) {
		if ((code = krb5_cc_default(ctx, &cc))) {
			krb5_free_context(ctx);
			return code;
		}
	} else {
		if ((code = krb5_cc_resolve(ctx, cc_name, &cc))) {
			DEBUG(3, ("ads_kdestroy: krb5_cc_resolve failed: %s\n",
				  error_message(code)));
			krb5_free_context(ctx);
			return code;
		}
	}

	if ((code = krb5_cc_destroy (ctx, cc))) {
		DEBUG(3, ("ads_kdestroy: krb5_cc_destroy failed: %s\n", 
			error_message(code)));
	}

	krb5_free_context (ctx);
	return code;
}

/************************************************************************
 Routine to fetch the salting principal for a service.  Active
 Directory may use a non-obvious principal name to generate the salt
 when it determines the key to use for encrypting tickets for a service,
 and hopefully we detected that when we joined the domain.
 ************************************************************************/

static char *kerberos_secrets_fetch_salting_principal(const char *service, int enctype)
{
	char *key = NULL;
	char *ret = NULL;

	if (asprintf(&key, "%s/%s/enctype=%d",
		     SECRETS_SALTING_PRINCIPAL, service, enctype) == -1) {
		return NULL;
	}
	ret = (char *)secrets_fetch(key, NULL);
	SAFE_FREE(key);
	return ret;
}

/************************************************************************
 Return the standard DES salt key
************************************************************************/

char* kerberos_standard_des_salt( void )
{
	fstring salt;

	fstr_sprintf( salt, "host/%s.%s@", global_myname(), lp_realm() );
	strlower_m( salt );
	fstrcat( salt, lp_realm() );

	return SMB_STRDUP( salt );
}

/************************************************************************
************************************************************************/

static char* des_salt_key( void )
{
	char *key;

	if (asprintf(&key, "%s/DES/%s", SECRETS_SALTING_PRINCIPAL,
		     lp_realm()) == -1) {
		return NULL;
	}

	return key;
}

/************************************************************************
************************************************************************/

bool kerberos_secrets_store_des_salt( const char* salt )
{
	char* key;
	bool ret;

	if ( (key = des_salt_key()) == NULL ) {
		DEBUG(0,("kerberos_secrets_store_des_salt: failed to generate key!\n"));
		return False;
	}

	if ( !salt ) {
		DEBUG(8,("kerberos_secrets_store_des_salt: deleting salt\n"));
		secrets_delete( key );
		return True;
	}

	DEBUG(3,("kerberos_secrets_store_des_salt: Storing salt \"%s\"\n", salt));

	ret = secrets_store( key, salt, strlen(salt)+1 );

	SAFE_FREE( key );

	return ret;
}

/************************************************************************
************************************************************************/

char* kerberos_secrets_fetch_des_salt( void )
{
	char *salt, *key;

	if ( (key = des_salt_key()) == NULL ) {
		DEBUG(0,("kerberos_secrets_fetch_des_salt: failed to generate key!\n"));
		return False;
	}

	salt = (char*)secrets_fetch( key, NULL );

	SAFE_FREE( key );

	return salt;
}

/************************************************************************
 Routine to get the default realm from the kerberos credentials cache.
 Caller must free if the return value is not NULL.
************************************************************************/

char *kerberos_get_default_realm_from_ccache( void )
{
	char *realm = NULL;
	krb5_context ctx = NULL;
	krb5_ccache cc = NULL;
	krb5_principal princ = NULL;

	initialize_krb5_error_table();
	if (krb5_init_context(&ctx)) {
		return NULL;
	}

	DEBUG(5,("kerberos_get_default_realm_from_ccache: "
		"Trying to read krb5 cache: %s\n",
		krb5_cc_default_name(ctx)));
	if (krb5_cc_default(ctx, &cc)) {
		DEBUG(0,("kerberos_get_default_realm_from_ccache: "
			"failed to read default cache\n"));
		goto out;
	}
	if (krb5_cc_get_principal(ctx, cc, &princ)) {
		DEBUG(0,("kerberos_get_default_realm_from_ccache: "
			"failed to get default principal\n"));
		goto out;
	}

#if defined(HAVE_KRB5_PRINCIPAL_GET_REALM)
	realm = SMB_STRDUP(krb5_principal_get_realm(ctx, princ));
#elif defined(HAVE_KRB5_PRINC_REALM)
	{
		krb5_data *realm_data = krb5_princ_realm(ctx, princ);
		realm = SMB_STRNDUP(realm_data->data, realm_data->length);
	}
#endif

  out:

	if (ctx) {
		if (princ) {
			krb5_free_principal(ctx, princ);
		}
		if (cc) {
			krb5_cc_close(ctx, cc);
		}
		krb5_free_context(ctx);
	}

	return realm;
}


/************************************************************************
 Routine to get the salting principal for this service.  This is 
 maintained for backwards compatibilty with releases prior to 3.0.24.
 Since we store the salting principal string only at join, we may have 
 to look for the older tdb keys.  Caller must free if return is not null.
 ************************************************************************/

krb5_principal kerberos_fetch_salt_princ_for_host_princ(krb5_context context,
							krb5_principal host_princ,
							int enctype)
{
	char *unparsed_name = NULL, *salt_princ_s = NULL;
	krb5_principal ret_princ = NULL;
	
	/* lookup new key first */

	if ( (salt_princ_s = kerberos_secrets_fetch_des_salt()) == NULL ) {
	
		/* look under the old key.  If this fails, just use the standard key */

		if (smb_krb5_unparse_name(context, host_princ, &unparsed_name) != 0) {
			return (krb5_principal)NULL;
		}
		if ((salt_princ_s = kerberos_secrets_fetch_salting_principal(unparsed_name, enctype)) == NULL) {
			/* fall back to host/machine.realm@REALM */
			salt_princ_s = kerberos_standard_des_salt();
		}
	}

	if (smb_krb5_parse_name(context, salt_princ_s, &ret_princ) != 0) {
		ret_princ = NULL;
	}
	
	SAFE_FREE(unparsed_name);
	SAFE_FREE(salt_princ_s);
	
	return ret_princ;
}

/************************************************************************
 Routine to set the salting principal for this service.  Active
 Directory may use a non-obvious principal name to generate the salt
 when it determines the key to use for encrypting tickets for a service,
 and hopefully we detected that when we joined the domain.
 Setting principal to NULL deletes this entry.
 ************************************************************************/

bool kerberos_secrets_store_salting_principal(const char *service,
					      int enctype,
					      const char *principal)
{
	char *key = NULL;
	bool ret = False;
	krb5_context context = NULL;
	krb5_principal princ = NULL;
	char *princ_s = NULL;
	char *unparsed_name = NULL;
	krb5_error_code code;

	if (((code = krb5_init_context(&context)) != 0) || (context == NULL)) {
		DEBUG(5, ("kerberos_secrets_store_salting_pricipal: kdb5_init_context failed: %s\n",
			  error_message(code)));
		return False;
	}
	if (strchr_m(service, '@')) {
		if (asprintf(&princ_s, "%s", service) == -1) {
			goto out;
		}
	} else {
		if (asprintf(&princ_s, "%s@%s", service, lp_realm()) == -1) {
			goto out;
		}
	}

	if (smb_krb5_parse_name(context, princ_s, &princ) != 0) {
		goto out;
		
	}
	if (smb_krb5_unparse_name(context, princ, &unparsed_name) != 0) {
		goto out;
	}

	if (asprintf(&key, "%s/%s/enctype=%d",
		     SECRETS_SALTING_PRINCIPAL, unparsed_name, enctype)
	    == -1) {
		goto out;
	}

	if ((principal != NULL) && (strlen(principal) > 0)) {
		ret = secrets_store(key, principal, strlen(principal) + 1);
	} else {
		ret = secrets_delete(key);
	}

 out:

	SAFE_FREE(key);
	SAFE_FREE(princ_s);
	SAFE_FREE(unparsed_name);

	if (princ) {
		krb5_free_principal(context, princ);
	}

	if (context) {
		krb5_free_context(context);
	}

	return ret;
}


/************************************************************************
************************************************************************/

int kerberos_kinit_password(const char *principal,
			    const char *password,
			    int time_offset,
			    const char *cache_name)
{
	return kerberos_kinit_password_ext(principal, 
					   password, 
					   time_offset, 
					   0, 
					   0,
					   cache_name,
					   False,
					   False,
					   0,
					   NULL);
}

/************************************************************************
************************************************************************/

static char *print_kdc_line(char *mem_ctx,
			const char *prev_line,
			const struct sockaddr_storage *pss)
{
	char *kdc_str = NULL;

	if (pss->ss_family == AF_INET) {
		kdc_str = talloc_asprintf(mem_ctx, "%s\tkdc = %s\n",
					prev_line,
                                        print_canonical_sockaddr(mem_ctx, pss));
	} else {
		char addr[INET6_ADDRSTRLEN];
		uint16_t port = get_sockaddr_port(pss);

		if (port != 0 && port != DEFAULT_KRB5_PORT) {
			/* Currently for IPv6 we can't specify a non-default
			   krb5 port with an address, as this requires a ':'.
			   Resolve to a name. */
			char hostname[MAX_DNS_NAME_LENGTH];
			int ret = sys_getnameinfo((const struct sockaddr *)pss,
					sizeof(*pss),
					hostname, sizeof(hostname),
					NULL, 0,
					NI_NAMEREQD);
			if (ret) {
				DEBUG(0,("print_kdc_line: can't resolve name "
					"for kdc with non-default port %s. "
					"Error %s\n.",
					print_canonical_sockaddr(mem_ctx, pss),
					gai_strerror(ret)));
			}
			/* Success, use host:port */
			kdc_str = talloc_asprintf(mem_ctx,
					"%s\tkdc = %s:%u\n",
					prev_line,
					hostname,
					(unsigned int)port);
		} else {
			kdc_str = talloc_asprintf(mem_ctx, "%s\tkdc = %s\n",
					prev_line,
					print_sockaddr(addr,
						sizeof(addr),
						pss));
		}
	}
	return kdc_str;
}

/************************************************************************
 Create a string list of available kdc's, possibly searching by sitename.
 Does DNS queries.
************************************************************************/

static char *get_kdc_ip_string(char *mem_ctx,
		const char *realm,
		const char *sitename,
		struct sockaddr_storage *pss)
{
	int i;
	struct ip_service *ip_srv_site = NULL;
	struct ip_service *ip_srv_nonsite = NULL;
	int count_site = 0;
	int count_nonsite;
	char *kdc_str = print_kdc_line(mem_ctx, "", pss);

	if (kdc_str == NULL) {
		return NULL;
	}

	/* Get the KDC's only in this site. */

	if (sitename) {

		get_kdc_list(realm, sitename, &ip_srv_site, &count_site);

		for (i = 0; i < count_site; i++) {
			if (sockaddr_equal(&ip_srv_site[i].ss, pss)) {
				continue;
			}
			/* Append to the string - inefficient
			 * but not done often. */
			kdc_str = print_kdc_line(mem_ctx,
						kdc_str,
						&ip_srv_site[i].ss);
			if (!kdc_str) {
				SAFE_FREE(ip_srv_site);
				return NULL;
			}
		}
	}

	/* Get all KDC's. */

	get_kdc_list(realm, NULL, &ip_srv_nonsite, &count_nonsite);

	for (i = 0; i < count_nonsite; i++) {
		int j;

		if (sockaddr_equal(&ip_srv_nonsite[i].ss, pss)) {
			continue;
		}

		/* Ensure this isn't an IP already seen (YUK! this is n*n....) */
		for (j = 0; j < count_site; j++) {
			if (sockaddr_equal(&ip_srv_nonsite[i].ss,
						&ip_srv_site[j].ss)) {
				break;
			}
			/* As the lists are sorted we can break early if nonsite > site. */
			if (ip_service_compare(&ip_srv_nonsite[i], &ip_srv_site[j]) > 0) {
				break;
			}
		}
		if (j != i) {
			continue;
		}

		/* Append to the string - inefficient but not done often. */
		kdc_str = print_kdc_line(mem_ctx,
				kdc_str,
				&ip_srv_nonsite[i].ss);
		if (!kdc_str) {
			SAFE_FREE(ip_srv_site);
			SAFE_FREE(ip_srv_nonsite);
			return NULL;
		}
	}


	SAFE_FREE(ip_srv_site);
	SAFE_FREE(ip_srv_nonsite);

	DEBUG(10,("get_kdc_ip_string: Returning %s\n",
		kdc_str ));

	return kdc_str;
}

/************************************************************************
 Create  a specific krb5.conf file in the private directory pointing
 at a specific kdc for a realm. Keyed off domain name. Sets
 KRB5_CONFIG environment variable to point to this file. Must be
 run as root or will fail (which is a good thing :-).
************************************************************************/

bool create_local_private_krb5_conf_for_domain(const char *realm,
						const char *domain,
						const char *sitename,
						struct sockaddr_storage *pss)
{
	char *dname = talloc_asprintf(NULL, "%s/smb_krb5", lp_lockdir());
	char *tmpname = NULL;
	char *fname = NULL;
	char *file_contents = NULL;
	char *kdc_ip_string = NULL;
	size_t flen = 0;
	ssize_t ret;
	int fd;
	char *realm_upper = NULL;

	if (!dname) {
		return False;
	}
	if ((mkdir(dname, 0755)==-1) && (errno != EEXIST)) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: "
			"failed to create directory %s. Error was %s\n",
			dname, strerror(errno) ));
		TALLOC_FREE(dname);
		return False;
	}

	tmpname = talloc_asprintf(dname, "%s/smb_tmp_krb5.XXXXXX", lp_lockdir());
	if (!tmpname) {
		TALLOC_FREE(dname);
		return False;
	}

	fname = talloc_asprintf(dname, "%s/krb5.conf.%s", dname, domain);
	if (!fname) {
		TALLOC_FREE(dname);
		return False;
	}

	DEBUG(10,("create_local_private_krb5_conf_for_domain: fname = %s, realm = %s, domain = %s\n",
		fname, realm, domain ));

	realm_upper = talloc_strdup(fname, realm);
	strupper_m(realm_upper);

	kdc_ip_string = get_kdc_ip_string(dname, realm, sitename, pss);
	if (!kdc_ip_string) {
		TALLOC_FREE(dname);
		return False;
	}

	file_contents = talloc_asprintf(fname,
					"[libdefaults]\n\tdefault_realm = %s\n"
					"\tdefault_tgs_enctypes = RC4-HMAC DES-CBC-CRC DES-CBC-MD5\n"
					"\tdefault_tkt_enctypes = RC4-HMAC DES-CBC-CRC DES-CBC-MD5\n"
					"\tpreferred_enctypes = RC4-HMAC DES-CBC-CRC DES-CBC-MD5\n\n"
					"[realms]\n\t%s = {\n"
					"\t%s\t}\n",
					realm_upper, realm_upper, kdc_ip_string);

	if (!file_contents) {
		TALLOC_FREE(dname);
		return False;
	}

	flen = strlen(file_contents);

	fd = smb_mkstemp(tmpname);
	if (fd == -1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: smb_mkstemp failed,"
			" for file %s. Errno %s\n",
			tmpname, strerror(errno) ));
		TALLOC_FREE(dname);
		return false;
	}

	if (fchmod(fd, 0644)==-1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: fchmod failed for %s."
			" Errno %s\n",
			tmpname, strerror(errno) ));
		unlink(tmpname);
		close(fd);
		TALLOC_FREE(dname);
		return False;
	}

	ret = write(fd, file_contents, flen);
	if (flen != ret) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: write failed,"
			" returned %d (should be %u). Errno %s\n",
			(int)ret, (unsigned int)flen, strerror(errno) ));
		unlink(tmpname);
		close(fd);
		TALLOC_FREE(dname);
		return False;
	}
	if (close(fd)==-1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: close failed."
			" Errno %s\n", strerror(errno) ));
		unlink(tmpname);
		TALLOC_FREE(dname);
		return False;
	}

	if (rename(tmpname, fname) == -1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: rename "
			"of %s to %s failed. Errno %s\n",
			tmpname, fname, strerror(errno) ));
		unlink(tmpname);
		TALLOC_FREE(dname);
		return False;
	}

	DEBUG(5,("create_local_private_krb5_conf_for_domain: wrote "
		"file %s with realm %s KDC list = %s\n",
		fname, realm_upper, kdc_ip_string));

	/* Set the environment variable to this file. */
	setenv("KRB5_CONFIG", fname, 1);

#if defined(OVERWRITE_SYSTEM_KRB5_CONF)

#define SYSTEM_KRB5_CONF_PATH "/etc/krb5.conf"
	/* Insanity, sheer insanity..... */

	if (strequal(realm, lp_realm())) {
		char linkpath[PATH_MAX+1];
		int lret;

		lret = readlink(SYSTEM_KRB5_CONF_PATH, linkpath, sizeof(linkpath)-1);
		if (lret != -1) {
			linkpath[lret] = '\0';
		}

		if (lret != -1 || strcmp(linkpath, fname) == 0) {
			/* Symlink already exists. */
			TALLOC_FREE(dname);
			return True;
		}

		/* Try and replace with a symlink. */
		if (symlink(fname, SYSTEM_KRB5_CONF_PATH) == -1) {
			const char *newpath = SYSTEM_KRB5_CONF_PATH ## ".saved";
			if (errno != EEXIST) {
				DEBUG(0,("create_local_private_krb5_conf_for_domain: symlink "
					"of %s to %s failed. Errno %s\n",
					fname, SYSTEM_KRB5_CONF_PATH, strerror(errno) ));
				TALLOC_FREE(dname);
				return True; /* Not a fatal error. */
			}

			/* Yes, this is a race conditon... too bad. */
			if (rename(SYSTEM_KRB5_CONF_PATH, newpath) == -1) {
				DEBUG(0,("create_local_private_krb5_conf_for_domain: rename "
					"of %s to %s failed. Errno %s\n",
					SYSTEM_KRB5_CONF_PATH, newpath,
					strerror(errno) ));
				TALLOC_FREE(dname);
				return True; /* Not a fatal error. */
			}

			if (symlink(fname, SYSTEM_KRB5_CONF_PATH) == -1) {
				DEBUG(0,("create_local_private_krb5_conf_for_domain: "
					"forced symlink of %s to /etc/krb5.conf failed. Errno %s\n",
					fname, strerror(errno) ));
				TALLOC_FREE(dname);
				return True; /* Not a fatal error. */
			}
		}
	}
#endif

	TALLOC_FREE(dname);

	return True;
}
#endif
