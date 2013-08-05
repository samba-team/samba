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
#include "system/filesys.h"
#include "smb_krb5.h"
#include "../librpc/gen_ndr/ndr_misc.h"
#include "libads/kerberos_proto.h"
#include "libads/cldap.h"
#include "secrets.h"
#include "../lib/tsocket/tsocket.h"

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
			strncpy((char *)prompts[0].reply->data, (const char *)data,
				prompts[0].reply->length-1);
			prompts[0].reply->length = strlen((const char *)prompts[0].reply->data);
		} else {
			prompts[0].reply->length = 0;
		}
	}
	return 0;
}

 static bool smb_krb5_get_ntstatus_from_krb5_error(krb5_error *error,
						   NTSTATUS *nt_status)
{
	DATA_BLOB edata;
	DATA_BLOB unwrapped_edata;
	TALLOC_CTX *mem_ctx;
	struct KRB5_EDATA_NTSTATUS parsed_edata;
	enum ndr_err_code ndr_err;

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

	ndr_err = ndr_pull_struct_blob_all(&unwrapped_edata, mem_ctx, 
		&parsed_edata, (ndr_pull_flags_fn_t)ndr_pull_KRB5_EDATA_NTSTATUS);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
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
		if ((code = smb_krb5_gen_netbios_krb5_address(&addr,
							lp_netbios_name()))) {
			goto out;
		}
		krb5_get_init_creds_opt_set_address_list(opt, addr->addrs);
	}

	if ((code = krb5_get_init_creds_password(ctx, &my_creds, me, discard_const_p(char,password), 
						 kerb_prompter, discard_const_p(char, password),
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

	fstr_sprintf( salt, "host/%s.%s@", lp_netbios_name(), lp_realm() );
	(void)strlower_m( salt );
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

static
char* kerberos_secrets_fetch_des_salt( void )
{
	char *salt, *key;

	if ( (key = des_salt_key()) == NULL ) {
		DEBUG(0,("kerberos_secrets_fetch_des_salt: failed to generate key!\n"));
		return NULL;
	}

	salt = (char*)secrets_fetch( key, NULL );

	SAFE_FREE( key );

	return salt;
}

/************************************************************************
 Routine to get the salting principal for this service.  This is 
 maintained for backwards compatibilty with releases prior to 3.0.24.
 Since we store the salting principal string only at join, we may have 
 to look for the older tdb keys.  Caller must free if return is not null.
 ************************************************************************/

static
krb5_principal kerberos_fetch_salt_princ_for_host_princ(krb5_context context,
							krb5_principal host_princ,
							int enctype)
{
	char *unparsed_name = NULL, *salt_princ_s = NULL;
	krb5_principal ret_princ = NULL;

	/* lookup new key first */

	if ( (salt_princ_s = kerberos_secrets_fetch_des_salt()) == NULL ) {

		/* look under the old key.  If this fails, just use the standard key */

		if (smb_krb5_unparse_name(talloc_tos(), context, host_princ, &unparsed_name) != 0) {
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

	TALLOC_FREE(unparsed_name);
	SAFE_FREE(salt_princ_s);

	return ret_princ;
}

int create_kerberos_key_from_string(krb5_context context,
					krb5_principal host_princ,
					krb5_data *password,
					krb5_keyblock *key,
					krb5_enctype enctype,
					bool no_salt)
{
	krb5_principal salt_princ = NULL;
	int ret;
	/*
	 * Check if we've determined that the KDC is salting keys for this
	 * principal/enctype in a non-obvious way.  If it is, try to match
	 * its behavior.
	 */
	if (no_salt) {
		KRB5_KEY_DATA(key) = (KRB5_KEY_DATA_CAST *)SMB_MALLOC(password->length);
		if (!KRB5_KEY_DATA(key)) {
			return ENOMEM;
		}
		memcpy(KRB5_KEY_DATA(key), password->data, password->length);
		KRB5_KEY_LENGTH(key) = password->length;
		KRB5_KEY_TYPE(key) = enctype;
		return 0;
	}
	salt_princ = kerberos_fetch_salt_princ_for_host_princ(context, host_princ, enctype);
	ret = create_kerberos_key_from_string_direct(context, salt_princ ? salt_princ : host_princ, password, key, enctype);
	if (salt_princ) {
		krb5_free_principal(context, salt_princ);
	}
	return ret;
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
	if (smb_krb5_unparse_name(talloc_tos(), context, princ, &unparsed_name) != 0) {
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
	TALLOC_FREE(unparsed_name);

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
			const struct sockaddr_storage *pss,
			const char *kdc_name)
{
	char addr[INET6_ADDRSTRLEN];
	uint16_t port = get_sockaddr_port(pss);

	if (pss->ss_family == AF_INET) {
		return talloc_asprintf(mem_ctx, "%s\tkdc = %s\n",
				       prev_line,
				       print_canonical_sockaddr(mem_ctx, pss));
	}

	/*
	 * IPv6 starts here
	 */

	DEBUG(10, ("print_kdc_line: IPv6 case for kdc_name: %s, port: %d\n",
		   kdc_name, port));

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
			return NULL;
		}
		/* Success, use host:port */
		return talloc_asprintf(mem_ctx,
				       "%s\tkdc = %s:%u\n",
				       prev_line,
				       hostname,
				       (unsigned int)port);
	}

	/* no krb5 lib currently supports "kdc = ipv6 address"
	 * at all, so just fill in just the kdc_name if we have
	 * it and let the krb5 lib figure out the appropriate
	 * ipv6 address - gd */

	if (kdc_name) {
		return talloc_asprintf(mem_ctx, "%s\tkdc = %s\n",
				       prev_line, kdc_name);
	}

	return talloc_asprintf(mem_ctx, "%s\tkdc = %s\n",
			       prev_line,
			       print_sockaddr(addr,
					      sizeof(addr),
					      pss));
}

/************************************************************************
 Create a string list of available kdc's, possibly searching by sitename.
 Does DNS queries.

 If "sitename" is given, the DC's in that site are listed first.

************************************************************************/

static void add_sockaddr_unique(struct sockaddr_storage *addrs, int *num_addrs,
				const struct sockaddr_storage *addr)
{
	int i;

	for (i=0; i<*num_addrs; i++) {
		if (sockaddr_equal((const struct sockaddr *)&addrs[i],
				   (const struct sockaddr *)addr)) {
			return;
		}
	}
	addrs[i] = *addr;
	*num_addrs += 1;
}

static char *get_kdc_ip_string(char *mem_ctx,
		const char *realm,
		const char *sitename,
		const struct sockaddr_storage *pss,
		const char *kdc_name)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int i;
	struct ip_service *ip_srv_site = NULL;
	struct ip_service *ip_srv_nonsite = NULL;
	int count_site = 0;
	int count_nonsite;
	int num_dcs;
	struct sockaddr_storage *dc_addrs;
	struct tsocket_address **dc_addrs2 = NULL;
	const struct tsocket_address * const *dc_addrs3 = NULL;
	char *result = NULL;
	struct netlogon_samlogon_response **responses = NULL;
	NTSTATUS status;
	char *kdc_str = print_kdc_line(mem_ctx, "", pss, kdc_name);

	if (kdc_str == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	/*
	 * First get the KDC's only in this site, the rest will be
	 * appended later
	 */

	if (sitename) {
		get_kdc_list(realm, sitename, &ip_srv_site, &count_site);
	}

	/* Get all KDC's. */

	get_kdc_list(realm, NULL, &ip_srv_nonsite, &count_nonsite);

	dc_addrs = talloc_array(talloc_tos(), struct sockaddr_storage,
				1 + count_site + count_nonsite);
	if (dc_addrs == NULL) {
		goto fail;
	}

	dc_addrs[0] = *pss;
	num_dcs = 1;

	for (i=0; i<count_site; i++) {
		add_sockaddr_unique(dc_addrs, &num_dcs, &ip_srv_site[i].ss);
	}

	for (i=0; i<count_nonsite; i++) {
		add_sockaddr_unique(dc_addrs, &num_dcs, &ip_srv_nonsite[i].ss);
	}

	dc_addrs2 = talloc_zero_array(talloc_tos(),
				      struct tsocket_address *,
				      num_dcs);
	if (dc_addrs2 == NULL) {
		goto fail;
	}

	for (i=0; i<num_dcs; i++) {
		char addr[INET6_ADDRSTRLEN];
		int ret;

		print_sockaddr(addr, sizeof(addr), &dc_addrs[i]);

		ret = tsocket_address_inet_from_strings(dc_addrs2, "ip",
							addr, LDAP_PORT,
							&dc_addrs2[i]);
		if (ret != 0) {
			status = map_nt_error_from_unix(errno);
			DEBUG(2,("Failed to create tsocket_address for %s - %s\n",
				 addr, nt_errstr(status)));
			goto fail;
		}
	}

	dc_addrs3 = (const struct tsocket_address * const *)dc_addrs2;

	status = cldap_multi_netlogon(talloc_tos(),
			dc_addrs3, num_dcs,
			realm, lp_netbios_name(),
			NETLOGON_NT_VERSION_5 | NETLOGON_NT_VERSION_5EX,
			MIN(num_dcs, 3), timeval_current_ofs(3, 0), &responses);
	TALLOC_FREE(dc_addrs2);
	dc_addrs3 = NULL;

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("get_kdc_ip_string: cldap_multi_netlogon failed: "
			  "%s\n", nt_errstr(status)));
		goto fail;
	}

	kdc_str = talloc_strdup(mem_ctx, "");
	if (kdc_str == NULL) {
		goto fail;
	}

	for (i=0; i<num_dcs; i++) {
		char *new_kdc_str;

		if (responses[i] == NULL) {
			continue;
		}

		/* Append to the string - inefficient but not done often. */
		new_kdc_str = print_kdc_line(mem_ctx, kdc_str,
					     &dc_addrs[i],
					     kdc_name);
		if (new_kdc_str == NULL) {
			goto fail;
		}
		TALLOC_FREE(kdc_str);
		kdc_str = new_kdc_str;
	}

	DEBUG(10,("get_kdc_ip_string: Returning %s\n",
		kdc_str ));

	result = kdc_str;
fail:
	SAFE_FREE(ip_srv_site);
	SAFE_FREE(ip_srv_nonsite);
	TALLOC_FREE(frame);
	return result;
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
					        const struct sockaddr_storage *pss,
						const char *kdc_name)
{
	char *dname;
	char *tmpname = NULL;
	char *fname = NULL;
	char *file_contents = NULL;
	char *kdc_ip_string = NULL;
	size_t flen = 0;
	ssize_t ret;
	int fd;
	char *realm_upper = NULL;
	bool result = false;
	char *aes_enctypes = NULL;

	if (!lp_create_krb5_conf()) {
		return false;
	}

	if (realm == NULL) {
		DEBUG(0, ("No realm has been specified! Do you really want to "
			  "join an Active Directory server?\n"));
		return false;
	}

	if (domain == NULL || pss == NULL || kdc_name == NULL) {
		return false;
	}

	dname = lock_path("smb_krb5");
	if (!dname) {
		return false;
	}
	if ((mkdir(dname, 0755)==-1) && (errno != EEXIST)) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: "
			"failed to create directory %s. Error was %s\n",
			dname, strerror(errno) ));
		goto done;
	}

	tmpname = lock_path("smb_tmp_krb5.XXXXXX");
	if (!tmpname) {
		goto done;
	}

	fname = talloc_asprintf(dname, "%s/krb5.conf.%s", dname, domain);
	if (!fname) {
		goto done;
	}

	DEBUG(10,("create_local_private_krb5_conf_for_domain: fname = %s, realm = %s, domain = %s\n",
		fname, realm, domain ));

	realm_upper = talloc_strdup(fname, realm);
	if (!strupper_m(realm_upper)) {
		goto done;
	}

	kdc_ip_string = get_kdc_ip_string(dname, realm, sitename, pss, kdc_name);
	if (!kdc_ip_string) {
		goto done;
	}

	aes_enctypes = talloc_strdup(fname, "");
	if (aes_enctypes == NULL) {
		goto done;
	}

#ifdef HAVE_ENCTYPE_AES256_CTS_HMAC_SHA1_96
	aes_enctypes = talloc_asprintf_append(aes_enctypes, "%s", "aes256-cts-hmac-sha1-96 ");
	if (aes_enctypes == NULL) {
		goto done;
	}
#endif
#ifdef HAVE_ENCTYPE_AES128_CTS_HMAC_SHA1_96
	aes_enctypes = talloc_asprintf_append(aes_enctypes, "%s", "aes128-cts-hmac-sha1-96");
	if (aes_enctypes == NULL) {
		goto done;
	}
#endif

	file_contents = talloc_asprintf(fname,
					"[libdefaults]\n\tdefault_realm = %s\n"
					"\tdefault_tgs_enctypes = %s RC4-HMAC DES-CBC-CRC DES-CBC-MD5\n"
					"\tdefault_tkt_enctypes = %s RC4-HMAC DES-CBC-CRC DES-CBC-MD5\n"
					"\tpreferred_enctypes = %s RC4-HMAC DES-CBC-CRC DES-CBC-MD5\n\n"
					"[realms]\n\t%s = {\n"
					"\t%s\t}\n",
					realm_upper, aes_enctypes, aes_enctypes, aes_enctypes,
					realm_upper, kdc_ip_string);

	if (!file_contents) {
		goto done;
	}

	flen = strlen(file_contents);

	fd = mkstemp(tmpname);
	if (fd == -1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: smb_mkstemp failed,"
			" for file %s. Errno %s\n",
			tmpname, strerror(errno) ));
		goto done;
	}

	if (fchmod(fd, 0644)==-1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: fchmod failed for %s."
			" Errno %s\n",
			tmpname, strerror(errno) ));
		unlink(tmpname);
		close(fd);
		goto done;
	}

	ret = write(fd, file_contents, flen);
	if (flen != ret) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: write failed,"
			" returned %d (should be %u). Errno %s\n",
			(int)ret, (unsigned int)flen, strerror(errno) ));
		unlink(tmpname);
		close(fd);
		goto done;
	}
	if (close(fd)==-1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: close failed."
			" Errno %s\n", strerror(errno) ));
		unlink(tmpname);
		goto done;
	}

	if (rename(tmpname, fname) == -1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: rename "
			"of %s to %s failed. Errno %s\n",
			tmpname, fname, strerror(errno) ));
		unlink(tmpname);
		goto done;
	}

	DEBUG(5,("create_local_private_krb5_conf_for_domain: wrote "
		"file %s with realm %s KDC list = %s\n",
		fname, realm_upper, kdc_ip_string));

	/* Set the environment variable to this file. */
	setenv("KRB5_CONFIG", fname, 1);

	result = true;

#if defined(OVERWRITE_SYSTEM_KRB5_CONF)

#define SYSTEM_KRB5_CONF_PATH "/etc/krb5.conf"
	/* Insanity, sheer insanity..... */

	if (strequal(realm, lp_realm())) {
		SMB_STRUCT_STAT sbuf;

		if (sys_lstat(SYSTEM_KRB5_CONF_PATH, &sbuf, false) == 0) {
			if (S_ISLNK(sbuf.st_ex_mode) && sbuf.st_ex_size) {
				int lret;
				size_t alloc_size = sbuf.st_ex_size + 1;
				char *linkpath = talloc_array(talloc_tos(), char,
						alloc_size);
				if (!linkpath) {
					goto done;
				}
				lret = readlink(SYSTEM_KRB5_CONF_PATH, linkpath,
						alloc_size - 1);
				if (lret == -1) {
					TALLOC_FREE(linkpath);
					goto done;
				}
				linkpath[lret] = '\0';

				if (strcmp(linkpath, fname) == 0) {
					/* Symlink already exists. */
					TALLOC_FREE(linkpath);
					goto done;
				}
				TALLOC_FREE(linkpath);
			}
		}

		/* Try and replace with a symlink. */
		if (symlink(fname, SYSTEM_KRB5_CONF_PATH) == -1) {
			const char *newpath = SYSTEM_KRB5_CONF_PATH ".saved";
			if (errno != EEXIST) {
				DEBUG(0,("create_local_private_krb5_conf_for_domain: symlink "
					"of %s to %s failed. Errno %s\n",
					fname, SYSTEM_KRB5_CONF_PATH, strerror(errno) ));
				goto done; /* Not a fatal error. */
			}

			/* Yes, this is a race conditon... too bad. */
			if (rename(SYSTEM_KRB5_CONF_PATH, newpath) == -1) {
				DEBUG(0,("create_local_private_krb5_conf_for_domain: rename "
					"of %s to %s failed. Errno %s\n",
					SYSTEM_KRB5_CONF_PATH, newpath,
					strerror(errno) ));
				goto done; /* Not a fatal error. */
			}

			if (symlink(fname, SYSTEM_KRB5_CONF_PATH) == -1) {
				DEBUG(0,("create_local_private_krb5_conf_for_domain: "
					"forced symlink of %s to /etc/krb5.conf failed. Errno %s\n",
					fname, strerror(errno) ));
				goto done; /* Not a fatal error. */
			}
		}
	}
#endif

done:
	TALLOC_FREE(tmpname);
	TALLOC_FREE(dname);

	return result;
}
#endif
