/* 
   Unix SMB/CIFS implementation.
   ads (active directory) utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Jim McDonough 2002
   
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

#ifdef HAVE_ADS

/*
  connect to the LDAP server
*/
ADS_STATUS ads_connect(ADS_STRUCT *ads)
{
	int version = LDAP_VERSION3;
	int code;
	ADS_STATUS status;

	ads->last_attempt = time(NULL);

	ads->ld = ldap_open(ads->ldap_server, ads->ldap_port);
	if (!ads->ld) {
		return ADS_ERROR_SYSTEM(errno);
	}
	status = ads_server_info(ads);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("Failed to get ldap server info\n"));
		return status;
	}

	ldap_set_option(ads->ld, LDAP_OPT_PROTOCOL_VERSION, &version);

#if KRB5_DNS_HACK
	/* this is a really nasty hack to avoid ADS DNS problems. It needs a patch
	   to MIT kerberos to work (tridge) */
	{
		char *env;
		asprintf(&env, "KRB5_KDC_ADDRESS_%s", ads->server_realm);
		setenv(env, inet_ntoa(*interpret_addr2(ads->ldap_server)), 1);
		free(env);
	}
#endif

	if (ads->password) {
		if ((code = ads_kinit_password(ads)))
			return ADS_ERROR_KRB5(code);
	}

	return ads_sasl_bind(ads);
}


/* Do a search with paged results.  cookie must be null on the first
   call, and then returned on each subsequent call.  It will be null
   again when the entire search is complete */

ADS_STATUS ads_do_paged_search(ADS_STRUCT *ads, const char *bind_path,
			       int scope, const char *exp,
			       const char **attrs, void **res, 
			       int *count, void **cookie)
{
	int rc;
#define ADS_PAGE_CTL_OID "1.2.840.113556.1.4.319"
#define ADS_NO_REFERRALS_OID "1.2.840.113556.1.4.1339"
	int version;
	LDAPControl PagedResults; 
	LDAPControl NoReferrals;
	BerElement *berelem = NULL;
	struct berval *berval = NULL;
	LDAPControl *controls[3];
	LDAPControl **rcontrols, *cur_control;

	*res = NULL;

	ldap_get_option(ads->ld, LDAP_OPT_PROTOCOL_VERSION, &version);

		/* Paged results only available on ldap v3 or later, so check
		   version first before using, since at connect time we're
		   only v2.  Not sure exactly why... */
	if (version < LDAP_VERSION3) 
		return ADS_ERROR(LDAP_NOT_SUPPORTED);

	berelem = ber_alloc_t(LBER_USE_DER);
	if (cookie && *cookie) {
		ber_printf(berelem, "{iO}", (ber_int_t) 1000, *cookie);
		ber_bvfree(*cookie); /* don't need it from last time */
		*cookie = NULL;
	} else {
		ber_printf(berelem, "{io}", (ber_int_t) 1000, "", 0);
	}
	ber_flatten(berelem, &berval);
	PagedResults.ldctl_oid = ADS_PAGE_CTL_OID;
	PagedResults.ldctl_iscritical = (char) 0;
	PagedResults.ldctl_value.bv_len = berval->bv_len;
	PagedResults.ldctl_value.bv_val = berval->bv_val;

	NoReferrals.ldctl_oid = ADS_NO_REFERRALS_OID;
	NoReferrals.ldctl_iscritical = (char) 0;
	NoReferrals.ldctl_value.bv_len = 0;
	NoReferrals.ldctl_value.bv_val = "";

	controls[0] = &NoReferrals;
	controls[1] = &PagedResults;
	controls[2] = NULL;

	*res = NULL;

	/* we need to disable referrals as the openldap libs don't
	   seem to handle them correctly. They result in the result
	   record containing the server control being removed from the
	   result list (tridge) 
	
	   leaving this in despite the control that says don't generate
	   referrals, in case the server doesn't support it (jmcd)
	*/
	ldap_set_option(ads->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

	rc = ldap_search_ext_s(ads->ld, bind_path, scope, exp, 
			       (char **) attrs, 0, controls, NULL,
			       NULL, LDAP_NO_LIMIT,
			       (LDAPMessage **)res);

	if (rc) {
		DEBUG(3,("ldap_search_ext_s(%s) -> %s\n", exp, ldap_err2string(rc)));
		return ADS_ERROR(rc);
	}

	ber_free(berelem, 1);
	ber_bvfree(berval);

	rc = ldap_parse_result(ads->ld, *res, NULL, NULL, NULL,
					NULL, &rcontrols,  0);

	if (!rcontrols) {
		return ADS_ERROR(rc);
	}

	for (cur_control=rcontrols[0]; cur_control; cur_control++) {
		if (strcmp(ADS_PAGE_CTL_OID, cur_control->ldctl_oid) == 0) {
			berelem = ber_init(&cur_control->ldctl_value);
			ber_scanf(berelem,"{iO}", (ber_int_t *) count,
				  &berval);
			/* the berval is the cookie, but must be freed when
			   it is all done */
			if (berval->bv_len) /* still more to do */
				*cookie=ber_bvdup(berval);
			else
				*cookie=NULL;
			ber_bvfree(berval);
			ber_free(berelem, 1);
			break;
		}
	}
	ldap_controls_free(rcontrols);
			
	return ADS_ERROR(rc);
}


/*
  this uses ads_do_paged_search() to return all entries in a large
  search.  The interface is the same as ads_do_search(), which makes
  it more convenient than the paged interface
 */
ADS_STATUS ads_do_search_all(ADS_STRUCT *ads, const char *bind_path,
			     int scope, const char *exp,
			     const char **attrs, void **res)
{
	void *cookie = NULL;
	int count = 0;
	ADS_STATUS status;

	status = ads_do_paged_search(ads, bind_path, scope, exp, attrs, res, &count, &cookie);

	if (!ADS_ERR_OK(status)) return status;

	while (cookie) {
		void *res2 = NULL;
		ADS_STATUS status2;
		LDAPMessage *msg, *next;

		status2 = ads_do_paged_search(ads, bind_path, scope, exp, attrs, &res2, &count, &cookie);

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

/*
  do a search with a timeout
*/
ADS_STATUS ads_do_search(ADS_STRUCT *ads, const char *bind_path, int scope, 
			 const char *exp,
			 const char **attrs, void **res)
{
	struct timeval timeout;
	int rc;

	timeout.tv_sec = ADS_SEARCH_TIMEOUT;
	timeout.tv_usec = 0;
	*res = NULL;

	rc = ldap_search_ext_s(ads->ld, 
			       bind_path, scope,
			       exp, (char **) attrs, 0, NULL, NULL, 
			       &timeout, LDAP_NO_LIMIT, (LDAPMessage **)res);

	if (rc == LDAP_SIZELIMIT_EXCEEDED) {
		DEBUG(3,("Warning! sizelimit exceeded in ldap. Truncating.\n"));
		rc = 0;
	}

	return ADS_ERROR(rc);
}
/*
  do a general ADS search
*/
ADS_STATUS ads_search(ADS_STRUCT *ads, void **res, 
		      const char *exp, 
		      const char **attrs)
{
	return ads_do_search(ads, ads->bind_path, LDAP_SCOPE_SUBTREE, 
			     exp, attrs, res);
}

/*
  do a search on a specific DistinguishedName
*/
ADS_STATUS ads_search_dn(ADS_STRUCT *ads, void **res, 
			 const char *dn, 
			 const char **attrs)
{
	return ads_do_search(ads, dn, LDAP_SCOPE_BASE, "(objectclass=*)", attrs, res);
}

/*
  free up memory from a ads_search
*/
void ads_msgfree(ADS_STRUCT *ads, void *msg)
{
	if (!msg) return;
	ldap_msgfree(msg);
}

/*
  free up memory from various ads requests
*/
void ads_memfree(ADS_STRUCT *ads, void *mem)
{
	if (!mem) return;
	ldap_memfree(mem);
}

/*
  get a dn from search results
*/
char *ads_get_dn(ADS_STRUCT *ads, void *res)
{
	return ldap_get_dn(ads->ld, res);
}

/*
  find a machine account given a hostname 
*/
ADS_STATUS ads_find_machine_acct(ADS_STRUCT *ads, void **res, const char *host)
{
	ADS_STATUS status;
	char *exp;
	const char *attrs[] = {"*", "nTSecurityDescriptor", NULL};

	/* the easiest way to find a machine account anywhere in the tree
	   is to look for hostname$ */
	asprintf(&exp, "(samAccountName=%s$)", host);
	status = ads_search(ads, res, exp, attrs);
	free(exp);
	return status;
}

/*
  duplicate an already-assembled list of values so that it can be
  freed as part of the standard msgfree call
*/
static char **ads_dup_values(TALLOC_CTX *ctx, char **values)
{
	char **newvals;
	int i;
#define ADS_MAX_NUM_VALUES 32

	for (i=0; values[i] && i<ADS_MAX_NUM_VALUES; i++);
	if (!(newvals = talloc_zero(ctx, (i+1)*sizeof(char *))))
		return NULL;
	for (i=0; values[i] && i<ADS_MAX_NUM_VALUES; i++)
		newvals[i] = values[i];
	newvals[i] = NULL;
	return newvals;
}

/*
  initialize a list of mods 
*/

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
				  int mod_op, const char *name, char **values)
{
	int curmod;
	LDAPMod **modlist = (LDAPMod **) *mods;

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
	modlist[curmod]->mod_type = name;
	if (mod_op & LDAP_MOD_BVALUES)
		modlist[curmod]->mod_bvalues = (struct berval **) values;
	else
		modlist[curmod]->mod_values = values;
	modlist[curmod]->mod_op = mod_op;
	return ADS_ERROR(LDAP_SUCCESS);
}

ADS_STATUS ads_mod_add_list(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
			    char *name, char **values)
{
	char **newvals = ads_dup_values(ctx, values);
	if (newvals)
		return ads_modlist_add(ctx, mods, LDAP_MOD_ADD, name, newvals);
	else
		return ADS_ERROR(LDAP_NO_MEMORY);
}

ADS_STATUS ads_mod_repl_list(TALLOC_CTX *ctx, ADS_MODLIST *mods,
			     char *name, char **values)
{
	char **newvals;
	if (values && *values) {
		if (!(newvals = ads_dup_values(ctx, values)))
			return ADS_ERROR(LDAP_NO_MEMORY);
		else
			return ads_modlist_add(ctx, mods, LDAP_MOD_REPLACE,
						name, newvals);
	}
	else
		return ads_modlist_add(ctx, mods, LDAP_MOD_DELETE, name, NULL);
}

/*
  add an attribute to the list, with values list to be built from args
*/
ADS_STATUS ads_mod_add_var(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
			   int mod_op, const char *name, ...)
{
	va_list ap;
	int num_vals, i, do_op;
	char *value, **values;

	/* count the number of values */
	va_start(ap, name);
	for (num_vals=0; va_arg(ap, char *); num_vals++);
	va_end(ap);

	if (num_vals) {
		if (!(values = talloc_zero(ctx, sizeof(char *)*(num_vals+1))))
			return ADS_ERROR(LDAP_NO_MEMORY);
		va_start(ap, name);
		for (i=0; (value = (char *) va_arg(ap, char *)) &&
			     i < num_vals; i++)
			values[i] = value;
		va_end(ap);
		values[i] = NULL;
		do_op = mod_op;
	} else {
		do_op = LDAP_MOD_DELETE;
		values = NULL;
	}
	return ads_modlist_add(ctx, mods, do_op, name, values);
}

ADS_STATUS ads_mod_add_ber(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
			   int mod_op, const char *name, ...)
{
	va_list ap;
	int num_vals, i, do_op;
	char *value, **values;

	/* count the number of values */
	va_start(ap, name);
	for (num_vals=0; va_arg(ap, struct berval *); num_vals++);
	va_end(ap);

	if (num_vals) {
		if (!(values = talloc_zero(ctx, sizeof(struct berval) * 
					   (num_vals + 1))))
			return ADS_ERROR(LDAP_NO_MEMORY);
		va_start(ap, name);
		for (i=0; (value = (char *) va_arg(ap, char *)) &&
			     i < num_vals; i++)
			values[i] = value;
		va_end(ap);
		values[i] = NULL;
		do_op = mod_op;
	} else {
		do_op = LDAP_MOD_DELETE;
		values = NULL;
	}
	do_op |= LDAP_MOD_BVALUES;
	return ads_modlist_add(ctx, mods, do_op, name, values);
}

ADS_STATUS ads_mod_repl(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
			char *name, char *val)
{
	if (val)
		return ads_mod_add_var(ctx, mods, LDAP_MOD_REPLACE,
				       name, val, NULL);
	else
		return ads_mod_add_var(ctx, mods, LDAP_MOD_DELETE, name, NULL);
}

ADS_STATUS ads_mod_add(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
		       const char *name, const char *val)
{
	return ads_mod_add_var(ctx, mods, LDAP_MOD_ADD, name, val, NULL);
}

ADS_STATUS ads_mod_add_len(TALLOC_CTX *ctx, ADS_MODLIST *mods,
			   char *name, size_t size, char *val)
{
	struct berval *bval = NULL;

	if (!(bval = talloc_zero(ctx, sizeof(struct berval *))))
		return ADS_ERROR(LDAP_NO_MEMORY);
	if (!(bval->bv_val = talloc_zero(ctx, sizeof(char *))))
		return ADS_ERROR(LDAP_NO_MEMORY);

	bval->bv_val = val;
	bval->bv_len = size;
	return ads_mod_add_ber(ctx, mods, LDAP_MOD_ADD, name, bval, NULL);
}

ADS_STATUS ads_mod_repl_len(TALLOC_CTX *ctx, ADS_MODLIST *mods,
			    const char *name, size_t size, char *val)
{
	struct berval *bval = NULL;

	if (!(bval = talloc_zero(ctx, sizeof(struct berval *))))
		return ADS_ERROR(LDAP_NO_MEMORY);

	if (!val)
		return ads_mod_add_ber(ctx, mods, LDAP_MOD_DELETE, name, NULL);
	else {
		if (!(bval->bv_val = talloc_zero(ctx, sizeof(char *))))
			return ADS_ERROR(LDAP_NO_MEMORY);
		bval->bv_val = val;
		bval->bv_len = size;
		return ads_mod_add_ber(ctx, mods, LDAP_MOD_REPLACE, name, 
				       bval, NULL);
	}
}

ADS_STATUS ads_gen_mod(ADS_STRUCT *ads, const char *mod_dn, ADS_MODLIST mods)
{
	int ret,i;
	/* 
	   this control is needed to modify that contains a currently 
	   non-existent attribute (but allowable for the object) to run
	*/
	LDAPControl PermitModify = {
		"1.2.840.113556.1.4.1413",
		{0, NULL},
		(char) 1};
	LDAPControl *controls[2];

	controls[0] = &PermitModify;
	controls[1] = NULL;

	/* find the end of the list, marked by NULL or -1 */
	for(i=0;(mods[i]!=0)&&(mods[i]!=(LDAPMod *) -1);i++);
	/* make sure the end of the list is NULL */
	mods[i] = NULL;
	ret = ldap_modify_ext_s(ads->ld, mod_dn, (LDAPMod **) mods,
				controls, NULL);
	return ADS_ERROR(ret);
}

ADS_STATUS ads_gen_add(ADS_STRUCT *ads, const char *new_dn, ADS_MODLIST mods)
{
	int i;

	/* find the end of the list, marked by NULL or -1 */
	for(i=0;(mods[i]!=0)&&(mods[i]!=(LDAPMod *) -1);i++);
	/* make sure the end of the list is NULL */
	mods[i] = NULL;

	return ADS_ERROR(ldap_add_s(ads->ld, new_dn, mods));
}

ADS_STATUS ads_del_dn(ADS_STRUCT *ads, char *del_dn)
{
	return ADS_ERROR(ldap_delete(ads->ld, del_dn));
}

/*
  build an org unit string
  if org unit is Computers or blank then assume a container, otherwise
  assume a \ separated list of organisational units
  caller must free
*/
char *ads_ou_string(const char *org_unit)
{	
	if (!org_unit || !*org_unit || strcasecmp(org_unit, "Computers") == 0) {
		return strdup("cn=Computers");
	}

	return ads_build_path(org_unit, "\\/", "ou=", 1);
}



/*
  add a machine account to the ADS server
*/
static ADS_STATUS ads_add_machine_acct(ADS_STRUCT *ads, const char *hostname, 
				       const char *org_unit)
{
	ADS_STATUS ret;
	char *host_spn, *host_upn, *new_dn, *samAccountName, *controlstr;
	char *ou_str;
	TALLOC_CTX *ctx;
	ADS_MODLIST mods;

	if (!(ctx = talloc_init_named("machine_account")))
		return ADS_ERROR(LDAP_NO_MEMORY);

	ret = ADS_ERROR(LDAP_NO_MEMORY);

	if (!(host_spn = talloc_asprintf(ctx, "HOST/%s", hostname)))
		goto done;
	if (!(host_upn = talloc_asprintf(ctx, "%s@%s", host_spn, ads->realm)))
		goto done;
	ou_str = ads_ou_string(org_unit);
	new_dn = talloc_asprintf(ctx, "cn=%s,%s,%s", hostname, ou_str, 
				 ads->bind_path);
	free(ou_str);
	if (!new_dn)
		goto done;

	if (!(samAccountName = talloc_asprintf(ctx, "%s$", hostname)))
		goto done;
	if (!(controlstr = talloc_asprintf(ctx, "%u", 
		   UF_DONT_EXPIRE_PASSWD | UF_WORKSTATION_TRUST_ACCOUNT | 
		   UF_TRUSTED_FOR_DELEGATION | UF_USE_DES_KEY_ONLY)))
		goto done;

	if (!(mods = ads_init_mods(ctx)))
		goto done;
	
	ads_mod_add(ctx, &mods, "cn", hostname);
	ads_mod_add(ctx, &mods, "sAMAccountName", samAccountName);
	ads_mod_add_var(ctx, &mods, LDAP_MOD_ADD, "objectClass",
			"top", "person", "organizationalPerson",
			"user", "computer", NULL);
	ads_mod_add(ctx, &mods, "userPrincipalName", host_upn);
	ads_mod_add(ctx, &mods, "servicePrincipalName", host_spn);
	ads_mod_add(ctx, &mods, "dNSHostName", hostname);
	ads_mod_add(ctx, &mods, "userAccountControl", controlstr);
	ads_mod_add(ctx, &mods, "operatingSystem", "Samba");
	ads_mod_add(ctx, &mods, "operatingSystemVersion", VERSION);

	ads_gen_add(ads, new_dn, mods);
	ret = ads_set_machine_sd(ads, hostname, new_dn);

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

	if (!(ctx = talloc_init_named("sec_io_desc")))
		return;

	/* prepare data */
	prs_init(&ps, values[0]->bv_len, ctx, UNMARSHALL);
	prs_append_data(&ps, values[0]->bv_val, values[0]->bv_len);
	ps.data_offset = 0;

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
static void dump_string(const char *field, struct berval **values)
{
	int i;
	for (i=0; values[i]; i++) {
		printf("%s: %s\n", field, values[i]->bv_val);
	}
}

/*
  dump a record from LDAP on stdout
  used for debugging
*/
void ads_dump(ADS_STRUCT *ads, void *res)
{
	char *field;
	void *msg;
	BerElement *b;
	struct {
		char *name;
		void (*handler)(const char *, struct berval **);
	} handlers[] = {
		{"objectGUID", dump_binary},
		{"nTSecurityDescriptor", dump_sd},
		{"objectSid", dump_sid},
		{NULL, NULL}
	};
    
	for (msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		for (field = ldap_first_attribute(ads->ld, (LDAPMessage *)msg, &b); 
		     field;
		     field = ldap_next_attribute(ads->ld, (LDAPMessage *)msg, b)) {
			struct berval **values;
			int i;

			values = ldap_get_values_len(ads->ld, (LDAPMessage *)msg, field);

			for (i=0; handlers[i].name; i++) {
				if (StrCaseCmp(handlers[i].name, field) == 0) {
					handlers[i].handler(field, values);
					break;
				}
			}
			if (!handlers[i].name) {
				dump_string(field, values);
			}
			ldap_value_free_len(values);
			ldap_memfree(field);
		}

		ber_free(b, 1);
		printf("\n");
	}
}

/*
  count how many replies are in a LDAPMessage
*/
int ads_count_replies(ADS_STRUCT *ads, void *res)
{
	return ldap_count_entries(ads->ld, (LDAPMessage *)res);
}

/*
  join a machine to a realm, creating the machine account
  and setting the machine password
*/
ADS_STATUS ads_join_realm(ADS_STRUCT *ads, const char *hostname, const char *org_unit)
{
	ADS_STATUS status;
	LDAPMessage *res;
	char *host;

	/* hostname must be lowercase */
	host = strdup(hostname);
	strlower(host);

	status = ads_find_machine_acct(ads, (void **)&res, host);
	if (ADS_ERR_OK(status) && ads_count_replies(ads, res) == 1) {
		DEBUG(0, ("Host account for %s already exists - deleting old account\n", host));
		status = ads_leave_realm(ads, host);
		if (!ADS_ERR_OK(status)) {
			DEBUG(0, ("Failed to delete host '%s' from the '%s' realm.\n", 
				  host, ads->realm));
			return status;
		}
	}

	status = ads_add_machine_acct(ads, host, org_unit);
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

/*
  delete a machine from the realm
*/
ADS_STATUS ads_leave_realm(ADS_STRUCT *ads, const char *hostname)
{
	ADS_STATUS status;
	void *res;
	char *hostnameDN, *host; 
	int rc;

	/* hostname must be lowercase */
	host = strdup(hostname);
	strlower(host);

	status = ads_find_machine_acct(ads, &res, host);
	if (!ADS_ERR_OK(status)) {
	    DEBUG(0, ("Host account for %s does not exist.\n", host));
	    return status;
	}

	hostnameDN = ads_get_dn(ads, (LDAPMessage *)res);
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

/* 
  add machine account to existing security descriptor 
*/
ADS_STATUS ads_set_machine_sd(ADS_STRUCT *ads, const char *hostname, char *dn)
{
	const char     *attrs[] = {"ntSecurityDescriptor", "objectSid", 0};
	char           *exp     = 0;
	size_t          sd_size = 0;
	struct berval **bvals   = 0;
	prs_struct      ps;
	prs_struct      ps_wire;

	LDAPMessage *res  = 0;
	LDAPMessage *msg  = 0;
	ADS_MODLIST  mods = 0;

	NTSTATUS    status;
	ADS_STATUS  ret;
	DOM_SID     sid;
	SEC_DESC   *psd = 0;
	TALLOC_CTX *ctx = 0;	

	if (!ads) return ADS_ERROR(LDAP_SERVER_DOWN);

	ret = ADS_ERROR(LDAP_SUCCESS);

	asprintf(&exp, "(samAccountName=%s$)", hostname);
	ret = ads_search(ads, (void *) &res, exp, attrs);

	if (!ADS_ERR_OK(ret)) return ret;

	msg   = ads_first_entry(ads, res);
	bvals = ldap_get_values_len(ads->ld, msg, attrs[0]);
	ads_pull_sid(ads, msg, attrs[1], &sid);	
	ads_msgfree(ads, res);
#if 0
	file_save("/tmp/sec_desc.old", bvals[0]->bv_val, bvals[0]->bv_len);
#endif
	if (!(ctx = talloc_init_named("sec_io_desc")))
		return ADS_ERROR(LDAP_NO_MEMORY);

	prs_init(&ps, bvals[0]->bv_len, ctx, UNMARSHALL);
	prs_append_data(&ps, bvals[0]->bv_val, bvals[0]->bv_len);
	ps.data_offset = 0;
	ldap_value_free_len(bvals);

	if (!sec_io_desc("sd", &psd, &ps, 1))
		goto ads_set_sd_error;

	status = sec_desc_add_sid(ctx, &psd, &sid, SEC_RIGHTS_FULL_CTRL, &sd_size);

	if (!NT_STATUS_IS_OK(status))
		goto ads_set_sd_error;

	prs_init(&ps_wire, sd_size, ctx, MARSHALL);
	if (!sec_io_desc("sd_wire", &psd, &ps_wire, 1))
		goto ads_set_sd_error;

#if 0
	file_save("/tmp/sec_desc.new", ps_wire.data_p, sd_size);
#endif
	if (!(mods = ads_init_mods(ctx))) return ADS_ERROR(LDAP_NO_MEMORY);

	ads_mod_repl_len(ctx, &mods, attrs[0], sd_size, ps_wire.data_p);
	ret = ads_gen_mod(ads, dn, mods);

	prs_mem_free(&ps);
	prs_mem_free(&ps_wire);
	talloc_destroy(ctx);
	return ret;

ads_set_sd_error:
	prs_mem_free(&ps);
	prs_mem_free(&ps_wire);
	talloc_destroy(ctx);
	return ADS_ERROR(LDAP_NO_MEMORY);
}

ADS_STATUS ads_set_machine_password(ADS_STRUCT *ads,
				    const char *hostname, 
				    const char *password)
{
	ADS_STATUS status;
	char *host = strdup(hostname);
	char *principal; 

        if (!ads->kdc_server) {
		DEBUG(0, ("Unable to find KDC server\n"));
		return ADS_ERROR(LDAP_SERVER_DOWN);
	}

	strlower(host);

	asprintf(&principal, "%s@%s", host, ads->realm);
	
	status = krb5_set_password(ads->kdc_server, principal, password);
	
	free(host);
	free(principal);

	return status;
}

/*
  pull the first entry from a ADS result
*/
void *ads_first_entry(ADS_STRUCT *ads, void *res)
{
	return (void *)ldap_first_entry(ads->ld, (LDAPMessage *)res);
}

/*
  pull the next entry from a ADS result
*/
void *ads_next_entry(ADS_STRUCT *ads, void *res)
{
	return (void *)ldap_next_entry(ads->ld, (LDAPMessage *)res);
}

/*
  pull a single string from a ADS result
*/
char *ads_pull_string(ADS_STRUCT *ads, 
		      TALLOC_CTX *mem_ctx, void *msg, const char *field)
{
	char **values;
	char *ret = NULL;

	values = ldap_get_values(ads->ld, msg, field);
	if (!values) return NULL;
	
	if (values[0]) {
		ret = talloc_strdup(mem_ctx, values[0]);
	}
	ldap_value_free(values);
	return ret;
}

/*
  pull a single uint32 from a ADS result
*/
BOOL ads_pull_uint32(ADS_STRUCT *ads, 
		     void *msg, const char *field, uint32 *v)
{
	char **values;

	values = ldap_get_values(ads->ld, msg, field);
	if (!values) return False;
	if (!values[0]) {
		ldap_value_free(values);
		return False;
	}

	*v = atoi(values[0]);
	ldap_value_free(values);
	return True;
}

/*
  pull a single DOM_SID from a ADS result
*/
BOOL ads_pull_sid(ADS_STRUCT *ads, 
		  void *msg, const char *field, DOM_SID *sid)
{
	struct berval **values;
	BOOL ret = False;

	values = ldap_get_values_len(ads->ld, msg, field);

	if (!values) return False;

	if (values[0]) {
		ret = sid_parse(values[0]->bv_val, values[0]->bv_len, sid);
	}
	
	ldap_value_free_len(values);
	return ret;
}

/*
  pull an array of DOM_SIDs from a ADS result
  return the count of SIDs pulled
*/
int ads_pull_sids(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
		  void *msg, const char *field, DOM_SID **sids)
{
	struct berval **values;
	BOOL ret;
	int count, i;

	values = ldap_get_values_len(ads->ld, msg, field);

	if (!values) return 0;

	for (i=0; values[i]; i++) /* nop */ ;

	(*sids) = talloc(mem_ctx, sizeof(DOM_SID) * i);

	count = 0;
	for (i=0; values[i]; i++) {
		ret = sid_parse(values[i]->bv_val, values[i]->bv_len, &(*sids)[count]);
		if (ret) count++;
	}
	
	ldap_value_free_len(values);
	return count;
}


/* find the update serial number - this is the core of the ldap cache */
ADS_STATUS ads_USN(ADS_STRUCT *ads, uint32 *usn)
{
	const char *attrs[] = {"highestCommittedUSN", NULL};
	ADS_STATUS status;
	void *res;

	status = ads_do_search(ads, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) return status;

	if (ads_count_replies(ads, res) != 1) {
		return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
	}

	ads_pull_uint32(ads, res, "highestCommittedUSN", usn);
	ads_msgfree(ads, res);
	return ADS_SUCCESS;
}


/* find the servers name and realm - this can be done before authentication 
   The ldapServiceName field on w2k  looks like this:
     vnet3.home.samba.org:win2000-vnet3$@VNET3.HOME.SAMBA.ORG
*/
ADS_STATUS ads_server_info(ADS_STRUCT *ads)
{
	const char *attrs[] = {"ldapServiceName", NULL};
	ADS_STATUS status;
	void *res;
	char **values;
	char *p;

	status = ads_do_search(ads, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) return status;

	values = ldap_get_values(ads->ld, res, "ldapServiceName");
	if (!values || !values[0]) return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);

	p = strchr(values[0], ':');
	if (!p) {
		ldap_value_free(values);
		ldap_msgfree(res);
		return ADS_ERROR(LDAP_DECODING_ERROR);
	}

	SAFE_FREE(ads->ldap_server_name);

	ads->ldap_server_name = strdup(p+1);
	p = strchr(ads->ldap_server_name, '$');
	if (!p || p[1] != '@') {
		ldap_value_free(values);
		ldap_msgfree(res);
		SAFE_FREE(ads->ldap_server_name);
		return ADS_ERROR(LDAP_DECODING_ERROR);
	}

	*p = 0;

	SAFE_FREE(ads->server_realm);
	SAFE_FREE(ads->bind_path);

	ads->server_realm = strdup(p+2);
	ads->bind_path = ads_build_dn(ads->server_realm);

	/* in case the realm isn't configured in smb.conf */
	if (!ads->realm || !ads->realm[0]) {
		SAFE_FREE(ads->realm);
		ads->realm = strdup(ads->server_realm);
	}

	DEBUG(3,("got ldap server name %s@%s\n", 
		 ads->ldap_server_name, ads->realm));

	return ADS_SUCCESS;
}


/* 
   find the list of trusted domains
*/
ADS_STATUS ads_trusted_domains(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, 
			       int *num_trusts, char ***names, DOM_SID **sids)
{
	const char *attrs[] = {"flatName", "securityIdentifier", NULL};
	ADS_STATUS status;
	void *res, *msg;
	int count, i;

	*num_trusts = 0;

	status = ads_search(ads, &res, "(objectcategory=trustedDomain)", attrs);
	if (!ADS_ERR_OK(status)) return status;

	count = ads_count_replies(ads, res);
	if (count == 0) {
		ads_msgfree(ads, res);
		return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
	}

	(*names) = talloc(mem_ctx, sizeof(char *) * count);
	(*sids) = talloc(mem_ctx, sizeof(DOM_SID) * count);
	if (! *names || ! *sids) return ADS_ERROR(LDAP_NO_MEMORY);

	for (i=0, msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		(*names)[i] = ads_pull_string(ads, mem_ctx, msg, "flatName");
		if (ads_pull_sid(ads, msg, "securityIdentifier", &(*sids)[i])) {
			i++;
		}
	}

	ads_msgfree(ads, res);

	*num_trusts = i;

	return ADS_SUCCESS;
}

/* find the domain sid for our domain */
ADS_STATUS ads_domain_sid(ADS_STRUCT *ads, DOM_SID *sid)
{
	const char *attrs[] = {"objectSid", NULL};
	void *res;
	ADS_STATUS rc;

	rc = ads_do_search(ads, ads->bind_path, LDAP_SCOPE_BASE, "(objectclass=*)", 
			   attrs, &res);
	if (!ADS_ERR_OK(rc)) return rc;
	if (!ads_pull_sid(ads, res, "objectSid", sid)) {
		return ADS_ERROR_SYSTEM(ENOENT);
	}
	ads_msgfree(ads, res);
	
	return ADS_SUCCESS;
}

#endif
