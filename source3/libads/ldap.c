/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   ads (active directory) utility library
   Copyright (C) Andrew Tridgell 2001
   
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

/* return a dn of the form "dc=AA,dc=BB,dc=CC" from a 
   realm of the form AA.BB.CC 
   caller must free
*/
static char *ads_build_dn(const char *realm)
{
	char *p, *r;
	int numdots = 0;
	char *ret;
	int len;
	
	r = strdup(realm);

	if (!r || !*r) return r;

	for (p=r; *p; p++) {
		if (*p == '.') numdots++;
	}

	len = (numdots+1)*4 + strlen(r) + 1;

	ret = malloc(len);
	strlcpy(ret,"dc=", len);
	p=strtok(r,"."); 
	strlcat(ret, p, len);

	while ((p=strtok(NULL,"."))) {
		strlcat(ret,",dc=", len);
		strlcat(ret, p, len);
	}

	free(r);

	return ret;
}

/*
  return a string for an error from a ads routine
*/
char *ads_errstr(int rc)
{
	return ldap_err2string(rc);
}

/*
  find the ldap server from DNS
*/
static char *find_ldap_server(ADS_STRUCT *ads)
{
	char *list = NULL;

	if (ldap_domain2hostlist(ads->realm, &list) == LDAP_SUCCESS) {
		char *p;
		p = strchr(list, ':');
		if (p) *p = 0;
		return list;
	}

	return NULL;
}

/*
  initialise a ADS_STRUCT, ready for some ads_ ops
*/
ADS_STRUCT *ads_init(const char *realm, 
		     const char *ldap_server,
		     const char *bind_path)
{
	ADS_STRUCT *ads;
	
	ads = (ADS_STRUCT *)malloc(sizeof(*ads));
	if (!ads) return NULL;
	memset(ads, 0, sizeof(*ads));
	
	ads->realm = realm? strdup(realm) : NULL;
	ads->ldap_server = ldap_server? strdup(ldap_server) : NULL;
	ads->bind_path = bind_path? strdup(bind_path) : NULL;
	ads->ldap_port = LDAP_PORT;

	if (!ads->realm) {
		ads->realm = lp_realm();
	}
	if (!ads->bind_path) {
		ads->bind_path = ads_build_dn(ads->realm);
	}
	if (!ads->ldap_server) {
		ads->ldap_server = lp_ads_server();
		if (!ads->ldap_server[0]) {
			ads->ldap_server = find_ldap_server(ads);
		}
	}
	if (!ads->kdc_server) {
		/* assume its the same as LDAP */
		ads->kdc_server = ads->ldap_server? strdup(ads->ldap_server) : NULL;
	}

	return ads;
}

/*
  free the memory used by the ADS structure initialized with 'ads_init(...)'
*/
void ads_destroy(ADS_STRUCT *ads)
{
	if (ads->ld) ldap_unbind(ads->ld);
	SAFE_FREE(ads->realm);
	SAFE_FREE(ads->ldap_server);
	SAFE_FREE(ads->kdc_server);
	SAFE_FREE(ads->bind_path);
	ZERO_STRUCTP(ads);
	free(ads);
}

/*
  this is a minimal interact function, just enough for SASL to talk
  GSSAPI/kerberos to W2K
  Error handling is a bit of a problem. I can't see how to get Cyrus-sasl
  to give sensible errors
*/
static int sasl_interact(LDAP *ld,unsigned flags,void *defaults,void *in)
{
	sasl_interact_t *interact = in;

	while (interact->id != SASL_CB_LIST_END) {
		interact->result = strdup("");
		interact->len = strlen(interact->result);
		interact++;
	}
	
	return LDAP_SUCCESS;
}

/*
  connect to the LDAP server
*/
int ads_connect(ADS_STRUCT *ads)
{
	int version = LDAP_VERSION3;
	int rc;

	ads->ld = ldap_open(ads->ldap_server, ads->ldap_port);
	if (!ads->ld) {
		return errno;
	}
	ldap_set_option(ads->ld, LDAP_OPT_PROTOCOL_VERSION, &version);

	rc = ldap_sasl_interactive_bind_s(ads->ld, NULL, NULL, NULL, NULL, 
					  LDAP_SASL_QUIET,
					  sasl_interact, NULL);

	return rc;
}


/*
  find a machine account given a hostname 
*/
int ads_find_machine_acct(ADS_STRUCT *ads, void **res, const char *host)
{
	int ret;
	char *exp;

	/* the easiest way to find a machine account anywhere in the tree
	   is to look for hostname$ */
	asprintf(&exp, "(samAccountName=%s$)", host);
	*res = NULL;
	ret = ldap_search_s(ads->ld, ads->bind_path, 
			    LDAP_SCOPE_SUBTREE, exp, NULL, 0, (LDAPMessage **)res);
	free(exp);
	return ret;
}


/*
  a convenient routine for adding a generic LDAP record 
*/
int ads_gen_add(ADS_STRUCT *ads, const char *new_dn, ...)
{
	int i;
	va_list ap;
	LDAPMod **mods;
	char *name, *value;
	int ret;
#define MAX_MOD_VALUES 10
	
	/* count the number of attributes */
	va_start(ap, new_dn);
	for (i=0; va_arg(ap, char *); i++) {
		/* skip the values */
		while (va_arg(ap, char *)) ;
	}
	va_end(ap);

	mods = malloc(sizeof(LDAPMod *) * (i+1));

	va_start(ap, new_dn);
	for (i=0; (name=va_arg(ap, char *)); i++) {
		char **values;
		int j;
		values = (char **)malloc(sizeof(char *) * (MAX_MOD_VALUES+1));
		for (j=0; (value=va_arg(ap, char *)) && j < MAX_MOD_VALUES; j++) {
			values[j] = value;
		}
		values[j] = NULL;
		mods[i] = malloc(sizeof(LDAPMod));
		mods[i]->mod_type = name;
		mods[i]->mod_op = LDAP_MOD_ADD;
		mods[i]->mod_values = values;
	}
	mods[i] = NULL;
	va_end(ap);

	ret = ldap_add_s(ads->ld, new_dn, mods);

	for (i=0; mods[i]; i++) {
		free(mods[i]->mod_values);
		free(mods[i]);
	}
	free(mods);
	
	return ret;
}

/*
  add a machine account to the ADS server
*/
static int ads_add_machine_acct(ADS_STRUCT *ads, const char *hostname)
{
	int ret;
	char *host_spn, *host_upn, *new_dn, *samAccountName, *controlstr;

	asprintf(&host_spn, "HOST/%s", hostname);
	asprintf(&host_upn, "%s@%s", host_spn, ads->realm);
	asprintf(&new_dn, "cn=%s,cn=Computers,%s", hostname, ads->bind_path);
	asprintf(&samAccountName, "%s$", hostname);
	asprintf(&controlstr, "%u", 
		UF_DONT_EXPIRE_PASSWD | UF_WORKSTATION_TRUST_ACCOUNT |
		UF_TRUSTED_FOR_DELEGATION | UF_USE_DES_KEY_ONLY);
    
	ret = ads_gen_add(ads, new_dn,
			   "cn", hostname, NULL,
			   "sAMAccountName", samAccountName, NULL,
			   "objectClass", 
			      "top", "person", "organizationalPerson", 
			      "user", "computer", NULL,
			   "userPrincipalName", host_upn, NULL, 
			   "servicePrincipalName", host_spn, NULL,
			   "dNSHostName", hostname, NULL,
			   "userAccountControl", controlstr, NULL,
			   "operatingSystem", "Samba", NULL,
			   "operatingSystemVersion", VERSION, NULL,
			   NULL);

	free(host_spn);
	free(host_upn);
	free(new_dn);
	free(samAccountName);
	free(controlstr);

	return ret;
}

/*
  dump a record from LDAP on stdout
  used for debugging
*/
void ads_dump(ADS_STRUCT *ads, void *res)
{
	char *field;
	LDAPMessage *msg;
	BerElement *b;
	char *this_dn;
    
	for (msg = ldap_first_entry(ads->ld, (LDAPMessage *)res); 
	     msg; msg = ldap_next_entry(ads->ld, msg)) {
		this_dn = ldap_get_dn(ads->ld, (LDAPMessage *)res);
		if (this_dn) {
			printf("Dumping: %s\n", this_dn);
		}
		ldap_memfree(this_dn);

		for (field = ldap_first_attribute(ads->ld, msg, &b); 
		     field;
		     field = ldap_next_attribute(ads->ld, msg, b)) {
			char **values, **p;
			values = ldap_get_values(ads->ld, msg, field);
			for (p = values; *p; p++) {
				printf("%s: %s\n", field, *p);
			}
			ldap_value_free(values);
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
int ads_join_realm(ADS_STRUCT *ads, const char *hostname)
{
	int rc;
	LDAPMessage *res;

	rc = ads_find_machine_acct(ads, (void **)&res, hostname);
	if (rc == LDAP_SUCCESS && ads_count_replies(ads, res) == 1) {
		DEBUG(0, ("Host account for %s already exists\n", hostname));
		return LDAP_SUCCESS;
	}

	rc = ads_add_machine_acct(ads, hostname);
	if (rc != LDAP_SUCCESS) {
		DEBUG(0, ("ads_add_machine_acct: %s\n", ads_errstr(rc)));
		return rc;
	}

	rc = ads_find_machine_acct(ads, (void **)&res, hostname);
	if (rc != LDAP_SUCCESS || ads_count_replies(ads, res) != 1) {
		DEBUG(0, ("Host account test failed\n"));
		/* hmmm, we need NTSTATUS */
		return -1;
	}

	return LDAP_SUCCESS;
}

/*
  delete a machine from the realm
*/
int ads_leave_realm(ADS_STRUCT *ads, const char *hostname)
{
	int rc;
	void *res;
	char *hostnameDN; 

	rc = ads_find_machine_acct(ads, &res, hostname);
	if (rc != LDAP_SUCCESS || ads_count_replies(ads, res) != 1) {
	    DEBUG(0, ("Host account for %s does not exist.\n", hostname));
	    return -1;
	}

	hostnameDN = ldap_get_dn(ads->ld, (LDAPMessage *)res);
	rc = ldap_delete_s(ads->ld, hostnameDN);
	ldap_memfree(hostnameDN);
	if (rc != LDAP_SUCCESS) {
	    DEBUG(0, ("ldap_delete_s: %s\n", ads_errstr(rc)));
	    return rc;
	}

	rc = ads_find_machine_acct(ads, &res, hostname);
	if (rc == LDAP_SUCCESS && ads_count_replies(ads, res) == 1 ) {
	    DEBUG(0, ("Failed to remove host account.\n"));
	    /*hmmm, we need NTSTATUS */
	    return -1;
	}
	
	return LDAP_SUCCESS;
}


NTSTATUS ads_set_machine_password(ADS_STRUCT *ads,
				  const char *hostname, 
				  const char *password)
{
	return krb5_set_password(ads->kdc_server, hostname, ads->realm, password);
}

#endif
