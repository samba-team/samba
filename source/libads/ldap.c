/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   ads (active directory) utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   
   
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
  build a ADS_STATUS structure
*/
ADS_STATUS ads_build_error(enum ads_error_type etype, 
			   int rc, int minor_status)
{
	ADS_STATUS ret;
	ret.error_type = etype;
	ret.rc = rc;
	ret.minor_status = minor_status;
	return ret;
}

/*
  do a rough conversion between ads error codes and NT status codes
  we'll need to fill this in more
*/
NTSTATUS ads_ntstatus(ADS_STATUS rc)
{
	if (ADS_ERR_OK(rc)) return NT_STATUS_OK;
	return NT_STATUS_UNSUCCESSFUL;
}

/*
  return a string for an error from a ads routine
*/
const char *ads_errstr(ADS_STATUS status)
{
	gss_buffer_desc msg1, msg2;
	uint32 minor;
	int msg_ctx;
	static char *ret;

	SAFE_FREE(ret);
	msg_ctx = 0;

	switch (status.error_type) {
	case ADS_ERROR_KRB5: 
		return error_message(status.rc);
	case ADS_ERROR_LDAP:
		return ldap_err2string(status.rc);
	case ADS_ERROR_SYSTEM:
		return strerror(status.rc);
	case ADS_ERROR_GSS:
		msg1.value = NULL;
		msg2.value = NULL;
		gss_display_status(&minor, status.rc, GSS_C_GSS_CODE,
				   GSS_C_NULL_OID, &msg_ctx, &msg1);
		gss_display_status(&minor, status.minor_status, GSS_C_MECH_CODE,
				   GSS_C_NULL_OID, &msg_ctx, &msg2);
		asprintf(&ret, "%s : %s", (char *)msg1.value, (char *)msg2.value);
		gss_release_buffer(&minor, &msg1);
		gss_release_buffer(&minor, &msg2);
		return ret;
	}

	return "Unknown ADS error type!?";
}

/*
  connect to the LDAP server
*/
ADS_STATUS ads_connect(ADS_STRUCT *ads)
{
	int version = LDAP_VERSION3;
	ADS_STATUS status;

	ads->last_attempt = time(NULL);

	ads->ld = ldap_open(ads->ldap_server, ads->ldap_port);
	if (!ads->ld) {
		return ADS_ERROR_SYSTEM(errno)
	}
	status = ads_server_info(ads);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("Failed to get ldap server info\n"));
		return status;
	}

	ldap_set_option(ads->ld, LDAP_OPT_PROTOCOL_VERSION, &version);

	if (ads->password) {
		ads_kinit_password(ads);
	}

	return ads_sasl_bind(ads);
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
			       exp, attrs, 0, NULL, NULL, 
			       &timeout, LDAP_NO_LIMIT, (LDAPMessage **)res);
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
  find a machine account given a hostname 
*/
ADS_STATUS ads_find_machine_acct(ADS_STRUCT *ads, void **res, const char *host)
{
	ADS_STATUS status;
	char *exp;

	/* the easiest way to find a machine account anywhere in the tree
	   is to look for hostname$ */
	asprintf(&exp, "(samAccountName=%s$)", host);
	status = ads_search(ads, res, exp, NULL);
	free(exp);
	return status;
}


/*
  a convenient routine for adding a generic LDAP record 
*/
ADS_STATUS ads_gen_add(ADS_STRUCT *ads, const char *new_dn, ...)
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
	
	return ADS_ERROR(ret);
}

/*
  add a machine account to the ADS server
*/
static ADS_STATUS ads_add_machine_acct(ADS_STRUCT *ads, const char *hostname, 
				       const char *org_unit)
{
	ADS_STATUS ret;
	char *host_spn, *host_upn, *new_dn, *samAccountName, *controlstr;

	asprintf(&host_spn, "HOST/%s", hostname);
	asprintf(&host_upn, "%s@%s", host_spn, ads->realm);
	asprintf(&new_dn, "cn=%s,cn=%s,%s", hostname, org_unit, ads->bind_path);
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
		DEBUG(0, ("Host account for %s already exists\n", host));
		return ADS_SUCCESS;
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

	hostnameDN = ldap_get_dn(ads->ld, (LDAPMessage *)res);
	rc = ldap_delete_s(ads->ld, hostnameDN);
	ldap_memfree(hostnameDN);
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


ADS_STATUS ads_set_machine_password(ADS_STRUCT *ads,
				    const char *hostname, 
				    const char *password)
{
	ADS_STATUS status;
	char *host = strdup(hostname);
	char *principal; 

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
		ads_pull_sid(ads, msg, "securityIdentifier", &(*sids)[i]);
		i++;
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
