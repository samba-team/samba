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
/*
  return a string for an error from a ads routine
*/
char *ads_errstr(int rc)
{
	return ldap_err2string(rc);
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
  do a general ADS search
*/
int ads_search(ADS_STRUCT *ads, void **res, 
	       const char *exp, 
	       const char **attrs)
{
	*res = NULL;
	return ldap_search_s(ads->ld, ads->bind_path, 
			     LDAP_SCOPE_SUBTREE, exp, (char **)attrs, 0, (LDAPMessage **)res);
}

/*
  do a search on a specific DistinguishedName
*/
int ads_search_dn(ADS_STRUCT *ads, void **res, 
		  const char *dn, 
		  const char **attrs)
{
	*res = NULL;
	return ldap_search_s(ads->ld, dn, 
			     LDAP_SCOPE_BASE, "(objectclass=*)", (char **)attrs, 0, (LDAPMessage **)res);
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
int ads_find_machine_acct(ADS_STRUCT *ads, void **res, const char *host)
{
	int ret;
	char *exp;

	/* the easiest way to find a machine account anywhere in the tree
	   is to look for hostname$ */
	asprintf(&exp, "(samAccountName=%s$)", host);
	ret = ads_search(ads, res, exp, NULL);
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
		{"objectSid", dump_binary},
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
int ads_join_realm(ADS_STRUCT *ads, const char *hostname)
{
	int rc;
	LDAPMessage *res;
	char *host;

	/* hostname must be lowercase */
	host = strdup(hostname);
	strlower(host);

	rc = ads_find_machine_acct(ads, (void **)&res, host);
	if (rc == LDAP_SUCCESS && ads_count_replies(ads, res) == 1) {
		DEBUG(0, ("Host account for %s already exists\n", host));
		return LDAP_SUCCESS;
	}

	rc = ads_add_machine_acct(ads, host);
	if (rc != LDAP_SUCCESS) {
		DEBUG(0, ("ads_add_machine_acct: %s\n", ads_errstr(rc)));
		return rc;
	}

	rc = ads_find_machine_acct(ads, (void **)&res, host);
	if (rc != LDAP_SUCCESS || ads_count_replies(ads, res) != 1) {
		DEBUG(0, ("Host account test failed\n"));
		/* hmmm, we need NTSTATUS */
		return -1;
	}

	free(host);

	return LDAP_SUCCESS;
}

/*
  delete a machine from the realm
*/
int ads_leave_realm(ADS_STRUCT *ads, const char *hostname)
{
	int rc;
	void *res;
	char *hostnameDN, *host; 

	/* hostname must be lowercase */
	host = strdup(hostname);
	strlower(host);

	rc = ads_find_machine_acct(ads, &res, host);
	if (rc != LDAP_SUCCESS || ads_count_replies(ads, res) != 1) {
	    DEBUG(0, ("Host account for %s does not exist.\n", host));
	    return -1;
	}

	hostnameDN = ldap_get_dn(ads->ld, (LDAPMessage *)res);
	rc = ldap_delete_s(ads->ld, hostnameDN);
	ldap_memfree(hostnameDN);
	if (rc != LDAP_SUCCESS) {
	    DEBUG(0, ("ldap_delete_s: %s\n", ads_errstr(rc)));
	    return rc;
	}

	rc = ads_find_machine_acct(ads, &res, host);
	if (rc == LDAP_SUCCESS && ads_count_replies(ads, res) == 1 ) {
	    DEBUG(0, ("Failed to remove host account.\n"));
	    /*hmmm, we need NTSTATUS */
	    return -1;
	}

	free(host);

	return LDAP_SUCCESS;
}


NTSTATUS ads_set_machine_password(ADS_STRUCT *ads,
				  const char *hostname, 
				  const char *password)
{
	NTSTATUS ret;
	char *host = strdup(hostname);
	strlower(host);
	ret = krb5_set_password(ads->kdc_server, host, ads->realm, password);
	free(host);
	return ret;
}


/*
  return a RFC2254 binary string representation of a buffer
  used in filters
  caller must free
*/
char *ads_binary_string(char *buf, int len)
{
	char *s;
	int i, j;
	const char *hex = "0123456789ABCDEF";
	s = malloc(len * 3 + 1);
	if (!s) return NULL;
	for (j=i=0;i<len;i++) {
		s[j] = '\\';
		s[j+1] = hex[((unsigned char)buf[i]) >> 4];
		s[j+2] = hex[((unsigned char)buf[i]) & 0xF];
		j += 3;
	}
	s[j] = 0;
	return s;
}

/*
  return the binary string representation of a DOM_SID
  caller must free
*/
char *ads_sid_binstring(DOM_SID *sid)
{
	char *buf, *s;
	int len = sid_size(sid);
	buf = malloc(len);
	if (!buf) return NULL;
	sid_linearize(buf, len, sid);
	s = ads_binary_string(buf, len);
	free(buf);
	return s;
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
BOOL ads_USN(ADS_STRUCT *ads, uint32 *usn)
{
	const char *attrs[] = {"highestCommittedUSN", NULL};
	int rc;
	void *res;

	rc = ldap_search_s(ads->ld, "", 
			   LDAP_SCOPE_BASE, "(objectclass=*)", attrs, 0, (LDAPMessage **)&res);
	if (rc || ads_count_replies(ads, res) != 1) return False;
	return ads_pull_uint32(ads, res, "highestCommittedUSN", usn);
}



#endif
