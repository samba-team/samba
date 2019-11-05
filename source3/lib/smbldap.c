/* 
   Unix SMB/CIFS implementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau	1998
   Copyright (C) Gerald Carter			2001-2003
   Copyright (C) Shahms King			2001
   Copyright (C) Andrew Bartlett		2002-2003
   Copyright (C) Stefan (metze) Metzmacher	2002-2003

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
#include "smbldap.h"
#include "../libcli/security/security.h"
#include <tevent.h>
#include "lib/param/loadparm.h"

/* Try not to hit the up or down server forever */

#define SMBLDAP_DONT_PING_TIME 10	/* ping only all 10 seconds */
#define SMBLDAP_NUM_RETRIES 8	        /* retry only 8 times */

#define SMBLDAP_IDLE_TIME 150		/* After 2.5 minutes disconnect */

struct smbldap_state {
	LDAP *ldap_struct;
	pid_t pid;
	time_t last_ping; /* monotonic */
	/* retrieve-once info */
	const char *uri;

	/* credentials */
	bool anonymous;
	char *bind_dn;
	char *bind_secret;
	smbldap_bind_callback_fn bind_callback;
	void *bind_callback_data;

	bool paged_results;

	unsigned int num_failures;

	time_t last_use; /* monotonic */
	struct tevent_context *tevent_context;
	struct tevent_timer *idle_event;

	struct timeval last_rebind; /* monotonic */
};

LDAP *smbldap_get_ldap(struct smbldap_state *state)
{
	return state->ldap_struct;
}

bool smbldap_get_paged_results(struct smbldap_state *state)
{
	return state->paged_results;
}

void smbldap_set_paged_results(struct smbldap_state *state,
			       bool paged_results)
{
	state->paged_results = paged_results;
}

void smbldap_set_bind_callback(struct smbldap_state *state,
			       smbldap_bind_callback_fn callback,
			       void *callback_data)
{
	state->bind_callback = callback;
	state->bind_callback_data = callback_data;
}
/*******************************************************************
 Search an attribute and return the first value found.
******************************************************************/

 bool smbldap_get_single_attribute (LDAP * ldap_struct, LDAPMessage * entry,
				    const char *attribute, char *value,
				    int max_len)
{
	char **values;
	size_t size = 0;

	if ( !attribute )
		return False;

	value[0] = '\0';

	if ((values = ldap_get_values (ldap_struct, entry, attribute)) == NULL) {
		DEBUG (10, ("smbldap_get_single_attribute: [%s] = [<does not exist>]\n", attribute));

		return False;
	}

	if (!convert_string(CH_UTF8, CH_UNIX,values[0], -1, value, max_len, &size)) {
		DEBUG(1, ("smbldap_get_single_attribute: string conversion of [%s] = [%s] failed!\n", 
			  attribute, values[0]));
		ldap_value_free(values);
		return False;
	}

	ldap_value_free(values);
#ifdef DEBUG_PASSWORDS
	DEBUG (100, ("smbldap_get_single_attribute: [%s] = [%s]\n", attribute, value));
#endif	
	return True;
}

 char * smbldap_talloc_single_attribute(LDAP *ldap_struct, LDAPMessage *entry,
					const char *attribute,
					TALLOC_CTX *mem_ctx)
{
	char **values;
	char *result;
	size_t converted_size;

	if (attribute == NULL) {
		return NULL;
	}

	values = ldap_get_values(ldap_struct, entry, attribute);

	if (values == NULL) {
		DEBUG(10, ("attribute %s does not exist\n", attribute));
		return NULL;
	}

	if (ldap_count_values(values) != 1) {
		DEBUG(10, ("attribute %s has %d values, expected only one\n",
			   attribute, ldap_count_values(values)));
		ldap_value_free(values);
		return NULL;
	}

	if (!pull_utf8_talloc(mem_ctx, &result, values[0], &converted_size)) {
		DEBUG(10, ("pull_utf8_talloc failed\n"));
		ldap_value_free(values);
		return NULL;
	}

	ldap_value_free(values);

#ifdef DEBUG_PASSWORDS
	DEBUG (100, ("smbldap_get_single_attribute: [%s] = [%s]\n",
		     attribute, result));
#endif	
	return result;
}

 char * smbldap_talloc_first_attribute(LDAP *ldap_struct, LDAPMessage *entry,
				       const char *attribute,
				       TALLOC_CTX *mem_ctx)
{
	char **values;
	char *result;
	size_t converted_size;

	if (attribute == NULL) {
		return NULL;
	}

	values = ldap_get_values(ldap_struct, entry, attribute);

	if (values == NULL) {
		DEBUG(10, ("attribute %s does not exist\n", attribute));
		return NULL;
	}

	if (!pull_utf8_talloc(mem_ctx, &result, values[0], &converted_size)) {
		DEBUG(10, ("pull_utf8_talloc failed\n"));
		ldap_value_free(values);
		return NULL;
	}

	ldap_value_free(values);

#ifdef DEBUG_PASSWORDS
	DEBUG (100, ("smbldap_get_first_attribute: [%s] = [%s]\n",
		     attribute, result));
#endif
	return result;
}

 char * smbldap_talloc_smallest_attribute(LDAP *ldap_struct, LDAPMessage *entry,
					  const char *attribute,
					  TALLOC_CTX *mem_ctx)
{
	char **values;
	char *result;
	size_t converted_size;
	int i, num_values;

	if (attribute == NULL) {
		return NULL;
	}

	values = ldap_get_values(ldap_struct, entry, attribute);

	if (values == NULL) {
		DEBUG(10, ("attribute %s does not exist\n", attribute));
		return NULL;
	}

	if (!pull_utf8_talloc(mem_ctx, &result, values[0], &converted_size)) {
		DEBUG(10, ("pull_utf8_talloc failed\n"));
		ldap_value_free(values);
		return NULL;
	}

	num_values = ldap_count_values(values);

	for (i=1; i<num_values; i++) {
		char *tmp;

		if (!pull_utf8_talloc(mem_ctx, &tmp, values[i],
				      &converted_size)) {
			DEBUG(10, ("pull_utf8_talloc failed\n"));
			TALLOC_FREE(result);
			ldap_value_free(values);
			return NULL;
		}

		if (strcasecmp_m(tmp, result) < 0) {
			TALLOC_FREE(result);
			result = tmp;
		} else {
			TALLOC_FREE(tmp);
		}
	}

	ldap_value_free(values);

#ifdef DEBUG_PASSWORDS
	DEBUG (100, ("smbldap_get_single_attribute: [%s] = [%s]\n",
		     attribute, result));
#endif
	return result;
}

 bool smbldap_talloc_single_blob(TALLOC_CTX *mem_ctx, LDAP *ld,
				 LDAPMessage *msg, const char *attrib,
				 DATA_BLOB *blob)
{
	struct berval **values;

	values = ldap_get_values_len(ld, msg, attrib);
	if (!values) {
		return false;
	}

	if (ldap_count_values_len(values) != 1) {
		DEBUG(10, ("Expected one value for %s, got %d\n", attrib,
			   ldap_count_values_len(values)));
		return false;
	}

	*blob = data_blob_talloc(mem_ctx, values[0]->bv_val,
				 values[0]->bv_len);
	ldap_value_free_len(values);

	return (blob->data != NULL);
}

 bool smbldap_pull_sid(LDAP *ld, LDAPMessage *msg, const char *attrib,
		       struct dom_sid *sid)
{
	DATA_BLOB blob;
	ssize_t ret;

	if (!smbldap_talloc_single_blob(talloc_tos(), ld, msg, attrib,
					&blob)) {
		return false;
	}
	ret = sid_parse(blob.data, blob.length, sid);
	TALLOC_FREE(blob.data);
	return (ret != -1);
}

 static int ldapmsg_destructor(LDAPMessage **result) {
	ldap_msgfree(*result);
	return 0;
}

 void smbldap_talloc_autofree_ldapmsg(TALLOC_CTX *mem_ctx, LDAPMessage *result)
{
	LDAPMessage **handle;

	if (result == NULL) {
		return;
	}

	handle = talloc(mem_ctx, LDAPMessage *);
	SMB_ASSERT(handle != NULL);

	*handle = result;
	talloc_set_destructor(handle, ldapmsg_destructor);
}

 static int ldapmod_destructor(LDAPMod ***mod) {
	ldap_mods_free(*mod, True);
	return 0;
}

 void smbldap_talloc_autofree_ldapmod(TALLOC_CTX *mem_ctx, LDAPMod **mod)
{
	LDAPMod ***handle;

	if (mod == NULL) {
		return;
	}

	handle = talloc(mem_ctx, LDAPMod **);
	SMB_ASSERT(handle != NULL);

	*handle = mod;
	talloc_set_destructor(handle, ldapmod_destructor);
}

/************************************************************************
 Routine to manage the LDAPMod structure array
 manage memory used by the array, by each struct, and values
 ***********************************************************************/

static void smbldap_set_mod_internal(LDAPMod *** modlist, int modop, const char *attribute, const char *value, const DATA_BLOB *blob)
{
	LDAPMod **mods;
	int i;
	int j;

	mods = *modlist;

	/* sanity checks on the mod values */

	if (attribute == NULL || *attribute == '\0') {
		return;	
	}

#if 0	/* commented out after discussion with abartlet.  Do not re-enable.
	   left here so other do not re-add similar code   --jerry */
       	if (value == NULL || *value == '\0')
		return;
#endif

	if (mods == NULL) {
		mods = SMB_MALLOC_P(LDAPMod *);
		if (mods == NULL) {
			smb_panic("smbldap_set_mod: out of memory!");
			/* notreached. */
		}
		mods[0] = NULL;
	}

	for (i = 0; mods[i] != NULL; ++i) {
		if (mods[i]->mod_op == modop && strequal(mods[i]->mod_type, attribute))
			break;
	}

	if (mods[i] == NULL) {
		mods = SMB_REALLOC_ARRAY (mods, LDAPMod *, i + 2);
		if (mods == NULL) {
			smb_panic("smbldap_set_mod: out of memory!");
			/* notreached. */
		}
		mods[i] = SMB_MALLOC_P(LDAPMod);
		if (mods[i] == NULL) {
			smb_panic("smbldap_set_mod: out of memory!");
			/* notreached. */
		}
		mods[i]->mod_op = modop;
		mods[i]->mod_values = NULL;
		mods[i]->mod_type = SMB_STRDUP(attribute);
		mods[i + 1] = NULL;
	}

	if (blob && (modop & LDAP_MOD_BVALUES)) {
		j = 0;
		if (mods[i]->mod_bvalues != NULL) {
			for (; mods[i]->mod_bvalues[j] != NULL; j++);
		}
		mods[i]->mod_bvalues = SMB_REALLOC_ARRAY(mods[i]->mod_bvalues, struct berval *, j + 2);

		if (mods[i]->mod_bvalues == NULL) {
			smb_panic("smbldap_set_mod: out of memory!");
			/* notreached. */
		}

		mods[i]->mod_bvalues[j] = SMB_MALLOC_P(struct berval);
		SMB_ASSERT(mods[i]->mod_bvalues[j] != NULL);

		mods[i]->mod_bvalues[j]->bv_val = (char *)smb_memdup(blob->data, blob->length);
		SMB_ASSERT(mods[i]->mod_bvalues[j]->bv_val != NULL);
		mods[i]->mod_bvalues[j]->bv_len = blob->length;

		mods[i]->mod_bvalues[j + 1] = NULL;
	} else if (value != NULL) {
		char *utf8_value = NULL;
		size_t converted_size;

		j = 0;
		if (mods[i]->mod_values != NULL) {
			for (; mods[i]->mod_values[j] != NULL; j++);
		}
		mods[i]->mod_values = SMB_REALLOC_ARRAY(mods[i]->mod_values, char *, j + 2);

		if (mods[i]->mod_values == NULL) {
			smb_panic("smbldap_set_mod: out of memory!");
			/* notreached. */
		}

		if (!push_utf8_talloc(talloc_tos(), &utf8_value, value, &converted_size)) {
			smb_panic("smbldap_set_mod: String conversion failure!");
			/* notreached. */
		}

		mods[i]->mod_values[j] = SMB_STRDUP(utf8_value);
		TALLOC_FREE(utf8_value);
		SMB_ASSERT(mods[i]->mod_values[j] != NULL);

		mods[i]->mod_values[j + 1] = NULL;
	}
	*modlist = mods;
}

 void smbldap_set_mod (LDAPMod *** modlist, int modop, const char *attribute, const char *value)
{
	smbldap_set_mod_internal(modlist, modop, attribute, value, NULL);
}

 void smbldap_set_mod_blob(LDAPMod *** modlist, int modop, const char *attribute, const DATA_BLOB *value)
{
	smbldap_set_mod_internal(modlist, modop | LDAP_MOD_BVALUES, attribute, NULL, value);
}

/**********************************************************************
  Set attribute to newval in LDAP, regardless of what value the
  attribute had in LDAP before.
*********************************************************************/

static void smbldap_make_mod_internal(LDAP *ldap_struct, LDAPMessage *existing,
				      LDAPMod ***mods,
				      const char *attribute, int op,
				      const char *newval,
				      const DATA_BLOB *newblob)
{
	char oldval[2048]; /* current largest allowed value is mungeddial */
	bool existed;
	DATA_BLOB oldblob = data_blob_null;

	if (existing != NULL) {
		if (op & LDAP_MOD_BVALUES) {
			existed = smbldap_talloc_single_blob(talloc_tos(), ldap_struct, existing, attribute, &oldblob);
		} else {
			existed = smbldap_get_single_attribute(ldap_struct, existing, attribute, oldval, sizeof(oldval));
		}
	} else {
		existed = False;
		*oldval = '\0';
	}

	if (existed) {
		bool equal = false;
		if (op & LDAP_MOD_BVALUES) {
			equal = (newblob && (data_blob_cmp(&oldblob, newblob) == 0));
		} else {
			/* all of our string attributes are case insensitive */
			equal = (newval && (strcasecmp_m(oldval, newval) == 0));
		}

		if (equal) {
			/* Believe it or not, but LDAP will deny a delete and
			   an add at the same time if the values are the
			   same... */
			DEBUG(10,("smbldap_make_mod: attribute |%s| not changed.\n", attribute));
			return;
		}

		/* There has been no value before, so don't delete it.
		 * Here's a possible race: We might end up with
		 * duplicate attributes */
		/* By deleting exactly the value we found in the entry this
		 * should be race-free in the sense that the LDAP-Server will
		 * deny the complete operation if somebody changed the
		 * attribute behind our back. */
		/* This will also allow modifying single valued attributes 
		 * in Novell NDS. In NDS you have to first remove attribute and then
		 * you could add new value */

		if (op & LDAP_MOD_BVALUES) {
			DEBUG(10,("smbldap_make_mod: deleting attribute |%s| blob\n", attribute));
			smbldap_set_mod_blob(mods, LDAP_MOD_DELETE, attribute, &oldblob);
		} else {
			DEBUG(10,("smbldap_make_mod: deleting attribute |%s| values |%s|\n", attribute, oldval));
			smbldap_set_mod(mods, LDAP_MOD_DELETE, attribute, oldval);
		}
	}

	/* Regardless of the real operation (add or modify)
	   we add the new value here. We rely on deleting
	   the old value, should it exist. */

	if (op & LDAP_MOD_BVALUES) {
		if (newblob && newblob->length) {
			DEBUG(10,("smbldap_make_mod: adding attribute |%s| blob\n", attribute));
			smbldap_set_mod_blob(mods, LDAP_MOD_ADD, attribute, newblob);
		}
	} else {
		if ((newval != NULL) && (strlen(newval) > 0)) {
			DEBUG(10,("smbldap_make_mod: adding attribute |%s| value |%s|\n", attribute, newval));
			smbldap_set_mod(mods, LDAP_MOD_ADD, attribute, newval);
		}
	}
}

 void smbldap_make_mod(LDAP *ldap_struct, LDAPMessage *existing,
		      LDAPMod ***mods,
		      const char *attribute, const char *newval)
{
	smbldap_make_mod_internal(ldap_struct, existing, mods, attribute,
				  0, newval, NULL);
}

 void smbldap_make_mod_blob(LDAP *ldap_struct, LDAPMessage *existing,
			    LDAPMod ***mods,
			    const char *attribute, const DATA_BLOB *newblob)
{
	smbldap_make_mod_internal(ldap_struct, existing, mods, attribute,
				  LDAP_MOD_BVALUES, NULL, newblob);
}

/**********************************************************************
 Some varients of the LDAP rebind code do not pass in the third 'arg' 
 pointer to a void*, so we try and work around it by assuming that the 
 value of the 'LDAP *' pointer is the same as the one we had passed in
 **********************************************************************/

struct smbldap_state_lookup {
	LDAP *ld;
	struct smbldap_state *smbldap_state;
	struct smbldap_state_lookup *prev, *next;
};

static struct smbldap_state_lookup *smbldap_state_lookup_list;

static struct smbldap_state *smbldap_find_state(LDAP *ld) 
{
	struct smbldap_state_lookup *t;

	for (t = smbldap_state_lookup_list; t; t = t->next) {
		if (t->ld == ld) {
			return t->smbldap_state;
		}
	}
	return NULL;
}

static void smbldap_delete_state(struct smbldap_state *smbldap_state) 
{
	struct smbldap_state_lookup *t;

	for (t = smbldap_state_lookup_list; t; t = t->next) {
		if (t->smbldap_state == smbldap_state) {
			DLIST_REMOVE(smbldap_state_lookup_list, t);
			SAFE_FREE(t);
			return;
		}
	}
}

static void smbldap_store_state(LDAP *ld, struct smbldap_state *smbldap_state) 
{
	struct smbldap_state *tmp_ldap_state;
	struct smbldap_state_lookup *t;

	if ((tmp_ldap_state = smbldap_find_state(ld))) {
		SMB_ASSERT(tmp_ldap_state == smbldap_state);
		return;
	}

	t = SMB_XMALLOC_P(struct smbldap_state_lookup);
	ZERO_STRUCTP(t);

	DLIST_ADD_END(smbldap_state_lookup_list, t);
	t->ld = ld;
	t->smbldap_state = smbldap_state;
}

/********************************************************************
 start TLS on an existing LDAP connection
*******************************************************************/

int smbldap_start_tls(LDAP *ldap_struct, int version)
{ 
#ifdef LDAP_OPT_X_TLS
	int rc,tls;
#endif

	if (lp_ldap_ssl() != LDAP_SSL_START_TLS) {
		return LDAP_SUCCESS;
	}

#ifdef LDAP_OPT_X_TLS
	/* check if we use ldaps already */
	ldap_get_option(ldap_struct, LDAP_OPT_X_TLS, &tls);
	if (tls == LDAP_OPT_X_TLS_HARD) {
		return LDAP_SUCCESS;
	}

	if (version != LDAP_VERSION3) {
		DEBUG(0, ("Need LDAPv3 for Start TLS\n"));
		return LDAP_OPERATIONS_ERROR;
	}

	if ((rc = ldap_start_tls_s (ldap_struct, NULL, NULL)) != LDAP_SUCCESS)	{
		DEBUG(0,("Failed to issue the StartTLS instruction: %s\n",
			 ldap_err2string(rc)));
		return rc;
	}

	DEBUG (3, ("StartTLS issued: using a TLS connection\n"));
	return LDAP_SUCCESS;
#else
	DEBUG(0,("StartTLS not supported by LDAP client libraries!\n"));
	return LDAP_OPERATIONS_ERROR;
#endif
}

/********************************************************************
 setup a connection to the LDAP server based on a uri
*******************************************************************/

static int smb_ldap_setup_conn(LDAP **ldap_struct, const char *uri)
{
	int rc;

	DEBUG(10, ("smb_ldap_setup_connection: %s\n", uri));

#ifdef HAVE_LDAP_INITIALIZE

	rc = ldap_initialize(ldap_struct, uri);
	if (rc) {
		DEBUG(0, ("ldap_initialize: %s\n", ldap_err2string(rc)));
		return rc;
	}

	if (lp_ldap_follow_referral() != Auto) {
		rc = ldap_set_option(*ldap_struct, LDAP_OPT_REFERRALS,
		     lp_ldap_follow_referral() ? LDAP_OPT_ON : LDAP_OPT_OFF);
		if (rc != LDAP_SUCCESS)
			DEBUG(0, ("Failed to set LDAP_OPT_REFERRALS: %s\n",
				ldap_err2string(rc)));
	}

	return LDAP_SUCCESS;
#else 

	/* Parse the string manually */

	{
		int port = 0;
		fstring protocol;
		fstring host;
		SMB_ASSERT(sizeof(protocol)>10 && sizeof(host)>254);


		/* skip leading "URL:" (if any) */
		if ( strnequal( uri, "URL:", 4 ) ) {
			uri += 4;
		}

		sscanf(uri, "%10[^:]://%254[^:/]:%d", protocol, host, &port);

		if (port == 0) {
			if (strequal(protocol, "ldap")) {
				port = LDAP_PORT;
			} else if (strequal(protocol, "ldaps")) {
				port = LDAPS_PORT;
			} else {
				DEBUG(0, ("unrecognised protocol (%s)!\n", protocol));
			}
		}

		if ((*ldap_struct = ldap_init(host, port)) == NULL)	{
			DEBUG(0, ("ldap_init failed !\n"));
			return LDAP_OPERATIONS_ERROR;
		}

	        if (strequal(protocol, "ldaps")) {
#ifdef LDAP_OPT_X_TLS
			int tls = LDAP_OPT_X_TLS_HARD;
			if (ldap_set_option (*ldap_struct, LDAP_OPT_X_TLS, &tls) != LDAP_SUCCESS)
			{
				DEBUG(0, ("Failed to setup a TLS session\n"));
			}

			DEBUG(3,("LDAPS option set...!\n"));
#else
			DEBUG(0,("smbldap_open_connection: Secure connection not supported by LDAP client libraries!\n"));
			return LDAP_OPERATIONS_ERROR;
#endif /* LDAP_OPT_X_TLS */
		}
	}
#endif /* HAVE_LDAP_INITIALIZE */

	/* now set connection timeout */
#ifdef LDAP_X_OPT_CONNECT_TIMEOUT /* Netscape */
	{
		int ct = lp_ldap_connection_timeout()*1000;
		rc = ldap_set_option(*ldap_struct, LDAP_X_OPT_CONNECT_TIMEOUT, &ct);
		if (rc != LDAP_SUCCESS) {
			DEBUG(0,("Failed to setup an ldap connection timeout %d: %s\n",
				ct, ldap_err2string(rc)));
		}
	}
#elif defined (LDAP_OPT_NETWORK_TIMEOUT) /* OpenLDAP */
	{
		struct timeval ct;
		ct.tv_usec = 0;
		ct.tv_sec = lp_ldap_connection_timeout();
		rc = ldap_set_option(*ldap_struct, LDAP_OPT_NETWORK_TIMEOUT, &ct);
		if (rc != LDAP_SUCCESS) {
			DEBUG(0,("Failed to setup an ldap connection timeout %d: %s\n",
				(int)ct.tv_sec, ldap_err2string(rc)));
		}
	}
#endif

	return LDAP_SUCCESS;
}

/********************************************************************
 try to upgrade to Version 3 LDAP if not already, in either case return current
 version 
 *******************************************************************/

static int smb_ldap_upgrade_conn(LDAP *ldap_struct, int *new_version)
{
	int version;
	int rc;

	/* assume the worst */
	*new_version = LDAP_VERSION2;

	rc = ldap_get_option(ldap_struct, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (rc) {
		return rc;
	}

	if (version == LDAP_VERSION3) {
		*new_version = LDAP_VERSION3;
		return LDAP_SUCCESS;
	}

	/* try upgrade */
	version = LDAP_VERSION3;
	rc = ldap_set_option (ldap_struct, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (rc) {
		return rc;
	}

	*new_version = LDAP_VERSION3;
	return LDAP_SUCCESS;
}

/*******************************************************************
 open a connection to the ldap server (just until the bind)
 ******************************************************************/

int smbldap_setup_full_conn(LDAP **ldap_struct, const char *uri)
{
	int rc, version;

	rc = smb_ldap_setup_conn(ldap_struct, uri);
	if (rc) {
		return rc;
	}

	rc = smb_ldap_upgrade_conn(*ldap_struct, &version);
	if (rc) {
		return rc;
	}

	rc = smbldap_start_tls(*ldap_struct, version);
	if (rc) {
		return rc;
	}

	return LDAP_SUCCESS;
}

/*******************************************************************
 open a connection to the ldap server.
******************************************************************/
static int smbldap_open_connection (struct smbldap_state *ldap_state)

{
	int rc = LDAP_SUCCESS;
	int version;
	int deref;
	LDAP **ldap_struct = &ldap_state->ldap_struct;

	rc = smb_ldap_setup_conn(ldap_struct, ldap_state->uri);
	if (rc) {
		return rc;
	}

	/* Store the LDAP pointer in a lookup list */

	smbldap_store_state(*ldap_struct, ldap_state);

	/* Upgrade to LDAPv3 if possible */

	rc = smb_ldap_upgrade_conn(*ldap_struct, &version);
	if (rc) {
		return rc;
	}

	/* Start TLS if required */

	rc = smbldap_start_tls(*ldap_struct, version);
	if (rc) {
		return rc;
	}

	/* Set alias dereferencing method */
	deref = lp_ldap_deref();
	if (deref != -1) {
		if (ldap_set_option (*ldap_struct, LDAP_OPT_DEREF, &deref) != LDAP_OPT_SUCCESS) {
			DEBUG(1,("smbldap_open_connection: Failed to set dereferencing method: %d\n", deref));
		} else {
			DEBUG(5,("Set dereferencing method: %d\n", deref));
		}
	}

	DEBUG(2, ("smbldap_open_connection: connection opened\n"));
	return rc;
}

/*******************************************************************
 a rebind function for authenticated referrals
 This version takes a void* that we can shove useful stuff in :-)
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#else
static int rebindproc_with_state  (LDAP * ld, char **whop, char **credp, 
				   int *methodp, int freeit, void *arg)
{
	struct smbldap_state *ldap_state = arg;
	struct timespec ts;

	/** @TODO Should we be doing something to check what servers we rebind to?
	    Could we get a referral to a machine that we don't want to give our
	    username and password to? */

	if (freeit) {
		SAFE_FREE(*whop);
		if (*credp) {
			memset(*credp, '\0', strlen(*credp));
		}
		SAFE_FREE(*credp);
	} else {
		DEBUG(5,("rebind_proc_with_state: Rebinding as \"%s\"\n", 
			  ldap_state->bind_dn?ldap_state->bind_dn:"[Anonymous bind]"));

		if (ldap_state->anonymous) {
			*whop = NULL;
			*credp = NULL;
		} else {
			*whop = SMB_STRDUP(ldap_state->bind_dn);
			if (!*whop) {
				return LDAP_NO_MEMORY;
			}
			*credp = SMB_STRDUP(ldap_state->bind_secret);
			if (!*credp) {
				SAFE_FREE(*whop);
				return LDAP_NO_MEMORY;
			}
		}
		*methodp = LDAP_AUTH_SIMPLE;
	}

	clock_gettime_mono(&ts);
	ldap_state->last_rebind = convert_timespec_to_timeval(ts);

	return 0;
}
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 a rebind function for authenticated referrals
 This version takes a void* that we can shove useful stuff in :-)
 and actually does the connection.
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
static int rebindproc_connect_with_state (LDAP *ldap_struct, 
					  LDAP_CONST char *url, 
					  ber_tag_t request,
					  ber_int_t msgid, void *arg)
{
	struct smbldap_state *ldap_state =
		(struct smbldap_state *)arg;
	int rc;
	struct timespec ts;
	int version;

	DEBUG(5,("rebindproc_connect_with_state: Rebinding to %s as \"%s\"\n", 
		 url, ldap_state->bind_dn?ldap_state->bind_dn:"[Anonymous bind]"));

	/* call START_TLS again (ldaps:// is handled by the OpenLDAP library
	 * itself) before rebinding to another LDAP server to avoid to expose
	 * our credentials. At least *try* to secure the connection - Guenther */

	smb_ldap_upgrade_conn(ldap_struct, &version);
	smbldap_start_tls(ldap_struct, version);

	/** @TODO Should we be doing something to check what servers we rebind to?
	    Could we get a referral to a machine that we don't want to give our
	    username and password to? */

	rc = ldap_simple_bind_s(ldap_struct, ldap_state->bind_dn, ldap_state->bind_secret);

	/* only set the last rebind timestamp when we did rebind after a
	 * non-read LDAP operation. That way we avoid the replication sleep
	 * after a simple redirected search operation - Guenther */

	switch (request) {

		case LDAP_REQ_MODIFY:
		case LDAP_REQ_ADD:
		case LDAP_REQ_DELETE:
		case LDAP_REQ_MODDN:
		case LDAP_REQ_EXTENDED:
			DEBUG(10,("rebindproc_connect_with_state: "
				"setting last_rebind timestamp "
				"(req: 0x%02x)\n", (unsigned int)request));
			clock_gettime_mono(&ts);
			ldap_state->last_rebind = convert_timespec_to_timeval(ts);
			break;
		default:
			ZERO_STRUCT(ldap_state->last_rebind);
			break;
	}

	return rc;
}
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 Add a rebind function for authenticated referrals
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#else
# if LDAP_SET_REBIND_PROC_ARGS == 2
static int rebindproc (LDAP *ldap_struct, char **whop, char **credp,
		       int *method, int freeit )
{
	struct smbldap_state *ldap_state = smbldap_find_state(ldap_struct);

	return rebindproc_with_state(ldap_struct, whop, credp,
				     method, freeit, ldap_state);
}
# endif /*LDAP_SET_REBIND_PROC_ARGS == 2*/
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 a rebind function for authenticated referrals
 this also does the connection, but no void*.
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
# if LDAP_SET_REBIND_PROC_ARGS == 2
static int rebindproc_connect (LDAP * ld, LDAP_CONST char *url, int request,
			       ber_int_t msgid)
{
	struct smbldap_state *ldap_state = smbldap_find_state(ld);

	return rebindproc_connect_with_state(ld, url, (ber_tag_t)request, msgid, 
					     ldap_state);
}
# endif /*LDAP_SET_REBIND_PROC_ARGS == 2*/
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 connect to the ldap server under system privilege.
******************************************************************/
static int smbldap_connect_system(struct smbldap_state *ldap_state)
{
	LDAP *ldap_struct = smbldap_get_ldap(ldap_state);
	int rc;
	int version;

	/* removed the sasl_bind_s "EXTERNAL" stuff, as my testsuite 
	   (OpenLDAP) doesn't seem to support it */

	DEBUG(10,("ldap_connect_system: Binding to ldap server %s as \"%s\"\n",
		  ldap_state->uri, ldap_state->bind_dn));

#ifdef HAVE_LDAP_SET_REBIND_PROC
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
# if LDAP_SET_REBIND_PROC_ARGS == 2	
	ldap_set_rebind_proc(ldap_struct, &rebindproc_connect);	
# endif
# if LDAP_SET_REBIND_PROC_ARGS == 3	
	ldap_set_rebind_proc(ldap_struct, &rebindproc_connect_with_state, (void *)ldap_state);	
# endif
#else /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/
# if LDAP_SET_REBIND_PROC_ARGS == 2	
	ldap_set_rebind_proc(ldap_struct, &rebindproc);	
# endif
# if LDAP_SET_REBIND_PROC_ARGS == 3	
	ldap_set_rebind_proc(ldap_struct, &rebindproc_with_state, (void *)ldap_state);	
# endif
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/
#endif

	/* When there is an alternative bind callback is set,
	   attempt to use it to perform the bind */
	if (ldap_state->bind_callback != NULL) {
		/* We have to allow bind callback to be run under become_root/unbecome_root
		   to make sure within smbd the callback has proper write access to its resources,
		   like credential cache. This is similar to passdb case where this callback is supposed
		   to be used. When used outside smbd, become_root()/unbecome_root() are no-op.
		*/
		become_root();
		rc = ldap_state->bind_callback(ldap_struct, ldap_state, ldap_state->bind_callback_data);
		unbecome_root();
	} else {
		rc = ldap_simple_bind_s(ldap_struct, ldap_state->bind_dn, ldap_state->bind_secret);
	}

	if (rc != LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(smbldap_get_ldap(ldap_state),
				LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(ldap_state->num_failures ? 2 : 0,
		      ("failed to bind to server %s with dn=\"%s\" Error: %s\n\t%s\n",
			       ldap_state->uri,
			       ldap_state->bind_dn ? ldap_state->bind_dn : "[Anonymous bind]",
			       ldap_err2string(rc),
			       ld_error ? ld_error : "(unknown)"));
		SAFE_FREE(ld_error);
		ldap_state->num_failures++;
		goto done;
	}

	ldap_state->num_failures = 0;
	ldap_state->paged_results = False;

	ldap_get_option(smbldap_get_ldap(ldap_state),
			LDAP_OPT_PROTOCOL_VERSION, &version);

	if (smbldap_has_control(smbldap_get_ldap(ldap_state), ADS_PAGE_CTL_OID)
	    && version == 3) {
		ldap_state->paged_results = True;
	}

	DEBUG(3, ("ldap_connect_system: successful connection to the LDAP server\n"));
	DEBUGADD(10, ("ldap_connect_system: LDAP server %s support paged results\n", 
		ldap_state->paged_results ? "does" : "does not"));
done:
	if (rc != 0) {
		ldap_unbind(ldap_struct);
		ldap_state->ldap_struct = NULL;
	}
	return rc;
}

static void smbldap_idle_fn(struct tevent_context *tevent_ctx,
			    struct tevent_timer *te,
			    struct timeval now_abs,
			    void *private_data);

/**********************************************************************
 Connect to LDAP server (called before every ldap operation)
*********************************************************************/
static int smbldap_open(struct smbldap_state *ldap_state)
{
	int rc, opt_rc;
	bool reopen = False;
	SMB_ASSERT(ldap_state);

	if ((smbldap_get_ldap(ldap_state) != NULL) &&
	    ((ldap_state->last_ping + SMBLDAP_DONT_PING_TIME) <
	     time_mono(NULL))) {

#ifdef HAVE_UNIXSOCKET
		struct sockaddr_un addr;
#else
		struct sockaddr_storage addr;
#endif
		socklen_t len = sizeof(addr);
		int sd;

		opt_rc = ldap_get_option(smbldap_get_ldap(ldap_state),
					 LDAP_OPT_DESC, &sd);
		if (opt_rc == 0 && (getpeername(sd, (struct sockaddr *) &addr, &len)) < 0 )
			reopen = True;

#ifdef HAVE_UNIXSOCKET
		if (opt_rc == 0 && addr.sun_family == AF_UNIX)
			reopen = True;
#endif
		if (reopen) {
		    	/* the other end has died. reopen. */
			ldap_unbind(smbldap_get_ldap(ldap_state));
			ldap_state->ldap_struct = NULL;
		    	ldap_state->last_ping = (time_t)0;
		} else {
			ldap_state->last_ping = time_mono(NULL);
		} 
    	}

	if (smbldap_get_ldap(ldap_state) != NULL) {
		DEBUG(11,("smbldap_open: already connected to the LDAP server\n"));
		return LDAP_SUCCESS;
	}

	if ((rc = smbldap_open_connection(ldap_state))) {
		return rc;
	}

	if ((rc = smbldap_connect_system(ldap_state))) {
		return rc;
	}


	ldap_state->last_ping = time_mono(NULL);
	ldap_state->pid = getpid();

	TALLOC_FREE(ldap_state->idle_event);

	if (ldap_state->tevent_context != NULL) {
		ldap_state->idle_event = tevent_add_timer(
			ldap_state->tevent_context, ldap_state,
			timeval_current_ofs(SMBLDAP_IDLE_TIME, 0),
			smbldap_idle_fn, ldap_state);
	}

	DEBUG(4,("The LDAP server is successfully connected\n"));

	return LDAP_SUCCESS;
}

/**********************************************************************
Disconnect from LDAP server 
*********************************************************************/
static NTSTATUS smbldap_close(struct smbldap_state *ldap_state)
{
	if (!ldap_state)
		return NT_STATUS_INVALID_PARAMETER;

	if (smbldap_get_ldap(ldap_state) != NULL) {
		ldap_unbind(smbldap_get_ldap(ldap_state));
		ldap_state->ldap_struct = NULL;
	}

	smbldap_delete_state(ldap_state);

	TALLOC_FREE(ldap_state->idle_event);

	DEBUG(5,("The connection to the LDAP server was closed\n"));
	/* maybe free the results here --metze */

	return NT_STATUS_OK;
}

static SIG_ATOMIC_T got_alarm;

static void gotalarm_sig(int dummy)
{
	got_alarm = 1;
}

static time_t calc_ldap_abs_endtime(int ldap_to)
{
	if (ldap_to == 0) {
		/* No timeout - don't
		   return a value for
		   the alarm. */
		return (time_t)0;
	}

	/* Make the alarm time one second beyond
	   the timout we're setting for the
	   remote search timeout, to allow that
	   to fire in preference. */

	return time_mono(NULL)+ldap_to+1;
}

static int end_ldap_local_alarm(time_t absolute_endtime, int rc)
{
	if (absolute_endtime) {
		alarm(0);
		CatchSignal(SIGALRM, SIG_IGN);
		if (got_alarm) {
			/* Client timeout error code. */
			got_alarm = 0;
			return LDAP_TIMEOUT;
		}
	}
	return rc;
}

static void setup_ldap_local_alarm(struct smbldap_state *ldap_state, time_t absolute_endtime)
{
	time_t now = time_mono(NULL);

	if (absolute_endtime) {
		got_alarm = 0;
		CatchSignal(SIGALRM, gotalarm_sig);
		alarm(absolute_endtime - now);
	}

	if (ldap_state->pid != getpid()) {
		smbldap_close(ldap_state);
	}
}

static void get_ldap_errs(struct smbldap_state *ldap_state, char **pp_ld_error, int *p_ld_errno)
{
	ldap_get_option(smbldap_get_ldap(ldap_state),
			LDAP_OPT_ERROR_NUMBER, p_ld_errno);

	ldap_get_option(smbldap_get_ldap(ldap_state),
			LDAP_OPT_ERROR_STRING, pp_ld_error);
}

static int get_cached_ldap_connect(struct smbldap_state *ldap_state, time_t abs_endtime)
{
	int attempts = 0;

	while (1) {
		int rc;
		time_t now;

		now = time_mono(NULL);
		ldap_state->last_use = now;

		if (abs_endtime && now > abs_endtime) {
			smbldap_close(ldap_state);
			return LDAP_TIMEOUT;
		}

		rc = smbldap_open(ldap_state);

		if (rc == LDAP_SUCCESS) {
			return LDAP_SUCCESS;
		}

		attempts++;
		DEBUG(1, ("Connection to LDAP server failed for the "
			"%d try!\n", attempts));

		if (rc == LDAP_INSUFFICIENT_ACCESS) {
			/* The fact that we are non-root or any other
			 * access-denied condition will not change in the next
			 * round of trying */
			return rc;
		}

		if (got_alarm) {
			smbldap_close(ldap_state);
			return LDAP_TIMEOUT;
		}

		smb_msleep(1000);

		if (got_alarm) {
			smbldap_close(ldap_state);
			return LDAP_TIMEOUT;
		}
	}
}

/*********************************************************************
 ********************************************************************/

static int smbldap_search_ext(struct smbldap_state *ldap_state,
			      const char *base, int scope, const char *filter, 
			      const char *attrs[], int attrsonly,
			      LDAPControl **sctrls, LDAPControl **cctrls, 
			      int sizelimit, LDAPMessage **res)
{
	int 		rc = LDAP_SERVER_DOWN;
	char           *utf8_filter;
	int		to = lp_ldap_timeout();
	time_t		abs_endtime = calc_ldap_abs_endtime(to);
	struct		timeval timeout;
	struct		timeval *timeout_ptr = NULL;
	size_t		converted_size;

	SMB_ASSERT(ldap_state);

	DEBUG(5,("smbldap_search_ext: base => [%s], filter => [%s], "
		 "scope => [%d]\n", base, filter, scope));

	if (ldap_state->last_rebind.tv_sec > 0) {
		struct timeval	tval;
		struct timespec ts;
		int64_t	tdiff = 0;
		int		sleep_time = 0;

		clock_gettime_mono(&ts);
		tval = convert_timespec_to_timeval(ts);

		tdiff = usec_time_diff(&tval, &ldap_state->last_rebind);
		tdiff /= 1000; /* Convert to milliseconds. */

		sleep_time = lp_ldap_replication_sleep()-(int)tdiff;
		sleep_time = MIN(sleep_time, MAX_LDAP_REPLICATION_SLEEP_TIME);

		if (sleep_time > 0) {
			/* we wait for the LDAP replication */
			DEBUG(5,("smbldap_search_ext: waiting %d milliseconds "
				 "for LDAP replication.\n",sleep_time));
			smb_msleep(sleep_time);
			DEBUG(5,("smbldap_search_ext: go on!\n"));
		}
		ZERO_STRUCT(ldap_state->last_rebind);
	}

	if (!push_utf8_talloc(talloc_tos(), &utf8_filter, filter, &converted_size)) {
		return LDAP_NO_MEMORY;
	}

	/* Setup remote timeout for the ldap_search_ext_s call. */
	if (to) {
		timeout.tv_sec = to;
		timeout.tv_usec = 0;
		timeout_ptr = &timeout;
	}

	setup_ldap_local_alarm(ldap_state, abs_endtime);

	while (1) {
		char *ld_error = NULL;
		int ld_errno;

		rc = get_cached_ldap_connect(ldap_state, abs_endtime);
		if (rc != LDAP_SUCCESS) {
			break;
		}

		rc = ldap_search_ext_s(smbldap_get_ldap(ldap_state),
				       base, scope,
				       utf8_filter,
				       discard_const_p(char *, attrs),
				       attrsonly, sctrls, cctrls, timeout_ptr,
				       sizelimit, res);
		if (rc == LDAP_SUCCESS) {
			break;
		}

		get_ldap_errs(ldap_state, &ld_error, &ld_errno);

		DEBUG(10, ("Failed search for base: %s, error: %d (%s) "
			   "(%s)\n", base, ld_errno,
			   ldap_err2string(rc),
			   ld_error ? ld_error : "unknown"));
		SAFE_FREE(ld_error);

		if (ld_errno != LDAP_SERVER_DOWN) {
			break;
		}
		ldap_unbind(smbldap_get_ldap(ldap_state));
		ldap_state->ldap_struct = NULL;
	}

	TALLOC_FREE(utf8_filter);
	return end_ldap_local_alarm(abs_endtime, rc);
}

int smbldap_search(struct smbldap_state *ldap_state, 
		   const char *base, int scope, const char *filter, 
		   const char *attrs[], int attrsonly, 
		   LDAPMessage **res)
{
	return smbldap_search_ext(ldap_state, base, scope, filter, attrs,
				  attrsonly, NULL, NULL, LDAP_NO_LIMIT, res);
}

int smbldap_search_paged(struct smbldap_state *ldap_state, 
			 const char *base, int scope, const char *filter, 
			 const char **attrs, int attrsonly, int pagesize,
			 LDAPMessage **res, void **cookie)
{
	LDAPControl     pr;
	LDAPControl 	**rcontrols;
	LDAPControl 	*controls[2] = { NULL, NULL};
	BerElement 	*cookie_be = NULL;
	struct berval 	*cookie_bv = NULL;
	int		tmp = 0, i, rc;
	bool 		critical = True;

	*res = NULL;

	DEBUG(3,("smbldap_search_paged: base => [%s], filter => [%s],"
		 "scope => [%d], pagesize => [%d]\n",
		 base, filter, scope, pagesize));

	cookie_be = ber_alloc_t(LBER_USE_DER);
	if (cookie_be == NULL) {
		DEBUG(0,("smbldap_create_page_control: ber_alloc_t returns "
			 "NULL\n"));
		return LDAP_NO_MEMORY;
	}

	/* construct cookie */
	if (*cookie != NULL) {
		ber_printf(cookie_be, "{iO}", (ber_int_t) pagesize, *cookie);
		ber_bvfree((struct berval *)*cookie); /* don't need it from last time */
		*cookie = NULL;
	} else {
		ber_printf(cookie_be, "{io}", (ber_int_t) pagesize, "", 0);
	}
	ber_flatten(cookie_be, &cookie_bv);

	pr.ldctl_oid = discard_const_p(char, ADS_PAGE_CTL_OID);
	pr.ldctl_iscritical = (char) critical;
	pr.ldctl_value.bv_len = cookie_bv->bv_len;
	pr.ldctl_value.bv_val = cookie_bv->bv_val;

	controls[0] = &pr;
	controls[1] = NULL;

	rc = smbldap_search_ext(ldap_state, base, scope, filter, attrs, 
				 0, controls, NULL, LDAP_NO_LIMIT, res);

	ber_free(cookie_be, 1);
	ber_bvfree(cookie_bv);

	if (rc != 0) {
		DEBUG(3,("smbldap_search_paged: smbldap_search_ext(%s) "
			 "failed with [%s]\n", filter, ldap_err2string(rc)));
		goto done;
	}

	DEBUG(3,("smbldap_search_paged: search was successful\n"));

	rc = ldap_parse_result(smbldap_get_ldap(ldap_state), *res, NULL, NULL,
			       NULL, NULL, &rcontrols,  0);
	if (rc != 0) {
		DEBUG(3,("smbldap_search_paged: ldap_parse_result failed " \
			 "with [%s]\n", ldap_err2string(rc)));
		goto done;
	}

	if (rcontrols == NULL)
		goto done;

	for (i=0; rcontrols[i]; i++) {

		if (strcmp(ADS_PAGE_CTL_OID, rcontrols[i]->ldctl_oid) != 0)
			continue;

		cookie_be = ber_init(&rcontrols[i]->ldctl_value);
		ber_scanf(cookie_be,"{iO}", &tmp, &cookie_bv);
		/* the berval is the cookie, but must be freed when it is all
		   done */
		if (cookie_bv->bv_len)
			*cookie=ber_bvdup(cookie_bv);
		else
			*cookie=NULL;
		ber_bvfree(cookie_bv);
		ber_free(cookie_be, 1);
		break;
	}
	ldap_controls_free(rcontrols);
done:	
	return rc;
}

int smbldap_modify(struct smbldap_state *ldap_state, const char *dn, LDAPMod *attrs[])
{
	int 		rc = LDAP_SERVER_DOWN;
	char           *utf8_dn;
	time_t		abs_endtime = calc_ldap_abs_endtime(lp_ldap_timeout());
	size_t		converted_size;

	SMB_ASSERT(ldap_state);

	DEBUG(5,("smbldap_modify: dn => [%s]\n", dn ));

	if (!push_utf8_talloc(talloc_tos(), &utf8_dn, dn, &converted_size)) {
		return LDAP_NO_MEMORY;
	}

	setup_ldap_local_alarm(ldap_state, abs_endtime);

	while (1) {
		char *ld_error = NULL;
		int ld_errno;

		rc = get_cached_ldap_connect(ldap_state, abs_endtime);
		if (rc != LDAP_SUCCESS) {
			break;
		}

		rc = ldap_modify_s(smbldap_get_ldap(ldap_state), utf8_dn,
				   attrs);
		if (rc == LDAP_SUCCESS) {
			break;
		}

		get_ldap_errs(ldap_state, &ld_error, &ld_errno);

		DEBUG(10, ("Failed to modify dn: %s, error: %d (%s) "
			   "(%s)\n", dn, ld_errno,
			   ldap_err2string(rc),
			   ld_error ? ld_error : "unknown"));
		SAFE_FREE(ld_error);

		if (ld_errno != LDAP_SERVER_DOWN) {
			break;
		}
		ldap_unbind(smbldap_get_ldap(ldap_state));
		ldap_state->ldap_struct = NULL;
	}

	TALLOC_FREE(utf8_dn);
	return end_ldap_local_alarm(abs_endtime, rc);
}

int smbldap_add(struct smbldap_state *ldap_state, const char *dn, LDAPMod *attrs[])
{
	int 		rc = LDAP_SERVER_DOWN;
	char           *utf8_dn;
	time_t		abs_endtime = calc_ldap_abs_endtime(lp_ldap_timeout());
	size_t		converted_size;

	SMB_ASSERT(ldap_state);

	DEBUG(5,("smbldap_add: dn => [%s]\n", dn ));

	if (!push_utf8_talloc(talloc_tos(), &utf8_dn, dn, &converted_size)) {
		return LDAP_NO_MEMORY;
	}

	setup_ldap_local_alarm(ldap_state, abs_endtime);

	while (1) {
		char *ld_error = NULL;
		int ld_errno;

		rc = get_cached_ldap_connect(ldap_state, abs_endtime);
		if (rc != LDAP_SUCCESS) {
			break;
		}

		rc = ldap_add_s(smbldap_get_ldap(ldap_state), utf8_dn, attrs);
		if (rc == LDAP_SUCCESS) {
			break;
		}

		get_ldap_errs(ldap_state, &ld_error, &ld_errno);

		DEBUG(10, ("Failed to add dn: %s, error: %d (%s) "
			   "(%s)\n", dn, ld_errno,
			   ldap_err2string(rc),
			   ld_error ? ld_error : "unknown"));
		SAFE_FREE(ld_error);

		if (ld_errno != LDAP_SERVER_DOWN) {
			break;
		}
		ldap_unbind(smbldap_get_ldap(ldap_state));
		ldap_state->ldap_struct = NULL;
	}

	TALLOC_FREE(utf8_dn);
	return end_ldap_local_alarm(abs_endtime, rc);
}

int smbldap_delete(struct smbldap_state *ldap_state, const char *dn)
{
	int 		rc = LDAP_SERVER_DOWN;
	char           *utf8_dn;
	time_t		abs_endtime = calc_ldap_abs_endtime(lp_ldap_timeout());
	size_t		converted_size;

	SMB_ASSERT(ldap_state);

	DEBUG(5,("smbldap_delete: dn => [%s]\n", dn ));

	if (!push_utf8_talloc(talloc_tos(), &utf8_dn, dn, &converted_size)) {
		return LDAP_NO_MEMORY;
	}

	setup_ldap_local_alarm(ldap_state, abs_endtime);

	while (1) {
		char *ld_error = NULL;
		int ld_errno;

		rc = get_cached_ldap_connect(ldap_state, abs_endtime);
		if (rc != LDAP_SUCCESS) {
			break;
		}

		rc = ldap_delete_s(smbldap_get_ldap(ldap_state), utf8_dn);
		if (rc == LDAP_SUCCESS) {
			break;
		}

		get_ldap_errs(ldap_state, &ld_error, &ld_errno);

		DEBUG(10, ("Failed to delete dn: %s, error: %d (%s) "
			   "(%s)\n", dn, ld_errno,
			   ldap_err2string(rc),
			   ld_error ? ld_error : "unknown"));
		SAFE_FREE(ld_error);

		if (ld_errno != LDAP_SERVER_DOWN) {
			break;
		}
		ldap_unbind(smbldap_get_ldap(ldap_state));
		ldap_state->ldap_struct = NULL;
	}

	TALLOC_FREE(utf8_dn);
	return end_ldap_local_alarm(abs_endtime, rc);
}

int smbldap_extended_operation(struct smbldap_state *ldap_state, 
			       LDAP_CONST char *reqoid, struct berval *reqdata, 
			       LDAPControl **serverctrls, LDAPControl **clientctrls, 
			       char **retoidp, struct berval **retdatap)
{
	int 		rc = LDAP_SERVER_DOWN;
	time_t		abs_endtime = calc_ldap_abs_endtime(lp_ldap_timeout());

	if (!ldap_state)
		return (-1);

	setup_ldap_local_alarm(ldap_state, abs_endtime);

	while (1) {
		char *ld_error = NULL;
		int ld_errno;

		rc = get_cached_ldap_connect(ldap_state, abs_endtime);
		if (rc != LDAP_SUCCESS) {
			break;
		}

		rc = ldap_extended_operation_s(smbldap_get_ldap(ldap_state),
					       reqoid,
					       reqdata, serverctrls,
					       clientctrls, retoidp, retdatap);
		if (rc == LDAP_SUCCESS) {
			break;
		}

		get_ldap_errs(ldap_state, &ld_error, &ld_errno);

		DEBUG(10, ("Extended operation failed with error: "
			   "%d (%s) (%s)\n", ld_errno,
			   ldap_err2string(rc),
			   ld_error ? ld_error : "unknown"));
		SAFE_FREE(ld_error);

		if (ld_errno != LDAP_SERVER_DOWN) {
			break;
		}
		ldap_unbind(smbldap_get_ldap(ldap_state));
		ldap_state->ldap_struct = NULL;
	}

	return end_ldap_local_alarm(abs_endtime, rc);
}

/*******************************************************************
 run the search by name.
******************************************************************/
int smbldap_search_suffix (struct smbldap_state *ldap_state,
			   const char *filter, const char **search_attr,
			   LDAPMessage ** result)
{
	return smbldap_search(ldap_state, lp_ldap_suffix(),
			      LDAP_SCOPE_SUBTREE,
			      filter, search_attr, 0, result);
}

static void smbldap_idle_fn(struct tevent_context *tevent_ctx,
			    struct tevent_timer *te,
			    struct timeval now_abs,
			    void *private_data)
{
	struct smbldap_state *state = (struct smbldap_state *)private_data;

	TALLOC_FREE(state->idle_event);

	if (smbldap_get_ldap(state) == NULL) {
		DEBUG(10,("ldap connection not connected...\n"));
		return;
	}

	if ((state->last_use+SMBLDAP_IDLE_TIME) > time_mono(NULL)) {
		DEBUG(10,("ldap connection not idle...\n"));

		/* this needs to be made monotonic clock aware inside tevent: */
		state->idle_event = tevent_add_timer(
			tevent_ctx, state,
			timeval_add(&now_abs, SMBLDAP_IDLE_TIME, 0),
			smbldap_idle_fn,
			private_data);
		return;
	}

	DEBUG(7,("ldap connection idle...closing connection\n"));
	smbldap_close(state);
}

/**********************************************************************
 Housekeeping
 *********************************************************************/

void smbldap_free_struct(struct smbldap_state **ldap_state) 
{
	smbldap_close(*ldap_state);

	if ((*ldap_state)->bind_secret) {
		memset((*ldap_state)->bind_secret, '\0', strlen((*ldap_state)->bind_secret));
	}

	SAFE_FREE((*ldap_state)->bind_dn);
	SAFE_FREE((*ldap_state)->bind_secret);
	smbldap_set_bind_callback(*ldap_state, NULL, NULL);

	TALLOC_FREE(*ldap_state);

	/* No need to free any further, as it is talloc()ed */
}

static int smbldap_state_destructor(struct smbldap_state *state)
{
	smbldap_free_struct(&state);
	return 0;
}


/**********************************************************************
 Intitalise the 'general' ldap structures, on which ldap operations may be conducted
 *********************************************************************/

NTSTATUS smbldap_init(TALLOC_CTX *mem_ctx, struct tevent_context *tevent_ctx,
		      const char *location,
		      bool anon,
		      const char *bind_dn,
		      const char *bind_secret,
		      struct smbldap_state **smbldap_state)
{
	*smbldap_state = talloc_zero(mem_ctx, struct smbldap_state);
	if (!*smbldap_state) {
		DEBUG(0, ("talloc() failed for ldapsam private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (location) {
		(*smbldap_state)->uri = talloc_strdup(mem_ctx, location);
	} else {
		(*smbldap_state)->uri = "ldap://localhost";
	}

	(*smbldap_state)->tevent_context = tevent_ctx;

	if (bind_dn && bind_secret) {
		smbldap_set_creds(*smbldap_state, anon, bind_dn, bind_secret);
	}

	talloc_set_destructor(*smbldap_state, smbldap_state_destructor);
	return NT_STATUS_OK;
}

 char *smbldap_talloc_dn(TALLOC_CTX *mem_ctx, LDAP *ld,
			 LDAPMessage *entry)
{
	char *utf8_dn, *unix_dn;
	size_t converted_size;

	utf8_dn = ldap_get_dn(ld, entry);
	if (!utf8_dn) {
		DEBUG (5, ("smbldap_talloc_dn: ldap_get_dn failed\n"));
		return NULL;
	}
	if (!pull_utf8_talloc(mem_ctx, &unix_dn, utf8_dn, &converted_size)) {
		DEBUG (0, ("smbldap_talloc_dn: String conversion failure utf8 "
			   "[%s]\n", utf8_dn));
		return NULL;
	}
	ldap_memfree(utf8_dn);
	return unix_dn;
}

/*******************************************************************
 Check if root-dse has a certain Control or Extension
********************************************************************/

static bool smbldap_check_root_dse(LDAP *ld, const char **attrs, const char *value) 
{
	LDAPMessage *msg = NULL;
	LDAPMessage *entry = NULL;
	char **values = NULL;
	int rc, num_result, num_values, i;
	bool result = False;

	if (!attrs[0]) {
		DEBUG(3,("smbldap_check_root_dse: nothing to look for\n"));
		return False;
	}

	if (!strequal(attrs[0], "supportedExtension") && 
	    !strequal(attrs[0], "supportedControl") && 
	    !strequal(attrs[0], "namingContexts")) {
		DEBUG(3,("smbldap_check_root_dse: no idea what to query root-dse for: %s ?\n", attrs[0]));
		return False;
	}

	rc = ldap_search_s(ld, "", LDAP_SCOPE_BASE, 
			   "(objectclass=*)", discard_const_p(char *, attrs), 0 , &msg);

	if (rc != LDAP_SUCCESS) {
		DEBUG(3,("smbldap_check_root_dse: Could not search rootDSE\n"));
		return False;
	}

	num_result = ldap_count_entries(ld, msg);

	if (num_result != 1) {
		DEBUG(3,("smbldap_check_root_dse: Expected one rootDSE, got %d\n", num_result));
		goto done;
	}

	entry = ldap_first_entry(ld, msg);

	if (entry == NULL) {
		DEBUG(3,("smbldap_check_root_dse: Could not retrieve rootDSE\n"));
		goto done;
	}

	values = ldap_get_values(ld, entry, attrs[0]);

	if (values == NULL) {
		DEBUG(5,("smbldap_check_root_dse: LDAP Server does not support any %s\n", attrs[0]));
		goto done;
	}

	num_values = ldap_count_values(values);

	if (num_values == 0) {
		DEBUG(5,("smbldap_check_root_dse: LDAP Server does not have any %s\n", attrs[0]));
		goto done;
	}

	for (i=0; i<num_values; i++) {
		if (strcmp(values[i], value) == 0)
			result = True;
	}


 done:
	if (values != NULL)
		ldap_value_free(values);
	if (msg != NULL)
		ldap_msgfree(msg);

	return result;

}

/*******************************************************************
 Check if LDAP-Server supports a certain Control (OID in string format)
********************************************************************/

bool smbldap_has_control(LDAP *ld, const char *control)
{
	const char *attrs[] = { "supportedControl", NULL };
	return smbldap_check_root_dse(ld, attrs, control);
}

/*******************************************************************
 Check if LDAP-Server supports a certain Extension (OID in string format)
********************************************************************/

bool smbldap_has_extension(LDAP *ld, const char *extension)
{
	const char *attrs[] = { "supportedExtension", NULL };
	return smbldap_check_root_dse(ld, attrs, extension);
}

/*******************************************************************
 Check if LDAP-Server holds a given namingContext
********************************************************************/

bool smbldap_has_naming_context(LDAP *ld, const char *naming_context)
{
	const char *attrs[] = { "namingContexts", NULL };
	return smbldap_check_root_dse(ld, attrs, naming_context);
}

bool smbldap_set_creds(struct smbldap_state *ldap_state, bool anon, const char *dn, const char *secret)
{
	ldap_state->anonymous = anon;

	/* free any previously set credential */

	SAFE_FREE(ldap_state->bind_dn);
	smbldap_set_bind_callback(ldap_state, NULL, NULL);

	if (ldap_state->bind_secret) {
		/* make sure secrets are zeroed out of memory */
		memset(ldap_state->bind_secret, '\0', strlen(ldap_state->bind_secret));
		SAFE_FREE(ldap_state->bind_secret);
	}

	if ( ! anon) {
		ldap_state->bind_dn = SMB_STRDUP(dn);
		ldap_state->bind_secret = SMB_STRDUP(secret);
	}

	return True;
}
