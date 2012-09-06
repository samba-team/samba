/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Gerald Carter			2001-2003

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

#ifndef _SMBLDAP_H
#define _SMBLDAP_H

#include "include/smb_ldap.h"

#ifdef HAVE_LDAP

#include <talloc.h>
#include <tevent.h>

/**
 * Struct to keep the state for all the ldap stuff 
 *
 */

struct smbldap_state {
	LDAP *ldap_struct;
	pid_t pid;
	time_t last_ping; /* monotonic */
	/* retrive-once info */
	const char *uri;

	/* credentials */
	bool anonymous;
	char *bind_dn;
	char *bind_secret;
	int (*bind_callback)(LDAP *ldap_struct, struct smbldap_state *ldap_state, void *data);
	void *bind_callback_data;

	bool paged_results;

	unsigned int num_failures;

	time_t last_use; /* monotonic */
	struct tevent_context *tevent_context;
	struct timed_event *idle_event;

	struct timeval last_rebind; /* monotonic */
};

/* struct used by both pdb_ldap.c and pdb_nds.c */

struct ipasam_privates;

struct ldapsam_privates {
	struct smbldap_state *smbldap_state;

	/* Former statics */
	LDAPMessage *result;
	LDAPMessage *entry;
	int index;

	const char *domain_name;
	struct dom_sid domain_sid;

	/* configuration items */
	int schema_ver;

	char *domain_dn;

	/* Is this NDS ldap? */
	int is_nds_ldap;

	/* Is this IPA ldap? */
	int is_ipa_ldap;
	struct ipasam_privates *ipasam_privates;

	/* ldap server location parameter */
	char *location;

	struct {
		char *filter;
		LDAPMessage *result;
	} search_cache;
};

/* The following definitions come from lib/smbldap.c  */

NTSTATUS smbldap_init(TALLOC_CTX *mem_ctx,
		      struct tevent_context *tevent_ctx,
		      const char *location,
		      bool anon,
		      const char *bind_dn,
		      const char *bind_secret,
		      struct smbldap_state **smbldap_state);

void smbldap_set_mod (LDAPMod *** modlist, int modop, const char *attribute, const char *value);
void smbldap_set_mod_blob(LDAPMod *** modlist, int modop, const char *attribute, const DATA_BLOB *newblob);
void smbldap_make_mod(LDAP *ldap_struct, LDAPMessage *existing,
		      LDAPMod ***mods,
		      const char *attribute, const char *newval);
void smbldap_make_mod_blob(LDAP *ldap_struct, LDAPMessage *existing,
			   LDAPMod ***mods,
			   const char *attribute, const DATA_BLOB *newblob);
bool smbldap_get_single_attribute (LDAP * ldap_struct, LDAPMessage * entry,
				   const char *attribute, char *value,
				   int max_len);
int smbldap_modify(struct smbldap_state *ldap_state,
                   const char *dn,
                   LDAPMod *attrs[]);
int smbldap_start_tls(LDAP *ldap_struct, int version);
int smbldap_setup_full_conn(LDAP **ldap_struct, const char *uri);
int smbldap_search(struct smbldap_state *ldap_state,
		   const char *base, int scope, const char *filter,
		   const char *attrs[], int attrsonly,
		   LDAPMessage **res);
int smbldap_search_paged(struct smbldap_state *ldap_state,
			 const char *base, int scope, const char *filter,
			 const char **attrs, int attrsonly, int pagesize,
			 LDAPMessage **res, void **cookie);
int smbldap_modify(struct smbldap_state *ldap_state, const char *dn, LDAPMod *attrs[]);
int smbldap_add(struct smbldap_state *ldap_state, const char *dn, LDAPMod *attrs[]);
int smbldap_delete(struct smbldap_state *ldap_state, const char *dn);
int smbldap_extended_operation(struct smbldap_state *ldap_state,
			       LDAP_CONST char *reqoid, struct berval *reqdata,
			       LDAPControl **serverctrls, LDAPControl **clientctrls,
			       char **retoidp, struct berval **retdatap);
int smbldap_search_suffix (struct smbldap_state *ldap_state,
			   const char *filter, const char **search_attr,
			   LDAPMessage ** result);
void smbldap_free_struct(struct smbldap_state **ldap_state) ;
bool smbldap_has_control(LDAP *ld, const char *control);
bool smbldap_has_extension(LDAP *ld, const char *extension);
bool smbldap_has_naming_context(LDAP *ld, const char *naming_context);
bool smbldap_set_creds(struct smbldap_state *ldap_state, bool anon, const char *dn, const char *secret);
char * smbldap_talloc_single_attribute(LDAP *ldap_struct, LDAPMessage *entry,
				       const char *attribute,
				       TALLOC_CTX *mem_ctx);
char * smbldap_talloc_first_attribute(LDAP *ldap_struct, LDAPMessage *entry,
				      const char *attribute,
				      TALLOC_CTX *mem_ctx);
char * smbldap_talloc_smallest_attribute(LDAP *ldap_struct, LDAPMessage *entry,
					 const char *attribute,
					 TALLOC_CTX *mem_ctx);
bool smbldap_talloc_single_blob(TALLOC_CTX *mem_ctx, LDAP *ld,
				LDAPMessage *msg, const char *attrib,
				DATA_BLOB *blob);
bool smbldap_pull_sid(LDAP *ld, LDAPMessage *msg, const char *attrib,
		      struct dom_sid *sid);
void smbldap_talloc_autofree_ldapmsg(TALLOC_CTX *mem_ctx, LDAPMessage *result);
void smbldap_talloc_autofree_ldapmod(TALLOC_CTX *mem_ctx, LDAPMod **mod);
char *smbldap_talloc_dn(TALLOC_CTX *mem_ctx, LDAP *ld,
			      LDAPMessage *entry);

#endif 	/* HAVE_LDAP */

#endif	/* _SMBLDAP_H */
