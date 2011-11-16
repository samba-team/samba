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

struct smbldap_state;

#include "include/smb_ldap.h"

#ifdef HAVE_LDAP

/* Function declarations -- not included in proto.h so we don't
   have to worry about LDAP structure types */

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

int smb_ldap_start_tls(LDAP *ldap_struct, int version);
int smb_ldap_setup_full_conn(LDAP **ldap_struct, const char *uri);
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
void talloc_autofree_ldapmsg(TALLOC_CTX *mem_ctx, LDAPMessage *result);
void talloc_autofree_ldapmod(TALLOC_CTX *mem_ctx, LDAPMod **mod);
char *smbldap_talloc_dn(TALLOC_CTX *mem_ctx, LDAP *ld,
			      LDAPMessage *entry);

#endif 	/* HAVE_LDAP */

#define LDAP_DEFAULT_TIMEOUT   15
#define LDAP_CONNECTION_DEFAULT_TIMEOUT 2
#define LDAP_PAGE_SIZE 1024

#define ADS_PAGE_CTL_OID 	"1.2.840.113556.1.4.319"

/*
 * Work around versions of the LDAP client libs that don't have the OIDs
 * defined, or have them defined under the old name.
 * This functionality is really a factor of the server, not the client
 *
 */

#if defined(LDAP_EXOP_X_MODIFY_PASSWD) && !defined(LDAP_EXOP_MODIFY_PASSWD)
#define LDAP_EXOP_MODIFY_PASSWD LDAP_EXOP_X_MODIFY_PASSWD
#elif !defined(LDAP_EXOP_MODIFY_PASSWD)
#define LDAP_EXOP_MODIFY_PASSWD "1.3.6.1.4.1.4203.1.11.1"
#endif

#if defined(LDAP_EXOP_X_MODIFY_PASSWD_ID) && !defined(LDAP_EXOP_MODIFY_PASSWD_ID)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID LDAP_EXOP_X_MODIFY_PASSWD_ID
#elif !defined(LDAP_EXOP_MODIFY_PASSWD_ID)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID        ((ber_tag_t) 0x80U)
#endif

#if defined(LDAP_EXOP_X_MODIFY_PASSWD_NEW) && !defined(LDAP_EXOP_MODIFY_PASSWD_NEW)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW LDAP_EXOP_X_MODIFY_PASSWD_NEW
#elif !defined(LDAP_EXOP_MODIFY_PASSWD_NEW)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW       ((ber_tag_t) 0x82U)
#endif

#endif	/* _SMBLDAP_H */
