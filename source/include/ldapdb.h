/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   LDAP and NTDS prototypes &c

   Copyright (C) Luke Howard (PADL Software Pty Ltd) 2000

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

/*
 * The LDAP DB (LDAPDB) API is desgined to provide a nice,
 * database library-like, abstraction on top of the LDAP API for
 * the purposes of SAMBA. Eventually we'll write a general purpose
 * DB API, but it will probably look more like ADSI than DB.
 *
 * The primitive is the opaque LDAPDB. 
 *
 * The LDAPDB contains the following state:
 *
 *	- the connection to the LDAP server
 *	- the current search (msgid for async, chain for sync)
 *	- the current search position (an LDAPMessage *)
 *
 * You should use a separate LDAPDB for each subsequent search;
 * it's like a DB* that you can step through with smb_ldapdb_seq(), except
 * for the fact that (at present) the cursor is part of the handle.
 * This should probably be changed but it makes it an easy API
 * to write to for the moment, and it's sure better than having
 * a global LDAP structure / result.
 *
 * If you want to do another search without disturbing the existing
 * state, whilst still sharing the same connection to the LDAP server,
 * then you can create a duplicate handle with:
 *
 *	BOOL ret = smb_ldapdb_dup(original_handle, &new_handle);
 *
 * In fact the current implementation of smb_ldapdb_open() does this internally,
 * so that there is a single connection to the LDAP server. smb_ldapdb_dup()
 * sets an "owner" flag inside the handle so that when ldapdb_close() is
 * called the LDAP connection isn't closed unless it was the handle
 * that created it. The connection itself is referenced counted so
 * whenever ldapdb_dup() is called the count is incremented, and ds_close()
 * will only free the connection (nb: it will always free the result
 * chain) when the count drops to 1. Hopefully it will be OK to
 * _replace_ the connection if it becomes invalid without invalidating
 * the existing handles.
 *
 *	LDAPDB_DECLARE_HANDLE(hds);
 *
 *	if (!ldapdb_open(&hds)) {
 *		return False;
 *	}
 *
 *	// hds->flags |= LDAPDB_RETRIEVE_SYNCHRONOUSLY to use ldap_search_s() 
 *	if (!ldapdb_search(hds, "cn=users,dc=samba,dc=org", "(samaccountname=lkcl)", 1)) {
 *		return False;
 *	}
 *
 *	// now hds->entry has the entry 
 *
 *	ldapdb_close(&hds);
 */

#ifndef _LDAPDB_H
#define _LDAPDB_H

#ifdef WITH_NT5LDAP

#include <lber.h> 
#include <ldap.h>

/* always declare a handle like this, as ldapdb_open() will attempt to reuse a non-NULL handle */
#define LDAPDB_DECLARE_HANDLE(hds)		LDAPDB *hds = NULL

/*
 *	BOOL func(LDAPDB *_hds, ...)
 *	{
 *		LDAPDB_DECLARE_HANDLE(hds);
 *		BOOL ret = LDAPDB_OPEN(_hds, _hds);
 *		...
 *		ldapdb_close(&hds);
 *	}
 *
 * Use this where you can pass an optional handle. If a handle was passed,
 * then we duplicate it; otherwise, we just allocate a new one. If we
 * didn't call ldapdb_dup() (as done by DS_OPEN()) then, if a handle was
 * passed, then we would act as if we owned it, which we don't!
 */
#define LDAPDB_OPEN(_hds, hds)		((ldapdb_dup(_hds, hds) == TRUE) ? ldapdb_open(hds) : FALSE)

/* in ds.c */
struct ldapdb_handle_info;
typedef struct ldapdb_handle_info LDAPDB;

/* used to indicate handles which may be NULL if a temporary one is to be created */
/* these are used for functions that create a temporary handle anyway because 
 * they would otherwise change the handle's state.
 */
typedef LDAPDB *PLDAPDB;

/* One time library initialization. */
BOOL ldapdb_init(void);

/* Add/modify an entry in the directory */
BOOL ldapdb_update(PLDAPDB hds, const char *context, const char *attribute, const char *value, LDAPMod **mods, BOOL replace); /* FREES mods */

/* Add/modify an entry in the directory */
BOOL ldapdb_commit(LDAPDB *hds, const char *dn, LDAPMod **mods, BOOL create); /* FREES mods */

/* Enqueue a mod */
BOOL ldapdb_queue_mod(LDAPMod ***modlist,int modop, const char *attribute, const char *value);
BOOL ldapdb_queue_unistr_mod(LDAPMod ***modlist,int modop, const char *attribute, const UNISTR2 *value);
BOOL ldapdb_queue_uint32_mod(LDAPMod ***modlist, int modop, const char *attribute, uint32 value);

/* Enqueue a binary mod */
BOOL ldapdb_queue_mod_len(LDAPMod ***modlist,int modop, const char *attribute, struct berval *bv);

/* Search the directory */
/* 
 * Note: AD has a bitwise matching rule that lets them search, say, on
 * specific bit of groupType. Whilst we could construct a filter that
 * used that matching rule, it's unlikely that non-AD directory servers
 * are going to support it, so for the moment we construct an equality
 * filter. I will perhaps get around to adding support for the AD
 * AND/NOT matching rules to OpenLDAP.
 */
BOOL ldapdb_search(LDAPDB *hds, const char *subcontext, const char *filter, char *const *attrs, int sizelimit);

/* Get a new handle for a new search, or just allocate an empty one */
BOOL ldapdb_dup(PLDAPDB in, PLDAPDB *out);

/* Open up a handle */
BOOL ldapdb_open(PLDAPDB *phds);

/* Close off a handle. Closes off connection only if we own it */
void ldapdb_close(LDAPDB **phds);

/* Read an entry */
BOOL ldapdb_read(LDAPDB *hds, const char *dn, char *const *attrs);

/* Count entries, if we retrieved them synchronously */
BOOL ldapdb_count_entries(LDAPDB *hds, int *);

/* Set the synchronous flag; old flag value returned. */
BOOL ldapdb_set_synchronous(LDAPDB *hds, BOOL setto);

/* Delete an entry */
BOOL ldapdb_delete(LDAPDB *hds, const char *dn);

/* get dn */
BOOL ldapdb_get_dn(LDAPDB *hds, char **dn);

/* advance to the next entry */
BOOL ldapdb_seq(LDAPDB *hds);

/* get a value, caller suplies buffer */
BOOL ldapdb_get_value(LDAPDB *hds, const char *attribute, char *buf, size_t buflen);

#define ldapdb_get_pvalue(h, a, b)	ldapdb_get_value(h, a, b, (sizeof(pstring)-1))
#define ldapdb_get_fvalue(h, a, b)	ldapdb_get_value(h, a, b, (sizeof(fstring)-1))

BOOL ldapdb_get_unistr_value(LDAPDB *hds, const char *attribute, UNISTR2 *buf);

/* get values, caller frees memory */
BOOL ldapdb_get_values(LDAPDB *hds, const char *attribute, char ***values);

BOOL ldapdb_get_value_len(LDAPDB *hds, const char *attribute, struct berval **value);
BOOL ldapdb_get_values_len(LDAPDB *hds, const char *attribute, struct berval ***value);

/* get the entry, callee owns */
BOOL ldapdb_get_entry(LDAPDB *hds, LDAPMessage **e);

BOOL ldapdb_get_uint32(LDAPDB *hds, const char *attribute, uint32 *val);

/* extract a sid from the current entry.  objectSid attribute used. */
BOOL ldapdb_get_sid(LDAPDB *hds, const char *attribute, DOM_SID *sid);

/* extract a rid from the current entry. objectSid attribute used. */
BOOL ldapdb_get_rid(LDAPDB *hds, const char *attribute, uint32 *rid);

/* caller frees */
BOOL ldapdb_get_sids(LDAPDB *hds, const char *attribute, DOM_SID ***sid);
BOOL ldapdb_get_rids(LDAPDB *hds, const char *attribute, uint32 **rid);


/* check whether we have an entry */
BOOL ldapdb_peek(LDAPDB *hds);

/* get a new RID from the RID allocator */
BOOL ldapdb_allocate_rid(LDAPDB *hds, uint32 *rid);

/* lookup entry by posix name */
BOOL ldapdb_lookup_by_posix_name(LDAPDB *hds, const char *name);

/* lookup entry by posix uid */
BOOL ldapdb_lookup_by_posix_uid(LDAPDB *hds, uid_t uid);
BOOL ldapdb_lookup_by_posix_gid(LDAPDB *hds, gid_t uid);

/* decode a SID from LDAP attribute value */
BOOL berval_to_sid(const struct berval *siddata, DOM_SID *sid);

/* encode a SID into an LDAP attribute value */
BOOL sid_to_berval(const DOM_SID *sid, struct berval **siddata);

/* decode a RID using ldapdb_decode_sid() and global_sid */
BOOL berval_to_rid(struct berval *siddata, uint32 *rid);

/* encode a RID using ldapdb_encode_sid() and global_sid */
BOOL rid_to_berval(uint32 rid, struct berval **siddata);

BOOL berval_to_unicodepwd(const struct berval *bv, uint8 pwd[16]);
BOOL berval_to_dbcspwd(const struct berval *bv, uint8 pwd[16]);
BOOL unicodepwd_to_berval(const uint8 pwd[16], struct berval **bvp);
BOOL dbcspwd_to_berval(const uint8 pwd[16], struct berval **bvp);

/* name cracking */
BOOL ldapdb_dnsdomain_to_dn(const char *dnsdomain, pstring dn);
BOOL ldapdb_dn_to_dnsdomain(const char *dn, pstring dns);
const char *ldapdb_get_realm_name(void);

/* name mapping; can pass a NULL handle if you don't have a conn handy */

/* get the DN for a SAM account name */
BOOL ldapdb_ntname_to_dn(PLDAPDB hds, const char *ntname, pstring dn);

/* get the SAM account name for a DN */
BOOL ldapdb_dn_to_ntname(PLDAPDB hds, const char *dn, pstring ntname);

/* get the SID for a DN */
BOOL ldapdb_sid_to_dn(PLDAPDB hds, const DOM_SID *sid, pstring dn);

/* get the RID for a DN */
BOOL ldapdb_rid_to_dn(PLDAPDB hds, uint32 rid, pstring dn);

/* get sid filter */
BOOL ldapdb_make_sid_filter(const char *attribute, const DOM_SID *sid, fstring filter);
BOOL ldapdb_make_rid_filter(const char *attribute, uint32 rid, fstring filter);

/* get domain SID */
BOOL ldapdb_get_domain_info(PLDAPDB _hds, const char *dnsdomain, DOM_SID *sid, fstring nbname);

/* get the DN for a filter somewhere */
BOOL ldapdb_lookup_name(PLDAPDB hds, const char *, const char *, pstring dn);

/* lookup new entry by RID */
BOOL ldapdb_lookup_by_rid(LDAPDB *, uint32 rid);

/* lookup new entry by SID. How are we going to do this? objectSid is bianry. */
BOOL ldapdb_lookup_by_sid(LDAPDB *, const DOM_SID *sid);

/* lookup by sam account name */
BOOL ldapdb_lookup_by_ntname(LDAPDB *, const char *ntname);
BOOL ldapdb_lookup_by_unistr_ntname(LDAPDB *, const UNISTR2 *ntname);

/* lookup by nETBIOSName */
BOOL ldapdb_lookup_by_netbiosname (LDAPDB *hds, const char *nbname);

/* save time in modlist. need to do this not as a unix time_t. */
BOOL ldapdb_queue_time(LDAPMod ***modlist, int modop, const char *attribute, NTTIME *nttime);

/* parse out an NT5 timeval into an NT time */
BOOL ldapdb_parse_time(const char *timeval, NTTIME *nttime);

/* get some time attribute, uses ldapdb_parse_time() */
BOOL ldapdb_get_time(LDAPDB *hds, const char *attribute, NTTIME *nttime);

BOOL ldapdb_oc_check(LDAPDB *hds, const char *ocname);

/* Convert a UNISTR2 structure to a UTF8 string. */
void unistr2_to_utf8(char *dest, const UNISTR2 *str, size_t maxlen);

void utf8_to_unistr2(UNISTR2 *dest, const char *str);

/* in nt5ldap.c */
BOOL nt5ldap_make_local_grp_member(LDAPDB *hds, const char *dn, LOCAL_GRP_MEMBER *group);
BOOL nt5ldap_make_local_grp(LDAPDB *hds, LOCAL_GRP *group, LOCAL_GRP_MEMBER **members, int *num_memb, uint32 req_type);
BOOL nt5ldap_local_grp_mods (const LOCAL_GRP *group, LDAPMod ***mods, int operation, uint32 req_type);
BOOL nt5ldap_local_grp_member_mods (const DOM_SID *sid, LDAPMod ***mods, int operation, pstring member);
BOOL nt5ldap_make_domain_grp_member(LDAPDB *hds, const char *dn, DOMAIN_GRP_MEMBER *group);
BOOL nt5ldap_make_domain_grp (LDAPDB * hds, DOMAIN_GRP * group, DOMAIN_GRP_MEMBER ** members, int *num_membs);
BOOL nt5ldap_domain_grp_mods (const DOMAIN_GRP * group, LDAPMod *** mods, int operation);
BOOL nt5ldap_domain_grp_member_mods (uint32 user_rid, LDAPMod *** mods, int operation, pstring member);
BOOL nt5ldap_make_sam_user_info21(LDAPDB *hds, SAM_USER_INFO_21 *usr);
BOOL nt5ldap_sam_user_info21_mods(const SAM_USER_INFO_21 *usr, LDAPMod ***mods, int op, char *rdn, size_t rdnmaxlen, BOOL *iscomputer_p);
BOOL nt5ldap_make_group_rids (LDAPDB * _hds, const char *dn, uint32 ** rids, int *numrids, uint32 req_type);

/* in smbpassldap.c */
/* turn the currnet entry into an smb_passwd */
struct smb_passwd *nt5ldapsmb_getent(LDAPDB *hds);
/* get mods for an smb password */
BOOL nt5ldapsmb_smbmods(struct smb_passwd *newpwd, LDAPMod ***mods, int operation);

/* in sampassldap.c */
/* turn the currnet entry into an sam_passwd */
struct sam_passwd *nt5ldapsam_getent(LDAPDB *hds);
/* get mods for a sam password */
BOOL nt5ldapsam_sammods(struct sam_passwd *newpwd, LDAPMod ***mods, int operation);

/* in sampassdb.c */
/* convert between sam/smb password types */
struct sam_passwd *pwdb_smb_to_sam(struct smb_passwd *user);
struct smb_passwd *pwdb_sam_to_smb(struct sam_passwd *user);

#endif /* WITH_NT5LDAP */

#endif /* _LDAPDB_H */
