/*
   Unix SMB/CIFS implementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau	1998
   Copyright (C) Gerald Carter			2001-2003
   Copyright (C) Shahms King			2001
   Copyright (C) Andrew Bartlett		2002-2003
   Copyright (C) Stefan (metze) Metzmacher	2002-2003
   Copyright (C) Simo Sorce			2006

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

#ifndef _PASSDB_PDB_LDAP_H_
#define _PASSDB_PDB_LDAP_H_

/* struct used by both pdb_ldap.c and pdb_nds.c */

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

	/* ldap server location parameter */
	char *location;

	struct {
		char *filter;
		LDAPMessage *result;
	} search_cache;
};

/* The following definitions come from passdb/pdb_ldap.c  */

const char** get_userattr_list( TALLOC_CTX *mem_ctx, int schema_ver );
NTSTATUS pdb_ldapsam_init_common(struct pdb_methods **pdb_method, const char *location);
NTSTATUS pdb_ldapsam_init(TALLOC_CTX *);
int ldapsam_search_suffix_by_name(struct ldapsam_privates *ldap_state,
                                  const char *user,
                                  LDAPMessage ** result,
                                  const char **attr);
const char** get_userattr_list( TALLOC_CTX *mem_ctx, int schema_ver );
LDAP *priv2ld(struct ldapsam_privates *priv);

#endif /* _PASSDB_PDB_LDAP_H_ */
