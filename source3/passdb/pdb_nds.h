/*
   Unix SMB/CIFS mplementation.
   NDS LDAP helper functions for SAMBA
   Copyright (C) Vince Brimhall			2004-2005

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

#ifndef _PASSDB_PDB_NDS_H_
#define _PASSDB_PDB_NDS_H_

/* The following definitions come from passdb/pdb_nds.c  */

struct smbldap_state;

int pdb_nds_get_password(
	struct smbldap_state *ldap_state,
	char *object_dn,
	size_t *pwd_len,
	char *pwd );
int pdb_nds_set_password(
	struct smbldap_state *ldap_state,
	char *object_dn,
	const char *pwd );
NTSTATUS pdb_nds_init(void);

#endif /* _PASSDB_PDB_NDS_H_ */
