/*
   Unix SMB/CIFS implementation.
   IPA helper functions for SAMBA
   Copyright (C) Sumit Bose <sbose@redhat.com> 2010

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

static NTSTATUS pdb_init_IPA_ldapsam(struct pdb_methods **pdb_method, const char *location)
{
	struct ldapsam_privates *ldap_state;

	NTSTATUS nt_status = pdb_init_ldapsam(pdb_method, location);

	(*pdb_method)->name = "IPA_ldapsam";

	ldap_state = (struct ldapsam_privates *)((*pdb_method)->private_data);
	ldap_state->is_ipa_ldap = true;

	return nt_status;
}

NTSTATUS pdb_ipa_init(void)
{
	NTSTATUS nt_status;

	if (!NT_STATUS_IS_OK(nt_status = smb_register_passdb(PASSDB_INTERFACE_VERSION, "IPA_ldapsam", pdb_init_IPA_ldapsam)))
		return nt_status;

	return NT_STATUS_OK;
}
