/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   
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

#ifndef _TORTURE_PROVISION_H_
#define _TORTURE_PROVISION_H_

struct provision_settings {
	const char *dns_name;
	const char *site_name;
	const char *root_dn_str; 
	const char *domain_dn_str;
	const char *config_dn_str;
	const char *schema_dn_str;
	const struct GUID *invocation_id;
	const char *netbios_name;
	const char *realm;
	const char *domain;
	const struct GUID *ntds_guid;
	const char *ntds_dn_str;
	const char *machine_password;
	const char *samdb_ldb;
	const char *secrets_ldb;
	const char *secrets_keytab;
	const char *schemadn_ldb;
	const char *configdn_ldb;
	const char *domaindn_ldb;
	const char *templates_ldb;
	const char *dns_keytab;
};

NTSTATUS provision_bare(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx,
						struct provision_settings *settings);


#endif /* _TORTURE_PROVISION_H_ */
