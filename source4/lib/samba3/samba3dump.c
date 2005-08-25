/* 
   Unix SMB/CIFS implementation.
   Samba3 database dump utility

    Copyright (C) Jelmer Vernooij	2005
   
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
#include "lib/samba3/samba3.h"
#include "lib/cmdline/popt_common.h"

static void print_header(const char *txt)
{
	int i;
	printf("\n%s\n", txt);
	for (i = 0; txt[i]; i++) putchar('=');
	putchar('\n');
}

static NTSTATUS print_samba3_policy(struct samba3_policy *ret)
{
	print_header("Account Policies");
	printf("Min password length: %d\n", ret->min_password_length);
	printf("Password history length: %d\n", ret->password_history);
	printf("User must logon to change password: %d\n", ret->user_must_logon_to_change_password);
	printf("Maximum password age: %d\n", ret->maximum_password_age);
	printf("Minimum password age: %d\n", ret->minimum_password_age);
	printf("Lockout duration: %d\n", ret->lockout_duration);
	printf("Reset Count Minutes: %d\n", ret->reset_count_minutes);
	printf("Bad Lockout Minutes: %d\n", ret->bad_lockout_minutes);
	printf("Disconnect Time: %d\n", ret->disconnect_time);
	printf("Refuse Machine Password Change: %d\n", ret->refuse_machine_password_change);

	return NT_STATUS_OK;
}

static NTSTATUS print_samba3_sam(struct samba3 *samba3)
{
	struct samba3_samaccount *accounts = samba3->samaccounts;
	uint32_t count = samba3->samaccount_count, i;
	print_header("SAM Database");
	
	for (i = 0; i < count; i++) {
		printf("%d: %s\n", accounts[i].user_rid, accounts[i].username);
	}

	return NT_STATUS_OK;
}

static NTSTATUS print_samba3_shares(struct samba3 *samba3)
{
	int i, j;
	print_header("Configured shares");
	for (i = 0; i < samba3->share_count; i++) {
		struct samba3_share_info *share = &samba3->shares[i];
		printf("--- %s ---\n", share->name);

		for (j = 0; j < share->parameter_count; j++) {
			printf("\t%s = %s\n", share->parameters[j].name, share->parameters[j].value);
		}

		printf("\n");
	}

	return NT_STATUS_OK;
}

static NTSTATUS print_samba3_secrets(struct samba3_secrets *secrets)
{
	int i;
	print_header("Secrets");

	printf("IPC Credentials:\n");
	printf("	User: %s\n", cli_credentials_get_username(secrets->ipc_cred));
	printf("	Password: %s\n", cli_credentials_get_password(secrets->ipc_cred));
	printf("	Domain: %s\n\n", cli_credentials_get_domain(secrets->ipc_cred));

	printf("LDAP passwords:\n");
	for (i = 0; i < secrets->ldappw_count; i++) {
		printf("\t%s -> %s\n", secrets->ldappws[i].dn, secrets->ldappws[i].password);
	}
	printf("\n");

	printf("Domains:\n");
	for (i = 0; i < secrets->domain_count; i++) {
		printf("\t--- %s ---\n", secrets->domains[i].name);
		printf("\tSID: %s\n", dom_sid_string(NULL, &secrets->domains[i].sid));
		printf("\tGUID: %s\n", GUID_string(NULL, &secrets->domains[i].guid));
		printf("\tPlaintext pwd: %s\n", secrets->domains[i].plaintext_pw);
		printf("\tLast Changed: %lu\n", secrets->domains[i].last_change_time);
		printf("\tSecure Channel Type: %d\n\n", secrets->domains[i].sec_channel_type);
	}

	printf("Trusted domains:\n");
	for (i = 0; i < secrets->trusted_domain_count; i++) {
		int j;
		for (j = 0; j < secrets->trusted_domains[i].uni_name_len; j++) {
			printf("\t--- %s ---\n", secrets->trusted_domains[i].uni_name[j]);
		}
		printf("\tPassword: %s\n", secrets->trusted_domains[i].pass);
		printf("\tModified: %lu\n", secrets->trusted_domains[i].mod_time);
		printf("\tSID: %s\n", dom_sid_string(NULL, &secrets->trusted_domains[i].domain_sid));
	}

	return NT_STATUS_OK;
}

static NTSTATUS print_samba3_regdb(struct samba3_regdb *regdb)
{
	int i;
	print_header("Registry");

	for (i = 0; i < regdb->key_count; i++) {
		int j;
		printf("%s\n", regdb->keys[i].name);
		for (j = 0; j < regdb->keys[i].value_count; j++) {
			printf("\t%s: type %d, length %d\n", 
				   regdb->keys[i].values[j].name,
				   regdb->keys[i].values[j].type,
				   regdb->keys[i].values[j].data.length);
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS print_samba3_winsdb(struct samba3 *samba3)
{
	int i;
	print_header("WINS Database");

	for (i = 0; i < samba3->winsdb_count; i++) {
		printf("%s, nb_flags: %x, type: %d, ttl: %lu, %d ips\n", samba3->winsdb_entries[i].name, samba3->winsdb_entries[i].nb_flags, samba3->winsdb_entries[i].type, samba3->winsdb_entries[i].ttl, samba3->winsdb_entries[i].ip_count);
	}

	return NT_STATUS_OK;
}

static NTSTATUS print_samba3(struct samba3 *samba3)
{
	print_samba3_sam(samba3);
	print_samba3_policy(&samba3->policy);
	print_samba3_shares(samba3);
	print_samba3_winsdb(samba3);
	print_samba3_regdb(&samba3->registry);
	print_samba3_secrets(&samba3->secrets);

	return NT_STATUS_OK;
}
 
int main(int argc, char **argv)
{
	int opt;
	const char *format = "summary";
	const char *libdir = "/var/lib/samba";
	struct samba3 *samba3;
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ "format", 0, POPT_ARG_STRING, &format, 'f', "Format to use (one of: summary, text, ldif)" },
		{ "libdir", 0, POPT_ARG_STRING, &libdir, 'l', "Set libdir [/var/lib/samba]", "LIBDIR" },
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);

	poptSetOtherOptionHelp(pc, "<smb.conf>");

	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	samba3_read(poptGetArg(pc), libdir, NULL, &samba3);

	if (!strcmp(format, "summary")) {
		printf("WINS db entries: %d\n", samba3->winsdb_count);
		printf("SAM Accounts: %d\n", samba3->samaccount_count);
		printf("Registry key count: %d\n", samba3->registry.key_count);
		printf("Shares (including [global]): %d\n", samba3->share_count);
		printf("Groupmap count: %d\n", samba3->group.groupmap_count);
		printf("Alias count: %d\n", samba3->group.alias_count);
		printf("Idmap count: %d\n", samba3->idmap.mapping_count);
	} else if (!strcmp(format, "text")) {
		print_samba3(samba3);
	} else if (!strcmp(format, "ldif")) {
		printf("FIXME\n");
	}
	poptFreeContext(pc);

	return 0;
}
