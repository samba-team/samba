/*
   Samba Unix/Linux SMB client library
   net ads commands
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2001 Remus Koos (remuskoos@yahoo.com)
   Copyright (C) 2002 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2006 Gerald (Jerry) Carter (jerry@samba.org)

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
#include "utils/net.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"

#ifdef HAVE_ADS

/* when we do not have sufficient input parameters to contact a remote domain
 * we always fall back to our own realm - Guenther*/

static const char *assume_own_realm(struct net_context *c)
{
	if (!c->opt_host && strequal(lp_workgroup(), c->opt_target_workgroup)) {
		return lp_realm();
	}

	return NULL;
}

/*
  do a cldap netlogon query
*/
static int net_ads_cldap_netlogon(struct net_context *c, ADS_STRUCT *ads)
{
	char addr[INET6_ADDRSTRLEN];
	struct NETLOGON_SAM_LOGON_RESPONSE_EX reply;

	print_sockaddr(addr, sizeof(addr), &ads->ldap.ss);
	if ( !ads_cldap_netlogon_5(talloc_tos(), addr, ads->server.realm, &reply ) ) {
		d_fprintf(stderr, "CLDAP query failed!\n");
		return -1;
	}

	d_printf("Information for Domain Controller: %s\n\n",
		addr);

	d_printf("Response Type: ");
	switch (reply.command) {
	case LOGON_SAM_LOGON_USER_UNKNOWN_EX:
		d_printf("LOGON_SAM_LOGON_USER_UNKNOWN_EX\n");
		break;
	case LOGON_SAM_LOGON_RESPONSE_EX:
		d_printf("LOGON_SAM_LOGON_RESPONSE_EX\n");
		break;
	default:
		d_printf("0x%x\n", reply.command);
		break;
	}

	d_printf("GUID: %s\n", GUID_string(talloc_tos(), &reply.domain_uuid));

	d_printf("Flags:\n"
		 "\tIs a PDC:                                   %s\n"
		 "\tIs a GC of the forest:                      %s\n"
		 "\tIs an LDAP server:                          %s\n"
		 "\tSupports DS:                                %s\n"
		 "\tIs running a KDC:                           %s\n"
		 "\tIs running time services:                   %s\n"
		 "\tIs the closest DC:                          %s\n"
		 "\tIs writable:                                %s\n"
		 "\tHas a hardware clock:                       %s\n"
		 "\tIs a non-domain NC serviced by LDAP server: %s\n"
		 "\tIs NT6 DC that has some secrets:            %s\n"
		 "\tIs NT6 DC that has all secrets:             %s\n",
		 (reply.server_type & NBT_SERVER_PDC) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_GC) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_LDAP) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_DS) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_KDC) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_TIMESERV) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_CLOSEST) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_WRITABLE) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_GOOD_TIMESERV) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_NDNC) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_SELECT_SECRET_DOMAIN_6) ? "yes" : "no",
		 (reply.server_type & NBT_SERVER_FULL_SECRET_DOMAIN_6) ? "yes" : "no");


	printf("Forest:\t\t\t%s\n", reply.forest);
	printf("Domain:\t\t\t%s\n", reply.dns_domain);
	printf("Domain Controller:\t%s\n", reply.pdc_dns_name);

	printf("Pre-Win2k Domain:\t%s\n", reply.domain);
	printf("Pre-Win2k Hostname:\t%s\n", reply.pdc_name);

	if (*reply.user_name) printf("User name:\t%s\n", reply.user_name);

	printf("Server Site Name :\t\t%s\n", reply.server_site);
	printf("Client Site Name :\t\t%s\n", reply.client_site);

	d_printf("NT Version: %d\n", reply.nt_version);
	d_printf("LMNT Token: %.2x\n", reply.lmnt_token);
	d_printf("LM20 Token: %.2x\n", reply.lm20_token);

	return 0;
}

/*
  this implements the CLDAP based netlogon lookup requests
  for finding the domain controller of a ADS domain
*/
static int net_ads_lookup(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	int ret;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads lookup\n"
			 "    Find the ADS DC using CLDAP lookup.\n");
		return 0;
	}

	if (!ADS_ERR_OK(ads_startup_nobind(c, false, &ads))) {
		d_fprintf(stderr, "Didn't find the cldap server!\n");
		ads_destroy(&ads);
		return -1;
	}

	if (!ads->config.realm) {
		ads->config.realm = CONST_DISCARD(char *, c->opt_target_workgroup);
		ads->ldap.port = 389;
	}

	ret = net_ads_cldap_netlogon(c, ads);
	ads_destroy(&ads);
	return ret;
}



static int net_ads_info(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	char addr[INET6_ADDRSTRLEN];

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads info\n"
			 "    Display information about an Active Directory "
			 "server.\n");
		return 0;
	}

	if (!ADS_ERR_OK(ads_startup_nobind(c, false, &ads))) {
		d_fprintf(stderr, "Didn't find the ldap server!\n");
		return -1;
	}

	if (!ads || !ads->config.realm) {
		d_fprintf(stderr, "Didn't find the ldap server!\n");
		ads_destroy(&ads);
		return -1;
	}

	/* Try to set the server's current time since we didn't do a full
	   TCP LDAP session initially */

	if ( !ADS_ERR_OK(ads_current_time( ads )) ) {
		d_fprintf( stderr, "Failed to get server's current time!\n");
	}

	print_sockaddr(addr, sizeof(addr), &ads->ldap.ss);

	d_printf("LDAP server: %s\n", addr);
	d_printf("LDAP server name: %s\n", ads->config.ldap_server_name);
	d_printf("Realm: %s\n", ads->config.realm);
	d_printf("Bind Path: %s\n", ads->config.bind_path);
	d_printf("LDAP port: %d\n", ads->ldap.port);
	d_printf("Server time: %s\n", 
			 http_timestring(talloc_tos(), ads->config.current_time));

	d_printf("KDC server: %s\n", ads->auth.kdc_server );
	d_printf("Server time offset: %d\n", ads->auth.time_offset );

	ads_destroy(&ads);
	return 0;
}

static void use_in_memory_ccache(void) {
	/* Use in-memory credentials cache so we do not interfere with
	 * existing credentials */
	setenv(KRB5_ENV_CCNAME, "MEMORY:net_ads", 1);
}

static ADS_STATUS ads_startup_int(struct net_context *c, bool only_own_domain,
				  uint32 auth_flags, ADS_STRUCT **ads_ret)
{
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	bool need_password = false;
	bool second_time = false;
	char *cp;
	const char *realm = NULL;
	bool tried_closest_dc = false;

	/* lp_realm() should be handled by a command line param,
	   However, the join requires that realm be set in smb.conf
	   and compares our realm with the remote server's so this is
	   ok until someone needs more flexibility */

	*ads_ret = NULL;

retry_connect:
 	if (only_own_domain) {
		realm = lp_realm();
	} else {
		realm = assume_own_realm(c);
	}

	ads = ads_init(realm, c->opt_target_workgroup, c->opt_host);

retry:
	if (need_password) {
		set_cmdline_auth_info_getpass(c->auth_info);
	}

	if (get_cmdline_auth_info_got_pass(c->auth_info)) {
		use_in_memory_ccache();
		SAFE_FREE(ads->auth.password);
		ads->auth.password = smb_xstrdup(
				get_cmdline_auth_info_password(c->auth_info));
	}

	ads->auth.flags |= auth_flags;
	SAFE_FREE(ads->auth.user_name);
	ads->auth.user_name = smb_xstrdup(
			get_cmdline_auth_info_username(c->auth_info));

       /*
        * If the username is of the form "name@realm",
        * extract the realm and convert to upper case.
        * This is only used to establish the connection.
        */
       if ((cp = strchr_m(ads->auth.user_name, '@'))!=0) {
		*cp++ = '\0';
		SAFE_FREE(ads->auth.realm);
		ads->auth.realm = smb_xstrdup(cp);
		strupper_m(ads->auth.realm);
       }

	status = ads_connect(ads);

	if (!ADS_ERR_OK(status)) {

		if (NT_STATUS_EQUAL(ads_ntstatus(status),
				    NT_STATUS_NO_LOGON_SERVERS)) {
			DEBUG(0,("ads_connect: %s\n", ads_errstr(status)));
			ads_destroy(&ads);
			return status;
		}

		if (!need_password && !second_time && !(auth_flags & ADS_AUTH_NO_BIND)) {
			need_password = true;
			second_time = true;
			goto retry;
		} else {
			ads_destroy(&ads);
			return status;
		}
	}

	/* when contacting our own domain, make sure we use the closest DC.
	 * This is done by reconnecting to ADS because only the first call to
	 * ads_connect will give us our own sitename */

	if ((only_own_domain || !c->opt_host) && !tried_closest_dc) {

		tried_closest_dc = true; /* avoid loop */

		if (!ads_closest_dc(ads)) {

			namecache_delete(ads->server.realm, 0x1C);
			namecache_delete(ads->server.workgroup, 0x1C);

			ads_destroy(&ads);
			ads = NULL;

			goto retry_connect;
		}
	}

	*ads_ret = ads;
	return status;
}

ADS_STATUS ads_startup(struct net_context *c, bool only_own_domain, ADS_STRUCT **ads)
{
	return ads_startup_int(c, only_own_domain, 0, ads);
}

ADS_STATUS ads_startup_nobind(struct net_context *c, bool only_own_domain, ADS_STRUCT **ads)
{
	return ads_startup_int(c, only_own_domain, ADS_AUTH_NO_BIND, ads);
}

/*
  Check to see if connection can be made via ads.
  ads_startup() stores the password in opt_password if it needs to so
  that rpc or rap can use it without re-prompting.
*/
static int net_ads_check_int(const char *realm, const char *workgroup, const char *host)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;

	if ( (ads = ads_init( realm, workgroup, host )) == NULL ) {
		return -1;
	}

	ads->auth.flags |= ADS_AUTH_NO_BIND;

        status = ads_connect(ads);
        if ( !ADS_ERR_OK(status) ) {
                return -1;
        }

	ads_destroy(&ads);
	return 0;
}

int net_ads_check_our_domain(struct net_context *c)
{
	return net_ads_check_int(lp_realm(), lp_workgroup(), NULL);
}

int net_ads_check(struct net_context *c)
{
	return net_ads_check_int(NULL, c->opt_workgroup, c->opt_host);
}

/*
   determine the netbios workgroup name for a domain
 */
static int net_ads_workgroup(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	char addr[INET6_ADDRSTRLEN];
	struct NETLOGON_SAM_LOGON_RESPONSE_EX reply;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads workgroup\n"
			 "    Print the workgroup name\n");
		return 0;
	}

	if (!ADS_ERR_OK(ads_startup_nobind(c, false, &ads))) {
		d_fprintf(stderr, "Didn't find the cldap server!\n");
		return -1;
	}

	if (!ads->config.realm) {
		ads->config.realm = CONST_DISCARD(char *, c->opt_target_workgroup);
		ads->ldap.port = 389;
	}

	print_sockaddr(addr, sizeof(addr), &ads->ldap.ss);
	if ( !ads_cldap_netlogon_5(talloc_tos(), addr, ads->server.realm, &reply ) ) {
		d_fprintf(stderr, "CLDAP query failed!\n");
		ads_destroy(&ads);
		return -1;
	}

	d_printf("Workgroup: %s\n", reply.domain);

	ads_destroy(&ads);

	return 0;
}



static bool usergrp_display(ADS_STRUCT *ads, char *field, void **values, void *data_area)
{
	char **disp_fields = (char **) data_area;

	if (!field) { /* must be end of record */
		if (disp_fields[0]) {
			if (!strchr_m(disp_fields[0], '$')) {
				if (disp_fields[1])
					d_printf("%-21.21s %s\n",
					       disp_fields[0], disp_fields[1]);
				else
					d_printf("%s\n", disp_fields[0]);
			}
		}
		SAFE_FREE(disp_fields[0]);
		SAFE_FREE(disp_fields[1]);
		return true;
	}
	if (!values) /* must be new field, indicate string field */
		return true;
	if (StrCaseCmp(field, "sAMAccountName") == 0) {
		disp_fields[0] = SMB_STRDUP((char *) values[0]);
	}
	if (StrCaseCmp(field, "description") == 0)
		disp_fields[1] = SMB_STRDUP((char *) values[0]);
	return true;
}

static int net_ads_user_usage(struct net_context *c, int argc, const char **argv)
{
	return net_user_usage(c, argc, argv);
}

static int ads_user_add(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	char *upn, *userdn;
	LDAPMessage *res=NULL;
	int rc = -1;
	char *ou_str = NULL;

	if (argc < 1 || c->display_usage)
		return net_ads_user_usage(c, argc, argv);

	if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
		return -1;
	}

	status = ads_find_user_acct(ads, &res, argv[0]);

	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, "ads_user_add: %s\n", ads_errstr(status));
		goto done;
	}

	if (ads_count_replies(ads, res)) {
		d_fprintf(stderr, "ads_user_add: User %s already exists\n", argv[0]);
		goto done;
	}

	if (c->opt_container) {
		ou_str = SMB_STRDUP(c->opt_container);
	} else {
		ou_str = ads_default_ou_string(ads, WELL_KNOWN_GUID_USERS);
	}

	status = ads_add_user_acct(ads, argv[0], ou_str, c->opt_comment);

	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, "Could not add user %s: %s\n", argv[0],
			 ads_errstr(status));
		goto done;
	}

	/* if no password is to be set, we're done */
	if (argc == 1) {
		d_printf("User %s added\n", argv[0]);
		rc = 0;
		goto done;
	}

	/* try setting the password */
	if (asprintf(&upn, "%s@%s", argv[0], ads->config.realm) == -1) {
		goto done;
	}
	status = ads_krb5_set_password(ads->auth.kdc_server, upn, argv[1],
				       ads->auth.time_offset);
	SAFE_FREE(upn);
	if (ADS_ERR_OK(status)) {
		d_printf("User %s added\n", argv[0]);
		rc = 0;
		goto done;
	}

	/* password didn't set, delete account */
	d_fprintf(stderr, "Could not add user %s.  Error setting password %s\n",
		 argv[0], ads_errstr(status));
	ads_msgfree(ads, res);
	status=ads_find_user_acct(ads, &res, argv[0]);
	if (ADS_ERR_OK(status)) {
		userdn = ads_get_dn(ads, talloc_tos(), res);
		ads_del_dn(ads, userdn);
		TALLOC_FREE(userdn);
	}

 done:
	if (res)
		ads_msgfree(ads, res);
	ads_destroy(&ads);
	SAFE_FREE(ou_str);
	return rc;
}

static int ads_user_info(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	LDAPMessage *res;
	const char *attrs[] = {"memberOf", NULL};
	char *searchstring=NULL;
	char **grouplist;
	char *escaped_user;

	if (argc < 1 || c->display_usage) {
		return net_ads_user_usage(c, argc, argv);
	}

	escaped_user = escape_ldap_string_alloc(argv[0]);

	if (!escaped_user) {
		d_fprintf(stderr, "ads_user_info: failed to escape user %s\n", argv[0]);
		return -1;
	}

	if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
		SAFE_FREE(escaped_user);
		return -1;
	}

	if (asprintf(&searchstring, "(sAMAccountName=%s)", escaped_user) == -1) {
		SAFE_FREE(escaped_user);
		return -1;
	}
	rc = ads_search(ads, &res, searchstring, attrs);
	SAFE_FREE(searchstring);

	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "ads_search: %s\n", ads_errstr(rc));
		ads_destroy(&ads);
		SAFE_FREE(escaped_user);
		return -1;
	}

	grouplist = ldap_get_values((LDAP *)ads->ldap.ld,
				    (LDAPMessage *)res, "memberOf");

	if (grouplist) {
		int i;
		char **groupname;
		for (i=0;grouplist[i];i++) {
			groupname = ldap_explode_dn(grouplist[i], 1);
			d_printf("%s\n", groupname[0]);
			ldap_value_free(groupname);
		}
		ldap_value_free(grouplist);
	}

	ads_msgfree(ads, res);
	ads_destroy(&ads);
	SAFE_FREE(escaped_user);
	return 0;
}

static int ads_user_delete(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	LDAPMessage *res = NULL;
	char *userdn;

	if (argc < 1) {
		return net_ads_user_usage(c, argc, argv);
	}

	if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
		return -1;
	}

	rc = ads_find_user_acct(ads, &res, argv[0]);
	if (!ADS_ERR_OK(rc) || ads_count_replies(ads, res) != 1) {
		d_printf("User %s does not exist.\n", argv[0]);
		ads_msgfree(ads, res);
		ads_destroy(&ads);
		return -1;
	}
	userdn = ads_get_dn(ads, talloc_tos(), res);
	ads_msgfree(ads, res);
	rc = ads_del_dn(ads, userdn);
	TALLOC_FREE(userdn);
	if (ADS_ERR_OK(rc)) {
		d_printf("User %s deleted\n", argv[0]);
		ads_destroy(&ads);
		return 0;
	}
	d_fprintf(stderr, "Error deleting user %s: %s\n", argv[0],
		 ads_errstr(rc));
	ads_destroy(&ads);
	return -1;
}

int net_ads_user(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"add",
			ads_user_add,
			NET_TRANSPORT_ADS,
			"Add an AD user",
			"net ads user add\n"
			"    Add an AD user"
		},
		{
			"info",
			ads_user_info,
			NET_TRANSPORT_ADS,
			"Display information about an AD user",
			"net ads user info\n"
			"    Display information about an AD user"
		},
		{
			"delete",
			ads_user_delete,
			NET_TRANSPORT_ADS,
			"Delete an AD user",
			"net ads user delete\n"
			"    Delete an AD user"
		},
		{NULL, NULL, 0, NULL, NULL}
	};
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *shortattrs[] = {"sAMAccountName", NULL};
	const char *longattrs[] = {"sAMAccountName", "description", NULL};
	char *disp_fields[2] = {NULL, NULL};

	if (argc == 0) {
		if (c->display_usage) {
			d_printf("Usage:\n");
			d_printf("net ads user\n"
				 "    List AD users\n");
			net_display_usage_from_functable(func);
			return 0;
		}

		if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
			return -1;
		}

		if (c->opt_long_list_entries)
			d_printf("\nUser name             Comment"
				 "\n-----------------------------\n");

		rc = ads_do_search_all_fn(ads, ads->config.bind_path,
					  LDAP_SCOPE_SUBTREE,
					  "(objectCategory=user)",
					  c->opt_long_list_entries ? longattrs :
					  shortattrs, usergrp_display,
					  disp_fields);
		ads_destroy(&ads);
		return ADS_ERR_OK(rc) ? 0 : -1;
	}

	return net_run_function(c, argc, argv, "net ads user", func);
}

static int net_ads_group_usage(struct net_context *c, int argc, const char **argv)
{
	return net_group_usage(c, argc, argv);
}

static int ads_group_add(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	LDAPMessage *res=NULL;
	int rc = -1;
	char *ou_str = NULL;

	if (argc < 1 || c->display_usage) {
		return net_ads_group_usage(c, argc, argv);
	}

	if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
		return -1;
	}

	status = ads_find_user_acct(ads, &res, argv[0]);

	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, "ads_group_add: %s\n", ads_errstr(status));
		goto done;
	}

	if (ads_count_replies(ads, res)) {
		d_fprintf(stderr, "ads_group_add: Group %s already exists\n", argv[0]);
		goto done;
	}

	if (c->opt_container) {
		ou_str = SMB_STRDUP(c->opt_container);
	} else {
		ou_str = ads_default_ou_string(ads, WELL_KNOWN_GUID_USERS);
	}

	status = ads_add_group_acct(ads, argv[0], ou_str, c->opt_comment);

	if (ADS_ERR_OK(status)) {
		d_printf("Group %s added\n", argv[0]);
		rc = 0;
	} else {
		d_fprintf(stderr, "Could not add group %s: %s\n", argv[0],
			 ads_errstr(status));
	}

 done:
	if (res)
		ads_msgfree(ads, res);
	ads_destroy(&ads);
	SAFE_FREE(ou_str);
	return rc;
}

static int ads_group_delete(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	LDAPMessage *res = NULL;
	char *groupdn;

	if (argc < 1 || c->display_usage) {
		return net_ads_group_usage(c, argc, argv);
	}

	if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
		return -1;
	}

	rc = ads_find_user_acct(ads, &res, argv[0]);
	if (!ADS_ERR_OK(rc) || ads_count_replies(ads, res) != 1) {
		d_printf("Group %s does not exist.\n", argv[0]);
		ads_msgfree(ads, res);
		ads_destroy(&ads);
		return -1;
	}
	groupdn = ads_get_dn(ads, talloc_tos(), res);
	ads_msgfree(ads, res);
	rc = ads_del_dn(ads, groupdn);
	TALLOC_FREE(groupdn);
	if (ADS_ERR_OK(rc)) {
		d_printf("Group %s deleted\n", argv[0]);
		ads_destroy(&ads);
		return 0;
	}
	d_fprintf(stderr, "Error deleting group %s: %s\n", argv[0],
		 ads_errstr(rc));
	ads_destroy(&ads);
	return -1;
}

int net_ads_group(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"add",
			ads_group_add,
			NET_TRANSPORT_ADS,
			"Add an AD group",
			"net ads group add\n"
			"    Add an AD group"
		},
		{
			"delete",
			ads_group_delete,
			NET_TRANSPORT_ADS,
			"Delete an AD group",
			"net ads group delete\n"
			"    Delete an AD group"
		},
		{NULL, NULL, 0, NULL, NULL}
	};
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *shortattrs[] = {"sAMAccountName", NULL};
	const char *longattrs[] = {"sAMAccountName", "description", NULL};
	char *disp_fields[2] = {NULL, NULL};

	if (argc == 0) {
		if (c->display_usage) {
			d_printf("Usage:\n");
			d_printf("net ads group\n"
				 "    List AD groups\n");
			net_display_usage_from_functable(func);
			return 0;
		}

		if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
			return -1;
		}

		if (c->opt_long_list_entries)
			d_printf("\nGroup name            Comment"
				 "\n-----------------------------\n");
		rc = ads_do_search_all_fn(ads, ads->config.bind_path,
					  LDAP_SCOPE_SUBTREE,
					  "(objectCategory=group)",
					  c->opt_long_list_entries ? longattrs :
					  shortattrs, usergrp_display,
					  disp_fields);

		ads_destroy(&ads);
		return ADS_ERR_OK(rc) ? 0 : -1;
	}
	return net_run_function(c, argc, argv, "net ads group", func);
}

static int net_ads_status(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	LDAPMessage *res;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads status\n"
			 "    Display machine account details\n");
		return 0;
	}

	if (!ADS_ERR_OK(ads_startup(c, true, &ads))) {
		return -1;
	}

	rc = ads_find_machine_acct(ads, &res, global_myname());
	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "ads_find_machine_acct: %s\n", ads_errstr(rc));
		ads_destroy(&ads);
		return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, "No machine account for '%s' found\n", global_myname());
		ads_destroy(&ads);
		return -1;
	}

	ads_dump(ads, res);
	ads_destroy(&ads);
	return 0;
}

/*******************************************************************
 Leave an AD domain.  Windows XP disables the machine account.
 We'll try the same.  The old code would do an LDAP delete.
 That only worked using the machine creds because added the machine
 with full control to the computer object's ACL.
*******************************************************************/

static int net_ads_leave(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *ctx;
	struct libnet_UnjoinCtx *r = NULL;
	WERROR werr;
	struct user_auth_info *ai = c->auth_info;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads leave\n"
			 "    Leave an AD domain\n");
		return 0;
	}

	if (!*lp_realm()) {
		d_fprintf(stderr, "No realm set, are we joined ?\n");
		return -1;
	}

	if (!(ctx = talloc_init("net_ads_leave"))) {
		d_fprintf(stderr, "Could not initialise talloc context.\n");
		return -1;
	}

	if (!get_cmdline_auth_info_use_kerberos(ai)) {
		use_in_memory_ccache();
	}

	werr = libnet_init_UnjoinCtx(ctx, &r);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Could not initialise unjoin context.\n");
		return -1;
	}

	set_cmdline_auth_info_getpass(ai);

	r->in.debug		= true;
	r->in.use_kerberos	= get_cmdline_auth_info_use_kerberos(ai);
	r->in.dc_name		= c->opt_host;
	r->in.domain_name	= lp_realm();
	r->in.admin_account	= get_cmdline_auth_info_username(ai);
	r->in.admin_password	= get_cmdline_auth_info_password(ai);
	r->in.modify_config	= lp_config_backend_is_registry();
	r->in.unjoin_flags	= WKSSVC_JOIN_FLAGS_JOIN_TYPE |
				  WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE;

	werr = libnet_Unjoin(ctx, r);
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("Failed to leave domain: %s\n",
			 r->out.error_string ? r->out.error_string :
			 get_friendly_werror_msg(werr));
		goto done;
	}

	if (W_ERROR_IS_OK(werr)) {
		d_printf("Deleted account for '%s' in realm '%s'\n",
			r->in.machine_name, r->out.dns_domain_name);
		goto done;
	}

	/* We couldn't delete it - see if the disable succeeded. */
	if (r->out.disabled_machine_account) {
		d_printf("Disabled account for '%s' in realm '%s'\n",
			r->in.machine_name, r->out.dns_domain_name);
		werr = WERR_OK;
		goto done;
	}

	d_fprintf(stderr, "Failed to disable machine account for '%s' in realm '%s'\n",
		  r->in.machine_name, r->out.dns_domain_name);

 done:
	TALLOC_FREE(r);
	TALLOC_FREE(ctx);

	if (W_ERROR_IS_OK(werr)) {
		return 0;
	}

	return -1;
}

static NTSTATUS net_ads_join_ok(struct net_context *c)
{
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	set_cmdline_auth_info_use_machine_account(c->auth_info);

	status = ads_startup(c, true, &ads);
	if (!ADS_ERR_OK(status)) {
		return ads_ntstatus(status);
	}

	ads_destroy(&ads);
	return NT_STATUS_OK;
}

/*
  check that an existing join is OK
 */
int net_ads_testjoin(struct net_context *c, int argc, const char **argv)
{
	NTSTATUS status;
	use_in_memory_ccache();

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads testjoin\n"
			 "    Test if the existing join is ok\n");
		return 0;
	}

	/* Display success or failure */
	status = net_ads_join_ok(c);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,"Join to domain is not valid: %s\n",
			get_friendly_nt_error_msg(status));
		return -1;
	}

	printf("Join is OK\n");
	return 0;
}

/*******************************************************************
  Simple configu checks before beginning the join
 ********************************************************************/

static WERROR check_ads_config( void )
{
	if (lp_server_role() != ROLE_DOMAIN_MEMBER ) {
		d_printf("Host is not configured as a member server.\n");
		return WERR_INVALID_DOMAIN_ROLE;
	}

	if (strlen(global_myname()) > 15) {
		d_printf("Our netbios name can be at most 15 chars long, "
			 "\"%s\" is %u chars long\n", global_myname(),
			 (unsigned int)strlen(global_myname()));
		return WERR_INVALID_COMPUTERNAME;
	}

	if ( lp_security() == SEC_ADS && !*lp_realm()) {
		d_fprintf(stderr, "realm must be set in in %s for ADS "
			"join to succeed.\n", get_dyn_CONFIGFILE());
		return WERR_INVALID_PARAM;
	}

	return WERR_OK;
}

/*******************************************************************
 Send a DNS update request
*******************************************************************/

#if defined(WITH_DNS_UPDATES)
#include "dns.h"
DNS_ERROR DoDNSUpdate(char *pszServerName,
		      const char *pszDomainName, const char *pszHostName,
		      const struct sockaddr_storage *sslist,
		      size_t num_addrs );

static NTSTATUS net_update_dns_internal(TALLOC_CTX *ctx, ADS_STRUCT *ads,
					const char *machine_name,
					const struct sockaddr_storage *addrs,
					int num_addrs)
{
	struct dns_rr_ns *nameservers = NULL;
	int ns_count = 0;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	DNS_ERROR dns_err;
	fstring dns_server;
	const char *dnsdomain = NULL;
	char *root_domain = NULL;

	if ( (dnsdomain = strchr_m( machine_name, '.')) == NULL ) {
		d_printf("No DNS domain configured for %s. "
			 "Unable to perform DNS Update.\n", machine_name);
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	dnsdomain++;

	status = ads_dns_lookup_ns( ctx, dnsdomain, &nameservers, &ns_count );
	if ( !NT_STATUS_IS_OK(status) || (ns_count == 0)) {
		/* Child domains often do not have NS records.  Look
		   for the NS record for the forest root domain
		   (rootDomainNamingContext in therootDSE) */

		const char *rootname_attrs[] = 	{ "rootDomainNamingContext", NULL };
		LDAPMessage *msg = NULL;
		char *root_dn;
		ADS_STATUS ads_status;

		if ( !ads->ldap.ld ) {
			ads_status = ads_connect( ads );
			if ( !ADS_ERR_OK(ads_status) ) {
				DEBUG(0,("net_update_dns_internal: Failed to connect to our DC!\n"));
				goto done;
			}
		}

		ads_status = ads_do_search(ads, "", LDAP_SCOPE_BASE,
				       "(objectclass=*)", rootname_attrs, &msg);
		if (!ADS_ERR_OK(ads_status)) {
			goto done;
		}

		root_dn = ads_pull_string(ads, ctx, msg,  "rootDomainNamingContext");
		if ( !root_dn ) {
			ads_msgfree( ads, msg );
			goto done;
		}

		root_domain = ads_build_domain( root_dn );

		/* cleanup */
		ads_msgfree( ads, msg );

		/* try again for NS servers */

		status = ads_dns_lookup_ns( ctx, root_domain, &nameservers, &ns_count );

		if ( !NT_STATUS_IS_OK(status) || (ns_count == 0)) {
			DEBUG(3,("net_ads_join: Failed to find name server for the %s "
			 "realm\n", ads->config.realm));
			goto done;
		}

		dnsdomain = root_domain;

	}

	/* Now perform the dns update - we'll try non-secure and if we fail,
	   we'll follow it up with a secure update */

	fstrcpy( dns_server, nameservers[0].hostname );

	dns_err = DoDNSUpdate(dns_server, dnsdomain, machine_name, addrs, num_addrs);
	if (!ERR_DNS_IS_OK(dns_err)) {
		status = NT_STATUS_UNSUCCESSFUL;
	}

done:

	SAFE_FREE( root_domain );

	return status;
}

static NTSTATUS net_update_dns(TALLOC_CTX *mem_ctx, ADS_STRUCT *ads)
{
	int num_addrs;
	struct sockaddr_storage *iplist = NULL;
	fstring machine_name;
	NTSTATUS status;

	name_to_fqdn( machine_name, global_myname() );
	strlower_m( machine_name );

	/* Get our ip address (not the 127.0.0.x address but a real ip
	 * address) */

	num_addrs = get_my_ip_address( &iplist );
	if ( num_addrs <= 0 ) {
		DEBUG(4,("net_update_dns: Failed to find my non-loopback IP "
			 "addresses!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = net_update_dns_internal(mem_ctx, ads, machine_name,
					 iplist, num_addrs);
	SAFE_FREE( iplist );
	return status;
}
#endif


/*******************************************************************
 ********************************************************************/

static int net_ads_join_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf("net ads join [options]\n");
	d_printf("Valid options:\n");
	d_printf("   createupn[=UPN]    Set the userPrincipalName attribute during the join.\n");
	d_printf("                      The deault UPN is in the form host/netbiosname@REALM.\n");
	d_printf("   createcomputer=OU  Precreate the computer account in a specific OU.\n");
	d_printf("                      The OU string read from top to bottom without RDNs and delimited by a '/'.\n");
	d_printf("                      E.g. \"createcomputer=Computers/Servers/Unix\"\n");
	d_printf("                      NB: A backslash '\\' is used as escape at multiple levels and may\n");
	d_printf("                          need to be doubled or even quadrupled.  It is not used as a separator.\n");
	d_printf("   osName=string      Set the operatingSystem attribute during the join.\n");
	d_printf("   osVer=string       Set the operatingSystemVersion attribute during the join.\n");
	d_printf("                      NB: osName and osVer must be specified together for either to take effect.\n");
	d_printf("                          Also, the operatingSystemService attribute is also set when along with\n");
	d_printf("                          the two other attributes.\n");

	return -1;
}

/*******************************************************************
 ********************************************************************/

int net_ads_join(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *ctx = NULL;
	struct libnet_JoinCtx *r = NULL;
	const char *domain = lp_realm();
	WERROR werr = WERR_SETUP_NOT_JOINED;
	bool createupn = false;
	const char *machineupn = NULL;
	const char *create_in_ou = NULL;
	int i;
	const char *os_name = NULL;
	const char *os_version = NULL;
	bool modify_config = lp_config_backend_is_registry();
	struct user_auth_info *ai = c->auth_info;;

	if (c->display_usage)
		return net_ads_join_usage(c, argc, argv);

	if (!modify_config) {

		werr = check_ads_config();
		if (!W_ERROR_IS_OK(werr)) {
			d_fprintf(stderr, "Invalid configuration.  Exiting....\n");
			goto fail;
		}
	}

	if (!(ctx = talloc_init("net_ads_join"))) {
		d_fprintf(stderr, "Could not initialise talloc context.\n");
		werr = WERR_NOMEM;
		goto fail;
	}

	if (!get_cmdline_auth_info_use_kerberos(ai)) {
		use_in_memory_ccache();
	}

	werr = libnet_init_JoinCtx(ctx, &r);
	if (!W_ERROR_IS_OK(werr)) {
		goto fail;
	}

	/* process additional command line args */

	for ( i=0; i<argc; i++ ) {
		if ( !StrnCaseCmp(argv[i], "createupn", strlen("createupn")) ) {
			createupn = true;
			machineupn = get_string_param(argv[i]);
		}
		else if ( !StrnCaseCmp(argv[i], "createcomputer", strlen("createcomputer")) ) {
			if ( (create_in_ou = get_string_param(argv[i])) == NULL ) {
				d_fprintf(stderr, "Please supply a valid OU path.\n");
				werr = WERR_INVALID_PARAM;
				goto fail;
			}
		}
		else if ( !StrnCaseCmp(argv[i], "osName", strlen("osName")) ) {
			if ( (os_name = get_string_param(argv[i])) == NULL ) {
				d_fprintf(stderr, "Please supply a operating system name.\n");
				werr = WERR_INVALID_PARAM;
				goto fail;
			}
		}
		else if ( !StrnCaseCmp(argv[i], "osVer", strlen("osVer")) ) {
			if ( (os_version = get_string_param(argv[i])) == NULL ) {
				d_fprintf(stderr, "Please supply a valid operating system version.\n");
				werr = WERR_INVALID_PARAM;
				goto fail;
			}
		}
		else {
			domain = argv[i];
		}
	}

	if (!*domain) {
		d_fprintf(stderr, "Please supply a valid domain name\n");
		werr = WERR_INVALID_PARAM;
		goto fail;
	}

	/* Do the domain join here */

	set_cmdline_auth_info_getpass(ai);

	r->in.domain_name	= domain;
	r->in.create_upn	= createupn;
	r->in.upn		= machineupn;
	r->in.account_ou	= create_in_ou;
	r->in.os_name		= os_name;
	r->in.os_version	= os_version;
	r->in.dc_name		= c->opt_host;
	r->in.admin_account	= get_cmdline_auth_info_username(ai);
	r->in.admin_password	= get_cmdline_auth_info_password(ai);
	r->in.debug		= true;
	r->in.use_kerberos	= get_cmdline_auth_info_use_kerberos(ai);
	r->in.modify_config	= modify_config;
	r->in.join_flags	= WKSSVC_JOIN_FLAGS_JOIN_TYPE |
				  WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE |
				  WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED;

	werr = libnet_Join(ctx, r);
	if (!W_ERROR_IS_OK(werr)) {
		goto fail;
	}

	/* Check the short name of the domain */

	if (!modify_config && !strequal(lp_workgroup(), r->out.netbios_domain_name)) {
		d_printf("The workgroup in %s does not match the short\n", get_dyn_CONFIGFILE());
		d_printf("domain name obtained from the server.\n");
		d_printf("Using the name [%s] from the server.\n", r->out.netbios_domain_name);
		d_printf("You should set \"workgroup = %s\" in %s.\n",
			 r->out.netbios_domain_name, get_dyn_CONFIGFILE());
	}

	d_printf("Using short domain name -- %s\n", r->out.netbios_domain_name);

	if (r->out.dns_domain_name) {
		d_printf("Joined '%s' to realm '%s'\n", r->in.machine_name,
			r->out.dns_domain_name);
	} else {
		d_printf("Joined '%s' to domain '%s'\n", r->in.machine_name,
			r->out.netbios_domain_name);
	}

#if defined(WITH_DNS_UPDATES)
	if (r->out.domain_is_ad) {
		/* We enter this block with user creds */
		ADS_STRUCT *ads_dns = NULL;

		if ( (ads_dns = ads_init( lp_realm(), NULL, NULL )) != NULL ) {
			/* kinit with the machine password */

			use_in_memory_ccache();
			if (asprintf( &ads_dns->auth.user_name, "%s$", global_myname()) == -1) {
				goto fail;
			}
			ads_dns->auth.password = secrets_fetch_machine_password(
				r->out.netbios_domain_name, NULL, NULL );
			ads_dns->auth.realm = SMB_STRDUP( r->out.dns_domain_name );
			strupper_m(ads_dns->auth.realm );
			ads_kinit_password( ads_dns );
		}

		if ( !ads_dns || !NT_STATUS_IS_OK(net_update_dns( ctx, ads_dns )) ) {
			d_fprintf( stderr, "DNS update failed!\n" );
		}

		/* exit from this block using machine creds */
		ads_destroy(&ads_dns);
	}
#endif
	TALLOC_FREE(r);
	TALLOC_FREE( ctx );

	return 0;

fail:
	/* issue an overall failure message at the end. */
	d_printf("Failed to join domain: %s\n",
		r && r->out.error_string ? r->out.error_string :
		get_friendly_werror_msg(werr));
	TALLOC_FREE( ctx );

        return -1;
}

/*******************************************************************
 ********************************************************************/

static int net_ads_dns_register(struct net_context *c, int argc, const char **argv)
{
#if defined(WITH_DNS_UPDATES)
	ADS_STRUCT *ads;
	ADS_STATUS status;
	TALLOC_CTX *ctx;

#ifdef DEVELOPER
	talloc_enable_leak_report();
#endif

	if (argc > 0 || c->display_usage) {
		d_printf("Usage:\n"
			 "net ads dns register\n"
			 "    Register hostname with DNS\n");
		return -1;
	}

	if (!(ctx = talloc_init("net_ads_dns"))) {
		d_fprintf(stderr, "Could not initialise talloc context\n");
		return -1;
	}

	status = ads_startup(c, true, &ads);
	if ( !ADS_ERR_OK(status) ) {
		DEBUG(1, ("error on ads_startup: %s\n", ads_errstr(status)));
		TALLOC_FREE(ctx);
		return -1;
	}

	if ( !NT_STATUS_IS_OK(net_update_dns(ctx, ads)) ) {
		d_fprintf( stderr, "DNS update failed!\n" );
		ads_destroy( &ads );
		TALLOC_FREE( ctx );
		return -1;
	}

	d_fprintf( stderr, "Successfully registered hostname with DNS\n" );

	ads_destroy(&ads);
	TALLOC_FREE( ctx );

	return 0;
#else
	d_fprintf(stderr, "DNS update support not enabled at compile time!\n");
	return -1;
#endif
}

#if defined(WITH_DNS_UPDATES)
DNS_ERROR do_gethostbyname(const char *server, const char *host);
#endif

static int net_ads_dns_gethostbyname(struct net_context *c, int argc, const char **argv)
{
#if defined(WITH_DNS_UPDATES)
	DNS_ERROR err;

#ifdef DEVELOPER
	talloc_enable_leak_report();
#endif

	if (argc != 2 || c->display_usage) {
		d_printf("Usage:\n"
			 "net ads dns gethostbyname <server> <name>\n"
			 "  Look up hostname from the AD\n"
			 "    server\tName server to use\n"
			 "    name\tName to look up\n");
		return -1;
	}

	err = do_gethostbyname(argv[0], argv[1]);

	d_printf("do_gethostbyname returned %d\n", ERROR_DNS_V(err));
#endif
	return 0;
}

static int net_ads_dns(struct net_context *c, int argc, const char *argv[])
{
	struct functable func[] = {
		{
			"register",
			net_ads_dns_register,
			NET_TRANSPORT_ADS,
			"Add host dns entry to AD",
			"net ads dns register\n"
			"    Add host dns entry to AD"
		},
		{
			"gethostbyname",
			net_ads_dns_gethostbyname,
			NET_TRANSPORT_ADS,
			"Look up host",
			"net ads dns gethostbyname\n"
			"    Look up host"
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads dns", func);
}

/*******************************************************************
 ********************************************************************/

int net_ads_printer_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(
"\nnet ads printer search <printer>"
"\n\tsearch for a printer in the directory\n"
"\nnet ads printer info <printer> <server>"
"\n\tlookup info in directory for printer on server"
"\n\t(note: printer defaults to \"*\", server defaults to local)\n"
"\nnet ads printer publish <printername>"
"\n\tpublish printer in directory"
"\n\t(note: printer name is required)\n"
"\nnet ads printer remove <printername>"
"\n\tremove printer from directory"
"\n\t(note: printer name is required)\n");
	return -1;
}

/*******************************************************************
 ********************************************************************/

static int net_ads_printer_search(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	LDAPMessage *res = NULL;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads printer search\n"
			 "    List printers in the AD\n");
		return 0;
	}

	if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
		return -1;
	}

	rc = ads_find_printers(ads, &res);

	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "ads_find_printer: %s\n", ads_errstr(rc));
		ads_msgfree(ads, res);
		ads_destroy(&ads);
	 	return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, "No results found\n");
		ads_msgfree(ads, res);
		ads_destroy(&ads);
		return -1;
	}

	ads_dump(ads, res);
	ads_msgfree(ads, res);
	ads_destroy(&ads);
	return 0;
}

static int net_ads_printer_info(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *servername, *printername;
	LDAPMessage *res = NULL;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads printer info [printername [servername]]\n"
			 "  Display printer info from AD\n"
			 "    printername\tPrinter name or wildcard\n"
			 "    servername\tName of the print server\n");
		return 0;
	}

	if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
		return -1;
	}

	if (argc > 0) {
		printername = argv[0];
	} else {
		printername = "*";
	}

	if (argc > 1) {
		servername =  argv[1];
	} else {
		servername = global_myname();
	}

	rc = ads_find_printer_on_server(ads, &res, printername, servername);

	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "Server '%s' not found: %s\n",
			servername, ads_errstr(rc));
		ads_msgfree(ads, res);
		ads_destroy(&ads);
		return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, "Printer '%s' not found\n", printername);
		ads_msgfree(ads, res);
		ads_destroy(&ads);
		return -1;
	}

	ads_dump(ads, res);
	ads_msgfree(ads, res);
	ads_destroy(&ads);

	return 0;
}

static int net_ads_printer_publish(struct net_context *c, int argc, const char **argv)
{
        ADS_STRUCT *ads;
        ADS_STATUS rc;
	const char *servername, *printername;
	struct cli_state *cli;
	struct rpc_pipe_client *pipe_hnd;
	struct sockaddr_storage server_ss;
	NTSTATUS nt_status;
	TALLOC_CTX *mem_ctx = talloc_init("net_ads_printer_publish");
	ADS_MODLIST mods = ads_init_mods(mem_ctx);
	char *prt_dn, *srv_dn, **srv_cn;
	char *srv_cn_escaped = NULL, *printername_escaped = NULL;
	LDAPMessage *res = NULL;
	struct user_auth_info *ai = c->auth_info;

	if (argc < 1 || c->display_usage) {
		d_printf("Usage:\n"
			 "net ads printer publish <printername> [servername]\n"
			 "  Publish printer in AD\n"
			 "    printername\tName of the printer\n"
			 "    servername\tName of the print server\n");
		talloc_destroy(mem_ctx);
		return -1;
	}

	if (!ADS_ERR_OK(ads_startup(c, true, &ads))) {
		talloc_destroy(mem_ctx);
		return -1;
	}

	printername = argv[0];

	if (argc == 2) {
		servername = argv[1];
	} else {
		servername = global_myname();
	}

	/* Get printer data from SPOOLSS */

	resolve_name(servername, &server_ss, 0x20);

	nt_status = cli_full_connection(&cli, global_myname(), servername,
					&server_ss, 0,
					"IPC$", "IPC",
					get_cmdline_auth_info_username(ai),
					c->opt_workgroup,
					get_cmdline_auth_info_password(ai),
					CLI_FULL_CONNECTION_USE_KERBEROS,
					Undefined, NULL);

	if (NT_STATUS_IS_ERR(nt_status)) {
		d_fprintf(stderr, "Unable to open a connnection to %s to obtain data "
			 "for %s\n", servername, printername);
		ads_destroy(&ads);
		talloc_destroy(mem_ctx);
		return -1;
	}

	/* Publish on AD server */

	ads_find_machine_acct(ads, &res, servername);

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, "Could not find machine account for server %s\n", 
			 servername);
		ads_destroy(&ads);
		talloc_destroy(mem_ctx);
		return -1;
	}

	srv_dn = ldap_get_dn((LDAP *)ads->ldap.ld, (LDAPMessage *)res);
	srv_cn = ldap_explode_dn(srv_dn, 1);

	srv_cn_escaped = escape_rdn_val_string_alloc(srv_cn[0]);
	printername_escaped = escape_rdn_val_string_alloc(printername);
	if (!srv_cn_escaped || !printername_escaped) {
		SAFE_FREE(srv_cn_escaped);
		SAFE_FREE(printername_escaped);
		d_fprintf(stderr, "Internal error, out of memory!");
		ads_destroy(&ads);
		talloc_destroy(mem_ctx);
		return -1;
	}

	if (asprintf(&prt_dn, "cn=%s-%s,%s", srv_cn_escaped, printername_escaped, srv_dn) == -1) {
		SAFE_FREE(srv_cn_escaped);
		SAFE_FREE(printername_escaped);
		d_fprintf(stderr, "Internal error, out of memory!");
		ads_destroy(&ads);
		talloc_destroy(mem_ctx);
		return -1;
	}

	SAFE_FREE(srv_cn_escaped);
	SAFE_FREE(printername_escaped);

	nt_status = cli_rpc_pipe_open_noauth(cli, &ndr_table_spoolss.syntax_id, &pipe_hnd);
	if (!NT_STATUS_IS_OK(nt_status)) {
		d_fprintf(stderr, "Unable to open a connnection to the spoolss pipe on %s\n",
			 servername);
		SAFE_FREE(prt_dn);
		ads_destroy(&ads);
		talloc_destroy(mem_ctx);
		return -1;
	}

	if (!W_ERROR_IS_OK(get_remote_printer_publishing_data(pipe_hnd, mem_ctx, &mods,
							      printername))) {
		SAFE_FREE(prt_dn);
		ads_destroy(&ads);
		talloc_destroy(mem_ctx);
		return -1;
	}

        rc = ads_add_printer_entry(ads, prt_dn, mem_ctx, &mods);
        if (!ADS_ERR_OK(rc)) {
                d_fprintf(stderr, "ads_publish_printer: %s\n", ads_errstr(rc));
		SAFE_FREE(prt_dn);
		ads_destroy(&ads);
		talloc_destroy(mem_ctx);
                return -1;
        }

        d_printf("published printer\n");
	SAFE_FREE(prt_dn);
	ads_destroy(&ads);
	talloc_destroy(mem_ctx);

	return 0;
}

static int net_ads_printer_remove(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *servername;
	char *prt_dn;
	LDAPMessage *res = NULL;

	if (argc < 1 || c->display_usage) {
		d_printf("Usage:\n"
			 "net ads printer remove <printername> [servername]\n"
			 "  Remove a printer from the AD\n"
			 "    printername\tName of the printer\n"
			 "    servername\tName of the print server\n");
		return -1;
	}

	if (!ADS_ERR_OK(ads_startup(c, true, &ads))) {
		return -1;
	}

	if (argc > 1) {
		servername = argv[1];
	} else {
		servername = global_myname();
	}

	rc = ads_find_printer_on_server(ads, &res, argv[0], servername);

	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "ads_find_printer_on_server: %s\n", ads_errstr(rc));
		ads_msgfree(ads, res);
		ads_destroy(&ads);
		return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, "Printer '%s' not found\n", argv[1]);
		ads_msgfree(ads, res);
		ads_destroy(&ads);
		return -1;
	}

	prt_dn = ads_get_dn(ads, talloc_tos(), res);
	ads_msgfree(ads, res);
	rc = ads_del_dn(ads, prt_dn);
	TALLOC_FREE(prt_dn);

	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "ads_del_dn: %s\n", ads_errstr(rc));
		ads_destroy(&ads);
		return -1;
	}

	ads_destroy(&ads);
	return 0;
}

static int net_ads_printer(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"search",
			net_ads_printer_search,
			NET_TRANSPORT_ADS,
			"Search for a printer",
			"net ads printer search\n"
			"    Search for a printer"
		},
		{
			"info",
			net_ads_printer_info,
			NET_TRANSPORT_ADS,
			"Display printer information",
			"net ads printer info\n"
			"    Display printer information"
		},
		{
			"publish",
			net_ads_printer_publish,
			NET_TRANSPORT_ADS,
			"Publish a printer",
			"net ads printer publish\n"
			"    Publish a printer"
		},
		{
			"remove",
			net_ads_printer_remove,
			NET_TRANSPORT_ADS,
			"Delete a printer",
			"net ads printer remove\n"
			"    Delete a printer"
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads printer", func);
}


static int net_ads_password(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	const char *auth_principal;
	const char *auth_password;
	char *realm = NULL;
	char *new_password = NULL;
	char *chr, *prompt;
	const char *user;
	ADS_STATUS ret;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads password <username>\n"
			 "  Change password for user\n"
			 "    username\tName of user to change password for\n");
		return 0;
	}

	auth_principal = get_cmdline_auth_info_username(c->auth_info);
	set_cmdline_auth_info_getpass(c->auth_info);
	auth_password = get_cmdline_auth_info_password(c->auth_info);

	if (argc < 1) {
		d_fprintf(stderr, "ERROR: You must say which username to change password for\n");
		return -1;
	}

	user = argv[0];
	if (!strchr_m(user, '@')) {
		if (asprintf(&chr, "%s@%s", argv[0], lp_realm()) == -1) {
			return -1;
		}
		user = chr;
	}

	use_in_memory_ccache();
	chr = strchr_m(auth_principal, '@');
	if (chr) {
		realm = ++chr;
	} else {
		realm = lp_realm();
	}

	/* use the realm so we can eventually change passwords for users
	in realms other than default */
	if (!(ads = ads_init(realm, c->opt_workgroup, c->opt_host))) {
		return -1;
	}

	/* we don't actually need a full connect, but it's the easy way to
		fill in the KDC's addresss */
	ads_connect(ads);

	if (!ads->config.realm) {
		d_fprintf(stderr, "Didn't find the kerberos server!\n");
		ads_destroy(&ads);
		return -1;
	}

	if (argv[1]) {
		new_password = (char *)argv[1];
	} else {
		if (asprintf(&prompt, "Enter new password for %s:", user) == -1) {
			return -1;
		}
		new_password = getpass(prompt);
		free(prompt);
	}

	ret = kerberos_set_password(ads->auth.kdc_server, auth_principal,
				auth_password, user, new_password, ads->auth.time_offset);
	if (!ADS_ERR_OK(ret)) {
		d_fprintf(stderr, "Password change failed: %s\n", ads_errstr(ret));
		ads_destroy(&ads);
		return -1;
	}

	d_printf("Password change for %s completed.\n", user);
	ads_destroy(&ads);

	return 0;
}

int net_ads_changetrustpw(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	char *host_principal;
	fstring my_name;
	ADS_STATUS ret;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads changetrustpw\n"
			 "    Change the machine account's trust password\n");
		return 0;
	}

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}

	set_cmdline_auth_info_use_machine_account(c->auth_info);

	use_in_memory_ccache();

	if (!ADS_ERR_OK(ads_startup(c, true, &ads))) {
		return -1;
	}

	fstrcpy(my_name, global_myname());
	strlower_m(my_name);
	if (asprintf(&host_principal, "%s$@%s", my_name, ads->config.realm) == -1) {
		ads_destroy(&ads);
		return -1;
	}
	d_printf("Changing password for principal: %s\n", host_principal);

	ret = ads_change_trust_account_password(ads, host_principal);

	if (!ADS_ERR_OK(ret)) {
		d_fprintf(stderr, "Password change failed: %s\n", ads_errstr(ret));
		ads_destroy(&ads);
		SAFE_FREE(host_principal);
		return -1;
	}

	d_printf("Password change for principal %s succeeded.\n", host_principal);

	if (USE_SYSTEM_KEYTAB) {
		d_printf("Attempting to update system keytab with new password.\n");
		if (ads_keytab_create_default(ads)) {
			d_printf("Failed to update system keytab.\n");
		}
	}

	ads_destroy(&ads);
	SAFE_FREE(host_principal);

	return 0;
}

/*
  help for net ads search
*/
static int net_ads_search_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(
		"\nnet ads search <expression> <attributes...>\n"
		"\nPerform a raw LDAP search on a ADS server and dump the results.\n"
		"The expression is a standard LDAP search expression, and the\n"
		"attributes are a list of LDAP fields to show in the results.\n\n"
		"Example: net ads search '(objectCategory=group)' sAMAccountName\n\n"
		);
	net_common_flags_usage(c, argc, argv);
	return -1;
}


/*
  general ADS search function. Useful in diagnosing problems in ADS
*/
static int net_ads_search(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *ldap_exp;
	const char **attrs;
	LDAPMessage *res = NULL;

	if (argc < 1 || c->display_usage) {
		return net_ads_search_usage(c, argc, argv);
	}

	if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
		return -1;
	}

	ldap_exp = argv[0];
	attrs = (argv + 1);

	rc = ads_do_search_all(ads, ads->config.bind_path,
			       LDAP_SCOPE_SUBTREE,
			       ldap_exp, attrs, &res);
	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "search failed: %s\n", ads_errstr(rc));
		ads_destroy(&ads);
		return -1;
	}

	d_printf("Got %d replies\n\n", ads_count_replies(ads, res));

	/* dump the results */
	ads_dump(ads, res);

	ads_msgfree(ads, res);
	ads_destroy(&ads);

	return 0;
}


/*
  help for net ads search
*/
static int net_ads_dn_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(
		"\nnet ads dn <dn> <attributes...>\n"
		"\nperform a raw LDAP search on a ADS server and dump the results\n"
		"The DN standard LDAP DN, and the attributes are a list of LDAP fields \n"
		"to show in the results\n\n"
		"Example: net ads dn 'CN=administrator,CN=Users,DC=my,DC=domain' sAMAccountName\n\n"
		"Note: the DN must be provided properly escaped. See RFC 4514 for details\n\n"
		);
	net_common_flags_usage(c, argc, argv);
	return -1;
}


/*
  general ADS search function. Useful in diagnosing problems in ADS
*/
static int net_ads_dn(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *dn;
	const char **attrs;
	LDAPMessage *res = NULL;

	if (argc < 1 || c->display_usage) {
		return net_ads_dn_usage(c, argc, argv);
	}

	if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
		return -1;
	}

	dn = argv[0];
	attrs = (argv + 1);

	rc = ads_do_search_all(ads, dn,
			       LDAP_SCOPE_BASE,
			       "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "search failed: %s\n", ads_errstr(rc));
		ads_destroy(&ads);
		return -1;
	}

	d_printf("Got %d replies\n\n", ads_count_replies(ads, res));

	/* dump the results */
	ads_dump(ads, res);

	ads_msgfree(ads, res);
	ads_destroy(&ads);

	return 0;
}

/*
  help for net ads sid search
*/
static int net_ads_sid_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(
		"\nnet ads sid <sid> <attributes...>\n"
		"\nperform a raw LDAP search on a ADS server and dump the results\n"
		"The SID is in string format, and the attributes are a list of LDAP fields \n"
		"to show in the results\n\n"
		"Example: net ads sid 'S-1-5-32' distinguishedName\n\n"
		);
	net_common_flags_usage(c, argc, argv);
	return -1;
}


/*
  general ADS search function. Useful in diagnosing problems in ADS
*/
static int net_ads_sid(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *sid_string;
	const char **attrs;
	LDAPMessage *res = NULL;
	DOM_SID sid;

	if (argc < 1 || c->display_usage) {
		return net_ads_sid_usage(c, argc, argv);
	}

	if (!ADS_ERR_OK(ads_startup(c, false, &ads))) {
		return -1;
	}

	sid_string = argv[0];
	attrs = (argv + 1);

	if (!string_to_sid(&sid, sid_string)) {
		d_fprintf(stderr, "could not convert sid\n");
		ads_destroy(&ads);
		return -1;
	}

	rc = ads_search_retry_sid(ads, &res, &sid, attrs);
	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "search failed: %s\n", ads_errstr(rc));
		ads_destroy(&ads);
		return -1;
	}

	d_printf("Got %d replies\n\n", ads_count_replies(ads, res));

	/* dump the results */
	ads_dump(ads, res);

	ads_msgfree(ads, res);
	ads_destroy(&ads);

	return 0;
}

static int net_ads_keytab_flush(struct net_context *c, int argc, const char **argv)
{
	int ret;
	ADS_STRUCT *ads;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads keytab flush\n"
			 "    Delete the whole keytab\n");
		return 0;
	}

	if (!ADS_ERR_OK(ads_startup(c, true, &ads))) {
		return -1;
	}
	ret = ads_keytab_flush(ads);
	ads_destroy(&ads);
	return ret;
}

static int net_ads_keytab_add(struct net_context *c, int argc, const char **argv)
{
	int i;
	int ret = 0;
	ADS_STRUCT *ads;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads keytab add <principal> [principal ...]\n"
			 "  Add principals to local keytab\n"
			 "    principal\tKerberos principal to add to "
			 "keytab\n");
		return 0;
	}

	d_printf("Processing principals to add...\n");
	if (!ADS_ERR_OK(ads_startup(c, true, &ads))) {
		return -1;
	}
	for (i = 0; i < argc; i++) {
		ret |= ads_keytab_add_entry(ads, argv[i]);
	}
	ads_destroy(&ads);
	return ret;
}

static int net_ads_keytab_create(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	int ret;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads keytab create\n"
			 "    Create new default keytab\n");
		return 0;
	}

	if (!ADS_ERR_OK(ads_startup(c, true, &ads))) {
		return -1;
	}
	ret = ads_keytab_create_default(ads);
	ads_destroy(&ads);
	return ret;
}

static int net_ads_keytab_list(struct net_context *c, int argc, const char **argv)
{
	const char *keytab = NULL;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads keytab list [keytab]\n"
			 "  List a local keytab\n"
			 "    keytab\tKeytab to list\n");
		return 0;
	}

	if (argc >= 1) {
		keytab = argv[0];
	}

	return ads_keytab_list(keytab);
}


int net_ads_keytab(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"add",
			net_ads_keytab_add,
			NET_TRANSPORT_ADS,
			"Add a service principal",
			"net ads keytab add\n"
			"    Add a service principal"
		},
		{
			"create",
			net_ads_keytab_create,
			NET_TRANSPORT_ADS,
			"Create a fresh keytab",
			"net ads keytab create\n"
			"    Create a fresh keytab"
		},
		{
			"flush",
			net_ads_keytab_flush,
			NET_TRANSPORT_ADS,
			"Remove all keytab entries",
			"net ads keytab flush\n"
			"    Remove all keytab entries"
		},
		{
			"list",
			net_ads_keytab_list,
			NET_TRANSPORT_ADS,
			"List a keytab",
			"net ads keytab list\n"
			"    List a keytab"
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	if (!USE_KERBEROS_KEYTAB) {
		d_printf("\nWarning: \"kerberos method\" must be set to a "
		    "keytab method to use keytab functions.\n");
	}

	return net_run_function(c, argc, argv, "net ads keytab", func);
}

static int net_ads_kerberos_renew(struct net_context *c, int argc, const char **argv)
{
	int ret = -1;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads kerberos renew\n"
			 "    Renew TGT from existing credential cache\n");
		return 0;
	}

	ret = smb_krb5_renew_ticket(NULL, NULL, NULL, NULL);
	if (ret) {
		d_printf("failed to renew kerberos ticket: %s\n",
			error_message(ret));
	}
	return ret;
}

static int net_ads_kerberos_pac(struct net_context *c, int argc, const char **argv)
{
	struct PAC_DATA *pac = NULL;
	struct PAC_LOGON_INFO *info = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	NTSTATUS status;
	int ret = -1;
	struct user_auth_info *ai = c->auth_info;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads kerberos pac\n"
			 "    Dump the Kerberos PAC\n");
		return 0;
	}

	mem_ctx = talloc_init("net_ads_kerberos_pac");
	if (!mem_ctx) {
		goto out;
	}

	set_cmdline_auth_info_getpass(ai);

	status = kerberos_return_pac(mem_ctx,
				     get_cmdline_auth_info_username(ai),
				     get_cmdline_auth_info_password(ai),
			     	     0,
				     NULL,
				     NULL,
				     NULL,
				     true,
				     true,
				     2592000, /* one month */
				     &pac);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("failed to query kerberos PAC: %s\n",
			nt_errstr(status));
		goto out;
	}

	info = get_logon_info_from_pac(pac);
	if (info) {
		const char *s;
		s = NDR_PRINT_STRUCT_STRING(mem_ctx, PAC_LOGON_INFO, info);
		d_printf("The Pac: %s\n", s);
	}

	ret = 0;
 out:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_ads_kerberos_kinit(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx = NULL;
	int ret = -1;
	NTSTATUS status;
	struct user_auth_info *ai = c->auth_info;

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net ads kerberos kinit\n"
			 "    Get Ticket Granting Ticket (TGT) for the user\n");
		return 0;
	}

	mem_ctx = talloc_init("net_ads_kerberos_kinit");
	if (!mem_ctx) {
		goto out;
	}

	set_cmdline_auth_info_getpass(ai);

	ret = kerberos_kinit_password_ext(get_cmdline_auth_info_username(ai),
					  get_cmdline_auth_info_password(ai),
					  0,
					  NULL,
					  NULL,
					  NULL,
					  true,
					  true,
					  2592000, /* one month */
					  &status);
	if (ret) {
		d_printf("failed to kinit password: %s\n",
			nt_errstr(status));
	}
 out:
	return ret;
}

int net_ads_kerberos(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"kinit",
			net_ads_kerberos_kinit,
			NET_TRANSPORT_ADS,
			"Retrieve Ticket Granting Ticket (TGT)",
			"net ads kerberos kinit\n"
			"    Receive Ticket Granting Ticket (TGT)"
		},
		{
			"renew",
			net_ads_kerberos_renew,
			NET_TRANSPORT_ADS,
			"Renew Ticket Granting Ticket from credential cache"
			"net ads kerberos renew\n"
			"    Renew Ticket Granting Ticket from credential cache"
		},
		{
			"pac",
			net_ads_kerberos_pac,
			NET_TRANSPORT_ADS,
			"Dump Kerberos PAC",
			"net ads kerberos pac\n"
			"    Dump Kerberos PAC"
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads kerberos", func);
}

int net_ads(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"info",
			net_ads_info,
			NET_TRANSPORT_ADS,
			"Display details on remote ADS server",
			"net ads info\n"
			"    Display details on remote ADS server"
		},
		{
			"join",
			net_ads_join,
			NET_TRANSPORT_ADS,
			"Join the local machine to ADS realm",
			"net ads join\n"
			"    Join the local machine to ADS realm"
		},
		{
			"testjoin",
			net_ads_testjoin,
			NET_TRANSPORT_ADS,
			"Validate machine account",
			"net ads testjoin\n"
			"    Validate machine account"
		},
		{
			"leave",
			net_ads_leave,
			NET_TRANSPORT_ADS,
			"Remove the local machine from ADS",
			"net ads leave\n"
			"    Remove the local machine from ADS"
		},
		{
			"status",
			net_ads_status,
			NET_TRANSPORT_ADS,
			"Display machine account details",
			"net ads status\n"
			"    Display machine account details"
		},
		{
			"user",
			net_ads_user,
			NET_TRANSPORT_ADS,
			"List/modify users",
			"net ads user\n"
			"    List/modify users"
		},
		{
			"group",
			net_ads_group,
			NET_TRANSPORT_ADS,
			"List/modify groups",
			"net ads group\n"
			"    List/modify groups"
		},
		{
			"dns",
			net_ads_dns,
			NET_TRANSPORT_ADS,
			"Issue dynamic DNS update",
			"net ads dns\n"
			"    Issue dynamic DNS update"
		},
		{
			"password",
			net_ads_password,
			NET_TRANSPORT_ADS,
			"Change user passwords",
			"net ads password\n"
			"    Change user passwords"
		},
		{
			"changetrustpw",
			net_ads_changetrustpw,
			NET_TRANSPORT_ADS,
			"Change trust account password",
			"net ads changetrustpw\n"
			"    Change trust account password"
		},
		{
			"printer",
			net_ads_printer,
			NET_TRANSPORT_ADS,
			"List/modify printer entries",
			"net ads printer\n"
			"    List/modify printer entries"
		},
		{
			"search",
			net_ads_search,
			NET_TRANSPORT_ADS,
			"Issue LDAP search using filter",
			"net ads search\n"
			"    Issue LDAP search using filter"
		},
		{
			"dn",
			net_ads_dn,
			NET_TRANSPORT_ADS,
			"Issue LDAP search by DN",
			"net ads dn\n"
			"    Issue LDAP search by DN"
		},
		{
			"sid",
			net_ads_sid,
			NET_TRANSPORT_ADS,
			"Issue LDAP search by SID",
			"net ads sid\n"
			"    Issue LDAP search by SID"
		},
		{
			"workgroup",
			net_ads_workgroup,
			NET_TRANSPORT_ADS,
			"Display workgroup name",
			"net ads workgroup\n"
			"    Display the workgroup name"
		},
		{
			"lookup",
			net_ads_lookup,
			NET_TRANSPORT_ADS,
			"Perfom CLDAP query on DC",
			"net ads lookup\n"
			"    Find the ADS DC using CLDAP lookups"
		},
		{
			"keytab",
			net_ads_keytab,
			NET_TRANSPORT_ADS,
			"Manage local keytab file",
			"net ads keytab\n"
			"    Manage local keytab file"
		},
		{
			"gpo",
			net_ads_gpo,
			NET_TRANSPORT_ADS,
			"Manage group policy objects",
			"net ads gpo\n"
			"    Manage group policy objects"
		},
		{
			"kerberos",
			net_ads_kerberos,
			NET_TRANSPORT_ADS,
			"Manage kerberos keytab",
			"net ads kerberos\n"
			"    Manage kerberos keytab"
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads", func);
}

#else

static int net_ads_noads(void)
{
	d_fprintf(stderr, "ADS support not compiled in\n");
	return -1;
}

int net_ads_keytab(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_kerberos(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_changetrustpw(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_join(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_user(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_group(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

/* this one shouldn't display a message */
int net_ads_check(struct net_context *c)
{
	return -1;
}

int net_ads_check_our_domain(struct net_context *c)
{
	return -1;
}

int net_ads(struct net_context *c, int argc, const char **argv)
{
	return net_ads_noads();
}

#endif	/* WITH_ADS */
