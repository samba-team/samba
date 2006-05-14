/* 
   Samba Unix/Linux SMB client library 
   net ads commands
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2001 Remus Koos (remuskoos@yahoo.com)
   Copyright (C) 2002 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2006 Gerald (Jerry) Carter (jerry@samba.org)

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
#include "utils/net.h"

/* Macro for checking RPC error codes to make things more readable */

#define CHECK_RPC_ERR(rpc, msg) \
        if (!NT_STATUS_IS_OK(result = rpc)) { \
                DEBUG(0, (msg ": %s\n", nt_errstr(result))); \
                goto done; \
        }

#define CHECK_RPC_ERR_DEBUG(rpc, debug_args) \
        if (!NT_STATUS_IS_OK(result = rpc)) { \
                DEBUG(0, debug_args); \
                goto done; \
        }

#ifdef HAVE_ADS

int net_ads_usage(int argc, const char **argv)
{
	d_printf(
"\nnet ads join <org_unit>"\
"\n\tjoins the local machine to a ADS realm\n"\
"\nnet ads leave"\
"\n\tremoves the local machine from a ADS realm\n"\
"\nnet ads testjoin"\
"\n\ttests that an exiting join is OK\n"\
"\nnet ads user"\
"\n\tlist, add, or delete users in the realm\n"\
"\nnet ads group"\
"\n\tlist, add, or delete groups in the realm\n"\
"\nnet ads info"\
"\n\tshows some info on the server\n"\
"\nnet ads status"\
"\n\tdump the machine account details to stdout\n"
"\nnet ads lookup"\
"\n\tperform a CLDAP search on the server\n"
"\nnet ads password <username@realm> <password> -Uadmin_username@realm%%admin_pass"\
"\n\tchange a user's password using an admin account"\
"\n\t(note: use realm in UPPERCASE, prompts if password is obmitted)\n"\
"\nnet ads changetrustpw"\
"\n\tchange the trust account password of this machine in the AD tree\n"\
"\nnet ads printer [info | publish | remove] <printername> <servername>"\
"\n\t lookup, add, or remove directory entry for a printer\n"\
"\nnet ads search"\
"\n\tperform a raw LDAP search and dump the results\n"
"\nnet ads dn"\
"\n\tperform a raw LDAP search and dump attributes of a particular DN\n"
"\nnet ads sid"\
"\n\tperform a raw LDAP search and dump attributes of a particular SID\n"
"\nnet ads keytab"\
"\n\tcreates and updates the kerberos system keytab file\n"
		);
	return -1;
}


/*
  do a cldap netlogon query
*/
static int net_ads_cldap_netlogon(ADS_STRUCT *ads)
{
	struct cldap_netlogon_reply reply;

	if ( !ads_cldap_netlogon( inet_ntoa(ads->ldap_ip), ads->server.realm, &reply ) ) {
		d_fprintf(stderr, "CLDAP query failed!\n");
		return -1;
	}

	d_printf("Information for Domain Controller: %s\n\n", 
		inet_ntoa(ads->ldap_ip));

	d_printf("Response Type: ");
	switch (reply.type) {
	case SAMLOGON_AD_UNK_R:
		d_printf("SAMLOGON\n");
		break;
	case SAMLOGON_AD_R:
		d_printf("SAMLOGON_USER\n");
		break;
	default:
		d_printf("0x%x\n", reply.type);
		break;
	}
	d_printf("GUID: %s\n", 
		 smb_uuid_string_static(smb_uuid_unpack_static(reply.guid))); 
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
		 "\tIs a non-domain NC serviced by LDAP server: %s\n",
		 (reply.flags & ADS_PDC) ? "yes" : "no",
		 (reply.flags & ADS_GC) ? "yes" : "no",
		 (reply.flags & ADS_LDAP) ? "yes" : "no",
		 (reply.flags & ADS_DS) ? "yes" : "no",
		 (reply.flags & ADS_KDC) ? "yes" : "no",
		 (reply.flags & ADS_TIMESERV) ? "yes" : "no",
		 (reply.flags & ADS_CLOSEST) ? "yes" : "no",
		 (reply.flags & ADS_WRITABLE) ? "yes" : "no",
		 (reply.flags & ADS_GOOD_TIMESERV) ? "yes" : "no",
		 (reply.flags & ADS_NDNC) ? "yes" : "no");

	printf("Forest:\t\t\t%s\n", reply.forest);
	printf("Domain:\t\t\t%s\n", reply.domain);
	printf("Domain Controller:\t%s\n", reply.hostname);

	printf("Pre-Win2k Domain:\t%s\n", reply.netbios_domain);
	printf("Pre-Win2k Hostname:\t%s\n", reply.netbios_hostname);

	if (*reply.unk) printf("Unk:\t\t\t%s\n", reply.unk);
	if (*reply.user_name) printf("User name:\t%s\n", reply.user_name);

	printf("Site Name:\t\t%s\n", reply.site_name);
	printf("Site Name (2):\t\t%s\n", reply.site_name_2);

	d_printf("NT Version: %d\n", reply.version);
	d_printf("LMNT Token: %.2x\n", reply.lmnt_token);
	d_printf("LM20 Token: %.2x\n", reply.lm20_token);

	return 0;
}


/*
  this implements the CLDAP based netlogon lookup requests
  for finding the domain controller of a ADS domain
*/
static int net_ads_lookup(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	const char *realm = NULL;

	if ( strequal(lp_workgroup(), opt_target_workgroup ) )
		realm = lp_realm();

	ads = ads_init(realm, opt_target_workgroup, opt_host);
	if (ads) {
		ads->auth.flags |= ADS_AUTH_NO_BIND;
	}

	status = ads_connect(ads);
	if (!ADS_ERR_OK(status) || !ads) {
		d_fprintf(stderr, "Didn't find the cldap server!\n");
		return -1;
	}
	
	if (!ads->config.realm) {
		ads->config.realm = CONST_DISCARD(char *, opt_target_workgroup);
		ads->ldap_port = 389;
	}

	return net_ads_cldap_netlogon(ads);
}



static int net_ads_info(int argc, const char **argv)
{
	ADS_STRUCT *ads;

	if ( (ads = ads_init(lp_realm(), opt_target_workgroup, opt_host)) != NULL ) {
		ads->auth.flags |= ADS_AUTH_NO_BIND;
	}

	ads_connect(ads);

	if (!ads || !ads->config.realm) {
		d_fprintf(stderr, "Didn't find the ldap server!\n");
		return -1;
	}

	/* Try to set the server's current time since we didn't do a full
	   TCP LDAP session initially */

	if ( !ADS_ERR_OK(ads_current_time( ads )) ) {
		d_fprintf( stderr, "Failed to get server's current time!\n");
	}

	d_printf("LDAP server: %s\n", inet_ntoa(ads->ldap_ip));
	d_printf("LDAP server name: %s\n", ads->config.ldap_server_name);
	d_printf("Realm: %s\n", ads->config.realm);
	d_printf("Bind Path: %s\n", ads->config.bind_path);
	d_printf("LDAP port: %d\n", ads->ldap_port);
	d_printf("Server time: %s\n", http_timestring(ads->config.current_time));

	d_printf("KDC server: %s\n", ads->auth.kdc_server );
	d_printf("Server time offset: %d\n", ads->auth.time_offset );

	return 0;
}

static void use_in_memory_ccache(void) {
	/* Use in-memory credentials cache so we do not interfere with
	 * existing credentials */
	setenv(KRB5_ENV_CCNAME, "MEMORY:net_ads", 1);
}

static ADS_STRUCT *ads_startup(void)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	BOOL need_password = False;
	BOOL second_time = False;
	char *cp;
	
	/* lp_realm() should be handled by a command line param, 
	   However, the join requires that realm be set in smb.conf
	   and compares our realm with the remote server's so this is
	   ok until someone needs more flexibility */
	   
	ads = ads_init(lp_realm(), opt_target_workgroup, opt_host);

	if (!opt_user_name) {
		opt_user_name = "administrator";
	}

	if (opt_user_specified) {
		need_password = True;
	}

retry:
	if (!opt_password && need_password && !opt_machine_pass) {
		char *prompt;
		asprintf(&prompt,"%s's password: ", opt_user_name);
		opt_password = getpass(prompt);
		free(prompt);
	}

	if (opt_password) {
		use_in_memory_ccache();
		ads->auth.password = smb_xstrdup(opt_password);
	}

	ads->auth.user_name = smb_xstrdup(opt_user_name);

       /*
        * If the username is of the form "name@realm", 
        * extract the realm and convert to upper case.
        * This is only used to establish the connection.
        */
       if ((cp = strchr_m(ads->auth.user_name, '@'))!=0) {
               *cp++ = '\0';
               ads->auth.realm = smb_xstrdup(cp);
               strupper_m(ads->auth.realm);
       }

	status = ads_connect(ads);

	if (!ADS_ERR_OK(status)) {
		if (!need_password && !second_time) {
			need_password = True;
			second_time = True;
			goto retry;
		} else {
			DEBUG(0,("ads_connect: %s\n", ads_errstr(status)));
			return NULL;
		}
	}
	return ads;
}


/*
  Check to see if connection can be made via ads.
  ads_startup() stores the password in opt_password if it needs to so
  that rpc or rap can use it without re-prompting.
*/
int net_ads_check(void)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;

	if ( (ads = ads_init( lp_realm(), lp_workgroup(), NULL )) == NULL ) {
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

/* 
   determine the netbios workgroup name for a domain
 */
static int net_ads_workgroup(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	const char *realm = NULL;
	struct cldap_netlogon_reply reply;

	if ( strequal(lp_workgroup(), opt_target_workgroup ) )
		realm = lp_realm();

	ads = ads_init(realm, opt_target_workgroup, opt_host);
	if (ads) {
		ads->auth.flags |= ADS_AUTH_NO_BIND;
	}

	status = ads_connect(ads);
	if (!ADS_ERR_OK(status) || !ads) {
		d_fprintf(stderr, "Didn't find the cldap server!\n");
		return -1;
	}
	
	if (!ads->config.realm) {
		ads->config.realm = CONST_DISCARD(char *, opt_target_workgroup);
		ads->ldap_port = 389;
	}
	
	if ( !ads_cldap_netlogon( inet_ntoa(ads->ldap_ip), ads->server.realm, &reply ) ) {
		d_fprintf(stderr, "CLDAP query failed!\n");
		return -1;
	}

	d_printf("Workgroup: %s\n", reply.netbios_domain);

	ads_destroy(&ads);
	
	return 0;
}



static BOOL usergrp_display(char *field, void **values, void *data_area)
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
		return True;
	}
	if (!values) /* must be new field, indicate string field */
		return True;
	if (StrCaseCmp(field, "sAMAccountName") == 0) {
		disp_fields[0] = SMB_STRDUP((char *) values[0]);
	}
	if (StrCaseCmp(field, "description") == 0)
		disp_fields[1] = SMB_STRDUP((char *) values[0]);
	return True;
}

static int net_ads_user_usage(int argc, const char **argv)
{
	return net_help_user(argc, argv);
} 

static int ads_user_add(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	char *upn, *userdn;
	void *res=NULL;
	int rc = -1;

	if (argc < 1) return net_ads_user_usage(argc, argv);
	
	if (!(ads = ads_startup())) {
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

	if (opt_container == NULL) {
		opt_container = ads_default_ou_string(ads, WELL_KNOWN_GUID_USERS);
	}

	status = ads_add_user_acct(ads, argv[0], opt_container, opt_comment);

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
	asprintf(&upn, "%s@%s", argv[0], ads->config.realm);
	status = ads_krb5_set_password(ads->auth.kdc_server, upn, argv[1], 
				       ads->auth.time_offset);
	safe_free(upn);
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
		userdn = ads_get_dn(ads, res);
		ads_del_dn(ads, userdn);
		ads_memfree(ads, userdn);
	}

 done:
	if (res)
		ads_msgfree(ads, res);
	ads_destroy(&ads);
	return rc;
}

static int ads_user_info(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	void *res;
	const char *attrs[] = {"memberOf", NULL};
	char *searchstring=NULL;
	char **grouplist;
	char *escaped_user;

	if (argc < 1) {
		return net_ads_user_usage(argc, argv);
	}

	escaped_user = escape_ldap_string_alloc(argv[0]);

	if (!escaped_user) {
		d_fprintf(stderr, "ads_user_info: failed to escape user %s\n", argv[0]);
		return -1;
	}

	if (!(ads = ads_startup())) {
		SAFE_FREE(escaped_user);
		return -1;
	}

	asprintf(&searchstring, "(sAMAccountName=%s)", escaped_user);
	rc = ads_search(ads, &res, searchstring, attrs);
	safe_free(searchstring);

	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "ads_search: %s\n", ads_errstr(rc));
		ads_destroy(&ads);
		SAFE_FREE(escaped_user);
		return -1;
	}
	
	grouplist = ldap_get_values(ads->ld, res, "memberOf");

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

static int ads_user_delete(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	void *res;
	char *userdn;

	if (argc < 1) {
		return net_ads_user_usage(argc, argv);
	}
	
	if (!(ads = ads_startup())) {
		return -1;
	}

	rc = ads_find_user_acct(ads, &res, argv[0]);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(0, ("User %s does not exist\n", argv[0]));
		ads_destroy(&ads);
		return -1;
	}
	userdn = ads_get_dn(ads, res);
	ads_msgfree(ads, res);
	rc = ads_del_dn(ads, userdn);
	ads_memfree(ads, userdn);
	if (!ADS_ERR_OK(rc)) {
		d_printf("User %s deleted\n", argv[0]);
		ads_destroy(&ads);
		return 0;
	}
	d_fprintf(stderr, "Error deleting user %s: %s\n", argv[0], 
		 ads_errstr(rc));
	ads_destroy(&ads);
	return -1;
}

int net_ads_user(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADD", ads_user_add},
		{"INFO", ads_user_info},
		{"DELETE", ads_user_delete},
		{NULL, NULL}
	};
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *shortattrs[] = {"sAMAccountName", NULL};
	const char *longattrs[] = {"sAMAccountName", "description", NULL};
	char *disp_fields[2] = {NULL, NULL};
	
	if (argc == 0) {
		if (!(ads = ads_startup())) {
			return -1;
		}

		if (opt_long_list_entries)
			d_printf("\nUser name             Comment"\
				 "\n-----------------------------\n");

		rc = ads_do_search_all_fn(ads, ads->config.bind_path, 
					  LDAP_SCOPE_SUBTREE,
					  "(objectCategory=user)", 
					  opt_long_list_entries ? longattrs :
					  shortattrs, usergrp_display, 
					  disp_fields);
		ads_destroy(&ads);
		return 0;
	}

	return net_run_function(argc, argv, func, net_ads_user_usage);
}

static int net_ads_group_usage(int argc, const char **argv)
{
	return net_help_group(argc, argv);
} 

static int ads_group_add(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	void *res=NULL;
	int rc = -1;

	if (argc < 1) {
		return net_ads_group_usage(argc, argv);
	}
	
	if (!(ads = ads_startup())) {
		return -1;
	}

	status = ads_find_user_acct(ads, &res, argv[0]);

	if (!ADS_ERR_OK(status)) {
		d_fprintf(stderr, "ads_group_add: %s\n", ads_errstr(status));
		goto done;
	}
	
	if (ads_count_replies(ads, res)) {
		d_fprintf(stderr, "ads_group_add: Group %s already exists\n", argv[0]);
		ads_msgfree(ads, res);
		goto done;
	}

	if (opt_container == NULL) {
		opt_container = ads_default_ou_string(ads, WELL_KNOWN_GUID_USERS);
	}

	status = ads_add_group_acct(ads, argv[0], opt_container, opt_comment);

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
	return rc;
}

static int ads_group_delete(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	void *res;
	char *groupdn;

	if (argc < 1) {
		return net_ads_group_usage(argc, argv);
	}
	
	if (!(ads = ads_startup())) {
		return -1;
	}

	rc = ads_find_user_acct(ads, &res, argv[0]);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(0, ("Group %s does not exist\n", argv[0]));
		ads_destroy(&ads);
		return -1;
	}
	groupdn = ads_get_dn(ads, res);
	ads_msgfree(ads, res);
	rc = ads_del_dn(ads, groupdn);
	ads_memfree(ads, groupdn);
	if (!ADS_ERR_OK(rc)) {
		d_printf("Group %s deleted\n", argv[0]);
		ads_destroy(&ads);
		return 0;
	}
	d_fprintf(stderr, "Error deleting group %s: %s\n", argv[0], 
		 ads_errstr(rc));
	ads_destroy(&ads);
	return -1;
}

int net_ads_group(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADD", ads_group_add},
		{"DELETE", ads_group_delete},
		{NULL, NULL}
	};
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *shortattrs[] = {"sAMAccountName", NULL};
	const char *longattrs[] = {"sAMAccountName", "description", NULL};
	char *disp_fields[2] = {NULL, NULL};

	if (argc == 0) {
		if (!(ads = ads_startup())) {
			return -1;
		}

		if (opt_long_list_entries)
			d_printf("\nGroup name            Comment"\
				 "\n-----------------------------\n");
		rc = ads_do_search_all_fn(ads, ads->config.bind_path, 
					  LDAP_SCOPE_SUBTREE, 
					  "(objectCategory=group)", 
					  opt_long_list_entries ? longattrs : 
					  shortattrs, usergrp_display, 
					  disp_fields);

		ads_destroy(&ads);
		return 0;
	}
	return net_run_function(argc, argv, func, net_ads_group_usage);
}

static int net_ads_status(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	void *res;

	if (!(ads = ads_startup())) {
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

static int net_ads_leave(int argc, const char **argv)
{
	ADS_STRUCT *ads = NULL;
	ADS_STATUS rc;

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}

	if (!opt_password) {
		net_use_machine_password();
	}

	if (!(ads = ads_startup())) {
		return -1;
	}

	rc = ads_leave_realm(ads, global_myname());
	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "Failed to delete host '%s' from the '%s' realm.\n", 
			global_myname(), ads->config.realm);
		ads_destroy(&ads);
		return -1;
	}

	d_printf("Removed '%s' from realm '%s'\n", global_myname(), ads->config.realm);
	ads_destroy(&ads);
	return 0;
}

static int net_ads_join_ok(void)
{
	ADS_STRUCT *ads = NULL;

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}

	net_use_machine_password();

	if (!(ads = ads_startup())) {
		return -1;
	}

	ads_destroy(&ads);
	return 0;
}

/*
  check that an existing join is OK
 */
int net_ads_testjoin(int argc, const char **argv)
{
	use_in_memory_ccache();

	/* Display success or failure */
	if (net_ads_join_ok() != 0) {
		fprintf(stderr,"Join to domain is not valid\n");
		return -1;
	}

	printf("Join is OK\n");
	return 0;
}

/*******************************************************************
  Simple configu checks before beginning the join
 ********************************************************************/

static int check_ads_config( void )
{
	if (lp_server_role() != ROLE_DOMAIN_MEMBER ) {
		d_printf("Host is not configured as a member server.\n");
		return -1;
	}

	if (strlen(global_myname()) > 15) {
		d_printf("Our netbios name can be at most 15 chars long, "
			 "\"%s\" is %d chars long\n",
			 global_myname(), strlen(global_myname()));
		return -1;
	}

	if ( lp_security() == SEC_ADS && !*lp_realm()) {
		d_fprintf(stderr, "realm must be set in in smb.conf for ADS "
			"join to succeed.\n");
		return -1;
	}

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}
	
	return 0;
}

/*******************************************************************
 Store the machine password and domain SID
 ********************************************************************/

static int store_domain_account( const char *domain, DOM_SID *sid, const char *pw )
{
	if (!secrets_store_domain_sid(domain, sid)) {
		DEBUG(1,("Failed to save domain sid\n"));
		return -1;
	}

	if (!secrets_store_machine_password(pw, domain, SEC_CHAN_WKSTA)) {
		DEBUG(1,("Failed to save machine password\n"));
		return -1;
	}

	return 0;
}

/*******************************************************************
 ********************************************************************/

static NTSTATUS join_fetch_domain_sid( TALLOC_CTX *mem_ctx, struct cli_state *cli, DOM_SID **sid )
{
	struct rpc_pipe_client *pipe_hnd = NULL;
	POLICY_HND lsa_pol;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *domain = NULL;

	if ( (pipe_hnd = cli_rpc_pipe_open_noauth(cli, PI_LSARPC, &status)) == NULL ) {
		DEBUG(0, ("Error connecting to LSA pipe. Error was %s\n",
			nt_errstr(status) ));
		return status;
	}

	status = rpccli_lsa_open_policy(pipe_hnd, mem_ctx, True,
			SEC_RIGHTS_MAXIMUM_ALLOWED, &lsa_pol);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	status = rpccli_lsa_query_info_policy(pipe_hnd, mem_ctx, 
			&lsa_pol, 5, &domain, sid);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	rpccli_lsa_close(pipe_hnd, mem_ctx, &lsa_pol);
	cli_rpc_pipe_close(pipe_hnd); /* Done with this pipe */

	/* Bail out if domain didn't get set. */
	if (!domain) {
		DEBUG(0, ("Could not get domain name.\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	return NT_STATUS_OK;
}

/*******************************************************************
 Do the domain join
 ********************************************************************/
 
static NTSTATUS join_create_machine( TALLOC_CTX *mem_ctx, struct cli_state *cli, 
                           DOM_SID *dom_sid, const char *clear_pw )
{	
	struct rpc_pipe_client *pipe_hnd = NULL;
	POLICY_HND sam_pol, domain_pol, user_pol;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *acct_name;
	const char *const_acct_name;
	uint32 user_rid;
	uint32 num_rids, *name_types, *user_rids;
	uint32 flags = 0x3e8;
	uint32 acb_info = ACB_WSTRUST;
	uchar pwbuf[516];
	SAM_USERINFO_CTR ctr;
	SAM_USER_INFO_24 p24;
	SAM_USER_INFO_16 p16;
	uchar md4_trust_password[16];

	/* Open the domain */
	
	if ( (pipe_hnd = cli_rpc_pipe_open_noauth(cli, PI_SAMR, &status)) == NULL ) {
		DEBUG(0, ("Error connecting to SAM pipe. Error was %s\n",
			nt_errstr(status) ));
		return status;
	}

	status = rpccli_samr_connect(pipe_hnd, mem_ctx, 
			SEC_RIGHTS_MAXIMUM_ALLOWED, &sam_pol);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	
	status = rpccli_samr_open_domain(pipe_hnd, mem_ctx, &sam_pol,
			SEC_RIGHTS_MAXIMUM_ALLOWED, dom_sid, &domain_pol);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	/* Create domain user */
	
	acct_name = talloc_asprintf(mem_ctx, "%s$", global_myname()); 
	strlower_m(acct_name);
	const_acct_name = acct_name;

	/* Don't try to set any acb_info flags other than ACB_WSTRUST */

	status = rpccli_samr_create_dom_user(pipe_hnd, mem_ctx, &domain_pol,
			acct_name, acb_info, 0xe005000b, &user_pol, &user_rid);

	if ( !NT_STATUS_IS_OK(status) 
		&& !NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) 
	{
		d_fprintf(stderr, "Creation of workstation account failed\n");

		/* If NT_STATUS_ACCESS_DENIED then we have a valid
		   username/password combo but the user does not have
		   administrator access. */

		if (NT_STATUS_V(status) == NT_STATUS_V(NT_STATUS_ACCESS_DENIED))
			d_fprintf(stderr, "User specified does not have administrator privileges\n");

		return status;
	}

	/* We *must* do this.... don't ask... */

	if (NT_STATUS_IS_OK(status)) {
		rpccli_samr_close(pipe_hnd, mem_ctx, &user_pol);
	}

	status = rpccli_samr_lookup_names(pipe_hnd, mem_ctx,
			&domain_pol, flags, 1, &const_acct_name, 
			&num_rids, &user_rids, &name_types);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	if ( name_types[0] != SID_NAME_USER) {
		DEBUG(0, ("%s is not a user account (type=%d)\n", acct_name, name_types[0]));
		return NT_STATUS_INVALID_WORKSTATION;
	}

	user_rid = user_rids[0];
		
	/* Open handle on user */

	status = rpccli_samr_open_user(pipe_hnd, mem_ctx, &domain_pol,
			SEC_RIGHTS_MAXIMUM_ALLOWED, user_rid, &user_pol);
	
	/* Create a random machine account password */

	E_md4hash( clear_pw, md4_trust_password);
	encode_pw_buffer(pwbuf, clear_pw, STR_UNICODE);

	/* Set password on machine account */

	ZERO_STRUCT(ctr);
	ZERO_STRUCT(p24);

	init_sam_user_info24(&p24, (char *)pwbuf,24);

	ctr.switch_value = 24;
	ctr.info.id24 = &p24;

	status = rpccli_samr_set_userinfo(pipe_hnd, mem_ctx, &user_pol, 
			24, &cli->user_session_key, &ctr);

	/* Why do we have to try to (re-)set the ACB to be the same as what
	   we passed in the samr_create_dom_user() call?  When a NT
	   workstation is joined to a domain by an administrator the
	   acb_info is set to 0x80.  For a normal user with "Add
	   workstations to the domain" rights the acb_info is 0x84.  I'm
	   not sure whether it is supposed to make a difference or not.  NT
	   seems to cope with either value so don't bomb out if the set
	   userinfo2 level 0x10 fails.  -tpot */

	ZERO_STRUCT(ctr);
	ctr.switch_value = 16;
	ctr.info.id16 = &p16;

	/* Fill in the additional account flags now */

	acb_info |= ACB_PWNOEXP;
#ifndef ENCTYPE_ARCFOUR_HMAC
	acb_info |= ACB_USE_DES_KEY_ONLY;
#endif

	init_sam_user_info16(&p16, acb_info);

	status = rpccli_samr_set_userinfo2(pipe_hnd, mem_ctx, &user_pol, 16, 
					&cli->user_session_key, &ctr);

	rpccli_samr_close(pipe_hnd, mem_ctx, &user_pol);
	cli_rpc_pipe_close(pipe_hnd); /* Done with this pipe */
	
	return status;
}

/*******************************************************************
 Do the domain join
 ********************************************************************/

static int net_join_domain( TALLOC_CTX *ctx, const char *servername, 
                            struct in_addr *ip, DOM_SID **dom_sid, const char *password )
{
	int ret = -1;
	struct cli_state *cli = NULL;

	if ( !NT_STATUS_IS_OK(connect_to_ipc_krb5(&cli, ip, servername)) )
		goto done;
	
	saf_store( cli->server_domain, cli->desthost );

	if ( !NT_STATUS_IS_OK(join_fetch_domain_sid( ctx, cli, dom_sid )) )
		goto done;

	if ( !NT_STATUS_IS_OK(join_create_machine( ctx, cli, *dom_sid, password )) )
		goto done;

	ret = 0;

done:
	if ( cli ) 
		cli_shutdown(cli);

	return ret;
}

/*******************************************************************
 Set a machines dNSHostName and servicePrincipalName attributes
 ********************************************************************/

static ADS_STATUS net_set_machine_spn(TALLOC_CTX *ctx, ADS_STRUCT *ads_s )
{
	ADS_STATUS status = ADS_ERROR(LDAP_SERVER_DOWN);
	char *host_upn, *new_dn;
	ADS_MODLIST mods;
	const char *servicePrincipalName[3] = {NULL, NULL, NULL};
	char *psp;
	fstring my_fqdn;
	LDAPMessage *res = NULL;
	char *dn_string = NULL;
	const char *machine_name = global_myname();
	int count;
	
	if ( !machine_name ) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}
	
	/* Find our DN */
	
	status = ads_find_machine_acct(ads_s, (void **)(void *)&res, machine_name);
	if (!ADS_ERR_OK(status)) 
		return status;
		
	if ( (count = ads_count_replies(ads_s, res)) != 1 ) {
		DEBUG(1,("net_set_machine_spn: %d entries returned!\n", count));
		return ADS_ERROR(LDAP_NO_MEMORY);	
	}
	
	if ( (dn_string = ads_get_dn(ads_s, res)) == NULL ) {
		DEBUG(1, ("ads_add_machine_acct: ads_get_dn returned NULL (malloc failure?)\n"));
		goto done;
	}
	
	new_dn = talloc_strdup(ctx, dn_string);
	ads_memfree(ads_s, dn_string);
	if (!new_dn) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	/* Windows only creates HOST/shortname & HOST/fqdn.  We create 
	   the UPN as well so that 'kinit -k' will work.  You can only 
	   request a TGT for entries with a UPN in AD. */
	   
	if ( !(psp = talloc_asprintf(ctx, "HOST/%s", machine_name)) ) 
		goto done;
	strupper_m(psp);
	servicePrincipalName[0] = psp;

	name_to_fqdn(my_fqdn, machine_name);
	strlower_m(my_fqdn);
	if ( !(psp = talloc_asprintf(ctx, "HOST/%s", my_fqdn)) ) 
		goto done;
	servicePrincipalName[1] = psp;
	
	if (!(host_upn = talloc_asprintf(ctx, "%s@%s", servicePrincipalName[0], ads_s->config.realm)))
		goto done;

	/* now do the mods */
	
	if (!(mods = ads_init_mods(ctx))) {
		goto done;
	}
	
	/* fields of primary importance */
	
	ads_mod_str(ctx, &mods, "dNSHostName", my_fqdn);
	ads_mod_strlist(ctx, &mods, "servicePrincipalName", servicePrincipalName);
#if 0 
	ads_mod_str(ctx, &mods, "userPrincipalName", host_upn);
	ads_mod_str(ctx, &mods, "operatingSystem", "Samba");
	ads_mod_str(ctx, &mods, "operatingSystemVersion", SAMBA_VERSION_STRING);
#endif

	status = ads_gen_mod(ads_s, new_dn, mods);

done:
	ads_msgfree(ads_s, res);
	
	return status;
}


/*******************************************************************
  join a domain using ADS (LDAP mods)
 ********************************************************************/

static ADS_STATUS net_precreate_machine_acct( ADS_STRUCT *ads, const char *ou )
{
	ADS_STRUCT *ads_s = ads;
	ADS_STATUS rc = ADS_ERROR(LDAP_SERVER_DOWN);
	char *dn, *ou_str;
	LDAPMessage *res = NULL;

	ou_str = ads_ou_string(ads, ou);
	asprintf(&dn, "%s,%s", ou_str, ads->config.bind_path);
	free(ou_str);

	if ( !ads->ld ) {
		ads_s = ads_init( ads->config.realm, NULL, ads->config.ldap_server_name );

		if ( ads_s ) {
			rc = ads_connect( ads_s );
		}

		if ( !ADS_ERR_OK(rc) ) {
			goto done;
		}
	}

	rc = ads_search_dn(ads, (void**)&res, dn, NULL);
	ads_msgfree(ads, res);

	if (!ADS_ERR_OK(rc)) {
		goto done;
	}

	/* Attempt to create the machine account and bail if this fails.
	   Assume that the admin wants exactly what they requested */

	rc = ads_create_machine_acct( ads, global_myname(), dn );
	if ( rc.error_type == ENUM_ADS_ERROR_LDAP && rc.err.rc == LDAP_ALREADY_EXISTS ) {
		rc = ADS_SUCCESS;
		goto done;
	}
	if ( !ADS_ERR_OK(rc) ) {
		goto done;
	}

done:
	if ( ads_s != ads )
		ads_destroy( &ads_s );
	SAFE_FREE( dn );

	return rc;
}

/*******************************************************************
  join a domain using ADS (LDAP mods)
 ********************************************************************/
 
int net_ads_join(int argc, const char **argv)
{
	ADS_STRUCT *ads, *ads_s;
	ADS_STATUS status;
	char *machine_account = NULL;
	const char *short_domain_name = NULL;
	char *tmp_password, *password;
	struct cldap_netlogon_reply cldap_reply;
	TALLOC_CTX *ctx;
	DOM_SID *domain_sid = NULL;
	
	if ( check_ads_config() != 0 ) {
		d_fprintf(stderr, "Invalid configuration.  Exiting....\n");
		return -1;
	}

	if ( (ads = ads_startup()) == NULL ) {
		return -1;
	}

	if (strcmp(ads->config.realm, lp_realm()) != 0) {
		d_fprintf(stderr, "realm of remote server (%s) and realm in smb.conf "
			"(%s) DO NOT match.  Aborting join\n", ads->config.realm, 
			lp_realm());
		ads_destroy(&ads);
		return -1;
	}

	if (!(ctx = talloc_init("net_ads_join"))) {
		DEBUG(0, ("Could not initialise talloc context\n"));
		return -1;
	}

	/* If we were given an OU, try to create the machine in the OU account 
	   first and then do the normal RPC join */

	if ( argc > 0 ) {
		status = net_precreate_machine_acct( ads, argv[0] );
		if ( !ADS_ERR_OK(status) ) {
			d_fprintf( stderr, "Failed to pre-create the machine object "
				"in OU %s.\n", argv[0]);
			ads_destroy( &ads );
			return -1;
		}
	}

	/* Do the domain join here */

	tmp_password = generate_random_str(DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH);
	password = talloc_strdup(ctx, tmp_password);
	
	if ( net_join_domain( ctx, ads->config.ldap_server_name, &ads->ldap_ip, &domain_sid, password ) != 0 ) {
		d_fprintf(stderr, "Failed to join domain!\n");
		return -1;
	}
	
	/* Check the short name of the domain */
	
	ZERO_STRUCT( cldap_reply );
	
	if ( ads_cldap_netlogon( ads->config.ldap_server_name, 
		ads->server.realm, &cldap_reply ) ) 
	{
		short_domain_name = talloc_strdup( ctx, cldap_reply.netbios_domain );
		if ( !strequal(lp_workgroup(), short_domain_name) ) {
			d_printf("The workgroup in smb.conf does not match the short\n");
			d_printf("domain name obtained from the server.\n");
			d_printf("Using the name [%s] from the server.\n", short_domain_name);
			d_printf("You should set \"workgroup = %s\" in smb.conf.\n", short_domain_name);
		}
	} else {
		short_domain_name = lp_workgroup();
	}
	
	d_printf("Using short domain name -- %s\n", short_domain_name);

	/*  HACK ALERT!  Store the sid and password under both the lp_workgroup() 
	    value from smb.conf and the string returned from the server.  The former is
	    neede to bootstrap winbindd's first connection to the DC to get the real 
	    short domain name   --jerry */
	   
	if ( (store_domain_account( lp_workgroup(), domain_sid, password ) == -1)
		|| (store_domain_account( short_domain_name, domain_sid, password ) == -1) )
	{
		ads_destroy(&ads);
		return -1;
	}

	/* Verify that everything is ok */

	if ( net_rpc_join_ok(short_domain_name, ads->config.ldap_server_name, &ads->ldap_ip) != 0 ) {
		d_fprintf(stderr, "Failed to verify membership in domain!\n");
		return -1;
	}	

	/* From here on out, use the machine account.  But first delete any 
	   existing tickets based on the user's creds.  */

	ads_kdestroy( NULL );
	
	status = ADS_ERROR(LDAP_SERVER_DOWN);
	ads_s = ads_init( ads->server.realm, ads->server.workgroup, ads->server.ldap_server );

	if ( ads_s ) {
		asprintf( &ads_s->auth.user_name, "%s$", global_myname() );
		ads_s->auth.password = secrets_fetch_machine_password( short_domain_name, NULL, NULL );
		ads_s->auth.realm = SMB_STRDUP( lp_realm() );
		ads_kinit_password( ads_s );
		status = ads_connect( ads_s );
	}
	if ( !ADS_ERR_OK(status) ) {
		d_fprintf( stderr, "LDAP bind using machine credentials failed!\n");
		d_fprintf(stderr, "Only NTLM authentication will be possible.\n");
	} else {
		/* create the dNSHostName & servicePrincipalName values */
	
		status = net_set_machine_spn( ctx, ads_s );
		if ( !ADS_ERR_OK(status) )  {
			d_fprintf(stderr, "Failed to set servicePrincipalNames.\n");
			d_fprintf(stderr, "Only NTLM authentication will be possible.\n");

			/* don't fail */
		}
	}
	
	ads_destroy( &ads_s );
		

#if defined(HAVE_KRB5) 
	if (asprintf(&machine_account, "%s$", global_myname()) == -1) {
		d_fprintf(stderr, "asprintf failed\n");
		ads_destroy(&ads);
		return -1;
	}

	if (!kerberos_derive_salting_principal(machine_account)) {
		DEBUG(1,("Failed to determine salting principal\n"));
		ads_destroy(&ads);
		return -1;
	}

	if (!kerberos_derive_cifs_salting_principals()) {
		DEBUG(1,("Failed to determine salting principals\n"));
		ads_destroy(&ads);
		return -1;
	}
	
	/* Now build the keytab, using the same ADS connection */
	if (lp_use_kerberos_keytab() && ads_keytab_create_default(ads)) {
		DEBUG(1,("Error creating host keytab!\n"));
	}
#endif

	d_printf("Joined '%s' to realm '%s'\n", global_myname(), ads->config.realm);

	SAFE_FREE(machine_account);
	TALLOC_FREE( ctx );
	ads_destroy(&ads);
	
	return 0;
}

/*******************************************************************
 ********************************************************************/

int net_ads_printer_usage(int argc, const char **argv)
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

static int net_ads_printer_search(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	void *res = NULL;

	if (!(ads = ads_startup())) {
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

static int net_ads_printer_info(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *servername, *printername;
	void *res = NULL;

	if (!(ads = ads_startup())) {
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
		d_fprintf(stderr, "ads_find_printer_on_server: %s\n", ads_errstr(rc));
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

void do_drv_upgrade_printer(int msg_type, struct process_id src,
			    void *buf, size_t len)
{
	return;
}

static int net_ads_printer_publish(int argc, const char **argv)
{
        ADS_STRUCT *ads;
        ADS_STATUS rc;
	const char *servername, *printername;
	struct cli_state *cli;
	struct rpc_pipe_client *pipe_hnd;
	struct in_addr 		server_ip;
	NTSTATUS nt_status;
	TALLOC_CTX *mem_ctx = talloc_init("net_ads_printer_publish");
	ADS_MODLIST mods = ads_init_mods(mem_ctx);
	char *prt_dn, *srv_dn, **srv_cn;
	void *res = NULL;

	if (!(ads = ads_startup())) {
		return -1;
	}

	if (argc < 1) {
		return net_ads_printer_usage(argc, argv);
	}
	
	printername = argv[0];

	if (argc == 2) {
		servername = argv[1];
	} else {
		servername = global_myname();
	}
		
	/* Get printer data from SPOOLSS */

	resolve_name(servername, &server_ip, 0x20);

	nt_status = cli_full_connection(&cli, global_myname(), servername, 
					&server_ip, 0,
					"IPC$", "IPC",  
					opt_user_name, opt_workgroup,
					opt_password ? opt_password : "", 
					CLI_FULL_CONNECTION_USE_KERBEROS, 
					Undefined, NULL);

	if (NT_STATUS_IS_ERR(nt_status)) {
		d_fprintf(stderr, "Unable to open a connnection to %s to obtain data "
			 "for %s\n", servername, printername);
		ads_destroy(&ads);
		return -1;
	}

	/* Publish on AD server */

	ads_find_machine_acct(ads, &res, servername);

	if (ads_count_replies(ads, res) == 0) {
		d_fprintf(stderr, "Could not find machine account for server %s\n", 
			 servername);
		ads_destroy(&ads);
		return -1;
	}

	srv_dn = ldap_get_dn(ads->ld, res);
	srv_cn = ldap_explode_dn(srv_dn, 1);

	asprintf(&prt_dn, "cn=%s-%s,%s", srv_cn[0], printername, srv_dn);

	pipe_hnd = cli_rpc_pipe_open_noauth(cli, PI_SPOOLSS, &nt_status);
	if (!pipe_hnd) {
		d_fprintf(stderr, "Unable to open a connnection to the spoolss pipe on %s\n",
			 servername);
		ads_destroy(&ads);
		return -1;
	}

	get_remote_printer_publishing_data(pipe_hnd, mem_ctx, &mods,
					   printername);

        rc = ads_add_printer_entry(ads, prt_dn, mem_ctx, &mods);
        if (!ADS_ERR_OK(rc)) {
                d_fprintf(stderr, "ads_publish_printer: %s\n", ads_errstr(rc));
		ads_destroy(&ads);
                return -1;
        }
 
        d_printf("published printer\n");
	ads_destroy(&ads);
 
	return 0;
}

static int net_ads_printer_remove(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *servername;
	char *prt_dn;
	void *res = NULL;

	if (!(ads = ads_startup())) {
		return -1;
	}

	if (argc < 1) {
		return net_ads_printer_usage(argc, argv);
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

	prt_dn = ads_get_dn(ads, res);
	ads_msgfree(ads, res);
	rc = ads_del_dn(ads, prt_dn);
	ads_memfree(ads, prt_dn);

	if (!ADS_ERR_OK(rc)) {
		d_fprintf(stderr, "ads_del_dn: %s\n", ads_errstr(rc));
		ads_destroy(&ads);
		return -1;
	}

	ads_destroy(&ads);
	return 0;
}

static int net_ads_printer(int argc, const char **argv)
{
	struct functable func[] = {
		{"SEARCH", net_ads_printer_search},
		{"INFO", net_ads_printer_info},
		{"PUBLISH", net_ads_printer_publish},
		{"REMOVE", net_ads_printer_remove},
		{NULL, NULL}
	};
	
	return net_run_function(argc, argv, func, net_ads_printer_usage);
}


static int net_ads_password(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	const char *auth_principal = opt_user_name;
	const char *auth_password = opt_password;
	char *realm = NULL;
	char *new_password = NULL;
	char *c, *prompt;
	const char *user;
	ADS_STATUS ret;

	if (opt_user_name == NULL || opt_password == NULL) {
		d_fprintf(stderr, "You must supply an administrator username/password\n");
		return -1;
	}

	if (argc < 1) {
		d_fprintf(stderr, "ERROR: You must say which username to change password for\n");
		return -1;
	}

	user = argv[0];
	if (!strchr_m(user, '@')) {
		asprintf(&c, "%s@%s", argv[0], lp_realm());
		user = c;
	}

	use_in_memory_ccache();    
	c = strchr_m(auth_principal, '@');
	if (c) {
		realm = ++c;
	} else {
		realm = lp_realm();
	}

	/* use the realm so we can eventually change passwords for users 
	in realms other than default */
	if (!(ads = ads_init(realm, NULL, NULL))) {
		return -1;
	}

	/* we don't actually need a full connect, but it's the easy way to
		fill in the KDC's addresss */
	ads_connect(ads);
    
	if (!ads || !ads->config.realm) {
		d_fprintf(stderr, "Didn't find the kerberos server!\n");
		return -1;
	}

	if (argv[1]) {
		new_password = (char *)argv[1];
	} else {
		asprintf(&prompt, "Enter new password for %s:", user);
		new_password = getpass(prompt);
		free(prompt);
	}

	ret = kerberos_set_password(ads->auth.kdc_server, auth_principal, 
				auth_password, user, new_password, ads->auth.time_offset);
	if (!ADS_ERR_OK(ret)) {
		d_fprintf(stderr, "Password change failed :-( ...\n");
		ads_destroy(&ads);
		return -1;
	}

	d_printf("Password change for %s completed.\n", user);
	ads_destroy(&ads);

	return 0;
}

int net_ads_changetrustpw(int argc, const char **argv)
{    
	ADS_STRUCT *ads;
	char *host_principal;
	fstring my_name;
	ADS_STATUS ret;

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}

	net_use_machine_password();

	use_in_memory_ccache();

	if (!(ads = ads_startup())) {
		return -1;
	}

	fstrcpy(my_name, global_myname());
	strlower_m(my_name);
	asprintf(&host_principal, "%s@%s", my_name, ads->config.realm);
	d_printf("Changing password for principal: HOST/%s\n", host_principal);

	ret = ads_change_trust_account_password(ads, host_principal);

	if (!ADS_ERR_OK(ret)) {
		d_fprintf(stderr, "Password change failed :-( ...\n");
		ads_destroy(&ads);
		SAFE_FREE(host_principal);
		return -1;
	}
    
	d_printf("Password change for principal HOST/%s succeeded.\n", host_principal);

	if (lp_use_kerberos_keytab()) {
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
static int net_ads_search_usage(int argc, const char **argv)
{
	d_printf(
		"\nnet ads search <expression> <attributes...>\n"\
		"\nperform a raw LDAP search on a ADS server and dump the results\n"\
		"The expression is a standard LDAP search expression, and the\n"\
		"attributes are a list of LDAP fields to show in the results\n\n"\
		"Example: net ads search '(objectCategory=group)' sAMAccountName\n\n"
		);
	net_common_flags_usage(argc, argv);
	return -1;
}


/*
  general ADS search function. Useful in diagnosing problems in ADS
*/
static int net_ads_search(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *ldap_exp;
	const char **attrs;
	void *res = NULL;

	if (argc < 1) {
		return net_ads_search_usage(argc, argv);
	}

	if (!(ads = ads_startup())) {
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
static int net_ads_dn_usage(int argc, const char **argv)
{
	d_printf(
		"\nnet ads dn <dn> <attributes...>\n"\
		"\nperform a raw LDAP search on a ADS server and dump the results\n"\
		"The DN standard LDAP DN, and the attributes are a list of LDAP fields \n"\
		"to show in the results\n\n"\
		"Example: net ads dn 'CN=administrator,CN=Users,DC=my,DC=domain' sAMAccountName\n\n"
		);
	net_common_flags_usage(argc, argv);
	return -1;
}


/*
  general ADS search function. Useful in diagnosing problems in ADS
*/
static int net_ads_dn(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *dn;
	const char **attrs;
	void *res = NULL;

	if (argc < 1) {
		return net_ads_dn_usage(argc, argv);
	}

	if (!(ads = ads_startup())) {
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
static int net_ads_sid_usage(int argc, const char **argv)
{
	d_printf(
		"\nnet ads sid <sid> <attributes...>\n"\
		"\nperform a raw LDAP search on a ADS server and dump the results\n"\
		"The SID is in string format, and the attributes are a list of LDAP fields \n"\
		"to show in the results\n\n"\
		"Example: net ads sid 'S-1-5-32' distinguishedName\n\n"
		);
	net_common_flags_usage(argc, argv);
	return -1;
}


/*
  general ADS search function. Useful in diagnosing problems in ADS
*/
static int net_ads_sid(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *sid_string;
	const char **attrs;
	void *res = NULL;
	DOM_SID sid;

	if (argc < 1) {
		return net_ads_sid_usage(argc, argv);
	}

	if (!(ads = ads_startup())) {
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


static int net_ads_keytab_usage(int argc, const char **argv)
{
	d_printf(
		"net ads keytab <COMMAND>\n"\
"<COMMAND> can be either:\n"\
"  CREATE    Creates a fresh keytab\n"\
"  ADD       Adds new service principal\n"\
"  FLUSH     Flushes out all keytab entries\n"\
"  HELP      Prints this help message\n"\
"The ADD command will take arguments, the other commands\n"\
"will not take any arguments.   The arguments given to ADD\n"\
"should be a list of principals to add.  For example, \n"\
"   net ads keytab add srv1 srv2\n"\
"will add principals for the services srv1 and srv2 to the\n"\
"system's keytab.\n"\
"\n"
		);
	return -1;
}

static int net_ads_keytab_flush(int argc, const char **argv)
{
	int ret;
	ADS_STRUCT *ads;

	if (!(ads = ads_startup())) {
		return -1;
	}
	ret = ads_keytab_flush(ads);
	ads_destroy(&ads);
	return ret;
}

static int net_ads_keytab_add(int argc, const char **argv)
{
	int i;
	int ret = 0;
	ADS_STRUCT *ads;

	d_printf("Processing principals to add...\n");
	if (!(ads = ads_startup())) {
		return -1;
	}
	for (i = 0; i < argc; i++) {
		ret |= ads_keytab_add_entry(ads, argv[i]);
	}
	ads_destroy(&ads);
	return ret;
}

static int net_ads_keytab_create(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	int ret;

	if (!(ads = ads_startup())) {
		return -1;
	}
	ret = ads_keytab_create_default(ads);
	ads_destroy(&ads);
	return ret;
}

int net_ads_keytab(int argc, const char **argv)
{
	struct functable func[] = {
		{"CREATE", net_ads_keytab_create},
		{"ADD", net_ads_keytab_add},
		{"FLUSH", net_ads_keytab_flush},
		{"HELP", net_ads_keytab_usage},
		{NULL, NULL}
	};

	if (!lp_use_kerberos_keytab()) {
		d_printf("\nWarning: \"use kerberos keytab\" must be set to \"true\" in order to \
use keytab functions.\n");
	}

	return net_run_function(argc, argv, func, net_ads_keytab_usage);
}

int net_ads_help(int argc, const char **argv)
{
	struct functable func[] = {
		{"USER", net_ads_user_usage},
		{"GROUP", net_ads_group_usage},
		{"PRINTER", net_ads_printer_usage},
		{"SEARCH", net_ads_search_usage},
#if 0
		{"INFO", net_ads_info},
		{"JOIN", net_ads_join},
		{"JOIN2", net_ads_join2},
		{"LEAVE", net_ads_leave},
		{"STATUS", net_ads_status},
		{"PASSWORD", net_ads_password},
		{"CHANGETRUSTPW", net_ads_changetrustpw},
#endif
		{NULL, NULL}
	};

	return net_run_function(argc, argv, func, net_ads_usage);
}

int net_ads(int argc, const char **argv)
{
	struct functable func[] = {
		{"INFO", net_ads_info},
		{"JOIN", net_ads_join},
		{"TESTJOIN", net_ads_testjoin},
		{"LEAVE", net_ads_leave},
		{"STATUS", net_ads_status},
		{"USER", net_ads_user},
		{"GROUP", net_ads_group},
		{"PASSWORD", net_ads_password},
		{"CHANGETRUSTPW", net_ads_changetrustpw},
		{"PRINTER", net_ads_printer},
		{"SEARCH", net_ads_search},
		{"DN", net_ads_dn},
		{"SID", net_ads_sid},
		{"WORKGROUP", net_ads_workgroup},
		{"LOOKUP", net_ads_lookup},
		{"KEYTAB", net_ads_keytab},
		{"HELP", net_ads_help},
		{NULL, NULL}
	};
	
	return net_run_function(argc, argv, func, net_ads_usage);
}

#else

static int net_ads_noads(void)
{
	d_fprintf(stderr, "ADS support not compiled in\n");
	return -1;
}

int net_ads_keytab(int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_usage(int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_help(int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_changetrustpw(int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_join(int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_user(int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_group(int argc, const char **argv)
{
	return net_ads_noads();
}

/* this one shouldn't display a message */
int net_ads_check(void)
{
	return -1;
}

int net_ads(int argc, const char **argv)
{
	return net_ads_usage(argc, argv);
}

#endif
