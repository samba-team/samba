/* 
   Samba Unix/Linux SMB client library 
   net ads commands
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2001 Remus Koos (remuskoos@yahoo.com)
   Copyright (C) 2002 Jim McDonough (jmcd@us.ibm.com)

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
#include "../utils/net.h"

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
		);
	return -1;
}


/*
  this implements the CLDAP based netlogon lookup requests
  for finding the domain controller of a ADS domain
*/
static int net_ads_lookup(int argc, const char **argv)
{
	ADS_STRUCT *ads;

	ads = ads_init(NULL, opt_target_workgroup, opt_host);
	if (ads) {
		ads->auth.flags |= ADS_AUTH_NO_BIND;
	}

	ads_connect(ads);

	if (!ads || !ads->config.realm) {
		d_printf("Didn't find the cldap server!\n");
		return -1;
	}

	return ads_cldap_netlogon(ads);
}



static int net_ads_info(int argc, const char **argv)
{
	ADS_STRUCT *ads;

	ads = ads_init(NULL, opt_target_workgroup, opt_host);

	if (ads) {
		ads->auth.flags |= ADS_AUTH_NO_BIND;
	}

	ads_connect(ads);

	if (!ads || !ads->config.realm) {
		d_printf("Didn't find the ldap server!\n");
		return -1;
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
       if ((cp = strchr(ads->auth.user_name, '@'))!=0) {
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
			DEBUG(1,("ads_connect: %s\n", ads_errstr(status)));
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

	ads = ads_startup();
	if (!ads)
		return -1;
	ads_destroy(&ads);
	return 0;
}

/* 
   determine the netbios workgroup name for a domain
 */
static int net_ads_workgroup(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	TALLOC_CTX *ctx;
	const char *workgroup;

	if (!(ads = ads_startup())) return -1;

	if (!(ctx = talloc_init("net_ads_workgroup"))) {
		return -1;
	}

	if (!ADS_ERR_OK(ads_workgroup_name(ads, ctx, &workgroup))) {
		d_printf("Failed to find workgroup for realm '%s'\n", 
			 ads->config.realm);
		talloc_destroy(ctx);
		return -1;
	}

	d_printf("Workgroup: %s\n", workgroup);

	talloc_destroy(ctx);

	return 0;
}



static BOOL usergrp_display(char *field, void **values, void *data_area)
{
	char **disp_fields = (char **) data_area;

	if (!field) { /* must be end of record */
		if (!strchr_m(disp_fields[0], '$')) {
			if (disp_fields[1])
				d_printf("%-21.21s %s\n", 
				       disp_fields[0], disp_fields[1]);
			else
				d_printf("%s\n", disp_fields[0]);
		}
		SAFE_FREE(disp_fields[0]);
		SAFE_FREE(disp_fields[1]);
		return True;
	}
	if (!values) /* must be new field, indicate string field */
		return True;
	if (StrCaseCmp(field, "sAMAccountName") == 0) {
		disp_fields[0] = strdup((char *) values[0]);
	}
	if (StrCaseCmp(field, "description") == 0)
		disp_fields[1] = strdup((char *) values[0]);
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
	
	if (!(ads = ads_startup())) return -1;

	status = ads_find_user_acct(ads, &res, argv[0]);

	if (!ADS_ERR_OK(status)) {
		d_printf("ads_user_add: %s\n", ads_errstr(status));
		goto done;
	}
	
	if (ads_count_replies(ads, res)) {
		d_printf("ads_user_add: User %s already exists\n", argv[0]);
		goto done;
	}

	status = ads_add_user_acct(ads, argv[0], opt_container, opt_comment);

	if (!ADS_ERR_OK(status)) {
		d_printf("Could not add user %s: %s\n", argv[0],
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
	d_printf("Could not add user %s.  Error setting password %s\n",
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
	char *escaped_user = escape_ldap_string_alloc(argv[0]);

	if (argc < 1) return net_ads_user_usage(argc, argv);
	
	if (!(ads = ads_startup())) return -1;

	if (!escaped_user) {
		d_printf("ads_user_info: failed to escape user %s\n", argv[0]);
		return -1;
	}

	asprintf(&searchstring, "(sAMAccountName=%s)", escaped_user);
	rc = ads_search(ads, &res, searchstring, attrs);
	safe_free(searchstring);

	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_search: %s\n", ads_errstr(rc));
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
	return 0;
}

static int ads_user_delete(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	void *res;
	char *userdn;

	if (argc < 1) return net_ads_user_usage(argc, argv);
	
	if (!(ads = ads_startup())) return -1;

	rc = ads_find_user_acct(ads, &res, argv[0]);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(0, ("User %s does not exist\n", argv[0]));
		return -1;
	}
	userdn = ads_get_dn(ads, res);
	ads_msgfree(ads, res);
	rc = ads_del_dn(ads, userdn);
	ads_memfree(ads, userdn);
	if (!ADS_ERR_OK(rc)) {
		d_printf("User %s deleted\n", argv[0]);
		return 0;
	}
	d_printf("Error deleting user %s: %s\n", argv[0], 
		 ads_errstr(rc));
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
		if (!(ads = ads_startup())) return -1;

		if (opt_long_list_entries)
			d_printf("\nUser name             Comment"\
				 "\n-----------------------------\n");

		rc = ads_do_search_all_fn(ads, ads->config.bind_path, 
					  LDAP_SCOPE_SUBTREE,
					  "(objectclass=user)", 
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

	if (argc < 1) return net_ads_group_usage(argc, argv);
	
	if (!(ads = ads_startup())) return -1;

	status = ads_find_user_acct(ads, &res, argv[0]);

	if (!ADS_ERR_OK(status)) {
		d_printf("ads_group_add: %s\n", ads_errstr(status));
		goto done;
	}
	
	if (ads_count_replies(ads, res)) {
		d_printf("ads_group_add: Group %s already exists\n", argv[0]);
		ads_msgfree(ads, res);
		goto done;
	}

	status = ads_add_group_acct(ads, argv[0], opt_container, opt_comment);

	if (ADS_ERR_OK(status)) {
		d_printf("Group %s added\n", argv[0]);
		rc = 0;
	} else {
		d_printf("Could not add group %s: %s\n", argv[0],
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

	if (argc < 1) return net_ads_group_usage(argc, argv);
	
	if (!(ads = ads_startup())) return -1;

	rc = ads_find_user_acct(ads, &res, argv[0]);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(0, ("Group %s does not exist\n", argv[0]));
		return -1;
	}
	groupdn = ads_get_dn(ads, res);
	ads_msgfree(ads, res);
	rc = ads_del_dn(ads, groupdn);
	ads_memfree(ads, groupdn);
	if (!ADS_ERR_OK(rc)) {
		d_printf("Group %s deleted\n", argv[0]);
		return 0;
	}
	d_printf("Error deleting group %s: %s\n", argv[0], 
		 ads_errstr(rc));
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
		if (!(ads = ads_startup())) return -1;

		if (opt_long_list_entries)
			d_printf("\nGroup name            Comment"\
				 "\n-----------------------------\n");
		rc = ads_do_search_all_fn(ads, ads->config.bind_path, 
					  LDAP_SCOPE_SUBTREE, 
					  "(objectclass=group)", 
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

	if (!(ads = ads_startup())) return -1;

	rc = ads_find_machine_acct(ads, &res, global_myname());
	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_find_machine_acct: %s\n", ads_errstr(rc));
		return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_printf("No machine account for '%s' found\n", global_myname());
		return -1;
	}

	ads_dump(ads, res);

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
	    d_printf("Failed to delete host '%s' from the '%s' realm.\n", 
		     global_myname(), ads->config.realm);
	    return -1;
	}

	d_printf("Removed '%s' from realm '%s'\n", global_myname(), ads->config.realm);

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

/*
  join a domain using ADS
 */
int net_ads_join(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	char *password;
	char *machine_account = NULL;
	char *tmp_password;
	const char *org_unit = "Computers";
	char *dn;
	void *res;
	DOM_SID dom_sid;
	char *ou_str;
	uint32 sec_channel_type = SEC_CHAN_WKSTA;
	uint32 account_type = UF_WORKSTATION_TRUST_ACCOUNT;
	const char *short_domain_name = NULL;
	TALLOC_CTX *ctx = NULL;

	if (argc > 0) org_unit = argv[0];

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}

	tmp_password = generate_random_str(DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH);
	password = strdup(tmp_password);

	if (!(ads = ads_startup())) return -1;

	if (!*lp_realm()) {
		d_printf("realm must be set in in smb.conf for ADS join to succeed.\n");
		return -1;
	}

	if (strcmp(ads->config.realm, lp_realm()) != 0) {
		d_printf("realm of remote server (%s) and realm in smb.conf (%s) DO NOT match.  Aborting join\n", ads->config.realm, lp_realm());
		return -1;
	}

	ou_str = ads_ou_string(org_unit);
	asprintf(&dn, "%s,%s", ou_str, ads->config.bind_path);
	free(ou_str);

	rc = ads_search_dn(ads, &res, dn, NULL);
	ads_msgfree(ads, res);

	if (rc.error_type == ENUM_ADS_ERROR_LDAP && rc.err.rc == LDAP_NO_SUCH_OBJECT) {
		d_printf("ads_join_realm: organizational unit %s does not exist (dn:%s)\n", 
			 org_unit, dn);
		return -1;
	}
	free(dn);

	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_join_realm: %s\n", ads_errstr(rc));
		return -1;
	}	

	rc = ads_join_realm(ads, global_myname(), account_type, org_unit);
	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_join_realm: %s\n", ads_errstr(rc));
		return -1;
	}

	rc = ads_domain_sid(ads, &dom_sid);
	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_domain_sid: %s\n", ads_errstr(rc));	
	return -1;
	}

	if (asprintf(&machine_account, "%s$", global_myname()) == -1) {
		d_printf("asprintf failed\n");
		return -1;
	}

	rc = ads_set_machine_password(ads, machine_account, password);
	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_set_machine_password: %s\n", ads_errstr(rc));
		return -1;
	}
	
	/* make sure we get the right workgroup */
	
	if ( !(ctx = talloc_init("net ads join")) ) {
		d_printf("talloc_init() failed!\n");
		return -1;
	}
	
	rc = ads_workgroup_name(ads, ctx, &short_domain_name);
	if ( ADS_ERR_OK(rc) ) {
		if ( !strequal(lp_workgroup(), short_domain_name) ) {
			d_printf("The workgroup in smb.conf does not match the short\n");
			d_printf("domain name obtained from the server.\n");
			d_printf("Using the name [%s] from the server.\n", short_domain_name);
			d_printf("You should set \"workgroup = %s\" in smb.conf.\n", short_domain_name);
		}
	}
	else
		short_domain_name = lp_workgroup();
	
	d_printf("Using short domain name -- %s\n", short_domain_name);
	
	/*  HACK ALRET!  Store the sid and password under bother the lp_workgroup() 
	    value from smb.conf and the string returned from the server.  The former is
	    neede to bootstrap winbindd's first connection to the DC to get the real 
	    short domain name   --jerry */
	    
	if (!secrets_store_domain_sid(lp_workgroup(), &dom_sid)) {
		DEBUG(1,("Failed to save domain sid\n"));
		return -1;
	}

	if (!secrets_store_machine_password(password, lp_workgroup(), sec_channel_type)) {
		DEBUG(1,("Failed to save machine password\n"));
		return -1;
	}

	if (!secrets_store_domain_sid(short_domain_name, &dom_sid)) {
		DEBUG(1,("Failed to save domain sid\n"));
		return -1;
	}

	if (!secrets_store_machine_password(password, short_domain_name, sec_channel_type)) {
		DEBUG(1,("Failed to save machine password\n"));
		return -1;
	}
	
	d_printf("Joined '%s' to realm '%s'\n", global_myname(), ads->config.realm);

	SAFE_FREE(password);
	SAFE_FREE(machine_account);
	if ( ctx )
		talloc_destroy(ctx);
	return 0;
}

int net_ads_printer_usage(int argc, const char **argv)
{
	d_printf(
"\nnet ads printer search <printer>"
"\n\tsearch for a printer in the directory"
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

static int net_ads_printer_search(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	void *res = NULL;

	if (!(ads = ads_startup())) 
		return -1;

	rc = ads_find_printers(ads, &res);

	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_find_printer: %s\n", ads_errstr(rc));
		ads_msgfree(ads, res);
		return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_printf("No results found\n");
		ads_msgfree(ads, res);
		return -1;
	}

	ads_dump(ads, res);
	ads_msgfree(ads, res);

	return 0;
}

static int net_ads_printer_info(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *servername, *printername;
	void *res = NULL;

	if (!(ads = ads_startup())) return -1;

	if (argc > 0)
		printername = argv[0];
	else
		printername = "*";

	if (argc > 1)
		servername =  argv[1];
	else
		servername = global_myname();

	rc = ads_find_printer_on_server(ads, &res, printername, servername);

	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_find_printer_on_server: %s\n", ads_errstr(rc));
		ads_msgfree(ads, res);
		return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_printf("Printer '%s' not found\n", printername);
		ads_msgfree(ads, res);
		return -1;
	}

	ads_dump(ads, res);
	ads_msgfree(ads, res);

	return 0;
}

void do_drv_upgrade_printer(int msg_type, pid_t src, void *buf, size_t len)
{
	return;
}

static int net_ads_printer_publish(int argc, const char **argv)
{
        ADS_STRUCT *ads;
        ADS_STATUS rc;
	const char *servername, *printername;
	struct cli_state *cli;
	struct in_addr 		server_ip;
	NTSTATUS nt_status;
	TALLOC_CTX *mem_ctx = talloc_init("net_ads_printer_publish");
	ADS_MODLIST mods = ads_init_mods(mem_ctx);
	char *prt_dn, *srv_dn, **srv_cn;
	void *res = NULL;

	if (!(ads = ads_startup())) return -1;

	if (argc < 1)
		return net_ads_printer_usage(argc, argv);
	
	printername = argv[0];

	if (argc == 2)
		servername = argv[1];
	else
		servername = global_myname();
		
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
		d_printf("Unable to open a connnection to %s to obtain data "
			 "for %s\n", servername, printername);
		return -1;
	}

	/* Publish on AD server */

	ads_find_machine_acct(ads, &res, servername);

	if (ads_count_replies(ads, res) == 0) {
		d_printf("Could not find machine account for server %s\n", 
			 servername);
		return -1;
	}

	srv_dn = ldap_get_dn(ads->ld, res);
	srv_cn = ldap_explode_dn(srv_dn, 1);

	asprintf(&prt_dn, "cn=%s-%s,%s", srv_cn[0], printername, srv_dn);

	cli_nt_session_open(cli, PI_SPOOLSS);
	get_remote_printer_publishing_data(cli, mem_ctx, &mods, printername);

        rc = ads_add_printer_entry(ads, prt_dn, mem_ctx, &mods);
        if (!ADS_ERR_OK(rc)) {
                d_printf("ads_publish_printer: %s\n", ads_errstr(rc));
                return -1;
        }
 
        d_printf("published printer\n");
 
	return 0;
}

static int net_ads_printer_remove(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *servername;
	char *prt_dn;
	void *res = NULL;

	if (!(ads = ads_startup())) return -1;

	if (argc < 1)
		return net_ads_printer_usage(argc, argv);

	if (argc > 1)
		servername = argv[1];
	else
		servername = global_myname();

	rc = ads_find_printer_on_server(ads, &res, argv[0], servername);

	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_find_printer_on_server: %s\n", ads_errstr(rc));
		ads_msgfree(ads, res);
		return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_printf("Printer '%s' not found\n", argv[1]);
		ads_msgfree(ads, res);
		return -1;
	}

	prt_dn = ads_get_dn(ads, res);
	ads_msgfree(ads, res);
	rc = ads_del_dn(ads, prt_dn);
	ads_memfree(ads, prt_dn);

	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_del_dn: %s\n", ads_errstr(rc));
		return -1;
	}

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
	    d_printf("You must supply an administrator username/password\n");
	    return -1;
    }

    
    if (argc < 1) {
	    d_printf("ERROR: You must say which username to change password for\n");
	    return -1;
    }

    user = argv[0];
    if (!strchr(user, '@')) {
	    asprintf(&c, "%s@%s", argv[0], lp_realm());
	    user = c;
    }

    use_in_memory_ccache();    
    c = strchr(auth_principal, '@');
    if (c) {
	    realm = ++c;
    } else {
	    realm = lp_realm();
    }

    /* use the realm so we can eventually change passwords for users 
    in realms other than default */
    if (!(ads = ads_init(realm, NULL, NULL))) return -1;

    /* we don't actually need a full connect, but it's the easy way to
       fill in the KDC's addresss */
    ads_connect(ads);
    
    if (!ads || !ads->config.realm) {
	    d_printf("Didn't find the kerberos server!\n");
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
	d_printf("Password change failed :-( ...\n");
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
    char *hostname;
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

    hostname = strdup(global_myname());
    strlower_m(hostname);
    asprintf(&host_principal, "%s@%s", hostname, ads->config.realm);
    SAFE_FREE(hostname);
    d_printf("Changing password for principal: HOST/%s\n", host_principal);
    
    ret = ads_change_trust_account_password(ads, host_principal);

    if (!ADS_ERR_OK(ret)) {
	d_printf("Password change failed :-( ...\n");
	ads_destroy(&ads);
	SAFE_FREE(host_principal);
	return -1;
    }
    
    d_printf("Password change for principal HOST/%s succeeded.\n", host_principal);
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
		d_printf("search failed: %s\n", ads_errstr(rc));
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
		d_printf("search failed: %s\n", ads_errstr(rc));
		return -1;
	}	

	d_printf("Got %d replies\n\n", ads_count_replies(ads, res));

	/* dump the results */
	ads_dump(ads, res);

	ads_msgfree(ads, res);
	ads_destroy(&ads);

	return 0;
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
		{"WORKGROUP", net_ads_workgroup},
		{"LOOKUP", net_ads_lookup},
		{"HELP", net_ads_help},
		{NULL, NULL}
	};
	
	return net_run_function(argc, argv, func, net_ads_usage);
}

#else

static int net_ads_noads(void)
{
	d_printf("ADS support not compiled in\n");
	return -1;
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
