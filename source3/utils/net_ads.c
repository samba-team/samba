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
"\nnet ads user"\
"\n\tlist users in the realm\n"\
"\nnet ads group"\
"\n\tlist groups in the realm\n"\
"\nnet ads info"\
"\n\tshows some info on the server\n"\
"\nnet ads status"\
"\n\tdump the machine account details to stdout\n"
"\nnet ads password <username@realm> -Uadmin_username@realm%%admin_pass"\
"\n\tchange a user's password using an admin account"
"\n\t(note: use realm in UPPERCASE)\n"
"\nnet ads chostpass"
"\n\tchange the trust account password of this machine in the AD tree\n"
"\nnet ads printer [info | publish | remove] <printername> <servername>"
"\n\t lookup, add, or remove directory entry for a printer\n"
		);
	return -1;
}


static int net_ads_info(int argc, const char **argv)
{
	ADS_STRUCT *ads;

	ads = ads_init(NULL, opt_host, NULL, NULL);
	ads_connect(ads);

	if (!ads) {
		d_printf("Didn't find the ldap server!\n");
		return -1;
	}

	d_printf("LDAP server: %s\n", ads->ldap_server);
	d_printf("LDAP server name: %s\n", ads->ldap_server_name);
	d_printf("Realm: %s\n", ads->realm);
	d_printf("Bind Path: %s\n", ads->bind_path);
	d_printf("LDAP port: %d\n", ads->ldap_port);

	return 0;
}


static ADS_STRUCT *ads_startup(void)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	BOOL need_password = False;
	BOOL second_time = False;
	
	ads = ads_init(NULL, opt_host, NULL, NULL);

	if (!opt_user_name) {
		opt_user_name = "administrator";
	}

	if (opt_user_specified)
		need_password = True;

retry:
	if (!opt_password && need_password) {
		char *prompt;
		asprintf(&prompt,"%s password: ", opt_user_name);
		opt_password = getpass(prompt);
		free(prompt);
	}

	if (opt_password)
		ads->password = strdup(opt_password);

	ads->user_name = strdup(opt_user_name);

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


static void usergrp_display(char *field, void **values, void *data_area)
{
	char **disp_fields = (char **) data_area;

	if (!field) { /* must be end of record */
		if (!strchr_m(disp_fields[0], '$')) {
			if (disp_fields[1])
				printf("%-21.21s %-50.50s\n", 
				       disp_fields[0], disp_fields[1]);
			else
				printf("%-21.21s\n", disp_fields[0]);
		}
		SAFE_FREE(disp_fields[0]);
		SAFE_FREE(disp_fields[1]);
		return;
	}
	if (StrCaseCmp(field, "sAMAccountName") == 0) {
		disp_fields[0] = strdup(((struct berval *) values[0])->bv_val);
	}
	if (StrCaseCmp(field, "description") == 0)
		disp_fields[1] = strdup(((struct berval *) values[0])->bv_val);
}

static int net_ads_user_usage(int argc, const char **argv)
{
	return net_help_user(argc, argv);
} 

static int ads_user_add(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
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
		ads_msgfree(ads, res);
		goto done;
	}

	status = ads_add_user_acct(ads, argv[0], opt_comment);

	if (ADS_ERR_OK(status)) {
		d_printf("User %s added\n", argv[0]);
		rc = 0;
	} else {
		d_printf("Could not add user %s: %s\n", argv[0],
			 ads_errstr(status));
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

	if (argc < 1) return net_ads_user_usage(argc, argv);
	
	if (!(ads = ads_startup())) return -1;

	asprintf(&searchstring, "(sAMAccountName=%s)", argv[0]);
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
			printf("%s\n", groupname[0]);
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

		rc = ads_do_search_all_fn(ads, ads->bind_path, 
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

static int net_ads_group(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	const char *shortattrs[] = {"sAMAccountName", NULL};
	const char *longattrs[] = {"sAMAccountName", "description", NULL};
	char *disp_fields[2] = {NULL, NULL};

	if (!(ads = ads_startup())) return -1;

	if (opt_long_list_entries)
		d_printf("\nGroup name            Comment"\
			 "\n-----------------------------\n");
	rc = ads_do_search_all_fn(ads, ads->bind_path, LDAP_SCOPE_SUBTREE, 
				  "(objectclass=group)", opt_long_list_entries
				  ? longattrs : shortattrs, usergrp_display, 
				  disp_fields);

	ads_destroy(&ads);
	return 0;
}

static int net_ads_status(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	extern pstring global_myname;
	void *res;

	if (!(ads = ads_startup())) return -1;

	rc = ads_find_machine_acct(ads, &res, global_myname);
	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_find_machine_acct: %s\n", ads_errstr(rc));
		return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_printf("No machine account for '%s' found\n", global_myname);
		return -1;
	}

	ads_dump(ads, res);

	return 0;
}

static int net_ads_leave(int argc, const char **argv)
{
	ADS_STRUCT *ads = NULL;
	ADS_STATUS rc;
	extern pstring global_myname;

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}

	if (!opt_password) {
		asprintf(&opt_user_name, "%s$", global_myname);
		opt_password = secrets_fetch_machine_password();
	}

	if (!(ads = ads_startup())) {
		return -1;
	}

	rc = ads_leave_realm(ads, global_myname);
	if (!ADS_ERR_OK(rc)) {
	    d_printf("Failed to delete host '%s' from the '%s' realm.\n", 
		     global_myname, ads->realm);
	    return -1;
	}

	d_printf("Removed '%s' from realm '%s'\n", global_myname, ads->realm);

	return 0;
}

int net_ads_join(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	char *password;
	char *tmp_password;
	extern pstring global_myname;
	const char *org_unit = "Computers";
	char *dn;
	void *res;
	DOM_SID dom_sid;
	char *ou_str;

	if (argc > 0) org_unit = argv[0];

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}

	tmp_password = generate_random_str(DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH);
	password = strdup(tmp_password);

	if (!(ads = ads_startup())) return -1;

	ou_str = ads_ou_string(org_unit);
	asprintf(&dn, "%s,%s", ou_str, ads->bind_path);
	free(ou_str);

	rc = ads_search_dn(ads, &res, dn, NULL);
	ads_msgfree(ads, res);

	if (rc.error_type == ADS_ERROR_LDAP && rc.rc == LDAP_NO_SUCH_OBJECT) {
		d_printf("ads_join_realm: organizational unit %s does not exist (dn:%s)\n", 
			 org_unit, dn);
		return -1;
	}
	free(dn);

	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_join_realm: %s\n", ads_errstr(rc));
		return -1;
	}	

	rc = ads_join_realm(ads, global_myname, org_unit);
	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_join_realm: %s\n", ads_errstr(rc));
		return -1;
	}

	rc = ads_set_machine_password(ads, global_myname, password);
	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_set_machine_password: %s\n", ads_errstr(rc));
		return -1;
	}

	rc = ads_domain_sid(ads, &dom_sid);
	if (!ADS_ERR_OK(rc)) {
		d_printf("ads_domain_sid: %s\n", ads_errstr(rc));
		return -1;
	}

	if (!secrets_store_domain_sid(lp_workgroup(), &dom_sid)) {
		DEBUG(1,("Failed to save domain sid\n"));
		return -1;
	}

	if (!secrets_store_machine_password(password)) {
		DEBUG(1,("Failed to save machine password\n"));
		return -1;
	}

	d_printf("Joined '%s' to realm '%s'\n", global_myname, ads->realm);

	free(password);

	return 0;
}

int net_ads_printer_usage(int argc, const char **argv)
{
	d_printf(
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

static int net_ads_printer_info(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	char *servername, *printername;
	extern pstring global_myname;
	void *res = NULL;

	if (!(ads = ads_startup())) return -1;

	if (argc > 0)
		printername = argv[0];
	else
		printername = "*";

	if (argc > 1)
		servername =  argv[1];
	else
		servername = global_myname;

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

static int net_ads_printer_publish(int argc, const char **argv)
{
        ADS_STRUCT *ads;
        ADS_STATUS rc;
	char *uncname, *servername;
	ADS_PRINTER_ENTRY prt;
	extern pstring global_myname;

	/* 
	   these const strings are only here as an example.  The attributes
	   they represent are not implemented yet
	*/
	const char *bins[] = {"Tray 21", NULL};
	const char *media[] = {"Letter", NULL};
	const char *orients[] = {"PORTRAIT", NULL};
	const char *ports[] = {"Samba", NULL};

	if (!(ads = ads_startup())) return -1;

	if (argc < 1)
		return net_ads_printer_usage(argc, argv);

	memset(&prt, 0, sizeof(ADS_PRINTER_ENTRY));

	prt.printerName = argv[0];
	asprintf(&servername, "%s.%s", global_myname, ads->realm);
	prt.serverName = servername;
	prt.shortServerName = global_myname;
	prt.versionNumber = "4";
	asprintf(&uncname, "\\\\%s\\%s", global_myname, argv[0]);
	prt.uNCName=uncname;
	prt.printBinNames = (char **) bins;
	prt.printMediaSupported = (char **) media;
	prt.printOrientationsSupported = (char **) orients;
	prt.portName = (char **) ports;
	prt.printSpooling = "PrintAfterSpooled";
 
        rc = ads_add_printer(ads, &prt);
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
	char *servername, *prt_dn;
	extern pstring global_myname;
	void *res = NULL;

	if (!(ads = ads_startup())) return -1;

	if (argc < 1)
		return net_ads_printer_usage(argc, argv);

	if (argc > 1)
		servername = argv[1];
	else
		servername = global_myname;

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
    char *auth_principal = opt_user_name;
    char *auth_password = opt_password;
    char *realm = NULL;
    char *new_password = NULL;
    char *c;
    char *prompt;
    ADS_STATUS ret;

    
    if ((argc != 1) || (opt_user_name == NULL) || 
	(opt_password == NULL) || (strchr(opt_user_name, '@') == NULL) ||
	(strchr(argv[0], '@') == NULL)) {
	return net_ads_usage(argc, argv);
    }
    
    c = strchr(auth_principal, '@');
    realm = ++c;

    /* use the realm so we can eventually change passwords for users 
    in realms other than default */
    if (!(ads = ads_init(realm, NULL, NULL, NULL))) return -1;

    asprintf(&prompt, "Enter new password for %s:", argv[0]);

    new_password = getpass(prompt);

    ret = kerberos_set_password(ads->kdc_server, auth_principal, 
				auth_password, argv[0], new_password);
    if (!ADS_ERR_OK(ret)) {
	d_printf("Password change failed :-( ...\n");
	ads_destroy(&ads);
	free(prompt);
	return -1;
    }

    d_printf("Password change for %s completed.\n", argv[0]);
    ads_destroy(&ads);
    free(prompt);

    return 0;
}


static int net_ads_change_localhost_pass(int argc, const char **argv)
{    
    ADS_STRUCT *ads;
    extern pstring global_myname;
    char *host_principal;
    char *hostname;
    ADS_STATUS ret;


    if (!(ads = ads_init(NULL, NULL, NULL, NULL))) return -1;

    hostname = strdup(global_myname);
    strlower(hostname);
    asprintf(&host_principal, "%s@%s", hostname, ads->realm);
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

int net_ads_help(int argc, const char **argv)
{
	struct functable func[] = {
		{"USER", net_ads_user_usage},
#if 0
		{"INFO", net_ads_info},
		{"JOIN", net_ads_join},
		{"LEAVE", net_ads_leave},
		{"STATUS", net_ads_status},
		{"GROUP", net_ads_group},
		{"PASSWORD", net_ads_password},
		{"CHOSTPASS", net_ads_change_localhost_pass},
		{"PRINTER", net_ads_printer},
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
		{"LEAVE", net_ads_leave},
		{"STATUS", net_ads_status},
		{"USER", net_ads_user},
		{"GROUP", net_ads_group},
		{"PASSWORD", net_ads_password},
		{"CHOSTPASS", net_ads_change_localhost_pass},
		{"PRINTER", net_ads_printer},
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

int net_ads_join(int argc, const char **argv)
{
	return net_ads_noads();
}

int net_ads_user(int argc, const char **argv)
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
