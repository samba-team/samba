/* 
   Samba Unix/Linux SMB client library 
   Version 3.0
   net ads commands
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)

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

#ifdef HAVE_ADS

int net_ads_usage(int argc, const char **argv)
{
	d_printf(
"\nnet ads join"\
"\n\tjoins the local machine to a ADS realm\n"\
"\nnet ads leave"\
"\n\tremoves the local machine from a ADS realm\n"\
"\nnet ads user"\
"\n\tlist users in the realm\n"\
"\nnet ads group"\
"\n\tlist groups in the realm\n"\
"\nnet ads status"\
"\n\tdump the machine account details to stdout\n"
		);
	return -1;
}

static ADS_STRUCT *ads_startup(void)
{
	ADS_STRUCT *ads;
	int rc;
	ads = ads_init(NULL, NULL, NULL);

	rc = ads_connect(ads);
	if (rc) {
		d_printf("ads_connect: %s\n", ads_errstr(rc));
		return NULL;
	}
	return ads;
}

static int net_ads_user(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	int rc;
	void *res;
	const char *attrs[] = {"sAMAccountName", "name", "objectSid", NULL};

	if (!(ads = ads_startup())) return -1;
	rc = ads_search(ads, &res, "(objectclass=user)", attrs);
	if (rc) {
		d_printf("ads_search: %s\n", ads_errstr(rc));
		return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_printf("No users found\n");
		return -1;
	}

	ads_dump(ads, res);
	ads_destroy(&ads);
	return 0;
}

static int net_ads_group(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	int rc;
	void *res;
	const char *attrs[] = {"sAMAccountName", "name", "objectSid", NULL};

	if (!(ads = ads_startup())) return -1;
	rc = ads_search(ads, &res, "(objectclass=group)", attrs);
	if (rc) {
		d_printf("ads_search: %s\n", ads_errstr(rc));
		return -1;
	}

	if (ads_count_replies(ads, res) == 0) {
		d_printf("No groups found\n");
		return -1;
	}

	ads_dump(ads, res);
	return 0;
}

static int net_ads_status(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	int rc;
	extern pstring global_myname;
	void *res;

	if (!(ads = ads_startup())) return -1;

	rc = ads_find_machine_acct(ads, &res, global_myname);
	if (rc) {
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
	ADS_STRUCT *ads;
	int rc;
	extern pstring global_myname;

	if (!(ads = ads_startup())) return -1;

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}

	rc = ads_leave_realm(ads, global_myname);
	if (rc) {
	    d_printf("Failed to delete host '%s' from the '%s' realm.\n", 
		     global_myname, ads->realm);
	    return -1;
	}

	d_printf("Removed '%s' from realm '%s'\n", global_myname, ads->realm);

	return 0;
}

static int net_ads_join(int argc, const char **argv)
{
	ADS_STRUCT *ads;
	int rc;
	char *password;
	extern pstring global_myname;
	NTSTATUS status;

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}

	password = generate_random_str(15);
	password = strdup(password);

	if (!(ads = ads_startup())) return -1;

	rc = ads_join_realm(ads, global_myname);
	if (rc) {
		d_printf("ads_join_realm: %s\n", ads_errstr(rc));
		return -1;
	}

	status = ads_set_machine_password(ads, global_myname, password);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("ads_set_machine_password: %s\n", get_nt_error_msg(status));
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

int net_ads(int argc, const char **argv)
{
	struct functable func[] = {
		{"JOIN", net_ads_join},
		{"LEAVE", net_ads_leave},
		{"STATUS", net_ads_status},
		{"USER", net_ads_user},
		{"GROUP", net_ads_group},
		{NULL, NULL}
	};
	
	return net_run_function(argc, argv, func, net_ads_usage);
}

#else

int net_ads_usage(int argc, const char **argv)
{
	d_printf("ADS support not compiled in\n");
	return -1;
}

int net_ads(int argc, const char **argv)
{
	return net_ads_usage(argc, argv);
}

#endif
