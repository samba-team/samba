/* 
   Samba Unix/Linux SMB client library 
   Version 3.0
   join a realm
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

/* a lame random number generator - used /dev/urandom if possible */
static unsigned one_random(void)
{
	int fd = -1;
	static int initialised;
	unsigned ret;

	if (!initialised) {
		initialised = 1;
		fd = open("/dev/urandom", O_RDONLY);
		srandom(time(NULL) ^ getpid());
	}

	if (fd == -1) {
		return random();
	}

	read(fd, &ret, sizeof(ret));
	return ret;
}

/*
 * Generate a simple random password of 15 chars - not a cryptographic one
 */
static char *generate_random_password(int len)
{
	int i;
	char *pass;

	if (!(pass = malloc(len+1)))
		return NULL;

	for (i=0; i<len; ) {
		char c = one_random() & 0x7f;
		if (!isalnum(c) && !ispunct(c)) continue;
		pass[i++] = c;
	}
	
	return pass;
}


int net_join_usage(void)
{
	d_printf("\nnet join"\
		 "\n\tjoins the local machine to a ADS realm\n");
	return -1;
}

int net_join(int argc, const char **argv)
{
	char *ldap_host;
	char *hostname;
	ADS_STRUCT *ads;
	int rc;
	char *password;
	extern pstring global_myname;
	NTSTATUS status;

	hostname = strdup(global_myname);
	strlower(hostname);
	if (!*ldap_host) ldap_host = NULL;

	if (!secrets_init()) {
		DEBUG(1,("Failed to initialise secrets database\n"));
		return -1;
	}

	password = generate_random_password(15);

	ads = ads_init(NULL, NULL, NULL);

	rc = ads_connect(ads);
	if (rc) {
		d_printf("ads_connect: %s\n", ads_errstr(rc));
		ads_destory(&ads);
		return -1;
	}

	rc = ads_join_realm(ads, hostname);
	if (rc) {
		d_printf("ads_join_realm: %s\n", ads_errstr(rc));
		ads_destory(&ads);
		return -1;
	}

	status = ads_set_machine_password(ads, hostname, password);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("ads_set_machine_password: %s\n", get_nt_error_msg(status));
		ads_destory(&ads);
		return -1;
	}

	if (!secrets_store_machine_password(password)) {
		DEBUG(1,("Failed to save machine password\n"));
		ads_destory(&ads);
		return -1;
	}

	d_printf("Joined %s to realm %s\n", hostname, ads->realm);

	ads_destory(&ads);
	return 0;
}

#else

int net_join_usage(void)
{
	d_printf("ADS support not compiled in\n");
	return -1;
}

int net_join(int argc, const char **argv)
{
	return net_join_usage();
}

#endif
