/* 
   samba -- Unix SMB/CIFS implementation.

   Client credentials structure

   Copyright (C) Jelmer Vernooij 2004-2005

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

/* In order of priority */
enum credentials_obtained { 
	CRED_GUESSED	= 0, /* Current value should be used, which was guessed */
	CRED_CALLBACK, 		 /* Callback should be used to obtain value */
	CRED_SPECIFIED		 /* Was explicitly specified on the command-line */
};

struct cli_credentials {
	/* Preferred methods, NULL means default */
	const char **preferred_methods;

	enum credentials_obtained workstation_obtained;
	enum credentials_obtained username_obtained;
	enum credentials_obtained password_obtained;
	enum credentials_obtained domain_obtained;
	enum credentials_obtained realm_obtained;

	const char *workstation;
	const char *username;
	const char *password;
	const char *domain;
	const char *realm;

	const char *(*workstation_cb) (struct cli_credentials *);
	const char *(*password_cb) (struct cli_credentials *);
	const char *(*username_cb) (struct cli_credentials *);
	const char *(*domain_cb) (struct cli_credentials *);
	const char *(*realm_cb) (struct cli_credentials *);

	void *priv_data;
};

#define cli_credentials_is_anonymous(c) (!(c) || !(c)->username || !(c)->username[0])
