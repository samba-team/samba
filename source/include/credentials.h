/* 
   samba -- Unix SMB/CIFS implementation.

   Client credentials structure

   Copyright (C) 2004 Jelmer Vernooij <jelmer@samba.org>

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

struct cli_credentials {
	/* Preferred methods, NULL means default */
	const char **preferred_methods;

	const char *username;
	const char *password;
	const char *domain;
	const char *realm;

	const char *(*username_cb) (void);
	const char *(*password_cb) (void);
	const char *(*domain_cb) (void);
	const char *(*realm_cb) (void);
};
