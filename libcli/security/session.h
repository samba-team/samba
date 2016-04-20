/*
   Unix SMB/CIFS implementation.

   session_info utility functions

   Copyright (C) Andrew Bartlett 2008-2010

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

#ifndef _LIBCLI_SECURITY_SESSION_H_
#define _LIBCLI_SECURITY_SESSION_H_

enum security_user_level {
	SECURITY_ANONYMOUS            = 0,
	SECURITY_GUEST                = 1,
	SECURITY_USER                 = 10,
	SECURITY_RO_DOMAIN_CONTROLLER = 20,
	SECURITY_DOMAIN_CONTROLLER    = 30,
	SECURITY_ADMINISTRATOR        = 40,
	SECURITY_SYSTEM               = 50
};

struct cli_credentials;
struct security_token;
struct auth_user_info;
struct auth_user_info_torture;
struct auth_session_info;

enum security_user_level security_session_user_level(struct auth_session_info *session_info,
						     const struct dom_sid *domain_sid);

#endif
