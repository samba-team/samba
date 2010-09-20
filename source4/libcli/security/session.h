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

#include "libcli/security/session_proto.h"

enum security_user_level {
	SECURITY_ANONYMOUS            = 0,
	SECURITY_USER                 = 10,
	SECURITY_RO_DOMAIN_CONTROLLER = 20,
	SECURITY_DOMAIN_CONTROLLER    = 30,
	SECURITY_ADMINISTRATOR        = 40,
	SECURITY_SYSTEM               = 50
};

struct auth_session_info;
