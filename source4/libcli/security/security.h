/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2006

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

#ifndef _LIBCLI_SECURITY_SECURITY_H_
#define _LIBCLI_SECURITY_SECURITY_H_

#include "librpc/gen_ndr/security.h"

enum security_user_level {
	SECURITY_ANONYMOUS            = 0,
	SECURITY_USER                 = 10,
	SECURITY_RO_DOMAIN_CONTROLLER = 20,
	SECURITY_DOMAIN_CONTROLLER    = 30,
	SECURITY_ADMINISTRATOR        = 40,
	SECURITY_SYSTEM               = 50
};

struct auth_session_info;

struct object_tree {
	uint32_t remaining_access;
	struct GUID guid;
	int num_of_children;
	struct object_tree *children;
};

/* Moved the dom_sid functions to the top level dir with manual proto header */
#include "libcli/security/dom_sid.h"
#include "libcli/security/secace.h"
#include "libcli/security/secacl.h"
#include "libcli/security/proto.h"
#include "libcli/security/security_descriptor.h"
#include "libcli/security/sddl.h"

#endif
