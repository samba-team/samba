/*
   Unix SMB/CIFS implementation.

   Map SIDs to uids/gids and back

   Copyright (C) Kai Blin 2008

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

#ifndef _IDMAP_H_
#define _IDMAP_H_

struct idmap_context {
	struct loadparm_context *lp_ctx;
	struct ldb_context *ldb_ctx;
	struct dom_sid *unix_groups_sid;
	struct dom_sid *unix_users_sid;
};

enum id_type {
        ID_TYPE_NOT_SPECIFIED = 0,
        ID_TYPE_UID,
        ID_TYPE_GID,
	ID_TYPE_BOTH
};

struct unixid {
        uint32_t id;
        enum id_type type;
};

struct id_mapping {
	struct unixid *unixid;
	struct dom_sid *sid;
	NTSTATUS status;
};

#include "winbind/idmap_proto.h"

#endif

