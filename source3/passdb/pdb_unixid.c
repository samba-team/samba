/*
 *  Unix SMB/CIFS implementation.
 *  IDMAP unixid utility functions
 *  Copyright (C) Alexander Bokovoy 2012
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "passdb.h"
#include "../librpc/gen_ndr/idmap.h"

void unixid_from_uid(struct unixid *id, uint32_t some_uid)
{
	if(id) {
		id->id = some_uid;
		id->type = ID_TYPE_UID;
	}
}

void unixid_from_gid(struct unixid *id, uint32_t some_gid)
{
	if(id) {
		id->id = some_gid;
		id->type = ID_TYPE_GID;
	}
}

void unixid_from_both(struct unixid *id, uint32_t some_id)
{
	if(id) {
		id->id = some_id;
		id->type = ID_TYPE_BOTH;
	}
}

