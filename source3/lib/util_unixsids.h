/*
   Unix SMB/CIFS implementation.
   Translate unix-defined names to SIDs and vice versa
   Copyright (C) Volker Lendecke 2005

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

#ifndef __UTIL_UNIXSIDS_H__
#define __UTIL_UNIXSIDS_H__

#include "replace.h"

struct dom_sid;

bool sid_check_is_unix_users(const struct dom_sid *sid);
bool sid_check_is_in_unix_users(const struct dom_sid *sid);
void uid_to_unix_users_sid(uid_t uid, struct dom_sid *sid);
void gid_to_unix_groups_sid(gid_t gid, struct dom_sid *sid);
const char *unix_users_domain_name(void);
bool sid_check_is_unix_groups(const struct dom_sid *sid);
bool sid_check_is_in_unix_groups(const struct dom_sid *sid);
const char *unix_groups_domain_name(void);

#endif
