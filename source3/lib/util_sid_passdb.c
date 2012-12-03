/*
   Unix SMB/CIFS implementation.
   sid utility functions

   Copyright (C) Michael Adam 2012

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

#include "includes.h"
#include "lib/util_sid_passdb.h"
#include "passdb/machine_sid.h"

/**
 * check whether this is an object-sid that should
 * be treated by the passdb, e.g. for id-mapping.
 */
bool sid_check_object_is_for_passdb(const struct dom_sid *sid)
{
	if (sid_check_is_in_our_sam(sid)) {
		return true;
	}

	if (sid_check_is_in_builtin(sid)) {
		return true;
	}

	if (sid_check_is_in_wellknown_domain(sid)) {
		return true;
	}

	if (sid_check_is_in_unix_users(sid)) {
		return true;
	}

	if (sid_check_is_in_unix_groups(sid)) {
		return true;
	}

	return false;
}
/**
 * check whether this is an object- or domain-sid that should
 * be treated by the passdb, e.g. for id-mapping.
 */
bool sid_check_is_for_passdb(const struct dom_sid *sid)
{
	if (sid_check_is_our_sam(sid)) {
		return true;
	}

	if (sid_check_is_in_our_sam(sid)) {
		return true;
	}

	if (sid_check_is_builtin(sid)) {
		return true;
	}

	if (sid_check_is_in_builtin(sid)) {
		return true;
	}

	if (sid_check_is_wellknown_domain(sid, NULL)) {
		return true;
	}

	if (sid_check_is_in_wellknown_domain(sid)) {
		return true;
	}

	if (sid_check_is_unix_users(sid)) {
		return true;
	}

	if (sid_check_is_in_unix_users(sid)) {
		return true;
	}

	if (sid_check_is_unix_groups(sid)) {
		return true;
	}

	if (sid_check_is_in_unix_groups(sid)) {
		return true;
	}

	return false;
}
