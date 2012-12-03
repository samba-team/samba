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

#ifndef __LIB_UTIL_SID_PASSDB_H__
#define __LIB_UTIL_SID_PASSDB_H__

/**
 * check whether this is an object-sid that should
 * be treated by the passdb, e.g. for id-mapping.
 */
bool sid_check_object_is_for_passdb(const struct dom_sid *sid);

/**
 * check whether this is an object- or domain-sid that should
 * be treated by the passdb, e.g. for id-mapping.
 */
bool sid_check_is_for_passdb(const struct dom_sid *sid);

#endif /* __LIB_UTIL_SID_PASSDB_H__ */
