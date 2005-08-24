/* 
   ldb database library - Samba3 compatibility backend

   Copyright (C) Jelmer Vernooij 2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "ldb/ldb_map/ldb_map.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"

/* 
 * sambaGroupMapping -> group
 * 	gidNumber -> ???
 * 	sambaSID -> member
 * 	sambaGroupType -> groupType
 * 	displayName -> name
 * 	description -> description
 * 	sambaSIDList -> member 
 */

struct ldb_map_mappings samba3_mappings;

/* the init function */
#ifdef HAVE_DLOPEN_DISABLED
 struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *ldb_samba3_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	return ldb_map_init(ldb, &samba3_mappings, options);
}
