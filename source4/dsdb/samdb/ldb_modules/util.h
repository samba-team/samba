/* 
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 2009
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009

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

#include "dsdb/samdb/ldb_modules/util_proto.h"

#define DSDB_SEARCH_SEARCH_ALL_PARTITIONS     0x0001
#define DSDB_SEARCH_SHOW_DELETED              0x0002
#define DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT 0x0004
#define DSDB_SEARCH_SHOW_EXTENDED_DN          0x0010
