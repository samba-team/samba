/* 
   Unix SMB/CIFS implementation.

   interface functions for the sam database

   Copyright (C) Andrew Tridgell 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef __SAMDB_H__
#define __SAMDB_H__

struct auth_session_info;
struct drsuapi_DsNameInfo1;
struct drsuapi_DsReplicaObject;
struct drsuapi_DsReplicaOIDMapping_Ctr;
struct drsuapi_DsReplicaAttribute;
struct ldb_dn;

#define DSDB_CONTROL_REPLICATED_OBJECT_OID "1.3.6.1.4.1.7165.4.3.1"
struct dsdb_control_replicated_object {
	uint8_t __dummy;
};

#define DSDB_EXTENDED_REPLICATED_OBJECTS_OID "1.3.6.1.4.1.7165.4.4.1"
struct dsdb_extended_replicated_objects {
	struct ldb_dn *partition_dn;
};

#include "librpc/gen_ndr/security.h"
#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/samr.h"
#include "dsdb/schema/schema.h"
#include "dsdb/samdb/samdb_proto.h"

#endif /* __SAMDB_H__ */
