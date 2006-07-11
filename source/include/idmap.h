#ifndef _IDMAP_H_
#define _IDMAP_H_
/* 
   Unix SMB/CIFS implementation.

   Idmap headers

   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Simo Sorce 2003
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

/* idmap version determines auto-conversion - this is the database
   structure version specifier. */

#define IDMAP_VERSION 2

/* The interface version specifier. 
   Updated to 3 for enum types by JRA. */

#define SMB_IDMAP_INTERFACE_VERSION	3

enum idmap_type { ID_USERID, ID_GROUPID };

#define IDMAP_FLAG_NONE		0x0
#define IDMAP_FLAG_QUERY_ONLY	0x1	/* Don't ever allocate, just query. */
#define IDMAP_FLAG_CACHE_ONLY   0x2	/* Only look in our local cache, not remote. */

/* Filled out by IDMAP backends */
struct idmap_methods {

	/* Called when backend is first loaded */
	NTSTATUS (*init)( const char *params );

	NTSTATUS (*allocate_id)(unid_t *id, enum idmap_type id_type);
	NTSTATUS (*get_sid_from_id)(DOM_SID *sid, unid_t id, enum idmap_type id_type, int flags);
	NTSTATUS (*get_id_from_sid)(unid_t *id, enum idmap_type *id_type, const DOM_SID *sid, int flags);
	NTSTATUS (*set_mapping)(const DOM_SID *sid, unid_t id, enum idmap_type id_type);

	/* Called when backend is unloaded */
	NTSTATUS (*close_fn)(void);

	/* Called to dump backend status */
	void (*status)(void);
};
#endif /* _IDMAP_H_ */
