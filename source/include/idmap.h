/* 
   Unix SMB/CIFS implementation.

   Idmap headers

   Copyright (C) Anthony Liguori 2003
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

#define	ID_EMPTY	0
#define ID_USERID	1
#define ID_GROUPID	2
#define ID_OTHER	3

typedef union id_t {
	uid_t uid;
	gid_t gid;
} id_t;

/* Filled out by IDMAP backends */
struct idmap_methods {

	/* Called when backend is first loaded */
	NTSTATUS (*init)(void);

	NTSTATUS (*get_sid_from_id)(DOM_SID *sid, id_t id, int id_type);
	NTSTATUS (*get_id_from_sid)(id_t *id, int *id_type, DOM_SID *sid);

	/* Called when backend is unloaded */
	NTSTATUS (*close)(void);

	/* Called to dump backend status */
	void (*status)(void);
};

