/* 
   Unix SMB/CIFS implementation.

   private structures for clustering

   Copyright (C) Andrew Tridgell 2006
   
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

#ifndef _CLUSTER_PRIVATE_H_
#define _CLUSTER_PRIVATE_H_

struct cluster_ops {
	struct server_id (*cluster_id)(struct cluster_ops *ops, uint32_t id);
	const char *(*cluster_id_string)(struct cluster_ops *ops, 
					 TALLOC_CTX *, struct server_id );
	void *private; /* backend state */
};

void cluster_set_ops(struct cluster_ops *new_ops);
void cluster_local_init(void);

#endif
