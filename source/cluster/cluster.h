/* 
   Unix SMB/CIFS implementation.

   structures for clustering

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

#ifndef __CLUSTER_H__
#define __CLUSTER_H__ 

/*
  test for same cluster id
*/
#define cluster_id_equal(id1, id2) ((id1)->id == (id2)->id && (id1)->node == (id2)->node)

/* prototypes */
struct server_id cluster_id(uint32_t id);
const char *cluster_id_string(TALLOC_CTX *mem_ctx, struct server_id id);
struct tdb_wrap *cluster_tdb_tmp_open(TALLOC_CTX *mem_ctx, const char *dbname, int flags);
void *cluster_private(void);

#endif
