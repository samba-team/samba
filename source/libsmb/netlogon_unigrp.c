/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Universal groups helpers
   Copyright (C) Alexander Bokovoy                    2002.
   Copyright (C) Andrew Bartlett                      2002.
   
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
   
   This work was sponsored by Optifacio Software Services, Inc.
*/

#include "includes.h"

/*
    Handle for netlogon_unigrp.tdb database. It is used internally
    in cli_store_uni_groups_*() and cli_fetch_uni_groups()
    and is initialized on first call to cli_store_uni_groups_*()
*/
static TDB_CONTEXT *netlogon_unigrp_tdb = NULL;

/*
    Store universal groups info into netlogon_unigrp.tdb for
    later usage. We use 'domain_SID/user_rid' as key and
    array of uint32 where array[0] is number of elements
    and elements are array[1] ... array[array[0]]
*/

BOOL uni_group_cache_init(void)
{
	if (!netlogon_unigrp_tdb) {
		netlogon_unigrp_tdb = tdb_open_log(lock_path("netlogon_unigrp.tdb"), 0,
						   TDB_NOLOCK, O_RDWR | O_CREAT, 0644);
	}

	return (netlogon_unigrp_tdb != NULL);
}

void uni_group_cache_store_netlogon(TALLOC_CTX *mem_ctx, NET_USER_INFO_3 *user)
{
	TDB_DATA key,data;
        fstring keystr;
        int i;

	if (!uni_group_cache_init()) {
		DEBUG(0,("uni_group_cache_store_netlogon: cannot open netlogon_unigrp.tdb for write!\n"));
		return;
	}

	/* Prepare key as DOMAIN-SID/USER-RID string */
	slprintf(keystr, sizeof(keystr), "%s/%d", 
		 sid_string_static(&user->dom_sid.sid), user->user_rid);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;
	
	/* Prepare data */
	data.dsize = (user->num_groups2+1)*sizeof(uint32);
	data.dptr = talloc(mem_ctx, data.dsize);
	if(!data.dptr) {
		DEBUG(0,("uni_group_cache_store_netlogon: cannot allocate memory!\n"));
		talloc_destroy(mem_ctx);
		return;
	}
	
	/* Store data in byteorder-independent format */
	SIVAL(&((uint32*)data.dptr)[0],0,user->num_groups2);
	for(i=1; i<=user->num_groups2; i++) {
		SIVAL(&((uint32*)data.dptr)[i],0,user->gids[i-1].g_rid);
	}
	tdb_store(netlogon_unigrp_tdb, key, data, TDB_REPLACE);	
}

/*
    Fetch universal groups info from netlogon_unigrp.tdb for given
    domain sid and user rid and allocate it using given mem_ctx.
    Universal groups are returned as array of uint32 elements 
    and elements are array[0] ... array[num_elements-1]
    
*/
uint32* uni_group_cache_fetch(DOM_SID *domain, uint32 user_rid,
			      TALLOC_CTX *mem_ctx, uint32 *num_groups)
{
	TDB_DATA key,data;
	fstring keystr;
	uint32 *groups;
	uint32 i;
	uint32 group_count;
	
	if (!domain) {
		DEBUG(1,("uni_group_cache_fetch: expected non-null domain sid\n"));
		return NULL;
	}
	if (!mem_ctx) {
		DEBUG(1,("uni_group_cache_fetch: expected non-null memory context\n"));
		return NULL;
	}
	if (!num_groups) {
		DEBUG(1,("uni_group_cache_fetch: expected non-null num_groups\n"));
		return NULL;
	}
	if (!netlogon_unigrp_tdb) {
		netlogon_unigrp_tdb = tdb_open_log(lock_path("netlogon_unigrp.tdb"), 0,
                				    TDB_NOLOCK, O_RDWR, 0644);
	}
	if (!netlogon_unigrp_tdb) {
		DEBUG(5,("uni_group_cache_fetch: cannot open netlogon_unigrp.tdb for read - normal if not created yet\n"));
		return NULL;
	}
	
	*num_groups = 0;
	
	/* Fetch universal groups */
	slprintf(keystr, sizeof(keystr), "%s/%d", 
		 sid_string_static(domain), user_rid);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;
	data = tdb_fetch(netlogon_unigrp_tdb, key);
	
	/* There is no cached universal groups in netlogon_unigrp.tdb */
	/* for this user. */
	if (!data.dptr) return NULL;
	
	/* Transfer data to receiver's memory context */
	group_count = IVAL(&((uint32*)data.dptr)[0],0);
	groups = talloc(mem_ctx, (group_count)*sizeof(uint32));
	if (groups) {
		for(i=0; i<group_count; i++) {
			groups[i] = IVAL(&((uint32*)data.dptr)[i+1],0);
		}
		
	} else {
		DEBUG(1,("uni_group_cache_fetch: cannot allocate uni groups in receiver's memory context\n"));
	}
	SAFE_FREE(data.dptr);
	*num_groups = group_count;
	return groups;
}

/* Shutdown netlogon_unigrp database */
void uni_group_cache_shutdown(void)
{
	if(netlogon_unigrp_tdb) {
		tdb_close(netlogon_unigrp_tdb);
	}
}

