/* 
   Unix SMB/CIFS implementation.
   LDAP server SIMPLE LDB implementation
   Copyright (C) Stefan Metzmacher 2004
   
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

#include "includes.h"

static NTSTATUS sldb_Search(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_SearchRequest *r)
{
	struct ldap_Result *done;
	struct ldapsrv_reply *done_r;

	DEBUG(0, ("sldb_Search: %s\n", r->filter));

	done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
	if (!done_r) {
		ldapsrv_terminate_connection(call->conn, "ldapsrv_init_reply() failed");
		return NT_STATUS_NO_MEMORY;
	}

	done = &done_r->msg.r.SearchResultDone;
	done->resultcode = 32;
	done->dn = NULL;
	done->errormessage = NULL;
	done->referral = NULL;

	ldapsrv_queue_reply(call, done_r);

	return NT_STATUS_OK;
}

static const struct ldapsrv_partition_ops sldb_ops = {
	.Search		= sldb_Search
};

const struct ldapsrv_partition_ops *ldapsrv_get_sldb_partition_ops(void)
{
	return &sldb_ops;
}
