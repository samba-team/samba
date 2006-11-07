/* 
   Unix SMB/CIFS implementation.

   KDC structures

   Copyright (C) Andrew Tridgell	2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
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

#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "heimdal/kdc/kdc.h"
#include "heimdal/lib/hdb/hdb.h"
#include "kdc/pac-glue.h"

struct kdc_server;
struct socket_address;

NTSTATUS kdc_hdb_ldb_create(TALLOC_CTX *mem_ctx, 
			    krb5_context context, struct HDB **db, const char *arg);
BOOL kpasswdd_process(struct kdc_server *kdc,
		      TALLOC_CTX *mem_ctx, 
		      DATA_BLOB *input, 
		      DATA_BLOB *reply,
		      struct socket_address *peer_addr, 
		      struct socket_address *my_addr,
		      int datagram_reply);

/*
  top level context structure for the kdc server
*/
struct kdc_server {
	struct task_server *task;
	krb5_kdc_configuration *config;
	struct smb_krb5_context *smb_krb5_context;
};


