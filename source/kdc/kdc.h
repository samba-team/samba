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
#include "kdc/pac-glue.h"

krb5_error_code hdb_ldb_create(TALLOC_CTX *mem_ctx, 
			       krb5_context context, struct HDB **db, const char *arg);

/* hold all the info needed to send a reply */
struct kdc_reply {
	struct kdc_reply *next, *prev;
	const char *dest_address;
	int dest_port;
	DATA_BLOB packet;
};

/*
  top level context structure for the kdc server
*/
struct kdc_server {
	struct task_server *task;
	krb5_kdc_configuration *config;
	struct smb_krb5_context *smb_krb5_context;
};

/* hold information about one kdc socket */
struct kdc_socket {
	struct socket_context *sock;
	struct kdc_server *kdc;
	struct fd_event *fde;

	/* a queue of outgoing replies that have been deferred */
	struct kdc_reply *send_queue;
};

