/*
   Unix SMB/CIFS implementation.

   KDC structures

   Copyright (C) Andrew Tridgell	2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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

#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include <hdb.h>
#include <kdc.h>
#include <krb5/windc_plugin.h>
#include "kdc/hdb-samba4.h"

struct kdc_server;
struct tsocket_address;

extern struct krb5plugin_windc_ftable windc_plugin_table;

bool kpasswdd_process(struct kdc_server *kdc,
		      TALLOC_CTX *mem_ctx,
		      DATA_BLOB *input,
		      DATA_BLOB *reply,
		      struct tsocket_address *peer_addr,
		      struct tsocket_address *my_addr,
		      int datagram_reply);

/*
  top level context structure for the kdc server
*/
struct kdc_server {
	struct task_server *task;
	krb5_kdc_configuration *config;
	struct smb_krb5_context *smb_krb5_context;
	struct hdb_samba4_context *hdb_samba4_context;
};

/* from hdb-samba4.c */
NTSTATUS hdb_samba4_create_kdc(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev_ctx,
			      struct loadparm_context *lp_ctx,
			      krb5_context context, struct HDB **db);
