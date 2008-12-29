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
#include <kdc.h>
#include <hdb.h>
#include <krb5/windc_plugin.h>
#include "kdc/pac_glue.h"

struct kdc_server;
struct socket_address;

extern TALLOC_CTX *kdc_mem_ctx;
extern struct tevent_context *kdc_ev_ctx;
extern struct loadparm_context *kdc_lp_ctx;

bool kpasswdd_process(struct kdc_server *kdc,
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


struct hdb_ldb_private {
	struct ldb_context *samdb;
	struct smb_iconv_convenience *iconv_convenience;
	struct ldb_message *msg;
	struct ldb_message *realm_ref_msg;
	hdb_entry_ex *entry_ex;
	const char *netbios_name;
};
