/*
   Unix SMB/CIFS implementation.

   KDC related functions

   Copyright (c) 2005-2008 Andrew Bartlett <abartlet@samba.org>
   Copyright (c) 2005             Andrew Tridgell <tridge@samba.org>
   Copyright (c) 2005             Stefan Metzmacher <metze@samba.org>

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

#ifndef _KDC_SERVER_H
#define _KDC_SERVER_H

#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"

struct tsocket_address;
struct model_ops;

/*
 * Context structure for the kdc server
 */
struct kdc_server {
	struct task_server *task;
	struct smb_krb5_context *smb_krb5_context;
	struct samba_kdc_base_context *base_ctx;
	struct ldb_context *samdb;
	bool am_rodc;
	uint32_t proxy_timeout;
	const char *keytab_name;
	void *private_data;
};

typedef enum kdc_code_e {
	KDC_OK = 0,
	KDC_ERROR,
	KDC_PROXY_REQUEST
} kdc_code;

typedef kdc_code (*kdc_process_fn_t)(struct kdc_server *kdc,
				     TALLOC_CTX *mem_ctx,
				     DATA_BLOB *request,
				     DATA_BLOB *reply,
				     struct tsocket_address *remote_address,
				     struct tsocket_address *local_address,
				     int datagram);

/* Information about one kdc socket */
struct kdc_socket {
	struct kdc_server *kdc;
	struct tsocket_address *local_address;
	kdc_process_fn_t process;
};

/* Information about one kdc/kpasswd udp socket */
struct kdc_udp_socket {
	struct kdc_socket *kdc_socket;
	struct tdgram_context *dgram;
	struct tevent_queue *send_queue;
};

NTSTATUS kdc_add_socket(struct kdc_server *kdc,
			const struct model_ops *model_ops,
			const char *name,
			const char *address,
			uint16_t port,
			kdc_process_fn_t process,
			bool udp_only);

#endif /* _KDC_SERVER_H */
