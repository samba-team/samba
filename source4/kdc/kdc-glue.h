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

#ifndef _KDC_KDC_H
#define _KDC_KDC_H

#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include <hdb.h>
#include <kdc.h>
#include <krb5/windc_plugin.h>
#include "kdc/samba_kdc.h"

struct tsocket_address;

/*
  top level context structure for the kdc server
*/
struct kdc_server {
	struct task_server *task;
	krb5_kdc_configuration *config;
	struct smb_krb5_context *smb_krb5_context;
	struct samba_kdc_base_context *base_ctx;
	struct ldb_context *samdb;
	bool am_rodc;
	uint32_t proxy_timeout;
};

enum kdc_process_ret {
	KDC_PROCESS_OK=0,
	KDC_PROCESS_FAILED,
	KDC_PROCESS_PROXY};

struct kdc_udp_call {
	struct tsocket_address *src;
	DATA_BLOB in;
	DATA_BLOB out;
};

/* hold information about one kdc/kpasswd udp socket */
struct kdc_udp_socket {
	struct kdc_socket *kdc_socket;
	struct tdgram_context *dgram;
	struct tevent_queue *send_queue;
};

struct kdc_tcp_call {
	struct kdc_tcp_connection *kdc_conn;
	DATA_BLOB in;
	DATA_BLOB out;
	uint8_t out_hdr[4];
	struct iovec out_iov[2];
};

typedef enum kdc_process_ret (*kdc_process_fn_t)(struct kdc_server *kdc,
						 TALLOC_CTX *mem_ctx,
						 DATA_BLOB *input,
						 DATA_BLOB *reply,
						 struct tsocket_address *peer_addr,
						 struct tsocket_address *my_addr,
						 int datagram);


/* hold information about one kdc socket */
struct kdc_socket {
	struct kdc_server *kdc;
	struct tsocket_address *local_address;
	kdc_process_fn_t process;
};

/*
  state of an open tcp connection
*/
struct kdc_tcp_connection {
	/* stream connection we belong to */
	struct stream_connection *conn;

	/* the kdc_server the connection belongs to */
	struct kdc_socket *kdc_socket;

	struct tstream_context *tstream;

	struct tevent_queue *send_queue;
};


enum kdc_process_ret kpasswdd_process(struct kdc_server *kdc,
				      TALLOC_CTX *mem_ctx,
				      DATA_BLOB *input,
				      DATA_BLOB *reply,
				      struct tsocket_address *peer_addr,
				      struct tsocket_address *my_addr,
				      int datagram_reply);

/* from hdb-samba4.c */
NTSTATUS hdb_samba4_create_kdc(struct samba_kdc_base_context *base_ctx,
			       krb5_context context, struct HDB **db);

/* from proxy.c */
void kdc_udp_proxy(struct kdc_server *kdc, struct kdc_udp_socket *sock,
		   struct kdc_udp_call *call, uint16_t port);

void kdc_tcp_proxy(struct kdc_server *kdc, struct kdc_tcp_connection *kdc_conn,
		   struct kdc_tcp_call *call, uint16_t port);

#endif
