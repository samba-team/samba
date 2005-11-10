/* 
   Unix SMB/CIFS implementation.
   LDAP server
   Copyright (C) Volker Lendecke 2004
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

#include "libcli/ldap/ldap.h"

struct ldapsrv_connection {
	struct stream_connection *connection;
	struct gensec_security *gensec;
	struct auth_session_info *session_info;
	struct ldapsrv_service *service;
	struct tls_context *tls;
	struct ldapsrv_partition *rootDSE;
	struct ldapsrv_partition *default_partition;
	struct ldapsrv_partition *partitions;

	/* are we using gensec wrapping? */
	BOOL enable_wrap;

	/* connection should be terminated if non-null */
	const char *terminate;

	struct packet_context *packet;
};

struct ldapsrv_call {
	struct ldapsrv_connection *conn;
	struct ldap_message *request;
	struct ldapsrv_reply {
		struct ldapsrv_reply *prev, *next;
		struct ldap_message *msg;
	} *replies;
};

struct ldapsrv_service;
struct ldapsrv_partition;

struct ldapsrv_partition_ops {
	const char *name;
	NTSTATUS (*Init)(struct ldapsrv_partition *partition, struct ldapsrv_connection *conn);
	NTSTATUS (*Bind)(struct ldapsrv_partition *partition, struct ldapsrv_connection *conn);
	NTSTATUS (*Search)(struct ldapsrv_partition *partition, struct ldapsrv_call *call, struct ldap_SearchRequest *r);
	NTSTATUS (*Modify)(struct ldapsrv_partition *partition, struct ldapsrv_call *call, struct ldap_ModifyRequest *r);
	NTSTATUS (*Add)(struct ldapsrv_partition *partition, struct ldapsrv_call *call, struct ldap_AddRequest *r);
	NTSTATUS (*Del)(struct ldapsrv_partition *partition, struct ldapsrv_call *call, struct ldap_DelRequest *r);
	NTSTATUS (*ModifyDN)(struct ldapsrv_partition *partition, struct ldapsrv_call *call, struct ldap_ModifyDNRequest *r);
	NTSTATUS (*Compare)(struct ldapsrv_partition *partition, struct ldapsrv_call *call, struct ldap_CompareRequest *r);
	NTSTATUS (*Abandon)(struct ldapsrv_partition *partition, struct ldapsrv_call *call, struct ldap_AbandonRequest *r);
	NTSTATUS (*Extended)(struct ldapsrv_partition *partition, struct ldapsrv_call *call, struct ldap_ExtendedRequest *r);
};

struct ldapsrv_partition {
	struct ldapsrv_partition *prev,*next;

	void *private;
	const struct ldapsrv_partition_ops *ops;

	const char *base_dn;
};

struct ldapsrv_service {
	struct tls_params *tls_params;
};
