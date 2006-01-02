/* 
   Unix SMB/CIFS implementation.
 
   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   
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

#define GENSEC_OID_NTLMSSP "1 3 6 1 4 1 311 2 2 10"
#define GENSEC_OID_SPNEGO "1 3 6 1 5 5 2"
#define GENSEC_OID_KERBEROS5 "1 2 840 113554 1 2 2"
#define GENSEC_OID_KERBEROS5_OLD "1 2 840 48018 1 2 2"
#define GENSEC_OID_KERBEROS5_USER2USER "1 2 840 113554 1 2 2 3"

struct gensec_security;
struct gensec_target {
	const char *principal;
	const char *hostname;
	const char *service;
};

struct gensec_addr {
	const char *addr;
	int port;
};

#define GENSEC_FEATURE_SESSION_KEY	0x00000001
#define GENSEC_FEATURE_SIGN		0x00000002
#define GENSEC_FEATURE_SEAL		0x00000004
#define GENSEC_FEATURE_DCE_STYLE	0x00000008
#define GENSEC_FEATURE_ASYNC_REPLIES	0x00000010
#define GENSEC_FEATURE_DATAGRAM_MODE	0x00000020

/* GENSEC mode */
enum gensec_role
{
	GENSEC_SERVER,
	GENSEC_CLIENT
};

struct auth_session_info;

struct gensec_security_ops {
	const char *name;
	const char *sasl_name;
	uint8_t auth_type;  /* 0 if not offered on DCE-RPC */
	const char **oid;  /* NULL if not offered by SPNEGO */
	NTSTATUS (*client_start)(struct gensec_security *gensec_security);
	NTSTATUS (*server_start)(struct gensec_security *gensec_security);
	/**
	   Determine if a packet has the right 'magic' for this mechanism
	*/
	NTSTATUS (*magic)(struct gensec_security *gensec_security, 
			  const DATA_BLOB *first_packet);
	NTSTATUS (*update)(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx,
			   const DATA_BLOB in, DATA_BLOB *out);
	NTSTATUS (*seal_packet)(struct gensec_security *gensec_security, TALLOC_CTX *sig_mem_ctx,
				uint8_t *data, size_t length, 
				const uint8_t *whole_pdu, size_t pdu_length, 
				DATA_BLOB *sig);
	NTSTATUS (*sign_packet)(struct gensec_security *gensec_security, TALLOC_CTX *sig_mem_ctx,
				const uint8_t *data, size_t length, 
				const uint8_t *whole_pdu, size_t pdu_length, 
				DATA_BLOB *sig);
	size_t   (*sig_size)(struct gensec_security *gensec_security, size_t data_size);
	NTSTATUS (*check_packet)(struct gensec_security *gensec_security, TALLOC_CTX *sig_mem_ctx, 
				 const uint8_t *data, size_t length, 
				 const uint8_t *whole_pdu, size_t pdu_length, 
				 const DATA_BLOB *sig);
	NTSTATUS (*unseal_packet)(struct gensec_security *gensec_security, TALLOC_CTX *sig_mem_ctx,
				  uint8_t *data, size_t length, 
				  const uint8_t *whole_pdu, size_t pdu_length, 
				  const DATA_BLOB *sig);
	NTSTATUS (*wrap)(struct gensec_security *gensec_security, 
				  TALLOC_CTX *mem_ctx, 
				  const DATA_BLOB *in, 
				  DATA_BLOB *out); 
	NTSTATUS (*unwrap)(struct gensec_security *gensec_security, 
				  TALLOC_CTX *mem_ctx, 
				  const DATA_BLOB *in, 
				  DATA_BLOB *out); 
	NTSTATUS (*session_key)(struct gensec_security *gensec_security, DATA_BLOB *session_key);
	NTSTATUS (*session_info)(struct gensec_security *gensec_security, 
				 struct auth_session_info **session_info); 
	BOOL (*have_feature)(struct gensec_security *gensec_security,
				    uint32_t feature); 
	BOOL enabled;
};
	
struct gensec_security_ops_wrapper {
	const struct gensec_security_ops *op;
	const char *oid;
};

#define GENSEC_INTERFACE_VERSION 0

struct gensec_security {
	const struct gensec_security_ops *ops;
	void *private_data;
	struct cli_credentials *credentials;
	struct gensec_target target;
	enum gensec_role gensec_role;
	BOOL subcontext;
	uint32_t want_features;
	struct event_context *event_ctx;
	struct gensec_addr my_addr, peer_addr;
};

/* this structure is used by backends to determine the size of some critical types */
struct gensec_critical_sizes {
	int interface_version;
	int sizeof_gensec_security_ops;
	int sizeof_gensec_security;
};

#include "gensec_proto.h"
