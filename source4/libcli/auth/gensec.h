/* 
   Unix SMB/CIFS implementation.
 
   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   
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


struct gensec_security;
struct gensec_user {
	const char *domain;
	const char *realm;
	const char *name;
	const char *password;
	char schan_session_key[16];
};
struct gensec_target {
	const char *principal;
	const char *hostname;
	const struct sock_addr *addr;
	const char *service;
};

#define GENSEC_WANT_SESSION_KEY 0x1
#define GENSEC_WANT_SIGN 0x2
#define GENSEC_WANT_SEAL 0x4

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
	uint8 auth_type;  /* 0 if not offered on DCE-RPC */
	const char *oid;  /* NULL if not offered by SPENGO */
	NTSTATUS (*client_start)(struct gensec_security *gensec_security);
	NTSTATUS (*server_start)(struct gensec_security *gensec_security);
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
	size_t   (*sig_size)(struct gensec_security *gensec_security);
	NTSTATUS (*check_packet)(struct gensec_security *gensec_security, TALLOC_CTX *sig_mem_ctx, 
				 const uint8_t *data, size_t length, 
				 const uint8_t *whole_pdu, size_t pdu_length, 
				 const DATA_BLOB *sig);
	NTSTATUS (*unseal_packet)(struct gensec_security *gensec_security, TALLOC_CTX *sig_mem_ctx,
				  uint8_t *data, size_t length, 
				  const uint8_t *whole_pdu, size_t pdu_length, 
				  DATA_BLOB *sig);
	NTSTATUS (*session_key)(struct gensec_security *gensec_security, DATA_BLOB *session_key);
	NTSTATUS (*session_info)(struct gensec_security *gensec_security, 
				 struct auth_session_info **session_info); 
	void (*end)(struct gensec_security *gensec_security);
};
	
typedef NTSTATUS (*gensec_password_callback)(struct gensec_security *gensec_security, TALLOC_CTX *mem_ctx, 
					     char **password);

#define GENSEC_INTERFACE_VERSION 0

struct gensec_security {
	TALLOC_CTX *mem_ctx;
	gensec_password_callback password_callback;
	void *password_callback_private;
	const struct gensec_security_ops *ops;
	void *private_data;
	struct gensec_user user;
	struct gensec_user default_user;
	struct gensec_target target;
	enum gensec_role gensec_role;
	BOOL subcontext;
	uint32 want_features;
};

/* this structure is used by backends to determine the size of some critical types */
struct gensec_critical_sizes {
	int interface_version;
	int sizeof_gensec_security_ops;
	int sizeof_gensec_security;
};


       
