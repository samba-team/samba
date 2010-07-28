/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Jeremy Allison 2000-2004

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

#ifndef _NT_DOMAIN_H /* _NT_DOMAIN_H */
#define _NT_DOMAIN_H 

/*
 * A bunch of stuff that was put into smb.h
 * in the NTDOM branch - it didn't belong there.
 */

typedef struct _output_data {
	/*
	 * Raw RPC output data. This does not include RPC headers or footers.
	 */
	DATA_BLOB rdata;

	/* The amount of data sent from the current rdata struct. */
	uint32 data_sent_length;

	/*
	 * The current fragment being returned. This inclues
	 * headers, data and authentication footer.
	 */
	DATA_BLOB frag;

	/* The amount of data sent from the current PDU. */
	uint32 current_pdu_sent;
} output_data;

typedef struct _input_data {
	/*
	 * This is the current incoming pdu. The data here
	 * is collected via multiple writes until a complete
	 * pdu is seen, then the data is copied into the in_data
	 * structure. The maximum size of this is 0x1630 (RPC_MAX_PDU_FRAG_LEN).
	 * If length is zero, then we are at the start of a new
	 * pdu.
	 */
	DATA_BLOB pdu;

	/*
	 * The amount of data needed to complete the in_pdu.
	 * If this is zero, then we are at the start of a new
	 * pdu.
	 */
	uint32 pdu_needed_len;

	/*
	 * This is the collection of input data with all
	 * the rpc headers and auth footers removed.
	 * The maximum length of this (1Mb) is strictly enforced.
	 */
	DATA_BLOB data;

} input_data;

struct handle_list;

typedef struct pipe_rpc_fns {

	struct pipe_rpc_fns *next, *prev;

	/* RPC function table associated with the current rpc_bind (associated by context) */

	const struct api_struct *cmds;
	int n_cmds;
	uint32 context_id;

} PIPE_RPC_FNS;

/*
 * Different auth types we support.
 * Can't keep in sync with wire values as spnego wraps different auth methods.
 */

enum pipe_auth_type { PIPE_AUTH_TYPE_NONE = 0, PIPE_AUTH_TYPE_NTLMSSP, PIPE_AUTH_TYPE_SCHANNEL,
			PIPE_AUTH_TYPE_SPNEGO_NTLMSSP, PIPE_AUTH_TYPE_KRB5, PIPE_AUTH_TYPE_SPNEGO_KRB5 };

/* auth state for krb5. */
struct kerberos_auth_struct {
	const char *service_principal;
	DATA_BLOB session_key;
};

/* auth state for all bind types. */

struct pipe_auth_data {
	enum pipe_auth_type auth_type; /* switch for union below. */
	enum dcerpc_AuthLevel auth_level;

	union {
		struct schannel_state *schannel_auth;
		struct auth_ntlmssp_state *auth_ntlmssp_state;
		struct kerberos_auth_struct *kerberos_auth; /* Client only for now */
	} a_u;

	/* Only the client code uses these 3 for now */
	char *domain;
	char *user_name;
	DATA_BLOB user_session_key;

	void (*auth_data_free_func)(struct pipe_auth_data *);
};

/*
 * DCE/RPC-specific samba-internal-specific handling of data on
 * NamedPipes.
 */

struct pipes_struct {
	struct pipes_struct *next, *prev;

	char client_address[INET6_ADDRSTRLEN];

	struct auth_serversupplied_info *server_info;

	struct ndr_syntax_id syntax;

	/* linked list of rpc dispatch tables associated 
	   with the open rpc contexts */

	PIPE_RPC_FNS *contexts;

	struct pipe_auth_data auth;

	/*
	 * Set to true when an RPC bind has been done on this pipe.
	 */

	bool pipe_bound;

	/*
	 * Set to true when we should return fault PDU's for everything.
	 */

	bool fault_state;

	/*
	 * Set to true when we should return fault PDU's for a bad handle.
	 */

	bool bad_handle_fault_state;

	/*
	 * Set to true when the backend does not support a call.
	 */

	bool rng_fault_state;

	/*
	 * Set to RPC_BIG_ENDIAN when dealing with big-endian PDU's
	 */

	bool endian;

	/*
	 * Struct to deal with multiple pdu inputs.
	 */

	input_data in_data;

	/*
	 * Struct to deal with multiple pdu outputs.
	 */

	output_data out_data;

	/* This context is used for PDU data and is freed between each pdu.
		Don't use for pipe state storage. */
	TALLOC_CTX *mem_ctx;

	/* handle database to use on this pipe. */
	struct handle_list *pipe_handles;

	/* call id retrieved from the pdu header */
	uint32_t call_id;

	/* operation number retrieved from the rpc header */
	uint16_t opnum;

	/* private data for the interface implementation */
	void *private_data;

};

struct api_struct {  
	const char *name;
	uint8 opnum;
	bool (*fn) (struct pipes_struct *);
};

#endif /* _NT_DOMAIN_H */
