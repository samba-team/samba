/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell              2004
   
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

#include "includes.h"

/*
  mark the flags2 field in a packet as signed
*/
static void mark_packet_signed(struct request_context *req) 
{
	uint16_t flags2;
	flags2 = SVAL(req->out.hdr, HDR_FLG2);
	flags2 |= FLAGS2_SMB_SECURITY_SIGNATURES;
	SSVAL(req->out.hdr, HDR_FLG2, flags2);
}

/*
  calculate the signature for a message
*/
static void calc_signature(uint8 *buffer, size_t length,
			   DATA_BLOB *mac_key, uint8 signature[8])
{
	unsigned char calc_md5_mac[16];
	struct MD5Context md5_ctx;

	MD5Init(&md5_ctx);
	MD5Update(&md5_ctx, mac_key->data, mac_key->length); 
	MD5Update(&md5_ctx, buffer, length);
	MD5Final(calc_md5_mac, &md5_ctx);
	memcpy(signature, calc_md5_mac, 8);
}
			   

/*
  sign an outgoing packet
*/
void req_sign_packet(struct request_context *req)
{
	/* check if we are doing signing on this connection */
	if (req->smb->signing.signing_state != SMB_SIGNING_REQUIRED) {
		return;
	}

	SBVAL(req->out.hdr, HDR_SS_FIELD, req->seq_num+1);

	mark_packet_signed(req);

	calc_signature(req->out.hdr, req->out.size - NBT_HDR_SIZE,
		       &req->smb->signing.mac_key, 
		       &req->out.hdr[HDR_SS_FIELD]);
}


/*
  setup the signing key for a connection. Called after authentication succeeds
  in a session setup
*/
void srv_setup_signing(struct server_context *smb,
		       DATA_BLOB *session_key,
		       DATA_BLOB *session_response)
{
	smb->signing.mac_key = data_blob(NULL, 
					 session_key->length + session_response->length);
	memcpy(smb->signing.mac_key.data, session_key->data, session_key->length);
	if (session_response->length != 0) {
		memcpy(&smb->signing.mac_key.data[session_key->length],
		       session_response->data, 
		       session_response->length);
	}
}


/*
  allocate a sequence number to a request
*/
static void req_signing_alloc_seq_num(struct request_context *req)
{
	req->seq_num = req->smb->signing.next_seq_num;

	/* TODO: we need to handle one-way requests like NTcancel, which 
	   only increment the sequence number by 1 */
	if (req->smb->signing.signing_state != SMB_SIGNING_OFF) {
		req->smb->signing.next_seq_num += 2;
	}
}

/*
  check the signature of an incoming packet
*/
BOOL req_signing_check_incoming(struct request_context *req)
{
	unsigned char client_md5_mac[8], signature[8];

	switch (req->smb->signing.signing_state) {
	case SMB_SIGNING_OFF:
		return True;
	case SMB_SIGNING_SUPPORTED:
		if (req->flags2 & FLAGS2_SMB_SECURITY_SIGNATURES) {
			req->smb->signing.signing_state = SMB_SIGNING_REQUIRED;
		}
		return True;
	case SMB_SIGNING_REQUIRED:
		break;
	}

	req_signing_alloc_seq_num(req);

	/* the first packet isn't checked as the key hasn't been established */
	if (req->seq_num == 0) {
		return True;
	}

	/* room enough for the signature? */
	if (req->in.size < NBT_HDR_SIZE + HDR_SS_FIELD + 8) {
		return False;
	}

	memcpy(client_md5_mac, req->in.hdr + HDR_SS_FIELD, 8);

	SBVAL(req->in.hdr, HDR_SS_FIELD, req->seq_num);

	calc_signature(req->in.hdr, req->in.size - NBT_HDR_SIZE,
		       &req->smb->signing.mac_key, 
		       signature);

	if (memcmp(client_md5_mac, signature, 8) != 0) {
		DEBUG(2,("Bad SMB signature seq_num=%d\n", (int)req->seq_num));
		return False;
	}

	return True;
}
