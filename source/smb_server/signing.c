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
  sign an outgoing packet
*/
void req_sign_packet(struct smbsrv_request *req)
{
	/* check if we are doing signing on this connection */
	if (req->smb_conn->signing.signing_state != SMB_SIGNING_REQUIRED) {
		return;
	}
	sign_outgoing_message(&req->out, 
			      &req->smb_conn->signing.mac_key, 
			      req->seq_num+1);
}


/*
  setup the signing key for a connection. Called after authentication succeeds
  in a session setup
*/
void srv_setup_signing(struct smbsrv_connection *smb_conn,
		       DATA_BLOB *session_key,
		       DATA_BLOB *session_response)
{
	smb_conn->signing.mac_key = data_blob(NULL, 
					 session_key->length + session_response->length);
	memcpy(smb_conn->signing.mac_key.data, session_key->data, session_key->length);
	if (session_response->length != 0) {
		memcpy(&smb_conn->signing.mac_key.data[session_key->length],
		       session_response->data, 
		       session_response->length);
	}
}


/*
  allocate a sequence number to a request
*/
static void req_signing_alloc_seq_num(struct smbsrv_request *req)
{
	req->seq_num = req->smb_conn->signing.next_seq_num;

	/* TODO: we need to handle one-way requests like NTcancel, which 
	   only increment the sequence number by 1 */
	if (req->smb_conn->signing.signing_state != SMB_SIGNING_OFF) {
		req->smb_conn->signing.next_seq_num += 2;
	}
}

/*
  check the signature of an incoming packet
*/
BOOL req_signing_check_incoming(struct smbsrv_request *req)
{
	uint8_t client_md5_mac[8], signature[8];

	switch (req->smb_conn->signing.signing_state) {
	case SMB_SIGNING_OFF:
		return True;
	case SMB_SIGNING_SUPPORTED:
		if (req->flags2 & FLAGS2_SMB_SECURITY_SIGNATURES) {
			req->smb_conn->signing.signing_state = SMB_SIGNING_REQUIRED;
		}
		break;
	case SMB_SIGNING_REQUIRED:
		break;
	}

	req_signing_alloc_seq_num(req);

	/* the first packet isn't checked as the key hasn't been established */
	if (req->seq_num == 0) {
		return True;
	}

	return check_signed_incoming_message(&req->in,
					     &req->smb_conn->signing.mac_key,
					     req->seq_num);

}
