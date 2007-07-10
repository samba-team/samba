/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell              2004
   
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

#include "includes.h"
#include "smb_server/smb_server.h"
#include "libcli/raw/libcliraw.h"


/*
  sign an outgoing packet
*/
void smbsrv_sign_packet(struct smbsrv_request *req)
{
#if 0
	/* enable this when packet signing is preventing you working out why valgrind 
	   says that data is uninitialised */
	file_save("pkt.dat", req->out.buffer, req->out.size);
#endif

	switch (req->smb_conn->signing.signing_state) {
	case SMB_SIGNING_ENGINE_OFF:
		break;

	case SMB_SIGNING_ENGINE_BSRSPYL:
		/* mark the packet as signed - BEFORE we sign it...*/
		mark_packet_signed(&req->out);
		
		/* I wonder what BSRSPYL stands for - but this is what MS 
		   actually sends! */
		memcpy((req->out.hdr + HDR_SS_FIELD), "BSRSPYL ", 8);
		break;

	case SMB_SIGNING_ENGINE_ON:
			
		sign_outgoing_message(&req->out, 
				      &req->smb_conn->signing.mac_key, 
				      req->seq_num+1);
		break;
	}
	return;
}



/*
  setup the signing key for a connection. Called after authentication succeeds
  in a session setup
*/
BOOL smbsrv_setup_signing(struct smbsrv_connection *smb_conn,
			  DATA_BLOB *session_key,
			  DATA_BLOB *response)
{
	if (!set_smb_signing_common(&smb_conn->signing)) {
		return False;
	}
	return smbcli_simple_set_signing(smb_conn,
					 &smb_conn->signing, session_key, response);
}

void smbsrv_signing_restart(struct smbsrv_connection *smb_conn,
			    DATA_BLOB *session_key,
			    DATA_BLOB *response) 
{
	if (!smb_conn->signing.seen_valid) {
		DEBUG(5, ("Client did not send a valid signature on "
			  "SPNEGO session setup - ignored, expect good next time\n"));
		/* force things back on (most clients do not sign this packet)... */
		smbsrv_setup_signing(smb_conn, session_key, response);
		smb_conn->signing.next_seq_num = 2;
		if (smb_conn->signing.mandatory_signing) {
			DEBUG(5, ("Configured for mandatory signing, 'good packet seen' forced on\n"));
			/* if this is mandatory, then
			 * pretend we have seen a
			 * valid packet, so we don't
			 * turn it off */
			smb_conn->signing.seen_valid = True;
		}
	}
}

BOOL smbsrv_init_signing(struct smbsrv_connection *smb_conn)
{
	smb_conn->signing.mac_key = data_blob(NULL, 0);
	if (!smbcli_set_signing_off(&smb_conn->signing)) {
		return False;
	}
	
	switch (lp_server_signing()) {
	case SMB_SIGNING_OFF:
		smb_conn->signing.allow_smb_signing = False;
		break;
	case SMB_SIGNING_SUPPORTED:
		smb_conn->signing.allow_smb_signing = True;
		break;
	case SMB_SIGNING_REQUIRED:
		smb_conn->signing.allow_smb_signing = True;
		smb_conn->signing.mandatory_signing = True;
		break;
	case SMB_SIGNING_AUTO:
		if (lp_domain_logons()) {
			smb_conn->signing.allow_smb_signing = True;
		} else {
			smb_conn->signing.allow_smb_signing = False;
		}
		break;
	}
	return True;
}

/*
  allocate a sequence number to a request
*/
static void req_signing_alloc_seq_num(struct smbsrv_request *req)
{
	req->seq_num = req->smb_conn->signing.next_seq_num;

	if (req->smb_conn->signing.signing_state != SMB_SIGNING_ENGINE_OFF) {
		req->smb_conn->signing.next_seq_num += 2;
	}
}

/*
  called for requests that do not produce a reply of their own
*/
void smbsrv_signing_no_reply(struct smbsrv_request *req)
{
	if (req->smb_conn->signing.signing_state != SMB_SIGNING_ENGINE_OFF) {
		req->smb_conn->signing.next_seq_num--;
	}
}

/***********************************************************
 SMB signing - Simple implementation - check a MAC sent by client
************************************************************/
/**
 * Check a packet supplied by the server.
 * @return False if we had an established signing connection
 *         which had a back checksum, True otherwise
 */
BOOL smbsrv_signing_check_incoming(struct smbsrv_request *req)
{
	BOOL good;

	req_signing_alloc_seq_num(req);

	switch (req->smb_conn->signing.signing_state) 
	{
	case SMB_SIGNING_ENGINE_OFF:
		return True;
	case SMB_SIGNING_ENGINE_BSRSPYL:
	case SMB_SIGNING_ENGINE_ON:
	{			
		if (req->in.size < (HDR_SS_FIELD + 8)) {
			return False;
		} else {
			good = check_signed_incoming_message(&req->in, 
							     &req->smb_conn->signing.mac_key, 
							     req->seq_num);
			
			return signing_good(&req->smb_conn->signing, 
					    req->seq_num+1, good);
		}
	}
	}
	return False;
}
