/* 
   Unix SMB/CIFS implementation.
   SMB Signing Code
   Copyright (C) Jeremy Allison 2002.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003
   Copyright (C) James J Myers <myersjj@samba.org> 2003
   
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
#include "smb.h"
#include "libcli/raw/libcliraw.h"
#include "lib/crypto/crypto.h"

/***********************************************************
 SMB signing - Common code before we set a new signing implementation
************************************************************/
BOOL set_smb_signing_common(struct smb_signing_context *sign_info)
{
	if (sign_info->doing_signing) {
		DEBUG(5, ("SMB Signing already in progress, so we don't start it again\n"));
		return False;
	}

	if (!sign_info->allow_smb_signing) {
		DEBUG(5, ("SMB Signing has been locally disabled\n"));
		return False;
	}

	return True;
}

/***********************************************************
 SMB signing - Common code before we set a new signing implementation
************************************************************/
static BOOL smbcli_set_smb_signing_common(struct smbcli_transport *transport)
{
	if (!set_smb_signing_common(&transport->negotiate.sign_info)) {
		return False;
	}

	if (!(transport->negotiate.sec_mode & 
	      (NEGOTIATE_SECURITY_SIGNATURES_REQUIRED|NEGOTIATE_SECURITY_SIGNATURES_ENABLED))) {
		DEBUG(5, ("SMB Signing is not negotiated by the peer\n"));
		return False;
	}

	/* These calls are INCOMPATIBLE with SMB signing */
	transport->negotiate.readbraw_supported = False;
	transport->negotiate.writebraw_supported = False;

	return True;
}

void mark_packet_signed(struct request_buffer *out) 
{
	uint16_t flags2;
	flags2 = SVAL(out->hdr, HDR_FLG2);
	flags2 |= FLAGS2_SMB_SECURITY_SIGNATURES;
	SSVAL(out->hdr, HDR_FLG2, flags2);
}

BOOL signing_good(struct smb_signing_context *sign_info, 
			 unsigned int seq, BOOL good) 
{
	if (good) {
		if (!sign_info->doing_signing) {
			DEBUG(5, ("Seen valid packet, so turning signing on\n"));
			sign_info->doing_signing = True;
		}
		if (!sign_info->seen_valid) {
			DEBUG(5, ("Seen valid packet, so marking signing as 'seen valid'\n"));
			sign_info->seen_valid = True;
		}
	} else {
		if (!sign_info->seen_valid) {
			/* If we have never seen a good packet, just turn it off */
			DEBUG(5, ("signing_good: signing negotiated but not required and peer\n"
				  "isn't sending correct signatures. Turning off.\n"));
			smbcli_set_signing_off(sign_info);
			return True;
		} else {
			/* bad packet after signing started - fail and disconnect. */
			DEBUG(0, ("signing_good: BAD SIG: seq %u\n", seq));
			return False;
		}
	}
	return True;
}

void sign_outgoing_message(struct request_buffer *out, DATA_BLOB *mac_key, unsigned int seq_num) 
{
	uint8_t calc_md5_mac[16];
	struct MD5Context md5_ctx;

	/*
	 * Firstly put the sequence number into the first 4 bytes.
	 * and zero out the next 4 bytes.
	 */
	SIVAL(out->hdr, HDR_SS_FIELD, seq_num);
	SIVAL(out->hdr, HDR_SS_FIELD + 4, 0);

	/* mark the packet as signed - BEFORE we sign it...*/
	mark_packet_signed(out);

	/* Calculate the 16 byte MAC and place first 8 bytes into the field. */
	MD5Init(&md5_ctx);
        MD5Update(&md5_ctx, mac_key->data, mac_key->length);
	MD5Update(&md5_ctx, 
		  out->buffer + NBT_HDR_SIZE, 
		  out->size - NBT_HDR_SIZE);
	MD5Final(calc_md5_mac, &md5_ctx);

	memcpy(&out->hdr[HDR_SS_FIELD], calc_md5_mac, 8);

	DEBUG(5, ("sign_outgoing_message: SENT SIG (seq: %d): sent SMB signature of\n", 
		  seq_num));
	dump_data(5, calc_md5_mac, 8);
/*	req->out.hdr[HDR_SS_FIELD+2]=0; 
	Uncomment this to test if the remote server actually verifies signitures...*/
}

BOOL check_signed_incoming_message(struct request_buffer *in, DATA_BLOB *mac_key, uint_t seq_num) 
{
	BOOL good;
	uint8_t calc_md5_mac[16];
	uint8_t *server_sent_mac;
	uint8_t sequence_buf[8];
	struct MD5Context md5_ctx;
	const size_t offset_end_of_sig = (HDR_SS_FIELD + 8);
	int i;
	const int sign_range = 0;

	/* room enough for the signature? */
	if (in->size < NBT_HDR_SIZE + HDR_SS_FIELD + 8) {
		return False;
	}

	if (!mac_key->length) {
		/* NO key yet */
		return False;
	}

	/* its quite bogus to be guessing sequence numbers, but very useful
	   when debugging signing implementations */
	for (i = 0-sign_range; i <= 0+sign_range; i++) {
		/*
		 * Firstly put the sequence number into the first 4 bytes.
		 * and zero out the next 4 bytes.
		 */
		SIVAL(sequence_buf, 0, seq_num + i);
		SIVAL(sequence_buf, 4, 0);
		
		/* get a copy of the server-sent mac */
	        server_sent_mac = &in->hdr[HDR_SS_FIELD];
		
		/* Calculate the 16 byte MAC and place first 8 bytes into the field. */
		MD5Init(&md5_ctx);
		MD5Update(&md5_ctx, mac_key->data, 
			  mac_key->length); 
		MD5Update(&md5_ctx, in->hdr, HDR_SS_FIELD);
		MD5Update(&md5_ctx, sequence_buf, sizeof(sequence_buf));
		
		MD5Update(&md5_ctx, in->hdr + offset_end_of_sig, 
			  in->size - NBT_HDR_SIZE - (offset_end_of_sig));
		MD5Final(calc_md5_mac, &md5_ctx);
		
		good = (memcmp(server_sent_mac, calc_md5_mac, 8) == 0);

		if (i == 0) {
			if (!good) {
				DEBUG(5, ("check_signed_incoming_message: BAD SIG (seq: %d): wanted SMB signature of\n", seq_num + i));
				dump_data(5, calc_md5_mac, 8);
				
				DEBUG(5, ("check_signed_incoming_message: BAD SIG (seq: %d): got SMB signature of\n", seq_num + i));
				dump_data(5, server_sent_mac, 8);
			} else {
				DEBUG(15, ("check_signed_incoming_message: GOOD SIG (seq: %d): got SMB signature of\n", seq_num + i));
				dump_data(5, server_sent_mac, 8);
			}
		}

		if (good) break;
	}

	if (good && i != 0) {
		DEBUG(0,("SIGNING OFFSET %d (should be %d)\n", i, seq_num));
	}

	return good;
}

static void smbcli_req_allocate_seq_num(struct smbcli_request *req) 
{
	req->seq_num = req->transport->negotiate.sign_info.next_seq_num;
	
	/* some requests (eg. NTcancel) are one way, and the sequence number
	   should be increased by 1 not 2 */
	if (req->sign_single_increment) {
		req->transport->negotiate.sign_info.next_seq_num += 1;
	} else {
		req->transport->negotiate.sign_info.next_seq_num += 2;
	}
}

/***********************************************************
 SMB signing - Simple implementation - calculate a MAC to send.
************************************************************/
void smbcli_request_calculate_sign_mac(struct smbcli_request *req)
{
#if 0
	/* enable this when packet signing is preventing you working out why valgrind 
	   says that data is uninitialised */
	file_save("pkt.dat", req->out.buffer, req->out.size);
#endif

	switch (req->transport->negotiate.sign_info.signing_state) {
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
			
		smbcli_req_allocate_seq_num(req);
		sign_outgoing_message(&req->out, 
				      &req->transport->negotiate.sign_info.mac_key, 
				      req->seq_num);
		break;
	}
	return;
}


/**
 SMB signing - NULL implementation

 @note Used as an initialisation only - it will not correctly
       shut down a real signing mechanism
*/
BOOL smbcli_set_signing_off(struct smb_signing_context *sign_info)
{
	DEBUG(5, ("Shutdown SMB signing\n"));
	sign_info->doing_signing = False;
	sign_info->next_seq_num = 0;
	data_blob_free(&sign_info->mac_key);
	sign_info->signing_state = SMB_SIGNING_ENGINE_OFF;
	return True;
}

/**
 SMB signing - TEMP implementation - setup the MAC key.

*/
BOOL smbcli_temp_set_signing(struct smbcli_transport *transport)
{
	if (!smbcli_set_smb_signing_common(transport)) {
		return False;
	}
	DEBUG(5, ("BSRSPYL SMB signing enabled\n"));
	smbcli_set_signing_off(&transport->negotiate.sign_info);

	transport->negotiate.sign_info.mac_key = data_blob(NULL, 0);
	transport->negotiate.sign_info.signing_state = SMB_SIGNING_ENGINE_BSRSPYL;

	return True;
}

/***********************************************************
 SMB signing - Simple implementation - check a MAC sent by server.
************************************************************/
/**
 * Check a packet supplied by the server.
 * @return False if we had an established signing connection
 *         which had a back checksum, True otherwise
 */
BOOL smbcli_request_check_sign_mac(struct smbcli_request *req) 
{
	BOOL good;

	switch (req->transport->negotiate.sign_info.signing_state) 
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
							     &req->transport->negotiate.sign_info.mac_key, 
							     req->seq_num+1);
			
			return signing_good(&req->transport->negotiate.sign_info, 
					    req->seq_num+1, good);
		}
	}
	}
	return False;
}


/***********************************************************
 SMB signing - Simple implementation - setup the MAC key.
************************************************************/
BOOL smbcli_simple_set_signing(TALLOC_CTX *mem_ctx,
			       struct smb_signing_context *sign_info,
			       const DATA_BLOB *user_session_key, 
			       const DATA_BLOB *response)
{
	if (sign_info->mandatory_signing) {
		DEBUG(5, ("Mandatory SMB signing enabled!\n"));
	}

	DEBUG(5, ("SMB signing enabled!\n"));

	if (response && response->length) {
		sign_info->mac_key = data_blob_talloc(mem_ctx, NULL, response->length + user_session_key->length);
	} else {
		sign_info->mac_key = data_blob_talloc(mem_ctx, NULL, user_session_key->length);
	}
		
	memcpy(&sign_info->mac_key.data[0], user_session_key->data, user_session_key->length);

	if (response && response->length) {
		memcpy(&sign_info->mac_key.data[user_session_key->length],response->data, response->length);
	}

	dump_data_pw("Started Signing with key:\n", sign_info->mac_key.data, sign_info->mac_key.length);

	/* Initialise the sequence number */
	sign_info->next_seq_num = 0;

	sign_info->signing_state = SMB_SIGNING_ENGINE_ON;

	return True;
}


/***********************************************************
 SMB signing - Simple implementation - setup the MAC key.
************************************************************/
BOOL smbcli_transport_simple_set_signing(struct smbcli_transport *transport,
					 const DATA_BLOB user_session_key, 
					 const DATA_BLOB response)
{
	if (!smbcli_set_smb_signing_common(transport)) {
		return False;
	}

	return smbcli_simple_set_signing(transport,
					 &transport->negotiate.sign_info,
					 &user_session_key,
					 &response);
}


BOOL smbcli_init_signing(struct smbcli_transport *transport) 
{
	transport->negotiate.sign_info.mac_key = data_blob(NULL, 0);
	if (!smbcli_set_signing_off(&transport->negotiate.sign_info)) {
		return False;
	}
	
	switch (lp_client_signing()) {
	case SMB_SIGNING_OFF:
		transport->negotiate.sign_info.allow_smb_signing = False;
		break;
	case SMB_SIGNING_SUPPORTED:
	case SMB_SIGNING_AUTO:
		transport->negotiate.sign_info.allow_smb_signing = True;
		break;
	case SMB_SIGNING_REQUIRED:
		transport->negotiate.sign_info.allow_smb_signing = True;
		transport->negotiate.sign_info.mandatory_signing = True;
		break;
	}
	return True;
}
