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

struct smb_basic_signing_context {
	DATA_BLOB mac_key;
	uint32_t next_seq_num;
};

/***********************************************************
 SMB signing - Common code before we set a new signing implementation
************************************************************/
static BOOL set_smb_signing_common(struct cli_transport *transport)
{
	if (!(transport->negotiate.sec_mode & 
	      (NEGOTIATE_SECURITY_SIGNATURES_REQUIRED|NEGOTIATE_SECURITY_SIGNATURES_ENABLED))) {
		return False;
	}

	if (transport->negotiate.sign_info.doing_signing) {
		return False;
	}

	if (!transport->negotiate.sign_info.allow_smb_signing) {
		return False;
	}

	if (transport->negotiate.sign_info.free_signing_context)
		transport->negotiate.sign_info.free_signing_context(transport);

	/* These calls are INCOMPATIBLE with SMB signing */
	transport->negotiate.readbraw_supported = False;
	transport->negotiate.writebraw_supported = False;

	return True;
}

/***********************************************************
 SMB signing - Common code for 'real' implementations
************************************************************/
static BOOL set_smb_signing_real_common(struct cli_transport *transport) 
{
	if (transport->negotiate.sign_info.mandatory_signing) {
		DEBUG(5, ("Mandatory SMB signing enabled!\n"));
	}

	DEBUG(5, ("SMB signing enabled!\n"));

	return True;
}

static void mark_packet_signed(struct request_buffer *out) 
{
	uint16_t flags2;
	flags2 = SVAL(out->hdr, HDR_FLG2);
	flags2 |= FLAGS2_SMB_SECURITY_SIGNATURES;
	SSVAL(out->hdr, HDR_FLG2, flags2);
}

static BOOL signing_good(struct cli_request *req, unsigned int seq, BOOL good) 
{
	if (good) {
		if (!req->transport->negotiate.sign_info.doing_signing) {
			req->transport->negotiate.sign_info.doing_signing = True;
		}
		if (!req->transport->negotiate.sign_info.seen_valid) {
			req->transport->negotiate.sign_info.seen_valid = True;
		}
	} else {
		if (!req->transport->negotiate.sign_info.seen_valid) {
			/* If we have never seen a good packet, just turn it off */
			DEBUG(5, ("signing_good: signing negotiated but not required and peer\n"
				  "isn't sending correct signatures. Turning off.\n"));
			req->transport->negotiate.sign_info.negotiated_smb_signing = False;
			req->transport->negotiate.sign_info.allow_smb_signing = False;
			req->transport->negotiate.sign_info.doing_signing = False;
			if (req->transport->negotiate.sign_info.free_signing_context)
				req->transport->negotiate.sign_info.free_signing_context(req->transport);
			cli_null_set_signing(req->transport);
			return True;
		} else {
			/* bad packet after signing started - fail and disconnect. */
			DEBUG(0, ("signing_good: BAD SIG: seq %u\n", seq));
			return False;
		}
	}
	return True;
}

void sign_outgoing_message(struct request_buffer *out, DATA_BLOB *mac_key, uint_t seq_num) 
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
	MD5Update(&md5_ctx, mac_key->data, 
		  mac_key->length); 
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
	uint8_t server_sent_mac[8];
	uint8_t sequence_buf[8];
	struct MD5Context md5_ctx;
	const size_t offset_end_of_sig = (HDR_SS_FIELD + 8);
	int i;
	const int sign_range = 0;

	/* room enough for the signature? */
	if (in->size < NBT_HDR_SIZE + HDR_SS_FIELD + 8) {
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
		memcpy(server_sent_mac, &in->hdr[HDR_SS_FIELD], sizeof(server_sent_mac));
		
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

/***********************************************************
 SMB signing - Simple implementation - calculate a MAC to send.
************************************************************/
static void cli_request_simple_sign_outgoing_message(struct cli_request *req)
{
	struct smb_basic_signing_context *data = req->transport->negotiate.sign_info.signing_context;

#if 0
	/* enable this when packet signing is preventing you working out why valgrind 
	   says that data is uninitialised */
	file_save("pkt.dat", req->out.buffer, req->out.size);
#endif

	req->seq_num = data->next_seq_num;
	
	/* some requests (eg. NTcancel) are one way, and the sequence number
	   should be increased by 1 not 2 */
	if (req->one_way_request) {
		data->next_seq_num += 1;
	} else {
		data->next_seq_num += 2;
	}
	
	sign_outgoing_message(&req->out, &data->mac_key, req->seq_num);
}


/***********************************************************
 SMB signing - Simple implementation - check a MAC sent by server.
************************************************************/
static BOOL cli_request_simple_check_incoming_message(struct cli_request *req)
{
	struct smb_basic_signing_context *data 
		= req->transport->negotiate.sign_info.signing_context;

	BOOL good = check_signed_incoming_message(&req->in, 
						  &data->mac_key, 
						  req->seq_num+1);
						  
	return signing_good(req, req->seq_num+1, good);
}


/***********************************************************
 SMB signing - Simple implementation - free signing context
************************************************************/
static void cli_transport_simple_free_signing_context(struct cli_transport *transport)
{
	struct smb_basic_signing_context *data = transport->negotiate.sign_info.signing_context;

	data_blob_free(&data->mac_key);
	SAFE_FREE(transport->negotiate.sign_info.signing_context);

	return;
}


/***********************************************************
 SMB signing - Simple implementation - setup the MAC key.
************************************************************/
BOOL cli_transport_simple_set_signing(struct cli_transport *transport,
				      const DATA_BLOB user_session_key, 
				      const DATA_BLOB response)
{
	struct smb_basic_signing_context *data;

	if (!set_smb_signing_common(transport)) {
		return False;
	}

	if (!set_smb_signing_real_common(transport)) {
		return False;
	}

	data = smb_xmalloc(sizeof(*data));
	transport->negotiate.sign_info.signing_context = data;
	
	data->mac_key = data_blob(NULL, response.length + user_session_key.length);

	memcpy(&data->mac_key.data[0], user_session_key.data, user_session_key.length);

	if (response.length) {
		memcpy(&data->mac_key.data[user_session_key.length],response.data, response.length);
	}

	dump_data_pw("Started Signing with key:\n", data->mac_key.data, data->mac_key.length);

	/* Initialise the sequence number */
	data->next_seq_num = 0;

	transport->negotiate.sign_info.sign_outgoing_message = cli_request_simple_sign_outgoing_message;
	transport->negotiate.sign_info.check_incoming_message = cli_request_simple_check_incoming_message;
	transport->negotiate.sign_info.free_signing_context = cli_transport_simple_free_signing_context;

	return True;
}


/***********************************************************
 SMB signing - NULL implementation - calculate a MAC to send.
************************************************************/
static void cli_request_null_sign_outgoing_message(struct cli_request *req)
{
	/* we can't zero out the sig, as we might be trying to send a
	   transport request - which is NBT-level, not SMB level and doesn't
	   have the field */
}


/***********************************************************
 SMB signing - NULL implementation - check a MAC sent by server.
************************************************************/
static BOOL cli_request_null_check_incoming_message(struct cli_request *req)
{
	return True;
}


/***********************************************************
 SMB signing - NULL implementation - free signing context
************************************************************/
static void cli_null_free_signing_context(struct cli_transport *transport)
{
}

/**
 SMB signing - NULL implementation - setup the MAC key.

 @note Used as an initialisation only - it will not correctly
       shut down a real signing mechanism
*/
BOOL cli_null_set_signing(struct cli_transport *transport)
{
	transport->negotiate.sign_info.signing_context = NULL;
	
	transport->negotiate.sign_info.sign_outgoing_message = cli_request_null_sign_outgoing_message;
	transport->negotiate.sign_info.check_incoming_message = cli_request_null_check_incoming_message;
	transport->negotiate.sign_info.free_signing_context = cli_null_free_signing_context;

	return True;
}

/***********************************************************
 SMB signing - TEMP implementation - calculate a MAC to send.
************************************************************/
static void cli_request_temp_sign_outgoing_message(struct cli_request *req)
{
	/* mark the packet as signed - BEFORE we sign it...*/
	mark_packet_signed(&req->out);

	/* I wonder what BSRSPYL stands for - but this is what MS 
	   actually sends! */
	memcpy((req->out.hdr + HDR_SS_FIELD), "BSRSPYL ", 8);

	return;
}

/***********************************************************
 SMB signing - TEMP implementation - check a MAC sent by server.
************************************************************/
static BOOL cli_request_temp_check_incoming_message(struct cli_request *req)
{
	return True;
}

/***********************************************************
 SMB signing - NULL implementation - free signing context
************************************************************/
static void cli_temp_free_signing_context(struct cli_transport *transport)
{
	return;
}

/**
 SMB signing - TEMP implementation - setup the MAC key.

 @note Used as an initialisation only - it will not correctly
       shut down a real signing mechanism
*/
BOOL cli_temp_set_signing(struct cli_transport *transport)
{
	if (!set_smb_signing_common(transport)) {
		return False;
	}

	transport->negotiate.sign_info.signing_context = NULL;
	
	transport->negotiate.sign_info.sign_outgoing_message = cli_request_temp_sign_outgoing_message;
	transport->negotiate.sign_info.check_incoming_message = cli_request_temp_check_incoming_message;
	transport->negotiate.sign_info.free_signing_context = cli_temp_free_signing_context;

	return True;
}

/**
 * Free the signing context
 */
void cli_transport_free_signing_context(struct cli_transport *transport) 
{
	if (transport->negotiate.sign_info.free_signing_context) {
		transport->negotiate.sign_info.free_signing_context(transport);
	}

	cli_null_set_signing(transport);
}


/**
 * Sign a packet with the current mechanism
 */
void cli_request_calculate_sign_mac(struct cli_request *req)
{
	req->transport->negotiate.sign_info.sign_outgoing_message(req);
}


/**
 * Check a packet with the current mechanism
 * @return False if we had an established signing connection
 *         which had a back checksum, True otherwise
 */
BOOL cli_request_check_sign_mac(struct cli_request *req) 
{
	BOOL good;

	if (req->in.size < (HDR_SS_FIELD + 8)) {
		good = False;
	} else {
		good = req->transport->negotiate.sign_info.check_incoming_message(req);
	}

	if (!good && req->transport->negotiate.sign_info.doing_signing) {
		return False;
	}

	return True;
}


BOOL cli_init_signing(struct cli_transport *transport) 
{
	if (!cli_null_set_signing(transport)) {
		return False;
	}
	
	switch (lp_client_signing()) {
	case SMB_SIGNING_OFF:
	transport->negotiate.sign_info.allow_smb_signing = False;
		break;
	case SMB_SIGNING_SUPPORTED:
		transport->negotiate.sign_info.allow_smb_signing = True;
		break;
	case SMB_SIGNING_REQUIRED:
		transport->negotiate.sign_info.allow_smb_signing = True;
		transport->negotiate.sign_info.mandatory_signing = True;
		break;
	}
	return True;
}
