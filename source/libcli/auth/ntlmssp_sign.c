/* 
 *  Unix SMB/CIFS implementation.
 *  Version 3.0
 *  NTLMSSP Signing routines
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2001
 *  Copyright (C) Andrew Bartlett 2003
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "includes.h"

#define CLI_SIGN "session key to client-to-server signing key magic constant"
#define CLI_SEAL "session key to client-to-server sealing key magic constant"
#define SRV_SIGN "session key to server-to-client signing key magic constant"
#define SRV_SEAL "session key to server-to-client sealing key magic constant"

/**
 * Some notes on then NTLM2 code:
 *
 * This code works correctly for the sealing part of the problem.  If
 * we disable the check for valid client signatures, then we see that
 * the output of a rpcecho 'sinkdata' at smbd is correct.  We get the
 * valid data, and it is validly decrypted.
 * 
 * This means that the quantity of data passing though the RC4 sealing
 * pad is correct.  
 *
 * This code also correctly matches test values that I have obtained,
 * claiming to be the correct output of NTLM2 signature generation.
 *
 */

static void calc_ntlmv2_key(TALLOC_CTX *mem_ctx, 
			    DATA_BLOB *subkey,
			    DATA_BLOB session_key, 
			    const char *constant)
{
	struct MD5Context ctx3;
	*subkey = data_blob_talloc(mem_ctx, NULL, 16);
	MD5Init(&ctx3);
	MD5Update(&ctx3, session_key.data, session_key.length);
	MD5Update(&ctx3, constant, strlen(constant)+1);
	MD5Final(subkey->data, &ctx3);
}

enum ntlmssp_direction {
	NTLMSSP_SEND,
	NTLMSSP_RECEIVE
};

static NTSTATUS ntlmssp_make_packet_signature(struct ntlmssp_state *ntlmssp_state,
					      TALLOC_CTX *sig_mem_ctx, 
					      const uint8_t *data, size_t length, 
					      const uint8_t *whole_pdu, size_t pdu_length, 
					      enum ntlmssp_direction direction,
					      DATA_BLOB *sig, BOOL encrypt_sig)
{
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {

		HMACMD5Context ctx;
		uint8_t digest[16];
		uint8_t seq_num[4];

		*sig = data_blob_talloc(sig_mem_ctx, NULL, NTLMSSP_SIG_SIZE);
		if (!sig->data) {
			return NT_STATUS_NO_MEMORY;
		}
			
		switch (direction) {
		case NTLMSSP_SEND:
			SIVAL(seq_num, 0, ntlmssp_state->ntlm2_send_seq_num);
			ntlmssp_state->ntlm2_send_seq_num++;
			hmac_md5_init_limK_to_64(ntlmssp_state->send_sign_key.data, 
						 ntlmssp_state->send_sign_key.length, &ctx);
			break;
		case NTLMSSP_RECEIVE:
			SIVAL(seq_num, 0, ntlmssp_state->ntlm2_recv_seq_num);
			ntlmssp_state->ntlm2_recv_seq_num++;
			hmac_md5_init_limK_to_64(ntlmssp_state->recv_sign_key.data, 
						 ntlmssp_state->recv_sign_key.length, &ctx);
			break;
		}
		hmac_md5_update(seq_num, sizeof(seq_num), &ctx);
		hmac_md5_update(whole_pdu, pdu_length, &ctx);
		hmac_md5_final(digest, &ctx);

		if (encrypt_sig && ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
			switch (direction) {
			case NTLMSSP_SEND:
				arcfour_crypt_sbox(ntlmssp_state->send_seal_hash, digest, 8);
				break;
			case NTLMSSP_RECEIVE:
				arcfour_crypt_sbox(ntlmssp_state->recv_seal_hash, digest, 8);
				break;
			}
		}

		SIVAL(sig->data, 0, NTLMSSP_SIGN_VERSION);
		memcpy(sig->data + 4, digest, 8);
		memcpy(sig->data + 12, seq_num, 4);

	} else {
		uint32_t crc;
		crc = crc32_calc_buffer((const char *)data, length);
		if (!msrpc_gen(sig_mem_ctx, sig, "dddd", NTLMSSP_SIGN_VERSION, 0, crc, ntlmssp_state->ntlm_seq_num)) {
			return NT_STATUS_NO_MEMORY;
		}
		ntlmssp_state->ntlm_seq_num++;

		arcfour_crypt_sbox(ntlmssp_state->ntlmssp_hash, sig->data+4, sig->length-4);
	}
	dump_data_pw("calculated ntlmssp signature\n", sig->data, sig->length);
	return NT_STATUS_OK;
}

NTSTATUS ntlmssp_sign_packet(struct ntlmssp_state *ntlmssp_state,
			     TALLOC_CTX *sig_mem_ctx, 
			     const uint8_t *data, size_t length, 
			     const uint8_t *whole_pdu, size_t pdu_length, 
			     DATA_BLOB *sig) 
{
	if (!ntlmssp_state->session_key.length) {
		DEBUG(3, ("NO session key, cannot check sign packet\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}
	
	if (!ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SIGN) {
		DEBUG(3, ("NTLMSSP Signing not negotiated - cannot sign packet!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	return ntlmssp_make_packet_signature(ntlmssp_state, sig_mem_ctx, 
					     data, length, 
					     whole_pdu, pdu_length, 
					     NTLMSSP_SEND, sig, True);
}

/**
 * Check the signature of an incoming packet 
 *
 */

NTSTATUS ntlmssp_check_packet(struct ntlmssp_state *ntlmssp_state,
			      TALLOC_CTX *sig_mem_ctx, 
			      const uint8_t *data, size_t length, 
			      const uint8_t *whole_pdu, size_t pdu_length, 
			      const DATA_BLOB *sig) 
{
	DATA_BLOB local_sig;
	NTSTATUS nt_status;

	if (!ntlmssp_state->session_key.length) {
		DEBUG(3, ("NO session key, cannot check packet signature\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (sig->length < 8) {
		DEBUG(0, ("NTLMSSP packet check failed due to short signature (%lu bytes)!\n", 
			  (unsigned long)sig->length));
	}

	nt_status = ntlmssp_make_packet_signature(ntlmssp_state, sig_mem_ctx, 
						  data, length, 
						  whole_pdu, pdu_length, 
						  NTLMSSP_RECEIVE, &local_sig, True);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("NTLMSSP packet check failed with %s\n", nt_errstr(nt_status)));
		return nt_status;
	}

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		if (local_sig.length != sig->length ||
		    memcmp(local_sig.data, 
			   sig->data, sig->length) != 0) {
			DEBUG(5, ("BAD SIG NTLM2: wanted signature of\n"));
			dump_data(5, local_sig.data, local_sig.length);
			
			DEBUG(5, ("BAD SIG: got signature of\n"));
			dump_data(5, sig->data, sig->length);
			
			DEBUG(0, ("NTLMSSP NTLM2 packet check failed due to invalid signature!\n"));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else {
		if (local_sig.length != sig->length ||
		    memcmp(local_sig.data + 8, 
			   sig->data + 8, sig->length - 8) != 0) {
			DEBUG(5, ("BAD SIG NTLM1: wanted signature of\n"));
			dump_data(5, (const char *)local_sig.data, local_sig.length);
			
			DEBUG(5, ("BAD SIG: got signature of\n"));
			dump_data(5, (const char *)(sig->data), sig->length);
			
			DEBUG(0, ("NTLMSSP NTLM1 packet check failed due to invalid signature!\n"));
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	dump_data_pw("checked ntlmssp signature\n", sig->data, sig->length);

	return NT_STATUS_OK;
}


/**
 * Seal data with the NTLMSSP algorithm
 *
 */

NTSTATUS ntlmssp_seal_packet(struct ntlmssp_state *ntlmssp_state,
			     TALLOC_CTX *sig_mem_ctx, 
			     uint8_t *data, size_t length,
			     const uint8_t *whole_pdu, size_t pdu_length, 
			     DATA_BLOB *sig)
{	
	NTSTATUS nt_status;
	if (!ntlmssp_state->session_key.length) {
		DEBUG(3, ("NO session key, cannot seal packet\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (!ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SEAL) {
		DEBUG(3, ("NTLMSSP Sealing not negotiated - cannot seal packet!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(10,("ntlmssp_seal_data: seal\n"));
	dump_data_pw("ntlmssp clear data\n", data, length);
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		/* The order of these two operations matters - we must first seal the packet,
		   then seal the sequence number - this is becouse the send_seal_hash is not
		   constant, but is is rather updated with each iteration */
		nt_status = ntlmssp_make_packet_signature(ntlmssp_state, sig_mem_ctx, 
							  data, length, 
							  whole_pdu, pdu_length, 
							  NTLMSSP_SEND, sig, False);
		arcfour_crypt_sbox(ntlmssp_state->send_seal_hash, data, length);
		if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
			arcfour_crypt_sbox(ntlmssp_state->send_seal_hash, sig->data+4, 8);
		}
	} else {
		uint32_t crc;
		crc = crc32_calc_buffer((const char *)data, length);
		if (!msrpc_gen(sig_mem_ctx, sig, "dddd", NTLMSSP_SIGN_VERSION, 0, crc, ntlmssp_state->ntlm_seq_num)) {
			return NT_STATUS_NO_MEMORY;
		}

		/* The order of these two operations matters - we must
		   first seal the packet, then seal the sequence
		   number - this is becouse the ntlmssp_hash is not
		   constant, but is is rather updated with each
		   iteration */

		arcfour_crypt_sbox(ntlmssp_state->ntlmssp_hash, data, length);
		arcfour_crypt_sbox(ntlmssp_state->ntlmssp_hash, sig->data+4, sig->length-4);
		/* increment counter on send */
		ntlmssp_state->ntlm_seq_num++;
		nt_status = NT_STATUS_OK;
	}
	dump_data_pw("ntlmssp signature\n", sig->data, sig->length);
	dump_data_pw("ntlmssp sealed data\n", data, length);


	return nt_status;
}

/**
 * Unseal data with the NTLMSSP algorithm
 *
 */

NTSTATUS ntlmssp_unseal_packet(struct ntlmssp_state *ntlmssp_state,
			       TALLOC_CTX *sig_mem_ctx, 
			       uint8_t *data, size_t length,
			       const uint8_t *whole_pdu, size_t pdu_length, 
			       DATA_BLOB *sig)
{
	DATA_BLOB local_sig;
	NTSTATUS nt_status;
	if (!ntlmssp_state->session_key.length) {
		DEBUG(3, ("NO session key, cannot unseal packet\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	dump_data_pw("ntlmssp sealed data\n", data, length);
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		arcfour_crypt_sbox(ntlmssp_state->recv_seal_hash, data, length);

		nt_status = ntlmssp_make_packet_signature(ntlmssp_state, sig_mem_ctx, 
							  data, length, 
							  whole_pdu, pdu_length, 
							  NTLMSSP_RECEIVE, &local_sig, True);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		if (local_sig.length != sig->length ||
		    memcmp(local_sig.data, 
			   sig->data, sig->length) != 0) {
			DEBUG(5, ("BAD SIG NTLM2: wanted signature of\n"));
			dump_data(5, local_sig.data, local_sig.length);
			
			DEBUG(5, ("BAD SIG: got signature of\n"));
			dump_data(5, sig->data, sig->length);
			
			DEBUG(0, ("NTLMSSP NTLM2 packet check failed due to invalid signature!\n"));
			return NT_STATUS_ACCESS_DENIED;
		}

		dump_data_pw("ntlmssp clear data\n", data, length);
		return NT_STATUS_OK;
	} else {
		arcfour_crypt_sbox(ntlmssp_state->ntlmssp_hash, data, length);
		dump_data_pw("ntlmssp clear data\n", data, length);
		return ntlmssp_check_packet(ntlmssp_state, sig_mem_ctx, data, length, whole_pdu, pdu_length, sig);
	}
}

/**
   Initialise the state for NTLMSSP signing.
*/
NTSTATUS ntlmssp_sign_init(struct ntlmssp_state *ntlmssp_state)
{
	uint8_t p24[24];
	ZERO_STRUCT(p24);

	DEBUG(3, ("NTLMSSP Sign/Seal - Initialising with flags:\n"));
	debug_ntlmssp_flags(ntlmssp_state->neg_flags);

	if (!ntlmssp_state->session_key.length) {
		DEBUG(3, ("NO session key, cannot intialise signing\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2)
	{
		DATA_BLOB weak_session_key = ntlmssp_state->session_key;
		const char *send_sign_const;
		const char *send_seal_const;
		const char *recv_sign_const;
		const char *recv_seal_const;

		switch (ntlmssp_state->role) {
		case NTLMSSP_CLIENT:
			send_sign_const = CLI_SIGN;
			send_seal_const = CLI_SEAL;
			recv_sign_const = SRV_SIGN;
			recv_seal_const = SRV_SEAL;
			break;
		case NTLMSSP_SERVER:
			send_sign_const = SRV_SIGN;
			send_seal_const = SRV_SEAL;
			recv_sign_const = CLI_SIGN;
			recv_seal_const = CLI_SEAL;
			break;
		}
		
		/**
		   Weaken NTLMSSP keys to cope with down-level clients, servers and export restrictions.
		   
		   We probably should have some parameters to control this, once we get NTLM2 working.
		*/


		if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_128) {
			
		} else if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_56) {
			weak_session_key.length = 6;
		} else { /* forty bits */
			weak_session_key.length = 5;
		}
		dump_data_pw("NTLMSSP weakend master key:\n",
			     weak_session_key.data, 
			     weak_session_key.length);

		/* SEND */
		calc_ntlmv2_key(ntlmssp_state->mem_ctx, 
				&ntlmssp_state->send_sign_key, 
				ntlmssp_state->session_key, send_sign_const);
		dump_data_pw("NTLMSSP send sign key:\n",
			     ntlmssp_state->send_sign_key.data, 
			     ntlmssp_state->send_sign_key.length);
		
		calc_ntlmv2_key(ntlmssp_state->mem_ctx, 
				&ntlmssp_state->send_seal_key, 
				weak_session_key, send_seal_const);
		dump_data_pw("NTLMSSP send seal key:\n",
			     ntlmssp_state->send_seal_key.data, 
			     ntlmssp_state->send_seal_key.length);

		arcfour_init(ntlmssp_state->send_seal_hash, 
			     &ntlmssp_state->send_seal_key);

		dump_data_pw("NTLMSSP send sesl hash:\n", 
			     ntlmssp_state->send_seal_hash, 
			     sizeof(ntlmssp_state->send_seal_hash));

		/* RECV */
		calc_ntlmv2_key(ntlmssp_state->mem_ctx, 
				&ntlmssp_state->recv_sign_key, 
				ntlmssp_state->session_key, recv_sign_const);
		dump_data_pw("NTLMSSP recv sign key:\n",
			     ntlmssp_state->recv_sign_key.data, 
			     ntlmssp_state->recv_sign_key.length);

		calc_ntlmv2_key(ntlmssp_state->mem_ctx, 
				&ntlmssp_state->recv_seal_key, 
				weak_session_key, recv_seal_const);
		dump_data_pw("NTLMSSP recv seal key:\n",
			     ntlmssp_state->recv_seal_key.data, 
			     ntlmssp_state->recv_seal_key.length);
		arcfour_init(ntlmssp_state->recv_seal_hash, 
			     &ntlmssp_state->recv_seal_key);

		dump_data_pw("NTLMSSP receive seal hash:\n", 
			     ntlmssp_state->recv_seal_hash, 
			     sizeof(ntlmssp_state->recv_seal_hash));
	} else {
		DEBUG(5, ("NTLMSSP Sign/Seal - using NTLM1\n"));

		arcfour_init(ntlmssp_state->ntlmssp_hash, 
			     &ntlmssp_state->session_key);
		dump_data_pw("NTLMSSP hash:\n", ntlmssp_state->ntlmssp_hash,
			     sizeof(ntlmssp_state->ntlmssp_hash));
	}

	ntlmssp_state->ntlm_seq_num = 0;
	ntlmssp_state->ntlm2_send_seq_num = 0;
	ntlmssp_state->ntlm2_recv_seq_num = 0;

	return NT_STATUS_OK;
}
