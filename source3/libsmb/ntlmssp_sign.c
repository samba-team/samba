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

static void NTLMSSPcalc_ap( unsigned char *hash, unsigned char *data, int len)
{
    unsigned char index_i = hash[256];
    unsigned char index_j = hash[257];
    int ind;

    for (ind = 0; ind < len; ind++)
    {
        unsigned char tc;
        unsigned char t;

        index_i++;
        index_j += hash[index_i];

        tc = hash[index_i];
        hash[index_i] = hash[index_j];
        hash[index_j] = tc;

        t = hash[index_i] + hash[index_j];
        data[ind] = data[ind] ^ hash[t];
    }

    hash[256] = index_i;
    hash[257] = index_j;
}

static void calc_hash(unsigned char hash[258], const char *k2, int k2l)
{
	unsigned char j = 0;
	int ind;

	for (ind = 0; ind < 256; ind++)
	{
		hash[ind] = (unsigned char)ind;
	}

	for (ind = 0; ind < 256; ind++)
	{
		unsigned char tc;

		j += (hash[ind] + k2[ind%k2l]);

		tc = hash[ind];
		hash[ind] = hash[j];
		hash[j] = tc;
	}

	hash[256] = 0;
	hash[257] = 0;
}

static void calc_ntlmv2_hash(unsigned char hash[258], unsigned char digest[16],
			     DATA_BLOB session_key, 
			     const char *constant)
{
	struct MD5Context ctx3;

	/* NOTE:  This code is currently complate fantasy - it's
	   got more in common with reality than the previous code
	   (the LM session key is not the right thing to use) but
	   it still needs work */

	MD5Init(&ctx3);
	MD5Update(&ctx3, session_key.data, session_key.length);
	MD5Update(&ctx3, (const unsigned char *)constant, strlen(constant)+1);
	MD5Final(digest, &ctx3);

	calc_hash(hash, digest, 16);
}

enum ntlmssp_direction {
	NTLMSSP_SEND,
	NTLMSSP_RECEIVE
};

static NTSTATUS ntlmssp_make_packet_signature(NTLMSSP_STATE *ntlmssp_state,
					      const uchar *data, size_t length, 
					      enum ntlmssp_direction direction,
					      DATA_BLOB *sig) 
{
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		HMACMD5Context ctx;
		uchar seq_num[4];
		uchar digest[16];
		SIVAL(seq_num, 0, ntlmssp_state->ntlmssp_seq_num);

		hmac_md5_init_limK_to_64((const unsigned char *)(ntlmssp_state->send_sign_const), 16, &ctx);
		hmac_md5_update(seq_num, 4, &ctx);
		hmac_md5_update(data, length, &ctx);
		hmac_md5_final(digest, &ctx);

		if (!msrpc_gen(sig, "dBd", NTLMSSP_SIGN_VERSION, digest, 8 /* only copy first 8 bytes */
			       , ntlmssp_state->ntlmssp_seq_num)) {
			return NT_STATUS_NO_MEMORY;
		}

		if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
			switch (direction) {
			case NTLMSSP_SEND:
				NTLMSSPcalc_ap(ntlmssp_state->send_sign_hash,  sig->data+4, sig->length-4);
				break;
			case NTLMSSP_RECEIVE:
				NTLMSSPcalc_ap(ntlmssp_state->recv_sign_hash,  sig->data+4, sig->length-4);
				break;
			}
		}
	} else {
		uint32 crc;
		crc = crc32_calc_buffer((const char *)data, length);
		if (!msrpc_gen(sig, "dddd", NTLMSSP_SIGN_VERSION, 0, crc, ntlmssp_state->ntlmssp_seq_num)) {
			return NT_STATUS_NO_MEMORY;
		}
		
		dump_data_pw("ntlmssp hash:\n", ntlmssp_state->ntlmssp_hash,
			     sizeof(ntlmssp_state->ntlmssp_hash));
		NTLMSSPcalc_ap(ntlmssp_state->ntlmssp_hash, sig->data+4, sig->length-4);
	}
	return NT_STATUS_OK;
}

NTSTATUS ntlmssp_sign_packet(NTLMSSP_STATE *ntlmssp_state,
				    const uchar *data, size_t length, 
				    DATA_BLOB *sig) 
{
	NTSTATUS nt_status;
	if (!ntlmssp_state->session_key.length) {
		DEBUG(3, ("NO session key, cannot check sign packet\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	nt_status = ntlmssp_make_packet_signature(ntlmssp_state, data, length, NTLMSSP_SEND, sig);

	/* increment counter on send */
	ntlmssp_state->ntlmssp_seq_num++;
	return nt_status;
}

/**
 * Check the signature of an incoming packet 
 * @note caller *must* check that the signature is the size it expects 
 *
 */

NTSTATUS ntlmssp_check_packet(NTLMSSP_STATE *ntlmssp_state,
			      const uchar *data, size_t length, 
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

	nt_status = ntlmssp_make_packet_signature(ntlmssp_state, data, 
						  length, NTLMSSP_RECEIVE, &local_sig);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("NTLMSSP packet check failed with %s\n", nt_errstr(nt_status)));
		return nt_status;
	}
	
	if (memcmp(sig->data+sig->length - 8, local_sig.data+local_sig.length - 8, 8) != 0) {
		DEBUG(5, ("BAD SIG: wanted signature of\n"));
		dump_data(5, (const char *)local_sig.data, local_sig.length);
		
		DEBUG(5, ("BAD SIG: got signature of\n"));
		dump_data(5, (const char *)(sig->data), sig->length);

		DEBUG(0, ("NTLMSSP packet check failed due to invalid signature!\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* increment counter on recieive */
	ntlmssp_state->ntlmssp_seq_num++;

	return NT_STATUS_OK;
}


/**
 * Seal data with the NTLMSSP algorithm
 *
 */

NTSTATUS ntlmssp_seal_packet(NTLMSSP_STATE *ntlmssp_state,
			     uchar *data, size_t length,
			     DATA_BLOB *sig)
{	
	if (!ntlmssp_state->session_key.length) {
		DEBUG(3, ("NO session key, cannot seal packet\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	DEBUG(10,("ntlmssp_seal_data: seal\n"));
	dump_data_pw("ntlmssp clear data\n", data, length);
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		HMACMD5Context ctx;
		char seq_num[4];
		uchar digest[16];
		SIVAL(seq_num, 0, ntlmssp_state->ntlmssp_seq_num);

		hmac_md5_init_limK_to_64((const unsigned char *)(ntlmssp_state->send_sign_const), 16, &ctx);
		hmac_md5_update((const unsigned char *)seq_num, 4, &ctx);
		hmac_md5_update(data, length, &ctx);
		hmac_md5_final(digest, &ctx);

		if (!msrpc_gen(sig, "dBd", NTLMSSP_SIGN_VERSION, digest, 8 /* only copy first 8 bytes */
			       , ntlmssp_state->ntlmssp_seq_num)) {
			return NT_STATUS_NO_MEMORY;
		}

		dump_data_pw("ntlmssp client sealing hash:\n", 
			     ntlmssp_state->send_seal_hash,
			     sizeof(ntlmssp_state->send_seal_hash));
		NTLMSSPcalc_ap(ntlmssp_state->send_seal_hash, data, length);
		dump_data_pw("ntlmssp client signing hash:\n", 
			     ntlmssp_state->send_sign_hash,
			     sizeof(ntlmssp_state->send_sign_hash));
		NTLMSSPcalc_ap(ntlmssp_state->send_sign_hash,  sig->data+4, sig->length-4);
	} else {
		uint32 crc;
		crc = crc32_calc_buffer((const char *)data, length);
		if (!msrpc_gen(sig, "dddd", NTLMSSP_SIGN_VERSION, 0, crc, ntlmssp_state->ntlmssp_seq_num)) {
			return NT_STATUS_NO_MEMORY;
		}

		/* The order of these two operations matters - we must first seal the packet,
		   then seal the sequence number - this is becouse the ntlmssp_hash is not
		   constant, but is is rather updated with each iteration */
		
		dump_data_pw("ntlmssp hash:\n", ntlmssp_state->ntlmssp_hash,
			     sizeof(ntlmssp_state->ntlmssp_hash));
		NTLMSSPcalc_ap(ntlmssp_state->ntlmssp_hash, data, length);

		dump_data_pw("ntlmssp hash:\n", ntlmssp_state->ntlmssp_hash,
			     sizeof(ntlmssp_state->ntlmssp_hash));
		NTLMSSPcalc_ap(ntlmssp_state->ntlmssp_hash, sig->data+4, sig->length-4);
	}
	dump_data_pw("ntlmssp sealed data\n", data, length);

	/* increment counter on send */
	ntlmssp_state->ntlmssp_seq_num++;

	return NT_STATUS_OK;
}

/**
 * Unseal data with the NTLMSSP algorithm
 *
 */

NTSTATUS ntlmssp_unseal_packet(NTLMSSP_STATE *ntlmssp_state,
				      uchar *data, size_t length,
				      DATA_BLOB *sig)
{
	if (!ntlmssp_state->session_key.length) {
		DEBUG(3, ("NO session key, cannot unseal packet\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	DEBUG(10,("ntlmssp__unseal_data: seal\n"));
	dump_data_pw("ntlmssp sealed data\n", data, length);
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		NTLMSSPcalc_ap(ntlmssp_state->recv_seal_hash, data, length);
	} else {
		dump_data_pw("ntlmssp hash:\n", ntlmssp_state->ntlmssp_hash,
			     sizeof(ntlmssp_state->ntlmssp_hash));
		NTLMSSPcalc_ap(ntlmssp_state->ntlmssp_hash, data, length);
	}
	dump_data_pw("ntlmssp clear data\n", data, length);

	return ntlmssp_check_packet(ntlmssp_state, data, length, sig);
}

/**
   Initialise the state for NTLMSSP signing.
*/
NTSTATUS ntlmssp_sign_init(NTLMSSP_STATE *ntlmssp_state)
{
	unsigned char p24[24];
	ZERO_STRUCT(p24);

	DEBUG(3, ("NTLMSSP Sign/Seal - Initialising with flags:\n"));
	debug_ntlmssp_flags(ntlmssp_state->neg_flags);

	if (!ntlmssp_state->session_key.length) {
		DEBUG(3, ("NO session key, cannot intialise signing\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2)
	{
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

		calc_ntlmv2_hash(ntlmssp_state->send_sign_hash, 
				 ntlmssp_state->send_sign_const, 
				 ntlmssp_state->session_key, send_sign_const);
		dump_data_pw("NTLMSSP send sign hash:\n", 
			     ntlmssp_state->send_sign_hash, 
			     sizeof(ntlmssp_state->send_sign_hash));

		calc_ntlmv2_hash(ntlmssp_state->send_seal_hash, 
				 ntlmssp_state->send_seal_const, 
				 ntlmssp_state->session_key, send_seal_const);
		dump_data_pw("NTLMSSP send sesl hash:\n", 
			     ntlmssp_state->send_seal_hash, 
			     sizeof(ntlmssp_state->send_seal_hash));

		calc_ntlmv2_hash(ntlmssp_state->recv_sign_hash, 
				 ntlmssp_state->recv_sign_const, 
				 ntlmssp_state->session_key, recv_sign_const);
		dump_data_pw("NTLMSSP receive sign hash:\n", 
			     ntlmssp_state->recv_sign_hash, 
			     sizeof(ntlmssp_state->recv_sign_hash));

		calc_ntlmv2_hash(ntlmssp_state->recv_seal_hash, 
				 ntlmssp_state->recv_seal_const, 
				 ntlmssp_state->session_key, recv_seal_const);
		dump_data_pw("NTLMSSP receive seal hash:\n", 
			     ntlmssp_state->recv_sign_hash, 
			     sizeof(ntlmssp_state->recv_sign_hash));

	} 
	else if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) {
		if (!ntlmssp_state->session_key.data || ntlmssp_state->session_key.length < 8) {
			/* can't sign or check signatures yet */ 
			DEBUG(5, ("NTLMSSP Sign/Seal - cannot use LM KEY yet\n"));	
			return NT_STATUS_UNSUCCESSFUL;
		}
		
		DEBUG(5, ("NTLMSSP Sign/Seal - using LM KEY\n"));

		calc_hash(ntlmssp_state->ntlmssp_hash, (const char *)(ntlmssp_state->session_key.data), 8);
		dump_data_pw("NTLMSSP hash:\n", ntlmssp_state->ntlmssp_hash,
			     sizeof(ntlmssp_state->ntlmssp_hash));
	} else {
		if (!ntlmssp_state->session_key.data || ntlmssp_state->session_key.length < 16) {
			/* can't sign or check signatures yet */ 
			DEBUG(5, ("NTLMSSP Sign/Seal - cannot use NT KEY yet\n"));
			return NT_STATUS_UNSUCCESSFUL;
		}
		
		DEBUG(5, ("NTLMSSP Sign/Seal - using NT KEY\n"));

		calc_hash(ntlmssp_state->ntlmssp_hash, (const char *)(ntlmssp_state->session_key.data), 16);
		dump_data_pw("NTLMSSP hash:\n", ntlmssp_state->ntlmssp_hash,
			     sizeof(ntlmssp_state->ntlmssp_hash));
	}

	ntlmssp_state->ntlmssp_seq_num = 0;

	return NT_STATUS_OK;
}
