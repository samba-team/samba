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

static void calc_hash(unsigned char *hash, const char *k2, int k2l)
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

static void calc_ntlmv2_hash(unsigned char hash[16], char digest[16],
			     const char encrypted_response[16], 
			     const char *constant)
{
	struct MD5Context ctx3;

	MD5Init(&ctx3);
	MD5Update(&ctx3, encrypted_response, 5);
	MD5Update(&ctx3, constant, strlen(constant));
	MD5Final(digest, &ctx3);

	calc_hash(hash, digest, 16);
}

static NTSTATUS ntlmssp_make_packet_signiture(NTLMSSP_CLIENT_STATE *ntlmssp_state,
					      const uchar *data, size_t length, 
					      DATA_BLOB *sig) 
{
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		HMACMD5Context ctx;
		char seq_num[4];
		uchar digest[16];
		SIVAL(seq_num, 0, &ntlmssp_state->ntlmssp_seq_num);

		hmac_md5_init_limK_to_64(ntlmssp_state->cli_sign_const, 16, &ctx);
		hmac_md5_update(seq_num, 4, &ctx);
		hmac_md5_update(data, length, &ctx);
		hmac_md5_final(digest, &ctx);

		if (!msrpc_gen(sig, "Bd", digest, sizeof(digest), ntlmssp_state->ntlmssp_seq_num)) {
			return NT_STATUS_NO_MEMORY;
		}
	       
		NTLMSSPcalc_ap(ntlmssp_state->cli_seal_hash,  sig->data, sig->length);
	} else {
		uint32 crc;
		crc = crc32_calc_buffer(data, length);
		if (!msrpc_gen(sig, "ddd", 0, crc, ntlmssp_state->ntlmssp_seq_num)) {
			return NT_STATUS_NO_MEMORY;
		}
		
		NTLMSSPcalc_ap(ntlmssp_state->ntlmssp_hash, sig->data, sig->length);
	}
	return NT_STATUS_OK;
}

NTSTATUS ntlmssp_client_sign_packet(NTLMSSP_CLIENT_STATE *ntlmssp_state,
					   const uchar *data, size_t length, 
					   DATA_BLOB *sig) 
{
	ntlmssp_state->ntlmssp_seq_num++;
	return ntlmssp_make_packet_signiture(ntlmssp_state, data, length, sig);
}

/**
 * Check the signature of an incoming packet 
 * @note caller *must* check that the signature is the size it expects 
 *
 */

NTSTATUS ntlmssp_client_check_packet(NTLMSSP_CLIENT_STATE *ntlmssp_state,
					   const uchar *data, size_t length, 
					   const DATA_BLOB *sig) 
{
	DATA_BLOB local_sig;
	NTSTATUS nt_status;

	if (sig->length < 8) {
		DEBUG(0, ("NTLMSSP packet check failed due to short signiture (%u bytes)!\n", 
			  sig->length));
	}

	nt_status = ntlmssp_make_packet_signiture(ntlmssp_state, data, 
						  length, &local_sig);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("NTLMSSP packet check failed with %s\n", nt_errstr(nt_status)));
		return nt_status;
	}
	
	if (memcmp(sig->data, local_sig.data, MIN(sig->length, local_sig.length)) == 0) {
		return NT_STATUS_OK;
	} else {
		DEBUG(0, ("NTLMSSP packet check failed due to invalid signiture!\n"));
		return NT_STATUS_ACCESS_DENIED;
	}
}

/**
   Initialise the state for NTLMSSP signing.
*/
NTSTATUS ntlmssp_client_sign_init(NTLMSSP_CLIENT_STATE *ntlmssp_state)
{
	unsigned char p24[24];
	unsigned char lm_hash[16];

	if (!ntlmssp_state->lm_resp.data) {
		/* can't sign or check signitures yet */ 
		return NT_STATUS_UNSUCCESSFUL;
	}
			    
	E_deshash(ntlmssp_state->password, lm_hash);
		
	NTLMSSPOWFencrypt(lm_hash, ntlmssp_state->lm_resp.data, p24);
	
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2)
	{
		calc_ntlmv2_hash(ntlmssp_state->cli_sign_hash, ntlmssp_state->cli_sign_const, p24, CLI_SIGN);
		calc_ntlmv2_hash(ntlmssp_state->cli_seal_hash, ntlmssp_state->cli_seal_const, p24, CLI_SEAL);
		calc_ntlmv2_hash(ntlmssp_state->srv_sign_hash, ntlmssp_state->srv_sign_const, p24, SRV_SIGN);
		calc_ntlmv2_hash(ntlmssp_state->srv_seal_hash, ntlmssp_state->srv_seal_const, p24, SRV_SEAL);
	}
	else
	{
		char k2[8];
		memcpy(k2, p24, 5);
		k2[5] = 0xe5;
		k2[6] = 0x38;
		k2[7] = 0xb0;
		
		calc_hash(ntlmssp_state->ntlmssp_hash, k2, 8);
	}

	ntlmssp_state->ntlmssp_seq_num = 0;

	ZERO_STRUCT(lm_hash);
	return NT_STATUS_OK;
}
