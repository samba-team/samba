/* 
   Unix SMB/CIFS implementation.

   schannel library code

   Copyright (C) Andrew Tridgell 2004
   
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

struct schannel_state {
	TALLOC_CTX *mem_ctx;
	uint8_t session_key[16];
	uint32_t seq_num;
	BOOL initiator;
};

#define NETSEC_SIGN_SIGNATURE { 0x77, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 }
#define NETSEC_SEAL_SIGNATURE { 0x77, 0x00, 0x7a, 0x00, 0xff, 0xff, 0x00, 0x00 }

/*******************************************************************
 Encode or Decode the sequence number (which is symmetric)
 ********************************************************************/
static void netsec_deal_with_seq_num(struct schannel_state *state,
				     const uint8_t packet_digest[8],
				     uint8_t seq_num[8])
{
	static const uint8_t zeros[4];
	uint8_t sequence_key[16];
	uint8_t digest1[16];

	hmac_md5(state->session_key, zeros, sizeof(zeros), digest1);
	hmac_md5(digest1, packet_digest, 8, sequence_key);
	arcfour_crypt(seq_num, sequence_key, 8);

	state->seq_num++;
}


/*******************************************************************
 Calculate the key with which to encode the data payload 
 ********************************************************************/
static void netsec_get_sealing_key(const uint8_t session_key[16],
				   const uint8_t seq_num[8],
				   uint8_t sealing_key[16]) 
{
	static const uint8_t zeros[4];
	uint8_t digest2[16];
	uint8_t sess_kf0[16];
	int i;

	for (i = 0; i < 16; i++) {
		sess_kf0[i] = session_key[i] ^ 0xf0;
	}
	
	hmac_md5(sess_kf0, zeros, 4, digest2);
	hmac_md5(digest2, seq_num, 8, sealing_key);
}


/*******************************************************************
 Create a digest over the entire packet (including the data), and 
 MD5 it with the session key.
 ********************************************************************/
static void schannel_digest(const uint8_t sess_key[16],
			    const uint8_t netsec_sig[8],
			    const uint8_t *confounder,
			    const uint8_t *data, size_t data_len,
			    uint8_t digest_final[16]) 
{
	uint8_t packet_digest[16];
	static const uint8_t zeros[4];
	struct MD5Context ctx;
	
	MD5Init(&ctx);
	MD5Update(&ctx, zeros, 4);
	MD5Update(&ctx, netsec_sig, 8);
	if (confounder) {
		MD5Update(&ctx, confounder, 8);
	}
	MD5Update(&ctx, data, data_len);
	MD5Final(packet_digest, &ctx);
	
	hmac_md5(sess_key, packet_digest, sizeof(packet_digest), digest_final);
}


/*
  unseal a packet
*/
NTSTATUS schannel_unseal_packet(struct schannel_state *state,
				TALLOC_CTX *mem_ctx, 
				uint8_t *data, size_t length, 
				DATA_BLOB *sig)
{
	uint8_t digest_final[16];
	uint8_t confounder[8];
	uint8_t seq_num[8];
	uint8_t sealing_key[16];
	static const uint8_t netsec_sig[8] = NETSEC_SEAL_SIGNATURE;

	if (sig->length != 32) {
		return NT_STATUS_ACCESS_DENIED;
	}

	memcpy(confounder, sig->data+24, 8);

	RSIVAL(seq_num, 0, state->seq_num);
	SIVAL(seq_num, 4, state->initiator?0:0x80);

	netsec_get_sealing_key(state->session_key, seq_num, sealing_key);
	arcfour_crypt(confounder, sealing_key, 8);
	arcfour_crypt(data, sealing_key, length);

	schannel_digest(state->session_key, 
			netsec_sig, confounder, 
			data, length, digest_final);

	if (memcmp(digest_final, sig->data+16, 8) != 0) {
		dump_data_pw("calc digest:", digest_final, 8);
		dump_data_pw("wire digest:", sig->data+16, 8);
		return NT_STATUS_ACCESS_DENIED;
	}

	netsec_deal_with_seq_num(state, digest_final, seq_num);

	if (memcmp(seq_num, sig->data+8, 8) != 0) {
		dump_data_pw("calc seq num:", seq_num, 8);
		dump_data_pw("wire seq num:", sig->data+8, 8);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

/*
  check the signature on a packet
*/
NTSTATUS schannel_check_packet(struct schannel_state *state, 
			       const uint8_t *data, size_t length, 
			       const DATA_BLOB *sig)
{
	uint8_t digest_final[16];
	uint8_t seq_num[8];
	static const uint8_t netsec_sig[8] = NETSEC_SIGN_SIGNATURE;

	if (sig->length != 32) {
		return NT_STATUS_ACCESS_DENIED;
	}

	RSIVAL(seq_num, 0, state->seq_num);
	SIVAL(seq_num, 4, state->initiator?0:0x80);

	dump_data_pw("seq_num:\n", seq_num, 8);
	dump_data_pw("sess_key:\n", state->session_key, 16);

	schannel_digest(state->session_key, 
			netsec_sig, NULL, 
			data, length, digest_final);

	netsec_deal_with_seq_num(state, digest_final, seq_num);

	if (memcmp(seq_num, sig->data+8, 8) != 0) {
		dump_data_pw("calc seq num:", seq_num, 8);
		dump_data_pw("wire seq num:", sig->data+8, 8);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (memcmp(digest_final, sig->data+16, 8) != 0) {
		dump_data_pw("calc digest:", digest_final, 8);
		dump_data_pw("wire digest:", sig->data+16, 8);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}


/*
  seal a packet
*/
NTSTATUS schannel_seal_packet(struct schannel_state *state, 
			      TALLOC_CTX *mem_ctx, 
			      uint8_t *data, size_t length, 
			      DATA_BLOB *sig)
{
	uint8_t digest_final[16];
	uint8_t confounder[8];
	uint8_t seq_num[8];
	uint8_t sealing_key[16];
	static const uint8_t netsec_sig[8] = NETSEC_SEAL_SIGNATURE;

	generate_random_buffer(confounder, 8);

	RSIVAL(seq_num, 0, state->seq_num);
	SIVAL(seq_num, 4, state->initiator?0x80:0);

	schannel_digest(state->session_key, 
			netsec_sig, confounder, 
			data, length, digest_final);

	netsec_get_sealing_key(state->session_key, seq_num, sealing_key);
	arcfour_crypt(confounder, sealing_key, 8);
	arcfour_crypt(data, sealing_key, length);

	netsec_deal_with_seq_num(state, digest_final, seq_num);

	(*sig) = data_blob_talloc(state->mem_ctx, NULL, 32);

	memcpy(sig->data, netsec_sig, 8);
	memcpy(sig->data+8, seq_num, 8);
	memcpy(sig->data+16, digest_final, 8);
	memcpy(sig->data+24, confounder, 8);

	dump_data_pw("signature:", sig->data+ 0, 8);
	dump_data_pw("seq_num  :", sig->data+ 8, 8);
	dump_data_pw("digest   :", sig->data+16, 8);
	dump_data_pw("confound :", sig->data+24, 8);

	return NT_STATUS_OK;
}


/*
  sign a packet
*/
NTSTATUS schannel_sign_packet(struct schannel_state *state, 
			      TALLOC_CTX *mem_ctx, 
			      const uint8_t *data, size_t length, 
			      DATA_BLOB *sig)
{
	uint8_t digest_final[16];
	uint8_t seq_num[8];
	static const uint8_t netsec_sig[8] = NETSEC_SIGN_SIGNATURE;

	RSIVAL(seq_num, 0, state->seq_num);
	SIVAL(seq_num, 4, state->initiator?0x80:0);

	schannel_digest(state->session_key, 
			netsec_sig, NULL, 
			data, length, digest_final);

	netsec_deal_with_seq_num(state, digest_final, seq_num);

	(*sig) = data_blob_talloc(state->mem_ctx, NULL, 32);

	memcpy(sig->data, netsec_sig, 8);
	memcpy(sig->data+8, seq_num, 8);
	memcpy(sig->data+16, digest_final, 8);
	memset(sig->data+24, 0, 8);

	dump_data_pw("signature:", sig->data+ 0, 8);
	dump_data_pw("seq_num  :", sig->data+ 8, 8);
	dump_data_pw("digest   :", sig->data+16, 8);
	dump_data_pw("confound :", sig->data+24, 8);

	return NT_STATUS_OK;
}

/*
  destroy an schannel context
 */
void schannel_end(struct schannel_state **state)
{
	if (*state) {
		talloc_destroy((*state)->mem_ctx);
		(*state) = NULL;
	}
}

/*
  create an schannel context state
*/
NTSTATUS schannel_start(struct schannel_state **state,
			const uint8_t session_key[16],
			BOOL initiator)
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("schannel_state");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	(*state) = talloc_p(mem_ctx, struct schannel_state);
	if (!(*state)) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	(*state)->mem_ctx = mem_ctx;
	memcpy((*state)->session_key, session_key, 16);
	(*state)->initiator = initiator;
	(*state)->seq_num = 0;

	return NT_STATUS_OK;
}
