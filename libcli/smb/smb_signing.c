/*
   Unix SMB/CIFS implementation.
   SMB Signing Code
   Copyright (C) Jeremy Allison 2003.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003
   Copyright (C) Stefan Metzmacher 2009

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
#include "../lib/crypto/crypto.h"
#include "smb_common.h"
#include "smb_signing.h"

/* Used by the SMB signing functions. */

struct smb_signing_state {
	/* is signing localy allowed */
	bool allowed;

	/* is signing localy desired */
	bool desired;

	/* is signing localy mandatory */
	bool mandatory;

	/* is signing negotiated by the peer */
	bool negotiated;

	bool active; /* Have I ever seen a validly signed packet? */

	/* mac_key.length > 0 means signing is started */
	DATA_BLOB mac_key;

	/* the next expected seqnum */
	uint32_t seqnum;

	TALLOC_CTX *mem_ctx;
	void *(*alloc_fn)(TALLOC_CTX *mem_ctx, size_t len);
	void (*free_fn)(TALLOC_CTX *mem_ctx, void *ptr);
};

static void smb_signing_reset_info(struct smb_signing_state *si)
{
	si->active = false;
	si->seqnum = 0;

	if (si->free_fn) {
		si->free_fn(si->mem_ctx, si->mac_key.data);
	} else {
		talloc_free(si->mac_key.data);
	}
	si->mac_key.data = NULL;
	si->mac_key.length = 0;
}

struct smb_signing_state *smb_signing_init_ex(TALLOC_CTX *mem_ctx,
					      bool allowed,
					      bool desired,
					      bool mandatory,
					      void *(*alloc_fn)(TALLOC_CTX *, size_t),
					      void (*free_fn)(TALLOC_CTX *, void *))
{
	struct smb_signing_state *si;

	if (alloc_fn) {
		void *p = alloc_fn(mem_ctx, sizeof(struct smb_signing_state));
		if (p == NULL) {
			return NULL;
		}
		memset(p, 0, sizeof(struct smb_signing_state));
		si = (struct smb_signing_state *)p;
		si->mem_ctx = mem_ctx;
		si->alloc_fn = alloc_fn;
		si->free_fn = free_fn;
	} else {
		si = talloc_zero(mem_ctx, struct smb_signing_state);
		if (si == NULL) {
			return NULL;
		}
	}

	if (mandatory) {
		desired = true;
	}

	if (desired) {
		allowed = true;
	}

	si->allowed = allowed;
	si->desired = desired;
	si->mandatory = mandatory;

	return si;
}

struct smb_signing_state *smb_signing_init(TALLOC_CTX *mem_ctx,
					   bool allowed,
					   bool desired,
					   bool mandatory)
{
	return smb_signing_init_ex(mem_ctx, allowed, desired, mandatory,
				   NULL, NULL);
}

static bool smb_signing_good(struct smb_signing_state *si,
			     bool good, uint32_t seq)
{
	if (good) {
		if (!si->active) {
			si->active = true;
		}
		return true;
	}

	if (!si->mandatory && !si->active) {
		/* Non-mandatory signing - just turn off if this is the first bad packet.. */
		DEBUG(5, ("smb_signing_good: signing negotiated but not required and peer\n"
			  "isn't sending correct signatures. Turning off.\n"));
		smb_signing_reset_info(si);
		return true;
	}

	/* Mandatory signing or bad packet after signing started - fail and disconnect. */
	DEBUG(0, ("smb_signing_good: BAD SIG: seq %u\n", (unsigned int)seq));
	return false;
}

static void smb_signing_md5(const DATA_BLOB *mac_key,
			    const uint8_t *hdr, size_t len,
			    uint32_t seq_number,
			    uint8_t calc_md5_mac[16])
{
	const size_t offset_end_of_sig = (HDR_SS_FIELD + 8);
	uint8_t sequence_buf[8];
	MD5_CTX md5_ctx;

	/*
	 * Firstly put the sequence number into the first 4 bytes.
	 * and zero out the next 4 bytes.
	 *
	 * We do this here, to avoid modifying the packet.
	 */

	DEBUG(10,("smb_signing_md5: sequence number %u\n", seq_number ));

	SIVAL(sequence_buf, 0, seq_number);
	SIVAL(sequence_buf, 4, 0);

	/* Calculate the 16 byte MAC - but don't alter the data in the
	   incoming packet.

	   This makes for a bit of fussing about, but it's not too bad.
	*/
	MD5Init(&md5_ctx);

	/* intialise with the key */
	MD5Update(&md5_ctx, mac_key->data, mac_key->length);

	/* copy in the first bit of the SMB header */
	MD5Update(&md5_ctx, hdr, HDR_SS_FIELD);

	/* copy in the sequence number, instead of the signature */
	MD5Update(&md5_ctx, sequence_buf, sizeof(sequence_buf));

	/* copy in the rest of the packet in, skipping the signature */
	MD5Update(&md5_ctx, hdr + offset_end_of_sig,
		  len - (offset_end_of_sig));

	/* calculate the MD5 sig */
	MD5Final(calc_md5_mac, &md5_ctx);
}

uint32_t smb_signing_next_seqnum(struct smb_signing_state *si, bool oneway)
{
	uint32_t seqnum;

	if (si->mac_key.length == 0) {
		return 0;
	}

	seqnum = si->seqnum;
	if (oneway) {
		si->seqnum += 1;
	} else {
		si->seqnum += 2;
	}

	return seqnum;
}

void smb_signing_cancel_reply(struct smb_signing_state *si, bool oneway)
{
	if (si->mac_key.length == 0) {
		return;
	}

	if (oneway) {
		si->seqnum -= 1;
	} else {
		si->seqnum -= 2;
	}
}

void smb_signing_sign_pdu(struct smb_signing_state *si,
			  uint8_t *outhdr, size_t len,
			  uint32_t seqnum)
{
	uint8_t calc_md5_mac[16];
	uint8_t com;
	uint8_t flags;

	if (si->mac_key.length == 0) {
		if (!si->negotiated) {
			return;
		}
	}

	/* JRA Paranioa test - we should be able to get rid of this... */
	if (len < (HDR_SS_FIELD + 8)) {
		DEBUG(1,("smb_signing_sign_pdu: Logic error. "
			 "Can't check signature on short packet! smb_len = %u\n",
			 (unsigned)len));
		abort();
	}

	com = SVAL(outhdr, HDR_COM);
	flags = SVAL(outhdr, HDR_FLG);

	if (!(flags & FLAG_REPLY)) {
		uint16_t flags2 = SVAL(outhdr, HDR_FLG2);
		/*
		 * If this is a request, specify what is
		 * supported or required by the client
		 */
		if (si->negotiated && si->desired) {
			flags2 |= FLAGS2_SMB_SECURITY_SIGNATURES;
		}
		if (si->negotiated && si->mandatory) {
			flags2 |= FLAGS2_SMB_SECURITY_SIGNATURES_REQUIRED;
		}
		SSVAL(outhdr, HDR_FLG2, flags2);
	}

	if (si->mac_key.length == 0) {
		/* I wonder what BSRSPYL stands for - but this is what MS
		   actually sends! */
		if (com == SMBsesssetupX) {
			memcpy(calc_md5_mac, "BSRSPYL ", 8);
		} else {
			memset(calc_md5_mac, 0, 8);
		}
	} else {
		smb_signing_md5(&si->mac_key, outhdr, len,
				seqnum, calc_md5_mac);
	}

	DEBUG(10, ("smb_signing_sign_pdu: sent SMB signature of\n"));
	dump_data(10, calc_md5_mac, 8);

	memcpy(&outhdr[HDR_SS_FIELD], calc_md5_mac, 8);

/*	outhdr[HDR_SS_FIELD+2]=0;
	Uncomment this to test if the remote server actually verifies signatures...*/
}

bool smb_signing_check_pdu(struct smb_signing_state *si,
			   const uint8_t *inhdr, size_t len,
			   uint32_t seqnum)
{
	bool good;
	uint8_t calc_md5_mac[16];
	const uint8_t *reply_sent_mac;

	if (si->mac_key.length == 0) {
		return true;
	}

	if (len < (HDR_SS_FIELD + 8)) {
		DEBUG(1,("smb_signing_check_pdu: Can't check signature "
			 "on short packet! smb_len = %u\n",
			 (unsigned)len));
		return false;
	}

	smb_signing_md5(&si->mac_key, inhdr, len,
			seqnum, calc_md5_mac);

	reply_sent_mac = &inhdr[HDR_SS_FIELD];
	good = (memcmp(reply_sent_mac, calc_md5_mac, 8) == 0);

	if (!good) {
		int i;
		const int sign_range = 5;

		DEBUG(5, ("smb_signing_check_pdu: BAD SIG: wanted SMB signature of\n"));
		dump_data(5, calc_md5_mac, 8);

		DEBUG(5, ("smb_signing_check_pdu: BAD SIG: got SMB signature of\n"));
		dump_data(5, reply_sent_mac, 8);

		for (i = -sign_range; i < sign_range; i++) {
			smb_signing_md5(&si->mac_key, inhdr, len,
					seqnum+i, calc_md5_mac);
			if (memcmp(reply_sent_mac, calc_md5_mac, 8) == 0) {
				DEBUG(0,("smb_signing_check_pdu: "
					 "out of seq. seq num %u matches. "
					 "We were expecting seq %u\n",
					 (unsigned int)seqnum+i,
					 (unsigned int)seqnum));
				break;
			}
		}
	} else {
		DEBUG(10, ("smb_signing_check_pdu: seq %u: "
			   "got good SMB signature of\n",
			   (unsigned int)seqnum));
		dump_data(10, reply_sent_mac, 8);
	}

	return smb_signing_good(si, good, seqnum);
}

bool smb_signing_activate(struct smb_signing_state *si,
			  const DATA_BLOB user_session_key,
			  const DATA_BLOB response)
{
	size_t len;
	off_t ofs;

	if (!user_session_key.length) {
		return false;
	}

	if (!si->negotiated) {
		return false;
	}

	if (si->active) {
		return false;
	}

	if (si->mac_key.length > 0) {
		return false;
	}

	smb_signing_reset_info(si);

	len = response.length + user_session_key.length;
	if (si->alloc_fn) {
		si->mac_key.data = (uint8_t *)si->alloc_fn(si->mem_ctx, len);
		if (si->mac_key.data == NULL) {
			return false;
		}
	} else {
		si->mac_key.data = (uint8_t *)talloc_size(si, len);
		if (si->mac_key.data == NULL) {
			return false;
		}
	}
	si->mac_key.length = len;

	ofs = 0;
	memcpy(&si->mac_key.data[ofs], user_session_key.data, user_session_key.length);

	DEBUG(10, ("smb_signing_activate: user_session_key\n"));
	dump_data(10, user_session_key.data, user_session_key.length);

	if (response.length) {
		ofs = user_session_key.length;
		memcpy(&si->mac_key.data[ofs], response.data, response.length);
		DEBUG(10, ("smb_signing_activate: response_data\n"));
		dump_data(10, response.data, response.length);
	} else {
		DEBUG(10, ("smb_signing_activate: NULL response_data\n"));
	}

	dump_data_pw("smb_signing_activate: mac key is:\n",
		     si->mac_key.data, si->mac_key.length);

	/* Initialise the sequence number */
	si->seqnum = 2;

	return true;
}

bool smb_signing_is_active(struct smb_signing_state *si)
{
	return si->active;
}

bool smb_signing_is_allowed(struct smb_signing_state *si)
{
	return si->allowed;
}

bool smb_signing_is_desired(struct smb_signing_state *si)
{
	return si->desired;
}

bool smb_signing_is_mandatory(struct smb_signing_state *si)
{
	return si->mandatory;
}

bool smb_signing_set_negotiated(struct smb_signing_state *si,
				bool allowed, bool mandatory)
{
	if (si->active) {
		return true;
	}

	if (!si->allowed && mandatory) {
		return false;
	}

	if (si->mandatory && !allowed) {
		return false;
	}

	if (si->mandatory) {
		si->negotiated = true;
		return true;
	}

	if (mandatory) {
		si->negotiated = true;
		return true;
	}

	if (!si->desired) {
		si->negotiated = false;
		return true;
	}

	if (si->desired && allowed) {
		si->negotiated = true;
		return true;
	}

	si->negotiated = false;
	return true;
}

bool smb_signing_is_negotiated(struct smb_signing_state *si)
{
	return si->negotiated;
}

void smb_key_derivation(const uint8_t *KI, size_t KI_len,
			uint8_t KO[16])
{
	static const uint8_t SSKeyHash[256] = {
		0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79,
		0x20, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
		0x72, 0x65, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x55,
		0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x79, 0x07,
		0x6e, 0x28, 0x2e, 0x69, 0x88, 0x10, 0xb3, 0xdb,
		0x01, 0x55, 0x72, 0xfb, 0x74, 0x14, 0xfb, 0xc4,
		0xc5, 0xaf, 0x3b, 0x41, 0x65, 0x32, 0x17, 0xba,
		0xa3, 0x29, 0x08, 0xc1, 0xde, 0x16, 0x61, 0x7e,
		0x66, 0x98, 0xa4, 0x0b, 0xfe, 0x06, 0x83, 0x53,
		0x4d, 0x05, 0xdf, 0x6d, 0xa7, 0x51, 0x10, 0x73,
		0xc5, 0x50, 0xdc, 0x5e, 0xf8, 0x21, 0x46, 0xaa,
		0x96, 0x14, 0x33, 0xd7, 0x52, 0xeb, 0xaf, 0x1f,
		0xbf, 0x36, 0x6c, 0xfc, 0xb7, 0x1d, 0x21, 0x19,
		0x81, 0xd0, 0x6b, 0xfa, 0x77, 0xad, 0xbe, 0x18,
		0x78, 0xcf, 0x10, 0xbd, 0xd8, 0x78, 0xf7, 0xd3,
		0xc6, 0xdf, 0x43, 0x32, 0x19, 0xd3, 0x9b, 0xa8,
		0x4d, 0x9e, 0xaa, 0x41, 0xaf, 0xcb, 0xc6, 0xb9,
		0x34, 0xe7, 0x48, 0x25, 0xd4, 0x88, 0xc4, 0x51,
		0x60, 0x38, 0xd9, 0x62, 0xe8, 0x8d, 0x5b, 0x83,
		0x92, 0x7f, 0xb5, 0x0e, 0x1c, 0x2d, 0x06, 0x91,
		0xc3, 0x75, 0xb3, 0xcc, 0xf8, 0xf7, 0x92, 0x91,
		0x0b, 0x3d, 0xa1, 0x10, 0x5b, 0xd5, 0x0f, 0xa8,
		0x3f, 0x5d, 0x13, 0x83, 0x0a, 0x6b, 0x72, 0x93,
		0x14, 0x59, 0xd5, 0xab, 0xde, 0x26, 0x15, 0x6d,
		0x60, 0x67, 0x71, 0x06, 0x6e, 0x3d, 0x0d, 0xa7,
		0xcb, 0x70, 0xe9, 0x08, 0x5c, 0x99, 0xfa, 0x0a,
		0x5f, 0x3d, 0x44, 0xa3, 0x8b, 0xc0, 0x8d, 0xda,
		0xe2, 0x68, 0xd0, 0x0d, 0xcd, 0x7f, 0x3d, 0xf8,
		0x73, 0x7e, 0x35, 0x7f, 0x07, 0x02, 0x0a, 0xb5,
		0xe9, 0xb7, 0x87, 0xfb, 0xa1, 0xbf, 0xcb, 0x32,
		0x31, 0x66, 0x09, 0x48, 0x88, 0xcc, 0x18, 0xa3,
		0xb2, 0x1f, 0x1f, 0x1b, 0x90, 0x4e, 0xd7, 0xe1
	};
	HMACMD5Context ctx;

	hmac_md5_init_limK_to_64(KI, KI_len, &ctx);
	hmac_md5_update(SSKeyHash, sizeof(SSKeyHash), &ctx);
	hmac_md5_final(KO, &ctx);

	ZERO_STRUCT(ctx);
}
