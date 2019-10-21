/* 
   Unix SMB/CIFS implementation.

   a partial implementation of DES designed for use in the 
   SMB authentication protocol

   Copyright (C) Andrew Tridgell 1998
   
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
#include "libcli/auth/libcli_auth.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

static void str_to_key(const uint8_t *str,uint8_t *key)
{
	int i;

	key[0] = str[0]>>1;
	key[1] = ((str[0]&0x01)<<6) | (str[1]>>2);
	key[2] = ((str[1]&0x03)<<5) | (str[2]>>3);
	key[3] = ((str[2]&0x07)<<4) | (str[3]>>4);
	key[4] = ((str[3]&0x0F)<<3) | (str[4]>>5);
	key[5] = ((str[4]&0x1F)<<2) | (str[5]>>6);
	key[6] = ((str[5]&0x3F)<<1) | (str[6]>>7);
	key[7] = str[6]&0x7F;
	for (i=0;i<8;i++) {
		key[i] = (key[i]<<1);
	}
}

int des_crypt56_gnutls(uint8_t out[8], const uint8_t in[8],
		       const uint8_t key_in[7],
		       enum samba_gnutls_direction encrypt)
{
	/*
	 * A single block DES-CBC op, with an all-zero IV is the same as DES
	 * because the IV is combined with the data using XOR.
	 * This allows us to use GNUTLS_CIPHER_DES_CBC from GnuTLS and not
	 * implement single-DES in Samba.
	 *
	 * In turn this is used to build DES-ECB, which is used
	 * for example in the NTLM challenge/response calculation.
	 */
	static const uint8_t iv8[8];
	gnutls_datum_t iv = { discard_const(iv8), 8 };
	gnutls_datum_t key;
	gnutls_cipher_hd_t ctx;
	uint8_t key2[8];
	uint8_t outb[8];
	int ret;

	memset(out, 0, 8);

	str_to_key(key_in, key2);

	key.data = key2;
	key.size = 8;

	ret = gnutls_global_init();
	if (ret != 0) {
		return ret;
	}

	ret = gnutls_cipher_init(&ctx, GNUTLS_CIPHER_DES_CBC, &key, &iv);
	if (ret != 0) {
		return ret;
	}

	memcpy(outb, in, 8);
	if (encrypt == SAMBA_GNUTLS_ENCRYPT) {
		ret = gnutls_cipher_encrypt(ctx, outb, 8);
	} else {
		ret = gnutls_cipher_decrypt(ctx, outb, 8);
	}

	if (ret == 0) {
		memcpy(out, outb, 8);
	}

	gnutls_cipher_deinit(ctx);

	return ret;
}

int E_P16(const uint8_t *p14,uint8_t *p16)
{
	const uint8_t sp8[8] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
	int ret;

	ret = des_crypt56_gnutls(p16, sp8, p14, SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return ret;
	}

	return des_crypt56_gnutls(p16+8, sp8, p14+7, SAMBA_GNUTLS_ENCRYPT);
}

int E_P24(const uint8_t *p21, const uint8_t *c8, uint8_t *p24)
{
	int ret;

	ret = des_crypt56_gnutls(p24, c8, p21, SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return ret;
	}

	ret = des_crypt56_gnutls(p24+8, c8, p21+7, SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return ret;
	}

	return des_crypt56_gnutls(p24+16, c8, p21+14, SAMBA_GNUTLS_ENCRYPT);
}

int E_old_pw_hash( uint8_t *p14, const uint8_t *in, uint8_t *out)
{
	int ret;

        ret = des_crypt56_gnutls(out, in, p14, SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return ret;
	}

        return des_crypt56_gnutls(out+8, in+8, p14+7, SAMBA_GNUTLS_ENCRYPT);
}

/* des encryption with a 128 bit key */
int des_crypt128(uint8_t out[8], const uint8_t in[8], const uint8_t key[16])
{
	uint8_t buf[8];
	int ret;

	ret = des_crypt56_gnutls(buf, in, key, SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return ret;
	}

	return des_crypt56_gnutls(out, buf, key+9, SAMBA_GNUTLS_ENCRYPT);
}

/* des encryption with a 112 bit (14 byte) key */
int des_crypt112(uint8_t out[8], const uint8_t in[8], const uint8_t key[14],
		 enum samba_gnutls_direction encrypt)
{
	uint8_t buf[8];
	int ret;

	if (encrypt == SAMBA_GNUTLS_ENCRYPT) {
		ret = des_crypt56_gnutls(buf, in, key, SAMBA_GNUTLS_ENCRYPT);
		if (ret != 0) {
			return ret;
		}

		return des_crypt56_gnutls(out, buf, key+7, SAMBA_GNUTLS_ENCRYPT);
	}

	ret = des_crypt56_gnutls(buf, in, key+7, SAMBA_GNUTLS_DECRYPT);
	if (ret != 0) {
		return ret;
	}

	return des_crypt56_gnutls(out, buf, key, SAMBA_GNUTLS_DECRYPT);
}

/* des encryption of a 16 byte lump of data with a 112 bit key */
int des_crypt112_16(uint8_t out[16], const uint8_t in[16], const uint8_t key[14],
		    enum samba_gnutls_direction encrypt)
{
	int ret;

	ret = des_crypt56_gnutls(out, in, key, encrypt);
	if (ret != 0) {
		return ret;
	}

	return des_crypt56_gnutls(out + 8, in + 8, key+7, encrypt);
}

/* Decode a sam password hash into a password.  The password hash is the
   same method used to store passwords in the NT registry.  The DES key
   used is based on the RID of the user. */
int sam_rid_crypt(unsigned int rid, const uint8_t *in, uint8_t *out,
		  enum samba_gnutls_direction encrypt)
{
	uint8_t s[14];
	int ret;

	s[0] = s[4] = s[8] = s[12] = (uint8_t)(rid & 0xFF);
	s[1] = s[5] = s[9] = s[13] = (uint8_t)((rid >> 8) & 0xFF);
	s[2] = s[6] = s[10]        = (uint8_t)((rid >> 16) & 0xFF);
	s[3] = s[7] = s[11]        = (uint8_t)((rid >> 24) & 0xFF);

	ret = des_crypt56_gnutls(out, in, s, encrypt);
	if (ret != 0) {
		return ret;
	}
	return des_crypt56_gnutls(out+8, in+8, s+7, encrypt);
}
