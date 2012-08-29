/*
   Unix SMB/CIFS implementation.

   Kerberos utility functions

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2012

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
#include "krb5_samba.h"
#include "librpc/gen_ndr/netlogon.h"

const krb5_enctype *samba_all_enctypes(void)
{
	/* TODO: Find a way not to have to use a fixed list */
	static const krb5_enctype enctypes[] = {
		ENCTYPE_DES_CBC_CRC,
		ENCTYPE_DES_CBC_MD5,
		ENCTYPE_AES128_CTS_HMAC_SHA1_96,
		ENCTYPE_AES256_CTS_HMAC_SHA1_96,
		ENCTYPE_ARCFOUR_HMAC,
		0
	};
	return enctypes;
};

/* Translate between the IETF encryption type values and the Microsoft
 * msDS-SupportedEncryptionTypes values */
uint32_t kerberos_enctype_to_bitmap(krb5_enctype enc_type_enum)
{
	switch (enc_type_enum) {
	case ENCTYPE_DES_CBC_CRC:
		return ENC_CRC32;
	case ENCTYPE_DES_CBC_MD5:
		return ENC_RSA_MD5;
	case ENCTYPE_ARCFOUR_HMAC:
		return ENC_RC4_HMAC_MD5;
	case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
		return ENC_HMAC_SHA1_96_AES128;
	case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
		return ENC_HMAC_SHA1_96_AES256;
	default:
		return 0;
	}
}

/* Translate between the Microsoft msDS-SupportedEncryptionTypes values
 * and the IETF encryption type values */
krb5_enctype ms_suptype_to_ietf_enctype(uint32_t enctype_bitmap)
{
	switch (enctype_bitmap) {
	case ENC_CRC32:
		return ENCTYPE_DES_CBC_CRC;
	case ENC_RSA_MD5:
		return ENCTYPE_DES_CBC_MD5;
	case ENC_RC4_HMAC_MD5:
		return ENCTYPE_ARCFOUR_HMAC;
	case ENC_HMAC_SHA1_96_AES128:
		return ENCTYPE_AES128_CTS_HMAC_SHA1_96;
	case ENC_HMAC_SHA1_96_AES256:
		return ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	default:
		return 0;
	}
}

/* Return an array of krb5_enctype values */
krb5_error_code ms_suptypes_to_ietf_enctypes(TALLOC_CTX *mem_ctx,
					     uint32_t enctype_bitmap,
					     krb5_enctype **enctypes)
{
	unsigned int i, j = 0;
	*enctypes = talloc_zero_array(mem_ctx, krb5_enctype,
					(8 * sizeof(enctype_bitmap)) + 1);
	if (!*enctypes) {
		return ENOMEM;
	}
	for (i = 0; i < (8 * sizeof(enctype_bitmap)); i++) {
		uint32_t bit_value = (1 << i) & enctype_bitmap;
		if (bit_value & enctype_bitmap) {
			(*enctypes)[j] = ms_suptype_to_ietf_enctype(bit_value);
			if (!(*enctypes)[j]) {
				continue;
			}
			j++;
		}
	}
	(*enctypes)[j] = 0;
	return 0;
}
