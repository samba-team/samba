/* 
   Unix SMB/CIFS implementation.

   code to encrypt/decrypt data using the user session key

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

/*
  encrypt or decrypt a blob of data using the user session key
  as used in lsa_SetSecret

  before calling, the out blob must be initialised to be the same size
  as the in blob
*/
void sess_crypt_blob(DATA_BLOB *out, const DATA_BLOB *in, const DATA_BLOB *session_key,
		     BOOL forward)
{
	int i, k;

	for (i=0,k=0;
	     i<in->length;
	     i += 8, k += 7) {
		uint8_t bin[8], bout[8], key[7];

		memset(bin, 0, 8);
		memcpy(bin,  &in->data[i], MIN(8, in->length-i));

		if (k + 7 > session_key->length) {
			k = (session_key->length - k);
		}
		memcpy(key, &session_key->data[k], 7);

		smbhash(bout, bin, key, forward?1:0);

		memcpy(&out->data[i], bout, MIN(8, in->length-i));
	}
}


/*
  a convenient wrapper around sess_crypt_blob() for strings, using the LSA convention

  note that we round the length to a multiple of 8. This seems to be needed for 
  compatibility with windows

  caller should free using data_blob_free()
*/
DATA_BLOB sess_encrypt_string(const char *str, const DATA_BLOB *session_key)
{
	DATA_BLOB ret, src;
	int slen = strlen(str);
	int dlen = (slen+7) & ~7;

	src = data_blob(NULL, 8+dlen);
	if (!src.data) {
		return data_blob(NULL, 0);
	}

	ret = data_blob(NULL, 8+dlen);
	if (!ret.data) {
		data_blob_free(&src);
		return data_blob(NULL, 0);
	}

	SIVAL(src.data, 0, slen);
	SIVAL(src.data, 4, 1);
	memset(src.data+8, 0,   dlen);
	memcpy(src.data+8, str, slen);

	sess_crypt_blob(&ret, &src, session_key, True);
	
	data_blob_free(&src);

	return ret;
}

/*
  a convenient wrapper around sess_crypt_blob() for strings, using the LSA convention

  caller should free the returned string
*/
char *sess_decrypt_string(DATA_BLOB *blob, const DATA_BLOB *session_key)
{
	DATA_BLOB out;
	int slen;
	char *ret;

	if (blob->length < 8) {
		return NULL;
	}
	
	out = data_blob(NULL, blob->length);
	if (!out.data) {
		return NULL;
	}

	sess_crypt_blob(&out, blob, session_key, False);

	slen = IVAL(out.data, 0);
	if (slen > blob->length - 8) {
		DEBUG(0,("Invalid crypt length %d\n", slen));
		return NULL;
	}

	if (IVAL(out.data, 4) != 1) {
		DEBUG(0,("Unexpected revision number %d in session crypted string\n",
			 IVAL(out.data, 4)));
		return NULL;
	}
		
	ret = strndup(out.data+8, slen);

	data_blob_free(&out);

	return ret;
}
