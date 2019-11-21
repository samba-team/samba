/* 
   Unix SMB/CIFS implementation.

   code to encrypt/decrypt data using the user session key

   Copyright (C) Andrew Tridgell 2004
   
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

/*
  encrypt or decrypt a blob of data using the user session key
  as used in lsa_SetSecret

  before calling, the out blob must be initialised to be the same size
  as the in blob
*/
int sess_crypt_blob(DATA_BLOB *out, const DATA_BLOB *in, const DATA_BLOB *session_key,
		    enum samba_gnutls_direction encrypt)
{
	int i, k, rc;

	if (in->length % 8 != 0) {
		return GNUTLS_E_INVALID_REQUEST;
	}

	for (i=0,k=0;
	     i<in->length;
	     i += 8, k += 7) {
		uint8_t bin[8], bout[8], key[7];

		memcpy(bin,  &in->data[i], 8);

		if (k + 7 > session_key->length) {
			k = (session_key->length - k);
		}
		memcpy(key, &session_key->data[k], 7);

		rc = des_crypt56_gnutls(bout, bin, key, encrypt);
		if (rc != 0) {
			return rc;
		}

		memcpy(&out->data[i], bout, 8);
	}
	return 0;
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
	int rc;

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

	rc = sess_crypt_blob(&ret, &src, session_key, SAMBA_GNUTLS_ENCRYPT);
	
	data_blob_free(&src);
	if (rc != 0) {
		data_blob_free(&ret);
		return data_blob(NULL, 0);
	}

	return ret;
}

/*
  a convenient wrapper around sess_crypt_blob() for strings, using the LSA convention

  caller should free the returned string
*/
char *sess_decrypt_string(TALLOC_CTX *mem_ctx, 
			  DATA_BLOB *blob, const DATA_BLOB *session_key)
{
	DATA_BLOB out;
	int rc, slen;
	char *ret;

	if (blob->length < 8) {
		return NULL;
	}
	
	out = data_blob_talloc(mem_ctx, NULL, blob->length);
	if (!out.data) {
		return NULL;
	}

	rc = sess_crypt_blob(&out, blob, session_key, SAMBA_GNUTLS_DECRYPT);
	if (rc != 0) {
		data_blob_free(&out);
		return NULL;
	}

	if (IVAL(out.data, 4) != 1) {
		DEBUG(0,("Unexpected revision number %d in session crypted string\n",
			 IVAL(out.data, 4)));
		data_blob_free(&out);
		return NULL;
	}

	slen = IVAL(out.data, 0);
	if (slen > blob->length - 8) {
		DEBUG(0,("Invalid crypt length %d\n", slen));
		data_blob_free(&out);
		return NULL;
	}

	ret = talloc_strndup(mem_ctx, (const char *)(out.data+8), slen);

	data_blob_free(&out);

	DEBUG(0,("decrypted string '%s' of length %d\n", ret, slen));

	return ret;
}

/*
  a convenient wrapper around sess_crypt_blob() for DATA_BLOBs, using the LSA convention

  note that we round the length to a multiple of 8. This seems to be needed for 
  compatibility with windows

  caller should free using data_blob_free()
*/
DATA_BLOB sess_encrypt_blob(TALLOC_CTX *mem_ctx, DATA_BLOB *blob_in, const DATA_BLOB *session_key)
{
	DATA_BLOB ret, src;
	int dlen = (blob_in->length+7) & ~7;
	int rc;

	src = data_blob_talloc(mem_ctx, NULL, 8+dlen);
	if (!src.data) {
		return data_blob(NULL, 0);
	}

	ret = data_blob_talloc(mem_ctx, NULL, 8+dlen);
	if (!ret.data) {
		data_blob_free(&src);
		return data_blob(NULL, 0);
	}

	SIVAL(src.data, 0, blob_in->length);
	SIVAL(src.data, 4, 1);
	memset(src.data+8, 0, dlen);
	memcpy(src.data+8, blob_in->data, blob_in->length);

	rc = sess_crypt_blob(&ret, &src, session_key, SAMBA_GNUTLS_ENCRYPT);
	
	data_blob_free(&src);
	if (rc != 0) {
		data_blob_free(&ret);
		return data_blob(NULL, 0);
	}

	return ret;
}

/*
  Decrypt a DATA_BLOB using the LSA convention
*/
NTSTATUS sess_decrypt_blob(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob, const DATA_BLOB *session_key, 
			   DATA_BLOB *ret)
{
	DATA_BLOB out;
	int rc, slen;

	if (blob->length < 8) {
		DEBUG(0, ("Unexpected length %d in session crypted secret (BLOB)\n",
			  (int)blob->length));
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	out = data_blob_talloc(mem_ctx, NULL, blob->length);
	if (!out.data) {
		return NT_STATUS_NO_MEMORY;
	}

	rc = sess_crypt_blob(&out, blob, session_key, SAMBA_GNUTLS_DECRYPT);
	if (rc != 0) {
		data_blob_free(&out);
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}

	if (IVAL(out.data, 4) != 1) {
		DEBUG(2,("Unexpected revision number %d in session crypted secret (BLOB)\n",
			 IVAL(out.data, 4)));
		return NT_STATUS_UNKNOWN_REVISION;
	}
		
	slen = IVAL(out.data, 0);
	if (slen > blob->length - 8) {
		DEBUG(0,("Invalid crypt length %d in session crypted secret (BLOB)\n", slen));
		return NT_STATUS_WRONG_PASSWORD;
	}

	*ret = data_blob_talloc(mem_ctx, out.data+8, slen);
	if (slen && !ret->data) {
		return NT_STATUS_NO_MEMORY;
	}

	data_blob_free(&out);

	return NT_STATUS_OK;
}
