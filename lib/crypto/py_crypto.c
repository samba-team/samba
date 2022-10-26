/*
   Unix SMB/CIFS implementation.
   Samba crypto functions

   Copyright (C) Alexander Bokovoy <ab@samba.org> 2017

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

#include <Python.h>
#include "includes.h"
#include "python/py3compat.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "lib/crypto/gnutls_helpers.h"
#include "lib/crypto/md4.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/util/pyerrors.h"

static bool samba_gnutls_datum_from_PyObject(PyObject *py_obj,
					     gnutls_datum_t *datum)
{
	uint8_t *data = NULL;
	Py_ssize_t size;

	int ret;

	ret = PyBytes_AsStringAndSize(py_obj,
				      (char **)&data,
				      &size);
	if (ret != 0) {
		return false;
	}

	datum->data = data;
	datum->size = size;

	return true;
}

static bool samba_DATA_BLOB_from_PyObject(PyObject *py_obj,
					  DATA_BLOB *blob)
{
	uint8_t *data = NULL;
	Py_ssize_t size;

	int ret;

	ret = PyBytes_AsStringAndSize(py_obj,
				      (char **)&data,
				      &size);
	if (ret != 0) {
		return false;
	}

	blob->data = data;
	blob->length = size;

	return true;
}

static PyObject *py_crypto_arcfour_crypt_blob(PyObject *module, PyObject *args)
{
	DATA_BLOB data;
	PyObject *py_data, *py_key, *result;
	TALLOC_CTX *ctx;
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t key;
	int rc;

	if (!PyArg_ParseTuple(args, "OO", &py_data, &py_key))
		return NULL;

	if (!PyBytes_Check(py_data)) {
		PyErr_Format(PyExc_TypeError, "bytes expected");
		return NULL;
	}

	if (!PyBytes_Check(py_key)) {
		PyErr_Format(PyExc_TypeError, "bytes expected");
		return NULL;
	}

	ctx = talloc_new(NULL);

	data.length = PyBytes_Size(py_data);
	data.data = talloc_memdup(ctx, PyBytes_AsString(py_data), data.length);
	if (!data.data) {
		talloc_free(ctx);
		return PyErr_NoMemory();
	}

	key = (gnutls_datum_t) {
		.data = (uint8_t *)PyBytes_AsString(py_key),
		.size = PyBytes_Size(py_key),
	};

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&key,
				NULL);
	if (rc < 0) {
		talloc_free(ctx);
		PyErr_Format(PyExc_OSError, "encryption failed");
		return NULL;
	}
	rc = gnutls_cipher_encrypt(cipher_hnd,
				   data.data,
				   data.length);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc < 0) {
		talloc_free(ctx);
		PyErr_Format(PyExc_OSError, "encryption failed");
		return NULL;
	}

	result = PyBytes_FromStringAndSize((const char*) data.data, data.length);
	talloc_free(ctx);
	return result;
}

static PyObject *py_crypto_set_relax_mode(PyObject *module)
{
	GNUTLS_FIPS140_SET_LAX_MODE();

	Py_RETURN_NONE;
}

static PyObject *py_crypto_set_strict_mode(PyObject *module)
{
	GNUTLS_FIPS140_SET_STRICT_MODE();

	Py_RETURN_NONE;
}

static PyObject *py_crypto_des_crypt_blob_16(PyObject *self, PyObject *args)
{
	PyObject *py_data = NULL;
	uint8_t *data = NULL;
	Py_ssize_t data_size;

	PyObject *py_key = NULL;
	uint8_t *key = NULL;
	Py_ssize_t key_size;

	uint8_t result[16];

	bool ok;
	int ret;

	ok = PyArg_ParseTuple(args, "SS",
			      &py_data, &py_key);
	if (!ok) {
		return NULL;
	}

	ret = PyBytes_AsStringAndSize(py_data,
				      (char **)&data,
				      &data_size);
	if (ret != 0) {
		return NULL;
	}

	ret = PyBytes_AsStringAndSize(py_key,
				      (char **)&key,
				      &key_size);
	if (ret != 0) {
		return NULL;
	}

	if (data_size != 16) {
		return PyErr_Format(PyExc_ValueError,
				    "Expected data size of 16 bytes; got %zd",
				    data_size);
	}

	if (key_size != 14) {
		return PyErr_Format(PyExc_ValueError,
				    "Expected key size of 14 bytes; got %zd",
				    key_size);
	}

	ret = des_crypt112_16(result, data, key,
			      SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return PyErr_Format(PyExc_RuntimeError,
				    "des_crypt112_16() failed: %d",
				    ret);
	}

	return PyBytes_FromStringAndSize((const char *)result,
					 sizeof(result));
}

static PyObject *py_crypto_md4_hash_blob(PyObject *self, PyObject *args)
{
	PyObject *py_data = NULL;
	uint8_t *data = NULL;
	Py_ssize_t data_size;

	uint8_t result[16];

	bool ok;
	int ret;

	ok = PyArg_ParseTuple(args, "S",
			      &py_data);
	if (!ok) {
		return NULL;
	}

	ret = PyBytes_AsStringAndSize(py_data,
				      (char **)&data,
				      &data_size);
	if (ret != 0) {
		return NULL;
	}

	mdfour(result, data, data_size);

	return PyBytes_FromStringAndSize((const char *)result,
					 sizeof(result));
}

static PyObject *py_crypto_sha512_pbkdf2(PyObject *self, PyObject *args)
{
	PyObject *py_key = NULL;
	uint8_t *key = NULL;
	gnutls_datum_t key_datum = {0};

	PyObject *py_salt = NULL;
	gnutls_datum_t salt_datum = {0};

	uint8_t result[16];

	unsigned iterations = 0;

	bool ok;
	int ret;
	NTSTATUS status;

	ok = PyArg_ParseTuple(args, "SSI",
			      &py_key, &py_salt, &iterations);
	if (!ok) {
		return NULL;
	}

	ok = samba_gnutls_datum_from_PyObject(py_key, &key_datum);
	if (!ok) {
		return NULL;
	}

	ok = samba_gnutls_datum_from_PyObject(py_salt, &salt_datum);
	if (!ok) {
		return NULL;
	}

	ret = gnutls_pbkdf2(GNUTLS_MAC_SHA512,
			    &key_datum,
			    &salt_datum,
			    iterations,
			    result,
			    sizeof(result));
	BURN_DATA(key);
	if (ret < 0) {
		status = gnutls_error_to_ntstatus(ret, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	return PyBytes_FromStringAndSize((const char *)result,
					 sizeof(result));
}

static PyObject *py_crypto_aead_aes_256_cbc_hmac_sha512_blob(PyObject *self, PyObject *args)
{
	TALLOC_CTX *ctx = NULL;

	PyObject *py_ciphertext = NULL;
	DATA_BLOB ciphertext_blob = {0};

	PyObject *py_auth_data = NULL;
	PyObject *py_result = NULL;

	PyObject *py_plaintext = NULL;
	DATA_BLOB plaintext_blob = {0};
	PyObject *py_cek = NULL;
	DATA_BLOB cek_blob = {0};
	PyObject *py_key_salt = NULL;
	DATA_BLOB key_salt_blob = {0};
	PyObject *py_mac_salt = NULL;
	DATA_BLOB mac_salt_blob = {0};
	PyObject *py_iv = NULL;
	DATA_BLOB iv_blob = {0};

	uint8_t auth_data[64];

	bool ok;
	NTSTATUS status;

	ok = PyArg_ParseTuple(args, "SSSSS",
			      &py_plaintext,
			      &py_cek,
			      &py_key_salt,
			      &py_mac_salt,
			      &py_iv);
	if (!ok) {
		return NULL;
	}

	/* Create data blobs from the contents of the function parameters. */

	ok = samba_DATA_BLOB_from_PyObject(py_plaintext, &plaintext_blob);
	if (!ok) {
		return NULL;
	}

	ok = samba_DATA_BLOB_from_PyObject(py_cek, &cek_blob);
	if (!ok) {
		return NULL;
	}

	ok = samba_DATA_BLOB_from_PyObject(py_key_salt, &key_salt_blob);
	if (!ok) {
		return NULL;
	}

	ok = samba_DATA_BLOB_from_PyObject(py_mac_salt, &mac_salt_blob);
	if (!ok) {
		return NULL;
	}

	ok = samba_DATA_BLOB_from_PyObject(py_iv, &iv_blob);
	if (!ok) {
		return NULL;
	}

	ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return PyErr_NoMemory();
	}

	/* Encrypt the plaintext. */
	status = samba_gnutls_aead_aes_256_cbc_hmac_sha512_encrypt(ctx,
								   &plaintext_blob,
								   &cek_blob,
								   &key_salt_blob,
								   &mac_salt_blob,
								   &iv_blob,
								   &ciphertext_blob,
								   auth_data);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		talloc_free(ctx);
		return NULL;
	}

	/* Convert the output into Python 'bytes' objects. */
	py_ciphertext = PyBytes_FromStringAndSize((const char *)ciphertext_blob.data,
						  ciphertext_blob.length);
	talloc_free(ctx);
	if (py_ciphertext == NULL) {
		return NULL;
	}
	py_auth_data = PyBytes_FromStringAndSize((const char *)auth_data,
						 sizeof(auth_data));
	if (py_auth_data == NULL) {
		return NULL;
	}

	/* Steal ciphertext and auth_data into a new tuple. */
	py_result = Py_BuildValue("(NN)", py_ciphertext, py_auth_data);

	return py_result;
}



static const char py_crypto_arcfour_crypt_blob_doc[] = "arcfour_crypt_blob(data, key)\n"
					 "Encrypt the data with RC4 algorithm using the key";

static const char py_crypto_des_crypt_blob_16_doc[] = "des_crypt_blob_16(data, key) -> bytes\n"
						      "Encrypt the 16-byte data with DES using "
						      "the 14-byte key";

static const char py_crypto_md4_hash_blob_doc[] = "md4_hash_blob(data) -> bytes\n"
						  "Hash the data with MD4 algorithm";

static const char py_crypto_sha512_pbkdf2_doc[] = "sha512_pbkdf2(key, salt, iterations) -> bytes\n"
						  "Derive a key from an existing one with SHA512 "
						  "algorithm";

static const char py_crypto_aead_aes_256_cbc_hmac_sha512_blob_doc[] =
	"aead_aes_256_cbc_hmac_sha512_blob(plaintext, cek, key_salt, "
	"mac_salt, iv) -> ciphertext, auth_data\n"
	"Encrypt the plaintext with AES256 as specified in "
	"[MS-SAMR] 3.2.2.4 AES Cipher Usage";

static PyMethodDef py_crypto_methods[] = {
	{ "arcfour_crypt_blob", (PyCFunction)py_crypto_arcfour_crypt_blob, METH_VARARGS, py_crypto_arcfour_crypt_blob_doc },
	{ "set_relax_mode", (PyCFunction)py_crypto_set_relax_mode, METH_NOARGS, "Set fips to relax mode" },
	{ "set_strict_mode", (PyCFunction)py_crypto_set_strict_mode, METH_NOARGS, "Set fips to strict mode" },
	{ "des_crypt_blob_16", (PyCFunction)py_crypto_des_crypt_blob_16, METH_VARARGS, py_crypto_des_crypt_blob_16_doc },
	{ "md4_hash_blob", (PyCFunction)py_crypto_md4_hash_blob, METH_VARARGS, py_crypto_md4_hash_blob_doc },
	{ "sha512_pbkdf2", (PyCFunction)py_crypto_sha512_pbkdf2, METH_VARARGS, py_crypto_sha512_pbkdf2_doc },
	{
		"aead_aes_256_cbc_hmac_sha512_blob",
		(PyCFunction)py_crypto_aead_aes_256_cbc_hmac_sha512_blob,
		METH_VARARGS,
		py_crypto_aead_aes_256_cbc_hmac_sha512_blob_doc
	},
	{0},
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "crypto",
	.m_doc = "Crypto functions required for SMB",
	.m_size = -1,
	.m_methods = py_crypto_methods,
};

MODULE_INIT_FUNC(crypto)
{
	PyObject *m;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	return m;
}
