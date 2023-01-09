/*
   Samba Unix SMB/CIFS implementation.

   Python bindings for compression functions.

   Copyright (C) Petr Viktorin 2015
   Copyright (C) Douglas Bagnall 2022

     ** NOTE! The following LGPL license applies to the talloc
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include <talloc.h>
#include <Python.h>
#include "lzxpress.h"
#include "lzxpress_huffman.h"

/* CompressionError is filled out in module init */
static PyObject *CompressionError = NULL;

static PyObject *plain_compress(PyObject *mod, PyObject *args)
{
	uint8_t *src = NULL;
	Py_ssize_t src_len;
	char *dest = NULL;
	Py_ssize_t dest_len;
	PyObject *dest_obj = NULL;
	size_t alloc_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#", &src, &src_len)) {
		return NULL;
	}

	/*
	 * 9/8 + 4 is the worst case growth, but we add room.
	 *
	 * alloc_len can't overflow as src_len is ssize_t while alloc_len is
	 * size_t.
	 */
	alloc_len = src_len + src_len / 8 + 500;

	dest_obj = PyBytes_FromStringAndSize(NULL, alloc_len);
	if (dest_obj == NULL) {
		return NULL;
	}
	dest = PyBytes_AS_STRING(dest_obj);

	dest_len = lzxpress_compress(src,
				     src_len,
				     (uint8_t *)dest,
				     alloc_len);
	if (dest_len < 0) {
		PyErr_SetString(CompressionError, "unable to compress data");
		Py_DECREF(dest_obj);
		return NULL;
	}

	ret = _PyBytes_Resize(&dest_obj, dest_len);
	if (ret != 0) {
		/*
		 * Don't try to free dest_obj, as we're in deep MemoryError
		 * territory here.
		 */
		return NULL;
	}
	return dest_obj;
}


static PyObject *plain_decompress(PyObject *mod, PyObject *args)
{
	uint8_t *src = NULL;
	Py_ssize_t src_len;
	char *dest = NULL;
	Py_ssize_t dest_len;
	PyObject *dest_obj = NULL;
	Py_ssize_t alloc_len = 0;
	Py_ssize_t given_len = 0;
	int ret;

	if (!PyArg_ParseTuple(args, "s#|n", &src, &src_len, &given_len)) {
		return NULL;
	}
	if (given_len != 0) {
		/*
		 * With plain decompression, we don't *need* the exact output
		 * size (as we do with LZ77+Huffman), but it certainly helps
		 * when guessing the size.
		 */
		alloc_len = given_len;
	} else if (src_len > UINT32_MAX) {
		/*
		 * The underlying decompress function will reject this, but by
		 * checking here we can give a better message and be clearer
		 * about overflow risks.
		 *
		 * Note, the limit is actually the smallest of UINT32_MAX and
		 * SSIZE_MAX, but src_len is ssize_t so it already can't
		 * exceed that.
		 */
		PyErr_Format(CompressionError,
			     "The maximum size for compressed data is 4GB "
			     "cannot decompress %zu bytes.", src_len);
	} else {
		/*
		 * The data can expand massively (though not beyond the
		 * 4GB limit) so we guess a big number for small inputs
		 * (we expect small inputs), and a relatively conservative
		 * number for big inputs.
		 */
		if (src_len <= 3333333) {
			alloc_len = 10000000;
		} else if (src_len > UINT32_MAX / 3) {
			alloc_len = UINT32_MAX;
		} else {
			alloc_len = src_len * 3;
		}
	}

	dest_obj = PyBytes_FromStringAndSize(NULL, alloc_len);
	if (dest_obj == NULL) {
		return NULL;
	}
	dest = PyBytes_AS_STRING(dest_obj);

	dest_len = lzxpress_decompress(src,
				       src_len,
				       (uint8_t *)dest,
				       alloc_len);
	if (dest_len < 0) {
		if (alloc_len == given_len) {
			PyErr_Format(CompressionError,
				     "unable to decompress data into a buffer "
				     "of %zd bytes.", alloc_len);
		} else {
			PyErr_Format(CompressionError,
				     "unable to decompress data into a buffer "
				     "of %zd bytes. If you know the length, "
				     "supply it as the second argument.",
				     alloc_len);
		}
		Py_DECREF(dest_obj);
		return NULL;
	}

	ret = _PyBytes_Resize(&dest_obj, dest_len);
	if (ret != 0) {
		/*
		 * Don't try to free dest_obj, as we're in deep MemoryError
		 * territory here.
		 */
		return NULL;
	}
	return dest_obj;
}



static PyObject *huffman_compress(PyObject *mod, PyObject *args)
{
	uint8_t *src = NULL;
	Py_ssize_t src_len;
	char *dest = NULL;
	Py_ssize_t dest_len;
	PyObject *dest_obj = NULL;
	size_t alloc_len;
	int ret;
	struct lzxhuff_compressor_mem cmp_mem;

	if (!PyArg_ParseTuple(args, "s#", &src, &src_len)) {
		return NULL;
	}
	/*
	 * worst case is roughly 256 per 64k or less.
	 *
	 * alloc_len won't overflow as src_len is ssize_t while alloc_len is
	 * size_t.
	 */
	alloc_len = src_len + src_len / 8 + 500;

	dest_obj = PyBytes_FromStringAndSize(NULL, alloc_len);
	if (dest_obj == NULL) {
		return NULL;
	}
	dest = PyBytes_AS_STRING(dest_obj);

	dest_len = lzxpress_huffman_compress(&cmp_mem,
					     src,
					     src_len,
					     (uint8_t *)dest,
					     alloc_len);
	if (dest_len < 0) {
		PyErr_SetString(CompressionError, "unable to compress data");
		Py_DECREF(dest_obj);
		return NULL;
	}

	ret = _PyBytes_Resize(&dest_obj, dest_len);
	if (ret != 0) {
		return NULL;
	}
	return dest_obj;
}


static PyObject *huffman_decompress(PyObject *mod, PyObject *args)
{
	uint8_t *src = NULL;
	Py_ssize_t src_len;
	char *dest = NULL;
	Py_ssize_t dest_len;
	PyObject *dest_obj = NULL;
	Py_ssize_t given_len = 0;
	/*
	 * Here it is always necessary to supply the exact length.
	 */

	if (!PyArg_ParseTuple(args, "s#n", &src, &src_len, &given_len)) {
		return NULL;
	}

	dest_obj = PyBytes_FromStringAndSize(NULL, given_len);
	if (dest_obj == NULL) {
		return NULL;
	}
	dest = PyBytes_AS_STRING(dest_obj);

	dest_len = lzxpress_huffman_decompress(src,
					       src_len,
					       (uint8_t *)dest,
					       given_len);
	if (dest_len != given_len) {
		PyErr_Format(CompressionError,
			     "unable to decompress data into a %zd bytes.",
			     given_len);
		Py_DECREF(dest_obj);
		return NULL;
	}
	/* no resize here */
	return dest_obj;
}


static PyMethodDef mod_methods[] = {
	{ "plain_compress", (PyCFunction)plain_compress, METH_VARARGS,
		"compress bytes using lzxpress plain compression"},
	{ "plain_decompress", (PyCFunction)plain_decompress, METH_VARARGS,
		"decompress lzxpress plain compressed bytes"},
	{ "huffman_compress", (PyCFunction)huffman_compress, METH_VARARGS,
		"compress bytes using lzxpress plain compression"},
	{ "huffman_decompress", (PyCFunction)huffman_decompress, METH_VARARGS,
		"decompress lzxpress plain compressed bytes"},
	{0}
};


#define MODULE_DOC PyDoc_STR("LZXpress compresssion/decompression bindings")

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "compression",
    .m_doc = MODULE_DOC,
    .m_size = -1,
    .m_methods = mod_methods,
};


static PyObject *module_init(void)
{
	PyObject *m = PyModule_Create(&moduledef);
	if (m == NULL) {
		return NULL;
	}

	CompressionError = PyErr_NewException(
		"compression.CompressionError",
		PyExc_Exception,
		NULL);
	PyModule_AddObject(m, "CompressionError", CompressionError);

	return m;
}

PyMODINIT_FUNC PyInit_compression(void);
PyMODINIT_FUNC PyInit_compression(void)
{
	return module_init();
}
