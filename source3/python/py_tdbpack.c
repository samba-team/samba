/* -*- c-file-style: "python"; indent-tabs-mode: nil; -*-
	 
   Python wrapper for Samba tdb pack/unpack functions
   Copyright (C) Martin Pool 2002


   NOTE PYTHON STYLE GUIDE
   http://www.python.org/peps/pep-0007.html
   
   
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



#include "Python.h"

static int pytdbpack_calc_reqd_len(char *format_str,
				   PyObject *val_seq);

static PyObject *pytdbpack_unpack_item(char, char **pbuf, int *plen, PyObject *);

static PyObject *pytdbpack_pack_data(const char *format_str,
				     PyObject *val_seq,
				     unsigned char *buf);




static PyObject *pytdbpack_bad_type(char ch,
				    const char *expected,
				    PyObject *val_obj);

static const char * pytdbpack_docstring =
"Convert between Python values and Samba binary encodings.

This module is conceptually similar to the standard 'struct' module, but it
uses both a different binary format and a different description string.

Samba's encoding is based on that used inside DCE-RPC and SMB: a
little-endian, unpadded, non-self-describing binary format.  It is intended
that these functions be as similar as possible to the routines in Samba's
tdb/tdbutil module, with appropriate adjustments for Python datatypes.

Python strings are used to specify the format of data to be packed or
unpacked.

Strings in TDBs are typically stored in DOS codepages.  The caller of this
module must make appropriate translations if necessary, typically to and from
Unicode objects.

tdbpack format strings:

    'f':  NULL-terminated string in DOS codepage

    'P':  same as 'f'

    'd':  4 byte little-endian unsigned number

    'w':  2 byte little-endian unsigned number

    'P': \"Pointer\" value -- in the subset of DCERPC used by Samba, this is
          really just an \"exists\" or \"does not exist\" flag.  The boolean
          value of the Python object is used.
    
    'B': 4-byte LE length, followed by that many bytes of binary data.
         Corresponds to a Python integer giving the length, followed by a byte
         string of the appropriate length.

    '$': Special flag indicating that the preceding format code should be
         repeated while data remains.  This is only supported for unpacking.

    Every code corresponds to a single Python object, except 'B' which
    corresponds to two values (length and contents), and '$', which produces
    however many make sense.
";


static char const pytdbpack_pack_doc[] = 
"pack(format, values) -> buffer
Pack Python objects into Samba binary format according to format string.

arguments:
    format -- string of tdbpack format characters
    values -- sequence of value objects corresponding 1:1 to format characters

returns:
    buffer -- string containing packed data

raises:
    IndexError -- if there are too few values for the format
    ValueError -- if any of the format characters is illegal
    TypeError  -- if the format is not a string, or values is not a sequence,
        or any of the values is of the wrong type for the corresponding
        format character

notes:
    For historical reasons, it is not an error to pass more values than are consumed
    by the format.
";


static char const pytdbpack_unpack_doc[] =
"unpack(format, buffer) -> (values, rest)
Unpack Samba binary data according to format string.

arguments:
    format -- string of tdbpack characters
    buffer -- string of packed binary data

returns:
    2-tuple of:
        values -- sequence of values corresponding 1:1 to format characters
        rest -- string containing data that was not decoded, or '' if the
            whole string was consumed

raises:
    IndexError -- if there is insufficient data in the buffer for the
        format (or if the data is corrupt and contains a variable-length
        field extending past the end)
    ValueError -- if any of the format characters is illegal

notes:
    Because unconsumed data is returned, you can feed it back in to the
    unpacker to extract further fields.  Alternatively, if you wish to modify
    some fields near the start of the data, you may be able to save time by
    only unpacking and repacking the necessary part.
";



/*
  Game plan is to first of all walk through the arguments and calculate the
  total length that will be required.  We allocate a Python string of that
  size, then walk through again and fill it in.

  We just borrow references to all the passed arguments, since none of them
  need to be permanently stored.  We transfer ownership to the returned
  object.
 */	
static PyObject *
pytdbpack_pack(PyObject *self,
	       PyObject *args)
{
	char *format_str;
	PyObject *val_seq, *fast_seq, *buf_str;
	int reqd_len;
	char *packed_buf;

	/* TODO: Test passing wrong types or too many arguments */
	if (!PyArg_ParseTuple(args, "sO", &format_str, &val_seq))
		return NULL;

	/* Convert into a list or tuple (if not already one), so that we can
	 * index more easily. */
	fast_seq = PySequence_Fast(val_seq,
				   __FUNCTION__ ": argument 2 must be sequence");
	if (!fast_seq)
		return NULL;
			
	reqd_len = pytdbpack_calc_reqd_len(format_str, fast_seq);
	if (reqd_len == -1)	/* exception was thrown */
		return NULL;

	/* Allocate space.
	 
	   This design causes an unnecessary copying of the data when Python
	   constructs an object, and that might possibly be avoided by using a
	   Buffer object of some kind instead.  I'm not doing that for now
	   though.  */
	packed_buf = malloc(reqd_len);
	if (!packed_buf) {
		PyErr_Format(PyExc_MemoryError,
			     "%s: couldn't allocate %d bytes for packed buffer",
			     __FUNCTION__, reqd_len);
		return NULL;
	}	
	
	if (!pytdbpack_pack_data(format_str, fast_seq, packed_buf)) {
		free(packed_buf);
		return NULL;
	}

	buf_str = PyString_FromStringAndSize(packed_buf, reqd_len);
	free(packed_buf);	/* get rid of tmp buf */
	
	return buf_str;
}



static PyObject *
pytdbpack_unpack(PyObject *self,
		 PyObject *args)
{
	char *format_str, *packed_str, *ppacked;
	PyObject *val_list = NULL, *ret_tuple = NULL;
	PyObject *rest_string = NULL;
	int format_len, packed_len;
	int i;
	char last_format = '#';
	
	/* get arguments */
	if (!PyArg_ParseTuple(args, "ss#", &format_str, &packed_str, &packed_len))
		return NULL;

	format_len = strlen(format_str);
	
	/* Allocate list to hold results.  Initially empty, and we append
	   results as we go along. */
	val_list = PyList_New(0);
	if (!val_list)
		goto failed;
	ret_tuple = PyTuple_New(2);
	if (!ret_tuple)
		goto failed;
	
	/* For every object, unpack.  */
	for (ppacked = packed_str, i = 0; i < format_len; i++) {
		char format;

		format = format_str[i];
		if (format == '$') {
			if (i == 0) {
				PyErr_Format(PyExc_ValueError,
					     "%s: '$' may not be first character in format",
					     __FUNCTION__);
				goto failed;
			}
			else {
				format = last_format; /* repeat */
			}
		}

		if (!pytdbpack_unpack_item(format, &ppacked, &packed_len, val_list))
			goto failed;
		
		last_format = format;
	}

	/* save leftovers for next time */
	rest_string = PyString_FromStringAndSize(ppacked, packed_len);
	if (!rest_string)
		goto failed;

	/* return (values, rest) tuple; give up references to them */
	PyTuple_SET_ITEM(ret_tuple, 0, val_list);
	val_list = NULL;
	PyTuple_SET_ITEM(ret_tuple, 1, rest_string);
	val_list = NULL;
	return ret_tuple;

  failed:
	/* handle failure: deallocate anything.  XDECREF forms handle NULL
	   pointers for objects that haven't been allocated yet. */
	Py_XDECREF(val_list);
	Py_XDECREF(ret_tuple);
	Py_XDECREF(rest_string);
	return NULL;
}


/*
  Internal routine that calculates how many bytes will be required to
  encode the values in the format.

  Also checks that the value list is the right size for the format list.

  Returns number of bytes (may be 0), or -1 if there's something wrong, in
  which case a Python exception has been raised.

  Arguments:

    val_seq: a Fast Sequence (list or tuple), being all the values
*/
static int
pytdbpack_calc_reqd_len(char *format_str,
			PyObject *val_seq)
{
	int len = 0;
	char *p;
	int val_i;
	int val_len;

	val_len = PySequence_Length(val_seq);
	if (val_len == -1)
		return -1;

	for (p = format_str, val_i = 0; *p; p++, val_i++) {
		char ch = *p;

		if (val_i >= val_len) {
			PyErr_Format(PyExc_IndexError,
				     "%s: value list is too short for format string",
				     __FUNCTION__);
			return -1;
		}

		/* borrow a reference to the item */
		if (ch == 'd' || ch == 'p') 
			len += 4;
		else if (ch == 'w')
			len += 2;
		else if (ch == 'f' || ch == 'P') {
			/* nul-terminated 8-bit string */
			int item_len;
			PyObject *str_obj;

			str_obj = PySequence_GetItem(val_seq, val_i);
			if (!str_obj)
				return -1;

			if (!PyString_Check(str_obj) || ((item_len = PyString_Size(str_obj)) == -1)) {
				pytdbpack_bad_type(ch, "String", str_obj);
				return -1;
			}
			
			len += 1 + item_len;
		}
		else if (ch == 'B') {
			/* length-preceded byte buffer: n bytes, plus a preceding
			 * word */
			PyObject *len_obj;
			long len_val;

			len_obj = PySequence_GetItem(val_seq, val_i);
			val_i++; /* skip over buffer */

			if (!PyNumber_Check(len_obj)) {
				pytdbpack_bad_type(ch, "Number", len_obj);
				return -1;
			}

			len_val = PyInt_AsLong(len_obj);
			if (len_val < 0) {
				PyErr_Format(PyExc_ValueError,
					     "%s: format 'B' requires positive integer", __FUNCTION__);
				return -1;
			}

			len += 4 + len_val;
		}
		else {	
			PyErr_Format(PyExc_ValueError,
				     "%s: format character '%c' is not supported",
				     __FUNCTION__, ch);
		
			return -1;
		}
	}

	return len;
}


static PyObject *pytdbpack_bad_type(char ch,
				    const char *expected,
				    PyObject *val_obj)
{
	PyObject *r = PyObject_Repr(val_obj);
	if (!r)
		return NULL;
	PyErr_Format(PyExc_TypeError,
		     "tdbpack: format '%c' requires %s, not %s",
		     ch, expected, PyString_AS_STRING(r));
	Py_DECREF(r);
	return val_obj;
}


/*
  XXX: glib and Samba have quicker macro for doing the endianness conversions,
  but I don't know of one in plain libc, and it's probably not a big deal.  I
  realize this is kind of dumb because we'll almost always be on x86, but
  being safe is important.
*/
static void pack_uint32(unsigned long val_long, unsigned char **pbuf)
{
	(*pbuf)[0] =         val_long & 0xff;
	(*pbuf)[1] = (val_long >> 8)  & 0xff;
	(*pbuf)[2] = (val_long >> 16) & 0xff;
	(*pbuf)[3] = (val_long >> 24) & 0xff;
	(*pbuf) += 4;
}


static void pack_bytes(long len, const char *from,
		       unsigned char **pbuf)
{
	memcpy(*pbuf, from, len);
	(*pbuf) += len;
}


static void
unpack_err_too_short(void)
{
	PyErr_Format(PyExc_IndexError,
		     __FUNCTION__ ": data too short for unpack format");
}


static PyObject *
unpack_uint32(char **pbuf, int *plen)
{
	unsigned long v;
	unsigned char *b;
	
	if (*plen < 4) {
		unpack_err_too_short();
		return NULL;
	}

	b = *pbuf;
	v = b[0] | b[1]<<8 | b[2]<<16 | b[3]<<24;
	
	(*pbuf) += 4;
	(*plen) -= 4;

	return PyLong_FromUnsignedLong(v);
}


static PyObject *unpack_int16(char **pbuf, int *plen)
{
	long v;
	unsigned char *b;
	
	if (*plen < 2) {
		unpack_err_too_short();
		return NULL;
	}

	b = *pbuf;
	v = b[0] | b[1]<<8;
	
	(*pbuf) += 2;
	(*plen) -= 2;

	return PyInt_FromLong(v);
}


static PyObject *
unpack_string(char **pbuf, int *plen)
{
	int len;
	char *nul_ptr, *start;

	start = *pbuf;
	
	nul_ptr = memchr(start, '\0', *plen);
	if (!nul_ptr) {
		unpack_err_too_short();
		return NULL;
	}

	len = nul_ptr - start;

	*pbuf += len + 1;	/* skip \0 */
	*plen -= len + 1;

	return PyString_FromStringAndSize(start, len);
}


static PyObject *
unpack_buffer(char **pbuf, int *plen, PyObject *val_list)
{
	/* first get 32-bit len */
	long slen;
	unsigned char *b;
	unsigned char *start;
	PyObject *str_obj = NULL, *len_obj = NULL;
	
	if (*plen < 4) {
		unpack_err_too_short();
		return NULL;
	}
	
	b = *pbuf;
	slen = b[0] | b[1]<<8 | b[2]<<16 | b[3]<<24;

	if (slen < 0) { /* surely you jest */
		PyErr_Format(PyExc_ValueError,
			     __FUNCTION__ ": buffer seems to have negative length");
		return NULL;
	}

	(*pbuf) += 4;
	(*plen) -= 4;
	start = *pbuf;

	if (*plen < slen) {
		PyErr_Format(PyExc_IndexError,
			     __FUNCTION__ ": not enough data to unpack buffer: "
			     "need %d bytes, have %d",
			     (int) slen, *plen);
		return NULL;
	}

	(*pbuf) += slen;
	(*plen) -= slen;

	if (!(len_obj = PyInt_FromLong(slen)))
		goto failed;

	if (PyList_Append(val_list, len_obj) == -1)
		goto failed;
	
	if (!(str_obj = PyString_FromStringAndSize(start, slen)))
		goto failed;
	
	if (PyList_Append(val_list, str_obj) == -1)
		goto failed;
	
	return val_list;

  failed:
	Py_XDECREF(len_obj);	/* handles NULL */
	Py_XDECREF(str_obj);
	return NULL;
}


/* Unpack a single field from packed data, according to format character CH.
   Remaining data is at *PBUF, of *PLEN.

   *PBUF is advanced, and *PLEN reduced to reflect the amount of data that has
   been consumed.

   Returns a reference to None, or NULL for failure.
*/
static PyObject *pytdbpack_unpack_item(char ch,
				       char **pbuf,
				       int *plen,
				       PyObject *val_list)
{
	PyObject *result;
	
	if (ch == 'w') {	/* 16-bit int */
		result = unpack_int16(pbuf, plen);
	}
	else if (ch == 'd' || ch == 'p') { /* 32-bit int */
		/* pointers can just come through as integers */
		result = unpack_uint32(pbuf, plen);
	}
	else if (ch == 'f' || ch == 'P') { /* nul-term string  */
		result = unpack_string(pbuf, plen);
	}
	else if (ch == 'B') { /* length, buffer */
		return unpack_buffer(pbuf, plen, val_list);
	}
	else {
		PyErr_Format(PyExc_ValueError,
			     __FUNCTION__ ": format character '%c' is not supported",
			     ch);
		
		return NULL;
	}

	/* otherwise OK */
	if (!result)
		return NULL;
	if (PyList_Append(val_list, result) == -1)
		return NULL;
	
	return val_list;
}




/*
  Pack data according to FORMAT_STR from the elements of VAL_SEQ into
  PACKED_BUF.

  The string has already been checked out, so we know that VAL_SEQ is large
  enough to hold the packed data, and that there are enough value items.
  (However, their types may not have been thoroughly checked yet.)

  In addition, val_seq is a Python Fast sequence.

  Returns NULL for error (with exception set), or None.
*/
PyObject *
pytdbpack_pack_data(const char *format_str,
		    PyObject *val_seq,
		    unsigned char *packed)
{
	int format_i, val_i = 0;

	for (format_i = 0, val_i = 0; format_str[format_i]; format_i++) {
		char ch = format_str[format_i];
		PyObject *val_obj;

		/* borrow a reference to the item */
		val_obj = PySequence_GetItem(val_seq, val_i++);
		if (!val_obj)
			return NULL;

		if (ch == 'w') {
			unsigned long val_long;
			PyObject *long_obj;
			
			if (!(long_obj = PyNumber_Long(val_obj))) {
				pytdbpack_bad_type(ch, "Long", val_obj);
				return NULL;
			}
			
			val_long = PyLong_AsUnsignedLong(long_obj);
			(packed)[0] = val_long & 0xff;
			(packed)[1] = (val_long >> 8) & 0xff;
			(packed) += 2;
			Py_DECREF(long_obj);
		}
		else if (ch == 'd') {
			/* 4-byte LE number */
			PyObject *long_obj;
			
			if (!(long_obj = PyNumber_Long(val_obj))) {
				pytdbpack_bad_type(ch, "Long", val_obj);
				return NULL;
			}
			
			pack_uint32(PyLong_AsUnsignedLong(long_obj), &packed);

			Py_DECREF(long_obj);
		}
		else if (ch == 'p') {
			/* "Pointer" value -- in the subset of DCERPC used by Samba,
			   this is really just an "exists" or "does not exist"
			   flag. */
			pack_uint32(PyObject_IsTrue(val_obj), &packed);
		}
		else if (ch == 'f' || ch == 'P') {
			int size;
			char *sval;

			size = PySequence_Length(val_obj);
			if (size < 0)
				return NULL;
			sval = PyString_AsString(val_obj);
			if (!sval)
				return NULL;
			pack_bytes(size+1, sval, &packed); /* include nul */
		}
		else if (ch == 'B') {
			long size;
			char *sval;

			if (!PyInt_Check(val_obj))
				return NULL;

			size = PyInt_AsLong(val_obj);
			pack_uint32(size, &packed);

			val_obj = PySequence_GetItem(val_seq, val_i++);
			if (!val_obj)
				return NULL;
			
			sval = PyString_AsString(val_obj);
			if (!sval)
				return NULL;
			
			pack_bytes(size, sval, &packed); /* do not include nul */
		}
		else {
			/* this ought to be caught while calculating the length, but
			   just in case. */
			PyErr_Format(PyExc_ValueError,
				     "%s: format character '%c' is not supported",
				     __FUNCTION__, ch);
		
			return NULL;
		}
	}
		
	return Py_None;
}



static PyMethodDef pytdbpack_methods[] = {
	{ "pack", pytdbpack_pack, METH_VARARGS, (char *) pytdbpack_pack_doc },
	{ "unpack", pytdbpack_unpack, METH_VARARGS, (char *) pytdbpack_unpack_doc },
};

DL_EXPORT(void)
inittdbpack(void)
{
	Py_InitModule3("tdbpack", pytdbpack_methods,
		       (char *) pytdbpack_docstring);
}
