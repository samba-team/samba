/* 
   Unix SMB/CIFS implementation.

   Swig interface to ldb.

   Copyright (C) 2005 Tim Potter <tpot@samba.org>
   Copyright (C) 2006 Simo Sorce <idra@samba.org>

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

%module ldb

%{

/* This symbol is used in both includes.h and Python.h which causes an
   annoying compiler warning. */

#ifdef HAVE_FSTAT
#undef HAVE_FSTAT
#endif

#if (__GNUC__ >= 3)
/** Use gcc attribute to check printf fns.  a1 is the 1-based index of
 * the parameter containing the format, and a2 the index of the first
 * argument. Note that some gcc 2.x versions don't handle this
 * properly **/
#define PRINTF_ATTRIBUTE(a1, a2) __attribute__ ((format (__printf__, a1, a2)))
#else
#define PRINTF_ATTRIBUTE(a1, a2)
#endif

/* Include ldb headers */

/* Treat a uint8_t as an unsigned character */
typedef unsigned char uint8_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;

#include "lib/ldb/include/ldb.h"
#include "lib/talloc/talloc.h"

%}

/* The ldb functions will crash if a NULL ldb is passed */

%include exception.i

%typemap(check) struct ldb_context* {
	if ($1 == NULL)
		SWIG_exception(SWIG_ValueError, 
			"ldb context must be non-NULL");
}

/* Use talloc_init() to create a parameter to pass to ldb_init().  Don't
   forget to free it using talloc_free() afterwards. */

TALLOC_CTX *talloc_init(char *name);
int talloc_free(TALLOC_CTX *ptr);

/* In and out typemaps for struct ldb_val.  This is converted to and from
   the Python string datatype. */

%typemap(in) struct ldb_val {
	if (!PyString_Check($input)) {
		PyErr_SetString(PyExc_TypeError, "string arg expected");
		return NULL;
	}
	$1.length = PyString_Size($input);
	$1.data = PyString_AsString($input);
}

%typemap(out) struct ldb_val {
	if ($1.data == NULL && $1.length == 0) {
		$result = Py_None;
	} else {
		$result = PyString_FromStringAndSize($1.data, $1.length);
	}
}

enum ldb_scope {LDB_SCOPE_DEFAULT=-1, 
		LDB_SCOPE_BASE=0, 
		LDB_SCOPE_ONELEVEL=1,
		LDB_SCOPE_SUBTREE=2};

/* Typemap for passing a struct ldb_result by reference */

%typemap(in, numinputs=0) struct ldb_result **OUT (struct ldb_result *temp_ldb_result) {
	$1 = &temp_ldb_result;
}

%typemap(argout) struct ldb_result ** {
	unsigned int i;

	/* XXX: Handle resultobj by throwing an exception if required */

	resultobj = PyList_New((*$1)->count);

	for (i = 0; i < (*$1)->count; i++) {
		PyList_SetItem(resultobj, i, SWIG_NewPointerObj(*$1, SWIGTYPE_p_ldb_message, 0));
	}
}	

%types(struct ldb_result *);

struct ldb_message {
	struct ldb_dn *dn;
	unsigned int num_elements;
	struct ldb_message_element *elements;
	void *private_data; /* private to the backend */
};

/* Wrap ldb functions */

%rename ldb_init init;
struct ldb_context *ldb_init(TALLOC_CTX *mem_ctx);

%rename ldb_connect connect;
int ldb_connect(struct ldb_context *ldb, const char *url, unsigned int flags, const char *options[]);

%rename ldb_search search;
int ldb_search(struct ldb_context *ldb, const struct ldb_dn *base, enum ldb_scope scope, const char *expression, const char * const *attrs, struct ldb_result **OUT);
