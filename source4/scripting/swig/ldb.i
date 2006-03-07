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

%}

/* The ldb functions will crash if a NULL tdb is passed */

%include exception.i

%typemap(check) struct ldb_context* {
	if ($1 == NULL)
		SWIG_exception(SWIG_ValueError, 
			"ldb context must be non-NULL");
}

/* Throw an IOError exception if tdb_open() or tdb_open_ex() returns NULL */

%exception {
	$action
	if (result == NULL) {
		PyErr_SetFromErrno(PyExc_IOError);
		SWIG_fail;
	}
}


%rename ldb_init init;
struct ldb_context *ldb_init(void *mem_ctx);

%rename ldb_connect connect;
int ldb_connect(struct ldb_context *ldb, const char *url, unsigned int flags, const char *options[]);

%rename ldb_request request;
int ldb_request(struct ldb_context *ldb, struct ldb_request *request);
