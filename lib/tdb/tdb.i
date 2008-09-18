/* 
   Unix SMB/CIFS implementation.

   Swig interface to tdb.

   Copyright (C) 2004-2006 Tim Potter <tpot@samba.org>
   Copyright (C) 2007 Jelmer Vernooij <jelmer@samba.org>

     ** NOTE! The following LGPL license applies to the tdb
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

%define DOCSTRING
"TDB is a simple key-value database similar to GDBM that supports multiple writers."
%enddef

%module(docstring=DOCSTRING) tdb

%{

/* This symbol is used in both includes.h and Python.h which causes an
   annoying compiler warning. */

#ifdef HAVE_FSTAT
#undef HAVE_FSTAT
#endif

/* Include tdb headers */
#include <stdint.h>
#include <signal.h>
#include <tdb.h>
#include <fcntl.h>

typedef TDB_CONTEXT tdb;
%}

/* The tdb functions will crash if a NULL tdb context is passed */

%import exception.i
%import stdint.i

%typemap(check,noblock=1) TDB_CONTEXT* {
	if ($1 == NULL)
		SWIG_exception(SWIG_ValueError, 
			"tdb context must be non-NULL");
}

/* In and out typemaps for the TDB_DATA structure.  This is converted to
   and from the Python string type which can contain arbitrary binary
   data.. */

%typemap(in,noblock=1) TDB_DATA {
    if ($input == Py_None) {
        $1.dsize = 0;
        $1.dptr = NULL;
    } else if (!PyString_Check($input)) {
		PyErr_SetString(PyExc_TypeError, "string arg expected");
		return NULL;
	} else {
        $1.dsize = PyString_Size($input);
        $1.dptr = (uint8_t *)PyString_AsString($input);
    }
}

%typemap(out,noblock=1) TDB_DATA {
	if ($1.dptr == NULL && $1.dsize == 0) {
		$result = Py_None;
	} else {
		$result = PyString_FromStringAndSize((const char *)$1.dptr, $1.dsize);
		free($1.dptr);
    }
}

/* Treat a mode_t as an unsigned integer */
typedef int mode_t;

/* flags to tdb_store() */
%constant int REPLACE = TDB_REPLACE;
%constant int INSERT = TDB_INSERT;
%constant int MODIFY = TDB_MODIFY;

/* flags for tdb_open() */
%constant int DEFAULT = TDB_DEFAULT;
%constant int CLEAR_IF_FIRST = TDB_CLEAR_IF_FIRST;
%constant int INTERNAL = TDB_INTERNAL;
%constant int NOLOCK = TDB_NOLOCK;
%constant int NOMMAP = TDB_NOMMAP;
%constant int CONVERT = TDB_CONVERT;
%constant int BIGENDIAN = TDB_BIGENDIAN;

enum TDB_ERROR {
     TDB_SUCCESS=0, 
     TDB_ERR_CORRUPT, 
     TDB_ERR_IO, 
     TDB_ERR_LOCK, 
     TDB_ERR_OOM, 
     TDB_ERR_EXISTS, 
     TDB_ERR_NOLOCK, 
     TDB_ERR_LOCK_TIMEOUT,
     TDB_ERR_NOEXIST, 
     TDB_ERR_EINVAL, 
     TDB_ERR_RDONLY
};

%rename(lock_all) tdb_context::lockall;
%rename(unlock_all) tdb_context::unlockall;

%rename(read_lock_all) tdb_context::lockall_read;
%rename(read_unlock_all) tdb_context::unlockall_read;

%typemap(default,noblock=1) int tdb_flags {
    $1 = TDB_DEFAULT;
}

%typemap(default,noblock=1) int flags {
    $1 = O_RDWR;
}

%typemap(default,noblock=1) int hash_size {
    $1 = 0;
}

%typemap(default,noblock=1) mode_t mode {
    $1 = 0600;
}

%typemap(default,noblock=1) int flag {
    $1 = TDB_REPLACE;
}

%rename(Tdb) tdb_context;
%feature("docstring") tdb_context "A TDB file.";
%typemap(out,noblock=1) tdb * {
    /* Throw an IOError exception from errno if tdb_open() returns NULL */
    if ($1 == NULL) {
        PyErr_SetFromErrno(PyExc_IOError);
        SWIG_fail;
    }
    $result = SWIG_NewPointerObj($1, $1_descriptor, 0);
}

typedef struct tdb_context {
    %extend {
        %feature("docstring") tdb "S.__init__(name,hash_size=0,tdb_flags=TDB_DEFAULT,flags=O_RDWR,mode=0600)\n"
                                  "Open a TDB file.";
        tdb(const char *name, int hash_size, int tdb_flags, int flags, mode_t mode) {
            return tdb_open(name, hash_size, tdb_flags, flags, mode);
        }
        %feature("docstring") error "S.error() -> int\n"
                                    "Find last error number returned by operation on this TDB.";
        enum TDB_ERROR error();
        ~tdb() { tdb_close($self); }
        %feature("docstring") close "S.close() -> None\n"
                                    "Close the TDB file.";
        int close();
        int append(TDB_DATA key, TDB_DATA new_dbuf);
        %feature("docstring") errorstr "S.errorstr() -> errorstring\n"
                                        "Obtain last error message.";
        const char *errorstr();
        %rename(get) fetch;
        %feature("docstring") fetch "S.fetch(key) -> value\n"
                                        "Fetch a value.";
        TDB_DATA fetch(TDB_DATA key);
        %feature("docstring") delete "S.delete(key) -> None\n"
                                        "Delete an entry.";
        int delete(TDB_DATA key);
        %feature("docstring") store "S.store(key, value, flag=TDB_REPLACE) -> None\n"
                                        "Store an entry.";
        int store(TDB_DATA key, TDB_DATA dbuf, int flag);
        %feature("docstring") exists "S.exists(key) -> bool\n"
                                        "Check whether key exists in this database.";
        int exists(TDB_DATA key);
        %feature("docstring") firstkey "S.firstkey() -> data\n"
                                        "Return the first key in this database.";
        TDB_DATA firstkey();
        %feature("docstring") nextkey "S.nextkey(prev) -> data\n"
                                        "Return the next key in this database.";
        TDB_DATA nextkey(TDB_DATA key);
        %feature("docstring") lockall "S.lockall() -> bool";
        int lockall();
        %feature("docstring") unlockall "S.unlockall() -> bool";
        int unlockall();
        %feature("docstring") unlockall "S.lockall_read() -> bool";
        int lockall_read();
        %feature("docstring") unlockall "S.unlockall_read() -> bool";
        int unlockall_read();
        %feature("docstring") reopen "S.reopen() -> bool\n"
                                        "Reopen this file.";
        int reopen();
        %feature("docstring") transaction_start "S.transaction_start() -> None\n"
                                        "Start a new transaction.";
        int transaction_start();
        %feature("docstring") transaction_commit "S.transaction_commit() -> None\n"
                                        "Commit the currently active transaction.";
        int transaction_commit();
        %feature("docstring") transaction_cancel "S.transaction_cancel() -> None\n"
                                        "Cancel the currently active transaction.";
        int transaction_cancel();
        int transaction_recover();
        %feature("docstring") hash_size "S.hash_size() -> int";
        int hash_size();
        %feature("docstring") map_size "S.map_size() -> int";
        size_t map_size();
        %feature("docstring") get_flags "S.get_flags() -> int";
        int get_flags();
        %feature("docstring") set_max_dead "S.set_max_dead(int) -> None";
        void set_max_dead(int max_dead);
        %feature("docstring") name "S.name() -> path\n" \
                                   "Return filename of this TDB file.";
        const char *name();
    }

    %pythoncode {
    def __repr__(self):
        return "Tdb('%s')" % self.name()

    # Random access to keys, values
    def __getitem__(self, key):
        result = self.get(key)
        if result is None:
            raise KeyError, '%s: %s' % (key, self.errorstr())
        return result

    def __setitem__(self, key, item):
        if self.store(key, item) == -1:
            raise IOError, self.errorstr()

    def __delitem__(self, key):
        if not self.exists(key):
            raise KeyError, '%s: %s' % (key, self.errorstr())
        self.delete(key)

    def __contains__(self, key):
        return self.exists(key) != 0

    def has_key(self, key):
        return self.exists(key) != 0

    def fetch_uint32(self, key):
        data = self.get(key)
        if data is None:
            return None
        import struct
        return struct.unpack("<L", data)[0]

    def fetch_int32(self, key):
        data = self.get(key)
        if data is None:
            return None
        import struct
        return struct.unpack("<l", data)[0]

    # Tdb iterator
    class TdbIterator:
        def __init__(self, tdb):
            self.tdb = tdb
            self.key = None

        def __iter__(self):
            return self
            
        def next(self):
            if self.key is None:
                self.key = self.tdb.firstkey()
                if self.key is None:
                    raise StopIteration
                return self.key
            else:
                self.key = self.tdb.nextkey(self.key)
                if self.key is None:
                    raise StopIteration
                return self.key

    def __iter__(self):
        return self.TdbIterator(self)

    # Implement other dict functions using TdbIterator

    def keys(self):
        return [k for k in iter(self)]

    def values(self):
        return [self[k] for k in iter(self)]

    def items(self):
        return [(k, self[k]) for k in iter(self)]

    def __len__(self):
        return len(self.keys())

    def clear(self):
        for k in iter(self):
            del(self[k])

    def iterkeys(self):
        for k in iter(self):
            yield k
       
    def itervalues(self):
        for k in iter(self):
            yield self[k]

    def iteritems(self):
        for k in iter(self):
            yield (k, self[k])

    # TODO: any other missing methods for container types
    }
} tdb;
