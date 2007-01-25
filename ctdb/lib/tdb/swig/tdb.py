# This file was created automatically by SWIG 1.3.28.
# Don't modify this file, modify the SWIG interface instead.
# This file is compatible with both classic and new-style classes.

import _tdb
import new
new_instancemethod = new.instancemethod
def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "thisown"): return self.this.own(value)
    if (name == "this"):
        if type(value).__name__ == 'PySwigObject':
            self.__dict__[name] = value
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static) or hasattr(self,name):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    if (name == "thisown"): return self.this.own()
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError,name

import types
try:
    _object = types.ObjectType
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0
del types


TDB_REPLACE = _tdb.TDB_REPLACE
TDB_INSERT = _tdb.TDB_INSERT
TDB_MODIFY = _tdb.TDB_MODIFY
TDB_DEFAULT = _tdb.TDB_DEFAULT
TDB_CLEAR_IF_FIRST = _tdb.TDB_CLEAR_IF_FIRST
TDB_INTERNAL = _tdb.TDB_INTERNAL
TDB_NOLOCK = _tdb.TDB_NOLOCK
TDB_NOMMAP = _tdb.TDB_NOMMAP
TDB_CONVERT = _tdb.TDB_CONVERT
TDB_BIGENDIAN = _tdb.TDB_BIGENDIAN

open = _tdb.open

open_ex = _tdb.open_ex

reopen = _tdb.reopen

reopen_all = _tdb.reopen_all

logging_function = _tdb.logging_function

error = _tdb.error

errorstr = _tdb.errorstr

fetch = _tdb.fetch

delete = _tdb.delete

store = _tdb.store

append = _tdb.append

close = _tdb.close

firstkey = _tdb.firstkey

nextkey = _tdb.nextkey

traverse = _tdb.traverse

exists = _tdb.exists

lockall = _tdb.lockall

unlockall = _tdb.unlockall

chainlock = _tdb.chainlock

chainunlock = _tdb.chainunlock

dump_all = _tdb.dump_all

printfreelist = _tdb.printfreelist


