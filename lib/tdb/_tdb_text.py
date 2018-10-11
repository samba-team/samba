# Text wrapper for tdb bindings
#
# Copyright (C) 2015 Petr Viktorin <pviktori@redhat.com>
# Published under the GNU LGPLv3 or later

import sys

import tdb


class TdbTextWrapper(object):
    """Text interface for a TDB file"""

    def __init__(self, tdb):
        self._tdb = tdb

    @property
    def raw(self):
        return self._tdb

    def get(self, key):
        key = key.encode('utf-8')
        result = self._tdb.get(key)
        if result is not None:
            return result.decode('utf-8')

    def append(self, key, value):
        key = key.encode('utf-8')
        value = value.encode('utf-8')
        self._tdb.append(key, value)

    def firstkey(self):
        result = self._tdb.firstkey()
        if result:
            return result.decode('utf-8')

    def nextkey(self, key):
        key = key.encode('utf-8')
        result = self._tdb.nextkey(key)
        if result is not None:
            return result.decode('utf-8')

    def delete(self, key):
        key = key.encode('utf-8')
        self._tdb.delete(key)

    def store(self, key, value):
        key = key.encode('utf-8')
        value = value.encode('utf-8')
        self._tdb.store(key, value)

    def __iter__(self):
        for key in iter(self._tdb):
            yield key.decode('utf-8')

    def __getitem__(self, key):
        key = key.encode('utf-8')
        result = self._tdb[key]
        return result.decode('utf-8')

    def __contains__(self, key):
        key = key.encode('utf-8')
        return key in self._tdb

    def __repr__(self):
        return '<TdbTextWrapper for %r>' % self._tdb

    def __setitem__(self, key, value):
        key = key.encode('utf-8')
        value = value.encode('utf-8')
        self._tdb[key] = value

    def __delitem__(self, key):
        key = key.encode('utf-8')
        del self._tdb[key]

    if sys.version_info > (3, 0):
        keys = __iter__
    else:
        iterkeys = __iter__
        has_key = __contains__


## Add wrappers for functions and getters that don't deal with text

def _add_wrapper(name):
    orig = getattr(tdb.Tdb, name)

    def wrapper(self, *args, **kwargs):
        return orig(self._tdb, *args, **kwargs)
    wrapper.__name__ = orig.__name__
    wrapper.__doc__ = orig.__doc__

    setattr(TdbTextWrapper, name, wrapper)

for name in ("transaction_cancel",
             "transaction_commit",
             "transaction_prepare_commit",
             "transaction_start",
             "reopen",
             "lock_all",
             "unlock_all",
             "read_lock_all",
             "read_unlock_all",
             "close",
             "add_flags",
             "remove_flags",
             "clear",
             "repack",
             "enable_seqnum",
             "increment_seqnum_nonblock",
            ):
    _add_wrapper(name)


def _add_getter(name):
    orig = getattr(tdb.Tdb, name)
    doc = orig.__doc__

    def getter(self):
        return getattr(self._tdb, name)

    def setter(self, value):
        return setattr(self._tdb, name, value)

    setattr(TdbTextWrapper, name, property(getter, setter, doc=doc))

for name in ("hash_size",
             "map_size",
             "freelist_size",
             "flags",
             "max_dead",
             "filename",
             "seqnum",
             "text",
            ):
    _add_getter(name)
