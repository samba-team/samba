# Text wrapper for ldb bindings
#
# Copyright (C) 2015 Petr Viktorin <pviktori@redhat.com>
# Published under the GNU LGPLv3 or later

import ldb


def _recursive_encode(obj):
    if isinstance(obj, bytes):
        return obj
    elif isinstance(obj, str):
        return obj.encode('utf-8')
    else:
        return [_recursive_encode(o) for o in obj]


class _WrapBase(object):

    @classmethod
    def _wrap(cls, wrapped):
        self = cls.__new__(cls)
        self._wrapped = wrapped
        return self

    def __len__(self):
        return len(self._wrapped)

    def __eq__(self, other):
        if hasattr(other, '_wrapped'):
            return self._wrapped == other._wrapped
        else:
            return self._wrapped == other

    def __ne__(self, other):
        if hasattr(other, '_wrapped'):
            return self._wrapped != other._wrapped
        else:
            return self._wrapped != other

    def __lt__(self, other):
        if hasattr(other, '_wrapped'):
            return self._wrapped < other._wrapped
        else:
            return self._wrapped < other

    def __le__(self, other):
        if hasattr(other, '_wrapped'):
            return self._wrapped >= other._wrapped
        else:
            return self._wrapped >= other

    def __gt__(self, other):
        if hasattr(other, '_wrapped'):
            return self._wrapped > other._wrapped
        else:
            return self._wrapped > other

    def __ge__(self, other):
        if hasattr(other, '_wrapped'):
            return self._wrapped >= other._wrapped
        else:
            return self._wrapped >= other

    def __repr__(self):
        return '%s.text' % repr(self._wrapped)


class MessageElementTextWrapper(_WrapBase):

    """Text interface for a LDB message element"""

    def __iter__(self):
        for item in self._wrapped:
            yield item.decode('utf-8')

    def __getitem__(self, key):
        result = self._wrapped[key]
        if result is None:
            return None
        else:
            return result.decode('utf-8')

    @property
    def flags(self):
        return self._wrapped.flags

    @property
    def set_flags(self):
        return self._wrapped.set_flags


_wrap_element = MessageElementTextWrapper._wrap


class MessageTextWrapper(_WrapBase):

    """Text interface for a LDB message"""

    def __getitem__(self, key):
        result = self._wrapped[key]
        if result is None:
            return None
        else:
            return _wrap_element(result)

    def get(self, *args, **kwargs):
        result = self._wrapped.get(*args, **kwargs)
        if isinstance(result, ldb.MessageElement):
            return _wrap_element(result)
        elif isinstance(result, bytes):
            return result.decode('utf-8')
        else:
            return result

    def __setitem__(self, key, item):
        self._wrapped[key] = _recursive_encode(item)

    def __delitem__(self, key):
        del self._wrapped[key]

    def elements(self):
        return [_wrap_element(el) for el in self._wrapped.elements()]

    def items(self):
        return [(attr, _wrap_element(el)) for attr, el in self._wrapped.items()]

    @property
    def keys(self):
        return self._wrapped.keys

    @property
    def remove(self):
        return self._wrapped.remove

    @property
    def add(self):
        return self._wrapped.add

    @property
    def dn(self):
        return self._wrapped.dn

    @dn.setter
    def dn(self, new_value):
        self._wrapped.dn = new_value
