#!/usr/bin/python
from distutils.core import setup
from distutils.extension import Extension

setup(name='tdb',
      version='1.0',
      url="http://tdb.samba.org/",
      py_modules=["tdb"],
      ext_modules=[Extension('_tdb', ['tdb_wrap.c'], include_dirs=['include'],
          library_dirs=["."], libraries=['tdb'])],
)
