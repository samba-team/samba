#!/usr/bin/python
from distutils.core import setup
from distutils.extension import Extension
setup(name='ldb',
      version='1.0',
      ext_modules=[Extension('_ldb', ['ldb.i'], include_dirs=['include'],
                             libraries=['ldb','ldap'])],
      )
