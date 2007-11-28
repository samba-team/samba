#!/usr/bin/python
from distutils.core import setup
from distutils.extension import Extension

setup(name="ldb",
      version="1.0",
      url="http://ldb.samba.org/",
      author="LDB Developers",
      author_email="ldb@samba.org",
      license="LGPLv3",
      keywords=["ldap","ldb","db","ldif"],
      py_modules=["ldb"],
      ext_modules=[Extension('_ldb', ['ldb_wrap.c'], include_dirs=['include'],
                             library_dirs=["lib"], libraries=['ldb'])],
      )
