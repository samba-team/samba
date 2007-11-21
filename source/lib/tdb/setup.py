#!/usr/bin/python
from distutils.core import setup
from distutils.extension import Extension
setup(name='tdb',
      version='1.0',
      ext_modules=[Extension('_tdb', ['tdb.i'], include_dirs=['include'],
      libraries=['tdb'], swig_opts=["-noproxydel"])],
      )
