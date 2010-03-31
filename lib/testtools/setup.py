#!/usr/bin/env python
"""Distutils installer for testtools."""

from distutils.core import setup
import testtools
version = '.'.join(str(component) for component in testtools.__version__[0:3])
phase = testtools.__version__[3]
if phase != 'final':
    import bzrlib.workingtree
    t = bzrlib.workingtree.WorkingTree.open_containing(__file__)[0]
    if phase == 'alpha':
        # No idea what the next version will be
        version = 'next-%s' % t.branch.revno()
    else:
        # Preserve the version number but give it a revno prefix
        version = version + '~%s' % t.branch.revno()

setup(name='testtools',
      author='Jonathan M. Lange',
      author_email='jml+testtools@mumak.net',
      url='https://launchpad.net/testtools',
      description=('Extensions to the Python standard library unit testing '
                   'framework'),
      version=version,
      packages=['testtools', 'testtools.testresult', 'testtools.tests'])
