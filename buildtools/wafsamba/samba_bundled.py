# functions to support bundled libraries

from Configure import conf
from samba_utils import *

@conf
def BUNDLED_LIBRARY_EXTENSION(conf, extension):
    '''set extension to add to bundled libraries'''
    if not 'BUNDLED_EXTENSION' in conf.env:
        conf.env.BUNDLED_EXTENSION = extension

def BUNDLED_NAME(bld, name, bundled_extension):
    '''possibly rename a library to include a bundled extension'''
    if bld.env.DISABLE_SHARED:
        return name
    if bundled_extension and 'BUNDLED_EXTENSION' in bld.env:
        return name + '-' + bld.env.BUNDLED_EXTENSION
    return name


def BUILTIN_LIBRARY(bld, name):
    '''return True if a library should be builtin
       instead of being built as a shared lib'''
    if bld.env.DISABLE_SHARED:
        return True
    if name in bld.env.BUILTIN_LIBRARIES:
        return True
    return False
