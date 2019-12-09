# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import os
from waflib import Build
from samba_utils import TO_LIST
from samba_autoconf import library_flags

def SAMBA3_IS_STATIC_MODULE(bld, module):
    '''Check whether module is in static list'''
    if module in bld.env['static_modules']:
        return True
    return False
Build.BuildContext.SAMBA3_IS_STATIC_MODULE = SAMBA3_IS_STATIC_MODULE

def SAMBA3_IS_SHARED_MODULE(bld, module):
    '''Check whether module is in shared list'''
    if module in bld.env['shared_modules']:
        return True
    return False
Build.BuildContext.SAMBA3_IS_SHARED_MODULE = SAMBA3_IS_SHARED_MODULE

def SAMBA3_IS_ENABLED_MODULE(bld, module):
    '''Check whether module is in either shared or static list '''
    return SAMBA3_IS_STATIC_MODULE(bld, module) or SAMBA3_IS_SHARED_MODULE(bld, module)
Build.BuildContext.SAMBA3_IS_ENABLED_MODULE = SAMBA3_IS_ENABLED_MODULE



def s3_fix_kwargs(bld, kwargs):
    '''fix the build arguments for s3 build rules to include the
    necessary includes, subdir and cflags options '''
    s3dir = os.path.join(bld.env.srcdir, 'source3')
    s3reldir = os.path.relpath(s3dir, bld.path.abspath())

    # the extra_includes list is relative to the source3 directory
    extra_includes = [ '.', 'include', 'lib' ]
    # local heimdal paths only included when USING_SYSTEM_KRB5 is not set
    if not bld.CONFIG_SET("USING_SYSTEM_KRB5"):
        extra_includes += [ '../source4/heimdal/lib/com_err',
                            '../source4/heimdal/lib/krb5',
                            '../source4/heimdal/lib/gssapi',
                            '../source4/heimdal/lib/gssapi/gssapi',
                            '../source4/heimdal_build/include',
                            '../bin/default/source4/heimdal/lib/asn1' ]

    if bld.CONFIG_SET('USING_SYSTEM_TDB'):
        (tdb_includes, tdb_ldflags, tdb_cpppath) = library_flags(bld, 'tdb')
        extra_includes += tdb_cpppath
    else:
        extra_includes += [ '../lib/tdb/include' ]

    if bld.CONFIG_SET('USING_SYSTEM_TEVENT'):
        (tevent_includes, tevent_ldflags, tevent_cpppath) = library_flags(bld, 'tevent')
        extra_includes += tevent_cpppath
    else:
        extra_includes += [ '../lib/tevent' ]

    if bld.CONFIG_SET('USING_SYSTEM_TALLOC'):
        (talloc_includes, talloc_ldflags, talloc_cpppath) = library_flags(bld, 'talloc')
        extra_includes += talloc_cpppath
    else:
        extra_includes += [ '../lib/talloc' ]

    if bld.CONFIG_SET('USING_SYSTEM_POPT'):
        (popt_includes, popt_ldflags, popt_cpppath) = library_flags(bld, 'popt')
        extra_includes += popt_cpppath
    else:
        extra_includes += [ '../lib/popt' ]

    # s3 builds assume that they will have a bunch of extra include paths
    includes = []
    for d in extra_includes:
        includes += [ os.path.join(s3reldir, d) ]

    # the rule may already have some includes listed
    if 'includes' in kwargs:
        includes += TO_LIST(kwargs['includes'])
    kwargs['includes'] = includes

# these wrappers allow for mixing of S3 and S4 build rules in the one build

def SAMBA3_LIBRARY(bld, name, *args, **kwargs):
    s3_fix_kwargs(bld, kwargs)
    return bld.SAMBA_LIBRARY(name, *args, **kwargs)
Build.BuildContext.SAMBA3_LIBRARY = SAMBA3_LIBRARY

def SAMBA3_MODULE(bld, name, *args, **kwargs):
    s3_fix_kwargs(bld, kwargs)
    return bld.SAMBA_MODULE(name, *args, **kwargs)
Build.BuildContext.SAMBA3_MODULE = SAMBA3_MODULE

def SAMBA3_SUBSYSTEM(bld, name, *args, **kwargs):
    s3_fix_kwargs(bld, kwargs)
    return bld.SAMBA_SUBSYSTEM(name, *args, **kwargs)
Build.BuildContext.SAMBA3_SUBSYSTEM = SAMBA3_SUBSYSTEM

def SAMBA3_BINARY(bld, name, *args, **kwargs):
    s3_fix_kwargs(bld, kwargs)
    return bld.SAMBA_BINARY(name, *args, **kwargs)
Build.BuildContext.SAMBA3_BINARY = SAMBA3_BINARY

def SAMBA3_PYTHON(bld, name, *args, **kwargs):
    s3_fix_kwargs(bld, kwargs)
    return bld.SAMBA_PYTHON(name, *args, **kwargs)
Build.BuildContext.SAMBA3_PYTHON = SAMBA3_PYTHON
