# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Options
import Build
from optparse import SUPPRESS_HELP

def SAMBA3_ADD_OPTION(opt, option, help=(), dest=None, default=True,
                      with_name="with", without_name="without"):
    if help == ():
        help = ("Build with %s support" % option)
    if dest is None:
        dest = "with_%s" % option.replace('-', '_')

    with_val = "--%s-%s" % (with_name, option)
    without_val = "--%s-%s" % (without_name, option)

    #FIXME: This is broken and will always default to "default" no matter if
    # --with or --without is chosen.
    opt.add_option(with_val, help=help, action="store_true", dest=dest,
                   default=default)
    opt.add_option(without_val, help=SUPPRESS_HELP, action="store_false",
                   dest=dest)
Options.Handler.SAMBA3_ADD_OPTION = SAMBA3_ADD_OPTION

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
