# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Options
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
