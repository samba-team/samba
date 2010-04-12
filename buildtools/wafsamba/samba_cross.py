# functions for handling cross-compilation

import pproc, Utils
from Configure import conf
from pproc import Popen

real_Popen = None

class cross_Popen(Popen):
    '''cross-compilation wrapper for Popen'''
    def __init__(*k, **kw):
        (obj, args) = k
        if '--cross-execute' in args:
            # when --cross-execute is set, then change the arguments
            # to use the cross emulator
            i = args.index('--cross-execute')
            newargs = args[i+1].split()
            newargs.extend(args[0:i])
            args = newargs
        Popen.__init__(*(obj, args), **kw)


@conf
def SAMBA_CROSS_ARGS(conf):
    '''get exec_args to pass when running cross compiled binaries'''
    if not conf.env.CROSS_COMPILE or not conf.env.CROSS_EXECUTE:
        return []

    global real_Popen
    if real_Popen is None:
        real_Popen  = Utils.pproc.Popen
        Utils.pproc.Popen = cross_Popen

    return ['--cross-execute', conf.env.CROSS_EXECUTE]
