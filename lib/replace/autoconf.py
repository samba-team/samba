# a waf tool to add autoconf-like macros to the configure section

from Configure import conf

@conf
def DEFUN(conf, d, v):
    conf.define(d, v, quote=False)
    conf.env.append_value('CCDEFINES', d + '=' + str(v))

@conf
def CHECK_HEADERS(conf, list):
    for hdr in list.rsplit(' '):
        if conf.check(header_name=hdr):
            conf.env.hlist.append(hdr)

@conf
def CHECK_TYPES(conf, list):
    for t in list.rsplit(' '):
        conf.check(type_name=t, header_name=conf.env.hlist)

@conf
def CHECK_TYPE_IN(conf, t, hdr):
    if conf.check(header_name=hdr):
        conf.check(type_name=t, header_name=hdr)

@conf
def CHECK_TYPE(conf, t, alternate):
    if not conf.check(type_name=t, header_name=conf.env.hlist):
        conf.DEFUN(t, alternate)

@conf
def CHECK_FUNCS(conf, list):
    for f in list.rsplit(' '):
        conf.check(function_name=f, header_name=conf.env.hlist)

@conf
def CHECK_FUNCS_IN(conf, list, library):
    if conf.check(lib=library, uselib_store=library):
        for f in list.rsplit(' '):
            conf.check(function_name=f, lib=library, header_name=conf.env.hlist)

@conf
def check_rpath(conf):
    # this should check if rpath works
    conf.env.append_value('RPATH', '-Wl,-rpath=build/default')

