# functions to support third party libraries

import os
from waflib import Utils, Build, Context
from waflib.Configure import conf

@conf
def CHECK_FOR_THIRD_PARTY(conf):
    return os.path.exists(os.path.join(Context.g_module.top, 'third_party'))

Build.BuildContext.CHECK_FOR_THIRD_PARTY = CHECK_FOR_THIRD_PARTY

@conf
def CHECK_POPT(conf):
    return conf.CHECK_BUNDLED_SYSTEM('popt', checkfunctions='poptGetContext', headers='popt.h')

Build.BuildContext.CHECK_POPT = CHECK_POPT

@conf
def CHECK_CMOCKA(conf):
    return conf.CHECK_BUNDLED_SYSTEM_PKG('cmocka', minversion='1.1.3')

Build.BuildContext.CHECK_CMOCKA = CHECK_CMOCKA

@conf
def CHECK_SOCKET_WRAPPER(conf):
    return conf.CHECK_BUNDLED_SYSTEM_PKG('socket_wrapper', minversion='1.3.3')
Build.BuildContext.CHECK_SOCKET_WRAPPER = CHECK_SOCKET_WRAPPER

@conf
def CHECK_NSS_WRAPPER(conf):
    return conf.CHECK_BUNDLED_SYSTEM_PKG('nss_wrapper', minversion='1.1.11')
Build.BuildContext.CHECK_NSS_WRAPPER = CHECK_NSS_WRAPPER

@conf
def CHECK_RESOLV_WRAPPER(conf):
    return conf.CHECK_BUNDLED_SYSTEM_PKG('resolv_wrapper', minversion='1.1.7')
Build.BuildContext.CHECK_RESOLV_WRAPPER = CHECK_RESOLV_WRAPPER

@conf
def CHECK_UID_WRAPPER(conf):
    return conf.CHECK_BUNDLED_SYSTEM_PKG('uid_wrapper', minversion='1.2.7')
Build.BuildContext.CHECK_UID_WRAPPER = CHECK_UID_WRAPPER

@conf
def CHECK_PAM_WRAPPER(conf):
    return conf.CHECK_BUNDLED_SYSTEM_PKG('pam_wrapper', minversion='1.1.2')
Build.BuildContext.CHECK_PAM_WRAPPER = CHECK_PAM_WRAPPER
