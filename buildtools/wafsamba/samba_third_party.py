# functions to support third party libraries

from Configure import conf
import sys, Logs, os
from samba_bundled import *

@conf
def CHECK_FOR_THIRD_PARTY(conf):
    return os.path.exists('third_party')

Build.BuildContext.CHECK_FOR_THIRD_PARTY = CHECK_FOR_THIRD_PARTY

@conf
def CHECK_INIPARSER(conf):
    return conf.CHECK_BUNDLED_SYSTEM('iniparser', checkfunctions='iniparser_load', headers='iniparser.h')
