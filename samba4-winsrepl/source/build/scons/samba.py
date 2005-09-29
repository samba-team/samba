#!/usr/bin/python

import SCons.Defaults
import SCons.Util

# Samba contains different "subsystems":
# - binaries. Program()
#   receive list of component init functions
# - "real" subsystems (that you might want to use as shared libs, 
# and depend on such as RPC, NDR, REGISTRY, SAMR, LDAP_SERVER, GENSEC, etc). "Libraries"
#   have init_function that receives list of backend init functions
# - parts of subsystems (RPC_RAW, NDR_RAW, REGISTRY_CORE). have "parent". can have convienience init_function. Module()
# - optional parts of subsystems (RPC_SMB, REGISTRY_NT4, SERVER_SERVICE_LDAP). also have "parent". have init_function

# Library() builder
# autoproto=True/False
# proto_file=(defaults to include/proto.h)
# optional=True/False
# automatically get dependency on LIBREPLACE (unless this is LIBREPLACE, of course)
#def library(env, target, source = None, autoproto = False, proto_file = None, optional = False):
#	print "IEKS: %s, %s\n" % (target, env['CC'])

mergedobj_builder = SCons.Builder.Builder(action='ld -r -o $TARGET $SOURCES',
                                     src_suffix='$OBJSUFFIX',
                                     suffix='.mo',
									 src_builder='StaticObject'
									 )

def generate(env):
	env['BUILDERS']['MergedObject'] = mergedobj_builder
	#env['BUILDERS']['Library'] = library

def exists(env):
	return True
