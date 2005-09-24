"""SCons.Tool.proto

Tool-specific initialization for mkproto (C Proto File generator)

"""

import SCons.Defaults
import SCons.Util

proto_builder = SCons.Builder.Builder(action='$PROTOCOM',
                                     src_suffix = '.c',
                                     suffix='.h')

def generate(env):
	env['MKPROTO']          = './script/mkproto.sh'
	env['PROTOCOM']       = '$MKPROTO "$PERL" ${TARGETS[0]} $SOURCES'
	env['BUILDERS']['CProtoHeader'] = proto_builder

def exists(env):
	return env.Detect('./script/mkproto.sh')
