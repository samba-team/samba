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
	env['PROTO_DEFINE']		= '_PROTO_H_'
	env['PROTOCOM']       = '$MKPROTO "$PERL" -h $PROTO_DEFINE ${TARGETS[0]} $SOURCES'
	env['BUILDERS']['CProtoHeader'] = proto_builder

def exists(env):
	return env.Detect('./script/mkproto.sh')
