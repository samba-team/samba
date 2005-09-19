"""SCons.Tool.proto

Tool-specific initialization for mkproto (C Proto File generator)

"""

import SCons.Defaults
import SCons.Scanner.C
import SCons.Util

c_scanner = SCons.Scanner.C.CScan()

proto_builder = SCons.Builder.Builder(action='$PROTOCOM',
                                     src_suffix = '.idl',
                                     suffix='.h',
                                     scanner = c_scanner)

def generate(env):
    env['MKPROTO']          = './script/mkproto.sh'
    env['PROTOCOM']       = '$MKPROTO "$PERL" -h _PROTO_H_ ${TARGETS[0]} $SOURCE'
    env['BUILDERS']['ProtoHeader'] = proto_builder

def exists(env):
	return env.Detect('./script/mkproto.sh')


