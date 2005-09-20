"""SCons.Tool.et

Tool-specific initialization for et

"""

import SCons.Defaults
import SCons.Util
import SCons.Tool

et_builder = SCons.Builder.Builder(action='$ETCOM',
                                     src_suffix = '.et',
                                     suffix='.c')

def generate(env):
    env['ET']          = './bin/compile_et'
    env['ETCOM']       = '$ET $SOURCE'
    env['BUILDERS']['ErrorTable'] = et_builder

def exists(env):
	return env.Detect(['./bin/compile_et'])
