"""SCons.Tool.et

Tool-specific initialization for et

"""

import SCons.Defaults
import SCons.Scanner.ET
import SCons.Util

et_scanner = SCons.Scanner.ET.ETScan()

et_builder = SCons.Builder.Builder(action='$ETCOM',
                                     src_suffix = '.et',
                                     suffix='.c',
                                     scanner = et_scanner)

def generate(env):
    env['ET']          = 'FIXME'
    env['PROTOCOM']       = '$ET $SOURCE'
    env['BUILDERS']['ET'] = et_builder

def exists(env):
	return env.Detect('FIXME')


