"""SCons.Tool.asn1

Tool-specific initialization for ASN1

"""

import SCons.Defaults
import SCons.Scanner.ASN1
import SCons.Util

asn1_scanner = SCons.Scanner.ASN1.ASN1Scan()

asn1_builder = SCons.Builder.Builder(action='$ASN1COM',
                                     src_suffix = '.asn1',
                                     suffix='.c',
                                     scanner = asn1_scanner)

def generate(env):
    env['ASN1']          = 'FIXME'
    env['PROTOCOM']       = '$ASN1 $SOURCE'
    env['BUILDERS']['ASN1'] = asn1_builder

def exists(env):
	return env.Detect('FIXME')


