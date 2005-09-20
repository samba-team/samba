"""SCons.Tool.asn1

Tool-specific initialization for ASN1

"""

import SCons.Defaults
import SCons.Util
import re

output_re = re.compile(r'^([A-Za-z0-9_-]+)[ \t]*::=', re.M)

def asn1_emitter(target,source,env):
	targets = []
	for s in source:
		node = env.File(s)
		contents = node.get_contents()
		for j in output_re.findall(contents):
			targets.append(str(node.get_dir()) + '/asn1_' + j + '.c')
	return targets, source

asn1_builder = SCons.Builder.Builder(action='$ASN1COM',
                                     src_suffix = '.asn1',
                                     suffix='.c',
                                     emitter = asn1_emitter)

def generate(env):
    env['ASN1']          = './bin/asn1_compile'
    env['ASN1COM']       = '$ASN1 $SOURCE'
    env['BUILDERS']['ASN1'] = asn1_builder

def exists(env):
	return env.Detect('asn1_compile')
