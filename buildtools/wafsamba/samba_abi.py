# functions for handling ABI checking of libraries

import Options, Utils, os, Logs, samba_utils, sys, Task, fnmatch, re
from TaskGen import feature, before, after

# these type maps cope with platform specific names for common types
# please add new type mappings into the list below
abi_type_maps = {
    '_Bool' : 'bool',
    'struct __va_list_tag *' : 'va_list'
    }

def normalise_signature(sig):
    '''normalise a signature from gdb'''
    sig = sig.strip()
    sig = re.sub('^\$[0-9]+\s=\s\{*', '', sig)
    sig = re.sub('\}(\s0x[0-9a-f]+\s<\w+>)?$', '', sig)
    sig = re.sub('0x[0-9a-f]+', '0xXXXX', sig)

    for t in abi_type_maps:
        # we need to cope with non-word characters in mapped types
        m = t
        m = m.replace('*', '\*')
        if m[-1].isalnum() or m[-1] == '_':
            m += '\\b'
        if m[0].isalnum() or m[0] == '_':
            m = '\\b' + m
        sig = re.sub(m, abi_type_maps[t], sig)
    return sig

def normalise_varargs(sig):
    '''cope with older versions of gdb'''
    sig = re.sub(',\s\.\.\.', '', sig)
    return sig

def parse_sigs(sigs, abi_match):
    '''parse ABI signatures file'''
    abi_match = samba_utils.TO_LIST(abi_match)
    ret = {}
    a = sigs.split('\n')
    for s in a:
        if s.find(':') == -1:
            continue
        sa = s.split(':')
        if abi_match:
            matched = False
            for p in abi_match:
                if p[0] == '!' and fnmatch.fnmatch(sa[0], p[1:]):
                    break
                elif fnmatch.fnmatch(sa[0], p):
                    matched = True
                    break
            if not matched:
                continue
        ret[sa[0]] = normalise_signature(sa[1])
    return ret

def save_sigs(sig_file, parsed_sigs):
    '''save ABI signatures to a file'''
    sigs = ''
    for s in sorted(parsed_sigs.keys()):
        sigs += '%s: %s\n' % (s, parsed_sigs[s])
    return samba_utils.save_file(sig_file, sigs, create_dir=True)


def abi_check_task(self):
    '''check if the ABI has changed'''
    abi_gen = self.ABI_GEN

    libpath = self.inputs[0].abspath(self.env)
    libname = os.path.basename(libpath)

    sigs = Utils.cmd_output([abi_gen, libpath])
    parsed_sigs = parse_sigs(sigs, self.ABI_MATCH)

    sig_file = self.ABI_FILE

    old_sigs = samba_utils.load_file(sig_file)
    if old_sigs is None or Options.options.ABI_UPDATE:
        if not save_sigs(sig_file, parsed_sigs):
            raise Utils.WafError('Failed to save ABI file "%s"' % sig_file)
        Logs.warn('Generated ABI signatures %s' % sig_file)
        return

    parsed_old_sigs = parse_sigs(old_sigs, self.ABI_MATCH)

    # check all old sigs
    got_error = False
    for s in parsed_old_sigs:
        if not s in parsed_sigs:
            Logs.error('%s: symbol %s has been removed - please update major version\n\tsignature: %s' % (
                libname, s, parsed_old_sigs[s]))
            got_error = True
        elif normalise_varargs(parsed_old_sigs[s]) != normalise_varargs(parsed_sigs[s]):
            Logs.error('%s: symbol %s has changed - please update major version\n\told_signature: %s\n\tnew_signature: %s' % (
                libname, s, parsed_old_sigs[s], parsed_sigs[s]))
            got_error = True

    for s in parsed_sigs:
        if not s in parsed_old_sigs:
            Logs.error('%s: symbol %s has been added - please mark it _PRIVATE_ or update minor version\n\tsignature: %s' % (
                libname, s, parsed_sigs[s]))
            got_error = True

    if got_error:
        raise Utils.WafError('ABI for %s has changed - please fix library version then build with --abi-update\nSee http://wiki.samba.org/index.php/Waf#ABI_Checking for more information' % libname)


t = Task.task_type_from_func('abi_check', abi_check_task, color='BLUE', ext_in='.bin')
t.quiet = True
# allow "waf --abi-check" to force re-checking the ABI
if '--abi-check' in sys.argv:
    Task.always_run(t)

@after('apply_link')
@feature('abi_check')
def abi_check(self):
    '''check that ABI matches saved signatures'''
    env = self.bld.env
    if not env.ABI_CHECK or self.abi_file is None:
        return

    # if the platform doesn't support -fvisibility=hidden then the ABI
    # checks become fairly meaningless
    if not env.HAVE_VISIBILITY_ATTR:
        return

    topsrc = self.bld.srcnode.abspath()
    abi_gen = os.path.join(topsrc, 'buildtools/scripts/abi_gen.sh')

    tsk = self.create_task('abi_check', self.link_task.outputs[0])
    tsk.ABI_FILE = self.abi_file
    tsk.ABI_MATCH = self.abi_match
    tsk.ABI_GEN = abi_gen
