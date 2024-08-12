from waflib.Configure import conf
from waflib import Build
import os.path

@conf
def SAMBA_CHECK_RUST(conf):
    conf.find_program('cargo', var='CARGO',
                      mandatory=not conf.env.disable_rust)

def SAMBA_RUST(bld, rust_subdir, target_name, source, enabled=True):
    # force-disable when we can't build rust modules, so
    # every single call doesn't need to pass this in.
    if bld.env.disable_rust:
        enabled = False

    # Save time, no need to build rust when fuzzing
    if bld.env.enable_fuzzing:
        enabled = False

    release_flag = ''
    if bld.env.debug or bld.env.developer:
        target = os.path.join('debug', target_name)
    else:
        release_flag = '--release'
        target = os.path.join('release', target_name)
    target = bld.path.find_or_declare(target)
    # The Rust target directory is one directory above the located target
    target_dir = os.path.join(os.path.dirname('%s' % target), '../')

    rule = ['${CARGO}', 'build',
            '--manifest-path=${SRC[0].abspath(env)}',
            '--target-dir=%s' % target_dir,
            release_flag]
    bld.SAMBA_GENERATOR(target_name,
                        ' '.join(rule),
                        source='%s/Cargo.toml %s' % (rust_subdir, source),
                        target=target,
                        group='final',
                        enabled=enabled)
Build.BuildContext.SAMBA_RUST_LIBRARY = SAMBA_RUST
Build.BuildContext.SAMBA_RUST_BINARY = SAMBA_RUST
