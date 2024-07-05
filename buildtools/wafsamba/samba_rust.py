from waflib.Configure import conf
from waflib import Build
import os.path

@conf
def SAMBA_CHECK_RUST(conf):
    conf.find_program('cargo', var='CARGO',
                      mandatory=not conf.env.disable_rust)

def SAMBA_RUST(bld, name, source, enabled=True):
    # force-disable when we can't build rust modules, so
    # every single call doesn't need to pass this in.
    if bld.env.disable_rust:
        enabled = False

    # Save time, no need to build rust when fuzzing
    if bld.env.enable_fuzzing:
        enabled = False

    release_flag = ''
    if bld.env.debug or bld.env.developer:
        target = os.path.join('debug', name)
    else:
        release_flag = '--release'
        target = os.path.join('release', name)
    target = bld.path.find_or_declare(target)
    rust_vars = 'CARGO_TARGET_DIR=%s' % bld.path.find_or_declare('./')

    rule = [rust_vars, '${CARGO}', 'build',
            '--manifest-path=${SRC[0].abspath(env)}', release_flag]
    bld.SAMBA_GENERATOR(name,
                        ' '.join(rule),
                        source='Cargo.toml %s' % source,
                        target=target,
                        group='final',
                        enabled=enabled)
Build.BuildContext.SAMBA_RUST_LIBRARY = SAMBA_RUST
Build.BuildContext.SAMBA_RUST_BINARY = SAMBA_RUST
