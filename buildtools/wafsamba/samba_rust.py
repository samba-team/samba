from waflib.Configure import conf
from waflib import Build
import os

@conf
def SAMBA_CHECK_RUST(conf):
    conf.find_program('cargo', var='CARGO',
                      mandatory=not conf.env.disable_rust)

def find_sources(source_dir, dep_crate):
    sources = []
    for root, dirs, files in os.walk(os.path.join(source_dir, dep_crate)):
        for file in files:
            if os.path.splitext(file)[-1] in ['.rs', '.c', '.h']:
                sources.append(os.path.join(root, file))
    return sources

def SAMBA_RUST(bld, rust_subdir, target_name, dep_crates=[], enabled=True):
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
    # Try to determine the source directory
    source_dir = os.path.abspath(os.path.join(target_dir, '../../../rust'))
    if not os.path.exists(source_dir):
        raise Exception('Failed to determine rust source directory')
    # Now determine the sources of each local crate
    sources = find_sources(source_dir, rust_subdir)
    for dep_crate in dep_crates:
        sources.extend(find_sources(source_dir, dep_crate))
    sources = [os.path.relpath(p, source_dir) for p in sources]

    rule = ['${CARGO}', 'build',
            '--manifest-path=${SRC[0].abspath(env)}',
            '--target-dir=%s' % target_dir,
            release_flag]
    bld.SAMBA_GENERATOR(target_name,
                        ' '.join(rule),
                        source='%s/Cargo.toml %s' % (rust_subdir, ' '.join(sources)),
                        target=target,
                        group='final',
                        enabled=enabled)
Build.BuildContext.SAMBA_RUST_LIBRARY = SAMBA_RUST
Build.BuildContext.SAMBA_RUST_BINARY = SAMBA_RUST
