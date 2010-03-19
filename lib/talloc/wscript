VERSION = '2.0.1'

srcdir = '../..'
blddir = 'bin'

LIBREPLACE_DIR= srcdir + '/lib/replace'

def set_options(opt):
    opt.recurse(LIBREPLACE_DIR)

def configure(conf):
    conf.sub_config(LIBREPLACE_DIR)
    conf.SAMBA_CONFIG_H()

def build(bld):
    bld.BUILD_SUBDIR(LIBREPLACE_DIR)

    bld.SAMBA_LIBRARY('talloc',
                      'talloc.c',
                      deps='replace',
                      vnum=VERSION)

    bld.SAMBA_BINARY('talloc_testsuite',
                     'testsuite.c testsuite_main.c',
                     deps='talloc',
                     install=False)
