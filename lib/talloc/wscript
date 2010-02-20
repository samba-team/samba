srcdir = '.'
blddir = 'build'

def set_options(opt):
    opt.recurse('../replace')

def configure(conf):
    conf.recurse('../replace')

def build(bld):
    bld.recurse('../replace')

    bld.SAMBA_LIBRARY('talloc',
                      'talloc.c',
                      'replace')

    bld.SAMBA_BINARY('talloc_testsuite',
                     'testsuite.c testsuite_main.c',
                     'talloc')
