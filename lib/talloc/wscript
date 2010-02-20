srcdir = '.'
blddir = 'build'

def set_options(opt):
    opt.recurse('../replace')

def configure(conf):
    conf.recurse('../replace')

def build(bld):
    bld.recurse('../replace')

    bld(
        features = 'cc cshlib',
        source = 'talloc.c',
        target='talloc',
        includes = '. ../replace')

    # test program
    bld(
        features = 'cc cprogram',
        source = 'testsuite.c testsuite_main.c',
        target = 'talloc_testsuite',
        uselib_local = 'replace talloc',
        includes = '. ../replace default /usr/include')
