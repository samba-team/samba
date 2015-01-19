#!/usr/bin/env python

APPNAME = 'ldb'
VERSION = '1.1.20'

blddir = 'bin'

import sys, os

# find the buildtools directory
srcdir = '.'
while not os.path.exists(srcdir+'/buildtools') and len(srcdir.split('/')) < 5:
    srcdir = srcdir + '/..'
sys.path.insert(0, srcdir + '/buildtools/wafsamba')

import wafsamba, samba_dist, Options, Utils

samba_dist.DIST_DIRS('''lib/ldb:. lib/replace:lib/replace lib/talloc:lib/talloc
                        lib/tdb:lib/tdb lib/tdb:lib/tdb lib/tevent:lib/tevent
			third_party/popt:third_party/popt
                        buildtools:buildtools''')


def set_options(opt):
    opt.BUILTIN_DEFAULT('replace')
    opt.PRIVATE_EXTENSION_DEFAULT('ldb', noextension='ldb')
    opt.RECURSE('lib/tdb')
    opt.RECURSE('lib/tevent')
    opt.RECURSE('lib/replace')
    opt.tool_options('python') # options for disabling pyc or pyo compilation

def configure(conf):
    conf.RECURSE('lib/tdb')
    conf.RECURSE('lib/tevent')

    if conf.CHECK_FOR_THIRD_PARTY():
        conf.RECURSE('third_party/popt')
    else:
        if not conf.CHECK_POPT():
            raise Utils.WafError('popt development packages have not been found.\nIf third_party is installed, check that it is in the proper place.')
        else:
            conf.define('USING_SYSTEM_POPT', 1)

    conf.RECURSE('lib/replace')
    conf.find_program('python', var='PYTHON')
    conf.find_program('xsltproc', var='XSLTPROC')
    conf.check_tool('python')
    conf.check_python_version((2,4,2))
    conf.SAMBA_CHECK_PYTHON_HEADERS(mandatory=True)

    # where does the default LIBDIR end up? in conf.env somewhere?
    #
    conf.CONFIG_PATH('LDB_MODULESDIR', conf.SUBST_ENV_VAR('MODULESDIR') + '/ldb')

    conf.env.standalone_ldb = conf.IN_LAUNCH_DIR()

    if not conf.env.standalone_ldb:
        if conf.CHECK_BUNDLED_SYSTEM_PKG('ldb', minversion=VERSION,
                                     onlyif='talloc tdb tevent',
                                     implied_deps='replace talloc tdb tevent'):
            conf.define('USING_SYSTEM_LDB', 1)
        if conf.CHECK_BUNDLED_SYSTEM_PKG('pyldb-util', minversion=VERSION,
                                     onlyif='talloc tdb tevent ldb',
                                     implied_deps='replace talloc tdb tevent ldb'):
            conf.define('USING_SYSTEM_PYLDB_UTIL', 1)

    if conf.env.standalone_ldb:
        conf.CHECK_XSLTPROC_MANPAGES()

        # we need this for the ldap backend
        if conf.CHECK_FUNCS_IN('ber_flush ldap_open ldap_initialize', 'lber ldap', headers='lber.h ldap.h'):
            conf.env.ENABLE_LDAP_BACKEND = True

        # we don't want any libraries or modules to rely on runtime
        # resolution of symbols
        if not sys.platform.startswith("openbsd"):
            conf.ADD_LDFLAGS('-Wl,-no-undefined', testflags=True)

    conf.DEFINE('HAVE_CONFIG_H', 1, add_to_cflags=True)

    conf.SAMBA_CONFIG_H()

    conf.SAMBA_CHECK_UNDEFINED_SYMBOL_FLAGS()

def build(bld):
    bld.RECURSE('lib/tevent')

    if bld.CHECK_FOR_THIRD_PARTY():
        bld.RECURSE('third_party/popt')

    bld.RECURSE('lib/replace')
    bld.RECURSE('lib/tdb')

    if bld.env.standalone_ldb:
        private_library = False
    else:
        private_library = True

    LDB_MAP_SRC = bld.SUBDIR('ldb_map',
                             'ldb_map.c ldb_map_inbound.c ldb_map_outbound.c')

    COMMON_SRC = bld.SUBDIR('common',
                            '''ldb_modules.c ldb_ldif.c ldb_parse.c ldb_msg.c ldb_utf8.c
                            ldb_debug.c ldb_dn.c ldb_match.c ldb_options.c ldb_pack.c
                            ldb_attributes.c attrib_handlers.c ldb_controls.c qsort.c''')

    bld.SAMBA_MODULE('ldb_ldap', 'ldb_ldap/ldb_ldap.c',
                     init_function='ldb_ldap_init',
                     module_init_name='ldb_init_module',
                     deps='talloc lber ldap ldb',
                     enabled=bld.env.ENABLE_LDAP_BACKEND,
                     internal_module=False,
                     subsystem='ldb')

    # we're not currently linking against the ldap libs, but ldb.pc.in
    # has @LDAP_LIBS@
    bld.env.LDAP_LIBS = ''

    if not 'PACKAGE_VERSION' in bld.env:
        bld.env.PACKAGE_VERSION = VERSION
        bld.env.PKGCONFIGDIR = '${LIBDIR}/pkgconfig'

    if not bld.CONFIG_SET('USING_SYSTEM_PYLDB_UTIL'):
        bld.SAMBA_LIBRARY('pyldb-util',
                          deps='ldb',
                          source='pyldb_util.c',
                          public_headers='pyldb.h',
                          public_headers_install=not private_library,
                          vnum=VERSION,
                          private_library=private_library,
                          pc_files='pyldb-util.pc',
                          pyembed=True,
                          abi_directory='ABI',
                          abi_match='pyldb_*')

    if not bld.CONFIG_SET('USING_SYSTEM_LDB'):
        if Options.is_install:
            modules_dir = bld.EXPAND_VARIABLES('${LDB_MODULESDIR}')
        else:
            # when we run from the source directory, we want to use
            # the current modules, not the installed ones
            modules_dir = os.path.join(os.getcwd(), 'bin/modules/ldb')

        abi_match = '!ldb_*module_ops !ldb_*backend_ops ldb_*'

        bld.SAMBA_LIBRARY('ldb',
                          COMMON_SRC + ' ' + LDB_MAP_SRC,
                          deps='tevent LIBLDB_MAIN replace',
                          includes='include',
                          public_headers='include/ldb.h include/ldb_errors.h '\
                          'include/ldb_module.h include/ldb_handlers.h',
                          public_headers_install=not private_library,
                          pc_files='ldb.pc',
                          vnum=VERSION,
                          private_library=private_library,
                          manpages='man/ldb.3',
                          abi_directory='ABI',
                          abi_match = abi_match)

        # generate a include/ldb_version.h
        t = bld.SAMBA_GENERATOR('ldb_version.h',
                                rule='echo "#define LDB_VERSION \\"${LDB_VERSION}\\"" > ${TGT}',
                                dep_vars=['LDB_VERSION'],
                                target='include/ldb_version.h',
                                public_headers='include/ldb_version.h',
                                public_headers_install=not private_library)
        t.env.LDB_VERSION = VERSION


        bld.SAMBA_PYTHON('pyldb', 'pyldb.c',
                         deps='ldb pyldb-util',
                         realname='ldb.so',
                         cflags='-DPACKAGE_VERSION=\"%s\"' % VERSION)

        bld.SAMBA_MODULE('ldb_paged_results',
                         'modules/paged_results.c',
                         init_function='ldb_paged_results_init',
                         module_init_name='ldb_init_module',
                         internal_module=False,
                         deps='ldb',
                         subsystem='ldb')

        bld.SAMBA_MODULE('ldb_asq',
                         'modules/asq.c',
                         init_function='ldb_asq_init',
                         module_init_name='ldb_init_module',
                         internal_module=False,
                         deps='ldb',
                         subsystem='ldb')

        bld.SAMBA_MODULE('ldb_server_sort',
                         'modules/sort.c',
                         init_function='ldb_server_sort_init',
                         internal_module=False,
                         module_init_name='ldb_init_module',
                         deps='ldb',
                         subsystem='ldb')

        bld.SAMBA_MODULE('ldb_paged_searches',
                         'modules/paged_searches.c',
                         init_function='ldb_paged_searches_init',
                         internal_module=False,
                         module_init_name='ldb_init_module',
                         deps='ldb',
                         subsystem='ldb')

        bld.SAMBA_MODULE('ldb_rdn_name',
                         'modules/rdn_name.c',
                         init_function='ldb_rdn_name_init',
                         internal_module=False,
                         module_init_name='ldb_init_module',
                         deps='ldb',
                         subsystem='ldb')

        bld.SAMBA_MODULE('ldb_sample',
                         'tests/sample_module.c',
                         init_function='ldb_sample_init',
                         internal_module=False,
                         allow_warnings=True,
                         module_init_name='ldb_init_module',
                         deps='ldb',
                         subsystem='ldb')

        bld.SAMBA_MODULE('ldb_skel',
                         'modules/skel.c',
                         init_function='ldb_skel_init',
                         internal_module=False,
                         module_init_name='ldb_init_module',
                         deps='ldb',
                         subsystem='ldb')

        bld.SAMBA_MODULE('ldb_sqlite3',
                         'sqlite3/ldb_sqlite3.c',
                         init_function='ldb_sqlite3_init',
                         internal_module=False,
                         module_init_name='ldb_init_module',
                         enabled=False,
                         deps='ldb',
                         subsystem='ldb')

        bld.SAMBA_MODULE('ldb_tdb',
                         bld.SUBDIR('ldb_tdb',
                                    '''ldb_tdb.c ldb_search.c ldb_index.c
                                    ldb_cache.c ldb_tdb_wrap.c'''),
                         init_function='ldb_tdb_init',
                         module_init_name='ldb_init_module',
                         internal_module=False,
                         deps='tdb ldb',
                         subsystem='ldb')

        # have a separate subsystem for common/ldb.c, so it can rebuild
        # for install with a different -DLDB_MODULESDIR=
        bld.SAMBA_SUBSYSTEM('LIBLDB_MAIN',
                            'common/ldb.c',
                            deps='tevent tdb',
                            includes='include',
                            cflags=['-DLDB_MODULESDIR=\"%s\"' % modules_dir])

        LDB_TOOLS='ldbadd ldbsearch ldbdel ldbmodify ldbedit ldbrename'
        for t in LDB_TOOLS.split():
            bld.SAMBA_BINARY(t, 'tools/%s.c' % t, deps='ldb-cmdline ldb',
                             manpages='man/%s.1' % t)

        # ldbtest doesn't get installed
        bld.SAMBA_BINARY('ldbtest', 'tools/ldbtest.c', deps='ldb-cmdline ldb',
                         install=False)

        # ldbdump doesn't get installed
        bld.SAMBA_BINARY('ldbdump', 'tools/ldbdump.c', deps='ldb-cmdline ldb',
                         install=False)

        bld.SAMBA_LIBRARY('ldb-cmdline',
                          source='tools/ldbutil.c tools/cmdline.c',
                          deps='ldb dl popt',
                          private_library=True)


def test(ctx):
    '''run ldb testsuite'''
    import Utils, samba_utils, shutil
    test_prefix = "%s/st" % (Utils.g_module.blddir)
    shutil.rmtree(test_prefix, ignore_errors=True)
    os.makedirs(test_prefix)
    os.environ['TEST_DATA_PREFIX'] = test_prefix
    cmd = 'tests/test-tdb.sh %s' % Utils.g_module.blddir
    ret = samba_utils.RUN_COMMAND(cmd)
    print("testsuite returned %d" % ret)
    # FIXME: Run python testsuite
    sys.exit(ret)

def dist():
    '''makes a tarball for distribution'''
    samba_dist.dist()

def reconfigure(ctx):
    '''reconfigure if config scripts have changed'''
    import samba_utils
    samba_utils.reconfigure(ctx)
