#!/usr/bin/env python

APPNAME = 'ldb'
VERSION = '1.2.3'

blddir = 'bin'

import sys, os

# find the buildtools directory
srcdir = '.'
while not os.path.exists(srcdir+'/buildtools') and len(srcdir.split('/')) < 5:
    srcdir = srcdir + '/..'
sys.path.insert(0, srcdir + '/buildtools/wafsamba')

import wafsamba, samba_dist, Utils

samba_dist.DIST_DIRS('''lib/ldb:. lib/replace:lib/replace lib/talloc:lib/talloc
                        lib/tdb:lib/tdb lib/tdb:lib/tdb lib/tevent:lib/tevent
                        third_party/popt:third_party/popt
                        third_party/cmocka:third_party/cmocka
                        buildtools:buildtools third_party/waf:third_party/waf''')


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
        conf.RECURSE('third_party/cmocka')
    else:
        if not conf.CHECK_POPT():
            raise Utils.WafError('popt development packages have not been found.\nIf third_party is installed, check that it is in the proper place.')
        else:
            conf.define('USING_SYSTEM_POPT', 1)

        if not conf.CHECK_CMOCKA():
            raise Utils.WafError('cmocka development package have not been found.\nIf third_party is installed, check that it is in the proper place.')
        else:
            conf.define('USING_SYSTEM_CMOCKA', 1)

    conf.RECURSE('lib/replace')
    conf.find_program('python', var='PYTHON')
    conf.find_program('xsltproc', var='XSLTPROC')
    conf.check_tool('python')
    conf.check_python_version((2,4,2))
    conf.SAMBA_CHECK_PYTHON_HEADERS(mandatory=not conf.env.disable_python)

    # where does the default LIBDIR end up? in conf.env somewhere?
    #
    conf.CONFIG_PATH('LDB_MODULESDIR', conf.SUBST_ENV_VAR('MODULESDIR') + '/ldb')

    conf.env.standalone_ldb = conf.IN_LAUNCH_DIR()

    if not conf.env.standalone_ldb:
        if conf.env.disable_python:
            if conf.CHECK_BUNDLED_SYSTEM_PKG('ldb', minversion=VERSION,
                                         onlyif='talloc tdb tevent',
                                         implied_deps='replace talloc tdb tevent'):
                conf.define('USING_SYSTEM_LDB', 1)
        else:
            using_system_pyldb_util = True
            if not conf.CHECK_BUNDLED_SYSTEM_PKG('pyldb-util', minversion=VERSION,
                                             onlyif='talloc tdb tevent',
                                             implied_deps='replace talloc tdb tevent ldb'):
                using_system_pyldb_util = False

            # We need to get a pyldb-util for all the python versions
            # we are building for
            if conf.env['EXTRA_PYTHON']:
                name = 'pyldb-util' + conf.all_envs['extrapython']['PYTHON_SO_ABI_FLAG']
                if not conf.CHECK_BUNDLED_SYSTEM_PKG(name, minversion=VERSION,
                                                     onlyif='talloc tdb tevent',
                                                     implied_deps='replace talloc tdb tevent ldb'):
                    using_system_pyldb_util = False

            if using_system_pyldb_util:
                conf.define('USING_SYSTEM_PYLDB_UTIL', 1)

            if conf.CHECK_BUNDLED_SYSTEM_PKG('ldb', minversion=VERSION,
                                         onlyif='talloc tdb tevent pyldb-util',
                                         implied_deps='replace talloc tdb tevent'):
                conf.define('USING_SYSTEM_LDB', 1)

    if conf.CONFIG_SET('USING_SYSTEM_LDB'):
        v = VERSION.split('.')
        conf.DEFINE('EXPECTED_SYSTEM_LDB_VERSION_MAJOR', int(v[0]))
        conf.DEFINE('EXPECTED_SYSTEM_LDB_VERSION_MINOR', int(v[1]))
        conf.DEFINE('EXPECTED_SYSTEM_LDB_VERSION_RELEASE', int(v[2]))

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
        bld.RECURSE('third_party/cmocka')

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

    if bld.PYTHON_BUILD_IS_ENABLED():
        if not bld.CONFIG_SET('USING_SYSTEM_PYLDB_UTIL'):
            for env in bld.gen_python_environments(['PKGCONFIGDIR']):
                # we're not currently linking against the ldap libs, but ldb.pc.in
                # has @LDAP_LIBS@
                bld.env.LDAP_LIBS = ''

                if not 'PACKAGE_VERSION' in bld.env:
                    bld.env.PACKAGE_VERSION = VERSION
                    bld.env.PKGCONFIGDIR = '${LIBDIR}/pkgconfig'

                name = bld.pyembed_libname('pyldb-util')
                bld.SAMBA_LIBRARY(name,
                                  deps='ldb',
                                  source='pyldb_util.c',
                                  public_headers=('' if private_library else 'pyldb.h'),
                                  public_headers_install=not private_library,
                                  vnum=VERSION,
                                  private_library=private_library,
                                  pc_files='pyldb-util.pc',
                                  pyembed=True,
                                  enabled=bld.PYTHON_BUILD_IS_ENABLED(),
                                  abi_directory='ABI',
                                  abi_match='pyldb_*')

                if not bld.CONFIG_SET('USING_SYSTEM_LDB'):
                    bld.SAMBA_PYTHON('pyldb', 'pyldb.c',
                                     deps='ldb ' + name,
                                     realname='ldb.so',
                                     cflags='-DPACKAGE_VERSION=\"%s\"' % VERSION)

        # Do only install this file as part of the Samba build if we do not
        # use the system libldb!
        if not bld.CONFIG_SET('USING_SYSTEM_PYLDB_UTIL'):
            for env in bld.gen_python_environments(['PKGCONFIGDIR']):
                    bld.SAMBA_SCRIPT('_ldb_text.py',
                                     pattern='_ldb_text.py',
                                     installdir='python')

                    bld.INSTALL_FILES('${PYTHONARCHDIR}', '_ldb_text.py')

    if not bld.CONFIG_SET('USING_SYSTEM_LDB'):
        if bld.is_install:
            modules_dir = bld.EXPAND_VARIABLES('${LDB_MODULESDIR}')
        else:
            # when we run from the source directory, we want to use
            # the current modules, not the installed ones
            modules_dir = os.path.join(os.getcwd(), 'bin/modules/ldb')

        abi_match = '!ldb_*module_ops !ldb_*backend_ops ldb_*'

        ldb_headers = ('include/ldb.h include/ldb_errors.h '
                       'include/ldb_module.h include/ldb_handlers.h')

        bld.SAMBA_LIBRARY('ldb',
                          COMMON_SRC + ' ' + LDB_MAP_SRC,
                          deps='tevent LIBLDB_MAIN replace',
                          includes='include',
                          public_headers=('' if private_library else ldb_headers),
                          public_headers_install=not private_library,
                          pc_files='ldb.pc',
                          vnum=VERSION,
                          private_library=private_library,
                          manpages='man/ldb.3',
                          abi_directory='ABI',
                          abi_match = abi_match)

        # generate a include/ldb_version.h
        def generate_ldb_version_h(t):
            '''generate a vscript file for our public libraries'''

            tgt = t.outputs[0].bldpath(t.env)

            v = t.env.LDB_VERSION.split('.')

            f = open(tgt, mode='w')
            try:
                f.write('#define LDB_VERSION "%s"\n' % t.env.LDB_VERSION)
                f.write('#define LDB_VERSION_MAJOR %d\n' % int(v[0]))
                f.write('#define LDB_VERSION_MINOR %d\n' % int(v[1]))
                f.write('#define LDB_VERSION_RELEASE %d\n' % int(v[2]))
            finally:
                f.close()
            return
        t = bld.SAMBA_GENERATOR('ldb_version.h',
                                rule=generate_ldb_version_h,
                                dep_vars=['LDB_VERSION'],
                                target='include/ldb_version.h',
                                public_headers='include/ldb_version.h',
                                public_headers_install=not private_library)
        t.env.LDB_VERSION = VERSION


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

        bld.SAMBA_BINARY('ldb_tdb_mod_op_test',
                         source='tests/ldb_mod_op_test.c',
                         cflags='-DTEST_BE=\"tdb\"',
                         deps='cmocka ldb',
                         install=False)

        bld.SAMBA_BINARY('ldb_msg_test',
                         source='tests/ldb_msg.c',
                         deps='cmocka ldb',
                         install=False)

def test(ctx):
    '''run ldb testsuite'''
    import Utils, samba_utils, shutil
    env = samba_utils.LOAD_ENVIRONMENT()
    ctx.env = env

    test_prefix = "%s/st" % (Utils.g_module.blddir)
    shutil.rmtree(test_prefix, ignore_errors=True)
    os.makedirs(test_prefix)
    os.environ['TEST_DATA_PREFIX'] = test_prefix
    os.environ['LDB_MODULES_PATH'] = Utils.g_module.blddir + "/modules/ldb"
    samba_utils.ADD_LD_LIBRARY_PATH('bin/shared')
    samba_utils.ADD_LD_LIBRARY_PATH('bin/shared/private')

    cmd = 'tests/test-tdb.sh %s' % Utils.g_module.blddir
    ret = samba_utils.RUN_COMMAND(cmd)
    print("testsuite returned %d" % ret)

    tmp_dir = os.path.join(test_prefix, 'tmp')
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)
    pyret = samba_utils.RUN_PYTHON_TESTS(
        ['tests/python/api.py'],
        extra_env={'SELFTEST_PREFIX': test_prefix})
    print("Python testsuite returned %d" % pyret)

    cmocka_ret = 0
    for test_exe in ['ldb_tdb_mod_op_test',
                     'ldb_msg_test']:
            cmd = os.path.join(Utils.g_module.blddir, test_exe)
            cmocka_ret = cmocka_ret or samba_utils.RUN_COMMAND(cmd)

    sys.exit(ret or pyret or cmocka_ret)

def dist():
    '''makes a tarball for distribution'''
    samba_dist.dist()

def reconfigure(ctx):
    '''reconfigure if config scripts have changed'''
    import samba_utils
    samba_utils.reconfigure(ctx)
