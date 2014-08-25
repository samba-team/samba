import Build
from samba_utils import *
from Configure import conf

done = {}

@conf
def SAMBA_CHECK_PERL(conf, mandatory=True, version=(5,0,0)):
    #
    # TODO: use the @runonce mechanism for this.
    # The problem is that @runonce currently does
    # not seem to work together with @conf...
    # So @runonce (and/or) @conf needs fixing.
    #
    if "done" in done:
        return
    done["done"] = True
    conf.find_program('perl', var='PERL', mandatory=mandatory)
    conf.check_tool('perl')
    path_perl = conf.find_program('perl')
    conf.env.PERL_SPECIFIED = (conf.env.PERL != path_perl)
    conf.check_perl_version(version)

    def read_perl_config_var(cmd):
        return Utils.to_list(Utils.cmd_output([conf.env.PERL, '-MConfig', '-e', cmd]))

    def check_perl_config_var(var):
        conf.start_msg("Checking for perl $Config{%s}:" % var)
        try:
            v = read_perl_config_var('print $Config{%s}' % var)[0]
            conf.end_msg("'%s'" % (v), 'GREEN')
            return v
        except IndexError:
            conf.end_msg(False, 'YELLOW')
            pass
        return None

    vendor_prefix = check_perl_config_var('vendorprefix')

    perl_arch_install_dir = None
    if vendor_prefix == conf.env.PREFIX:
        perl_arch_install_dir = check_perl_config_var('vendorarch');
    if perl_arch_install_dir is None:
        perl_arch_install_dir = "${LIBDIR}/perl5";
    conf.start_msg("PERL_ARCH_INSTALL_DIR: ")
    conf.end_msg("'%s'" % (perl_arch_install_dir), 'GREEN')
    conf.env.PERL_ARCH_INSTALL_DIR = perl_arch_install_dir

    perl_lib_install_dir = None
    if vendor_prefix == conf.env.PREFIX:
        perl_lib_install_dir = check_perl_config_var('vendorlib');
    if perl_lib_install_dir is None:
        perl_lib_install_dir = "${DATADIR}/perl5";
    conf.start_msg("PERL_LIB_INSTALL_DIR: ")
    conf.end_msg("'%s'" % (perl_lib_install_dir), 'GREEN')
    conf.env.PERL_LIB_INSTALL_DIR = perl_lib_install_dir

    perl_inc = read_perl_config_var('print "@INC"')
    perl_inc.remove('.')
    conf.start_msg("PERL_INC: ")
    conf.end_msg("%s" % (perl_inc), 'GREEN')
    conf.env.PERL_INC = perl_inc
