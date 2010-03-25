# a set of config tests that use the samba_autoconf functions
# to test for commonly needed configuration options
from Configure import conf

@conf
def CHECK_ICONV(conf, define='HAVE_NATIVE_ICONV'):
    '''check if the iconv library is installed
       optionally pass a define'''
    if conf.CHECK_FUNCS_IN('iconv_open', 'iconv', checklibc=True, headers='iconv.h'):
        conf.DEFINE(define, 1)
        return True
    return False


@conf
def CHECK_LARGEFILE(conf, define='HAVE_LARGEFILE'):
    '''see what we need for largefile support'''
    if conf.CHECK_CODE('return !(sizeof(off_t) >= 8)',
                       define,
                       execute=True,
                       msg='Checking for large file support'):
        return True
    if conf.CHECK_CODE('return !(sizeof(off_t) >= 8)',
                       define,
                       execute=True,
                       cflags='-D_FILE_OFFSET_BITS=64',
                       msg='Checking for -D_FILE_OFFSET_BITS=64'):
        conf.DEFINE('_FILE_OFFSET_BITS', 64)
        return True
    return False


@conf
def CHECK_C_PROTOTYPE(conf, function, prototype, define, headers=None):
    '''verify that a C prototype matches the one on the current system'''
    if not conf.CHECK_DECLS(function, headers=headers):
        return False
    return conf.CHECK_CODE('%s; void *_x = (void *)%s' % (prototype, function),
                           define=define,
                           local_include=False,
                           headers=headers,
                           msg='Checking C prototype for %s' % function)


@conf
def CHECK_CHARSET_EXISTS(conf, charset, outcharset='UCS2-LE', libs=None, headers=None, define=None):
    '''check that a named charset is able to be used with iconv_open() for conversion
    to a target charset
    '''
    msg = 'Checking if can we convert from %s to %s' % (charset, outcharset)
    if define is None:
        define = 'HAVE_CHARSET_%s' % charset.upper().replace('-','_')
    return conf.CHECK_CODE('''
                           iconv_t cd = iconv_open("%s", "%s");
                           if (cd == 0 || cd == (iconv_t)-1) {
                             return -1;
                             }
                             return 0;
                             ''' % (charset, outcharset),
                           define=define,
                           execute=True,
                           libs=libs,
                           msg=msg,
                           headers=headers)
