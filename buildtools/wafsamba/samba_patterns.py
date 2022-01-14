# a waf tool to add extension based build patterns for Samba

import sys
from waflib import Build
from wafsamba import samba_version_file

def write_version_header(task):
    '''print version.h contents'''
    src = task.inputs[0].srcpath(task.env)

    version = samba_version_file(src, task.env.srcdir, env=task.env, is_install=task.generator.bld.is_install)
    string = str(version)

    task.outputs[0].write(string)
    return 0


def SAMBA_MKVERSION(bld, target, source='VERSION'):
    '''generate the version.h header for Samba'''

    # We only force waf to re-generate this file if we are installing,
    # because only then is information not included in the deps (the
    # git revision) included in the version.
    t = bld.SAMBA_GENERATOR('VERSION',
                            rule=write_version_header,
                            group='setup',
                            source=source,
                            target=target,
                            always=bld.is_install)
Build.BuildContext.SAMBA_MKVERSION = SAMBA_MKVERSION


def write_build_options_header(fp):
    '''write preamble for build_options.c'''
    fp.write("/*\n"
             "   Unix SMB/CIFS implementation.\n"
             "   Build Options for Samba Suite\n"
             "   Copyright (C) Vance Lankhaar <vlankhaar@linux.ca> 2003\n"
             "   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001\n"
             "\n"
             "   This program is free software; you can redistribute it and/or modify\n"
             "   it under the terms of the GNU General Public License as published by\n"
             "   the Free Software Foundation; either version 3 of the License, or\n"
             "   (at your option) any later version.\n"
             "\n"
             "   This program is distributed in the hope that it will be useful,\n"
             "   but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
             "   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
             "   GNU General Public License for more details.\n"
             "\n"
             "   You should have received a copy of the GNU General Public License\n"
             "   along with this program; if not, see <http://www.gnu.org/licenses/>.\n"
             "*/\n"
             "\n"
             "#include \"includes.h\"\n"
             "#include \"dynconfig/dynconfig.h\"\n"
             "#include \"lib/cluster_support.h\"\n"

             "\n"
             "static int output(bool screen, const char *format, ...) PRINTF_ATTRIBUTE(2,3);\n"
             "void build_options(bool screen);\n"
             "\n"
             "\n"
             "/****************************************************************************\n"
             "helper function for build_options\n"
             "****************************************************************************/\n"
             "static int output(bool screen, const char *format, ...)\n"
             "{\n"
             "       char *ptr = NULL;\n"
             "       int ret = 0;\n"
             "       va_list ap;\n"
             "       \n"
             "       va_start(ap, format);\n"
             "       ret = vasprintf(&ptr,format,ap);\n"
             "       va_end(ap);\n"
             "\n"
             "       if (screen) {\n"
             "              d_printf(\"%s\", ptr ? ptr : \"\");\n"
             "       } else {\n"
             "              DEBUG(4,(\"%s\", ptr ? ptr : \"\"));\n"
             "       }\n"
             "       \n"
             "       SAFE_FREE(ptr);\n"
             "       return ret;\n"
             "}\n"
             "\n"
             "/****************************************************************************\n"
             "options set at build time for the samba suite\n"
             "****************************************************************************/\n"
             "void build_options(bool screen)\n"
             "{\n"
             "       if ((DEBUGLEVEL < 4) && (!screen)) {\n"
             "              return;\n"
             "       }\n"
             "\n"
             "\n"
             "       /* Output various paths to files and directories */\n"
             "       output(screen,\"\\nPaths:\\n\");\n"
             "       output(screen,\"   SBINDIR: %s\\n\", get_dyn_SBINDIR());\n"
             "       output(screen,\"   BINDIR: %s\\n\", get_dyn_BINDIR());\n"
             "       output(screen,\"   CONFIGFILE: %s\\n\", get_dyn_CONFIGFILE());\n"
             "       output(screen,\"   LOGFILEBASE: %s\\n\", get_dyn_LOGFILEBASE());\n"
             "       output(screen,\"   LMHOSTSFILE: %s\\n\",get_dyn_LMHOSTSFILE());\n"
             "       output(screen,\"   LIBDIR: %s\\n\",get_dyn_LIBDIR());\n"
             "       output(screen,\"   DATADIR: %s\\n\",get_dyn_DATADIR());\n"
             "       output(screen,\"   SAMBA_DATADIR: %s\\n\",get_dyn_SAMBA_DATADIR());\n"
             "       output(screen,\"   MODULESDIR: %s\\n\",get_dyn_MODULESDIR());\n"
             "       output(screen,\"   SHLIBEXT: %s\\n\",get_dyn_SHLIBEXT());\n"
             "       output(screen,\"   LOCKDIR: %s\\n\",get_dyn_LOCKDIR());\n"
             "       output(screen,\"   STATEDIR: %s\\n\",get_dyn_STATEDIR());\n"
             "       output(screen,\"   CACHEDIR: %s\\n\",get_dyn_CACHEDIR());\n"
             "       output(screen,\"   PIDDIR: %s\\n\", get_dyn_PIDDIR());\n"
             "       output(screen,\"   SMB_PASSWD_FILE: %s\\n\",get_dyn_SMB_PASSWD_FILE());\n"
             "       output(screen,\"   PRIVATE_DIR: %s\\n\",get_dyn_PRIVATE_DIR());\n"
             "       output(screen,\"   BINDDNS_DIR: %s\\n\",get_dyn_BINDDNS_DIR());\n"
             "\n")

def write_build_options_footer(fp):
    fp.write("       /* Output the sizes of the various cluster features */\n"
             "       output(screen, \"\\n%s\", cluster_support_features());\n"
             "\n"
             "       /* Output the sizes of the various types */\n"
             "       output(screen, \"\\nType sizes:\\n\");\n"
             "       output(screen, \"   sizeof(char):         %lu\\n\",(unsigned long)sizeof(char));\n"
             "       output(screen, \"   sizeof(int):          %lu\\n\",(unsigned long)sizeof(int));\n"
             "       output(screen, \"   sizeof(long):         %lu\\n\",(unsigned long)sizeof(long));\n"
             "       output(screen, \"   sizeof(long long):    %lu\\n\",(unsigned long)sizeof(long long));\n"
             "       output(screen, \"   sizeof(uint8_t):      %lu\\n\",(unsigned long)sizeof(uint8_t));\n"
             "       output(screen, \"   sizeof(uint16_t):     %lu\\n\",(unsigned long)sizeof(uint16_t));\n"
             "       output(screen, \"   sizeof(uint32_t):     %lu\\n\",(unsigned long)sizeof(uint32_t));\n"
             "       output(screen, \"   sizeof(short):        %lu\\n\",(unsigned long)sizeof(short));\n"
             "       output(screen, \"   sizeof(void*):        %lu\\n\",(unsigned long)sizeof(void*));\n"
             "       output(screen, \"   sizeof(size_t):       %lu\\n\",(unsigned long)sizeof(size_t));\n"
             "       output(screen, \"   sizeof(off_t):        %lu\\n\",(unsigned long)sizeof(off_t));\n"
             "       output(screen, \"   sizeof(ino_t):        %lu\\n\",(unsigned long)sizeof(ino_t));\n"
             "       output(screen, \"   sizeof(dev_t):        %lu\\n\",(unsigned long)sizeof(dev_t));\n"
             "\n"
             "       output(screen, \"\\nBuiltin modules:\\n\");\n"
             "       output(screen, \"   %s\\n\", STRING_STATIC_MODULES);\n"
             "}\n")

def write_build_options_section(fp, keys, section):
    fp.write("\n\t/* Show %s */\n" % section)
    fp.write("       output(screen, \"\\n%s:\\n\");\n\n" % section)

    for k in sorted(keys):
        fp.write("#ifdef %s\n" % k)
        fp.write("       output(screen, \"   %s\\n\");\n" % k)
        fp.write("#endif\n")
    fp.write("\n")

def write_build_options(task):
    tbl = task.env
    keys_option_with = []
    keys_option_utmp = []
    keys_option_have = []
    keys_header_sys = []
    keys_header_other = []
    keys_misc = []
    if sys.hexversion>0x300000f:
        trans_table = bytes.maketrans(b'.-()', b'____')
    else:
        import string
        trans_table = string.maketrans('.-()', '____')

    for key in tbl:
        if key.startswith("HAVE_UT_UT_") or key.find("UTMP") >= 0:
            keys_option_utmp.append(key)
        elif key.startswith("WITH_"):
            keys_option_with.append(key)
        elif key.startswith("HAVE_SYS_"):
            keys_header_sys.append(key)
        elif key.startswith("HAVE_"):
            if key.endswith("_H"):
                keys_header_other.append(key)
            else:
                keys_option_have.append(key)
        elif key.startswith("static_init_"):
            l = key.split("(")
            keys_misc.append(l[0])
        else:
            keys_misc.append(key.translate(trans_table))

    tgt = task.outputs[0].bldpath(task.env)
    f = open(tgt, 'w')
    write_build_options_header(f)
    write_build_options_section(f, keys_header_sys, "System Headers")
    write_build_options_section(f, keys_header_other, "Headers")
    write_build_options_section(f, keys_option_utmp, "UTMP Options")
    write_build_options_section(f, keys_option_have, "HAVE_* Defines")
    write_build_options_section(f, keys_option_with, "--with Options")
    write_build_options_section(f, keys_misc, "Build Options")
    write_build_options_footer(f)
    f.close()
    return 0


def SAMBA_BLDOPTIONS(bld, target):
    '''generate the bld_options.c for Samba'''
    t = bld.SAMBA_GENERATOR(target,
                            rule=write_build_options,
                            dep_vars=['defines'],
                            target=target)
Build.BuildContext.SAMBA_BLDOPTIONS = SAMBA_BLDOPTIONS
