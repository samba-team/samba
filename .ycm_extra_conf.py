# This file is NOT licensed under the GPLv3, which is the license for the rest
# of Samba.
#
# Here's the license text for this file:
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org/>

import os
import ycm_core

flags = [
    # This is a C project
    '-x', 'c',
    '-DDEBUG_PASSWORD',
    '-DDEVELOPER',
    '-DHAVE_CONFIG_H=1',
    '-DCONFIG_H_IS_FROM_SAMBA=1',
    '-DSTATIC_replace_MODULES=NULL',
    '-DSTATIC_replace_MODULES_PROTO=extern',
    '-D_GNU_SOURCE=1',
    '-D_POSIX_PTHREAD_SEMANTICS',
    '-D_REENTRANT',
    '-D_SAMBA_BUILD_=4',
    '-D_XOPEN_SOURCE_EXTENDED=1',
    '-DAD_DC_BUILD_IS_ENABLED=1',
    '-DHAVE_IPV6=1',
    '-DFALL_THROUGH',
    '-I/usr/local/include',
    '-I.',
    '-Iauth',
    '-Iauth/credentials',
    '-Iauth/gensec',
    '-Iauth/kerberos',
    '-Iauth/ntlmssp',
    '-Ictdb',
    '-Ictdb/include',
    '-Idynconfig',
    '-Iinclude',
    '-Iinclude/public',
    '-Ilib',
    '-Ilib/addns',
    '-Ilib/afs',
    '-Ilib/async_req',
    '-Ilib/compression',
    '-Ilib/crypto',
    '-Ilib/dbwrap',
    '-Ilib/krb5_wrap',
    '-Ilib/ldb',
    '-Ilib/ldb-samba',
    '-Ilib/ldb/include',
    '-Ilib/param',
    '-Ilib/pthreadpool',
    '-Ilib/replace',
    '-Ilib/smbconf',
    '-Ilib/socket',
    '-Ilib/talloc',
    '-Ilib/tdb',
    '-Ilib/tdb/include',
    '-Ilib/tevent',
    '-Ilib/tsocket',
    '-Ilib/util/charset',
    '-Ilibcli/auth',
    '-Ilibcli/cldap',
    '-Ilibcli/drsuapi',
    '-Ilibcli/ldap',
    '-Ilibcli/lsarpc',
    '-Ilibcli/named_pipe_auth',
    '-Ilibcli/nbt',
    '-Ilibcli/netlogon',
    '-Ilibcli/registry',
    '-Ilibcli/security',
    '-Ilibcli/smb',
    '-Ilibcli/util',
    '-Ilibds/common',
    '-Ilibrpc',
    '-Insswitch',
    '-Insswitch/libwbclient',
    '-Isource3',
    '-Isource3/auth',
    '-Isource3/include',
    '-Isource3/lib',
    '-Isource3/librpc',
    '-Isource3/modules',
    '-Isource3/param',
    '-Isource3/rpc_server',
    '-Isource3/smbd/notifyd',
    '-Isource4',
    '-Isource4/auth',
    '-Isource4/auth/gensec',
    '-Isource4/auth/kerberos',
    '-Isource4/cluster',
    '-Isource4/dsdb',
    '-Isource4/include',
    '-Isource4/lib',
    '-Isource4/lib/events',
    '-Isource4/lib/http',
    '-Isource4/lib/messaging',
    '-Isource4/lib/socket',
    '-Isource4/lib/stream',
    '-Isource4/lib/tls',
    '-Isource4/libcli',
    '-Isource4/libcli/ldap',
    '-Isource4/librpc',
    '-Isource4/param',
    '-Ithird_party/zlib',
    '-Ibin/default',
    '-Ibin/default/auth',
    '-Ibin/default/auth/credentials',
    '-Ibin/default/auth/gensec',
    '-Ibin/default/auth/kerberos',
    '-Ibin/default/auth/ntlmssp',
    '-Ibin/default/ctdb',
    '-Ibin/default/ctdb/include',
    '-Ibin/default/dynconfig',
    '-Ibin/default/include',
    '-Ibin/default/include/public',
    '-Ibin/default/lib',
    '-Ibin/default/lib/addns',
    '-Ibin/default/lib/afs',
    '-Ibin/default/lib/async_req',
    '-Ibin/default/lib/compression',
    '-Ibin/default/lib/crypto',
    '-Ibin/default/lib/dbwrap',
    '-Ibin/default/lib/krb5_wrap',
    '-Ibin/default/lib/ldb',
    '-Ibin/default/lib/ldb-samba',
    '-Ibin/default/lib/ldb/include',
    '-Ibin/default/lib/param',
    '-Ibin/default/lib/pthreadpool',
    '-Ibin/default/lib/replace',
    '-Ibin/default/lib/smbconf',
    '-Ibin/default/lib/socket',
    '-Ibin/default/lib/talloc',
    '-Ibin/default/lib/tdb',
    '-Ibin/default/lib/tdb/include',
    '-Ibin/default/lib/tevent',
    '-Ibin/default/lib/tsocket',
    '-Ibin/default/lib/util/charset',
    '-Ibin/default/libcli/auth',
    '-Ibin/default/libcli/cldap',
    '-Ibin/default/libcli/drsuapi',
    '-Ibin/default/libcli/ldap',
    '-Ibin/default/libcli/lsarpc',
    '-Ibin/default/libcli/named_pipe_auth',
    '-Ibin/default/libcli/nbt',
    '-Ibin/default/libcli/netlogon',
    '-Ibin/default/libcli/registry',
    '-Ibin/default/libcli/security',
    '-Ibin/default/libcli/smb',
    '-Ibin/default/libcli/util',
    '-Ibin/default/libds/common',
    '-Ibin/default/librpc',
    '-Ibin/default/nsswitch',
    '-Ibin/default/nsswitch/libwbclient',
    '-Ibin/default/source3',
    '-Ibin/default/source3/auth',
    '-Ibin/default/source3/include',
    '-Ibin/default/source3/lib',
    '-Ibin/default/source3/librpc',
    '-Ibin/default/source3/modules',
    '-Ibin/default/source3/param',
    '-Ibin/default/source3/rpc_server',
    '-Ibin/default/source3/smbd/notifyd',
    '-Ibin/default/source4',
    '-Ibin/default/source4/auth',
    '-Ibin/default/source4/auth/gensec',
    '-Ibin/default/source4/auth/kerberos',
    '-Ibin/default/source4/cluster',
    '-Ibin/default/source4/dsdb',
    '-Ibin/default/source4/include',
    '-Ibin/default/source4/lib',
    '-Ibin/default/source4/lib/events',
    '-Ibin/default/source4/lib/http',
    '-Ibin/default/source4/lib/messaging',
    '-Ibin/default/source4/lib/socket',
    '-Ibin/default/source4/lib/stream',
    '-Ibin/default/source4/lib/tls',
    '-Ibin/default/source4/libcli',
    '-Ibin/default/source4/libcli/ldap',
    '-Ibin/default/source4/librpc',
    '-Ibin/default/source4/param',
    '-Ibin/default/third_party/zlib',
    '-Wall',
    '-Wcast-align',
    '-Wcast-qual',
    '-Wdeclaration-after-statement',
    '-Werror',
    '-Werror-implicit-function-declaration',
    '-Werror=address',
    '-Werror=declaration-after-statement',
    '-Werror=format',
    '-Werror=format-security',
    '-Werror=pointer-arith',
    '-Werror=return-type',
    '-Werror=strict-prototypes',
    '-Werror=uninitialized',
    '-Werror=write-strings',
    '-Wformat-security',
    '-Wformat=2',
    '-Wmissing-prototypes',
    '-Wno-error=deprecated-declarations',
    '-Wno-error=tautological-compare',
    '-Wno-format-y2k',
    '-Wpointer-arith',
    '-Wreturn-type',
    '-Wshadow',
    '-Wstrict-prototypes',
    '-Wuninitialized',
    '-Wwrite-strings',
]


# Set this to the absolute path to the folder (NOT the file!) containing the
# compile_commands.json file to use that instead of 'flags'. See here for
# more details: http://clang.llvm.org/docs/JSONCompilationDatabase.html
#
# You can get CMake to generate this file for you by adding:
#   set( CMAKE_EXPORT_COMPILE_COMMANDS 1 )
# to your CMakeLists.txt file.
#
# Most projects will NOT need to set this to anything; you can just change the
# 'flags' list of compilation flags. Notice that YCM itself uses that approach.
compilation_database_folder = ''

if os.path.exists( compilation_database_folder ):
  database = ycm_core.CompilationDatabase( compilation_database_folder )
else:
  database = None

SOURCE_EXTENSIONS = [ '.C', '.cpp', '.cxx', '.cc', '.c', '.m', '.mm' ]


def DirectoryOfThisScript():
  return os.path.dirname( os.path.abspath( __file__ ) )


def MakeRelativePathsInFlagsAbsolute( flags, working_directory ):
  if not working_directory:
    return list( flags )
  new_flags = []
  make_next_absolute = False
  path_flags = [ '-isystem', '-I', '-iquote', '--sysroot=' ]
  for flag in flags:
    new_flag = flag

    if make_next_absolute:
      make_next_absolute = False
      if not flag.startswith( '/' ):
        new_flag = os.path.join( working_directory, flag )

    for path_flag in path_flags:
      if flag == path_flag:
        make_next_absolute = True
        break

      if flag.startswith( path_flag ):
        path = flag[ len( path_flag ): ]
        new_flag = path_flag + os.path.join( working_directory, path )
        break

    if new_flag:
      new_flags.append( new_flag )
  return new_flags


def IsHeaderFile( filename ):
  extension = os.path.splitext( filename )[ 1 ]
  return extension in [ '.H', '.h', '.hxx', '.hpp', '.hh' ]


def GetCompilationInfoForFile( filename ):
  # The compilation_commands.json file generated by CMake does not have entries
  # for header files. So we do our best by asking the db for flags for a
  # corresponding source file, if any. If one exists, the flags for that file
  # should be good enough.
  if IsHeaderFile( filename ):
    basename = os.path.splitext( filename )[ 0 ]
    for extension in SOURCE_EXTENSIONS:
      replacement_file = basename + extension
      if os.path.exists( replacement_file ):
        compilation_info = database.GetCompilationInfoForFile(
          replacement_file )
        if compilation_info.compiler_flags_:
          return compilation_info
    return None
  return database.GetCompilationInfoForFile( filename )


def FlagsForFile( filename, **kwargs ):
  if database:
    # Bear in mind that compilation_info.compiler_flags_ does NOT return a
    # python list, but a "list-like" StringVec object
    compilation_info = GetCompilationInfoForFile( filename )
    if not compilation_info:
      return None

    final_flags = MakeRelativePathsInFlagsAbsolute(
      compilation_info.compiler_flags_,
      compilation_info.compiler_working_dir_ )
  else:
    relative_to = DirectoryOfThisScript()
    final_flags = MakeRelativePathsInFlagsAbsolute( flags, relative_to )

  return {
    'flags': final_flags,
    'do_cache': True
  }
