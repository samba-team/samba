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
'-Wall',
'-Wextra',
'-Werror',
'-Wno-unused-parameter',
# This is a C project
'-x', 'c',
# Defines
'-DCONFIG_H_IS_FROM_SAMBA=1',
'-DHAVE_CONFIG_H=1',
'-D_SAMBA_BUILD_=4',
'-DAD_DC_BUILD_IS_ENABLED=1',
'-D_GNU_SOURCE=1',
'-DHAVE_IPV6=1',
# Includes
'-I.',
'-Iauth',
'-Iauth/credentials',
'-Iauth/gensec',
'-Iauth/kerberos',
'-Iauth/ntlmssp',
'-Idfs_server',
'-Idynconfig',
'-Iinclude',
'-Iinclude/public',
'-Ilib',
'-Ilib/addns',
'-Ilib/async_req',
'-Ilib/ccan',
'-Ilib/compression',
'-Ilib/crypto',
'-Ilib/dbwrap',
'-Ilib/krb5_wrap',
'-Ilib/ldb',
'-Ilib/ldb-samba',
'-Ilib/ldb/include',
'-Ilib/param',
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
'-Ilibcli/dns',
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
'-Isource3/lib/asys',
'-Isource3/lib/pthreadpool',
'-Isource3/librpc',
'-Isource3/modules',
'-Isource3/passdb',
'-Isource3/rpc_server',
'-Isource4',
'-Isource4/auth',
'-Isource4/auth/gensec',
'-Isource4/auth/kerberos',
'-Isource4/dsdb',
'-Isource4/include',
'-Isource4/lib',
'-Isource4/lib/events',
'-Isource4/lib/socket',
'-Isource4/lib/stream',
'-Isource4/lib/tls',
'-Isource4/libcli',
'-Isource4/libcli/ldap',
'-Isource4/param',
'-Isource4/winbind',
# Generated headers
'-Ibin/default',
'-Ibin/default/auth/credentials',
'-Ibin/default/auth/gensec',
'-Ibin/default/file_server',
'-Ibin/default/include',
'-Ibin/default/include/public',
'-Ibin/default/include/public/core',
'-Ibin/default/include/public/gen_ndr',
'-Ibin/default/include/public/ndr',
'-Ibin/default/include/public/samba',
'-Ibin/default/include/public/util',
'-Ibin/default/libcli/nbt',
'-Ibin/default/lib/crypto',
'-Ibin/default/lib/ldb/include',
'-Ibin/default/lib/ldb-samba',
'-Ibin/default/lib/param',
'-Ibin/default/librpc/gen_ndr',
'-Ibin/default/lib/util',
'-Ibin/default/source3/include',
'-Ibin/default/source3/librpc/gen_ndr',
'-Ibin/default/source3/param',
'-Ibin/default/source4',
'-Ibin/default/source4/auth',
'-Ibin/default/source4/auth/gensec',
'-Ibin/default/source4/auth/kerberos',
'-Ibin/default/source4/auth/ntlm',
'-Ibin/default/source4/cldap_server',
'-Ibin/default/source4/dsdb/common',
'-Ibin/default/source4/dsdb/kcc',
'-Ibin/default/source4/dsdb/repl',
'-Ibin/default/source4/dsdb/samdb',
'-Ibin/default/source4/dsdb/samdb/ldb_modules',
'-Ibin/default/source4/dsdb/schema',
'-Ibin/default/source4/heimdal/kdc',
'-Ibin/default/source4/heimdal/lib/asn1',
'-Ibin/default/source4/heimdal/lib/gssapi',
'-Ibin/default/source4/heimdal/lib/gssapi/krb5',
'-Ibin/default/source4/heimdal/lib/gssapi/spnego',
'-Ibin/default/source4/heimdal/lib/hdb',
'-Ibin/default/source4/heimdal/lib/hx509',
'-Ibin/default/source4/heimdal/lib/krb5',
'-Ibin/default/source4/heimdal/lib/ntlm',
'-Ibin/default/source4/heimdal/lib/wind',
'-Ibin/default/source4/ldap_server',
'-Ibin/default/source4/libcli',
'-Ibin/default/source4/libcli/composite',
'-Ibin/default/source4/libcli/ldap',
'-Ibin/default/source4/libcli/rap',
'-Ibin/default/source4/libcli/raw',
'-Ibin/default/source4/libcli/resolve',
'-Ibin/default/source4/libcli/smb2',
'-Ibin/default/source4/libcli/util',
'-Ibin/default/source4/libcli/wrepl',
'-Ibin/default/source4/lib/cmdline',
'-Ibin/default/source4/libnet',
'-Ibin/default/source4/lib/registry',
'-Ibin/default/source4/lib/registry/tests',
'-Ibin/default/source4/lib/registry/tools',
'-Ibin/default/source4/librpc/gen_ndr',
'-Ibin/default/source4/librpc/rpc',
'-Ibin/default/source4/lib/socket',
'-Ibin/default/source4/nbt_server',
'-Ibin/default/source4/nbt_server/dgram',
'-Ibin/default/source4/nbt_server/wins',
'-Ibin/default/source4/ntptr',
'-Ibin/default/source4/ntvfs',
'-Ibin/default/source4/ntvfs/cifs_posix_cli',
'-Ibin/default/source4/ntvfs/common',
'-Ibin/default/source4/ntvfs/ipc',
'-Ibin/default/source4/ntvfs/posix',
'-Ibin/default/source4/ntvfs/simple',
'-Ibin/default/source4/rpc_server',
'-Ibin/default/source4/rpc_server/backupkey',
'-Ibin/default/source4/rpc_server/common',
'-Ibin/default/source4/rpc_server/lsa',
'-Ibin/default/source4/rpc_server/samr',
'-Ibin/default/source4/rpc_server/srvsvc',
'-Ibin/default/source4/smbd',
'-Ibin/default/source4/smb_server',
'-Ibin/default/source4/smb_server/smb',
'-Ibin/default/source4/smb_server/smb2',
'-Ibin/default/source4/torture/auth',
'-Ibin/default/source4/torture/basic',
'-Ibin/default/source4/torture/dfs',
'-Ibin/default/source4/torture/drs',
'-Ibin/default/source4/torture/ldap',
'-Ibin/default/source4/torture/libnet',
'-Ibin/default/source4/torture/libnetapi',
'-Ibin/default/source4/torture/libsmbclient',
'-Ibin/default/source4/torture/local',
'-Ibin/default/source4/torture/nbench',
'-Ibin/default/source4/torture/nbt',
'-Ibin/default/source4/torture/ndr',
'-Ibin/default/source4/torture/ntp',
'-Ibin/default/source4/torture/rap',
'-Ibin/default/source4/torture/raw',
'-Ibin/default/source4/torture/rpc',
'-Ibin/default/source4/torture/smb2',
'-Ibin/default/source4/torture/unix',
'-Ibin/default/source4/torture/winbind',
'-Ibin/default/source4/winbind',
'-Ibin/default/source4/wrepl_server',
'-Ibin/default/testsuite/headers',
]

# Set this to the absolute path to the folder (NOT the file!) containing the
# compile_commands.json file to use that instead of 'flags'. See here for
# more details: http://clang.llvm.org/docs/JSONCompilationDatabase.html
#
# Most projects will NOT need to set this to anything; you can just change the
# 'flags' list of compilation flags. Notice that YCM itself uses that approach.
compilation_database_folder = ''

if os.path.exists( compilation_database_folder ):
  database = ycm_core.CompilationDatabase( compilation_database_folder )
else:
  database = None

SOURCE_EXTENSIONS = [ '.cpp', '.cxx', '.cc', '.c', '.m', '.mm' ]

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
  return extension in [ '.h', '.hxx', '.hpp', '.hh' ]


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
