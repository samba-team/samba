/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   Build Options for Samba Suite
   Copyright (C) Vance Lankhaar <vlankhaar@hotmail.com> 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "build_env.h"

/****************************************************************************
helper function for build_options
****************************************************************************/
static void output(BOOL screen, char *buffer)
{
       if (screen) {
              d_printf(buffer);
       } else {
	       DEBUG(4, (buffer));
       }
}
/****************************************************************************
options set at build time for the samba suite
****************************************************************************/
void build_options(BOOL screen)
{
       pstring outstring;

       if ((DEBUGLEVEL < 4) && (!screen)) {
	       return;
       }

#ifdef _BUILD_ENV_H
       /* Output information about the build environment */
       snprintf(outstring,sizeof(outstring),"Build environment:\n");
       output(screen,outstring);       
       snprintf(outstring,sizeof(outstring),"   Built by:    %s@%s\n",BUILD_ENV_USER,BUILD_ENV_HOST);
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   Built on:    %s\n",BUILD_ENV_DATE);
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   Built using: %s\n",BUILD_ENV_COMPILER);
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   Build host:  %s\n",BUILD_ENV_UNAME);
       output(screen,outstring);
    
       snprintf(outstring,sizeof(outstring),"   SRCDIR:      %s\n",BUILD_ENV_SRCDIR);
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   BUILDDIR:    %s\n",BUILD_ENV_BUILDDIR);
       output(screen,outstring);
       
#endif

       /* Output various options (most correspond to --with options) */ 
       snprintf(outstring,sizeof(outstring),"\nBuild options:\n");
       output(screen,outstring);
#ifdef WITH_SMBWRAPPER 
       snprintf(outstring,sizeof(outstring),"   WITH_SMBWRAPPER\n");
       output(screen,outstring);
#endif
#ifdef WITH_AFS
       snprintf(outstring,sizeof(outstring),"   WITH_AFS\n");
       output(screen,outstring);
#endif
#ifdef WITH_DFS
       snprintf(outstring,sizeof(outstring),"   WITH_DFS\n");
       output(screen,outstring);
#endif
#if defined(KRB4_AUTH) && defined(KRB4_DIR) 
       snprintf(outstring,sizeof(outstring),"   KRB4_AUTH");
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   KRB4_DIR: %s\n",KRB4_DIR);
       output(screen,outstring);
#endif
#if HAVE_KRB5
       output(screen,"   HAVE_KRB5");
#endif
#ifdef WITH_AUTOMOUNT
       snprintf(outstring,sizeof(outstring),"   WITH_AUTOMOUNT\n");
       output(screen,outstring);
#endif
#ifdef WITH_SMBMOUNT
       snprintf(outstring,sizeof(outstring),"   WITH_SMBMOUNT\n");
       output(screen,outstring);
#endif
#ifdef WITH_PAM
       snprintf(outstring,sizeof(outstring),"   WITH_PAM\n");
       output(screen,outstring);
#endif
#ifdef WITH_TDB_SAM
       snprintf(outstring,sizeof(outstring),"   WITH_TDB_SAM\n");
       output(screen,outstring);
#endif
#ifdef WITH_LDAP_SAM
       snprintf(outstring,sizeof(outstring),"   WITH_LDAP_SAM\n");
       output(screen,outstring);
#endif
#ifdef WITH_SMBPASSWD_SAM
       snprintf(outstring,sizeof(outstring),"   WITH_SMBPASSWD_SAM\n");
       output(screen,outstring);
#endif
#ifdef WITH_NISPLUS_SAM
       snprintf(outstring,sizeof(outstring),"   WITH_NISPLUS_SAM\n");
       output(screen,outstring);
#endif
#ifdef WITH_NISPLUS_HOME
       snprintf(outstring,sizeof(outstring),"   WITH_NISPLUS_HOME\n");
       output(screen,outstring);
#endif
#ifdef WITH_SSL
       snprintf(outstring,sizeof(outstring),"   WITH_SSL\n");
       output(screen,outstring);
#endif
#ifdef SSL_DIR
       snprintf(outstring,sizeof(outstring),"   SSL_DIR: %s\n",SSL_DIR);
       output(screen,outstring);
#endif
#ifdef WITH_SYSLOG
       snprintf(outstring,sizeof(outstring),"   WITH_SYSLOG\n");
       output(screen,outstring);
#endif
#ifdef WITH_PROFILE
       snprintf(outstring,sizeof(outstring),"   WITH_PROFILE\n");
       output(screen,outstring);
#endif
#ifdef WITH_QUOTAS
       snprintf(outstring,sizeof(outstring),"   WITH_QUOTAS\n");
       output(screen,outstring);
#endif
#ifdef WITH_MSDFS
       snprintf(outstring,sizeof(outstring),"   WITH_MSDFS\n");
       output(screen,outstring);
#endif
#ifdef WITH_VFS
       snprintf(outstring,sizeof(outstring),"   WITH_VFS\n");
       output(screen,outstring);
#endif
#ifdef USE_SPINLOCKS
       snprintf(outstring,sizeof(outstring),"   USE_SPINLOCKS\n");
       output(screen,outstring);
#endif
#ifdef SPARC_SPINLOCKS
       snprintf(outstring,sizeof(outstring),"   SPARC_SPINLOCKS\n");
       output(screen,outstring);
#endif
#ifdef INTEL_SPINLOCKS
       snprintf(outstring,sizeof(outstring),"   INTEL_SPINLOCKS\n");
       output(screen,outstring);
#endif
#ifdef MIPS_SPINLOCKS
       snprintf(outstring,sizeof(outstring),"   MIPS_SPINLOCKS\n");
       output(screen,outstring);
#endif
#ifdef POWERPC_SPINLOCKS
       snprintf(outstring,sizeof(outstring),"   POWERPC_SPINLOCKS\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UNIXWARE_ACLS
       snprintf(outstring,sizeof(outstring),"   HAVE_UNIXWARE_ACLS\n");
       output(screen,outstring);
#endif
#ifdef HAVE_SOLARIS_ACLS
       snprintf(outstring,sizeof(outstring),"   HAVE_SOLARIS_ACLS\n");
       output(screen,outstring);
#endif 
#ifdef HAVE_IRIX_ACLS
       snprintf(outstring,sizeof(outstring),"   HAVE_IRIX_ACLS\n");
       output(screen,outstring);
#endif
#ifdef HAVE_AIX_ACLS
       snprintf(outstring,sizeof(outstring),"   HAVE_AIX_ACLS\n");
       output(screen,outstring);
#endif
#ifdef HAVE_POSIX_ACLS
       snprintf(outstring,sizeof(outstring),"   HAVE_POSIX_ACLS\n");
       output(screen,outstring);
#endif
#ifdef HAVE_TRU64_ACLS
       snprintf(outstring,sizeof(outstring),"   HAVE_TRU64_ACLS\n");
       output(screen,outstring);
#endif

#ifdef HAVE_ACL_GET_PERM_NP
       snprintf(outstring,sizeof(outstring),"   HAVE_ACL_GET_PERM_NP\n");
       output(screen,outstring);
#endif
#ifdef HAVE_NO_ACLS
       snprintf(outstring,sizeof(outstring),"   HAVE_NO_ACLS\n");
       output(screen,outstring);
#endif
#ifdef HAVE_LIBREADLINE
       snprintf(outstring,sizeof(outstring),"   HAVE_LIBREADLINE\n"); 
       output(screen,outstring);
#endif
#ifdef WITH_LIBICONV
       snprintf(outstring,sizeof(outstring),"   WITH_LIBICONV: %s\n",WITH_LIBICONV);
       output(screen,outstring);
#endif


       /* Output various paths to files and directories */
       snprintf(outstring,sizeof(outstring),"\nPaths:\n");
       output(screen,outstring);
#ifdef CONFIGFILE
       snprintf(outstring,sizeof(outstring),"   CONFIGFILE: %s\n",CONFIGFILE);
       output(screen,outstring);
#endif
#ifdef PRIVATE_DIR
       snprintf(outstring,sizeof(outstring),"   PRIVATE_DIR: %s\n",PRIVATE_DIR);
       output(screen,outstring);
#endif
#ifdef LMHOSTSFILE
       snprintf(outstring,sizeof(outstring),"   LMHOSTSFILE: %s\n",LMHOSTSFILE);
       output(screen,outstring);
#endif
#ifdef SBINDIR
       snprintf(outstring,sizeof(outstring),"   SBINDIR: %s\n",SBINDIR);
       output(screen,outstring);
#endif
#ifdef BINDIR
       snprintf(outstring,sizeof(outstring),"   BINDIR: %s\n",BINDIR);
       output(screen,outstring);
#endif
#ifdef LOCKDIR
       snprintf(outstring,sizeof(outstring),"   LOCKDIR: %s\n",LOCKDIR);
       output(screen,outstring);
#endif
#ifdef DRIVERFILE
       snprintf(outstring,sizeof(outstring),"   DRIVERFILE: %s\n",DRIVERFILE);
       output(screen,outstring);
#endif
#ifdef LOGFILEBASE
       snprintf(outstring,sizeof(outstring),"   LOGFILEBASE: %s\n",LOGFILEBASE);
       output(screen,outstring);
#endif
#ifdef FORMSFILE
       snprintf(outstring,sizeof(outstring),"   FORMSFILE: %s\n",FORMSFILE);
       output(screen,outstring);
#endif
#ifdef NTDRIVERSDIR
       snprintf(outstring,sizeof(outstring),"   NTDRIVERSDIR: %s\n",NTDRIVERSDIR);
       output(screen,outstring);
#endif 

       /*Output various other options (most map to defines in the configure script*/
       snprintf(outstring,sizeof(outstring),"\nOther Build Options:\n");
       output(screen,outstring);
#ifdef HAVE_VOLATILE
       snprintf(outstring,sizeof(outstring),"   HAVE_VOLATILE\n");
       output(screen,outstring);
#endif
#ifdef HAVE_SHADOW_H
       snprintf(outstring,sizeof(outstring),"   HAVE_SHADOW_H\n");
       output(screen,outstring);
#endif
#ifdef HAVE_CRYPT
       snprintf(outstring,sizeof(outstring),"   HAVE_CRYPT\n");
       output(screen,outstring);
#endif
#ifdef USE_BOTH_CRYPT_CALLS
       snprintf(outstring,sizeof(outstring),"   USE_BOTH_CRYPT_CALLS\n");
       output(screen,outstring);
#endif
#ifdef HAVE_TRUNCATED_SALT
       snprintf(outstring,sizeof(outstring),"   HAVE_TRUNCATED_SALT\n");
       output(screen,outstring);
#endif
#ifdef HAVE_CUPS
       snprintf(outstring,sizeof(outstring),"   HAVE_CUPS\n");
       output(screen,outstring);
#endif
#ifdef HAVE_CUPS_CUPS_H
       snprintf(outstring,sizeof(outstring),"   HAVE_CUPS_CUPS_H\n");
       output(screen,outstring);
#endif
#ifdef HAVE_CUPS_LANGUAGE_H
       snprintf(outstring,sizeof(outstring),"   HAVE_CUPS_LANGUAGE_H\n");
       output(screen,outstring);
#endif
#ifdef HAVE_LIBDL
       snprintf(outstring,sizeof(outstring),"   HAVE_LIBDL\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UNIXSOCKET
       snprintf(outstring,sizeof(outstring),"   HAVE_UNIXSOCKET\n");
       output(screen,outstring);
#endif
#ifdef HAVE_SOCKLEN_T_TYPE
       snprintf(outstring,sizeof(outstring),"   HAVE_SOCKLEN_T_TYPE\n");
       output(screen,outstring);
#endif
#ifdef HAVE_SIG_ATOMIC_T_TYPE
       snprintf(outstring,sizeof(outstring),"   HAVE_SIG_ATOMIC_T_TYPE\n");
       output(screen,outstring);
#endif
#ifdef HAVE_SETRESUID
       snprintf(outstring,sizeof(outstring),"   HAVE_SETRESUID\n");
       output(screen,outstring);
#endif
#ifdef HAVE_SETRESGID
       snprintf(outstring,sizeof(outstring),"   HAVE_SETRESGID\n");
       output(screen,outstring);
#endif
#ifdef HAVE_CONNECT
       snprintf(outstring,sizeof(outstring),"   HAVE_CONNECT\n");
       output(screen,outstring);
#endif
#ifdef HAVE_YP_GET_DEFAULT_DOMAIN
       snprintf(outstring,sizeof(outstring),"   HAVE_YP_GET_DEFAULT_DOMAIN\n");
       output(screen,outstring);
#endif
#ifdef HAVE_STAT64
       snprintf(outstring,sizeof(outstring),"   HAVE_STAT64\n");
       output(screen,outstring);
#endif
#ifdef HAVE_LSTAT64
       snprintf(outstring,sizeof(outstring),"   HAVE_LSTAT64\n");
       output(screen,outstring);
#endif
#ifdef HAVE_FSTAT64
       snprintf(outstring,sizeof(outstring),"   HAVE_FSTAT64\n");
       output(screen,outstring);
#endif
#ifdef HAVE_STRCASECMP
       snprintf(outstring,sizeof(outstring),"   HAVE_STRCASECMP\n");
       output(screen,outstring);
#endif
#ifdef HAVE_MEMSET
       snprintf(outstring,sizeof(outstring),"   HAVE_MEMSET\n");
       output(screen,outstring);
#endif
#ifdef HAVE_LONGLONG
       snprintf(outstring,sizeof(outstring),"   HAVE_LONGLONG\n");
       output(screen,outstring);
#endif
#ifdef COMPILER_SUPPORTS_LL
       snprintf(outstring,sizeof(outstring),"   COMPILER_SUPPORTS_LL\n");
       output(screen,outstring);
#endif
#ifdef SIZEOF_OFF_T
       snprintf(outstring,sizeof(outstring),"   SIZEOF_OFF_T: %d\n",SIZEOF_OFF_T);
       output(screen,outstring);
#endif
#ifdef HAVE_OFF64_T
       snprintf(outstring,sizeof(outstring),"   HAVE_OFF64_T\n");
       output(screen,outstring);
#endif
#ifdef SIZEOF_INO_T
       snprintf(outstring,sizeof(outstring),"   SIZEOF_INO_T: %d\n",SIZEOF_INO_T);
       output(screen,outstring);
#endif
#ifdef HAVE_INO64_T
       snprintf(outstring,sizeof(outstring),"   HAVE_INO64_T\n");
       output(screen,outstring);
#endif
#ifdef HAVE_STRUCT_DIRENT64
       snprintf(outstring,sizeof(outstring),"   HAVE_STRUCT_DIRENT64\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UNSIGNED_CHAR
       snprintf(outstring,sizeof(outstring),"   HAVE_UNSIGNED_CHAR\n");
       output(screen,outstring);
#endif
#ifdef HAVE_SOCK_SIN_LEN
       snprintf(outstring,sizeof(outstring),"   HAVE_SOCK_SIN_LEN\n");
       output(screen,outstring);
#endif
#ifdef SEEKDIR_RETURNS_VOID
       snprintf(outstring,sizeof(outstring),"   SEEKDIR_RETURNS_VOID\n");
       output(screen,outstring);
#endif
#ifdef HAVE_FILE_MACRO
       snprintf(outstring,sizeof(outstring),"   HAVE_FILE_MACRO\n");
       output(screen,outstring);
#endif
#ifdef HAVE_FUNCTION_MACRO
       snprintf(outstring,sizeof(outstring),"   HAVE_FUNCTION_MACRO\n");
       output(screen,outstring);
#endif
#ifdef HAVE_GETTIMEOFDAY
       snprintf(outstring,sizeof(outstring),"   HAVE_GETTIMEOFDAY\n");
       output(screen,outstring);
#endif
#ifdef HAVE_C99_VSNPRINTF
       snprintf(outstring,sizeof(outstring),"   HAVE_C99_VSNPRINTF\n");
       output(screen,outstring);
#endif
#ifdef HAVE_BROKEN_READDIR
       snprintf(outstring,sizeof(outstring),"   HAVE_BROKEN_READDIR\n");
       output(screen,outstring);
#endif
#ifdef HAVE_NATIVE_ICONV
       snprintf(outstring,sizeof(outstring),"   HAVE_NATIVE_ICONV\n");
       output(screen,outstring);
#endif
#ifdef HAVE_KERNEL_OPLOCKS_LINUX
       snprintf(outstring,sizeof(outstring),"   HAVE_KERNEL_OPLOCKS_LINUX\n");
       output(screen,outstring);
#endif
#ifdef HAVE_KERNEL_CHANGE_NOTIFY
       snprintf(outstring,sizeof(outstring),"   HAVE_KERNEL_CHANGE_NOTIFY\n");
       output(screen,outstring);
#endif
#ifdef HAVE_KERNEL_SHARE_MODES
       snprintf(outstring,sizeof(outstring),"   HAVE_KERNEL_SHARE_MODES\n");
       output(screen,outstring);
#endif
#ifdef HAVE_KERNEL_OPLOCKS_IRIX
       snprintf(outstring,sizeof(outstring),"   HAVE_KERNEL_OPLOCKS_IRIX\n");
       output(screen,outstring);
#endif
#ifdef HAVE_IRIX_SPECIFIC_CAPABILITIES
       snprintf(outstring,sizeof(outstring),"   HAVE_IRIX_SPECIFIC_CAPABILITIES\n");
       output(screen,outstring);
#endif
#ifdef HAVE_INT16_FROM_RPC_RPC_H
       snprintf(outstring,sizeof(outstring),"   HAVE_INT16_FROM_RPC_RPC_H\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UINT16_FROM_RPC_RPC_H
       snprintf(outstring,sizeof(outstring),"   HAVE_UINT16_FROM_RPC_RPC_H\n");
       output(screen,outstring);
#endif
#ifdef HAVE_INT32_FROM_RPC_RPC_H
       snprintf(outstring,sizeof(outstring),"   HAVE_INT16_FROM_RPC_RPC_H\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UINT32_FROM_RPC_RPC_H
       snprintf(outstring,sizeof(outstring),"   HAVE_UINT32_FROM_RPC_RPC_H\n");
       output(screen,outstring);
#endif
#ifdef HAVE_RPC_AUTH_ERROR_CONFLICT
       snprintf(outstring,sizeof(outstring),"   HAVE_RPC_AUTH_ERROR_CONFLICT\n");
       output(screen,outstring);
#endif
#ifdef HAVE_FTRUNCATE_EXTEND
       snprintf(outstring,sizeof(outstring),"   HAVE_FTRUNCATE_EXTEND\n");
       output(screen,outstring);
#endif
#ifdef HAVE_WORKING_AF_LOCAL
       snprintf(outstring,sizeof(outstring),"   HAVE_WORKING_AF_LOCAL\n");
       output(screen,outstring);
#endif
#ifdef HAVE_BROKEN_GETGROUPS
       snprintf(outstring,sizeof(outstring),"   HAVE_BROKEN_GETGROUPS\n");
       output(screen,outstring);
#endif
#ifdef REPLACE_GETPASS
       snprintf(outstring,sizeof(outstring),"   REPLACE_GETPASS\n");
       output(screen,outstring);
#endif
#ifdef REPLACE_INET_NTOA
       snprintf(outstring,sizeof(outstring),"   REPLACE_INET_NTOA\n");
       output(screen,outstring);
#endif
#ifdef HAVE_SECURE_MKSTEMP
       snprintf(outstring,sizeof(outstring),"   HAVE_SECURE_MKSTEMP\n");
       output(screen,outstring);
#endif
#ifdef SYSCONF_SC_NGROUPS_MAX
       snprintf(outstring,sizeof(outstring),"   SYSCONF_SC_NGROUPS_MAX\n");
       output(screen,outstring);
#endif
#ifdef HAVE_IFACE_AIX
       snprintf(outstring,sizeof(outstring),"   HAVE_IFACE_AIX\n");
       output(screen,outstring);
#endif
#ifdef HAVE_IFACE_IFCONF
       snprintf(outstring,sizeof(outstring),"   HAVE_IFACE_IFCONF\n");
       output(screen,outstring);
#endif
#ifdef HAVE_IFACE_IFREQ
       snprintf(outstring,sizeof(outstring),"   HAVE_IFACE_IFREQ\n");
       output(screen,outstring);
#endif
#ifdef USE_SETRESUID
       snprintf(outstring,sizeof(outstring),"   USE_SETRESUID\n");
       output(screen,outstring);
#endif
#ifdef USE_SETRESGID
       snprintf(outstring,sizeof(outstring),"   USE_SETREUID\n");
       output(screen,outstring);
#endif
#ifdef USE_SETEUID
       snprintf(outstring,sizeof(outstring),"   USE_SETEUID\n");
       output(screen,outstring);
#endif
#ifdef USE_SETUIDX
       snprintf(outstring,sizeof(outstring),"   USE_SETUIDX\n");
       output(screen,outstring);
#endif
#ifdef HAVE_MMAP
       snprintf(outstring,sizeof(outstring),"   HAVE_MMAP\n");
       output(screen,outstring);
#endif
#ifdef MMAP_BLACKLIST
       snprintf(outstring,sizeof(outstring),"   MMAP_BLACKLIST\n");
       output(screen,outstring);
#endif
#ifdef FTRUNCATE_NEEDS_ROOT
       snprintf(outstring,sizeof(outstring),"   FTRUNCATE_NEEDS_ROOT\n");
       output(screen,outstring);
#endif
#ifdef HAVE_FCNTL_LOCK
       snprintf(outstring,sizeof(outstring),"   HAVE_FCNTL_LOCK\n");
       output(screen,outstring);
#endif
#ifdef HAVE_BROKEN_FCNTL64_LOCKS
       snprintf(outstring,sizeof(outstring),"   HAVE_BROKEN_FCNTL64_LOCKS\n");
       output(screen,outstring);
#endif
#ifdef HAVE_STRUCT_FLOCK64
       snprintf(outstring,sizeof(outstring),"   HAVE_STRUCT_FLOCK64\n");
       output(screen,outstring);
#endif
#ifdef BROKEN_NISPLUS_INCLUDE_FILES
       snprintf(outstring,sizeof(outstring),"   BROKEN_NISPLUS_INCLUDE_FILES\n");
       output(screen,outstring);
#endif
#ifdef HAVE_LIBPAM
       snprintf(outstring,sizeof(outstring),"   HAVE_LIBPAM\n");
       output(screen,outstring);
#endif
#ifdef STAT_STATVFS64
       snprintf(outstring,sizeof(outstring),"   STAT_STATVFS64\n");
       output(screen,outstring);
#endif
#ifdef STAT_STATVFS
       snprintf(outstring,sizeof(outstring),"   STAT_STATVFS\n");
       output(screen,outstring);
#endif
#ifdef STAT_STATFS3_OSF1
       snprintf(outstring,sizeof(outstring),"   STAT_STATFS3_OSF1\n");
       output(screen,outstring);
#endif
#ifdef STAT_STATFS2_BSIZE
       snprintf(outstring,sizeof(outstring),"   STAT_STATFS2_BSIZE\n");
       output(screen,outstring);
#endif
#ifdef STAT_STATFS4
       snprintf(outstring,sizeof(outstring),"   STAT_STATFS4\n");
       output(screen,outstring);
#endif
#ifdef STAT_STATFS2_FSIZE
       snprintf(outstring,sizeof(outstring),"   STAT_STATFS2_FSIZE\n");
       output(screen,outstring);
#endif
#ifdef STAT_STATFS2_FS_DATA
       snprintf(outstring,sizeof(outstring),"   STAT_STATFS2_FS_DATA\n");
       output(screen,outstring);
#endif
#ifdef HAVE_EXPLICIT_LARGEFILE_SUPPORT
       snprintf(outstring,sizeof(outstring),"   HAVE_EXPLICIT_LARGEFILE_SUPPORT\n");
       output(screen,outstring);
#endif

#ifdef WITH_UTMP
       /* Output UTMP Stuff */
       snprintf(outstring,sizeof(outstring),"\nUTMP Related:\n");
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   WITH_UTMP\n");
       output(screen,outstring);

#ifdef HAVE_UTIMBUF
       snprintf(outstring,sizeof(outstring),"   HAVE_UTIMBUF\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UT_UT_NAME
       snprintf(outstring,sizeof(outstring),"   HAVE_UT_UT_NAME\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UT_UT_USER
       snprintf(outstring,sizeof(outstring),"   HAVE_UT_UT_USER\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UT_UT_ID
       snprintf(outstring,sizeof(outstring),"   HAVE_UT_UT_ID\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UT_UT_HOST
       snprintf(outstring,sizeof(outstring),"   HAVE_UT_UT_HOST\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UT_UT_TIME
       snprintf(outstring,sizeof(outstring),"   HAVE_UT_UT_TIME\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UT_UT_TV
       snprintf(outstring,sizeof(outstring),"   HAVE_UT_UT_TV\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UT_UT_TYPE
       snprintf(outstring,sizeof(outstring),"   HAVE_UT_UT_TYPE\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UT_UT_PID
       snprintf(outstring,sizeof(outstring),"   HAVE_UT_UT_PID\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UT_UT_EXIT
       snprintf(outstring,sizeof(outstring),"   HAVE_UT_UT_EXIT\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UT_UT_ADDR
       snprintf(outstring,sizeof(outstring),"   HAVE_UT_UT_ADDR\n");
       output(screen,outstring);
#endif
#ifdef PUTUTLINE_RETURNS_UTMP
       snprintf(outstring,sizeof(outstring),"   PUTUTLINE_RETURNS_UTMP\n");
       output(screen,outstring);
#endif
#ifdef HAVE_UX_UT_SYSLEN
       snprintf(outstring,sizeof(outstring),"   HAVE_UX_UT_SYSLEN\n");
       output(screen,outstring);
#endif
#endif

       /* Output Build OS */
       snprintf(outstring,sizeof(outstring),"\nBuilt for host os:\n");
       output(screen,outstring);
#ifdef LINUX
       snprintf(outstring,sizeof(outstring),"   LINUX\n");
       output(screen,outstring);
#endif
#ifdef SUNOS5
       snprintf(outstring,sizeof(outstring),"   SUNOS5\n");
       output(screen,outstring);
#endif
#ifdef SUNOS4
       snprintf(outstring,sizeof(outstring),"   SUNOS4\n");
       output(screen,outstring);
#endif
       /* BSD Isn't Defined in the configure script, but there is something about it in include/config.h.in (and I guess acconfig.h) */
#ifdef BSD
       snprintf(outstring,sizeof(outstring),"   BSD\n");
       output(screen,outstring);
#endif
#ifdef IRIX
       snprintf(outstring,sizeof(outstring),"   IRIX\n");
       output(screen,outstring);
#endif
#ifdef IRIX6
       snprintf(outstring,sizeof(outstring),"   IRIX6\n");
       output(screen,outstring);
#endif
#ifdef AIX
       snprintf(outstring,sizeof(outstring),"   AIX\n");
       output(screen,outstring);
#endif
#ifdef HPUX
       snprintf(outstring,sizeof(outstring),"   HPUX\n");
       output(screen,outstring);
#endif
#ifdef QNX
       snprintf(outstring,sizeof(outstring),"   QNX\n");
       output(screen,outstring);
#endif
#ifdef OSF1
       snprintf(outstring,sizeof(outstring),"   OSF1\n");
       output(screen,outstring);
#endif
#ifdef SCO
       snprintf(outstring,sizeof(outstring),"   SCO\n");
       output(screen,outstring);
#endif
#ifdef UNIXWARE
       snprintf(outstring,sizeof(outstring),"   UNIXWARE\n");
       output(screen,outstring);
#endif
#ifdef NEXT2
       snprintf(outstring,sizeof(outstring),"   NEXT2\n");
       output(screen,outstring);
#endif
#ifdef RELIANTUNIX
       snprintf(outstring,sizeof(outstring),"   RELIANTUNIX\n");
       output(screen,outstring);
#endif

       /* Output the sizes of the various types */
       snprintf(outstring,sizeof(outstring),"\nType sizes:\n");
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   sizeof(char):    %d\n",sizeof(char));
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   sizeof(int):     %d\n",sizeof(int));
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   sizeof(long):    %d\n",sizeof(long));
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   sizeof(uint8):   %d\n",sizeof(uint8));
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   sizeof(uint16):  %d\n",sizeof(uint16));
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   sizeof(uint32):  %d\n",sizeof(uint32));
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   sizeof(short):   %d\n",sizeof(short));
       output(screen,outstring);
       snprintf(outstring,sizeof(outstring),"   sizeof(void*):   %d\n",sizeof(void*));
       output(screen,outstring);
}



