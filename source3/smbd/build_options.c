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
#include "dynconfig.h"

static void output(BOOL screen, char *format, ...) PRINTF_ATTRIBUTE(2,3);

/*
#define OUTPUT(x) snprintf(outstring,sizeof(outstring),x); output(screen,outstring);
*/
/****************************************************************************
helper function for build_options
****************************************************************************/
static void output(BOOL screen, char *format, ...)
{
       char *ptr;
       va_list ap;
       
       va_start(ap, format);
       vasprintf(&ptr,format,ap);
       va_end(ap);

       if (screen) {
              d_printf("%s", ptr);
       } else {
	       DEBUG(4,("%s", ptr));
       }
       
       SAFE_FREE(ptr);
}

/****************************************************************************
options set at build time for the samba suite
****************************************************************************/
void build_options(BOOL screen)
{
       if ((DEBUGLEVEL < 4) && (!screen)) {
	       return;
       }

#ifdef _BUILD_ENV_H
       /* Output information about the build environment */
       output(screen,"Build environment:\n");
       output(screen,"   Built by:    %s@%s\n",BUILD_ENV_USER,BUILD_ENV_HOST);
       output(screen,"   Built on:    %s\n",BUILD_ENV_DATE);

       output(screen,"   Built using: %s\n",BUILD_ENV_COMPILER);
       output(screen,"   Build host:  %s\n",BUILD_ENV_UNAME);
       output(screen,"   SRCDIR:      %s\n",BUILD_ENV_SRCDIR);
       output(screen,"   BUILDDIR:    %s\n",BUILD_ENV_BUILDDIR);

       
#endif

       /* Output various options (most correspond to --with options) */ 
       output(screen,"\nBuild options:\n");
#ifdef WITH_SMBWRAPPER 
       output(screen,"   WITH_SMBWRAPPER\n");
#endif
#ifdef WITH_AFS
       output(screen,"   WITH_AFS\n");
#endif
#ifdef WITH_DFS
       output(screen,"   WITH_DFS\n");
#endif
#ifdef KRB4_AUTH
       output(screen,"   KRB4_AUTH");
#endif
#ifdef HAVE_KRB5
       output(screen,"   HAVE_KRB5");
#endif
#ifdef WITH_AUTOMOUNT
       output(screen,"   WITH_AUTOMOUNT\n");
#endif
#ifdef WITH_SMBMOUNT
       output(screen,"   WITH_SMBMOUNT\n");
#endif
#ifdef WITH_PAM
       output(screen,"   WITH_PAM\n");
#endif
#ifdef WITH_TDB_SAM
       output(screen,"   WITH_TDB_SAM\n");
#endif
#ifdef WITH_LDAP_SAM
       output(screen,"   WITH_LDAP_SAM\n");
#endif
#ifdef WITH_SMBPASSWD_SAM
       output(screen,"   WITH_SMBPASSWD_SAM\n");
#endif
#ifdef WITH_NISPLUS_SAM
       output(screen,"   WITH_NISPLUS_SAM\n");
#endif
#ifdef WITH_NISPLUS_HOME
       output(screen,"   WITH_NISPLUS_HOME\n");
#endif
#ifdef WITH_SSL
       output(screen,"   WITH_SSL\n");
#endif
#ifdef SSL_DIR
       output(screen,"   SSL_DIR: %s\n",SSL_DIR);
#endif
#ifdef WITH_SYSLOG
       output(screen,"   WITH_SYSLOG\n");
#endif
#ifdef WITH_PROFILE
       output(screen,"   WITH_PROFILE\n");
#endif
#ifdef WITH_QUOTAS
       output(screen,"   WITH_QUOTAS\n");
#endif
#ifdef WITH_VFS
       output(screen,"   WITH_VFS\n");
#endif
#ifdef USE_SPINLOCKS
       output(screen,"   USE_SPINLOCKS\n");
#endif
#ifdef SPARC_SPINLOCKS
       output(screen,"   SPARC_SPINLOCKS\n");
#endif
#ifdef INTEL_SPINLOCKS
       output(screen,"   INTEL_SPINLOCKS\n");
#endif
#ifdef MIPS_SPINLOCKS
       output(screen,"   MIPS_SPINLOCKS\n");
#endif
#ifdef POWERPC_SPINLOCKS
       output(screen,"   POWERPC_SPINLOCKS\n");
#endif
#ifdef HAVE_UNIXWARE_ACLS
       output(screen,"   HAVE_UNIXWARE_ACLS\n");
#endif
#ifdef HAVE_SOLARIS_ACLS
       output(screen,"   HAVE_SOLARIS_ACLS\n");
#endif 
#ifdef HAVE_IRIX_ACLS
       output(screen,"   HAVE_IRIX_ACLS\n");
#endif
#ifdef HAVE_AIX_ACLS
       output(screen,"   HAVE_AIX_ACLS\n");
#endif
#ifdef HAVE_POSIX_ACLS
       output(screen,"   HAVE_POSIX_ACLS\n");
#endif
#ifdef HAVE_TRU64_ACLS
       output(screen,"   HAVE_TRU64_ACLS\n");
#endif

#ifdef HAVE_ACL_GET_PERM_NP
       output(screen,"   HAVE_ACL_GET_PERM_NP\n");
#endif
#ifdef HAVE_NO_ACLS
       output(screen,"   HAVE_NO_ACLS\n");
#endif
#ifdef HAVE_LIBREADLINE
       output(screen,"   HAVE_LIBREADLINE\n"); 
#endif
#ifdef WITH_LIBICONV
       output(screen,"   WITH_LIBICONV: %s\n",WITH_LIBICONV);
#endif


       /* Output various paths to files and directories */
       output(screen,"\nPaths:\n");
       output(screen,"   CONFIGFILE: %s\n", dyn_CONFIGFILE);
#ifdef PRIVATE_DIR
       output(screen,"   PRIVATE_DIR: %s\n",PRIVATE_DIR);
#endif
#ifdef LMHOSTSFILE
       output(screen,"   LMHOSTSFILE: %s\n",LMHOSTSFILE);
#endif
       output(screen,"   SBINDIR: %s\n", dyn_SBINDIR);
       output(screen,"   BINDIR: %s\n", dyn_BINDIR);
       output(screen,"   LOCKDIR: %s\n",dyn_LOCKDIR);
       output(screen,"   DRIVERFILE: %s\n", dyn_DRIVERFILE);
       output(screen,"   LOGFILEBASE: %s\n", dyn_LOGFILEBASE);

       /*Output various other options (most map to defines in the configure script*/
       output(screen,"\nOther Build Options:\n");
#ifdef HAVE_VOLATILE
       output(screen,"   HAVE_VOLATILE\n");
#endif
#ifdef HAVE_SHADOW_H
       output(screen,"   HAVE_SHADOW_H\n");
#endif
#ifdef HAVE_CRYPT
       output(screen,"   HAVE_CRYPT\n");
#endif
#ifdef USE_BOTH_CRYPT_CALLS
       output(screen,"   USE_BOTH_CRYPT_CALLS\n");
#endif
#ifdef HAVE_TRUNCATED_SALT
       output(screen,"   HAVE_TRUNCATED_SALT\n");
#endif
#ifdef HAVE_CUPS
       output(screen,"   HAVE_CUPS\n");
#endif
#ifdef HAVE_CUPS_CUPS_H
       output(screen,"   HAVE_CUPS_CUPS_H\n");
#endif
#ifdef HAVE_CUPS_LANGUAGE_H
       output(screen,"   HAVE_CUPS_LANGUAGE_H\n");
#endif
#ifdef HAVE_LIBDL
       output(screen,"   HAVE_LIBDL\n");
#endif
#ifdef HAVE_UNIXSOCKET
       output(screen,"   HAVE_UNIXSOCKET\n");
#endif
#ifdef HAVE_SOCKLEN_T_TYPE
       output(screen,"   HAVE_SOCKLEN_T_TYPE\n");
#endif
#ifdef HAVE_SIG_ATOMIC_T_TYPE
       output(screen,"   HAVE_SIG_ATOMIC_T_TYPE\n");
#endif
#ifdef HAVE_SETRESUID
       output(screen,"   HAVE_SETRESUID\n");
#endif
#ifdef HAVE_SETRESGID
       output(screen,"   HAVE_SETRESGID\n");
#endif
#ifdef HAVE_CONNECT
       output(screen,"   HAVE_CONNECT\n");
#endif
#ifdef HAVE_YP_GET_DEFAULT_DOMAIN
       output(screen,"   HAVE_YP_GET_DEFAULT_DOMAIN\n");
#endif
#ifdef HAVE_STAT64
       output(screen,"   HAVE_STAT64\n");
#endif
#ifdef HAVE_LSTAT64
       output(screen,"   HAVE_LSTAT64\n");
#endif
#ifdef HAVE_FSTAT64
       output(screen,"   HAVE_FSTAT64\n");
#endif
#ifdef HAVE_STRCASECMP
       output(screen,"   HAVE_STRCASECMP\n");
#endif
#ifdef HAVE_MEMSET
       output(screen,"   HAVE_MEMSET\n");
#endif
#ifdef HAVE_LONGLONG
       output(screen,"   HAVE_LONGLONG\n");
#endif
#ifdef COMPILER_SUPPORTS_LL
       output(screen,"   COMPILER_SUPPORTS_LL\n");
#endif
#ifdef SIZEOF_OFF_T
       output(screen,"   SIZEOF_OFF_T: %d\n",SIZEOF_OFF_T);
#endif
#ifdef HAVE_OFF64_T
       output(screen,"   HAVE_OFF64_T\n");
#endif
#ifdef SIZEOF_INO_T
       output(screen,"   SIZEOF_INO_T: %d\n",SIZEOF_INO_T);
#endif
#ifdef HAVE_INO64_T
       output(screen,"   HAVE_INO64_T\n");
#endif
#ifdef HAVE_STRUCT_DIRENT64
       output(screen,"   HAVE_STRUCT_DIRENT64\n");
#endif
#ifdef HAVE_UNSIGNED_CHAR
       output(screen,"   HAVE_UNSIGNED_CHAR\n");
#endif
#ifdef HAVE_SOCK_SIN_LEN
       output(screen,"   HAVE_SOCK_SIN_LEN\n");
#endif
#ifdef SEEKDIR_RETURNS_VOID
       output(screen,"   SEEKDIR_RETURNS_VOID\n");
#endif
#ifdef HAVE_FILE_MACRO
       output(screen,"   HAVE_FILE_MACRO\n");
#endif
#ifdef HAVE_FUNCTION_MACRO
       output(screen,"   HAVE_FUNCTION_MACRO\n");
#endif
#ifdef HAVE_GETTIMEOFDAY
       output(screen,"   HAVE_GETTIMEOFDAY\n");
#endif
#ifdef HAVE_C99_VSNPRINTF
       output(screen,"   HAVE_C99_VSNPRINTF\n");
#endif
#ifdef HAVE_BROKEN_READDIR
       output(screen,"   HAVE_BROKEN_READDIR\n");
#endif
#ifdef HAVE_NATIVE_ICONV
       output(screen,"   HAVE_NATIVE_ICONV\n");
#endif
#ifdef HAVE_KERNEL_OPLOCKS_LINUX
       output(screen,"   HAVE_KERNEL_OPLOCKS_LINUX\n");
#endif
#ifdef HAVE_KERNEL_CHANGE_NOTIFY
       output(screen,"   HAVE_KERNEL_CHANGE_NOTIFY\n");
#endif
#ifdef HAVE_KERNEL_SHARE_MODES
       output(screen,"   HAVE_KERNEL_SHARE_MODES\n");
#endif
#ifdef HAVE_KERNEL_OPLOCKS_IRIX
       output(screen,"   HAVE_KERNEL_OPLOCKS_IRIX\n");
#endif
#ifdef HAVE_IRIX_SPECIFIC_CAPABILITIES
       output(screen,"   HAVE_IRIX_SPECIFIC_CAPABILITIES\n");
#endif
#ifdef HAVE_INT16_FROM_RPC_RPC_H
       output(screen,"   HAVE_INT16_FROM_RPC_RPC_H\n");
#endif
#ifdef HAVE_UINT16_FROM_RPC_RPC_H
       output(screen,"   HAVE_UINT16_FROM_RPC_RPC_H\n");
#endif
#ifdef HAVE_INT32_FROM_RPC_RPC_H
       output(screen,"   HAVE_INT16_FROM_RPC_RPC_H\n");
#endif
#ifdef HAVE_UINT32_FROM_RPC_RPC_H
       output(screen,"   HAVE_UINT32_FROM_RPC_RPC_H\n");
#endif
#ifdef HAVE_RPC_AUTH_ERROR_CONFLICT
       output(screen,"   HAVE_RPC_AUTH_ERROR_CONFLICT\n");
#endif
#ifdef HAVE_FTRUNCATE_EXTEND
       output(screen,"   HAVE_FTRUNCATE_EXTEND\n");
#endif
#ifdef HAVE_WORKING_AF_LOCAL
       output(screen,"   HAVE_WORKING_AF_LOCAL\n");
#endif
#ifdef HAVE_BROKEN_GETGROUPS
       output(screen,"   HAVE_BROKEN_GETGROUPS\n");
#endif
#ifdef REPLACE_GETPASS
       output(screen,"   REPLACE_GETPASS\n");
#endif
#ifdef REPLACE_INET_NTOA
       output(screen,"   REPLACE_INET_NTOA\n");
#endif
#ifdef HAVE_SECURE_MKSTEMP
       output(screen,"   HAVE_SECURE_MKSTEMP\n");
#endif
#ifdef SYSCONF_SC_NGROUPS_MAX
       output(screen,"   SYSCONF_SC_NGROUPS_MAX\n");
#endif
#ifdef HAVE_IFACE_AIX
       output(screen,"   HAVE_IFACE_AIX\n");
#endif
#ifdef HAVE_IFACE_IFCONF
       output(screen,"   HAVE_IFACE_IFCONF\n");
#endif
#ifdef HAVE_IFACE_IFREQ
       output(screen,"   HAVE_IFACE_IFREQ\n");
#endif
#ifdef USE_SETRESUID
       output(screen,"   USE_SETRESUID\n");
#endif
#ifdef USE_SETRESGID
       output(screen,"   USE_SETREUID\n");
#endif
#ifdef USE_SETEUID
       output(screen,"   USE_SETEUID\n");
#endif
#ifdef USE_SETUIDX
       output(screen,"   USE_SETUIDX\n");
#endif
#ifdef HAVE_MMAP
       output(screen,"   HAVE_MMAP\n");
#endif
#ifdef MMAP_BLACKLIST
       output(screen,"   MMAP_BLACKLIST\n");
#endif
#ifdef FTRUNCATE_NEEDS_ROOT
       output(screen,"   FTRUNCATE_NEEDS_ROOT\n");
#endif
#ifdef HAVE_FCNTL_LOCK
       output(screen,"   HAVE_FCNTL_LOCK\n");
#endif
#ifdef HAVE_BROKEN_FCNTL64_LOCKS
       output(screen,"   HAVE_BROKEN_FCNTL64_LOCKS\n");
#endif
#ifdef HAVE_STRUCT_FLOCK64
       output(screen,"   HAVE_STRUCT_FLOCK64\n");
#endif
#ifdef BROKEN_NISPLUS_INCLUDE_FILES
       output(screen,"   BROKEN_NISPLUS_INCLUDE_FILES\n");
#endif
#ifdef HAVE_LIBPAM
       output(screen,"   HAVE_LIBPAM\n");
#endif
#ifdef STAT_STATVFS64
       output(screen,"   STAT_STATVFS64\n");
#endif
#ifdef STAT_STATVFS
       output(screen,"   STAT_STATVFS\n");
#endif
#ifdef STAT_STATFS3_OSF1
       output(screen,"   STAT_STATFS3_OSF1\n");
#endif
#ifdef STAT_STATFS2_BSIZE
       output(screen,"   STAT_STATFS2_BSIZE\n");
#endif
#ifdef STAT_STATFS4
       output(screen,"   STAT_STATFS4\n");
#endif
#ifdef STAT_STATFS2_FSIZE
       output(screen,"   STAT_STATFS2_FSIZE\n");
#endif
#ifdef STAT_STATFS2_FS_DATA
       output(screen,"   STAT_STATFS2_FS_DATA\n");
#endif
#ifdef HAVE_EXPLICIT_LARGEFILE_SUPPORT
       output(screen,"   HAVE_EXPLICIT_LARGEFILE_SUPPORT\n");
#endif

#ifdef WITH_UTMP
       /* Output UTMP Stuff */
       output(screen,"\nUTMP Related:\n");
       output(screen,"   WITH_UTMP\n");

#ifdef HAVE_UTIMBUF
       output(screen,"   HAVE_UTIMBUF\n");
#endif
#ifdef HAVE_UT_UT_NAME
       output(screen,"   HAVE_UT_UT_NAME\n");
#endif
#ifdef HAVE_UT_UT_USER
       output(screen,"   HAVE_UT_UT_USER\n");
#endif
#ifdef HAVE_UT_UT_ID
       output(screen,"   HAVE_UT_UT_ID\n");
#endif
#ifdef HAVE_UT_UT_HOST
       output(screen,"   HAVE_UT_UT_HOST\n");
#endif
#ifdef HAVE_UT_UT_TIME
       output(screen,"   HAVE_UT_UT_TIME\n");
#endif
#ifdef HAVE_UT_UT_TV
       output(screen,"   HAVE_UT_UT_TV\n");
#endif
#ifdef HAVE_UT_UT_TYPE
       output(screen,"   HAVE_UT_UT_TYPE\n");
#endif
#ifdef HAVE_UT_UT_PID
       output(screen,"   HAVE_UT_UT_PID\n");
#endif
#ifdef HAVE_UT_UT_EXIT
       output(screen,"   HAVE_UT_UT_EXIT\n");
#endif
#ifdef HAVE_UT_UT_ADDR
       output(screen,"   HAVE_UT_UT_ADDR\n");
#endif
#ifdef PUTUTLINE_RETURNS_UTMP
       output(screen,"   PUTUTLINE_RETURNS_UTMP\n");
#endif
#ifdef HAVE_UX_UT_SYSLEN
       output(screen,"   HAVE_UX_UT_SYSLEN\n");
#endif
#endif /* WITH_UTMP */

       /* Output Build OS */
       output(screen,"\nBuilt for host os:\n");
#ifdef LINUX
       output(screen,"   LINUX\n");
#endif
#ifdef SUNOS5
       output(screen,"   SUNOS5\n");
#endif
#ifdef SUNOS4
       output(screen,"   SUNOS4\n");
#endif
       /* BSD Isn't Defined in the configure script, but there is something about it in include/config.h.in (and I guess acconfig.h) */
#ifdef BSD
       output(screen,"   BSD\n");
#endif
#ifdef IRIX
       output(screen,"   IRIX\n");
#endif
#ifdef IRIX6
       output(screen,"   IRIX6\n");
#endif
#ifdef AIX
       output(screen,"   AIX\n");
#endif
#ifdef HPUX
       output(screen,"   HPUX\n");
#endif
#ifdef QNX
       output(screen,"   QNX\n");
#endif
#ifdef OSF1
       output(screen,"   OSF1\n");
#endif
#ifdef SCO
       output(screen,"   SCO\n");
#endif
#ifdef UNIXWARE
       output(screen,"   UNIXWARE\n");
#endif
#ifdef NEXT2
       output(screen,"   NEXT2\n");
#endif
#ifdef RELIANTUNIX
       output(screen,"   RELIANTUNIX\n");
#endif

       /* Output the sizes of the various types */
       output(screen,"\nType sizes:\n");
       output(screen,"   sizeof(char):    %d\n",sizeof(char));
       output(screen,"   sizeof(int):     %d\n",sizeof(int));
       output(screen,"   sizeof(long):    %d\n",sizeof(long));
       output(screen,"   sizeof(uint8):   %d\n",sizeof(uint8));
       output(screen,"   sizeof(uint16):  %d\n",sizeof(uint16));
       output(screen,"   sizeof(uint32):  %d\n",sizeof(uint32));
       output(screen,"   sizeof(short):   %d\n",sizeof(short));
       output(screen,"   sizeof(void*):   %d\n",sizeof(void*));
}



