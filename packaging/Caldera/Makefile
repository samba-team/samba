###########################################################################
# Makefile for Samba SMB client/server for unix
# Copyright Andrew Tridgell 1992-1998
# Copyright John H Terpstra 1995-1998
###########################################################################

# The base directory for all samba files
BASEDIR = /usr

# The base manpages directory to put the man pages in
# Note: $(MANDIR)/man1, $(MANDIR)/man5 and $(MANDIR)/man8 must exist.
MANDIR = /usr/man

# The directories to put things in. If you use multiple
# architectures or share the samba binaries across NFS then
# you will probably want to change this layout.
# Note: The SBINDIR is for files you do not want users to access
#       normally only applies to nmbd and smbd
#       SBINDIR implies a secure binary directory
BINDIR = $(BASEDIR)/bin
SBINDIR = $(BASEDIR)/sbin
LIBDIR = /etc
VARDIR = /var/log/samba

# The permissions to give the executables
INSTALLPERMS = 0755

# Add any optimisation or debugging flags here
# add -DSYSLOG for syslog support
FLAGS1 = -O
LIBS1 = 

# You will need to use a ANSI C compiler. This means under SunOS 4 you can't 
# use cc, instead you will have to use gcc. 
CC = gcc

# This may help with some versions of make
SHELL = /bin/sh

# The following can be useful for compiling on multiple architectures
# just uncommment them putting the right directory in.
# srcdir=./
# VPATH=$(srcdir)

# set these to where to find various files
# These can be overridden by command line switches (see smbd(8))
# or in smb.conf (see smb.conf(5))
SMBLOGFILE = $(VARDIR)/log.smb
NMBLOGFILE = $(VARDIR)/log.nmb
CONFIGFILE = $(LIBDIR)/smb.conf
LMHOSTSFILE = $(LIBDIR)/lmhosts
DRIVERFILE = $(LIBDIR)/printers.def
SMB_PASSWD = $(BINDIR)/smbpasswd
SMB_PASSWD_FILE = $(LIBDIR)/smbpasswd
WEB_ROOT = $(BASEDIR)

# the directory where lock files go
LOCKDIR = /var/lock/samba

# The directory where code page definition files go
CODEPAGEDIR = $(LIBDIR)/codepages
# The current codepage definition list.
CODEPAGELIST= 437 850 852 932 866 949 950 936

# set this to the default group you want your machine to appear in
# for browsing. This can also be set in nmbd (see nmbd(8))
WORKGROUP = WORKGROUP

# set this to the name of the default account, which is the one
# to use when no username or password is specified.  This can be overridden
# in the runtime configuration file (see smb.conf(5))
# NOTE: The account "nobody" may not be a good one as
# on many unixes it may not be able to print. Thus you
# might have to create a separate guest account that can print.
GUESTACCOUNT = nobody

# where you are going to have the smbrun binary. This defaults to the 
# install directory. This binary is needed for correct printing
# and magic script execution. This should be an absolute path!
# Also not that this should include the name "smbrun" on the end (the
# name of the executable)
SMBRUN = $(BINDIR)/smbrun

#
# The following (PAM, AFS, DCE/DFS, Kerberos5, SMB) are the
# alternate choices for Samba authentication. If you are using
# the UNIX password database to authenticate users you do not
# need to uncomment any of them. If you wish to use one of these
# alternate methods then only uncomment one of them.

# This is for PAM authentication. RedHat Linux uses PAM.
# If you use PAM, then uncomment the following lines:
PAM_FLAGS = -DUSE_PAM
PAM_LIBS = -ldl -lpam

# This is for AFS authentication.  If you use AFS then set AFS_BASE 
# according to your system layout, and uncomment the other lines as well.
# AFS_BASE = /usr/afsws
# AFS_FLAGS = -DAFS_AUTH -I$(AFS_BASE)/include
# AFS_LIBDIR = $(AFS_BASE)/lib
# NOTE: You may need to add -laudit in the line below
# AFS_LIBS = -L$(AFS_LIBDIR) -L$(AFS_LIBDIR)/afs -lkauth -lprot -lubik \
#                -lauth -lrxkad -lsys -ldes -lrx -llwp -lcom_err \
#                $(AFS_LIBDIR)/afs/util.a

# This is for DCE/DFS enablement. Uncomment this so that smbd can
# operate as an authenticated user identity to operate on files that
# live in the DCE Distributed Filesystem.
# DCE_BASE = /opt/dcelocal
# DCE_FLAGS = -DDFS_AUTH -I$(DCE_BASE)/include
# DCE_LIBDIR = -L$(DCE_BASE)/lib
# DCE_LIBS =

# This is for Kerberos 5 authentication. Contributed by Nathan Neulinger
# Univ. of Missouri - Rolla <nneul@umr.edu>
# KRB5_BASE = /usr/local/krb5
# KRB5_FLAGS = -DKRB5_AUTH -I$(KRB5_BASE)/include
# KRB5_LIBS = -L$(KRB5_BASE)/lib -ldes425 -lkrb5 -lcrypto -lcom_err

# This is for Kerberos 4 authentication. Contributed by Johan Hedin
# Royal Institute of Technology, <johanh@fusion.kth.se>
# KRB4_BASE = /usr/athena
# KRB4_FLAGS = -DKRB4_AUTH -I$(KRB4_BASE)/include
# KRB4_LIBS = -L$(KRB4_BASE)/lib -lkrb -ldes -lresolv

######################################
# VTP-Support
#
# uncomment the following two lines to enable VTP-Support
#VTP_FLAGS = -DWITH_VTP
#VTP_OBJ = vt_mode.o
######################################

######################################
# WHICH AWK? awk is used for automatic prototype generation. GNU awk works
# where inferior awks don't. Sun is one manufacturer who supplies both
# a broken awk called 'awk' and a fixed one called 'nawk'. mkproto.awk will
# only work with the latter, and even that isn't as good as free GNU awk.
#
# Leave this uncommented; the OS-specific stuff will override it if required
AWK = awk
######################################

#####################################
# WHICH OPERATING SYSTEM?
# UNCOMMENT ONE OF THE SECTIONS BELOW
# MAKE SURE ONLY *ONE* IS UNCOMMENTED
#
# The following are additional flags that may apply
#   -DNETGROUP if your machine supports yp netgroups
#   -DAUTOMOUNT to ask for yp auto.home for users' home directories
#   -DNISPLUS add this to ask nis+ instead of yp for users' home directories
#   -DSHADOW_PWD if you are using shadow passwords
#   -DGETPWANAM if you wish to use getpwanam() call
#   -DPWDAUTH if you have and want to use the pwdauth() call
#   -DUFC_CRYPT if you want the fast crypt routine
#   -DALLOW_CHANGE_PASSWORD if you want users to be able to set their password
#                           remotely (only works on some systems)
#   -DQUOTAS for quota support in disk_free(). This probably only works 
#            on some systems.
#   -DFAST_SHARE_MODES if you want the fast shared memory instead of the
#                      slow description files for share mode locking. This
#                      requires the mmap() and fcntl() system calls.
#
#    NOTE: GETPWANAM & PWDAUTH are mutually exclusive, if you
#          Define one, you should NOT define the other.
#####################################

#####################################
# for the JAPANESE EXTENSION
# select filename's code set for KANJI/KANA in UNIX,
# apply the following flag
#   -DKANJI=\"<code>\"
#        <code> is select character code set for JAPAN.
#             sjis:   if your machine support SJIS
#             euc:      if your machine support EUC
#             jis7:     if your machine support JIS7
#             jis8:     if your machine support JIS8
#             junet:    if your machine support jis7 + junet rule
#             hex:      if your machine only support 7 bits ascii filename only
#                       convert to hexdecimal code preseeding ':'.
# see also README.jis
######################################


# This is for SUNOS 4. Use the SUNOS5 entry for Solaris 2.
# Note that you cannot use Suns "cc" compiler
# as it's not an Ansi-C compiler. Get gcc or acc. 
# Note that if you have adjunct passwords you may need the GETPWANAM 
# or PWDAUTH option. There have been reports that using PWDAUTH may crash
# your pwdauthd server so GETPWANAM is preferable (and probably faster)
# contributed by Andrew.Tridgell@anu.edu.au
# FLAGSM = -DSUNOS4 -DFAST_SHARE_MODES
# LIBSM =   
# AWK = nawk 

# If you are using Linux kernel version 2.1.70 and later, you should
# uncomment the following line to compile the smbmount utilities
# together with Samba. If you are using Linux kernel version 2.0.x
# you must use the smbfs utilities from
# ftp://ftp.gwdg.de/pub/linux/misc/smbfs

# MOUNT_PROGS = smbmount smbmnt smbumount

# Use this for Linux with shadow passwords - but not using PAM!
# contributed by Andrew.Tridgell@anu.edu.au
# add -DLINUX_BIGCRYPT is you have shadow passwords but don't have the
# right libraries and includes
# FLAGSM = -DLINUX -DSHADOW_PWD -DFAST_SHARE_MODES
# LIBSM = -lshadow

# Use this for Linux without shadow passwords or for any Linux
# system that uses PAM (eg: RedHat) in which case it handles ALL
# authentication methods that are supported by the version of
# PAM that is available on your system.
# contributed by Andrew.Tridgell@anu.edu.au & John.Terpstra@aquasoft.com.au
# AXPROC defines DEC Alpha Processor
# FLAGSM = -DLINUX -DAXPROC -DFAST_SHARE_MODES
FLAGSM = -DLINUX -DFAST_SHARE_MODES
LIBSM = 

# Use this for Linux with shadow passwords and quota - but not using PAM!
# contributed by xeno@mix.hive.no
# Tested on the 1.3.57 kernel and ext2fs filesystem.
# Notes:
# /usr/include/sys/quota.h must be a symlink to /usr/include/linux/quota.h
# The directory quota here must be a symlink to your quota package.
# I just do 'ln -sf /usr/src/quota-1.50 quota' in this directory to get it to work.
# FLAGSM = -O3 -m486 -DLINUX -DSHADOW_PWD -DQUOTAS -DFAST_SHARE_MODES
# LIBSM = -lshadow

# Use this for Linux with quota and glibc2 - not using PAM!
# contributed by Thorvald Natvig <slicer@bimbo.hive.no>
# Tested on the 2.0.30 kernel and ext2fs filesystem.
# FLAGSM = -DLINUX -DQUOTAS -DNO_ASMSIGNALH -DGLIBC2 -DFAST_SHARE_MODES
# LIBSM = -L/lib/libc5-compat -lcrypt

# Use this for Linux with glibc2 (libc6)
# contributed by Eloy Paris <peloy@ven.ra.rockwell.com>
# FLAGSM = -DLINUX -DNETGROUP -DSHADOW_PWD -DALLOW_CHANGE_PASSWORD -DFAST_SHARE_MODES -DNO_ASMSIGNALH -DGLIBC2
# LIBSM = -lnsl -lcrypt

# Use this for Linux with glibc2 (libc6) - RedHat Linux v5.0 with PAM
# contributed by John H Terpstra <jht@aquasoft.com.au>
# FLAGSM = -DLINUX -DNETGROUP -DALLOW_CHANGE_PASSWORD -DFAST_SHARE_MODES -DNO_ASMSIGNALH -DGLIBC2
# LIBSM = -lnsl -lcrypt

# This is for SUNOS5.4 and later (also known as Solaris 2.4 and later)
# contributed by Andrew.Tridgell@anu.edu.au
# FLAGSM = -DSUNOS5 -DSHADOW_PWD -DNETGROUP -DFAST_SHARE_MODES
# LIBSM = -lsocket -lnsl
# AWK = nawk 

# This is for SUNOS 5.2 and 5.3 (also known as Solaris 2.2 and 2.3)
# contributed by hdsi@newtech.net
# FLAGSM = -DSUNOS5 -DSHADOW_PWD -DNETGROUP -DNO_STRFTIME -DFAST_SHARE_MODES
# LIBSM = -lsocket -lnsl
# AWK = nawk 

# This is for UXP/DS
# contributed by dsfrost@oai6.yk.fujitsu.co.jp
# FLAGSM = -DSVR4 -DSHADOW_PWD
# LIBSM = -lsocket -lnsl

# This is for SVR4
# Contributed by mark@scot1.ucsalf.ac.uk
# FLAGSM = -DSVR4 -DSHADOW_PWD -DALLOW_CHANGE_PASSWORD
# LIBSM = -lsocket -lnsl -lc -L/usr/ucblib -lucb


# This is for the Motorola 88xxx/9xx range of machines
# Contributed by RPE@monnet.com
# FLAGSM = -DSVR4 -DSHADOW_PWD -DGETTIMEOFDAY1
# LIBSM = -lsocket -lnsl -lc -L/usr/ucblib -lucb


# This is for UnixWare 1.x.
# Contributed by Warren Young <tkennedy@cyberport.com>
#FLAGSM = -Xa -DSVR4 -DSHADOW_PWD
#LIBSM = -lsocket -lnsl -lc -L/usr/ucblib -lucb

# This is for UnixWare 2.x WITH libdes support.
# Contributed by tangent@cyberport.com
#FLAGSM = -Xa -DSVR4
#LIBSM = -lsocket -lnsl -lc -L/usr/ucblib -lucb

# This is for UnixWare 2.x WITHOUT libdes support.
# Contributed by tangent@cyberport.com
#FLAGSM = -Xa -DSVR4 -DIA_UINFO
#LIBSM = -lsocket -lnsl -lc -L/usr/ucblib -lucb -lcrypt -liaf

# This is for UNIXWARE 2.x with shadow passwords.
# Contributed by fja@extratech.com
#FLAGSM = -Xa -DSVR4 -DSHADOW_PWD
#LIBSM = -lsocket -lnsl -lc -L/usr/ucblib -lucb -lcrypt -lgen

# This is for ULTRIX. Add -DULTRIX_AUTH for Ultrix enhanced security.
# contributed by iversen@dsfys1.fi.uib.no
# FLAGSM = -DULTRIX
# LIBSM =   


# This is for OSF1 (Alpha)
# contributed by errath@balu.kfunigraz.ac.at
# NOTE: You may need -warning_unresolved if you get unresolved symbols
# FLAGSM = -DOSF1 -DFAST_SHARE_MODES 
# LIBSM =

# This is for OSF1 with DCE/DFS
# contributed by Jim Doyle <doyle@oec.com>
# FLAGSM = -DOSF1 -DDFS_AUTH -DSIGCLD_IGNORE -DNO_SIGNAL_TEST
# LIBSM = -ldce -lpthreads -lmach -lc_r

# This is for OSF1 (Alpha) with NIS and Fast Crypt
# contributed by David Gardiner <dgardine@cssip.edu.au>
# FLAGSM = -DOSF1 -DNETGROUP -DUFC_CRYPT
# LIBSM =


# This is for OSF1 (Alpha) V2.0/V4.0 Enhanced Security 
# contributed by Udo Linauer <ul@eacpc4.tuwien.ac.at>
# FLAGSM = -DOSF1 -DOSF1_ENH_SEC -DFAST_SHARE_MODES
# LIBSM = -lsecurity


# This is for AIX 3.2.5 (without DCE/DFS)
# contributed by Miguel Angel Cruz <mcruz@maccsys.org>
# FLAGSM = -DAIX
# LIBSM =   

# This is for AIX 3.2.5 with DCE/DFS
# contributed by Jim Doyle <doyle@oec.com>
# FLAGSM = -DAIX -DDFS_AUTH -DSIGCLD_IGNORE -DNO_SIGNAL_TEST
# LIBSM = -lc_r -ldce -lpthreads
# CC = cc_r

# This is for AIX 4.x
# contributed by tomc@osi.curtin.edu.au
# FLAGSM = -DAIX -DFAST_SHARE_MODES
# LIBSM =   

# This is for AIX 4.x with quota support
# contributed by tomc@osi.curtin.edu.au
# FLAGSM = -DAIX -DFAST_SHARE_MODES -DQUOTAS
# LIBSM =   

# This is for BSDI 
# contributed by tomh@metrics.com
# versions of BSDI prior to 2.0 may need to add -DUSE_F_FSIZE for 
# disk usage stats to be correct
# FLAGSM = -DBSDI -DFAST_SHARE_MODES
# LIBSM =   


# This is for NetBSD. Add -DNETBSD_1_0 if you are using 1.0
# contributed by noses@oink.rhein.de
# FLAGSM = -DNETBSD -DSHADOW_PWD
# LIBSM = -lcrypt 

# This is for NetBSD 1.3  
# contributed by sean@fuzzymagic.com  
# FLAGSM = -DNETBSD -DSHADOW_PWD -DUFC_CRYPT -DALLOW_CHANGE_PASSWORD -DFAST_SHARE_MODES  
# LIBSM = -lcrypt

# This is for SEQUENT. 
# Contributed by fwk@ix.netcom.com (Frank Keeney) and 
# rpwillia@Pentagon-EMH6.army.mil (Ray Williams)
# tested on DYNIX/ptx(R) V2.1.0
# FLAGSM = -DSEQUENT -DSHADOW_PWD -DHAVE_TIMEZONE
# LIBSM = -lrpc -lsocket -lPW -linet -lnsl -lseq -lsec


# This is for SEQUENT PTX 4.1.x
# Contributed by bressler@iftccu.ca.boeing.com (Rick Bressler)
# based on Keeny and Williams contribution.
# tested on DYNIX/ptx(R) V4.1.3
# FLAGSM = -DSEQUENT -DSHADOW_PWD -DHAVE_TIMEZONE -DPTX4
# LIBSM = -lrpc -lsocket -lPW -lnsl -lseq -lsec


# This is for HP-UX 9.x. Note that some systems don't like the -Aa switch.
# contributed by Pasi.Kaara@atk.tpo.fi
# You will need -DREPLACE_GETPASS if you use smb encryption
# FLAGSM = -DHPUX -Aa -D_HPUX_SOURCE -D_POSIX_SOURCE
# LIBSM = 

# This is for HP-UX 10.x. Note that some systems don't like the -Aa switch.
# contributed by Pasi.Kaara@atk.tpo.fi
# You will need -DREPLACE_GETPASS if you use smb encryption
# FLAGSM = -DHPUX -Aa -D_HPUX_SOURCE -D_POSIX_SOURCE -DHPUX10 -DFAST_SHARE_MODES
# LIBSM = 


# This is for HP-UX with DCE/DFS
# contributed by Jim Doyle <doyle@oec.com>
# Add -DHPUX10 -DFAST_SHARE_MODES if compiling on HPUX 10.x
# FLAGSM = -DHPUX -Aa -D_HPUX_SOURCE -D_POSIX_SOURCE -DDFS_AUTH -D_REENTRANT -I/usr/include/reentrant
# LIBSM = -ldce -lM -lc_r

# HP-UX 10.x Trusted System
# Contributed by David-Michael Lincke (dlincke@sgcl1.unisg.ch)
# FLAGSM = +O3 -Ae -DHPUX -DHPUX10 -DHPUX_10_TRUSTED -DFAST_SHARE_MODES
# LIBSM = -lsec


# This is for SGI.
# FOR SGI IRIX 4.x.x, use the following line
# contributed by lpc@solomon.technet.sg (Michael Chua)
# FLAGSM = -DSGI4 -DHAVE_TIMEZONE 
# LIBSM = -lsun
# FLAGS1 = -O -g3

# FOR SGI IRIX 5.x.x, use this line instead
# Contributed by <unknown>
# FLAGSM = -DSGI5 -DSHADOW_PWD -DHAVE_TIMEZONE -DFAST_SHARE_MODES
# LIBSM =
# FLAGS1 = -O -g3

# FOR SGI IRIX 6.2 using the system compiler (*NOT* gcc), use this line instead
# Contributed by David.Billinghurst@restech.cra.com.au
# FLAGSM = -DSGI6 -DSHADOW_PWD -DHAVE_TIMEZONE -DFAST_SHARE_MODES
# LIBSM = 
# FLAGS1 = -O -n32 -g3

# This is for FreeBSD
# contributed by kuku@acds.physik.rwth-aachen.de
# NOTE: You may need to add -DBSD44 if you have password problems
# FLAGSM = -DFreeBSD -DFAST_SHARE_MODES
# LIBSM = -lcrypt 

# This is for OpenBSD
# contributed by todd@openbsd.org
# FLAGSM = -DFAST_SHARE_MODES -DBSD44
# LIBSM =

# This is for NEXTSTEP Release 2.X
# No Posix.
# contributed by brad@cac.washington.edu (Brad Greer)
# FLAGSM = -DNEXT2 
# LIBSM = 

# This is for NEXTSTEP Release 3.0 and greater (including OPENSTEP for Mach).
# contributed by brad@cac.washington.edu (Brad Greer)
# additional configuration by pmarcos@next.com (Paul Marcos)
# For compiling n-way fat executables, you should append the appropriat -arch 
# flags to the FLAGSM variable.  Valid flags are:
#    -arch m68k
#    -arch i386
#    -arch hppa
#    -arch sparc
# To compile 4-way fat, you would append
#    -arch m68k -arch i386 -arch hppa -arch sparc
# FLAGSM = -DNEXT3_0
# LIBSM = 


# NOTE: ISC is also known as "INTERACTIVE"
# This is for Sunsoft ISC SVR3V4 running in POSIX mode
# contributed by pim@cti-software.nl (Pim Zandbergen)
# FLAGSM = -posix -D_SYSV3 -DISC -DSHADOW_PWD
# LIBSM = -lsec -lcrypt -linet

# This is for Sunsoft ISC SVR3V4 running in iBCS2 mode
# contributed by pim@cti-software.nl (Pim Zandbergen)
# FLAGSM = -D_POSIX_SOURCE -D_XOPEN_SOURCE -D_SYSV3\
#          -DISC -DSHADOW_PWD -DREPLACE_GETWD -DREPLACE_RENAME
# LIBSM = -lsec -lcrypt -linet -lcposix


# This is for A/UX 3.0
# Contributed by root@dolphin.csudh.edu (Jon S. Stevens)
# FLAGSM = -DAUX
# LIBSM =

# This is for Altos Series 386/1000
# Contributed by cal@zls.com
# FLAGSM = -DALTOS -DHAS_RDCHK
# LIBSM = -lsocket -lxenix


#Note: The SCO entries require the libcrypt library. You can get it via
#anonymous ftp from ftp.sco.com:/SLS/lng225b.* or ftp.uu.net:/vendors/sco
#
# Use this for SCO with shadow passwords. Tested on "Open enterprise 3.0"
# SCO changes from Heinz Mauelshagen (mauelsha@ez.da.telekom.de)
# FLAGSM = -DSCO -DSHADOW_PWD -DNETGROUP
# LIBSM = -lyp -lrpc -lyp -lsec -lsocket -lcrypt_i -lintl

# Use this for SCO with shadow passwords, without YP.
# Tested on "Open Enterprise Server 3.0" (John Owens john@micros.com)
# Also, use "CC = cc" above.
# FLAGSM = -DSCO -DSHADOW_PWD
# LIBSM = -lsec -lsocket -lcrypt_i

# Use this for SCO with TCB passwords (default).
# Tested on "Open enterprise 3.0". Contributed by lance@fox.com.
# CC     = cc
# FLAGSM = -DSCO -DSecureWare
# LIBSM  = -lprot_s -lcrypt -lsocket -lm -lc_s

# Use this for SCO Unix 3.2v2 (ODT 1.1) with TCB passwords (default).
# Contributed by Stephen.Rothwell@pd.necisa.oz.au
# N.B. this needs gcc
# FLAGSM = -DSCO -DSecureWare -DSCO3_2_2
# LIBSM  = -lprot -lcrypt_i -lsocket -lm -lintl

# This is for the european distribution of SCO. 
# Contributed by Urmet.Janes@gwhite.goodwin.ee
# FLAGSM = -DSCO -DSHADOW_PWD 
# LIBSM = -lsec -lsocket /usr/lib/libcrypt_i.a -lintl

# Use this for SCO OpenServer 5 with TCB passwords (default).
# contributed by Scott Michel <scottm@intime.intime.com>
# you may also like to add the -dy switch (recommended by Marnus van 
# Niekerk, mvn@pixie.co.za)
# CC     = cc -Xc
# FLAGSM = -DSCO -DSecureWare -DEVEREST -DUSE_MMAP
# LIBSM  = -lprot -lcurses -lcrypt -lsocket -lPW -lm -lx -lc_s -lc


# This is for intergraph. 
# contributed by cjkiick@flinx.b11.ingr.com
# modified by ttj@sknsws61.sjo.statkart.no
# FLAGSM = -DCLIX -D_INGR_EXTENSIONS=1
# LIBSM = -lbsd -lc_s

# This is for DGUX. 
# Contributed by ross@augie.insci.com (Ross Andrus)
# FLAGSM = -DDGUX 
# LIBSM  = 

# This is for DGUX on Intel boxes.
# Contributed by tim@denmantire.com
# FLAGSM = -DDGUX 
# LIBSM  = -lsocket -lnsl -lresolv

# This is for Apollo Domain/OS sr10.3 (systype = BSD4.3)
# Added 1994-07-08 Stephen C. Steel <steve@qv3donald.LeidenUniv.nl>
# additional patches by jmi@csd.cri.dk (John Mills)
# you may need the "-A ansi" switch to cc
# FLAGSM = -DAPOLLO -D_INCLUDE_BSD_SOURCE -D_INCLUDE_XOPEN_SOURCE
# LIBSM =


# RiscIX. 
# contributed by Jim Barry <jim@ilp.com> and 
# Charles Gay-Jones <charlie@ilp.com>
# FLAGSM = -DRiscIX -DNOSTRDUP
# LIBSM =


# This is for System V with some berkely extensions (Motorola 88k R32V3.2).
# contributed by tonyb@plaza.ds.adp.com (Tony D. Birnseth)
# FLAGSM = -DM88K_R3
# LIBSM = -lgen -lbsd -lnsl


# This is for DNIX.
# contributed by Peter Olsson <pol@leissner.se>
# NOTE: You may need an updated libc.a from your vendor as older
# versions have broken mktime calls and no initgroups() call
# NOTE2: You may need -lpasswd if you use shadow passwords
# NOTE3: Please read the file DNIX.txt in the docs directory. It
# contains important information about uid handling under DNIX, you may
# need to patch your C library.
# FLAGSM = -DDNIX -I/usr/include/bsd
# LIBSM = -ln


# This is for Cray, Unicos 8.0
# contributed by velo@sesun3.epfl.ch (Martin Ouwehand)
# FLAGSM = -DCRAY -U__STDC__ -DQUOTAS
# LIBSM =

# This is for Convex
# contributed by Victor Balashov <balashov@cv.jinr.dubna.su>
# and Ulrich Hahn <ulrich.hahn@zdv.uni-tuebingen.de>
# FLAGSM= -DCONVEX -DSHADOW_PWD
# LIBSM= 

# This is for SMP_DC.OSx v1.1-94c079 on Pyramid S series
# contributed by jeffrey@itm.org
# FLAGSM = -DSOLARIS -DSHADOW_PWD -DBSD_COMP
# LIBSM = -lsocket -lnsl

# This is for QNX 4.22
# Contributed by eldo@invisa.satlink.net (Eldo Loguzzo)
# FLAGSM = -DQNX -DGUEST_SESSSETUP=1
# LIBSM =


# This is for SONY NEWS, NEWS-OS 4.2.x
# contributed by sky@sm.sony.co.jp (Katushi Sato)
# FLAGSM = -DNEWS42 -DKANJI=\"sjis\"
# LIBSM =


# This is for SONY NEWS, NEWS-OS 6.1.x
# contributed by kobo@sm.sony.co.jp (Yoichi Kobori)
# FLAGSM = -Xa -DSVR4 -DNEWS61 -DSHADOW_PWD -DNETGROUP -DGETTIMEOFDAY1 -DKANJI=\"euc\"\ -D_SONYILS_H
# LIBSM = -lsocket -lnsl


# This is for OS/2 using EMX 
# Contributed by jasonr@pec.co.nz (Jason Rumney)
# Now maintained by Jacco de Leeuw <leeuw@wins.uva.nl>
# FLAGSM = -DOS2
# LIBSM = -Zexe -lsocket


# This is for LYNX 2.3.0 (gcc v2.6)
# Contributed by woelfel@hpe.fzk.de (Manfred Woelfel)
# FLAGSM = -DLYNX -DUFC_CRYPT -mposix
# LIBSM = -lbsd


# This is for MachTen (a unix like system for Macintoshes)
# contributed by Trevor Strohman (trev@figment.tenon.com)
# FLAGSM = -DMACHTEN
# LIBSM =


# RISCOs 5.0B
# contributed by John Agnew <johna@bfs.Unibol.COM>
# FLAGSM = -systype svr4 -std -DSVR4
# LIBSM = -lsocket -lnsl -lc -L/usr/ucblib -lucb


# This is for B.O.S. (Bull Operating System)
# Contributed by koine@fileita.it
# FLAGSM = -DBOS -DNO_RESOURCEH -DUSE_WAITPID
# LIBSM = -linet


# This for Amiga using GCC and ixemul.library 43.0 or later.
# contributed by Rask Ingemann Lambertsen <rask@k4315.kampsax.dtu.dk>
# The binaries will support both AmiTCP and AS225R2 compatible
# protocol stacks because of the use of ixnet.library.
# Other protocol stacks will be supported automatically if
# support for them is added to ixnet.library.
# The binaries will have automatic stack extension :-)
# smbd must be run from inetd :-(
# FLAGSM = -DAMIGA -Dfork=vfork -mstackextend
# LIBSM =



######################################################################
# DON'T EDIT BELOW THIS LINE
######################################################################

PASSWD_FLAGS = -DSMB_PASSWD=\"$(SMB_PASSWD)\" -DSMB_PASSWD_FILE=\"$(SMB_PASSWD_FILE)\"
CFLAGS1 = $(FLAGS1) -DSMBLOGFILE=\"$(SMBLOGFILE)\" -DNMBLOGFILE=\"$(NMBLOGFILE)\"
CFLAGS2 = -DCONFIGFILE=\"$(CONFIGFILE)\" -DLMHOSTSFILE=\"$(LMHOSTSFILE)\" -DWEB_ROOT=\"$(WEB_ROOT)\"
CFLAGS3 = -DLOCKDIR=\"$(LOCKDIR)\" -DSMBRUN=\"$(SMBRUN)\" -DCODEPAGEDIR=\"$(CODEPAGEDIR)\"
CFLAGS4 = -DWORKGROUP=\"$(WORKGROUP)\" -DGUEST_ACCOUNT=\"$(GUESTACCOUNT)\" -DDRIVERFILE=\"$(DRIVERFILE)\"
CFLAGS5 = $(CFLAGS1) $(CFLAGS2) $(CFLAGS3) $(CFLAGS4) $(FLAGSM) $(AFS_FLAGS) $(KRB5_FLAGS) $(KRB4_FLAGS) $(RPM_OPT_FLAGS)
CFLAGS  = $(CFLAGS5) $(PAM_FLAGS) $(DCE_FLAGS) $(DES_FLAGS) $(PASSWD_FLAGS) $(VTP_FLAGS)
LIBS = $(LIBS1) $(LIBSM) $(PAM_LIBS) $(DCE_LIBS) $(KRB5_LIBS) $(KRB4_LIBS) $(DES_LIB)

INCLUDES1 = $(srcdir)version.h $(srcdir)local.h $(srcdir)includes.h $(srcdir)smb.h 
INCLUDES2 = $(srcdir)trans2.h 
INCLUDES = $(INCLUDES1) $(INCLUDES2)

SPROGS = smbd nmbd
PROGS1 = smbclient testparm testprns smbrun smbstatus smbpasswd make_smbcodepage
PROGS = $(PROGS1) nmblookup make_printerdef $(MOUNT_PROGS)

SCRIPTS = smbtar addtosmbpass


######################################################################
# object modules
######################################################################

# modules in the ubiqx library from Chris Hertel
UBIOBJ = ubiqx/ubi_dLinkList.o

# client specific object code in the rpc_pipes directory
RPC_CLI_OBJ = rpc_pipes/ntclientpipe.o rpc_pipes/ntclientlsa.o rpc_pipes/ntclientnet.o 

# server specific object code in the rpc_pipes directory
RPC_SERV_OBJ = rpc_pipes/pipenetlog.o rpc_pipes/pipentlsa.o rpc_pipes/pipesrvsvc.o rpc_pipes/pipewkssvc.o rpc_pipes/pipesamr.o

# server object files in the rpc_pipes subdirectory
RPC_OBJ1 = rpc_pipes/srvparse.o rpc_pipes/smbparse.o rpc_pipes/lsaparse.o rpc_pipes/pipeutil.o 
RPC_OBJ2 = rpc_pipes/pipe_hnd.o rpc_pipes/samrparse.o rpc_pipes/wksparse.o rpc_pipes/lsa_hnd.o
RPC_OBJ = $(RPC_OBJ1) $(RPC_OBJ2) 

# general utility object files
UTILOBJ1 = util.o system.o charset.o kanji.o fault.o smbencrypt.o smbdes.o charcnv.o
UTILOBJ2 = $(UTILOBJ1) md4.o loadparm.o params.o pcap.o username.o time.o namequery.o nmblib.o
UTILOBJ = $(UTILOBJ2) interface.o replace.o print_svid.o smberr.o mem_man/mem_man.o slprintf.o

# object code for smbd
SMBDOBJ1 = $(UTILOBJ) trans2.o message.o dir.o printing.o 
SMBDOBJ2 = ipc.o reply.o mangle.o chgpasswd.o password.o quotas.o uid.o
SMBDOBJ3 = predict.o credentials.o clientgen.o pipes.o server.o access.o 
SMBDOBJ4 = ufc.o smbpass.o
SMBDOBJ = $(SMBDOBJ1) $(SMBDOBJ2) $(SMBDOBJ3) $(SMBDOBJ4) $(UBIOBJ) $(RPC_OBJ) $(RPC_SERV_OBJ) $(VTP_OBJ) $(LOCKOBJ)

# object code needed for programs that handle the the locking files
LOCKOBJ = locking_shm.o locking_slow.o locking.o shmem.o shmem_sysv.o

# object code for nmbd
NMBDOBJ1 = nmbd.o nmbd_packets.o nmbd_lmhosts.o nmbd_become_dmb.o nmbd_logonnames.o
NMBDOBJ2 = nmbd_browserdb.o nmbd_responserecordsdb.o nmbd_workgroupdb.o nmbd_serverlistdb.o
NMBDOBJ3 = nmbd_subnetdb.o nmbd_browsesync.o nmbd_nodestatus.o nmbd_mynames.o nmbd_winsproxy.o
NMBDOBJ4 = nmbd_sendannounce.o nmbd_processlogon.o nmbd_incomingdgrams.o clientgen.o
NMBDOBJ5 = asyncdns.o smbpass.o nmbd_winsserver.o nmbd_incomingrequests.o nmbd_nameregister.o
NMBDOBJ6 = nmbd_namerelease.o nmbd_namequery.o nmbd_become_lmb.o nmbd_elections.o nmbd_namelistdb.o

NMBDOBJ = $(UTILOBJ) $(NMBDOBJ1) $(NMBDOBJ2) $(NMBDOBJ3) $(NMBDOBJ4) $(NMBDOBJ5) $(NMBDOBJ6)

# object files for smbclient
CLIENT_OBJ = client.o ntclient.o credentials.o clientutil.o clitar.o getsmbpass.o $(UTILOBJ) $(RPC_CLI_OBJ) $(RPC_OBJ)

# object files for smbmount
MOUNT_OBJ = smbmount.o ntclient.o credentials.o clientutil.o getsmbpass.o $(UTILOBJ) $(RPC_CLI_OBJ) $(RPC_OBJ)

# object files for smbmnt
MNT_OBJ = smbmnt.o

# object files for smbumount
UMOUNT_OBJ = smbumount.o

# object files for smbstatus
STATUS_OBJ = status.o $(UTILOBJ) $(LOCKOBJ) 

# object files for nmblookup
LOOKUP_OBJ = nmblookup.o $(UTILOBJ) 


# object files to be auto-prototyped
PROTOOBJ = $(UTILOBJ) $(SMBDOBJ) $(NMBDOBJ) $(LOCKOBJ) $(CLIENT_OBJ) $(STATUS_OBJ) cgi.o namequery.o


######################################################################
# now the rules...
######################################################################

all : CHECK $(SPROGS) $(PROGS) 

CHECK :
	@$(SHELL) $(srcdir)checkos.sh $(FLAGSM)
	@echo "Using CFLAGS = $(CFLAGS)"
	@echo "Using LIBS = $(LIBS)"

.SUFFIXES:
.SUFFIXES: .c .o .h

.c.o: $(INCLUDES)
	@echo Compiling $*.c
	@$(CC) $(CFLAGS) -c $(srcdir)$*.c -o $(srcdir)$*.o

smbd: $(SMBDOBJ) $(ARCFOUR_OBJ)
	@echo Linking smbd
	@$(CC) $(CFLAGS) -o smbd $(SMBDOBJ) $(ARCFOUR_OBJ) $(LIBS) $(AFS_LIBS)

smbrun: smbrun.o 
	@echo Linking smbrun
	@$(CC) $(CFLAGS) -o smbrun smbrun.o $(LIBS)

nmblookup: $(LOOKUP_OBJ)
	@echo Linking nmblookup
	@$(CC) $(CFLAGS) -o nmblookup $(LOOKUP_OBJ) $(LIBS)

nmbd: $(NMBDOBJ)
	@echo Linking nmbd
	@$(CC) $(CFLAGS) -o nmbd $(NMBDOBJ) $(LIBS)

smbclient: $(CLIENT_OBJ) $(ARCFOUR_OBJ)
	@echo Linking smbclient
	@$(CC) $(CFLAGS) -o smbclient $(CLIENT_OBJ) $(ARCFOUR_OBJ) $(LIBS)

smbmount: $(MOUNT_OBJ) $(ARCFOUR_OBJ)
	@echo Linking smbmount
	@$(CC) $(CFLAGS) -o smbmount $(MOUNT_OBJ) $(ARCFOUR_OBJ) $(LIBS)

smbmnt: $(MNT_OBJ)
	@echo Linking smbmnt
	@$(CC) $(CFLAGS) -o smbmnt $(MNT_OBJ)

smbumount: $(UMOUNT_OBJ)
	@echo Linking smbumount
	@$(CC) $(CFLAGS) -o smbumount $(UMOUNT_OBJ)

smbtorture: torture.o clientgen.o getsmbpass.o $(UTILOBJ)
	@echo Linking smbtorture
	@$(CC) $(CFLAGS) -o smbtorture torture.o clientgen.o getsmbpass.o $(UTILOBJ) $(LIBS)

smbstatus: $(STATUS_OBJ)
	@echo Linking smbstatus
	@$(CC) $(CFLAGS) -o smbstatus $(STATUS_OBJ) $(LIBS)

testparm: testparm.o access.o $(UTILOBJ)
	@echo Linking testparm
	@$(CC) $(CFLAGS) -o testparm testparm.o access.o $(UTILOBJ) $(LIBS)

testprns: testprns.o $(UTILOBJ)
	@echo Linking testprns
	@$(CC) $(CFLAGS) -o testprns testprns.o $(UTILOBJ) $(LIBS)

smbpasswd: smbpasswd.o getsmbpass.o smbpass.o clientgen.o $(UTILOBJ)
	@echo Linking smbpasswd
	@$(CC) $(CFLAGS) -o smbpasswd smbpasswd.o getsmbpass.o smbpass.o clientgen.o $(UTILOBJ) $(LIBS)

make_smbcodepage: make_smbcodepage.o $(UTILOBJ) 
	@echo Linking make_smbcodepage
	@$(CC) $(CFLAGS) -o make_smbcodepage make_smbcodepage.o $(UTILOBJ) $(LIBS)

make_printerdef: make_printerdef.o $(UTILOBJ) 
	@echo Linking make_printerdef
	@$(CC) $(CFLAGS) -o make_printerdef make_printerdef.o $(UTILOBJ) $(LIBS)

wsmbstatus: wsmbstatus.o $(UTILOBJ)  
	@echo Linking wsmbstatus
	@$(CC) $(CFLAGS) -o wsmbstatus wsmbstatus.o $(UTILOBJ) $(LIBS)

wsmbconf: wsmbconf.o $(UTILOBJ) cgi.o
	@echo Linking wsmbconf
	@$(CC) $(CFLAGS) -o wsmbconf wsmbconf.o $(UTILOBJ) cgi.o $(LIBS)

install: installbin installman installscripts installcp

installbin: all
	@$(SHELL) $(srcdir)installbin.sh $(INSTALLPERMS) $(BASEDIR) $(SBINDIR) $(LIBDIR) $(VARDIR) $(SPROGS)
	@$(SHELL) $(srcdir)installbin.sh $(INSTALLPERMS) $(BASEDIR) $(BINDIR) $(LIBDIR) $(VARDIR) $(PROGS)

installscripts:
	@$(SHELL) $(srcdir)installscripts.sh $(INSTALLPERMS) $(BINDIR) $(SCRIPTS)

installcp:
	@$(SHELL) $(srcdir)installcp.sh $(LIBDIR) $(CODEPAGEDIR) $(BINDIR) $(CODEPAGELIST)

# revert to the previously installed version
revert:
	@$(SHELL) $(srcdir)revert.sh $(SBINDIR) $(SPROGS) $(SCRIPTS)
	@$(SHELL) $(srcdir)revert.sh $(BINDIR) $(PROGS) $(SCRIPTS)

installman:
	@$(SHELL) $(srcdir)installman.sh $(MANDIR) $(srcdir)

uninstall: uninstallman uninstallbin uninstallscripts uninstallcp

uninstallman:
	@$(SHELL) $(srcdir)uninstallman.sh $(MANDIR) $(srcdir)

uninstallbin:
	@$(SHELL) $(srcdir)uninstallbin.sh $(INSTALLPERMS) $(BASEDIR) $(SBINDIR) $(LIBDIR) $(VARDIR) $(SPROGS)
	@$(SHELL) $(srcdir)uninstallbin.sh $(INSTALLPERMS) $(BASEDIR) $(BINDIR) $(LIBDIR) $(VARDIR) $(PROGS)

uninstallscripts:
	@$(SHELL) $(srcdir)uninstallscripts.sh $(INSTALLPERMS) $(BINDIR) $(SCRIPTS)

uninstallcp:
	@$(SHELL) $(srcdir)uninstallcp.sh $(CODEPAGEDIR) $(CODEPAGELIST)

clean:
	rm -f core *.o */*.o *~ $(PROGS) $(SPROGS)

cleandir:  clean
	rm -f .depend tags

proto:
	@$(SHELL) $(srcdir)checkos.sh $(FLAGSM)
	$(AWK) -f mkproto.awk `echo $(PROTOOBJ) | sed -e 's/\.o/\.c/g' | tr ' ' '\n' | sort | uniq` > proto.h

tags:
	etags `find . -name "*.[ch]"`

realclean: clean

