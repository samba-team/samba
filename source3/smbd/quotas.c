#ifdef QUOTAS
/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   support for quotas
   Copyright (C) Andrew Tridgell 1992-1995
   
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


/* 
 * This is one of the most system dependent parts of Samba, and its
 * done a litle differently. Each system has its own way of doing 
 * things :-(
 */

#include "includes.h"

extern int DEBUGLEVEL;

#ifdef LINUX

#ifdef __KERNEL__
# undef __KERNEL__
# include <sys/quota.h>
# define __KERNEL__
#else
# include <sys/quota.h>
#endif

#include <mntent.h>

/****************************************************************************
try to get the disk space from disk quotas (LINUX version)
****************************************************************************/
/*
If you didn't make the symlink to the quota package, too bad :(
*/
#include "quota/quotactl.c"
#include "quota/hasquota.c"
BOOL disk_quotas(char *path, int *bsize, int *dfree, int *dsize)
{
  uid_t euser_id;
  struct dqblk D;
  struct stat S;
  dev_t devno ;
  struct mntent *mnt;
  FILE *fp;
  int found ;
  int qcmd, fd ;
  char *qfpathname;
  
  /* find the block device file */
  
  if ( stat(path, &S) == -1 )
    return(False) ;

  devno = S.st_dev ;
  
  fp = setmntent(MOUNTED,"r");
  found = False ;
  
  while ((mnt = getmntent(fp)) != (struct mntent *) 0) {
    if ( stat(mnt->mnt_dir,&S) == -1 )
      continue ;
    if (S.st_dev == devno) {
      found = True ;
      break ;
    }
  }
  endmntent(fp) ;
  
  if ( ! found )
    return(False) ;
  
  qcmd = QCMD(Q_GETQUOTA, USRQUOTA);
  
  if (hasmntopt(mnt, MNTOPT_NOAUTO) || hasmntopt(mnt, MNTOPT_NOQUOTA))
    return(False) ;
  
  if (!hasquota(mnt, USRQUOTA, &qfpathname))
    return(False) ;
  
  euser_id = geteuid();
  seteuid(0);
  
  if (quotactl(qcmd, mnt->mnt_fsname, euser_id, (caddr_t)&D) != 0) {
    if ((fd = open(qfpathname, O_RDONLY)) < 0) {
      seteuid(euser_id);
      return(False);
    }
    lseek(fd, (long) dqoff(euser_id), L_SET);
    switch (read(fd, &D, sizeof(struct dqblk))) {
    case 0:/* EOF */
      memset((caddr_t)&D, 0, sizeof(struct dqblk));
      break;
    case sizeof(struct dqblk):   /* OK */
      break;
    default:   /* ERROR */
      close(fd);
      seteuid(euser_id);
      return(False);
    }
  }
  seteuid(euser_id);
  *bsize=1024;

  if (D.dqb_bsoftlimit==0)
    return(False);
  if ((D.dqb_curblocks>D.dqb_bsoftlimit)||(D.dqb_curinodes>D.dqb_isoftlimit))
    {
      *dfree = 0;
      *dsize = D.dqb_curblocks;
    }
  else {
    *dfree = D.dqb_bsoftlimit - D.dqb_curblocks;
    *dsize = D.dqb_bsoftlimit;
  }
  return (True);
}

#elif defined(CRAY)

#include <sys/quota.h>
#include <mntent.h>

/****************************************************************************
try to get the disk space from disk quotas (CRAY VERSION)
****************************************************************************/
BOOL disk_quotas(char *path, int *bsize, int *dfree, int *dsize)
{
  struct mntent *mnt;
  FILE *fd;
  struct stat sbuf;
  dev_t devno ;
  static dev_t devno_cached = 0 ;
  static char name[MNTMAXSTR] ;
  struct q_request request ;
  struct qf_header header ;
  static int quota_default = 0 ;
  int found ;
  
  if ( stat(path,&sbuf) == -1 )
    return(False) ;
  
  devno = sbuf.st_dev ;
  
  if ( devno != devno_cached ) {
    
    devno_cached = devno ;
    
    if ((fd = setmntent(KMTAB)) == NULL)
      return(False) ;
    
    found = False ;
    
    while ((mnt = getmntent(fd)) != NULL) {
      
      if ( stat(mnt->mnt_dir,&sbuf) == -1 )
	continue ;
      
      if (sbuf.st_dev == devno) {
	
	found = True ;
	break ;
	
      }
      
    }
    
    strcpy(name,mnt->mnt_dir) ;
    endmntent(fd) ;
    
    if ( ! found )
      return(False) ;
  }
  
  request.qf_magic = QF_MAGIC ;
  request.qf_entry.id = geteuid() ;
  
  if (quotactl(name, Q_GETQUOTA, &request) == -1)
    return(False) ;
  
  if ( ! request.user )
    return(False) ;
  
  if ( request.qf_entry.user_q.f_quota == QFV_DEFAULT ) {
    
    if ( ! quota_default ) {
      
      if ( quotactl(name, Q_GETHEADER, &header) == -1 )
	return(False) ;
      else
	quota_default = header.user_h.def_fq ;
    }
    
    *dfree = quota_default ;
    
  }else if ( request.qf_entry.user_q.f_quota == QFV_PREVENT ) {
    
    *dfree = 0 ;
    
  }else{
    
    *dfree = request.qf_entry.user_q.f_quota ;
    
  }
  
  *dsize = request.qf_entry.user_q.f_use ;
  
  if ( *dfree )
    *dfree -= *dsize ;
  
  if ( *dfree < 0 )
    *dfree = 0 ;
  
  *bsize = 4096 ;  /* Cray blocksize */
  
  return(True) ;
  
}


#elif defined(SUNOS5) || defined(SUNOS4)

#include <fcntl.h>
#if defined(SUNOS5)
#include <sys/fs/ufs_quota.h>
#include <sys/mnttab.h>
#else /* defined(SUNOS4) */
#include <ufs/quota.h>
#include <mntent.h>
#endif

/****************************************************************************
try to get the disk space from disk quotas (solaris 2 version)
****************************************************************************/
/* Quota code by Peter Urbanec (amiga@cse.unsw.edu.au) */
BOOL disk_quotas(char *path, int *bsize, int *dfree, int *dsize)
{
  uid_t user_id, euser_id;
  int ret;
  struct dqblk D;
#if defined(SUNOS5)
  struct quotctl command;
  int file;
  struct mnttab mnt;
  static char name[MNT_LINE_MAX] ;
#else
  struct mntent *mnt;
  static char name[MNTMAXSTR] ;
#endif
  FILE *fd;
  struct stat sbuf;
  dev_t devno ;
  static dev_t devno_cached = 0 ;
  int found ;
  
  if ( stat(path,&sbuf) == -1 )
    return(False) ;
  
  devno = sbuf.st_dev ;
  DEBUG(5,("disk_quotas: looking for path \"%s\" devno=%o\n", path,devno));
  if ( devno != devno_cached ) {
    devno_cached = devno ;
#if defined(SUNOS5)
    if ((fd = fopen(MNTTAB, "r")) == NULL)
      return(False) ;
    
    found = False ;
    while (getmntent(fd, &mnt) == 0) {
      if ( stat(mnt.mnt_mountp,&sbuf) == -1 )
	continue ;
      DEBUG(5,("disk_quotas: testing \"%s\" devno=%o\n", 
	       mnt.mnt_mountp,sbuf.st_dev));
      if (sbuf.st_dev == devno) {
	found = True ;
	break ;
      }
    }
    
    strcpy(name,mnt.mnt_mountp) ;
    strcat(name,"/quotas") ;
    fclose(fd) ;
#else
    if ((fd = setmntent(MOUNTED, "r")) == NULL)
      return(False) ;
    
    found = False ;
    while ((mnt = getmntent(fd)) != NULL) {
      if ( stat(mnt->mnt_dir,&sbuf) == -1 )
	continue ;
      DEBUG(5,("disk_quotas: testing \"%s\" devno=%o\n", 
	       mnt->mnt_dir,sbuf.st_dev));
      if (sbuf.st_dev == devno) {
	found = True ;
	break ;
      }
    }
    
    strcpy(name,mnt->mnt_fsname) ;
    endmntent(fd) ;
#endif
    
    if ( ! found )
      return(False) ;
  }

  euser_id = geteuid();
  user_id = getuid();

  setuid(0);  /* Solaris seems to want to give info only to super-user */
  seteuid(0);

#if defined(SUNOS5)
  DEBUG(5,("disk_quotas: looking for quotas file \"%s\"\n", name));
  if((file=open(name, O_RDONLY))<0) {
    setuid(user_id);  /* Restore the original UID status */
    seteuid(euser_id);
    return(False);
  }
  command.op = Q_GETQUOTA;
  command.uid = euser_id;
  command.addr = (caddr_t) &D;
  ret = ioctl(file, Q_QUOTACTL, &command);
  close(file);
#else
  DEBUG(5,("disk_quotas: trying quotactl on device \"%s\"\n", name));
  ret = quotactl(Q_GETQUOTA, name, euser_id, &D);
#endif

  setuid(user_id);  /* Restore the original UID status */
  seteuid(euser_id);

  if (ret < 0) {
    DEBUG(2,("disk_quotas ioctl (Solaris) failed\n"));
    return(False);
  }


  /* Use softlimit to determine disk space. A user exceeding the quota is told
   * that there's no space left. Writes might actually work for a bit if the
   * hardlimit is set higher than softlimit. Effectively the disk becomes
   * made of rubber latex and begins to expand to accommodate the user :-)
   */

  if (D.dqb_bsoftlimit==0)
    return(False);
  *bsize = 512;
  *dfree = D.dqb_bsoftlimit - D.dqb_curblocks;
  *dsize = D.dqb_bsoftlimit;
  if(*dfree < 0)
    {
     *dfree = 0;
     *dsize = D.dqb_curblocks;
    }
      
DEBUG(5,("disk_quotas for path \"%s\" returning  bsize %d, dfree %d, dsize %d\n",
         path,*bsize,*dfree,*dsize));

      return(True);
}

#else

#include <sys/quota.h>
#include <devnm.h>

/****************************************************************************
try to get the disk space from disk quotas - default version
****************************************************************************/
BOOL disk_quotas(char *path, int *bsize, int *dfree, int *dsize)
{
  uid_t user_id, euser_id;
  int r;
  char dev_disk[256];
  struct dqblk D;
  struct stat S;
  /* find the block device file */
  if ((stat(path, &S)<0) ||
      (devnm(S_IFBLK, S.st_dev, dev_disk, 256, 0)<0)) return (False);

  euser_id = geteuid();

#ifdef USE_SETRES
  /* for HPUX, real uid must be same as euid to execute quotactl for euid */
  user_id = getuid();
  setresuid(euser_id,-1,-1);
#endif
  r=quotactl(Q_GETQUOTA, dev_disk, euser_id, &D);
  #ifdef USE_SETRES
  if (setresuid(user_id,-1,-1))
    DEBUG(5,("Unable to reset uid to %d\n", user_id));
  #endif
  /* Use softlimit to determine disk space, except when it has been exceeded */
  *bsize = 1024;
  if (r)
    {
      if (errno == EDQUOT) 
	{
 	  *dfree =0;
 	  *dsize =D.dqb_curblocks;
 	  return (True);
	}
      else return(False);
    }
  if (D.dqb_bsoftlimit==0)
    return(False);
  /* Use softlimit to determine disk space, except when it has been exceeded */
  if ((D.dqb_curblocks>D.dqb_bsoftlimit)||(D.dqb_curfiles>D.dqb_fsoftlimit)) 
    {
      *dfree = 0;
      *dsize = D.dqb_curblocks;
    }
  else {
    *dfree = D.dqb_bsoftlimit - D.dqb_curblocks;
    *dsize = D.dqb_bsoftlimit;
  }
  return (True);
}

#endif

#else
/* this keeps fussy compilers happy */
 void quotas_dummy(void) {}
#endif /* QUOTAS */

