/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   status reporting
   Copyright (C) Andrew Tridgell 1994-1998
   
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

   Revision History:

   12 aug 96: Erik.Devriendt@te6.siemens.be
   added support for shared memory implementation of share mode locking

   21-Jul-1998: rsharpe@ns.aus.com (Richard Sharpe)
   Added -L (locks only) -S (shares only) flags and code

*/

/*
 * This program reports current SMB connections
 */

#define NO_SYSLOG

#include "includes.h"

struct session_record{
  pid_t pid;
  uid_t uid;
  char machine[31];
  time_t start;
  struct session_record *next;
} *srecs;

extern FILE *dbf;
extern BOOL AllowDebugChange;

static pstring Ucrit_username = "";                   /* added by OH */
static pid_t	Ucrit_pid[100];  /* Ugly !!! */        /* added by OH */
static int            Ucrit_MaxPid=0;                        /* added by OH */
static unsigned int   Ucrit_IsActive = 0;                    /* added by OH */
static int verbose, brief;
static int            shares_only = 0;            /* Added by RJS */
static int            locks_only  = 0;            /* Added by RJS */
static BOOL processes_only=False;
static int show_brl;

/* we need these because we link to locking*.o */
 void become_root(void) {}
 void unbecome_root(void) {}


/* added by OH */
static void Ucrit_addUsername(char *username)
{
	pstrcpy(Ucrit_username, username);
	if(strlen(Ucrit_username) > 0)
		Ucrit_IsActive = 1;
}

static unsigned int Ucrit_checkUsername(char *username)
{
	if ( !Ucrit_IsActive) return 1;
	if (strcmp(Ucrit_username,username) ==0) return 1;
	return 0;
}

static void Ucrit_addPid(pid_t pid)
{
	int i;
	if ( !Ucrit_IsActive) return;
	for (i=0;i<Ucrit_MaxPid;i++)
		if( pid == Ucrit_pid[i] ) return;
	Ucrit_pid[Ucrit_MaxPid++] = pid;
}

static unsigned int Ucrit_checkPid(pid_t pid)
{
	int i;
	if ( !Ucrit_IsActive) return 1;
	for (i=0;i<Ucrit_MaxPid;i++)
		if( pid == Ucrit_pid[i] ) return 1;
	return 0;
}


static void print_share_mode(share_mode_entry *e, char *fname)
{
	static int count;
	if (count==0) {
		printf("Locked files:\n");
		printf("Pid    DenyMode   Access      R/W        Oplock           Name\n");
		printf("--------------------------------------------------------------\n");
	}
	count++;

	if (Ucrit_checkPid(e->pid)) {
          printf("%-5d  ",(int)e->pid);
	  switch (GET_DENY_MODE(e->share_mode)) {
	  case DENY_NONE: printf("DENY_NONE  "); break;
	  case DENY_ALL:  printf("DENY_ALL   "); break;
	  case DENY_DOS:  printf("DENY_DOS   "); break;
	  case DENY_READ: printf("DENY_READ  "); break;
	  case DENY_WRITE:printf("DENY_WRITE "); break;
	  case DENY_FCB:  printf("DENY_FCB "); break;
	  }
          printf("0x%-8x  ",(unsigned int)e->desired_access);
	  switch (e->share_mode&0xF) {
	  case 0: printf("RDONLY     "); break;
	  case 1: printf("WRONLY     "); break;
	  case 2: printf("RDWR       "); break;
	  }

	  if((e->op_type & 
	     (EXCLUSIVE_OPLOCK|BATCH_OPLOCK)) == 
	      (EXCLUSIVE_OPLOCK|BATCH_OPLOCK))
		printf("EXCLUSIVE+BATCH ");
	  else if (e->op_type & EXCLUSIVE_OPLOCK)
		printf("EXCLUSIVE       ");
	  else if (e->op_type & BATCH_OPLOCK)
		printf("BATCH           ");
	  else if (e->op_type & LEVEL_II_OPLOCK)
		printf("LEVEL_II        ");
	  else
		printf("NONE            ");

	  printf(" %s   %s",dos_to_unix_static(fname),
             asctime(LocalTime((time_t *)&e->time.tv_sec)));
	}
}

static void print_brl(SMB_DEV_T dev, SMB_INO_T ino, int pid, 
		      enum brl_type lock_type,
		      br_off start, br_off size)
{
	static int count;
	if (count==0) {
		printf("Byte range locks:\n");
		printf("   Pid     dev:inode  R/W      start        size\n");
		printf("------------------------------------------------\n");
	}
	count++;

	printf("%6d   %05x:%05x    %s  %9.0f   %9.0f\n", 
	       (int)pid, (int)dev, (int)ino, 
	       lock_type==READ_LOCK?"R":"W",
	       (double)start, (double)size);
}


/*******************************************************************
 dump the elements of the profile structure
  ******************************************************************/
static int profile_dump(void)
{
#ifdef WITH_PROFILE
	if (!profile_setup(True)) {
		fprintf(stderr,"Failed to initialise profile memory\n");
		return -1;
	}

	printf("smb_count:                      %u\n", profile_p->smb_count);
	printf("uid_changes:                    %u\n", profile_p->uid_changes);
	printf("************************ System Calls ****************************\n");
	printf("opendir_count:                  %u\n", profile_p->syscall_opendir_count);
	printf("opendir_time:                   %u\n", profile_p->syscall_opendir_time);
	printf("readdir_count:                  %u\n", profile_p->syscall_readdir_count);
	printf("readdir_time:                   %u\n", profile_p->syscall_readdir_time);
	printf("mkdir_count:                    %u\n", profile_p->syscall_mkdir_count);
	printf("mkdir_time:                     %u\n", profile_p->syscall_mkdir_time);
	printf("rmdir_count:                    %u\n", profile_p->syscall_rmdir_count);
	printf("rmdir_time:                     %u\n", profile_p->syscall_rmdir_time);
	printf("closedir_count:                 %u\n", profile_p->syscall_closedir_count);
	printf("closedir_time:                  %u\n", profile_p->syscall_closedir_time);
	printf("open_count:                     %u\n", profile_p->syscall_open_count);
	printf("open_time:                      %u\n", profile_p->syscall_open_time);
	printf("close_count:                    %u\n", profile_p->syscall_close_count);
	printf("close_time:                     %u\n", profile_p->syscall_close_time);
	printf("read_count:                     %u\n", profile_p->syscall_read_count);
	printf("read_time:                      %u\n", profile_p->syscall_read_time);
	printf("read_bytes:                     %u\n", profile_p->syscall_read_bytes);
	printf("write_count:                    %u\n", profile_p->syscall_write_count);
	printf("write_time:                     %u\n", profile_p->syscall_write_time);
	printf("write_bytes:                    %u\n", profile_p->syscall_write_bytes);
#ifdef WITH_SENDFILE
	printf("sendfile_count:                    %u\n", profile_p->syscall_sendfile_count);
	printf("sendfile_time:                     %u\n", profile_p->syscall_sendfile_time);
	printf("sendfile_bytes:                    %u\n", profile_p->syscall_sendfile_bytes);
#endif
	printf("lseek_count:                    %u\n", profile_p->syscall_lseek_count);
	printf("lseek_time:                     %u\n", profile_p->syscall_lseek_time);
	printf("rename_count:                   %u\n", profile_p->syscall_rename_count);
	printf("rename_time:                    %u\n", profile_p->syscall_rename_time);
	printf("fsync_count:                    %u\n", profile_p->syscall_fsync_count);
	printf("fsync_time:                     %u\n", profile_p->syscall_fsync_time);
	printf("stat_count:                     %u\n", profile_p->syscall_stat_count);
	printf("stat_time:                      %u\n", profile_p->syscall_stat_time);
	printf("fstat_count:                    %u\n", profile_p->syscall_fstat_count);
	printf("fstat_time:                     %u\n", profile_p->syscall_fstat_time);
	printf("lstat_count:                    %u\n", profile_p->syscall_lstat_count);
	printf("lstat_time:                     %u\n", profile_p->syscall_lstat_time);
	printf("unlink_count:                   %u\n", profile_p->syscall_unlink_count);
	printf("unlink_time:                    %u\n", profile_p->syscall_unlink_time);
	printf("chmod_count:                    %u\n", profile_p->syscall_chmod_count);
	printf("chmod_time:                     %u\n", profile_p->syscall_chmod_time);
	printf("fchmod_count:                   %u\n", profile_p->syscall_fchmod_count);
	printf("fchmod_time:                    %u\n", profile_p->syscall_fchmod_time);
	printf("chown_count:                    %u\n", profile_p->syscall_chown_count);
	printf("chown_time:                     %u\n", profile_p->syscall_chown_time);
	printf("fchown_count:                   %u\n", profile_p->syscall_fchown_count);
	printf("fchown_time:                    %u\n", profile_p->syscall_fchown_time);
	printf("chdir_count:                    %u\n", profile_p->syscall_chdir_count);
	printf("chdir_time:                     %u\n", profile_p->syscall_chdir_time);
	printf("getwd_count:                    %u\n", profile_p->syscall_getwd_count);
	printf("getwd_time:                     %u\n", profile_p->syscall_getwd_time);
	printf("utime_count:                    %u\n", profile_p->syscall_utime_count);
	printf("utime_time:                     %u\n", profile_p->syscall_utime_time);
	printf("ftruncate_count:                %u\n", profile_p->syscall_ftruncate_count);
	printf("ftruncate_time:                 %u\n", profile_p->syscall_ftruncate_time);
	printf("fcntl_lock_count:               %u\n", profile_p->syscall_fcntl_lock_count);
	printf("fcntl_lock_time:                %u\n", profile_p->syscall_fcntl_lock_time);
	printf("readlink_count:                 %u\n", profile_p->syscall_readlink_count);
	printf("readlink_time:                  %u\n", profile_p->syscall_readlink_time);
	printf("symlink_count:                  %u\n", profile_p->syscall_symlink_count);
	printf("symlink_time:                   %u\n", profile_p->syscall_symlink_time);
	printf("************************ Statcache *******************************\n");
	printf("lookups:                        %u\n", profile_p->statcache_lookups);
	printf("misses:                         %u\n", profile_p->statcache_misses);
	printf("hits:                           %u\n", profile_p->statcache_hits);
	printf("************************ Writecache ******************************\n");
	printf("read_hits:                      %u\n", profile_p->writecache_read_hits);
	printf("abutted_writes:                 %u\n", profile_p->writecache_abutted_writes);
	printf("total_writes:                   %u\n", profile_p->writecache_total_writes);
	printf("non_oplock_writes:              %u\n", profile_p->writecache_non_oplock_writes);
	printf("direct_writes:                  %u\n", profile_p->writecache_direct_writes);
	printf("init_writes:                    %u\n", profile_p->writecache_init_writes);
	printf("flushed_writes[SEEK]:           %u\n", profile_p->writecache_flushed_writes[SEEK_FLUSH]);
	printf("flushed_writes[READ]:           %u\n", profile_p->writecache_flushed_writes[READ_FLUSH]);
	printf("flushed_writes[WRITE]:          %u\n", profile_p->writecache_flushed_writes[WRITE_FLUSH]);
	printf("flushed_writes[READRAW]:        %u\n", profile_p->writecache_flushed_writes[READRAW_FLUSH]);
	printf("flushed_writes[OPLOCK_RELEASE]: %u\n", profile_p->writecache_flushed_writes[OPLOCK_RELEASE_FLUSH]);
	printf("flushed_writes[CLOSE]:          %u\n", profile_p->writecache_flushed_writes[CLOSE_FLUSH]);
	printf("flushed_writes[SYNC]:           %u\n", profile_p->writecache_flushed_writes[SYNC_FLUSH]);
	printf("flushed_writes[SIZECHANGE]:     %u\n", profile_p->writecache_flushed_writes[SIZECHANGE_FLUSH]);
	printf("num_perfect_writes:             %u\n", profile_p->writecache_num_perfect_writes);
	printf("num_write_caches:               %u\n", profile_p->writecache_num_write_caches);
	printf("allocated_write_caches:         %u\n", profile_p->writecache_allocated_write_caches);
	printf("************************ SMB Calls *******************************\n");
	printf("mkdir_count:                    %u\n", profile_p->SMBmkdir_count);
	printf("mkdir_time:                     %u\n", profile_p->SMBmkdir_time);
	printf("rmdir_count:                    %u\n", profile_p->SMBrmdir_count);
	printf("rmdir_time:                     %u\n", profile_p->SMBrmdir_time);
	printf("open_count:                     %u\n", profile_p->SMBopen_count);
	printf("open_time:                      %u\n", profile_p->SMBopen_time);
	printf("create_count:                   %u\n", profile_p->SMBcreate_count);
	printf("create_time:                    %u\n", profile_p->SMBcreate_time);
	printf("close_count:                    %u\n", profile_p->SMBclose_count);
	printf("close_time:                     %u\n", profile_p->SMBclose_time);
	printf("flush_count:                    %u\n", profile_p->SMBflush_count);
	printf("flush_time:                     %u\n", profile_p->SMBflush_time);
	printf("unlink_count:                   %u\n", profile_p->SMBunlink_count);
	printf("unlink_time:                    %u\n", profile_p->SMBunlink_time);
	printf("mv_count:                       %u\n", profile_p->SMBmv_count);
	printf("mv_time:                        %u\n", profile_p->SMBmv_time);
	printf("getatr_count:                   %u\n", profile_p->SMBgetatr_count);
	printf("getatr_time:                    %u\n", profile_p->SMBgetatr_time);
	printf("setatr_count:                   %u\n", profile_p->SMBsetatr_count);
	printf("setatr_time:                    %u\n", profile_p->SMBsetatr_time);
	printf("read_count:                     %u\n", profile_p->SMBread_count);
	printf("read_time:                      %u\n", profile_p->SMBread_time);
	printf("write_count:                    %u\n", profile_p->SMBwrite_count);
	printf("write_time:                     %u\n", profile_p->SMBwrite_time);
	printf("lock_count:                     %u\n", profile_p->SMBlock_count);
	printf("lock_time:                      %u\n", profile_p->SMBlock_time);
	printf("unlock_count:                   %u\n", profile_p->SMBunlock_count);
	printf("unlock_time:                    %u\n", profile_p->SMBunlock_time);
	printf("ctemp_count:                    %u\n", profile_p->SMBctemp_count);
	printf("ctemp_time:                     %u\n", profile_p->SMBctemp_time);
	printf("mknew_count:                    %u\n", profile_p->SMBmknew_count);
	printf("mknew_time:                     %u\n", profile_p->SMBmknew_time);
	printf("chkpth_count:                   %u\n", profile_p->SMBchkpth_count);
	printf("chkpth_time:                    %u\n", profile_p->SMBchkpth_time);
	printf("exit_count:                     %u\n", profile_p->SMBexit_count);
	printf("exit_time:                      %u\n", profile_p->SMBexit_time);
	printf("lseek_count:                    %u\n", profile_p->SMBlseek_count);
	printf("lseek_time:                     %u\n", profile_p->SMBlseek_time);
	printf("lockread_count:                 %u\n", profile_p->SMBlockread_count);
	printf("lockread_time:                  %u\n", profile_p->SMBlockread_time);
	printf("writeunlock_count:              %u\n", profile_p->SMBwriteunlock_count);
	printf("writeunlock_time:               %u\n", profile_p->SMBwriteunlock_time);
	printf("readbraw_count:                 %u\n", profile_p->SMBreadbraw_count);
	printf("readbraw_time:                  %u\n", profile_p->SMBreadbraw_time);
	printf("readBmpx_count:                 %u\n", profile_p->SMBreadBmpx_count);
	printf("readBmpx_time:                  %u\n", profile_p->SMBreadBmpx_time);
	printf("readBs_count:                   %u\n", profile_p->SMBreadBs_count);
	printf("readBs_time:                    %u\n", profile_p->SMBreadBs_time);
	printf("writebraw_count:                %u\n", profile_p->SMBwritebraw_count);
	printf("writebraw_time:                 %u\n", profile_p->SMBwritebraw_time);
	printf("writeBmpx_count:                %u\n", profile_p->SMBwriteBmpx_count);
	printf("writeBmpx_time:                 %u\n", profile_p->SMBwriteBmpx_time);
	printf("writeBs_count:                  %u\n", profile_p->SMBwriteBs_count);
	printf("writeBs_time:                   %u\n", profile_p->SMBwriteBs_time);
	printf("writec_count:                   %u\n", profile_p->SMBwritec_count);
	printf("writec_time:                    %u\n", profile_p->SMBwritec_time);
	printf("setattrE_count:                 %u\n", profile_p->SMBsetattrE_count);
	printf("setattrE_time:                  %u\n", profile_p->SMBsetattrE_time);
	printf("getattrE_count:                 %u\n", profile_p->SMBgetattrE_count);
	printf("getattrE_time:                  %u\n", profile_p->SMBgetattrE_time);
	printf("lockingX_count:                 %u\n", profile_p->SMBlockingX_count);
	printf("lockingX_time:                  %u\n", profile_p->SMBlockingX_time);
	printf("trans_count:                    %u\n", profile_p->SMBtrans_count);
	printf("trans_time:                     %u\n", profile_p->SMBtrans_time);
	printf("transs_count:                   %u\n", profile_p->SMBtranss_count);
	printf("transs_time:                    %u\n", profile_p->SMBtranss_time);
	printf("ioctl_count:                    %u\n", profile_p->SMBioctl_count);
	printf("ioctl_time:                     %u\n", profile_p->SMBioctl_time);
	printf("ioctls_count:                   %u\n", profile_p->SMBioctls_count);
	printf("ioctls_time:                    %u\n", profile_p->SMBioctls_time);
	printf("copy_count:                     %u\n", profile_p->SMBcopy_count);
	printf("copy_time:                      %u\n", profile_p->SMBcopy_time);
	printf("move_count:                     %u\n", profile_p->SMBmove_count);
	printf("move_time:                      %u\n", profile_p->SMBmove_time);
	printf("echo_count:                     %u\n", profile_p->SMBecho_count);
	printf("echo_time:                      %u\n", profile_p->SMBecho_time);
	printf("writeclose_count:               %u\n", profile_p->SMBwriteclose_count);
	printf("writeclose_time:                %u\n", profile_p->SMBwriteclose_time);
	printf("openX_count:                    %u\n", profile_p->SMBopenX_count);
	printf("openX_time:                     %u\n", profile_p->SMBopenX_time);
	printf("readX_count:                    %u\n", profile_p->SMBreadX_count);
	printf("readX_time:                     %u\n", profile_p->SMBreadX_time);
	printf("writeX_count:                   %u\n", profile_p->SMBwriteX_count);
	printf("writeX_time:                    %u\n", profile_p->SMBwriteX_time);
	printf("trans2_count:                   %u\n", profile_p->SMBtrans2_count);
	printf("trans2_time:                    %u\n", profile_p->SMBtrans2_time);
	printf("transs2_count:                  %u\n", profile_p->SMBtranss2_count);
	printf("transs2_time:                   %u\n", profile_p->SMBtranss2_time);
	printf("findclose_count:                %u\n", profile_p->SMBfindclose_count);
	printf("findclose_time:                 %u\n", profile_p->SMBfindclose_time);
	printf("findnclose_count:               %u\n", profile_p->SMBfindnclose_count);
	printf("findnclose_time:                %u\n", profile_p->SMBfindnclose_time);
	printf("tcon_count:                     %u\n", profile_p->SMBtcon_count);
	printf("tcon_time:                      %u\n", profile_p->SMBtcon_time);
	printf("tdis_count:                     %u\n", profile_p->SMBtdis_count);
	printf("tdis_time:                      %u\n", profile_p->SMBtdis_time);
	printf("negprot_count:                  %u\n", profile_p->SMBnegprot_count);
	printf("negprot_time:                   %u\n", profile_p->SMBnegprot_time);
	printf("sesssetupX_count:               %u\n", profile_p->SMBsesssetupX_count);
	printf("sesssetupX_time:                %u\n", profile_p->SMBsesssetupX_time);
	printf("ulogoffX_count:                 %u\n", profile_p->SMBulogoffX_count);
	printf("ulogoffX_time:                  %u\n", profile_p->SMBulogoffX_time);
	printf("tconX_count:                    %u\n", profile_p->SMBtconX_count);
	printf("tconX_time:                     %u\n", profile_p->SMBtconX_time);
	printf("dskattr_count:                  %u\n", profile_p->SMBdskattr_count);
	printf("dskattr_time:                   %u\n", profile_p->SMBdskattr_time);
	printf("search_count:                   %u\n", profile_p->SMBsearch_count);
	printf("search_time:                    %u\n", profile_p->SMBsearch_time);
	printf("ffirst_count:                   %u\n", profile_p->SMBffirst_count);
	printf("ffirst_time:                    %u\n", profile_p->SMBffirst_time);
	printf("funique_count:                  %u\n", profile_p->SMBfunique_count);
	printf("funique_time:                   %u\n", profile_p->SMBfunique_time);
	printf("fclose_count:                   %u\n", profile_p->SMBfclose_count);
	printf("fclose_time:                    %u\n", profile_p->SMBfclose_time);
	printf("nttrans_count:                  %u\n", profile_p->SMBnttrans_count);
	printf("nttrans_time:                   %u\n", profile_p->SMBnttrans_time);
	printf("nttranss_count:                 %u\n", profile_p->SMBnttranss_count);
	printf("nttranss_time:                  %u\n", profile_p->SMBnttranss_time);
	printf("ntcreateX_count:                %u\n", profile_p->SMBntcreateX_count);
	printf("ntcreateX_time:                 %u\n", profile_p->SMBntcreateX_time);
	printf("ntcancel_count:                 %u\n", profile_p->SMBntcancel_count);
	printf("ntcancel_time:                  %u\n", profile_p->SMBntcancel_time);
	printf("splopen_count:                  %u\n", profile_p->SMBsplopen_count);
	printf("splopen_time:                   %u\n", profile_p->SMBsplopen_time);
	printf("splwr_count:                    %u\n", profile_p->SMBsplwr_count);
	printf("splwr_time:                     %u\n", profile_p->SMBsplwr_time);
	printf("splclose_count:                 %u\n", profile_p->SMBsplclose_count);
	printf("splclose_time:                  %u\n", profile_p->SMBsplclose_time);
	printf("splretq_count:                  %u\n", profile_p->SMBsplretq_count);
	printf("splretq_time:                   %u\n", profile_p->SMBsplretq_time);
	printf("sends_count:                    %u\n", profile_p->SMBsends_count);
	printf("sends_time:                     %u\n", profile_p->SMBsends_time);
	printf("sendb_count:                    %u\n", profile_p->SMBsendb_count);
	printf("sendb_time:                     %u\n", profile_p->SMBsendb_time);
	printf("fwdname_count:                  %u\n", profile_p->SMBfwdname_count);
	printf("fwdname_time:                   %u\n", profile_p->SMBfwdname_time);
	printf("cancelf_count:                  %u\n", profile_p->SMBcancelf_count);
	printf("cancelf_time:                   %u\n", profile_p->SMBcancelf_time);
	printf("getmac_count:                   %u\n", profile_p->SMBgetmac_count);
	printf("getmac_time:                    %u\n", profile_p->SMBgetmac_time);
	printf("sendstrt_count:                 %u\n", profile_p->SMBsendstrt_count);
	printf("sendstrt_time:                  %u\n", profile_p->SMBsendstrt_time);
	printf("sendend_count:                  %u\n", profile_p->SMBsendend_count);
	printf("sendend_time:                   %u\n", profile_p->SMBsendend_time);
	printf("sendtxt_count:                  %u\n", profile_p->SMBsendtxt_count);
	printf("sendtxt_time:                   %u\n", profile_p->SMBsendtxt_time);
	printf("invalid_count:                  %u\n", profile_p->SMBinvalid_count);
	printf("invalid_time:                   %u\n", profile_p->SMBinvalid_time);
	printf("************************ Pathworks Calls *************************\n");
	printf("setdir_count:                   %u\n", profile_p->pathworks_setdir_count);
	printf("setdir_time:                    %u\n", profile_p->pathworks_setdir_time);
	printf("************************ Trans2 Calls ****************************\n");
	printf("open_count:                     %u\n", profile_p->Trans2_open_count);
	printf("open_time:                      %u\n", profile_p->Trans2_open_time);
	printf("findfirst_count:                %u\n", profile_p->Trans2_findfirst_count);
	printf("findfirst_time:                 %u\n", profile_p->Trans2_findfirst_time);
	printf("findnext_count:                 %u\n", profile_p->Trans2_findnext_count);
	printf("findnext_time:                  %u\n", profile_p->Trans2_findnext_time);
	printf("qfsinfo_count:                  %u\n", profile_p->Trans2_qfsinfo_count);
	printf("qfsinfo_time:                   %u\n", profile_p->Trans2_qfsinfo_time);
	printf("setfsinfo_count:                %u\n", profile_p->Trans2_setfsinfo_count);
	printf("setfsinfo_time:                 %u\n", profile_p->Trans2_setfsinfo_time);
	printf("qpathinfo_count:                %u\n", profile_p->Trans2_qpathinfo_count);
	printf("qpathinfo_time:                 %u\n", profile_p->Trans2_qpathinfo_time);
	printf("setpathinfo_count:              %u\n", profile_p->Trans2_setpathinfo_count);
	printf("setpathinfo_time:               %u\n", profile_p->Trans2_setpathinfo_time);
	printf("qfileinfo_count:                %u\n", profile_p->Trans2_qfileinfo_count);
	printf("qfileinfo_time:                 %u\n", profile_p->Trans2_qfileinfo_time);
	printf("setfileinfo_count:              %u\n", profile_p->Trans2_setfileinfo_count);
	printf("setfileinfo_time:               %u\n", profile_p->Trans2_setfileinfo_time);
	printf("fsctl_count:                    %u\n", profile_p->Trans2_fsctl_count);
	printf("fsctl_time:                     %u\n", profile_p->Trans2_fsctl_time);
	printf("ioctl_count:                    %u\n", profile_p->Trans2_ioctl_count);
	printf("ioctl_time:                     %u\n", profile_p->Trans2_ioctl_time);
	printf("findnotifyfirst_count:          %u\n", profile_p->Trans2_findnotifyfirst_count);
	printf("findnotifyfirst_time:           %u\n", profile_p->Trans2_findnotifyfirst_time);
	printf("findnotifynext_count:           %u\n", profile_p->Trans2_findnotifynext_count);
	printf("findnotifynext_time:            %u\n", profile_p->Trans2_findnotifynext_time);
	printf("mkdir_count:                    %u\n", profile_p->Trans2_mkdir_count);
	printf("mkdir_time:                     %u\n", profile_p->Trans2_mkdir_time);
	printf("session_setup_count:            %u\n", profile_p->Trans2_session_setup_count);
	printf("session_setup_time:             %u\n", profile_p->Trans2_session_setup_time);
	printf("get_dfs_referral_count:         %u\n", profile_p->Trans2_get_dfs_referral_count);
	printf("get_dfs_referral_time:          %u\n", profile_p->Trans2_get_dfs_referral_time);
	printf("report_dfs_inconsistancy_count: %u\n", profile_p->Trans2_report_dfs_inconsistancy_count);
	printf("report_dfs_inconsistancy_time:  %u\n", profile_p->Trans2_report_dfs_inconsistancy_time);
	printf("************************ NT Transact Calls ***********************\n");
	printf("create_count:                   %u\n", profile_p->NT_transact_create_count);
	printf("create_time:                    %u\n", profile_p->NT_transact_create_time);
	printf("ioctl_count:                    %u\n", profile_p->NT_transact_ioctl_count);
	printf("ioctl_time:                     %u\n", profile_p->NT_transact_ioctl_time);
	printf("set_security_desc_count:        %u\n", profile_p->NT_transact_set_security_desc_count);
	printf("set_security_desc_time:         %u\n", profile_p->NT_transact_set_security_desc_time);
	printf("notify_change_count:            %u\n", profile_p->NT_transact_notify_change_count);
	printf("notify_change_time:             %u\n", profile_p->NT_transact_notify_change_time);
	printf("rename_count:                   %u\n", profile_p->NT_transact_rename_count);
	printf("rename_time:                    %u\n", profile_p->NT_transact_rename_time);
	printf("query_security_desc_count:      %u\n", profile_p->NT_transact_query_security_desc_count);
	printf("query_security_desc_time:       %u\n", profile_p->NT_transact_query_security_desc_time);
	printf("************************ ACL Calls *******************************\n");
	printf("get_nt_acl_count:               %u\n", profile_p->get_nt_acl_count);
	printf("get_nt_acl_time:                %u\n", profile_p->get_nt_acl_time);
	printf("fget_nt_acl_count:              %u\n", profile_p->fget_nt_acl_count);
	printf("fget_nt_acl_time:               %u\n", profile_p->fget_nt_acl_time);
	printf("set_nt_acl_count:               %u\n", profile_p->set_nt_acl_count);
	printf("set_nt_acl_time:                %u\n", profile_p->set_nt_acl_time);
	printf("fset_nt_acl_count:              %u\n", profile_p->fset_nt_acl_count);
	printf("fset_nt_acl_time:               %u\n", profile_p->fset_nt_acl_time);
	printf("chmod_acl_count:                %u\n", profile_p->chmod_acl_count);
	printf("chmod_acl_time:                 %u\n", profile_p->chmod_acl_time);
	printf("fchmod_acl_count:               %u\n", profile_p->fchmod_acl_count);
	printf("fchmod_acl_time:                %u\n", profile_p->fchmod_acl_time);
	printf("************************ NMBD Calls ****************************\n");
	printf("name_release_count:             %u\n", profile_p->name_release_count);
	printf("name_release_time:              %u\n", profile_p->name_release_time);
	printf("name_refresh_count:             %u\n", profile_p->name_refresh_count);
	printf("name_refresh_time:              %u\n", profile_p->name_refresh_time);
	printf("name_registration_count:        %u\n", profile_p->name_registration_count);
	printf("name_registration_time:         %u\n", profile_p->name_registration_time);
	printf("node_status_count:              %u\n", profile_p->node_status_count);
	printf("node_status_time:               %u\n", profile_p->node_status_time);
	printf("name_query_count:               %u\n", profile_p->name_query_count);
	printf("name_query_time:                %u\n", profile_p->name_query_time);
	printf("host_announce_count:            %u\n", profile_p->host_announce_count);
	printf("host_announce_time:             %u\n", profile_p->host_announce_time);
	printf("workgroup_announce_count:       %u\n", profile_p->workgroup_announce_count);
	printf("workgroup_announce_time:        %u\n", profile_p->workgroup_announce_time);
	printf("local_master_announce_count:    %u\n", profile_p->local_master_announce_count);
	printf("local_master_announce_time:     %u\n", profile_p->local_master_announce_time);
	printf("master_browser_announce_count:  %u\n", profile_p->master_browser_announce_count);
	printf("master_browser_announce_time:   %u\n", profile_p->master_browser_announce_time);
	printf("lm_host_announce_count:         %u\n", profile_p->lm_host_announce_count);
	printf("lm_host_announce_time:          %u\n", profile_p->lm_host_announce_time);
	printf("get_backup_list_count:          %u\n", profile_p->get_backup_list_count);
	printf("get_backup_list_time:           %u\n", profile_p->get_backup_list_time);
	printf("reset_browser_count:            %u\n", profile_p->reset_browser_count);
	printf("reset_browser_time:             %u\n", profile_p->reset_browser_time);
	printf("announce_request_count:         %u\n", profile_p->announce_request_count);
	printf("announce_request_time:          %u\n", profile_p->announce_request_time);
	printf("lm_announce_request_count:      %u\n", profile_p->lm_announce_request_count);
	printf("lm_announce_request_time:       %u\n", profile_p->lm_announce_request_time);
	printf("domain_logon_count:             %u\n", profile_p->domain_logon_count);
	printf("domain_logon_time:              %u\n", profile_p->domain_logon_time);
	printf("sync_browse_lists_count:        %u\n", profile_p->sync_browse_lists_count);
	printf("sync_browse_lists_time:         %u\n", profile_p->sync_browse_lists_time);
	printf("run_elections_count:            %u\n", profile_p->run_elections_count);
	printf("run_elections_time:             %u\n", profile_p->run_elections_time);
	printf("election_count:                 %u\n", profile_p->election_count);
	printf("election_time:                  %u\n", profile_p->election_time);

#else /* ndef WITH_PROFILE */
	fprintf(stderr,"Profile data unavailable\n");
#endif /* WITH_PROFILE */
	return 0;
}


static int traverse_fn1(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf, void *state)
{
	static pid_t last_pid;
	struct session_record *ptr;
	struct connections_data crec;

	if (dbuf.dsize != sizeof(crec))
		return 0;

	memcpy(&crec, dbuf.dptr, sizeof(crec));

	if (crec.cnum == -1)
		return 0;

	if (!process_exists(crec.pid) || !Ucrit_checkUsername(uidtoname(crec.uid))) {
		return 0;
	}

	if (brief) {
		ptr=srecs;
		while (ptr!=NULL) {
			if ((ptr->pid==crec.pid)&&(strncmp(ptr->machine,crec.machine,30)==0)) {
				if (ptr->start > crec.start)
					ptr->start=crec.start;
				break;
			}
			ptr=ptr->next;
		}
		if (ptr==NULL) {
			ptr=(struct session_record *) malloc(sizeof(struct session_record));
			if (!ptr)
				return 0;
			ptr->uid=crec.uid;
			ptr->pid=crec.pid;
			ptr->start=crec.start;
			strncpy(ptr->machine,crec.machine,30);
			ptr->machine[30]='\0';
			ptr->next=srecs;
			srecs=ptr;
		}
	} else {
		Ucrit_addPid(crec.pid);  
		if (processes_only) {
			if (last_pid != crec.pid)
				printf("%d\n",(int)crec.pid);
			last_pid = crec.pid; /* XXXX we can still get repeats, have to
						add a sort at some time */
		} else {
			printf("%-10.10s   %-8s %-8s %5d   %-8s (%s) %s",
			       crec.name,uidtoname(crec.uid),gidtoname(crec.gid),(int)crec.pid,
			       crec.machine,crec.addr,
			       asctime(LocalTime(&crec.start)));
		}
	}

	return 0;
}




 int main(int argc, char *argv[])
{
	pstring fname;
	int c;
	static pstring servicesf = CONFIGFILE;
	extern char *optarg;
	int profile_only = 0;
	TDB_CONTEXT *tdb;
	struct session_record *ptr;

	TimeInit();
	setup_logging(argv[0],True);
	
	charset_initialise();
	
	AllowDebugChange = False;
	DEBUGLEVEL = 0;
	dbf = stderr;
	
	if (getuid() != geteuid()) {
		printf("smbstatus should not be run setuid\n");
		return(1);
	}
	
	while ((c = getopt(argc, argv, "pdLSs:u:bPB")) != EOF) {
		switch (c) {
		case 'b':
			brief = 1;
			break;
		case 'B':
			show_brl = 1;
			break;
		case 'd':
			verbose = 1;
			break;
		case 'L':
			locks_only = 1;
			break;
		case 'p':
			processes_only = 1;
			break;
		case 'P':
			profile_only = 1;
			break;
		case 'S':
			shares_only = 1;
			break;
		case 's':
			pstrcpy(servicesf, optarg);
			break;
		case 'u':                                      
			Ucrit_addUsername(optarg);             
			break;
		default:
			fprintf(stderr, "Usage: %s [-P] [-d] [-L] [-p] [-S] [-s configfile] [-u username]\n", *argv);
			return (-1);
		}
	}
	
	if (!lp_load(servicesf,False,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
		return (-1);
	}
	
	if (verbose) {
		printf("using configfile = %s\n", servicesf);
	}
	
	if (profile_only) {
		return profile_dump();
	}
	
	tdb = tdb_open_log(lock_path("connections.tdb"), 0, TDB_DEFAULT, O_RDONLY, 0);
	if (!tdb) {
		printf("%s not initialized.\n", lock_path("connections.tdb"));
		printf("This is normal if an SMB client has never connected to your server.\n");
		if (!lp_status(-1)) {
			printf("You need to have status=yes in your smb config file\n");
		}
		return(0);
	}  else if (verbose) {
		slprintf (fname, sizeof(fname)-1, "%s/%s", lp_lockdir(), "connections.tdb");
		printf("Opened %s\n", fname);
	}

	if (locks_only) goto locks;

	printf("\nSamba version %s\n",VERSION);
	if (brief) {
		printf("PID     Username  Machine                       Time logged in\n");
		printf("-------------------------------------------------------------------\n");
	} else {
		printf("Service      uid      gid      pid     machine\n");
		printf("----------------------------------------------\n");
	}
	tdb_traverse(tdb, traverse_fn1, NULL);
	

 locks:
	if (processes_only) exit(0);
  
	if (brief)  {
		ptr=srecs;
		while (ptr!=NULL) {
			printf("%-8d%-10.10s%-30.30s%s",
			       (int)ptr->pid,uidtoname(ptr->uid),
			       ptr->machine,
			       asctime(LocalTime(&(ptr->start))));
			ptr=ptr->next;
		}
		printf("\n");
		exit(0);
	}

	printf("\n");

	if (!shares_only) {
		int ret;

		if (!locking_init(1)) {
			printf("Can't initialise locking module - exiting\n");
			exit(1);
		}
		
		ret = share_mode_forall(print_share_mode);

		if (ret == 0) {
			printf("No locked files\n");
		} else if (ret == -1) {
			printf("locked file list truncated\n");
		}
		
		printf("\n");

		if (show_brl) {
			brl_forall(print_brl);
		}
		
		locking_end();
	}

	return (0);
}

